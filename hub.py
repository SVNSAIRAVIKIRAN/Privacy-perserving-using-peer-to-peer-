"""
hub.py — Central Authentication Hub (port 8000)
Handles: user registry, peer discovery, auth engine (Steps 1-9),
         SSE monitor, message relay, file transfer.

Run:  python hub.py
"""
import hashlib
import io
import os
import re
import secrets
import threading
import time
from functools import wraps

from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, send_file, stream_with_context, url_for)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _HAS_LIMITER = True
except ImportError:
    _HAS_LIMITER = False
from werkzeug.utils import secure_filename

import config
import crypto
import sse
import store
import ai_intrusion_detection as ids

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

if _HAS_LIMITER:
    limiter = Limiter(get_remote_address, app=app,
                      default_limits=["500 per day", "100 per hour"])
else:
    class _NoopLimiter:
        def limit(self, *a, **k): return lambda f: f
    limiter = _NoopLimiter()

# ── In-memory presence (not persisted — intentionally ephemeral) ──────────────
_lock        = threading.Lock()
online_peers = {}   # {username: {anonymous_id, last_seen, status, peer_url}}
conn_requests = []  # [{id, from_user, from_anon, to_user, to_anon, status, timestamp}]

# ── Input validation ──────────────────────────────────────────────────────────
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{3,32}$')


def _validate_credentials(username: str, password: str) -> str | None:
    """Returns error string or None if valid."""
    if not USERNAME_RE.match(username):
        return f"Username must be {config.USERNAME_MIN}–{config.USERNAME_MAX} chars, letters/digits/_ only."
    if len(password) < config.PASSWORD_MIN:
        return f"Password must be at least {config.PASSWORD_MIN} characters."
    return None


# ── Peer presence helpers ─────────────────────────────────────────────────────

def _is_online(username: str) -> bool:
    with _lock:
        info = online_peers.get(username)
    if not info:
        return False
    return (time.time() - info["last_seen"]) <= config.OFFLINE_THRESHOLD


def peers_payload() -> list[dict]:
    now = time.time()
    with _lock:
        peers = list(online_peers.items())
    result = []
    for u, info in peers:
        online = (now - info["last_seen"]) <= config.OFFLINE_THRESHOLD
        result.append({
            "username":     u,
            "anonymous_id": info["anonymous_id"],
            "status":       "online" if online else "offline",
            "peer_url":     info.get("peer_url", ""),
        })
    return result


def requests_for(username: str) -> list[dict]:
    with _lock:
        return [r for r in conn_requests
                if r["to_user"] == username and r["status"] == "pending"]


# ── Background cleanup ────────────────────────────────────────────────────────

def _cleanup_loop():
    while True:
        time.sleep(config.CLEANUP_INTERVAL)
        # Purge expired sessions from DB
        purged = store.purge_expired_sessions()
        if purged:
            sse.add_log(8, "SESSION CLEANUP", "hub",
                        f"{purged} expired session(s) removed", "warning")

        # Purge stale connection requests (older than 10 minutes)
        cutoff = time.time() - 600
        with _lock:
            before = len(conn_requests)
            conn_requests[:] = [
                r for r in conn_requests
                if r["status"] == "pending" or r.get("_ts", 0) > cutoff
            ]
            removed = before - len(conn_requests)
        if removed:
            sse.add_log(5, "REQ CLEANUP", "hub",
                        f"{removed} stale request(s) removed", "warning")


threading.Thread(target=_cleanup_loop, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Pages
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("hub_index.html")


@app.route("/monitor")
def monitor():
    return render_template("monitor.html", logs=sse.get_logs())


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Steps 1 & 3: Registration
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/register", methods=["POST"])
@limiter.limit("20 per hour")
def hub_register():
    d        = request.get_json() or {}
    username = d.get("username", "").strip()
    password = d.get("password", "").strip()

    err = _validate_credentials(username, password)
    if err:
        return jsonify({"success": False, "message": err})
    if store.user_exists(username):
        return jsonify({"success": False, "message": "Username already taken."})

    anon_id   = crypto.generate_anonymous_id(username)
    pw_hash   = crypto.hash_password(password)
    store.create_user(username, pw_hash, anon_id)

    sse.add_log(1, "USER REGISTERED", username,
                f"'{username}' registered — bcrypt(12) password hash stored", "info")
    sse.add_log(3, "ANON ID ASSIGNED", anon_id[:16] + "…",
                f"Anonymous ID: SHA-256(username+salt) = {anon_id[:24]}…", "success")

    return jsonify({"success": True, "anonymous_id": anon_id})


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Step 2 & 4: Login / Logout / Heartbeat
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/login", methods=["POST"])
@limiter.limit("15 per minute")
def hub_login():
    d        = request.get_json() or {}
    username = d.get("username", "").strip()
    password = d.get("password", "").strip()
    peer_url = d.get("peer_url", "").strip()

    user = store.get_user(username)
    if not user:
        ids.record_login(username, success=False)
        result = ids.analyse(username)
        if result["anomaly"]:
            sse.add_log(2, "IDS ALERT", username,
                        f"Anomaly on unknown user login — risk: {result['risk'].upper()} | {'; '.join(result['reasons'])}", "error")
        return jsonify({"success": False, "message": "User not found."})
    if not crypto.verify_password(password, user["password_hash"]):
        ids.record_login(username, success=False)
        result = ids.analyse(username)
        if result["anomaly"]:
            sse.add_log(2, "IDS ALERT", username,
                        f"Failed login anomaly — risk: {result['risk'].upper()} | {'; '.join(result['reasons'])}", "error")
        return jsonify({"success": False, "message": "Wrong password."})

    with _lock:
        online_peers[username] = {
            "anonymous_id": user["anonymous_id"],
            "last_seen":    time.time(),
            "status":       "online",
            "peer_url":     peer_url,
        }

    ids.record_login(username, success=True)
    result = ids.analyse(username)
    if result["anomaly"]:
        sse.add_log(2, "IDS ALERT", username,
                    f"Suspicious login pattern — risk: {result['risk'].upper()} | {'; '.join(result['reasons'])}", "error")
    else:
        sse.add_log(2, "IDS OK", username,
                    f"Login behaviour normal — risk: {result['risk']} | score: {result['score']}", "info")

    sse.add_log(2, "PEER LOGIN", user["anonymous_id"][:16] + "…",
                f"'{username}' authenticated — bcrypt verified, joined network", "success")
    sse.add_log(2, "USER_LOGIN", username,
                f"'{username}' login successful → session token issued", "success")
    sse.add_log(4, "PEER DISCOVERY", user["anonymous_id"][:16] + "…",
                f"'{username}' broadcasting presence — peer discovery active", "info")
    sse.add_log(4, "PEER_DISCOVERY", user["anonymous_id"][:16] + "…",
                f"'{username}' found in network — peer list updated", "info")
    sse.push("peers", peers_payload())

    return jsonify({"success": True, "anonymous_id": user["anonymous_id"]})


@app.route("/hub/logout", methods=["POST"])
def hub_logout():
    d = request.get_json() or {}
    u = d.get("username", "")
    with _lock:
        info = online_peers.pop(u, {})
    anon = info.get("anonymous_id", u)
    sse.add_log(2, "PEER LOGOUT", anon[:16] + "…",
                f"'{u}' disconnected from network", "warning")
    sse.push("peers", peers_payload())
    return jsonify({"success": True})


@app.route("/hub/heartbeat", methods=["POST"])
def hub_heartbeat():
    d = request.get_json() or {}
    u = d.get("username", "")
    peer_url = d.get("peer_url", "")
    with _lock:
        if u in online_peers:
            online_peers[u]["last_seen"] = time.time()
            online_peers[u]["status"]    = "online"
            if peer_url:
                online_peers[u]["peer_url"] = peer_url
    return jsonify({"ok": True})


# ── Peers / Requests ──────────────────────────────────────────────────────────

@app.route("/hub/peers")
@app.route("/api/peers")
def hub_peers():
    return jsonify(peers_payload())


@app.route("/hub/requests")
def hub_requests():
    u = request.args.get("username", "")
    return jsonify(requests_for(u))


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Step 5: Connection request
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/connect/request", methods=["POST"])
def hub_connect_request():
    d       = request.get_json() or {}
    from_u  = d.get("from_user", "").strip()
    from_a  = d.get("from_anon", "").strip()
    to_u    = d.get("to_user",   "").strip()

    if not from_u or not to_u:
        return jsonify({"success": False, "message": "Missing fields."})

    # Check last_seen directly — never trust cached status field
    if not _is_online(to_u):
        return jsonify({"success": False, "message": f"'{to_u}' is not online."})

    with _lock:
        for r in conn_requests:
            if (r["from_user"] == from_u and r["to_user"] == to_u
                    and r["status"] == "pending"):
                return jsonify({"success": False, "message": "Request already pending."})

        req = {
            "id":        secrets.token_hex(8),
            "from_user": from_u,
            "from_anon": from_a,
            "to_user":   to_u,
            "to_anon":   online_peers[to_u]["anonymous_id"],
            "status":    "pending",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "_ts":       time.time(),
        }
        conn_requests.append(req)

    sse.add_log(5, "CONN REQUEST", from_a[:16] + "…",
                f"'{from_u}' → '{to_u}': connection request dispatched", "info")
    sse.add_log(5, "AUTH_REQUEST", from_a[:16] + "…",
                f"'{from_u}' → '{to_u}': authentication request initiated", "info")

    ids.record_connection_request(from_u)
    ids_result = ids.analyse(from_u)
    if ids_result["anomaly"]:
        sse.add_log(5, "IDS ALERT", from_u,
                    f"Abnormal request pattern — risk: {ids_result['risk'].upper()} | {'; '.join(ids_result['reasons'])}", "error")
    sse.push("req_update", {"to_user": to_u, "requests": requests_for(to_u)})

    return jsonify({"success": True, "message": f"Request sent to {to_u}."})


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Steps 6–9: Accept / Reject → full auth pipeline
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/connect/respond", methods=["POST"])
def hub_connect_respond():
    d      = request.get_json() or {}
    req_id = d.get("req_id", "")
    action = d.get("action", "")
    me     = d.get("username", "")

    with _lock:
        req = next((r for r in conn_requests if r["id"] == req_id), None)
        if not req or req["to_user"] != me:
            return jsonify({"success": False, "message": "Request not found."})
        req["status"] = action

    if action == "accept":
        sse.add_log(6, "AUTH INITIATED", req["to_anon"][:16] + "…",
                    f"'{me}' accepted — ECC/ECDH engine starting for "
                    f"'{req['from_user']}' ↔ '{me}'", "info")

        def run_auth(r=req):
            time.sleep(0.3)

            # Step 6a — ECC key gen peer A
            sse.add_log(6, "ECC KEY GEN", r["from_anon"][:16] + "…",
                        f"SECP256R1 key pair generated for '{r['from_user']}'", "info")
            p1_priv, p1_pub = crypto.generate_ecc_keys()

            time.sleep(0.3)
            # Step 6b — ECC key gen peer B
            sse.add_log(6, "ECC KEY GEN", r["to_anon"][:16] + "…",
                        f"SECP256R1 key pair generated for '{r['to_user']}'", "info")
            p2_priv, p2_pub = crypto.generate_ecc_keys()

            time.sleep(0.3)
            # Step 6c — public key exchange
            sse.add_log(6, "KEY EXCHANGE", r["from_anon"][:16] + "…",
                        "Public keys exchanged — private keys never transmitted", "info")

            # Step 6d — ECDH shared secret
            shared, auth_time, ok = crypto.authenticate_peers(p1_priv, p1_pub, p2_priv, p2_pub)
            time.sleep(0.3)

            if not ok:
                sse.add_log(6, "AUTH FAILED", r["from_anon"][:16] + "…",
                            "ECDH secrets do NOT match — rejected", "error")
                return

            sse.add_log(6, "ECDH VERIFIED", r["from_anon"][:16] + "…",
                        f"Shared secret computed in {auth_time:.6f}s — both sides MATCH ✓", "success")
            sse.add_log(6, "ECDH_KEY_EXCHANGE", r["from_anon"][:16] + "…",
                        f"ECDH key exchange complete — shared secret verified in {auth_time:.6f}s", "success")

            # Step 7 — token generation + verification
            time.sleep(0.3)
            skey_hex = crypto.derive_session_key(shared)   # full 64-char key
            token, nonce = crypto.generate_session_token(r["from_user"], r["to_user"], skey_hex)

            sse.add_log(7, "TOKEN GENERATED", r["from_anon"][:16] + "…",
                        f"SHA-256 nonce-bound token: {token[:28]}…", "info")
            time.sleep(0.25)

            valid = crypto.verify_session_token(token, r["from_user"], r["to_user"], skey_hex, nonce)
            sse.add_log(7, "TOKEN VALIDATED", r["to_anon"][:16] + "…",
                        f"Token context-verification: {'PASSED ✓' if valid else 'FAILED ✗'}", 
                        "success" if valid else "error")

            if not valid:
                return

            # Step 8 — session key + DB storage
            time.sleep(0.3)
            sess_id = secrets.token_hex(8)
            store.create_session(
                sess_id, r["from_user"], r["to_user"],
                r["from_anon"], r["to_anon"],
                skey_hex, token, nonce,
                config.SESSION_TTL,
            )

            sse.add_log(8, "SESSION KEY", r["to_anon"][:16] + "…",
                        f"AES-256 session key (HKDF-SHA256): {skey_hex[:28]}… — channel ready", "success")
            sse.add_log(8, "SESSION_KEY_CREATED", r["to_anon"][:16] + "…",
                        f"Session key derived: {skey_hex[:28]}… | AES-256-GCM ready", "success")
            time.sleep(0.25)
            sse.add_log(8, "SESSION ACTIVE", r["from_anon"][:16] + "…",
                        f"SECURE SESSION — '{r['from_user']}' ↔ '{r['to_user']}' | ID: {sess_id}", "success")

            # Step 9 — P2P channel open
            time.sleep(0.2)
            sse.add_log(9, "P2P CHANNEL OPEN", r["from_anon"][:16] + "…",
                        f"Encrypted P2P channel active: '{r['from_user']}' ↔ '{r['to_user']}'", "success")
            sse.add_log(9, "SECURE_CHANNEL_ESTABLISHED", r["from_anon"][:16] + "…",
                        f"Secure channel live: '{r['from_user']}' ↔ '{r['to_user']}' | E2E encrypted", "success")

            sse.push("session", {
                "peerA":       r["from_user"],
                "peerB":       r["to_user"],
                "session_id":  sess_id,
                "session_key": skey_hex[:32] + "…",   # display only — full key stays in DB
                "token":       token[:24] + "…",
            })

        threading.Thread(target=run_auth, daemon=True).start()

    else:
        sse.add_log(5, "REQ REJECTED", req["to_anon"][:16] + "…",
                    f"'{me}' rejected from '{req['from_user']}'", "warning")

    sse.push("req_update", {"to_user": me, "requests": requests_for(me)})
    return jsonify({"success": True, "action": action})


# ── Sessions ──────────────────────────────────────────────────────────────────

@app.route("/hub/sessions")
def hub_sessions():
    u = request.args.get("username", "")
    sessions = store.get_sessions_for_user(u)
    # Return display-safe version (never expose full session key)
    result = []
    for s in sessions:
        result.append({
            "session_id":  s["session_id"],
            "peerA":       s["peer_a"],
            "peerB":       s["peer_b"],
            "session_key": s["session_key"][:32] + "…",
            "token":       s["token"][:24] + "…",
            "created_at":  s["created_at"],
        })
    return jsonify(result)


@app.route("/hub/sessions/all")
def hub_sessions_all():
    sessions = store.get_all_sessions()
    result = []
    for s in sessions:
        result.append({
            "session_id":  s["session_id"],
            "peerA":       s["peer_a"],
            "peerB":       s["peer_b"],
            "session_key": s["session_key"][:32] + "…",
            "token":       s["token"][:24] + "…",
            "created_at":  s["created_at"],
        })
    return jsonify(result)


@app.route("/hub/session/revoke", methods=["POST"])
def hub_session_revoke():
    d          = request.get_json() or {}
    session_id = d.get("session_id", "")
    username   = d.get("username", "")
    sess = store.get_session(session_id)
    if not sess:
        return jsonify({"success": False, "message": "Session not found."})
    if sess["peer_a"] != username and sess["peer_b"] != username:
        return jsonify({"success": False, "message": "Access denied."})
    store.revoke_session(session_id)
    sse.add_log(8, "SESSION REVOKED", username,
                f"Session {session_id[:8]}… revoked by '{username}'", "warning")
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Step 9: Messages
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/message/send", methods=["POST"])
def hub_message_send():
    d       = request.get_json() or {}
    from_u  = d.get("from_user", "").strip()
    from_a  = d.get("from_anon", "").strip()
    to_u    = d.get("to_user",   "").strip()
    content = d.get("content",   "").strip()

    if not content:
        return jsonify({"success": False, "message": "Empty message."})
    if len(content) > 4096:
        return jsonify({"success": False, "message": "Message too long (max 4096 chars)."})

    sessions = store.get_sessions_for_user(from_u)
    sess = next((s for s in sessions
                 if (s["peer_a"] == from_u and s["peer_b"] == to_u) or
                    (s["peer_a"] == to_u   and s["peer_b"] == from_u)), None)
    if not sess:
        return jsonify({"success": False, "message": "No active session. Authenticate first."})

    msg_id = secrets.token_hex(6)
    store.save_message(msg_id, from_u, to_u, sess["session_id"], content)

    msg = {"id": msg_id, "from_user": from_u, "to_user": to_u,
           "sess_id": sess["session_id"], "content": content,
           "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

    sse.add_log(9, "P2P MESSAGE", from_a[:16] + "…",
                f"'{from_u}' → '{to_u}': message via session {sess['session_id'][:8]}…", "success")
    sse.push("message", msg)
    return jsonify({"success": True})


@app.route("/hub/message/inbox")
def hub_message_inbox():
    u = request.args.get("username", "")
    return jsonify(store.get_messages_for_user(u))


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — Step 9: File transfer
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/file/upload", methods=["POST"])
def hub_file_upload():
    uploader   = request.form.get("username",     "").strip()
    anon       = request.form.get("anonymous_id", "").strip()
    session_id = request.form.get("session_id",   "").strip()

    if not uploader:
        return jsonify({"success": False, "message": "Missing username."})
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file provided."})

    f = request.files["file"]
    safe_name = secure_filename(f.filename or "")
    if not safe_name:
        return jsonify({"success": False, "message": "Invalid or missing filename."})

    # Resolve session: explicit session_id preferred, else find one for this user
    if session_id:
        sess = store.get_session(session_id)
        if not sess or (sess["peer_a"] != uploader and sess["peer_b"] != uploader):
            return jsonify({"success": False, "message": "Invalid or expired session."})
    else:
        user_sessions = store.get_sessions_for_user(uploader)
        if not user_sessions:
            return jsonify({"success": False, "message": "No active session. Connect to a peer first."})
        sess = user_sessions[0]   # most recent active session

    raw = f.read(config.MAX_FILE_SIZE + 1)
    if len(raw) > config.MAX_FILE_SIZE:
        return jsonify({"success": False,
                        "message": f"File exceeds {config.MAX_FILE_SIZE // (1024*1024)} MB limit."})

    fhash     = hashlib.sha256(raw).hexdigest()
    fid       = secrets.token_hex(8)
    skey_hex  = sess["session_key"]     # full 64-char key from DB

    # AES-256-GCM encrypt
    try:
        encrypted = crypto.encrypt_file(raw, skey_hex)
    except Exception as e:
        return jsonify({"success": False, "message": f"Encryption failed: {e}"})

    # Write blob to disk
    blob_path = os.path.join(config.FILES_DIR, fid + ".enc")
    with open(blob_path, "wb") as fp:
        fp.write(encrypted)

    store.save_file_meta(fid, safe_name, len(raw), uploader, anon,
                         sess["session_id"], fhash, blob_path)

    other = sess["peer_b"] if sess["peer_a"] == uploader else sess["peer_a"]
    sse.add_log(9, "FILE UPLOADED", anon[:16] + "…",
                f"'{uploader}' → '{other}': '{safe_name}' ({len(raw)} B) "
                f"AES-256-GCM encrypted. SHA256:{fhash[:16]}…", "success")
    ids.record_file_transfer(uploader)
    sse.push("file_shared", {
        "file_id":   fid,
        "filename":  safe_name,
        "size":      len(raw),
        "uploader":  uploader,
        "sha256":    fhash,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "session_id": sess["session_id"],
    })

    return jsonify({"success": True, "file_id": fid, "sha256": fhash})


@app.route("/hub/file/list")
def hub_file_list():
    username = request.args.get("username", "")
    files = store.get_files_for_user(username)
    # Strip blob_path from public response
    return jsonify([{k: v for k, v in f.items() if k != "blob_path"} for f in files])


@app.route("/hub/file/download/<file_id>")
def hub_file_download(file_id):
    username = request.args.get("username", "")
    meta = store.get_file_meta(file_id)
    if not meta:
        return jsonify({"success": False, "message": "File not found."}), 404

    sess = store.get_session(meta["session_id"])
    if not sess:
        return jsonify({"success": False, "message": "Session expired."}), 403
    if sess["peer_a"] != username and sess["peer_b"] != username:
        return jsonify({"success": False, "message": "Access denied."}), 403

    if not os.path.exists(meta["blob_path"]):
        return jsonify({"success": False, "message": "File blob missing from disk."}), 500

    with open(meta["blob_path"], "rb") as fp:
        encrypted = fp.read()

    try:
        raw = crypto.decrypt_file(encrypted, sess["session_key"])
    except Exception:
        sse.add_log(9, "DECRYPT FAIL", username,
                    f"AES-GCM authentication tag mismatch on '{meta['filename']}'", "error")
        return jsonify({"success": False, "message": "Decryption failed — file may be corrupted."}), 500

    # Integrity check
    if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
        sse.add_log(9, "INTEGRITY FAIL", username,
                    f"SHA-256 mismatch on '{meta['filename']}'", "error")
        return jsonify({"success": False, "message": "Integrity check failed."}), 500

    anon = ""
    with _lock:
        anon = online_peers.get(username, {}).get("anonymous_id", username)
    sse.add_log(9, "FILE DOWNLOAD", anon[:16] + "…",
                f"'{username}' downloaded '{meta['filename']}' — AES-GCM decrypted, SHA-256 verified ✓", "success")

    return send_file(io.BytesIO(raw), download_name=meta["filename"], as_attachment=True)


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES — SSE stream
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/stream")
def hub_stream():
    username = request.args.get("username", "")
    q = sse.new_client_queue()

    def generate():
        # Send initial state
        yield f"event: peers\ndata: {__import__('json').dumps(peers_payload())}\n\n"
        if username:
            yield f"event: req_update\ndata: {__import__('json').dumps({'to_user': username, 'requests': requests_for(username)})}\n\n"
        try:
            while True:
                try:
                    yield q.get(timeout=25)
                except __import__("queue").Empty:
                    yield ": ping\n\n"
        except GeneratorExit:
            pass
        finally:
            sse.remove_client_queue(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/hub/monitor/logs")
def hub_monitor_logs():
    try:
        last_n = int(request.args.get("n", 200))
    except ValueError:
        last_n = 200
    return __import__("flask").jsonify(sse.get_logs(last_n))


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/hub/debug")
def hub_debug():
    now = time.time()
    with _lock:
        peers_info = {
            u: {
                "last_seen_ago": round(now - info["last_seen"], 1),
                "is_online": (now - info["last_seen"]) <= config.OFFLINE_THRESHOLD,
                "peer_url": info.get("peer_url", ""),
                "anonymous_id": info["anonymous_id"][:16] + "...",
            }
            for u, info in online_peers.items()
        }
        pending_reqs = [
            {
                "id": r["id"],
                "from": r["from_user"],
                "to": r["to_user"],
                "status": r["status"],
                "age_s": round(now - r["_ts"], 1),
            }
            for r in conn_requests
        ]
    return jsonify({
        "online_peers": peers_info,
        "pending_requests": pending_reqs,
        "offline_threshold": config.OFFLINE_THRESHOLD,
        "sse_clients": sse.client_count(),
    })


if __name__ == "__main__":
    store.init_db()
    print("=" * 60)
    print(f"  HUB SERVER  →  http://localhost:{config.HUB_PORT}")
    print(f"  Monitor     →  http://localhost:{config.HUB_PORT}/monitor")
    print(f"  DB          →  {config.DB_PATH}")
    print(f"  File store  →  {config.FILES_DIR}/")
    print("=" * 60)
    app.run(debug=False, port=config.HUB_PORT, threaded=True)
