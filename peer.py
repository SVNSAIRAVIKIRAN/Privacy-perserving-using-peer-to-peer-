import secrets
import sys

import requests as req_lib
from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session, url_for)

import config

PORT     = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
PEER_URL = sys.argv[2] if len(sys.argv) > 2 else f"http://localhost:{PORT}"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # generated fresh each run — never hardcoded


def hub(path: str, data=None, method: str = "POST", timeout: int = 30):
    url = config.HUB_URL + path
    try:
        if method == "POST":
            r = req_lib.post(url, json=data, timeout=timeout)
        else:
            r = req_lib.get(url, params=data, timeout=timeout)
        return r.json()
    except Exception as e:
        return {"success": False, "message": str(e)}


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("peer_dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        resp = hub("/hub/register", request.get_json())
        return jsonify(resp)
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        d = request.get_json() or {}
        d["peer_url"] = PEER_URL
        resp = hub("/hub/login", d)
        if resp.get("success"):
            session["username"]     = d["username"]
            session["anonymous_id"] = resp["anonymous_id"]
        return jsonify(resp)
    return render_template("login.html")


@app.route("/logout")
def logout():
    if "username" in session:
        hub("/hub/logout", {"username": session["username"]})
    session.clear()
    return redirect(url_for("index"))


@app.route("/peer")
def peer_dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template(
        "peer_dashboard.html",
        username=session["username"],
        anonymous_id=session["anonymous_id"],
        peer_port=PORT,
        hub_url=config.HUB_URL,
        heartbeat_interval=config.HEARTBEAT_INTERVAL * 1000,  # ms for JS
    )


@app.route("/monitor")
def monitor_redirect():
    return redirect(f"{config.HUB_URL}/monitor")


# ══════════════════════════════════════════════════════════════════════════════
# API PROXIES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/session")
def api_session():
    return jsonify({
        "logged_in": "username" in session,
        "username":  session.get("username", ""),
    })


@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    if "username" not in session:
        return jsonify({"ok": False})
    hub("/hub/heartbeat", {"username": session["username"], "peer_url": PEER_URL})
    return jsonify({"ok": True})


@app.route("/api/peers")
def api_peers():
    resp = hub("/hub/peers", method="GET")
    return jsonify(resp if isinstance(resp, list) else [])


@app.route("/api/requests")
def api_requests():
    if "username" not in session:
        return jsonify([])
    resp = hub("/hub/requests", {"username": session["username"]}, method="GET")
    return jsonify(resp if isinstance(resp, list) else [])


@app.route("/api/sessions")
def api_sessions():
    if "username" not in session:
        return jsonify([])
    resp = hub("/hub/sessions", {"username": session["username"]}, method="GET")
    return jsonify(resp if isinstance(resp, list) else [])


@app.route("/api/connect/request", methods=["POST"])
def connect_request():
    if "username" not in session:
        return jsonify({"success": False, "message": "Not logged in."})
    d = request.get_json() or {}
    return jsonify(hub("/hub/connect/request", {
        "from_user": session["username"],
        "from_anon": session["anonymous_id"],
        "to_user":   d.get("to_user", ""),
    }))


@app.route("/api/connect/respond", methods=["POST"])
def connect_respond():
    if "username" not in session:
        return jsonify({"success": False, "message": "Not logged in."})
    d = request.get_json() or {}
    return jsonify(hub("/hub/connect/respond", {
        "req_id":   d.get("req_id", ""),
        "action":   d.get("action", ""),
        "username": session["username"],
    }))


@app.route("/api/message/send", methods=["POST"])
def message_send():
    if "username" not in session:
        return jsonify({"success": False, "message": "Not logged in."})
    d = request.get_json() or {}
    return jsonify(hub("/hub/message/send", {
        "from_user": session["username"],
        "from_anon": session["anonymous_id"],
        "to_user":   d.get("to_user", ""),
        "content":   d.get("content", ""),
    }))


@app.route("/api/message/inbox")
def message_inbox():
    if "username" not in session:
        return jsonify([])
    resp = hub("/hub/message/inbox", {"username": session["username"]}, method="GET")
    return jsonify(resp if isinstance(resp, list) else [])


@app.route("/api/session/revoke", methods=["POST"])
def session_revoke():
    if "username" not in session:
        return jsonify({"success": False, "message": "Not logged in."})
    d = request.get_json() or {}
    return jsonify(hub("/hub/session/revoke", {
        "session_id": d.get("session_id", ""),
        "username":   session["username"],
    }))


@app.route("/api/file/upload", methods=["POST"])
def file_upload():
    if "username" not in session:
        return jsonify({"success": False, "message": "Not logged in."})
    try:
        f = request.files.get("file")
        if not f:
            return jsonify({"success": False, "message": "No file provided."})
        resp = req_lib.post(
            config.HUB_URL + "/hub/file/upload",
            data={
                "username":     session["username"],
                "anonymous_id": session["anonymous_id"],
                "session_id":   request.form.get("session_id", ""),
            },
            files={"file": (f.filename, f.read(), f.content_type or "application/octet-stream")},
            timeout=60,
        )
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route("/api/file/list")
def file_list():
    if "username" not in session:
        return jsonify([])
    resp = hub("/hub/file/list", {"username": session["username"]}, method="GET")
    return jsonify(resp if isinstance(resp, list) else [])


@app.route("/api/file/download/<file_id>")
def file_download(file_id):
    if "username" not in session:
        return jsonify({"success": False, "message": "Not logged in."}), 401
    try:
        r = req_lib.get(
            f"{config.HUB_URL}/hub/file/download/{file_id}",
            params={"username": session["username"]},
            timeout=60,
            stream=True,
        )
        cd = r.headers.get("Content-Disposition", f'attachment; filename="{file_id}"')
        return Response(
            r.content,
            headers={
                "Content-Disposition": cd,
                "Content-Type": r.headers.get("Content-Type", "application/octet-stream"),
            },
        )
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print(f"  PEER NODE   →  http://localhost:{PORT}")
    print(f"  Hub         →  {config.HUB_URL}")
    print(f"  Open:          http://localhost:{PORT}")
    print("=" * 60)
    app.run(debug=False, port=PORT, threaded=True)
