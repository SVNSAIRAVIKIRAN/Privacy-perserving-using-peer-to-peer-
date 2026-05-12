"""
store.py — SQLite-backed persistence for users, sessions, messages, and file metadata.
File blobs live on disk under FILES_DIR; only metadata is in the DB.
"""
import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager

from config import DB_PATH, FILES_DIR

# Ensure file storage directory exists
os.makedirs(FILES_DIR, exist_ok=True)


# ── DB connection ─────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username     TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            anonymous_id  TEXT NOT NULL,
            created_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            peer_a       TEXT NOT NULL,
            peer_b       TEXT NOT NULL,
            anon_a       TEXT NOT NULL,
            anon_b       TEXT NOT NULL,
            session_key  TEXT NOT NULL,
            token        TEXT NOT NULL,
            nonce        TEXT NOT NULL,
            created_ts   REAL NOT NULL,
            created_at   TEXT NOT NULL,
            expires_at   REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id           TEXT PRIMARY KEY,
            from_user    TEXT NOT NULL,
            to_user      TEXT NOT NULL,
            session_id   TEXT NOT NULL,
            content      TEXT NOT NULL,
            timestamp    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            file_id      TEXT PRIMARY KEY,
            filename     TEXT NOT NULL,
            size         INTEGER NOT NULL,
            uploader     TEXT NOT NULL,
            uploader_anon TEXT NOT NULL,
            session_id   TEXT NOT NULL,
            sha256       TEXT NOT NULL,
            blob_path    TEXT NOT NULL,
            timestamp    TEXT NOT NULL
        );
        """)


# ── Users ─────────────────────────────────────────────────────────────────────

def create_user(username: str, password_hash: str, anonymous_id: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, anonymous_id, created_at) VALUES (?,?,?,?)",
            (username, password_hash, anonymous_id, ts),
        )


def get_user(username: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None


def user_exists(username: str) -> bool:
    with get_db() as conn:
        return conn.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone() is not None


# ── Sessions ──────────────────────────────────────────────────────────────────

def create_session(
    session_id, peer_a, peer_b, anon_a, anon_b,
    session_key, token, nonce, ttl_seconds
):
    now_ts = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            """INSERT INTO sessions
               (session_id,peer_a,peer_b,anon_a,anon_b,session_key,token,nonce,
                created_ts,created_at,expires_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (session_id, peer_a, peer_b, anon_a, anon_b,
             session_key, token, nonce, now_ts, now_str, now_ts + ttl_seconds),
        )


def get_session(session_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id=? AND expires_at > ?",
            (session_id, time.time()),
        ).fetchone()
        return dict(row) if row else None


def get_sessions_for_user(username: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE (peer_a=? OR peer_b=?) AND expires_at > ? ORDER BY created_ts DESC",
            (username, username, time.time()),
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_sessions() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE expires_at > ? ORDER BY created_ts DESC",
            (time.time(),),
        ).fetchall()
        return [dict(r) for r in rows]


def revoke_session(session_id: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at=0 WHERE session_id=?", (session_id,)
        )


def purge_expired_sessions() -> int:
    with get_db() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        return cur.rowcount


# ── Messages ──────────────────────────────────────────────────────────────────

def save_message(msg_id, from_user, to_user, session_id, content):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO messages (id,from_user,to_user,session_id,content,timestamp) VALUES (?,?,?,?,?,?)",
            (msg_id, from_user, to_user, session_id, content, ts),
        )


def get_messages_for_user(username: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE from_user=? OR to_user=? ORDER BY timestamp",
            (username, username),
        ).fetchall()
        return [dict(r) for r in rows]


# ── Files ─────────────────────────────────────────────────────────────────────

def save_file_meta(file_id, filename, size, uploader, uploader_anon, session_id, sha256, blob_path):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            """INSERT INTO files
               (file_id,filename,size,uploader,uploader_anon,session_id,sha256,blob_path,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (file_id, filename, size, uploader, uploader_anon, session_id, sha256, blob_path, ts),
        )


def get_file_meta(file_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
        return dict(row) if row else None


def get_files_for_user(username: str) -> list[dict]:
    """Return files in sessions the user is part of."""
    sessions = get_sessions_for_user(username)
    session_ids = {s["session_id"] for s in sessions}
    if not session_ids:
        return []
    placeholders = ",".join("?" * len(session_ids))
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM files WHERE session_id IN ({placeholders}) ORDER BY timestamp DESC",
            list(session_ids),
        ).fetchall()
        return [dict(r) for r in rows]
