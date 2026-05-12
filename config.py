"""
config.py — Central configuration for all servers.
Override any value via environment variables or a .env file.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Network ───────────────────────────────────────────────────────────────────
HUB_PORT          = int(os.getenv("HUB_PORT", 8000))
HUB_URL           = os.getenv("HUB_URL", f"http://localhost:{HUB_PORT}")

# ── Peer presence ─────────────────────────────────────────────────────────────
OFFLINE_THRESHOLD  = int(os.getenv("OFFLINE_THRESHOLD",  300))  # 5 minutes — very generous grace window
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL",  20))  # browser sends heartbeat every 20s

# ── Session lifecycle ─────────────────────────────────────────────────────────
SESSION_TTL       = int(os.getenv("SESSION_TTL", 3600))        # 1 hour
CLEANUP_INTERVAL  = 60                                          # run cleanup every 60s
LOG_MAX           = 500                                         # max monitor log entries

# ── Files ─────────────────────────────────────────────────────────────────────
MAX_FILE_SIZE     = int(os.getenv("MAX_FILE_MB", 10)) * 1024 * 1024
FILES_DIR         = os.getenv("FILES_DIR", "./file_store")
DB_PATH           = os.getenv("DB_PATH", "./p2p.db")

# ── Security ──────────────────────────────────────────────────────────────────
BCRYPT_ROUNDS     = int(os.getenv("BCRYPT_ROUNDS", 12))
USERNAME_MIN      = 3
USERNAME_MAX      = 32
PASSWORD_MIN      = 8
