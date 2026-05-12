"""
ai_intrusion_detection.py — ML-based Intrusion Detection System
Uses Isolation Forest (unsupervised anomaly detection) to flag:
  - Brute-force login attempts
  - Abnormal connection request bursts
  - Suspicious peer behaviour patterns

No training data required — Isolation Forest learns the baseline
from normal traffic and flags statistical outliers in real-time.
"""
import threading
import time
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

# ── Per-user behaviour tracking ───────────────────────────────────────────────
_lock = threading.Lock()

# Raw event counters per user (reset every window)
_login_attempts:    dict[str, list[float]] = defaultdict(list)   # timestamps
_failed_logins:     dict[str, int]         = defaultdict(int)
_conn_requests:     dict[str, list[float]] = defaultdict(list)   # timestamps
_file_transfers:    dict[str, int]         = defaultdict(int)
_last_seen:         dict[str, float]       = {}

# Sliding window (seconds) for rate calculations
WINDOW = 60.0

# Isolation Forest — trained incrementally as feature vectors accumulate
_model: IsolationForest | None = None
_training_data: list[list[float]] = []
_MIN_SAMPLES = 10          # minimum samples before model is trained
_RETRAIN_EVERY = 20        # retrain every N new samples
_sample_count = 0

# Contamination: expected fraction of anomalies (5%)
_CONTAMINATION = 0.05


# ── Feature extraction ────────────────────────────────────────────────────────

def _now_window_count(timestamps: list[float]) -> int:
    """Count events within the last WINDOW seconds."""
    cutoff = time.time() - WINDOW
    return sum(1 for t in timestamps if t > cutoff)


def _avg_interval(timestamps: list[float]) -> float:
    """Average time between consecutive events. 0 if fewer than 2."""
    recent = sorted(t for t in timestamps if t > time.time() - WINDOW)
    if len(recent) < 2:
        return 0.0
    gaps = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
    return sum(gaps) / len(gaps)


def _build_features(username: str) -> list[float]:
    """
    Feature vector for one user snapshot:
      [0] login_rate          — logins per minute in last window
      [1] failed_login_count  — failed logins in last window
      [2] avg_login_interval  — avg seconds between logins (0 = single event)
      [3] conn_request_rate   — connection requests per minute
      [4] avg_req_interval    — avg seconds between conn requests
      [5] file_transfer_count — file transfers in last window
      [6] time_since_last     — seconds since last any activity
    """
    now = time.time()
    logins   = _login_attempts.get(username, [])
    reqs     = _conn_requests.get(username, [])
    failed   = _failed_logins.get(username, 0)
    files    = _file_transfers.get(username, 0)
    last     = _last_seen.get(username, now)

    return [
        _now_window_count(logins),
        failed,
        _avg_interval(logins),
        _now_window_count(reqs),
        _avg_interval(reqs),
        files,
        now - last,
    ]


# ── Model management ──────────────────────────────────────────────────────────

def _maybe_retrain():
    global _model, _sample_count
    n = len(_training_data)
    if n < _MIN_SAMPLES:
        return
    if n % _RETRAIN_EVERY == 0 or _model is None:
        X = np.array(_training_data)
        _model = IsolationForest(
            n_estimators=100,
            contamination=_CONTAMINATION,
            random_state=42,
        )
        _model.fit(X)


# ── Public API ────────────────────────────────────────────────────────────────

def record_login(username: str, success: bool):
    """Call on every login attempt."""
    with _lock:
        now = time.time()
        _login_attempts[username].append(now)
        _last_seen[username] = now
        if not success:
            _failed_logins[username] += 1
        # Prune old timestamps
        cutoff = now - WINDOW * 5
        _login_attempts[username] = [t for t in _login_attempts[username] if t > cutoff]


def record_connection_request(username: str):
    """Call when a peer sends a connection request."""
    with _lock:
        now = time.time()
        _conn_requests[username].append(now)
        _last_seen[username] = now
        cutoff = now - WINDOW * 5
        _conn_requests[username] = [t for t in _conn_requests[username] if t > cutoff]


def record_file_transfer(username: str):
    """Call on file upload/download."""
    with _lock:
        _file_transfers[username] += 1
        _last_seen[username] = time.time()


def analyse(username: str) -> dict:
    """
    Analyse current behaviour for username.
    Returns:
      {
        "anomaly":  bool,
        "score":    float,   # lower = more anomalous (-1..0 range from IF)
        "risk":     str,     # "low" | "medium" | "high" | "critical"
        "reasons":  list[str],
        "features": dict,
      }
    """
    global _sample_count

    with _lock:
        features = _build_features(username)

    feat_dict = {
        "login_rate":          features[0],
        "failed_logins":       features[1],
        "avg_login_interval":  round(features[2], 2),
        "conn_request_rate":   features[3],
        "avg_req_interval":    round(features[4], 2),
        "file_transfers":      features[5],
        "idle_seconds":        round(features[6], 1),
    }

    # Add to training pool and maybe retrain
    with _lock:
        _training_data.append(features)
        _sample_count += 1
        _maybe_retrain()

    # Rule-based thresholds (always active, no model needed)
    reasons = []
    if features[0] >= 10:
        reasons.append(f"High login rate: {int(features[0])} logins in {int(WINDOW)}s")
    if features[1] >= 5:
        reasons.append(f"Multiple failed logins: {int(features[1])}")
    if features[2] > 0 and features[2] < 2:
        reasons.append(f"Rapid login attempts: avg {features[2]:.1f}s apart")
    if features[3] >= 15:
        reasons.append(f"Connection request burst: {int(features[3])} in {int(WINDOW)}s")
    if features[3] > 0 and features[4] < 1:
        reasons.append(f"Rapid connection requests: avg {features[4]:.1f}s apart")

    # ML score (if model is ready)
    anomaly = len(reasons) > 0
    score = 0.0
    if _model is not None:
        X = np.array([features])
        score = float(_model.score_samples(X)[0])   # negative = anomalous
        pred  = _model.predict(X)[0]                # -1 = anomaly, 1 = normal
        if pred == -1:
            anomaly = True
            if not reasons:
                reasons.append(f"ML anomaly detected (score: {score:.3f})")

    # Risk level
    if features[1] >= 10 or features[0] >= 20 or features[3] >= 30:
        risk = "critical"
    elif features[1] >= 5 or features[0] >= 10 or features[3] >= 15 or (anomaly and score < -0.3):
        risk = "high"
    elif anomaly:
        risk = "medium"
    else:
        risk = "low"

    return {
        "anomaly":  anomaly,
        "score":    round(score, 4),
        "risk":     risk,
        "reasons":  reasons,
        "features": feat_dict,
    }


def reset_user(username: str):
    """Clear counters for a user (e.g. after manual review)."""
    with _lock:
        _login_attempts.pop(username, None)
        _failed_logins.pop(username, None)
        _conn_requests.pop(username, None)
        _file_transfers.pop(username, None)
        _last_seen.pop(username, None)
