import json
import queue
import threading
import time

from config import LOG_MAX

_lock       = threading.Lock()
_sse_clients: list[queue.Queue] = []
_monitor_log: list[dict]        = []


def add_log(step: int, event: str, peer: str, detail: str, level: str = "info") -> dict:
    entry = {
        "time":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "step":   step,
        "event":  event,
        "peer":   peer,
        "detail": detail,
        "level":  level,
    }
    with _lock:
        _monitor_log.append(entry)
        if len(_monitor_log) > LOG_MAX:
            _monitor_log.pop(0)
    push("monitor", entry)
    return entry


def get_logs(last_n: int = 200) -> list[dict]:
    with _lock:
        return list(_monitor_log[-last_n:])


def push(event_type: str, data: dict):
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    # Critical events that must not be dropped
    critical = event_type in ("req_update", "session", "peers")
    dead = []
    with _lock:
        clients = list(_sse_clients)
    for q in clients:
        try:
            q.put_nowait(msg)
        except queue.Full:
            if critical:
                # Drain one old item to make room for critical event
                try:
                    q.get_nowait()
                    q.put_nowait(msg)
                except Exception:
                    dead.append(q)
            else:
                dead.append(q)
    if dead:
        with _lock:
            for q in dead:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass


def new_client_queue() -> queue.Queue:
    q = queue.Queue(maxsize=500)
    with _lock:
        _sse_clients.append(q)
    return q


def remove_client_queue(q: queue.Queue):
    with _lock:
        try:
            _sse_clients.remove(q)
        except ValueError:
            pass


def client_count() -> int:
    with _lock:
        return len(_sse_clients)
