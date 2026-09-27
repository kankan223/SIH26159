"""SecureMailScope — append-only audit trail for operator actions.

Events are one JSON object per line in config/audit.jsonl:
    {"ts": "...", "event": "...", "detail": "..."}

Append-only by design: entries are never rewritten or deleted, so the trail
survives restarts and retention sweeps. Recording must never break the
request path, so all I/O errors are swallowed.
"""
import json
import os
import threading
from datetime import datetime

AUDIT_PATH = os.path.join(os.path.dirname(__file__), "config", "audit.jsonl")
_LOCK = threading.Lock()


def record(event, detail):
    """Append one event; returns the stored entry."""
    entry = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "detail": detail,
    }
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
        with _LOCK:
            with open(AUDIT_PATH, "a") as f:
                f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # audit must not break the request path
    return entry


def read_all():
    """All events, oldest first (for export). Torn lines skipped."""
    try:
        with _LOCK, open(AUDIT_PATH) as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def tail(limit=400):
    """Newest-first view of the last `limit` events."""
    try:
        with _LOCK, open(AUDIT_PATH) as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue  # skip torn/corrupt lines
        if len(out) >= limit:
            break
    return out
