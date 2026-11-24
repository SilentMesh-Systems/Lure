"""The alert log (alerts.jsonl): append-only, shared safely by every Lure process.

`lure listen`, `lure watch`, `lure aws watch` and the MCP server can all write to the same file. Earlier versions
numbered alerts 1, 2, 3 per process (ids collided) and acknowledged an alert by rewriting the whole file (which
erased lines another process had just appended). Now:

- every alert line gets an id from the clock, unique across processes and restarts;
- acknowledging appends a small record {"type": "ack", "ids": [...]} instead of rewriting anything;
- readers apply those records, and skip lines they cannot parse.

Lines are written with one write() call in append mode, so concurrent writers do not interleave within a line.
"""

import json
import os
import threading
import time

_lock = threading.Lock()
_last_id = 0


def new_id():
    """A positive integer id, increasing, unique across processes (microseconds since 1970).
    Fits exactly in a JavaScript number, so the dashboard can use it."""
    global _last_id
    with _lock:
        candidate = time.time_ns() // 1000
        _last_id = max(candidate, _last_id + 1)
        return _last_id


def _append(path, record):
    line = (json.dumps(record) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def append_alert(path, ev):
    _append(path, ev)


def append_ack(path, ids, by="lure"):
    _append(path, {"type": "ack", "ids": sorted(set(ids)), "time": int(time.time()), "by": by})


def parse_lines(lines):
    """Alerts (with acknowledgements applied) and the lines that could not be read."""
    alerts, acked, bad = [], set(), []
    for line in lines:
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            bad.append(line)
            continue
        if not isinstance(rec, dict):
            bad.append(line)
        elif rec.get("type") == "ack":
            acked.update(i for i in rec.get("ids", []) if isinstance(i, int))
        else:
            alerts.append(rec)
    for a in alerts:
        if a.get("id") in acked:
            a["acknowledged"] = True
    return alerts, acked, bad


def read(path):
    """All alerts in the log with acknowledgements applied. Missing file: empty list."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            alerts, _, _ = parse_lines(f)
    except FileNotFoundError:
        return []
    return alerts


class Tail:
    """Reads what other processes appended since the last call."""

    def __init__(self, path, offset=0):
        self.path, self.offset = path, offset

    def new_lines(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read()
        except FileNotFoundError:
            return []
        end = data.rfind(b"\n") + 1          # only whole lines; a half-written line is read next time
        self.offset += end
        return data[:end].decode("utf-8", "replace").splitlines(True)
