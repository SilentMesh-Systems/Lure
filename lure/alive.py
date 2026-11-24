"""Tamper alarm: prove Lure is still running, so a killed or crashed listener cannot go unnoticed.

Silence from a deception tool looks the same whether nothing happened or someone switched it off. The weekly
heartbeat is too slow to catch that. This module pings a dead-man URL every few minutes (healthchecks.io,
Cronitor, Better Stack, Uptime Kuma push monitors and the like). That outside service raises the alarm when the
pings stop: Lure killed, crashed, or its machine down or cut off. It can also write a small "alive" file that
local monitoring can check for freshness.
"""

import json
import os
import threading
import time
import urllib.request


def beat(url=None, path=None, info=None, out=print, now=None):
    """One check-in. Returns True when every configured target succeeded."""
    ok = True
    stamp = time.time() if now is None else now
    if path:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(dict(info or {}, time=int(stamp), pid=os.getpid()), f)
            os.replace(tmp, path)
        except OSError as e:
            ok = False
            out(json.dumps({"error": f"alive file failed: {e}"}))
    if url:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "lure-alive"})
            urllib.request.urlopen(req, timeout=10).close()
        except (OSError, ValueError) as e:
            ok = False
            out(json.dumps({"error": f"alive ping failed: {e}"}))
    return ok


def start(url=None, path=None, every_minutes=5, info=None, out=print, sleep=time.sleep, stop=None):
    """Check in now, then every `every_minutes` on a background thread. Returns the thread (or None).
    `stop` (a threading.Event) ends the loop; tests use it."""
    if not (url or path):
        return None
    if every_minutes <= 0:
        raise ValueError("every_minutes must be more than 0")
    stop = stop or threading.Event()
    beat(url, path, info() if callable(info) else info, out)

    def loop():
        while not stop.is_set():
            sleep(every_minutes * 60)
            if stop.is_set():
                break
            try:
                beat(url, path, info() if callable(info) else info, out)
            except Exception as e:  # noqa: BLE001  the tamper alarm must keep running
                out(json.dumps({"error": f"alive check-in failed: {e}"}))

    t = threading.Thread(target=loop, name="lure-alive", daemon=True)
    t.start()
    return t
