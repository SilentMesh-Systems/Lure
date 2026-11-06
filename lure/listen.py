"""Listen on the bait ports and raise an alert when a bait credential is used.

Run it on a host nothing legitimate ever logs into. Every connection is
suspicious; a connection that carries a bait username says exactly which
bait file was found. Alerts go only to endpoints you configure (a webhook,
syslog, or stdout). Nothing is sent anywhere else.
"""

import asyncio
import base64
import json
import re
import socket
import threading
import time
import urllib.request
from datetime import datetime, timezone

RDP_COOKIE = re.compile(rb"Cookie: mstshash=([^\r\n]+)")
HTTP_AUTH = re.compile(rb"Authorization: Basic ([A-Za-z0-9+/=]+)", re.I)


def parse_rdp(data):
    m = RDP_COOKIE.search(data)
    return m.group(1).decode("utf-8", "replace").strip() if m else None


def parse_http(data):
    m = HTTP_AUTH.search(data)
    if not m:
        return None
    try:
        user = base64.b64decode(m.group(1)).decode("utf-8", "replace").split(":", 1)[0]
    except ValueError:
        return None
    return user or None


class Alerter:
    """Dedupes and rate-limits, then fans out to the configured sinks."""

    def __init__(self, manifest, webhook=None, syslog=None, window=600, max_per_window=20, out=print, log=None):
        self.by_user = {b["username"]: b for b in manifest.get("baits", [])}
        # Services whose username cannot be read (OpenVPN) are identified by port.
        self.by_port = {b["port"]: b for b in manifest.get("baits", []) if b.get("port")}
        self.webhook, self.syslog, self.out = webhook, syslog, out
        self.window, self.max_per_window = window, max_per_window
        self.seen = {}
        self.sent = []
        self.manifest = manifest
        self.log = log
        self.lock = threading.Lock()
        self.history = []
        if log:
            try:
                with open(log) as f:
                    self.history = [json.loads(line) for line in f if line.strip()]
            except FileNotFoundError:
                pass

    def event(self, service, src_ip, src_port, username, now=None, local_port=None):
        now = time.time() if now is None else now
        bait = self.by_user.get(username) if username else None
        if bait is None and username is None and local_port in self.by_port:
            bait = self.by_port[local_port]
            username = bait["username"]
        ev = {
            "time": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds"),
            "severity": "high" if bait else "medium",
            "service": service,
            "source": f"{src_ip}:{src_port}",
            "username": username,
            "bait_file": bait["file"] if bait else None,
            "planted_on": bait["plant_on"] if bait else None,
            "location": bait.get("location") if bait else None,
            "why": ("a bait credential was used: someone found and tried it" if bait else
                    "a connection reached the listener host, which nothing legitimate uses"),
        }
        key = (src_ip, service, username)
        if now - self.seen.get(key, -1e18) < self.window:
            return None
        self.sent = [t for t in self.sent if now - t < self.window]
        if len(self.sent) >= self.max_per_window:
            return None
        self.seen[key] = now
        self.sent.append(now)
        self._emit(ev)
        return ev

    def acknowledge(self, alert_id):
        with self.lock:
            for ev in self.history:
                if ev.get("id") == alert_id:
                    ev["acknowledged"] = True
                    if self.log:
                        with open(self.log, "w") as f:
                            f.writelines(json.dumps(e) + "\n" for e in self.history)
                    return True
        return False

    def state(self):
        with self.lock:
            alerts = list(reversed(self.history))
        fired = {a["username"] for a in alerts if a.get("severity") == "high"}
        baits = [dict(b, triggered=b["username"] in fired) for b in self.manifest.get("baits", [])]
        return {"baits": baits, "alerts": alerts}

    def _emit(self, ev):
        line = json.dumps(ev)
        with self.lock:
            ev = dict(ev, id=len(self.history) + 1, acknowledged=False)
            self.history.append(ev)
            if self.log:
                with open(self.log, "a") as f:
                    f.write(json.dumps(ev) + "\n")
        self.out(line)
        try:
            import sys; sys.stdout.flush()
        except Exception:
            pass
        if self.webhook:
            try:
                req = urllib.request.Request(self.webhook, data=line.encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except OSError as e:
                self.out(json.dumps({"error": f"webhook failed: {e}"}))
        if self.syslog:
            host, _, port = self.syslog.partition(":")
            msg = f"<10>lure: {line}".encode()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(msg, (host, int(port or 514)))


async def _serve(alerter, service, port, parser, reply):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        sock = writer.get_extra_info("sockname") or ("?", port)
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
        except (asyncio.TimeoutError, ConnectionError):
            data = b""
        alerter.event(service, peer[0], peer[1], parser(data) if parser else None, local_port=sock[1])
        try:
            if reply:
                writer.write(reply)
                await writer.drain()
        finally:
            writer.close()

    return await asyncio.start_server(handle, "0.0.0.0", port)


HTTP_401 = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"SCADA\"\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n")


async def run(alerter, rdp=3389, http=8080, openvpn=1194, openvpn_ports=None):
    ports = sorted(set(openvpn_ports or [openvpn]))
    servers = [
        await _serve(alerter, "rdp", rdp, parse_rdp, None),
        await _serve(alerter, "http", http, parse_http, HTTP_401),
    ] + [await _serve(alerter, "openvpn", p, None, None) for p in ports]
    await asyncio.gather(*(s.serve_forever() for s in servers))

