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


HTTP_PATH_TOKEN = re.compile(rb"^[A-Z]+ /(?:q|go|s)/([a-z0-9-]{4,40})[/?\s]", re.I)


def parse_http(data):
    m = HTTP_AUTH.search(data)
    if not m:
        # A token in the path: QR codes and bookmarks carry no login, only a URL.
        p = HTTP_PATH_TOKEN.search(data)
        return ("~" + p.group(1).decode().lower()) if p else None
    try:
        user = base64.b64decode(m.group(1)).decode("utf-8", "replace").split(":", 1)[0]
    except ValueError:
        return None
    return user or None


def _summary(ev):
    if ev.get("severity") == "high":
        head = ("Retired bait used: " if ev.get("retired") else "Bait used: ") + str(ev.get("bait_file"))
    else:
        head = "Someone touched the Lure listener"
    where = ev.get("location") or ev.get("planted_on") or ""
    return head, where


def webhook_payload(url, ev):
    """Shape the alert for the webhook's platform; plain JSON for everything else."""
    head, where = _summary(ev)
    lines = [f"*{head}*" if "slack" in url else head]
    if where:
        lines.append(f"Planted: {where}")
    lines.append(f"From {ev.get('source')} over {ev.get('service')}" + (f" as {ev['username']}" if ev.get("username") else ""))
    lines.append(f"{ev.get('time')} · severity {ev.get('severity')}")
    text = "\n".join(lines)
    if "hooks.slack.com" in url:
        return {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}},
                                         {"type": "context", "elements": [{"type": "mrkdwn", "text": "SilentMesh Lure · " + ev.get("why", "")}]}]}
    if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
        return {"username": "Lure", "content": text}
    if "office.com" in url or "webhook.office" in url or "logic.azure.com" in url:
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions",
                "themeColor": "FF7A59" if ev.get("severity") == "high" else "F2C14E",
                "summary": head, "title": head,
                "sections": [{"facts": [{"name": k, "value": str(v)} for k, v in
                              [("Planted", where), ("Source", ev.get("source")), ("Service", ev.get("service")),
                               ("Username", ev.get("username")), ("Time", ev.get("time")), ("Why", ev.get("why"))] if v]}]}
    if "api.telegram.org" in url:
        return {"text": text}
    return ev


class Alerter:
    """Dedupes and rate-limits, then fans out to the configured sinks."""

    def __init__(self, manifest, webhook=None, syslog=None, window=600, max_per_window=20, out=print, log=None, merge_window=0):
        self.by_user = {b["username"]: b for b in manifest.get("baits", [])}
        # Services whose username cannot be read (OpenVPN) are identified by port.
        # Only live baits own a port; a rotated set reuses the same ports.
        self.by_port = {b["port"]: b for b in manifest.get("baits", []) if b.get("port") and not b.get("retired")}
        self.webhook, self.syslog, self.out = webhook, syslog, out
        self.window, self.max_per_window = window, max_per_window
        self.seen = {}
        self.sent = []
        self.manifest = manifest
        # Browsers and git first ask without a login, then retry with one. A bare
        # touch is held this many seconds and dropped if the same source then
        # uses a bait, so one intrusion makes one alert, not two.
        self.merge_window = merge_window
        self.pending = {}
        self.log = log
        self.lock = threading.Lock()
        self.history = []
        if log:
            try:
                with open(log) as f:
                    self.history = [json.loads(line) for line in f if line.strip()]
            except FileNotFoundError:
                pass

    def event(self, service, src_ip, src_port, username, now=None, local_port=None, source_detail=None):
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
            "retired": bool(bait and bait.get("retired")),
            "why": ("a bait username appeared in a real system's log: someone tried it against a real service"
                    if bait and service.startswith("log:") else
                    "a bait hostname was looked up: someone found it and tried to reach it"
                    if bait and service == "dns" else
                    "a retired bait was used: it was taken before the last rotation and is still being tried"
                    if bait and bait.get("retired") else
                    "a bait credential was used: someone found and tried it" if bait else
                    "an unknown login was tried on the listener host, which nothing legitimate uses" if username else
                    "a connection reached the listener host, which nothing legitimate uses"),
        }
        if source_detail:
            ev["detail"] = source_detail
        key = (src_ip, service, username)
        if now - self.seen.get(key, -1e18) < self.window:
            return None
        self.sent = [t for t in self.sent if now - t < self.window]
        if len(self.sent) >= self.max_per_window:
            return None
        self.seen[key] = now
        self.sent.append(now)
        if bait is None and username is None and self.merge_window:
            timer = threading.Timer(self.merge_window, self._flush_pending, (src_ip,))
            timer.daemon = True
            with self.lock:
                if src_ip in self.pending:
                    self.pending[src_ip][1].cancel()
                self.pending[src_ip] = (ev, timer)
            timer.start()
            return ev
        if bait is not None:
            with self.lock:
                held = self.pending.pop(src_ip, None)
            if held:
                held[1].cancel()
        self._emit(ev)
        return ev

    def _flush_pending(self, src_ip):
        with self.lock:
            held = self.pending.pop(src_ip, None)
        if held:
            self._emit(held[0])

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
        baits = [dict(b, triggered=b["username"] in fired) for b in self.manifest.get("baits", [])
                 if not b.get("retired") or b["username"] in fired]
        # The attacker's path: per source address, the baits used, oldest first.
        paths = {}
        for a in reversed(alerts):
            if a.get("severity") == "high":
                ip = a["source"].rsplit(":", 1)[0]
                step = {"time": a["time"], "file": a["bait_file"], "service": a["service"]}
                if not paths.get(ip) or paths[ip][-1]["file"] != step["file"]:
                    paths.setdefault(ip, []).append(step)
        return {"baits": baits, "alerts": alerts, "paths": paths}

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
                req = urllib.request.Request(self.webhook, data=json.dumps(webhook_payload(self.webhook, ev)).encode(),
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

    try:
        return await asyncio.start_server(handle, "0.0.0.0", port)
    except OSError as e:
        raise SystemExit(f"lure: cannot listen on port {port} for {service} ({e.strerror}). "
                         "Is another listener already running? Pick free ports with --rdp, --http, "
                         "or generate VPN baits with a different --vpn-port.") from None


HTTP_401 = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"SCADA\"\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n")


async def run(alerter, rdp=3389, http=8080, openvpn=1194, openvpn_ports=None, dns_zone=None, dns_port=53):
    ports = sorted(set(openvpn_ports or [openvpn]))
    servers = [
        await _serve(alerter, "rdp", rdp, parse_rdp, None),
        await _serve(alerter, "http", http, parse_http, HTTP_401),
    ] + [await _serve(alerter, "openvpn", p, None, None) for p in ports]
    if dns_zone:
        from .dnstoken import serve as serve_dns
        await serve_dns(alerter, dns_zone, dns_port)
    await asyncio.gather(*(s.serve_forever() for s in servers))

