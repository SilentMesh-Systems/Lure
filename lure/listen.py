"""Listen on the bait ports and raise an alert when a bait credential is used.

Run it on a host nothing legitimate ever logs into. Every connection is
suspicious; a connection that carries a bait username says exactly which
bait file was found. Alerts go only to endpoints you configure (a webhook,
syslog, email, a desktop popup or stdout). Alert contents never go anywhere else;
anonymous usage counts are described in telemetry.py.
"""

import asyncio
import base64
import json
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .explain import explain, short_who

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


def alert_text(ev, bold=False):
    """The alert as a short message a person can act on."""
    head, _ = _summary(ev)
    x = ev.get("explain") or explain(ev)
    lines = [f"*{head}*" if bold else head, "Who: " + x["who"], "What: " + x["what"], "How: " + x["how"], "Next:"]
    d = ev.get("depth")
    if d and (d["baits_used"] > 1 or d["after_warning"]):
        lines.append(f"Same source: {d['baits_used']} bait(s), {d['attempts']} attempt(s)"
                     + (", re-entered after the warning banner" if d["after_warning"] else ""))
    lines += [f"  {i}. {step}" for i, step in enumerate(x["next"], 1)]
    lines.append(f"{ev.get('time')} · severity {ev.get('severity')}")
    return head, "\n".join(lines)


def _ntfy(url):
    """ntfy wants the topic in the body when it gets JSON: split https://host/topic."""
    u = urllib.parse.urlsplit(url)
    if "ntfy" not in u.netloc:
        return None
    topic = u.path.strip("/")
    return (f"{u.scheme}://{u.netloc}/", topic) if topic and "/" not in topic else None


def webhook_payload(url, ev):
    """Shape the alert for the webhook's platform; plain JSON for everything else."""
    head, text = alert_text(ev, bold="slack" in url)
    where = ev.get("location") or ev.get("planted_on") or ""
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
    nt = _ntfy(url)
    if nt:
        return {"topic": nt[1], "title": head, "message": text, "priority": 5 if ev.get("severity") == "high" else 3,
                "tags": ["warning"]}
    return ev


def _incidents(alerts):
    """One incident per source address: what they did, in order, and what to do now."""
    by_ip = {}
    for a in reversed(alerts):
        by_ip.setdefault(a["source"].rsplit(":", 1)[0], []).append(a)
    out = []
    for ip, evs in by_ip.items():
        highs = [e for e in evs if e.get("severity") == "high"]
        last = (highs or evs)[-1]
        out.append({
            "source": ip, "who": last["explain"]["who"], "from": short_who(ip), "baits": len({e["bait_file"] for e in highs}),
            "first": evs[0]["time"], "last": evs[-1]["time"], "severity": "high" if highs else "medium",
            "steps": [{"time": e["time"], "how": e["explain"]["how"], "service": e.get("service"),
                       "attack": e["explain"].get("attack"), "bait": e.get("bait_file")} for e in evs],
            "next": last["explain"]["next"], "ids": [e["id"] for e in evs],
            "handled": all(e.get("acknowledged") for e in evs), "demo": any(e.get("demo") for e in evs)})
    open_ = sorted([i for i in out if not i["handled"]], key=lambda i: i["last"], reverse=True)
    done = sorted([i for i in out if i["handled"]], key=lambda i: i["last"], reverse=True)
    return open_ + done


def _channel_name(url):
    if not url:
        return None
    host = urllib.parse.urlsplit(url).netloc
    for key, name in (("slack", "Slack"), ("discord", "Discord"), ("telegram", "Telegram"), ("ntfy", "ntfy"),
                      ("office", "Teams"), ("logic.azure", "Teams")):
        if key in host:
            return name
    return host or "webhook"


def _files(baits):
    """Baits grouped by file: the spreadsheet holds several logins but is one thing to plant."""
    files = {}
    for b in baits:
        f = files.setdefault(b["file"], {"file": b["file"], "plant_on": b.get("plant_on"), "location": b.get("location"),
                                         "logins": 0, "used": False, "retired": bool(b.get("retired"))})
        f["logins"] += 1
        f["used"] = f["used"] or b.get("triggered", False)
        f["location"] = f["location"] or b.get("location")
        if "(" in (f["plant_on"] or "") and " row)" in f["plant_on"]:
            f["plant_on"] = f["plant_on"].split(" (")[0]
    return list(files.values())


def smtplib_error():
    import smtplib
    return smtplib.SMTPException


class Alerter:
    """Dedupes and rate-limits, then fans out to the configured sinks."""

    def __init__(self, manifest, webhook=None, syslog=None, window=600, max_per_window=20, out=print, log=None,
                 merge_window=0, desktop=False, email=None, demo=False):
        self.by_user = {b["username"]: b for b in manifest.get("baits", [])}
        # Services whose username cannot be read (OpenVPN) are identified by port.
        # Only live baits own a port; a rotated set reuses the same ports.
        self.by_port = {b["port"]: b for b in manifest.get("baits", []) if b.get("port") and not b.get("retired")}
        self.webhook, self.syslog, self.out = webhook, syslog, out
        self.desktop, self.email, self.demo = desktop, email, demo
        self.update_available = None
        self.started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.syslog_on = bool(syslog)
        self.listen_info = {"listener": manifest.get("listener"), "ports": {}}
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
        # (source ip, username) of HTTP bait logins answered with the warning banner.
        self.warned = set()
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
                    "an AWS bait key was used: someone found it and called AWS with it"
                    if bait and service == "aws" else
                    "a retired bait was used: it was taken before the last rotation and is still being tried"
                    if bait and bait.get("retired") else
                    "a bait credential was used: someone found and tried it" if bait else
                    "an unknown login was tried on the listener host, which nothing legitimate uses" if username else
                    "a connection reached the listener host, which nothing legitimate uses"),
        }
        if source_detail:
            ev["detail"] = source_detail
        if self.demo:
            ev["demo"] = True
        ev["explain"] = explain(ev)
        key = (src_ip, service, username)
        after_warning = bool(bait) and service == "http" and (src_ip, username) in self.warned
        if after_warning:
            # The same bait login was sent again after the warning banner: let it through once.
            self.warned.discard((src_ip, username))
            ev["after_warning"] = True
            ev["why"] = ("a bait credential was entered again after a written warning that the system "
                         "is for authorised personnel only")
        elif now - self.seen.get(key, -1e18) < self.window:
            return None
        self.sent = [t for t in self.sent if now - t < self.window]
        if len(self.sent) >= self.max_per_window:
            return None
        self.seen[key] = now
        self.sent.append(now)
        if bait is not None:
            if service == "http" and not after_warning:
                self.warned.add((src_ip, username))
            ev.update(self._evidence(src_ip, ev))
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

    def _evidence(self, src_ip, ev):
        """Engagement depth for this source and what the alert does and does not show."""
        with self.lock:
            prior = [a for a in self.history if a.get("severity") == "high"
                     and a["source"].rsplit(":", 1)[0] == src_ip]
        files = []
        for a in prior + [ev]:
            if a.get("bait_file") and a["bait_file"] not in files:
                files.append(a["bait_file"])
        warned = any(a.get("after_warning") for a in prior) or ev.get("after_warning", False)
        return {
            "depth": {"baits_used": len(files), "attempts": len(prior) + 1,
                      "order": files, "after_warning": warned},
            "evidence": {
                "observed": f"{len(prior) + 1} bait login(s) from {src_ip}, {len(files)} distinct bait(s)"
                            + (", repeated after a warning" if warned else ""),
                "can_conclude": "someone at or behind this address found bait credentials and tried them",
                "cannot_conclude": "who the person is or their motive; the address may be a NAT, VPN or "
                                   "compromised pivot host; baits found but never tried are not seen",
            },
        }

    def _flush_pending(self, src_ip):
        with self.lock:
            held = self.pending.pop(src_ip, None)
        if held:
            self._emit(held[0])

    def acknowledge(self, alert_id):
        ids = set(alert_id) if isinstance(alert_id, (list, tuple, set)) else {alert_id}
        with self.lock:
            hit = False
            for ev in self.history:
                if ev.get("id") in ids:
                    ev["acknowledged"] = hit = True
            if hit and self.log:
                with open(self.log, "w") as f:
                    f.writelines(json.dumps(e) + "\n" for e in self.history)
        return hit

    def state(self):
        with self.lock:
            alerts = [a if "explain" in a else dict(a, explain=explain(a)) for a in reversed(self.history)]
        fired = {a["username"] for a in alerts if a.get("severity") == "high"}
        baits = [dict(b, triggered=b["username"] in fired) for b in self.manifest.get("baits", [])
                 if not b.get("retired") or b["username"] in fired]
        # The attacker's path: per source address, the baits used, oldest first.
        paths, depth = {}, {}
        for a in reversed(alerts):
            if a.get("severity") == "high":
                ip = a["source"].rsplit(":", 1)[0]
                step = {"time": a["time"], "file": a["bait_file"], "service": a["service"]}
                if not paths.get(ip) or paths[ip][-1]["file"] != step["file"]:
                    paths.setdefault(ip, []).append(step)
                d = depth.setdefault(ip, {"baits_used": 0, "attempts": 0, "after_warning": False, "_f": set()})
                d["attempts"] += 1
                d["_f"].add(a["bait_file"])
                d["baits_used"] = len(d["_f"])
                d["after_warning"] = d["after_warning"] or bool(a.get("after_warning"))
        for d in depth.values():
            d.pop("_f")
        return {"baits": baits, "alerts": alerts, "paths": paths, "demo": self.demo, "update": self.update_available,
                "incidents": _incidents(alerts), "files": _files(baits), "since": self.started, "listening": self.listen_info, "profile": self.manifest.get("profile"),
                "channels": {"desktop": bool(self.desktop), "email": (self.email or {}).get("to"),
                             "webhook": _channel_name(self.webhook), "syslog": self.syslog_on}, "depth": depth}

    def heartbeat(self, started=False, now=None):
        """Tell the user Lure is still listening, so silence never means 'is it broken?'."""
        now = time.time() if now is None else now
        with self.lock:
            since = getattr(self, "_last_beat", None)
            recent = [a for a in self.history
                      if since is None or datetime.fromisoformat(a["time"]).timestamp() >= since]
            self._last_beat = now
        live = [b for b in self.manifest.get("baits", []) if not b.get("retired")]
        files = len({b["file"] for b in live})
        where = self.listen_info.get("listener") or "this machine"
        if started:
            title = "Lure is listening"
            text = f"Started on {where}. {files} bait files armed. You will get a short message like this every week."
        else:
            new = [a for a in recent if a.get("severity") == "high"]
            title = "Lure is still listening"
            text = (f"Listening on {where}. {files} bait files armed. "
                    + (f"{len(new)} bait login(s) since the last check; see the dashboard." if new
                       else "No bait has been used since the last check. All quiet."))
        self.out(json.dumps({"heartbeat": title, "message": text}))
        if self.webhook:
            try:
                nt = _ntfy(self.webhook)
                req = urllib.request.Request(nt[0] if nt else self.webhook,
                                             data=json.dumps(text_payload(self.webhook, title, text)).encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except OSError as e:
                self.out(json.dumps({"error": f"heartbeat webhook failed: {e}"}))
        if self.desktop:
            from .notify import desktop
            try:
                desktop(title, text)
            except Exception as e:
                self.out(json.dumps({"error": f"heartbeat popup failed: {e}"}))
        if self.email:
            from .notify import email
            try:
                email(self.email, title, text)
            except (OSError, smtplib_error()) as e:
                self.out(json.dumps({"error": f"heartbeat email failed: {e}"}))
        return title, text

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
        from . import telemetry
        telemetry.send("alert", {"severity": ev.get("severity"), "service": (ev.get("service") or "").split(":")[0],
                                 "demo": bool(ev.get("demo"))})
        if self.webhook:
            try:
                nt = _ntfy(self.webhook)
                req = urllib.request.Request(nt[0] if nt else self.webhook,
                                             data=json.dumps(webhook_payload(self.webhook, ev)).encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except OSError as e:
                self.out(json.dumps({"error": f"webhook failed: {e}"}))
        if self.desktop or self.email:
            head, text = alert_text(ev)
            if self.desktop:
                from .notify import desktop
                x = ev["explain"]
                try:
                    desktop("Lure: " + head, x["who"] + " " + x["how"])
                except Exception as e:
                    self.out(json.dumps({"error": f"desktop popup failed: {e}"}))
            if self.email:
                from .notify import email
                try:
                    email(self.email, "Lure alert: " + head, text)
                except (OSError, smtplib_error()) as e:
                    self.out(json.dumps({"error": f"email failed: {e}"}))
        if self.syslog:
            host, _, port = self.syslog.partition(":")
            msg = f"<10>lure: {line}".encode()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(msg, (host, int(port or 514)))


def text_payload(url, title, text):
    """A plain message (not an alert) shaped for the webhook's platform."""
    if "hooks.slack.com" in url:
        return {"text": f"*{title}*\n{text}"}
    if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
        return {"username": "Lure", "content": f"{title}\n{text}"}
    if "office.com" in url or "webhook.office" in url or "logic.azure.com" in url:
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": title, "title": title, "text": text}
    if "api.telegram.org" in url:
        return {"text": f"{title}\n{text}"}
    nt = _ntfy(url)
    if nt:
        return {"topic": nt[1], "title": title, "message": text, "priority": 2}
    return {"type": "heartbeat", "title": title, "message": text}


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


WARNING_BODY = (b"<html><body><h1>Authorised personnel only</h1>"
                b"<p>This system is restricted. Access attempts are logged. If you are not authorised, "
                b"do not continue. Re-enter your credentials to confirm you are authorised.</p></body></html>")
HTTP_401 = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"SCADA - authorised personnel "
            b"only, access is logged. Re-enter credentials to confirm\"\r\nContent-Type: text/html\r\n"
            b"Content-Length: " + str(len(WARNING_BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + WARNING_BODY)


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

