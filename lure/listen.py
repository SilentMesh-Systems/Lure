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
HTTP_AUTH = re.compile(rb"^Authorization:[ \t]*Basic[ \t]+([A-Za-z0-9+/=]+)", re.I | re.M)
HTTP_DIGEST_USER = re.compile(rb'^Authorization:[ \t]*Digest[ \t].*?\busername[ \t]*=[ \t]*"([^"]{1,200})"', re.I | re.M)
# Field names a login form or JSON API commonly uses for the account name.
LOGIN_FIELDS = ("username", "user", "login", "email", "uname", "user_name", "userid", "user_id", "account",
                "j_username", "log", "name")
MAX_HTTP_HEAD, MAX_HTTP_BODY = 16384, 8192


def parse_rdp(data):
    m = RDP_COOKIE.search(data)
    return m.group(1).decode("utf-8", "replace").strip() if m else None


HTTP_PATH_TOKEN = re.compile(rb"^[A-Z]+ /(?:q|go|s)/([a-z0-9-]{4,40})[/?\s]", re.I)


def _login_from_fields(fields):
    """The account name from parsed form or JSON fields, if any login-like field is present."""
    lower = {str(k).lower(): v for k, v in fields.items()}
    for name in LOGIN_FIELDS:
        v = lower.get(name)
        if isinstance(v, list):
            v = v[0] if v else None
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v).strip()[:200]
    return None


def _login_from_body(head, body):
    ctype = (re.search(rb"^Content-Type:[ \t]*([^\r\n;]+)", head, re.I | re.M) or [None, b""])[1].strip().lower()
    text = body.decode("utf-8", "replace")
    if ctype == b"application/json" or text.lstrip().startswith("{"):
        try:
            obj = json.loads(text)
        except ValueError:
            return None
        if isinstance(obj, dict):
            return _login_from_fields(obj) or next(
                (_login_from_fields(v) for v in obj.values() if isinstance(v, dict) and _login_from_fields(v)), None)
        return None
    if ctype in (b"application/x-www-form-urlencoded", b"") or "=" in text:
        return _login_from_fields(urllib.parse.parse_qs(text, keep_blank_values=False))
    return None


def parse_http(data):
    """The login name in an HTTP request: Basic or Digest auth, a login form or JSON body, or a query string.
    Bookmarks and QR codes carry a token in the path instead (returned as '~token')."""
    head, _, body = data.partition(b"\r\n\r\n")
    m = HTTP_AUTH.search(head)
    if m:
        try:
            user = base64.b64decode(m.group(1)).decode("utf-8", "replace").split(":", 1)[0]
        except ValueError:
            user = None
        if user:
            return user
    m = HTTP_DIGEST_USER.search(head)
    if m:
        return m.group(1).decode("utf-8", "replace")
    if body.strip():
        user = _login_from_body(head, body)
        if user:
            return user
    first = head.split(b"\r\n", 1)[0]
    if b"?" in first:
        query = first.split(b" ")[1].split(b"?", 1)[1] if len(first.split(b" ")) > 1 else b""
        user = _login_from_fields(urllib.parse.parse_qs(query.decode("utf-8", "replace")))
        if user:
            return user
    # A token in the path: QR codes and bookmarks carry no login, only a URL.
    p = HTTP_PATH_TOKEN.search(head)
    return ("~" + p.group(1).decode().lower()) if p else None


async def read_http_request(reader, timeout=5):
    """Read a whole request: headers up to the blank line, then the body by Content-Length (both capped).
    One read() of 4 KB missed logins that came after large headers or arrived split across packets."""
    data = b""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while b"\r\n\r\n" not in data and len(data) < MAX_HTTP_HEAD:
        left = deadline - loop.time()
        if left <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=left)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    head, sep, body = data.partition(b"\r\n\r\n")
    if sep:
        m = re.search(rb"^Content-Length:[ \t]*(\d{1,9})", head, re.I | re.M)
        want = min(int(m.group(1)), MAX_HTTP_BODY) if m else 0
        while len(body) < want:
            left = deadline - loop.time()
            if left <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(want - len(body)), timeout=left)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            body += chunk
        data = head + sep + body[:MAX_HTTP_BODY]
    return data


def _summary(ev):
    if ev.get("service") == "flood":
        return "Burst of junk logins on the Lure listener", ""
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


def _slack_escape(t):
    """Slack treats <...> as links and mentions (<!channel>, <https://x|label>); escape so text stays text."""
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_MD = re.compile("([" + re.escape("\\`*_[]()<>#|~") + "])")


def _md_escape(t):
    """Neutralise Markdown/HTML in attacker-influenced text for Teams cards."""
    return _MD.sub(lambda m: "\\" + m.group(1), str(t))


def _safe_ev(ev):
    """A copy whose attacker-chosen fields (username, log detail) are shortened for display."""
    ev = dict(ev)
    changed = False
    for k in ("username", "detail"):
        if ev.get(k) and len(str(ev[k])) > 80:
            ev[k] = str(ev[k])[:80] + "..."
            changed = True
    if changed:
        ev["explain"] = explain(ev)
    return ev


def webhook_payload(url, ev):
    """Shape the alert for the webhook's platform; plain JSON for everything else.

    Login names and log lines in an alert are chosen by whoever touched the listener, so chat markup in them
    (Slack links and mentions, Discord @everyone, Teams Markdown) is escaped or disabled."""
    ev = _safe_ev(ev)
    head, text = alert_text(ev, bold="slack" in url)
    where = ev.get("location") or ev.get("planted_on") or ""
    if "hooks.slack.com" in url:
        body = _slack_escape(text)
        return {"text": body, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": body}},
                                         {"type": "context", "elements": [{"type": "mrkdwn", "text": "SilentMesh Lure · " + _slack_escape(ev.get("why", ""))}]}]}
    if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
        return {"username": "Lure", "content": text, "allowed_mentions": {"parse": []}}
    if "office.com" in url or "webhook.office" in url or "logic.azure.com" in url:
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions",
                "themeColor": "FF7A59" if ev.get("severity") == "high" else "F2C14E",
                "summary": head, "title": _md_escape(head),
                "sections": [{"facts": [{"name": k, "value": _md_escape(v)} for k, v in
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
        highs = [e for e in evs if e.get("severity") == "high" and e.get("bait_file")]
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
        # Low-value events dropped by the budget, and when the flood alert was last raised.
        self.suppressed = 0
        self.flood_reported = -1e18
        self._queue = None
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
        self.repaired = 0
        self._tail = None
        if log:
            from . import alertlog
            self._tail = alertlog.Tail(log)
            alerts, _, bad = alertlog.parse_lines(self._tail.new_lines())
            self.history = alerts
            if bad:
                # One damaged line (a crash mid-write, or tampering) must not stop Lure from starting. The log is
                # never rewritten (other Lure processes may be appending); bad lines are skipped and copied out
                # once for inspection.
                self.repaired = len(bad)
                seen = set()
                try:
                    with open(log + ".corrupt", errors="replace") as f:
                        seen = {line.rstrip("\r\n") for line in f}
                except FileNotFoundError:
                    pass
                new = [b.rstrip("\r\n") for b in bad if b.rstrip("\r\n") not in seen]
                if new:
                    with open(log + ".corrupt", "a", errors="replace") as f:
                        f.writelines(line + "\n" for line in new)
                self.out(json.dumps({"error": f"alert log: {len(bad)} unreadable line(s) skipped; "
                                              f"copies are in {log}.corrupt"}))

    def _sync(self):
        """Pick up alerts and acknowledgements that other Lure processes appended to the same log."""
        if not self._tail:
            return
        from . import alertlog
        alerts, acked, _ = alertlog.parse_lines(self._tail.new_lines())
        with self.lock:
            known = {e.get("id") for e in self.history}
            self.history.extend(a for a in alerts if a.get("id") not in known)
            if acked:
                for e in self.history:
                    if e.get("id") in acked:
                        e["acknowledged"] = True

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
        flood = None
        # The listener, log watchers, the DNS bait and the dashboard's test button all call event() from
        # different threads; dedupe, budget and warning state change together under one lock.
        with self.lock:
            after_warning = bool(bait) and service == "http" and (src_ip, username) in self.warned
            if after_warning:
                # The same bait login was sent again after the warning banner: let it through once.
                self.warned.discard((src_ip, username))
                ev["after_warning"] = True
                ev["why"] = ("a bait credential was entered again after a written warning that the system "
                             "is for authorised personnel only")
            elif now - self.seen.get(key, -1e18) < self.window:
                return None
            if bait is None:
                # Only events that carry no bait share the budget. A bait use is never dropped for budget
                # reasons: otherwise an intruder could send junk logins until the budget is gone, then use a
                # bait unseen.
                self.sent = [t for t in self.sent if now - t < self.window]
                if len(self.sent) >= self.max_per_window:
                    self.suppressed += 1
                    if now - self.flood_reported >= self.window:
                        self.flood_reported = now
                        flood = self._flood_event(now, src_ip, src_port)
                    else:
                        return None
                else:
                    self.sent.append(now)
            if flood is None:
                self.seen[key] = now
                if bait is not None and service == "http" and not after_warning:
                    self.warned.add((src_ip, username))
        if flood is not None:
            self._emit(flood)
            return None
        if bait is not None:
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

    def _flood_event(self, now, src_ip, src_port):
        """One alert when the low-value budget runs out: a burst like this can be an attempt to hide a real login."""
        ev = {
            "time": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds"),
            "severity": "high", "service": "flood", "source": f"{src_ip}:{src_port}", "username": None,
            "bait_file": None, "planted_on": None, "location": None, "retired": False,
            "why": (f"more than {self.max_per_window} unknown logins or connections in {self.window // 60} minutes: "
                    "someone may be flooding the listener to hide a real bait login. Bait logins are still alerted."),
            "suppressed": self.suppressed,
        }
        if self.demo:
            ev["demo"] = True
        ev["explain"] = explain(ev)
        return ev

    def _evidence(self, src_ip, ev):
        """Engagement depth for this source and what the alert does and does not show."""
        with self.lock:
            prior = [a for a in self.history if a.get("severity") == "high" and a.get("bait_file")
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
        self._sync()
        with self.lock:
            matched = [ev["id"] for ev in self.history if ev.get("id") in ids]
            for ev in self.history:
                if ev.get("id") in ids:
                    ev["acknowledged"] = True
        if matched and self.log:
            # Appended, never a rewrite: other processes may be writing to the same log.
            from . import alertlog
            alertlog.append_ack(self.log, matched, by="dashboard")
        return bool(matched)

    def state(self):
        self._sync()
        with self.lock:
            alerts = [a if "explain" in a else dict(a, explain=explain(a)) for a in reversed(self.history)]
        fired = {a["username"] for a in alerts if a.get("severity") == "high" and a.get("bait_file")}
        baits = [dict(b, triggered=b["username"] in fired) for b in self.manifest.get("baits", [])
                 if not b.get("retired") or b["username"] in fired]
        # The attacker's path: per source address, the baits used, oldest first.
        paths, depth = {}, {}
        for a in reversed(alerts):
            if a.get("severity") == "high" and a.get("bait_file"):
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

    def heartbeat(self, started=False, now=None, every_days=7):
        """Tell the user Lure is still listening, so silence never means 'is it broken?'."""
        now = time.time() if now is None else now
        with self.lock:
            since = getattr(self, "_last_beat", None)
            recent = [a for a in self.history if since is None or _ts(a.get("time")) >= since]
            self._last_beat = now
        live = [b for b in self.manifest.get("baits", []) if not b.get("retired")]
        files = len({b["file"] for b in live})
        where = self.listen_info.get("listener") or "this machine"
        if started:
            title = "Lure is listening"
            every = "every week" if every_days == 7 else f"every {every_days:g} day(s)"
            text = f"Started on {where}. {files} bait files armed. You will get a short message like this {every}."
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
            except (OSError, ValueError) as e:
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
        from . import alertlog
        with self.lock:
            # Clock-based ids stay unique when listen, watch and aws watch share one log.
            ev = dict(ev, id=alertlog.new_id(), acknowledged=False)
            self.history.append(ev)
            if self.log:
                alertlog.append_alert(self.log, ev)
        self.out(line)
        try:
            import sys; sys.stdout.flush()
        except Exception:
            pass
        # Slow or broken channels (webhook, email, popup, syslog) must never hold up the listener: the reply to
        # the connection, and every other connection, would wait behind them. They run on a background worker.
        self._enqueue(ev, line)

    def _enqueue(self, ev, line):
        with self.lock:
            if self._queue is None:
                import queue
                self._queue = queue.Queue()
                threading.Thread(target=self._deliver_loop, name="lure-delivery", daemon=True).start()
                import atexit
                atexit.register(self.flush, 20)
        self._queue.put((ev, line))

    def _deliver_loop(self):
        while True:
            ev, line = self._queue.get()
            try:
                self._deliver(ev, line)
            except Exception as e:  # noqa: BLE001  a channel must never kill delivery of the next alert
                self.out(json.dumps({"error": f"alert delivery failed: {e}"}))
            finally:
                self._queue.task_done()

    def flush(self, timeout=None):
        """Wait until queued alerts have been delivered (or timeout seconds pass). Returns True when done."""
        q = self._queue
        if q is None:
            return True
        deadline = None if timeout is None else time.time() + timeout
        while q.unfinished_tasks:
            if deadline is not None and time.time() > deadline:
                return False
            time.sleep(0.02)
        return True

    def _deliver(self, ev, line):
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
            except (OSError, ValueError) as e:
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
            try:
                host, _, port = self.syslog.partition(":")
                msg = f"<10>lure: {line}".encode()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(msg, (host, int(port or 514)))
            except (OSError, ValueError) as e:
                self.out(json.dumps({"error": f"syslog failed: {e}"}))


def _ts(value):
    """Seconds since the epoch for an alert time; 0 if it is missing or unreadable."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


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
            if service == "http":
                data = await read_http_request(reader)
            else:
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

