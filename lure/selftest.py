"""`lure test`: prove the whole chain works, from bait to alert, in seconds.

Plays an attacker from this machine: tries one RDP bait and one HTTP bait
against the listener, then tells you what to expect in your terminal, webhook
or syslog. Run on the listener host and it also confirms the alert was written.
"""

import base64
import json
import os
import socket
import time
import urllib.request


def _rdp(host, port, username):
    body = b"\xe0\x00\x00\x00\x00\x00Cookie: mstshash=" + username.encode() + b"\r\n\x01\x00\x08\x00\x03\x00\x00\x00"
    x224 = bytes([len(body)]) + body
    pkt = b"\x03\x00" + (4 + len(x224)).to_bytes(2, "big") + x224
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(pkt)


def _http(host, port, username, path="/"):
    auth = base64.b64encode(f"{username}:test".encode()).decode()
    req = urllib.request.Request(f"http://{host}:{port}{path}", headers={"Authorization": "Basic " + auth})
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except urllib.error.HTTPError:
        pass  # 401 is the expected reply from a decoy


def _count(log):
    try:
        with open(log) as f:
            return sum(1 for _ in f)
    except OSError:
        return None


def run(manifest_path, listener=None, rdp=3389, http=8080, out=print):
    with open(manifest_path) as f:
        m = json.load(f)
    host = listener or m["listener"]
    live = [b for b in m["baits"] if not b.get("retired")]
    pick = {}
    for b in live:
        if b["service"] in ("rdp", "http") and b["service"] not in pick and not b.get("path_token"):
            pick[b["service"]] = b
    if not pick:
        raise SystemExit("lure test: the manifest has no RDP or HTTP baits to try")
    log = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), "alerts.jsonl")
    before = _count(log)
    results = []
    for service, b in pick.items():
        port = rdp if service == "rdp" else http
        try:
            (_rdp if service == "rdp" else _http)(host, port, b["username"])
            results.append((service, port, b, None))
        except OSError as e:
            results.append((service, port, b, e))
    out(f"lure test: tried {len(results)} bait login(s) against {host}")
    ok = 0
    for service, port, b, err in results:
        if err:
            out(f"  FAIL {service.upper()} {host}:{port}  ({err}). Is `lure listen` running there, and is the port open?")
        else:
            ok += 1
            out(f"  sent {service.upper()} login as {b['username']}  (from {b['file']})")
    if not ok:
        return False
    sent = [b for _, _, b, err in results if not err]
    time.sleep(1.5)
    after = _count(log)
    if after is not None and after > (before or 0):
        with open(log) as f:
            last = json.loads(f.readlines()[-1])
        out(f"  alert written: {last.get('severity', '?')} {last.get('username') or ''} from {last.get('source', '')} -> {log}")
        out("  If a webhook or syslog is configured, the same alert is already there.")
    elif after is None:
        out("  This machine does not hold alerts.jsonl, so check the listener terminal, your Slack/Teams channel or syslog now.")
        out(f"  Expect one HIGH alert naming {sent[0]['username']} from this machine's address.")
    else:
        out(f"  No new line in {log} yet. If the listener runs on another host, check there, your webhook or syslog.")
        out(f"  If it runs here, the login reached the port but no alert was raised: check the listener terminal for {sent[0]['username']}.")
    out("  Nothing in production was touched. These are bait accounts; they do not exist anywhere real.")
    return True
