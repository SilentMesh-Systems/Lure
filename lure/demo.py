"""`lure demo`: see Lure catch someone in under a minute, on one machine.

Plants a bait set in a temporary folder pointing at 127.0.0.1, starts the
listener and the dashboard on high ports, then plays an attacker who finds
the baits and tries them one by one. Nothing leaves the machine.
"""

import asyncio
import base64
import json
import os
import socket
import tempfile
import threading
import time
import urllib.request
import webbrowser

from .generate import generate
from .listen import Alerter, run
from .ui import serve


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _say(text, pause=1.2):
    print(text, flush=True)
    time.sleep(pause)


def _attack(manifest, http, rdp):
    baits = manifest["baits"]
    pick = lambda pred: next(b for b in baits if pred(b))
    git = pick(lambda b: b["file"] == ".git-credentials")
    sheet = pick(lambda b: b["file"].endswith(".xlsx") and b["service"] == "http")
    rdp_bait = pick(lambda b: b["service"] == "rdp")
    qr = pick(lambda b: b.get("path_token") and b["file"].endswith(".png"))

    def http_login(user, path):
        req = urllib.request.Request(f"http://127.0.0.1:{http}{path}", headers={
            "Authorization": "Basic " + base64.b64encode(f"{user}:guess".encode()).decode()})
        try:
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass

    _say("\n[attacker] Lands on a workstation and goes looking for saved passwords...", 2)
    _say(f"[attacker] Finds .git-credentials in a home directory and tries it: git login as {git['username']}")
    http_login(git["username"], "/it/infra-scripts.git/info/refs")
    _say(f"[attacker] Opens {sheet['file']} on the file share and tries a login: {sheet['username']}")
    http_login(sheet["username"], "/nas")
    _say(f"[attacker] Scans the QR on the helpdesk notice: {qr['file']}")
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{http}/q/{qr['path_token']}", timeout=3)
    except Exception:
        pass
    _say(f"[attacker] Double-clicks {rdp_bait['file']} and tries Remote Desktop as {rdp_bait['username']}")
    with socket.create_connection(("127.0.0.1", rdp), timeout=3) as s:
        s.sendall(b"\x03\x00\x00\x2f\x2a\xe0\x00\x00\x00\x00\x00Cookie: mstshash="
                  + rdp_bait["username"].encode() + b"\r\n\x01\x00\x08\x00\x03\x00\x00\x00")
    time.sleep(1)


def demo(open_browser=True, keep=False):
    d = tempfile.mkdtemp(prefix="lure-demo-")
    http, rdp, vpn, ui_port = _free_port(), _free_port(), _free_port(), _free_port()
    m = generate("127.0.0.1", d, http_port=http, rdp_port=rdp, vpn_port=vpn)
    files = sorted({b["file"] for b in m["baits"]})
    print(f"\nLure demo: {len(m['baits'])} bait credentials in {len(files)} files, planted in {d}")
    for f in files:
        print(f"  {f}")
    alerter = Alerter(m, out=lambda line: print("  ALERT " + line, flush=True),
                      log=os.path.join(d, "alerts.jsonl"))
    serve(alerter, "127.0.0.1", ui_port)
    url = f"http://127.0.0.1:{ui_port}/"
    print(f"\nDashboard: {url}")
    loop_ready = threading.Event()

    def listener():
        async def main():
            loop_ready.set()
            await run(alerter, rdp, http, openvpn_ports=[vpn])
        try:
            asyncio.run(main())
        except Exception:
            pass

    threading.Thread(target=listener, daemon=True).start()
    loop_ready.wait(5)
    time.sleep(1)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    _attack(m, http, rdp)
    state = alerter.state()
    path = next(iter(state["paths"].values()), [])
    print("\nWhat Lure saw:")
    print(f"  {len([a for a in state['alerts'] if a['severity'] == 'high'])} high alerts, attacker path: "
          + " -> ".join(s["file"] for s in path))
    print(f"\nOpening, copying or scanning the files never fired anything. Only using a credential did.")
    if keep:
        print(f"Dashboard stays up at {url}. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    print("\nNext: lure generate --listener <spare machine IP> --out baits   (see README)")
    return state
