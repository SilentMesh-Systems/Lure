"""`lure init`: a first install with no decisions, on the machine you are sitting at.

Finds this machine's address, writes a bait set that points at it, and prints
the two commands that finish the job. Everything can be changed later with
`lure generate`; this exists so the first ten minutes need no reading.
"""

import os
import socket
import sys

from .generate import generate

def cmd():
    """How this user runs Lure: `lure` when installed, `python3 -m lure` from a clone."""
    return "lure" if os.path.basename(sys.argv[0]) in ("lure", "lure.exe", "silentmesh-lure") else "python3 -m lure"


GUIDE_TEMPLATE = """
Three commands, one machine:

  {c} demo            see Lure catch a simulated attacker (nothing leaves this machine)
  {c} init            write real baits pointing at this machine; it tells you the next step
  {c} listen --ui     wait for someone to use one; the dashboard opens on http://127.0.0.1:8765

Then prove it from another terminal or machine:  {c} test

Everything else (profiles, log watching, DNS and AWS baits, MCP for AI agents):
  {c} --help   or   https://github.com/SilentMesh-Systems/Lure#readme
"""


def guide():
    return GUIDE_TEMPLATE.replace("{c}", cmd())


def my_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # no packet is sent; the OS just picks the outbound interface
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def init(out_dir="baits", listener=None, profile="it", out=print):
    manifest = os.path.join(out_dir, "manifest.json")
    if os.path.exists(manifest):
        out(f"{manifest} already exists. Use `lure rotate` for fresh baits, or `lure init --out other-folder`.")
        return None
    c = cmd()
    host = listener or my_ip()
    m = generate(host, out_dir, profile=profile)
    files = sorted({b["file"] for b in m["baits"]})
    out(f"wrote {len(files)} bait files to {out_dir}/, every login in them points at {host}")
    for f in files:
        out(f"  {f}")
    out("")
    out("Next:")
    if host.startswith("127."):
        out("note: no network address found, so these baits point at this machine only. Re-run with --listener <this machine's LAN IP> to catch use from other machines.")
    out(f"  1. Start the listener here, in this terminal:   {c} listen --manifest {manifest} --ui")
    out(f"  2. Prove it, from another terminal:             {c} test --manifest {manifest}")
    out(f"  3. Copy a bait or two to a machine an intruder would reach (a desktop, a share), then tell Lure where:")
    example = next((f for f in files if f.endswith(".rdp")), files[0])
    out(f"     {c} record \"{example}\" \"HOSTNAME:C:\\Users\\someone\\Desktop\"")
    out("")
    out(f"Keep {manifest} on this machine only; it maps usernames to baits (it holds no passwords).")
    out("Alerts to Slack, Teams or syslog: add --webhook URL or --syslog HOST to `lure listen`.")
    return m
