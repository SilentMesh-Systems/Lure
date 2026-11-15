"""`lure init`: a first install on the machine you are sitting at.

Finds this machine's address, writes a bait set that points at it, and prints
the commands that finish the job. In a terminal it asks two questions (is this
a home or a work computer, and how do you want to be told); without a
terminal it uses the defaults, so scripts keep working.
"""

import os
import shutil
import socket
import sys

from .generate import generate


def cmd(sub=None):
    """How this user runs a Lure command: `lure` when installed, else through Python (py on Windows)."""
    if os.path.basename(sys.argv[0]) in ("lure", "lure.exe", "silentmesh-lure") or shutil.which("lure"):
        base = "lure"
    else:
        base = f"{'py' if sys.platform == 'win32' else 'python3'} -m lure"
    return base if sub is None else f"{base} {sub}"


def guide():
    return f"""
Three commands, one machine:

  {cmd('demo'):<28}  see Lure catch a pretend attacker (nothing leaves this machine)
  {cmd('init'):<28}  write real baits pointing at this machine; it asks two questions
  {cmd('listen --ui'):<28}  wait for someone to use one; the dashboard opens on http://127.0.0.1:8765

Then prove it from another terminal or machine:  {cmd('test')}
New version available? {cmd('update')} shows what changed and installs only if you say yes.

Everything else (profiles, log watching, DNS and AWS baits, MCP for AI agents):
  {cmd('--help')}   or   https://github.com/SilentMesh-Systems/Lure#readme
"""


def my_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # no packet is sent; the OS just picks the outbound interface
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def port_free(port):
    with socket.socket() as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _choose(ask, question, options, default):
    """Ask until the answer is one of the options' keys; Enter takes the default."""
    while True:
        answer = ask(question).strip().lower() or default
        if answer in options:
            return options[answer]


def ask_notify(ask, out):
    """Return a notify config from the user's answers."""
    out("\nHow do you want to be told when someone uses a bait?")
    out("  1. Only on the dashboard (you check it yourself)")
    out("  2. A popup on this computer")
    out("  3. On my phone: paste a Telegram, Discord or ntfy link")
    out("  4. By email, through my own Gmail or Outlook")
    choice = _choose(ask, "Pick 1-4 [2]: ", {"1": "1", "2": "2", "3": "3", "4": "4"}, "2")
    if choice == "2":
        return {"desktop": True}
    if choice == "3":
        out("  Easiest: install the free ntfy app, subscribe to a topic name nobody would guess,")
        out("  and paste https://ntfy.sh/<that-topic>. A Telegram bot or Discord webhook link also works.")
        url = ask("  Link: ").strip()
        return {"webhook": url, "desktop": True} if url.startswith("https://") else {"desktop": True}
    if choice == "4":
        to = ask("  Send alerts to (email address): ").strip()
        if "@" not in to:
            return {"desktop": True}
        domain = to.rsplit("@", 1)[1].lower()
        host = "smtp.office365.com" if domain in ("outlook.com", "hotmail.com", "live.com") else "smtp.gmail.com"
        out(f"  Lure sends from {to} through {host}. It needs an app password (not your normal one):")
        out("  Gmail: myaccount.google.com/apppasswords   Outlook: account.microsoft.com/security")
        out("  Lure never saves it. Set it before starting the listener:")
        out("    Windows:  set LURE_SMTP_PASSWORD=the-app-password" if sys.platform == "win32"
            else "    export LURE_SMTP_PASSWORD='the-app-password'")
        return {"email": {"to": to, "user": to, "host": host, "port": 587}, "desktop": True}
    return {}


def init(out_dir="baits", listener=None, profile=None, out=print, ask=None, notify_path=None):
    manifest = os.path.join(out_dir, "manifest.json")
    if os.path.exists(manifest):
        out(f"{manifest} already exists. Use `{cmd('rotate')}` for fresh baits, or `{cmd('init --out other-folder')}`.")
        return None
    if profile is None:
        profile = "it"
        if ask:
            profile = _choose(ask, "Is this a home computer or a work computer? [home/work] (work): ",
                              {"home": "home", "h": "home", "work": "it", "w": "it"}, "work")
    rdp_port = 3389
    if listener is None and not port_free(3389):
        rdp_port = 13389
        out("Port 3389 is in use here (usually Windows Remote Desktop), so the RDP bait uses port 13389.")
    host = listener or my_ip()
    m = generate(host, out_dir, profile=profile, rdp_port=rdp_port)
    files = sorted({b["file"] for b in m["baits"]})
    out(f"wrote {len(files)} bait files to {out_dir}/, every login in them points at {host}")
    for f in files:
        out(f"  {f}")
    if ask:
        from .notify import save_config
        path = save_config(ask_notify(ask, out), notify_path)
        out(f"  saved to {path} (outside the bait folder, on purpose)")
    out("")
    out("Next:")
    if host.startswith("127."):
        out(f"note: no network address found, so these baits point at this machine only. Re-run with --listener <this machine's LAN IP> to catch use from other machines.")
    out(f"  1. Start the listener here, in this terminal:   {cmd(f'listen --manifest {manifest} --ui')}")
    out(f"  2. Prove it, from another terminal:             {cmd(f'test --manifest {manifest}')}")
    out(f"  3. Copy a bait or two to where an intruder would look (desktop, Documents, a shared folder), then tell Lure where:")
    example = next((f for f in files if f.endswith(".rdp")), files[0])
    out(f"     {cmd('record')} \"{example}\" \"HOSTNAME:C:\\Users\\someone\\Desktop\"")
    out("")
    out(f"Keep {manifest} on this machine only; it maps usernames to baits (it holds no passwords).")
    if not ask:
        out("Be told about alerts: add --desktop, --email-to ADDRESS or --webhook URL to `lure listen`.")
    return m
