"""Ways to be told about an alert that need no webhook: a desktop popup or an email.

The choice made at `lure init` is saved in the user's own config folder, never
next to the baits, because the bait folder may be copied to places an
attacker can read. The email password is never saved: it comes from the
LURE_SMTP_PASSWORD environment variable at run time.
"""

import json
import os
import shutil
import smtplib
import subprocess
import sys
from email.message import EmailMessage


def config_path():
    base = os.environ.get("APPDATA") if sys.platform == "win32" else \
        os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base or os.path.expanduser("~"), "lure", "notify.json")


def load_config(path=None):
    try:
        with open(path or config_path()) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def save_config(cfg, path=None):
    path = path or config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    return path


def _ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def desktop(title, body, run=subprocess.run):
    """Show a popup on this machine. Returns False if the platform offers no way."""
    title, body = str(title)[:120], str(body)[:400]
    if sys.platform == "win32":
        script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
            "$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
            f"$t = $x.GetElementsByTagName('text'); $t.Item(0).InnerText = {_ps_quote(title)}; $t.Item(1).InnerText = {_ps_quote(body)};"
            "$n = [Windows.UI.Notifications.ToastNotification]::new($x);"
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show($n)")
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    elif sys.platform == "darwin":
        q = lambda s: '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
        cmd = ["osascript", "-e", f"display notification {q(body)} with title {q(title)}"]
    elif shutil.which("notify-send"):
        cmd = ["notify-send", "--urgency=critical", "--app-name=Lure", title, body]
    else:
        return False
    try:
        run(cmd, check=False, timeout=15, capture_output=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def email(cfg, subject, body, smtp=smtplib.SMTP):
    """Send through the user's own mail account. cfg: to, from, host, port, user."""
    password = os.environ.get("LURE_SMTP_PASSWORD")
    if not password:
        raise OSError("set LURE_SMTP_PASSWORD (an app password for your mail account)")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg.get("from") or cfg["user"], cfg["to"]
    msg.set_content(body)
    with smtp(cfg.get("host", "smtp.gmail.com"), int(cfg.get("port", 587)), timeout=15) as s:
        s.starttls()
        s.login(cfg["user"], password)
        s.send_message(msg)
