"""Anonymous usage statistics, so we can see how Lure is used and fix what breaks.

What is sent: the command run (demo, init, listen, test...), the Lure version,
the operating system, the Python version, the bait profile name, which alert
channels are on (yes or no only), and for each alert only its severity, service
and whether it came from the demo. Each install gets a random ID that is not
linked to you.

What is never sent: IP addresses, hostnames, usernames, bait file names or
contents, alert details, webhook URLs or email addresses.

Turn it off with LURE_NO_TELEMETRY=1 or DO_NOT_TRACK=1.
"""

import json
import os
import platform
import sys
import threading
import urllib.request
import uuid

from . import __version__

POSTHOG_HOST = "https://us.i.posthog.com"
# PostHog project API keys are public by design (write-only, used in browsers).
BUILTIN_KEY = "phc_yQ334afjJkZ9qzmzx25gft57aiT8hyz4q6uecyqP9BX9"

ALLOWED = {"command", "version", "os", "python", "profile", "channels", "severity", "service", "demo", "count"}


def _key():
    return os.environ.get("LURE_POSTHOG_KEY") or BUILTIN_KEY


def enabled():
    if os.environ.get("LURE_NO_TELEMETRY") or os.environ.get("DO_NOT_TRACK") == "1":
        return False
    return bool(_key())


def _dir():
    from .notify import config_path
    return os.path.dirname(config_path())


def install_id():
    path = os.path.join(_dir(), "telemetry-id")
    try:
        with open(path) as f:
            value = f.read().strip()
            if value:
                return value
    except OSError:
        pass
    value = str(uuid.uuid4())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(value)
    except OSError:
        pass
    return value


def notice(out=print):
    """Say once per install that stats are on, and how to turn them off."""
    try:
        _notice(out)
    except Exception:
        pass


def _notice(out):
    if not enabled():
        return
    marker = os.path.join(_dir(), "telemetry-noticed")
    if os.path.exists(marker):
        return
    out("Lure sends anonymous usage stats (command, version, OS). Never IPs, bait names or alert contents. "
        "Turn off: set LURE_NO_TELEMETRY=1.")
    try:
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        open(marker, "w").close()
    except OSError:
        pass


def payload(event, props=None):
    base = {"version": __version__, "os": platform.system(), "python": "%d.%d" % sys.version_info[:2]}
    base.update({k: v for k, v in (props or {}).items() if k in ALLOWED})
    base["$process_person_profile"] = False
    return {"api_key": _key(), "event": "lure_" + event, "distinct_id": install_id(), "properties": base}


def _post(body):
    req = urllib.request.Request(POSTHOG_HOST + "/i/v0/e/", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": f"lure/{__version__}"})
    urllib.request.urlopen(req, timeout=3).close()


def send(event, props=None, post=None, wait=False):
    """Fire and forget. Never raises and never slows Lure down."""
    try:
        if not enabled():
            return
    except Exception:
        return

    def go():
        try:
            (post or _post)(payload(event, props))
        except Exception:
            pass
    t = threading.Thread(target=go, daemon=True)
    t.start()
    if wait:
        t.join(4)
