"""Updates reach users only with their approval.

`lure listen` asks PyPI at most once a day whether a newer Lure exists and, if
so, says so in the terminal and on the dashboard. It never installs anything.
`lure update` shows what changed and installs only after the user types yes.

The check is one HTTPS request to pypi.org carrying nothing about the user
beyond their IP address. Turn it off with --no-update-check or
LURE_NO_UPDATE_CHECK=1.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

from . import __version__

PACKAGE = "silentmesh-lure"
PYPI = f"https://pypi.org/pypi/{PACKAGE}/json"
NOTES = "https://api.github.com/repos/SilentMesh-Systems/Lure/releases/tags/v{version}"
_V = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$")
_STAGE = {"a": 0, "b": 1, "rc": 2, None: 3}


def parse(v):
    """Order versions like 0.1.0b2 < 0.1.0rc1 < 0.1.0 < 0.1.1. None if not understood."""
    m = _V.match(v.strip())
    if not m:
        return None
    return (int(m[1]), int(m[2]), int(m[3]), _STAGE[m[4]], int(m[5] or 0))


def newest(releases, current=__version__):
    """The newest version worth offering. Pre-releases only to users already on one."""
    cur = parse(current)
    pre_ok = cur is not None and cur[3] < 3
    best = None
    for v, files in releases.items():
        pv = parse(v)
        if pv is None or not files or (pv[3] < 3 and not pre_ok) or any(f.get("yanked") for f in files):
            continue
        if best is None or pv > parse(best):
            best = v
    return best if best and cur and parse(best) > cur else None


def _cache_path():
    from .notify import config_path
    return os.path.join(os.path.dirname(config_path()), "update-check.json")


def check(fetch=None, now=None, max_age=86400, cache=None):
    """Return the newer version or None. Never raises; a failed check is silent."""
    if os.environ.get("LURE_NO_UPDATE_CHECK"):
        return None
    now = time.time() if now is None else now
    cache = cache or _cache_path()
    try:
        with open(cache) as f:
            c = json.load(f)
        if now - c.get("checked", 0) < max_age and c.get("current") == __version__:
            return c.get("newer")
    except (OSError, ValueError):
        pass
    try:
        data = (fetch or _get_json)(PYPI)
        newer = newest(data.get("releases", {}))
    except Exception:
        return None
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        with open(cache, "w") as f:
            json.dump({"checked": now, "current": __version__, "newer": newer}, f)
    except OSError:
        pass
    return newer


def _get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"lure/{__version__}"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def notes(version, fetch=None):
    try:
        body = (fetch or _get_json)(NOTES.format(version=version)).get("body") or ""
    except Exception:
        body = ""
    return body.strip() or f"See https://github.com/SilentMesh-Systems/Lure/releases/tag/v{version}"


def run(ask=input, out=print, fetch=None, install=subprocess.call, yes=False):
    """`lure update`: show what changed, install only on an explicit yes. Returns an exit code."""
    try:
        data = (fetch or _get_json)(PYPI)
    except Exception as e:
        out(f"could not reach PyPI ({e}). Nothing changed.")
        return 1
    newer = newest(data.get("releases", {}))
    if not newer:
        out(f"Lure {__version__} is the newest version. Nothing to do.")
        return 0
    out(f"Lure {newer} is available (you have {__version__}).\n\nWhat changed:\n")
    out(notes(newer, fetch))
    out("")
    if not yes:
        try:
            answer = ask(f"Install Lure {newer} now? Type yes to install: ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            out("Not installed. Run `lure update` again whenever you are ready.")
            return 0
    if not any(d in os.path.abspath(__file__) for d in ("site-packages", "dist-packages")):
        out("You are running Lure from a downloaded folder, not a pip install. Update it there with: git pull")
        return 0
    out(f"installing {PACKAGE}=={newer} ...")
    code = install([sys.executable, "-m", "pip", "install", "--upgrade", f"{PACKAGE}=={newer}"])
    if code == 0:
        out(f"Installed Lure {newer}. Restart `lure listen` to use it; your baits and alerts are unchanged.")
    else:
        out("pip did not finish. If you installed with pipx, run: pipx upgrade silentmesh-lure")
    return code
