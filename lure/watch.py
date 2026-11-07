"""Watch real authentication logs for bait usernames.

A bait username has no business appearing anywhere real. If an attacker types
one into your actual VPN, Active Directory, SSH or web login, the listener
never sees it, but the real system logs it. `lure watch` follows those logs
and raises a high alert the moment a bait username appears.

It reads plain-text logs: Linux auth logs, VPN and RADIUS logs, web server
logs, or Windows Security events forwarded to syslog or exported with
`wevtutil qe Security /f:text` (event IDs 4625 and 4771 carry the user name).
"""

import os
import re
import time


def _pattern(usernames):
    names = sorted({u for u in usernames if u}, key=len, reverse=True)
    if not names:
        return None
    # Match whole account names only, with or without a DOMAIN\ or @domain part.
    return re.compile(r"(?<![\w.])(?:[\w-]+\\)?(" + "|".join(re.escape(n) for n in names) + r")(?![\w])", re.I)


class Watcher:
    def __init__(self, alerter, paths, from_start=False):
        self.alerter = alerter
        self.paths = paths
        self.pattern = _pattern(alerter.by_user)
        self.offsets = {}
        for p in paths:
            try:
                self.offsets[p] = 0 if from_start else os.path.getsize(p)
            except OSError:
                self.offsets[p] = 0

    def scan_line(self, path, line):
        if not self.pattern:
            return None
        m = self.pattern.search(line)
        if not m:
            return None
        username = next(u for u in self.alerter.by_user if u.lower() == m.group(1).lower())
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        return self.alerter.event("log:" + os.path.basename(path), ip.group(1) if ip else "unknown", 0,
                                  username, source_detail=line.strip()[:300])

    def poll(self):
        hits = []
        for p in self.paths:
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if size < self.offsets[p]:  # rotated or truncated
                self.offsets[p] = 0
            if size == self.offsets[p]:
                continue
            with open(p, errors="replace") as f:
                f.seek(self.offsets[p])
                for line in f:
                    ev = self.scan_line(p, line)
                    if ev:
                        hits.append(ev)
                self.offsets[p] = f.tell()
        return hits

    def run(self, interval=2.0):
        while True:
            self.poll()
            time.sleep(interval)
