import argparse
import asyncio
import json

from .generate import generate
from .listen import Alerter, run


def main():
    p = argparse.ArgumentParser(prog="tripwire", description="Credential tripwires for IT/OT networks.")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write a set of bait files")
    g.add_argument("--listener", required=True, help="host or IP that runs `tripwire listen`")
    g.add_argument("--out", default="baits")
    g.add_argument("--site", default="plant")

    l = sub.add_parser("listen", help="alert when a bait credential is used")
    l.add_argument("--manifest", default="baits/manifest.json")
    l.add_argument("--webhook", help="POST each alert as JSON to this URL")
    l.add_argument("--syslog", help="host[:port] for UDP syslog")
    l.add_argument("--rdp", type=int, default=3389)
    l.add_argument("--http", type=int, default=8080)
    l.add_argument("--openvpn", type=int, default=1194)

    a = p.parse_args()
    if a.cmd == "generate":
        m = generate(a.listener, a.out, a.site)
        print(f"wrote {len(m['baits'])} bait credentials to {a.out}/ (see manifest.json for where to plant each)")
    else:
        with open(a.manifest) as f:
            manifest = json.load(f)
        alerter = Alerter(manifest, webhook=a.webhook, syslog=a.syslog)
        print(f"listening: rdp {a.rdp}, http {a.http}, openvpn {a.openvpn}")
        asyncio.run(run(alerter, a.rdp, a.http, a.openvpn))


if __name__ == "__main__":
    main()
