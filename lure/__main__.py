import argparse
import asyncio
import json

from . import __version__
from .generate import generate, record
from .listen import Alerter, run


def main():
    p = argparse.ArgumentParser(prog="lure", description="Credential lures for everyone: planted credentials that give the attacker away.")
    p.add_argument("--version", action="version", version=f"lure v{__version__} by SilentMesh")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write a set of bait files")
    g.add_argument("--listener", required=True, help="host or IP that runs `lure listen`")
    g.add_argument("--out", default="baits")
    g.add_argument("--site", default="plant")
    g.add_argument("--vpn-port", type=int, default=1194, help="first VPN bait port (the next baits use the following ports)")
    g.add_argument("--vpn-count", type=int, default=1, help="one VPN bait per placement; each gets its own listener port")

    r = sub.add_parser("record", help="record where a bait was actually planted")
    r.add_argument("bait", help="bait username or file name")
    r.add_argument("location", help='for example "ENG-WS-07:C:\\Users\\eng\\Desktop"')
    r.add_argument("--manifest", default="baits/manifest.json")

    l = sub.add_parser("listen", help="alert when a bait credential is used")
    l.add_argument("--manifest", default="baits/manifest.json")
    l.add_argument("--webhook", help="POST each alert as JSON to this URL")
    l.add_argument("--syslog", help="host[:port] for UDP syslog")
    l.add_argument("--rdp", type=int, default=3389)
    l.add_argument("--http", type=int, default=8080)
    l.add_argument("--openvpn", type=int, default=1194, help="only used for a manifest without VPN ports; otherwise the ports written into the VPN baits are used")

    a = p.parse_args()
    if a.cmd == "generate":
        m = generate(a.listener, a.out, a.site, a.vpn_count, a.vpn_port)
        print(f"wrote {len(m['baits'])} bait credentials to {a.out}/ (see manifest.json for where to plant each)")
    elif a.cmd == "record":
        n = record(a.manifest, a.bait, a.location)
        if not n:
            raise SystemExit(f"no bait named {a.bait!r} in {a.manifest}")
        print(f"recorded location for {n} bait(s): {a.location}")
    else:
        with open(a.manifest) as f:
            manifest = json.load(f)
        alerter = Alerter(manifest, webhook=a.webhook, syslog=a.syslog)
        vpn_ports = [b["port"] for b in manifest.get("baits", []) if b.get("service") == "openvpn" and b.get("port")]
        ports = ", ".join(str(p) for p in sorted(set(vpn_ports or [a.openvpn])))
        print(f"listening: rdp {a.rdp}, http {a.http}, openvpn {ports}", flush=True)
        asyncio.run(run(alerter, a.rdp, a.http, a.openvpn, vpn_ports))


if __name__ == "__main__":
    main()
