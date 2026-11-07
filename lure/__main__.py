import argparse
import asyncio
import json

from . import __version__
from .generate import PROFILES, generate, record, rotate
from .listen import Alerter, run


def main():
    p = argparse.ArgumentParser(prog="lure", description="Credential lures for everyone: planted credentials that give the attacker away.")
    p.add_argument("--version", action="version", version=f"lure v{__version__} by SilentMesh")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write a set of bait files")
    g.add_argument("--listener", required=True, help="host or IP that runs `lure listen`")
    g.add_argument("--out", default="baits")
    g.add_argument("--site", default="site")
    g.add_argument("--profile", default="it", choices=sorted(PROFILES),
                   help="vocabulary that fits the place: it (default), office, plant, bank or hospital")
    g.add_argument("--vpn-port", type=int, default=1194, help="first VPN bait port (the next baits use the following ports)")
    g.add_argument("--vpn-count", type=int, default=1, help="one VPN bait per placement; each gets its own listener port")

    ro = sub.add_parser("rotate", help="replace the baits with fresh ones; old ones keep alerting")
    ro.add_argument("--manifest", default="baits/manifest.json")
    ro.add_argument("--profile", choices=sorted(PROFILES))

    r = sub.add_parser("record", help="record where a bait was actually planted")
    r.add_argument("bait", help="bait username or file name")
    r.add_argument("location", help='for example "ENG-WS-07:C:\\Users\\eng\\Desktop"')
    r.add_argument("--manifest", default="baits/manifest.json")

    l = sub.add_parser("listen", help="alert when a bait credential is used")
    l.add_argument("--manifest", default="baits/manifest.json")
    l.add_argument("--webhook", help="POST each alert as JSON to this URL")
    l.add_argument("--syslog", help="host[:port] for UDP syslog")
    l.add_argument("--ui", action="store_true", help="serve a local dashboard (default http://127.0.0.1:8765)")
    l.add_argument("--ui-host", default="127.0.0.1", help="dashboard address; keep 127.0.0.1 unless you know why")
    l.add_argument("--ui-port", type=int, default=8765)
    l.add_argument("--log", help="append alerts to this JSON-lines file (default: alerts.jsonl next to the manifest)")
    l.add_argument("--rdp", type=int, default=3389)
    l.add_argument("--http", type=int, default=8080)
    l.add_argument("--openvpn", type=int, default=1194, help="only used for a manifest without VPN ports; otherwise the ports written into the VPN baits are used")

    a = p.parse_args()
    if a.cmd == "generate":
        m = generate(a.listener, a.out, a.site, a.vpn_count, a.vpn_port, profile=a.profile)
        files = sorted({b["file"] for b in m["baits"]})
        print(f"wrote {len(m['baits'])} bait credentials in {len(files)} files to {a.out}/ (see manifest.json for where to plant each)")
        for name in files:
            print(f"  {name}")
    elif a.cmd == "rotate":
        kw = {"profile": a.profile} if a.profile else {}
        m = rotate(a.manifest, **kw)
        live = [b for b in m["baits"] if not b.get("retired")]
        print(f"rotated: {len(live)} fresh baits written; {len(m['baits']) - len(live)} retired baits still alert")
    elif a.cmd == "record":
        n = record(a.manifest, a.bait, a.location)
        if not n:
            raise SystemExit(f"no bait named {a.bait!r} in {a.manifest}")
        print(f"recorded location for {n} bait(s): {a.location}")
    else:
        with open(a.manifest) as f:
            manifest = json.load(f)
        import os
        log = a.log or os.path.join(os.path.dirname(os.path.abspath(a.manifest)), "alerts.jsonl")
        alerter = Alerter(manifest, webhook=a.webhook, syslog=a.syslog, log=log, merge_window=8)
        if a.ui:
            from .ui import serve
            serve(alerter, a.ui_host, a.ui_port)
            print(f"dashboard: http://{a.ui_host}:{a.ui_port}/", flush=True)
        vpn_ports = [b["port"] for b in manifest.get("baits", []) if b.get("service") == "openvpn" and b.get("port")]
        ports = ", ".join(str(p) for p in sorted(set(vpn_ports or [a.openvpn])))
        print(f"listening: rdp {a.rdp}, http {a.http}, openvpn {ports}", flush=True)
        asyncio.run(run(alerter, a.rdp, a.http, a.openvpn, vpn_ports))


if __name__ == "__main__":
    main()
