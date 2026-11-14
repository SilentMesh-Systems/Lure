import argparse
import asyncio
import json
import sys

from . import __version__
from .generate import PROFILES, STORYLINES, generate, record, rotate
from .listen import Alerter, run


def main():
    p = argparse.ArgumentParser(prog="lure", description="Credential lures for everyone: planted credentials that give the attacker away.")
    p.add_argument("--version", action="version", version=f"lure v{__version__} by SilentMesh")
    sub = p.add_subparsers(dest="cmd", required=True)

    ini = sub.add_parser("init", help="first install on this machine: write baits pointing here and say what to do next")
    ini.add_argument("--out", default="baits")
    ini.add_argument("--listener", help="use this address instead of this machine's own")
    ini.add_argument("--profile", default="it", help="it (default), office, home, plant, bank, hospital, or a JSON profile file")
    ini.add_argument("--storyline", choices=sorted(STORYLINES), help="the story the baits tell together (default: picked at random)")

    g = sub.add_parser("generate", help="write a set of bait files")
    g.add_argument("--listener", required=True, help="host or IP that runs `lure listen`")
    g.add_argument("--out", default="baits")
    g.add_argument("--site", default="site")
    g.add_argument("--profile", default="it",
                   help="it (default), office, home, plant, bank, hospital, or a JSON profile file such as profiles/legal.json")
    g.add_argument("--storyline", choices=sorted(STORYLINES),
                   help="vendor (remote access never cleaned up) or admin (a leaver's unfinished handover); default: random. "
                        "The same three fictional people appear in every bait")
    g.add_argument("--dns-zone", help="a subdomain delegated to the listener (NS record); adds a DNS bait hostname")
    g.add_argument("--vpn-port", type=int, default=1194, help="first VPN bait port (the next baits use the following ports)")
    g.add_argument("--vpn-count", type=int, default=1, help="one VPN bait per placement; each gets its own listener port")

    ro = sub.add_parser("rotate", help="replace the baits with fresh ones; old ones keep alerting")
    ro.add_argument("--manifest", default="baits/manifest.json")
    ro.add_argument("--profile", help="built-in profile name or a JSON profile file")
    ro.add_argument("--storyline", choices=sorted(STORYLINES), help="change the storyline (default: keep the current one)")

    r = sub.add_parser("record", help="record where a bait was actually planted")
    r.add_argument("bait", help="bait username or file name")
    r.add_argument("location", help='for example "ENG-WS-07:C:\\Users\\eng\\Desktop"')
    r.add_argument("--manifest", default="baits/manifest.json")

    w = sub.add_parser("watch", help="watch real authentication logs for bait usernames")
    w.add_argument("logs", nargs="+", metavar="LOGFILE")
    w.add_argument("--manifest", default="baits/manifest.json")
    w.add_argument("--webhook")
    w.add_argument("--format", choices=["native", "chain"], default="native",
                   help="webhook and syslog payload: native Lure alert, or the shared intent-chain event SilentMesh joins on")
    w.add_argument("--syslog")
    w.add_argument("--from-start", action="store_true", help="scan existing lines too, not only new ones")

    aw = sub.add_parser("aws", help="AWS bait keys: create one, or watch CloudTrail for their use")
    aw.add_argument("action", choices=["create", "watch"])
    aw.add_argument("--manifest", default="baits/manifest.json")
    aw.add_argument("--aws-profile", help="AWS credentials profile used to create and watch (not the bait)")
    aw.add_argument("--region", default="us-east-1", help="CloudTrail region to watch (IAM and most console calls land in us-east-1)")
    aw.add_argument("--interval", type=int, default=300)
    aw.add_argument("--user-name", help="IAM user name for the bait (default svc-backup-sync)")
    aw.add_argument("--webhook")
    aw.add_argument("--once", action="store_true", help="check once and exit")

    de = sub.add_parser("demo", help="see Lure catch a simulated attacker on this machine in under a minute")
    de.add_argument("--no-browser", action="store_true", help="do not open the dashboard in a browser")
    de.add_argument("--keep", action="store_true", help="keep the dashboard running after the demo")

    mc = sub.add_parser("mcp", help="run an MCP server over stdio so AI agents can use Lure")
    mc.add_argument("--manifest", default="baits/manifest.json")
    mc.add_argument("--log", help="alert log written by `lure listen` (default: alerts.jsonl next to the manifest)")

    t = sub.add_parser("test", help="fire a real bait login at the listener and confirm the alert arrives")
    t.add_argument("--manifest", default="baits/manifest.json")
    t.add_argument("--listener", help="override the listener host from the manifest")
    t.add_argument("--rdp", type=int, default=3389)
    t.add_argument("--http", type=int, default=8080)
    t.add_argument("--report", action="store_true", help="also print a readiness report (JSON): what was proven, when, and what was not")

    l = sub.add_parser("listen", help="alert when a bait credential is used")
    l.add_argument("--manifest", default="baits/manifest.json")
    l.add_argument("--webhook", help="POST each alert as JSON to this URL")
    l.add_argument("--format", choices=["native", "chain"], default="native",
                   help="webhook and syslog payload: native Lure alert, or the shared intent-chain event SilentMesh joins on")
    l.add_argument("--syslog", help="host[:port] for UDP syslog")
    l.add_argument("--ui", action="store_true", help="serve a local dashboard (default http://127.0.0.1:8765)")
    l.add_argument("--ui-host", default="127.0.0.1", help="dashboard address; keep 127.0.0.1 unless you know why")
    l.add_argument("--ui-port", type=int, default=8765)
    l.add_argument("--log", help="append alerts to this JSON-lines file (default: alerts.jsonl next to the manifest)")
    l.add_argument("--dns-port", type=int, default=53, help="UDP port for DNS baits (needs --dns-zone in the manifest)")
    l.add_argument("--watch", nargs="+", metavar="LOGFILE", help="also watch these real auth logs for bait usernames")
    l.add_argument("--rdp", type=int, default=3389)
    l.add_argument("--http", type=int, default=8080)
    l.add_argument("--openvpn", type=int, default=1194, help="only used for a manifest without VPN ports; otherwise the ports written into the VPN baits are used")

    if len(sys.argv) == 1:
        from .init import guide
        print(f"lure v{__version__} by SilentMesh: planted credentials that give the attacker away." + guide())
        return
    a = p.parse_args()
    if a.cmd == "init":
        from .init import init
        if init(a.out, a.listener, a.profile, storyline=a.storyline) is None:
            raise SystemExit(1)
        return
    if a.cmd == "generate":
        m = generate(a.listener, a.out, a.site, a.vpn_count, a.vpn_port, profile=a.profile, dns_zone=a.dns_zone,
                     storyline=a.storyline)
        files = sorted({b["file"] for b in m["baits"]})
        print(f"wrote {len(m['baits'])} bait credentials in {len(files)} files to {a.out}/ (see manifest.json for where to plant each)")
        print(f"storyline: {m['storyline']['name']}. {m['storyline']['summary']}")
        for name in files:
            print(f"  {name}")
        print(f"prove it works: lure test --manifest {a.out}/manifest.json")
    elif a.cmd == "rotate":
        kw = {k: v for k, v in (("profile", a.profile), ("storyline", a.storyline)) if v}
        m = rotate(a.manifest, **kw)
        live = [b for b in m["baits"] if not b.get("retired")]
        print(f"rotated: {len(live)} fresh baits written; {len(m['baits']) - len(live)} retired baits still alert")
    elif a.cmd == "watch":
        import os
        from .watch import Watcher
        with open(a.manifest) as f:
            manifest = json.load(f)
        log = os.path.join(os.path.dirname(os.path.abspath(a.manifest)), "alerts.jsonl")
        alerter = Alerter(manifest, webhook=a.webhook, syslog=a.syslog, log=log, fmt=a.format)
        print(f"watching {len(a.logs)} log file(s) for {len(alerter.by_user)} bait usernames", flush=True)
        Watcher(alerter, a.logs, from_start=a.from_start).run()
    elif a.cmd == "aws":
        import os
        from . import aws
        if a.action == "create":
            r = aws.create_bait_key(os.path.dirname(os.path.abspath(a.manifest)), a.manifest, a.aws_profile, a.user_name)
            print(f"created IAM user {r['iam_user']} (no permissions) and bait key {r['access_key_id']}")
            print(f"  wrote {r['file']}; plant it, then run: lure aws watch --manifest {a.manifest}")
        else:
            with open(a.manifest) as f:
                manifest = json.load(f)
            log = os.path.join(os.path.dirname(os.path.abspath(a.manifest)), "alerts.jsonl")
            alerter = Alerter(manifest, webhook=a.webhook, log=log)
            print(f"watching CloudTrail ({a.region}) every {a.interval}s for AWS bait keys", flush=True)
            aws.watch(alerter, a.aws_profile, a.region, a.interval, once=a.once)
    elif a.cmd == "demo":
        from .demo import demo
        demo(open_browser=not a.no_browser, keep=a.keep)
    elif a.cmd == "mcp":
        from .mcp import serve_stdio
        serve_stdio(a.manifest, a.log)
    elif a.cmd == "test":
        from .selftest import run as selftest
        if a.report:
            from .selftest import readiness
            r = readiness(a.manifest, a.listener, a.rdp, a.http)
            print(json.dumps(r, indent=2))
            if not r["applicable"] or r["ready"] < r["applicable"]:
                raise SystemExit(1)
        elif not selftest(a.manifest, a.listener, a.rdp, a.http):
            raise SystemExit(1)
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
        alerter = Alerter(manifest, webhook=a.webhook, syslog=a.syslog, log=log, merge_window=8, fmt=a.format)
        if a.ui:
            from .ui import serve
            serve(alerter, a.ui_host, a.ui_port)
            print(f"dashboard: http://{a.ui_host}:{a.ui_port}/", flush=True)
        vpn_ports = [b["port"] for b in manifest.get("baits", []) if b.get("service") == "openvpn" and b.get("port")]
        ports = ", ".join(str(p) for p in sorted(set(vpn_ports or [a.openvpn])))
        print(f"listening: rdp {a.rdp}, http {a.http}, openvpn {ports}", flush=True)
        if a.watch:
            import threading
            from .watch import Watcher
            threading.Thread(target=Watcher(alerter, a.watch).run, daemon=True).start()
            print(f"watching logs: {', '.join(a.watch)}", flush=True)
        zone = manifest.get("dns_zone")
        if zone:
            print(f"dns: answering *.{zone} on udp {a.dns_port}", flush=True)
        asyncio.run(run(alerter, a.rdp, a.http, a.openvpn, vpn_ports, dns_zone=zone, dns_port=a.dns_port))


if __name__ == "__main__":
    main()
