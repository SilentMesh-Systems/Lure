import asyncio
import base64
import json
import os
import socket
import sys
import tempfile
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lure.generate import generate
from lure.listen import Alerter, parse_http, parse_rdp, run


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class GenerateTest(unittest.TestCase):
    def test_bait_set_is_complete_unique_and_valid(self):
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d)
            names = [b["username"] for b in m["baits"]]
            self.assertEqual(len(names), len(set(names)))
            files = {b["file"] for b in m["baits"]}
            for f in files | {"manifest.json"}:
                self.assertTrue(os.path.exists(os.path.join(d, f)), f)
            sheet = next(f for f in files if f.endswith(".xlsx"))
            with zipfile.ZipFile(os.path.join(d, sheet)) as z:
                self.assertIsNone(z.testzip())
                xml = z.read("xl/worksheets/sheet1.xml").decode() + z.read("xl/worksheets/sheet2.xml").decode()
                self.assertIn("IT Support", z.read("docProps/core.xml").decode())
            for b in m["baits"]:
                if b["file"] == sheet:
                    self.assertIn(b["username"], xml)
            rdp = next(b for b in m["baits"] if b["service"] == "rdp")
            with open(os.path.join(d, rdp["file"])) as f:
                self.assertIn("10.0.5.20:3389", f.read())

    def test_baits_look_real(self):
        import re
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d)
            for b in m["baits"]:
                # No random hex tails, the classic tell of generated accounts.
                self.assertIsNone(re.search(r"[0-9a-f]{6}$", b["username"]), b["username"])
                # Files are backdated weeks or months.
                age = time.time() - os.path.getmtime(os.path.join(d, b["file"]))
                self.assertGreater(age, 30 * 86400, b["file"])

    def test_baits_point_at_each_other(self):
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d)
            rdp = next(b for b in m["baits"] if b["service"] == "rdp")["file"]
            vpn = next(b for b in m["baits"] if b["service"] == "openvpn")["file"]
            with open(os.path.join(d, vpn)) as f:
                self.assertIn("RDP file", f.read())
            eml = next(b for b in m["baits"] if b["file"].endswith(".eml"))["file"]
            with open(os.path.join(d, eml)) as f:
                self.assertIn(vpn, f.read())
            self.assertIn(rdp, next(b for b in m["baits"] if b["service"] == "openvpn")["leads_to"])

    def test_profiles(self):
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d, profile="bank")
            sheet = next(b["file"] for b in m["baits"] if b["file"].endswith(".xlsx"))
            with zipfile.ZipFile(os.path.join(d, sheet)) as z:
                self.assertIn("Core banking", z.read("xl/worksheets/sheet1.xml").decode())
            with self.assertRaises(ValueError):
                generate("10.0.5.20", d, profile="nope")
        for prof in ("it", "office", "home", "plant", "bank", "hospital"):
            with tempfile.TemporaryDirectory() as d:
                m = generate("10.0.5.20", d, profile=prof)
                self.assertEqual(m["profile"], prof)
                self.assertGreaterEqual(len(m["baits"]), 12)

    def test_rotate_keeps_old_baits_alerting(self):
        from lure.generate import rotate
        with tempfile.TemporaryDirectory() as d:
            old = generate("10.0.5.20", d)
            new = rotate(os.path.join(d, "manifest.json"))
            live = [b for b in new["baits"] if not b.get("retired")]
            retired = [b for b in new["baits"] if b.get("retired")]
            self.assertEqual(len(retired), len(old["baits"]))
            self.assertFalse({b["username"] for b in live} & {b["username"] for b in retired})
            ev = Alerter(new, out=[].append).event("http", "10.9.9.9", 1, retired[0]["username"], now=0)
            self.assertEqual((ev["severity"], ev["retired"]), ("high", True))


class ParseTest(unittest.TestCase):
    def test_rdp_cookie(self):
        self.assertEqual(parse_rdp(b"\x03\x00\x00\x2aCookie: mstshash=eng_maint_abc123\r\n"), "eng_maint_abc123")
        self.assertIsNone(parse_rdp(b"\x03\x00"))

    def test_http_basic(self):
        h = b"GET / HTTP/1.1\r\nAuthorization: Basic " + base64.b64encode(b"scada_ro_x:pw") + b"\r\n\r\n"
        self.assertEqual(parse_http(h), "scada_ro_x")
        self.assertIsNone(parse_http(b"GET / HTTP/1.1\r\n\r\n"))


class AlerterTest(unittest.TestCase):
    def setUp(self):
        self.out = []
        m = {"baits": [{"username": "u1", "file": "passwords.xlsx", "plant_on": "share"}]}
        self.a = Alerter(m, out=self.out.append, window=600, max_per_window=3)

    def test_known_bait_is_high(self):
        ev = self.a.event("http", "10.1.1.1", 5000, "u1", now=0)
        self.assertEqual(ev["severity"], "high")
        self.assertEqual(ev["bait_file"], "passwords.xlsx")

    def test_unknown_touch_is_medium(self):
        self.assertEqual(self.a.event("openvpn", "10.1.1.1", 5000, None, now=0)["severity"], "medium")

    def test_dedupe_and_rate_limit(self):
        self.assertIsNotNone(self.a.event("rdp", "10.1.1.1", 1, "u1", now=0))
        self.assertIsNone(self.a.event("rdp", "10.1.1.1", 2, "u1", now=10))
        self.assertIsNotNone(self.a.event("rdp", "10.1.1.1", 3, "u1", now=700))
        self.a.event("rdp", "10.2.2.2", 1, None, now=701)
        self.a.event("rdp", "10.3.3.3", 1, None, now=702)
        self.assertIsNone(self.a.event("rdp", "10.4.4.4", 1, None, now=703))


class DemonstratedIntentTest(unittest.TestCase):
    def setUp(self):
        m = {"baits": [{"username": "u1", "file": "passwords.xlsx", "plant_on": "share"},
                       {"username": "u2", "file": "JUMP-SRV-01.rdp", "plant_on": "desktop"}]}
        self.a = Alerter(m, out=[].append)

    def test_http_bait_reentered_after_warning_is_flagged_once(self):
        first = self.a.event("http", "10.1.1.1", 1, "u1", now=0)
        self.assertNotIn("after_warning", first)
        again = self.a.event("http", "10.1.1.1", 2, "u1", now=5)
        self.assertTrue(again["after_warning"])
        self.assertIn("warning", again["why"])
        self.assertTrue(again["depth"]["after_warning"])
        self.assertIsNone(self.a.event("http", "10.1.1.1", 3, "u1", now=9))

    def test_other_source_is_not_after_warning(self):
        self.a.event("http", "10.1.1.1", 1, "u1", now=0)
        self.assertNotIn("after_warning", self.a.event("http", "10.9.9.9", 1, "u1", now=5))

    def test_depth_and_evidence_count_distinct_baits_per_source(self):
        self.a.event("http", "10.1.1.1", 1, "u1", now=0)
        ev = self.a.event("rdp", "10.1.1.1", 2, "u2", now=5)
        self.assertEqual(ev["depth"]["baits_used"], 2)
        self.assertEqual(ev["depth"]["order"], ["passwords.xlsx", "JUMP-SRV-01.rdp"])
        self.assertIn("cannot_conclude", ev["evidence"])
        self.assertEqual(self.a.state()["depth"]["10.1.1.1"]["baits_used"], 2)

    def test_medium_touch_has_no_depth(self):
        self.assertNotIn("depth", self.a.event("rdp", "10.1.1.1", 1, None, now=0))

    def test_http_reply_shows_warning(self):
        from lure.listen import HTTP_401
        self.assertIn(b"authorised personnel only", HTTP_401.lower())
        head, body = HTTP_401.split(b"\r\n\r\n", 1)
        self.assertIn(b"Content-Length: %d" % len(body), head)


class EndToEndTest(unittest.TestCase):
    def test_http_login_with_bait_raises_alert(self):
        out = []
        m = {"baits": [{"username": "scada_ro_e2e", "file": "passwords.xlsx", "plant_on": "share"}]}
        alerter = Alerter(m, out=out.append)
        ports = [free_port() for _ in range(3)]

        async def scenario():
            task = asyncio.create_task(run(alerter, *ports))
            await asyncio.sleep(0.2)
            r, w = await asyncio.open_connection("127.0.0.1", ports[1])
            w.write(b"GET / HTTP/1.1\r\nAuthorization: Basic " +
                    base64.b64encode(b"scada_ro_e2e:x") + b"\r\n\r\n")
            await w.drain()
            reply = await r.read(100)
            w.close()
            await asyncio.sleep(0.1)
            task.cancel()
            return reply

        reply = asyncio.run(scenario())
        self.assertIn(b"401", reply)
        ev = json.loads(out[0])
        self.assertEqual((ev["severity"], ev["username"]), ("high", "scada_ro_e2e"))


if __name__ == "__main__":
    unittest.main()


class PlacementTest(unittest.TestCase):
    def test_record_sets_location_and_alert_carries_it(self):
        from lure.generate import record
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d)
            rdp = next(b for b in m["baits"] if b["service"] == "rdp")
            sheet = next(b["file"] for b in m["baits"] if b["file"].endswith(".xlsx"))
            n_sheet = sum(1 for b in m["baits"] if b["file"] == sheet)
            path = os.path.join(d, "manifest.json")
            self.assertEqual(record(path, rdp["file"], "ENG-WS-07:Desktop"), 1)
            self.assertEqual(record(path, sheet, "\\\\files\\eng"), n_sheet)
            self.assertEqual(record(path, "nope", "x"), 0)
            with open(path) as f:
                saved = json.load(f)
            out = []
            ev = Alerter(saved, out=out.append).event("rdp", "10.1.1.1", 1, rdp["username"], now=0)
            self.assertEqual(ev["location"], "ENG-WS-07:Desktop")


class VpnPortTest(unittest.TestCase):
    def test_each_vpn_bait_gets_its_own_port(self):
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d, vpn_count=3)
            vpns = [b for b in m["baits"] if b["service"] == "openvpn"]
            self.assertEqual([b["port"] for b in vpns], [1194, 1195, 1196])
            for b in vpns:
                with open(os.path.join(d, b["file"])) as f:
                    self.assertIn(f"remote 10.0.5.20 {b['port']}", f.read())
            ev = Alerter(m, out=[].append).event("openvpn", "10.1.1.1", 1, None, now=0, local_port=1195)
            self.assertEqual((ev["severity"], ev["bait_file"]), ("high", vpns[1]["file"]))

    def test_openvpn_connection_end_to_end_names_the_file(self):
        out = []
        p_rdp, p_http, p_vpn = free_port(), free_port(), free_port()
        m = {"baits": [{"username": "vendor_sup_x", "file": "a.ovpn", "service": "openvpn",
                        "port": p_vpn, "plant_on": "jump host"}]}
        alerter = Alerter(m, out=out.append)

        async def scenario():
            task = asyncio.create_task(run(alerter, p_rdp, p_http, openvpn_ports=[p_vpn]))
            await asyncio.sleep(0.2)
            r, w = await asyncio.open_connection("127.0.0.1", p_vpn)
            w.write(b"\x00\x0e\x38")
            await w.drain()
            w.close()
            await asyncio.sleep(5.3)
            task.cancel()

        asyncio.run(scenario())
        ev = json.loads(out[0])
        self.assertEqual((ev["severity"], ev["bait_file"]), ("high", "a.ovpn"))


class DashboardTest(unittest.TestCase):
    def test_state_ack_and_csrf_guard(self):
        import urllib.request, urllib.error
        from lure.ui import serve
        with tempfile.TemporaryDirectory() as d:
            m = {"baits": [{"username": "u1", "file": "passwords.xlsx", "service": "http", "plant_on": "share"}]}
            log = os.path.join(d, "alerts.jsonl")
            a = Alerter(m, out=[].append, log=log)
            a.event("http", "10.1.1.1", 1, "u1", now=0)
            port = free_port()
            srv = serve(a, "127.0.0.1", port)
            try:
                base = f"http://127.0.0.1:{port}"
                page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
                self.assertIn("Lure console", page)
                st = json.loads(urllib.request.urlopen(base + "/api/state", timeout=5).read())
                self.assertTrue(st["baits"][0]["triggered"])
                self.assertEqual(st["alerts"][0]["severity"], "high")

                def post(ctype, origin):
                    req = urllib.request.Request(base + "/api/ack", data=b'{"id": 1}', method="POST",
                                                 headers={"Content-Type": ctype, "Origin": origin})
                    try:
                        return urllib.request.urlopen(req, timeout=5).status
                    except urllib.error.HTTPError as e:
                        return e.code

                self.assertEqual(post("text/plain", base), 403)
                self.assertEqual(post("application/json", "https://evil.example"), 403)
                self.assertEqual(post("application/json", base), 200)
                st = json.loads(urllib.request.urlopen(base + "/api/state", timeout=5).read())
                self.assertTrue(st["alerts"][0]["acknowledged"])
            finally:
                srv.shutdown()
                srv.server_close()
            # History survives a restart through the log file.
            again = Alerter(m, out=[].append, log=log)
            self.assertEqual(len(again.history), 1)
            self.assertTrue(again.history[0]["acknowledged"])


class PathTest(unittest.TestCase):
    def test_attacker_path_in_order(self):
        m = {"baits": [{"username": "a", "file": "sheet.xlsx", "service": "http", "plant_on": "s"},
                       {"username": "b", "file": "jump.rdp", "service": "rdp", "plant_on": "d"}]}
        al = Alerter(m, out=[].append)
        al.event("http", "10.1.1.7", 1, "a", now=100)
        al.event("rdp", "10.1.1.7", 2, "b", now=200)
        path = al.state()["paths"]["10.1.1.7"]
        self.assertEqual([s["file"] for s in path], ["sheet.xlsx", "jump.rdp"])


class GitCredentialTest(unittest.TestCase):
    def test_git_credential_url_is_well_formed(self):
        from urllib.parse import urlsplit, unquote
        with tempfile.TemporaryDirectory() as d:
            for _ in range(20):
                m = generate("10.0.5.20", d)
                b = next(b for b in m["baits"] if b["file"] == ".git-credentials")
                with open(os.path.join(d, ".git-credentials")) as f:
                    u = urlsplit(f.read().strip())
                self.assertEqual((u.hostname, u.port, unquote(u.username)), ("10.0.5.20", 8080, b["username"]))


class MergeTest(unittest.TestCase):
    def test_bare_probe_folds_into_bait_use(self):
        out = []
        m = {"baits": [{"username": "u", "file": ".git-credentials", "service": "http", "plant_on": "home"}]}
        a = Alerter(m, out=out.append, merge_window=0.5)
        a.event("http", "10.2.2.2", 1, None)
        a.event("http", "10.2.2.2", 2, "u")
        time.sleep(0.8)
        self.assertEqual([json.loads(x)["severity"] for x in out], ["high"])

    def test_bare_probe_alone_still_alerts(self):
        out = []
        a = Alerter({"baits": []}, out=out.append, merge_window=0.3)
        a.event("http", "10.3.3.3", 1, None)
        time.sleep(0.6)
        self.assertEqual([json.loads(x)["severity"] for x in out], ["medium"])


    def test_unknown_login_is_never_folded_away(self):
        out = []
        m = {"baits": [{"username": "u", "file": "a.rdp", "service": "rdp", "plant_on": "desk"}]}
        a = Alerter(m, out=out.append, merge_window=0.3)
        a.event("http", "10.4.4.4", 1, "admin")
        a.event("rdp", "10.4.4.4", 2, "u")
        time.sleep(0.6)
        sev = sorted(json.loads(x)["severity"] for x in out)
        self.assertEqual(sev, ["high", "medium"])


class McpTest(unittest.TestCase):
    def test_protocol_and_tools(self):
        import io
        from lure.mcp import serve_stdio
        with tempfile.TemporaryDirectory() as d:
            man = os.path.join(d, "manifest.json")
            msgs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "lure_generate", "arguments": {"listener": "10.0.5.20"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "lure_status", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "lure_generate", "arguments": {"listener": "x"}}},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "lure_baits", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 7, "method": "nope"},
            ]
            out = io.StringIO()
            serve_stdio(man, stdin=io.StringIO("\n".join(json.dumps(m) for m in msgs) + "\n"), stdout=out)
            replies = {r["id"]: r for r in map(json.loads, out.getvalue().splitlines())}
            self.assertEqual(replies[1]["result"]["serverInfo"]["name"], "lure")
            self.assertNotIn(None, replies)  # the notification got no reply
            self.assertEqual(len(replies[2]["result"]["tools"]), 7)
            self.assertFalse(replies[3]["result"]["isError"])
            self.assertGreaterEqual(replies[4]["result"]["structuredContent"]["live_baits"], 14)
            self.assertTrue(replies[5]["result"]["isError"])  # refuses to overwrite a set
            baits = replies[6]["result"]["structuredContent"]["baits"]
            self.assertTrue(all("password" not in b for b in baits))
            self.assertEqual(replies[7]["error"]["code"], -32601)

    def test_2026_stateless_and_discover(self):
        from lure.mcp import Server, PROTOCOL, SUPPORTED
        with tempfile.TemporaryDirectory() as d:
            s = Server(os.path.join(d, "manifest.json"))
            k = "io.modelcontextprotocol/"
            meta = {k + "protocolVersion": PROTOCOL, k + "clientCapabilities": {}}
            r = s.handle({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta}})["result"]
            self.assertEqual(r["supportedVersions"], SUPPORTED)
            self.assertEqual(r["_meta"][k + "serverInfo"]["name"], "lure")
            self.assertIn("tools", r["capabilities"])
            self.assertEqual(s.handle({"jsonrpc": "2.0", "id": 2, "method": "server/discover"})["result"]["resultType"], "complete")
            r = s.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": meta}})["result"]
            self.assertEqual(len(r["tools"]), 7)
            self.assertIn("ttlMs", r)
            bad = {k + "protocolVersion": "2099-01-01"}
            e = s.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {"_meta": bad}})["error"]
            self.assertEqual(e["code"], -32022)
            self.assertEqual(e["data"], {"supported": SUPPORTED, "requested": "2099-01-01"})
            old = s.handle({"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})["result"]
            self.assertEqual(old["protocolVersion"], "2025-11-25")
            old = s.handle({"jsonrpc": "2.0", "id": 6, "method": "initialize", "params": {"protocolVersion": "2099-01-01"}})["result"]
            self.assertEqual(old["protocolVersion"], "2025-11-25")
            self.assertNotIn("_meta", old)
            for junk in ([], "x", {"_meta": []}, {"_meta": "x"}):
                r = s.handle({"jsonrpc": "2.0", "id": 7, "method": "ping", "params": junk})
                self.assertEqual(r["result"], {})

    def test_alerts_and_acknowledge(self):
        import io
        from lure.mcp import Server
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d)
            u = m["baits"][0]["username"]
            a = Alerter(m, out=[].append, log=os.path.join(d, "alerts.jsonl"))
            a.event("rdp", "10.1.1.9", 1, u, now=0)
            s = Server(os.path.join(d, "manifest.json"))
            self.assertEqual(s.lure_status()["open_alerts"], 1)
            aid = s.lure_alerts(severity="high")["alerts"][0]["id"]
            s.lure_acknowledge(aid)
            self.assertEqual(s.lure_alerts(open_only=True)["matching"], 0)


class WatchTest(unittest.TestCase):
    def test_bait_username_in_real_logs(self):
        from lure.watch import Watcher
        m = {"baits": [{"username": "r.patil_adm", "file": "x.rdp", "service": "rdp", "plant_on": "desk"}]}
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "auth.log")
            with open(log, "w") as f:
                f.write("Nov  7 10:00:01 vpn sshd[1]: Failed password for alice from 10.0.0.5 port 2 ssh2\n")
            out = []
            w = Watcher(Alerter(m, out=out.append), [log])
            with open(log, "a") as f:
                f.write("Nov  7 10:00:09 vpn sshd[1]: Failed password for r.patil_adm from 10.9.8.7 port 5 ssh2\n")
                f.write("An account failed to log on. Account Name: CORP\\\\R.PATIL_ADM Source Network Address: 10.9.8.8\n")
                f.write("Failed login for r.patil_adm2 from 10.1.1.1\n")
            hits = w.poll()
            self.assertEqual([h["source"] for h in hits], ["10.9.8.7:0", "10.9.8.8:0"])
            self.assertTrue(all(h["severity"] == "high" and "real system" in h["why"] for h in hits))


class DnsTest(unittest.TestCase):
    def test_dns_bait_lookup_alerts(self):
        from lure.dnstoken import serve, parse_qname
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d, dns_zone="backup.example.com")
            b = next(b for b in m["baits"] if b["service"] == "dns")
            out = []
            a = Alerter(m, out=out.append)
            port = free_port()

            def query(name):
                q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                for part in name.split("."):
                    q += bytes([len(part)]) + part.encode()
                return q + b"\x00\x00\x01\x00\x01"

            async def scenario():
                t = await serve(a, "backup.example.com", port)
                loop = asyncio.get_running_loop()
                cli, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port))
                cli.sendto(query(f"{b['dns_label']}.backup.example.com"))
                cli.sendto(query("google.com"))
                await asyncio.sleep(0.3)
                cli.close(); t.close()

            asyncio.run(scenario())
            self.assertEqual(parse_qname(query("A.Example.com"))[1], "a.example.com")
            evs = [json.loads(x) for x in out]
            self.assertEqual(len(evs), 1)
            self.assertEqual((evs[0]["severity"], evs[0]["service"]), ("high", "dns"))


class WebhookFormatTest(unittest.TestCase):
    def test_platform_payloads(self):
        from lure.listen import webhook_payload
        ev = {"severity": "high", "bait_file": "a.rdp", "location": "WS-1", "source": "1.2.3.4:5",
              "service": "rdp", "username": "u", "time": "t", "why": "w"}
        self.assertIn("blocks", webhook_payload("https://hooks.slack.com/services/x", ev))
        self.assertEqual(webhook_payload("https://outlook.office.com/webhook/x", ev)["@type"], "MessageCard")
        self.assertIn("content", webhook_payload("https://discord.com/api/webhooks/x", ev))
        self.assertEqual(webhook_payload("https://example.com/hook", ev), ev)


class RotateFolderTest(unittest.TestCase):
    def test_rotate_moves_old_files_aside(self):
        from lure.generate import rotate
        with tempfile.TemporaryDirectory() as d:
            old = generate("10.0.5.20", d)
            old_files = {b["file"] for b in old["baits"]}
            new = rotate(os.path.join(d, "manifest.json"))
            new_files = {b["file"] for b in new["baits"] if not b.get("retired")}
            here = set(os.listdir(d)) - {"manifest.json", "retired"}
            self.assertEqual(here, new_files)
            moved = set(os.listdir(os.path.join(d, "retired", os.listdir(os.path.join(d, "retired"))[0])))
            self.assertTrue(old_files - new_files <= moved)


class PathTokenTest(unittest.TestCase):
    def test_qr_and_bookmark_baits(self):
        from lure.listen import parse_http
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d)
            qrb = next(b for b in m["baits"] if b.get("path_token") and b["file"].endswith(".png"))
            bmb = next(b for b in m["baits"] if b["file"] == "bookmarks.html")
            with open(os.path.join(d, qrb["file"]), "rb") as f:
                self.assertEqual(f.read(8), b"\x89PNG\r\n\x1a\n")
            with open(os.path.join(d, "bookmarks.html")) as f:
                self.assertIn("/go/" + bmb["path_token"], f.read())
            req = f"GET /q/{qrb['path_token']} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
            self.assertEqual(parse_http(req), qrb["username"])
            self.assertIsNone(parse_http(b"GET /index.html HTTP/1.1\r\n\r\n"))
            ev = Alerter(m, out=[].append).event("http", "10.5.5.5", 1, parse_http(req), now=0)
            self.assertEqual((ev["severity"], ev["bait_file"]), ("high", qrb["file"]))


class QrTest(unittest.TestCase):
    def test_matrix_shapes(self):
        from lure.qr import encode
        self.assertEqual(len(encode("HELLO")), 21)
        self.assertEqual(len(encode("y" * 150)), 17 + 4 * 8)
        with self.assertRaises(ValueError):
            encode("z" * 400)


class ProfileFileTest(unittest.TestCase):
    def test_gallery_profiles_work(self):
        here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "profiles")
        for name in sorted(os.listdir(here)):
            with tempfile.TemporaryDirectory() as d:
                m = generate("10.0.5.20", d, profile=os.path.join(here, name))
                self.assertGreaterEqual(len(m["baits"]), 14, name)

    def test_bad_profile_file(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.json")
            with open(bad, "w") as f:
                json.dump({"systems": []}, f)
            with self.assertRaises(ValueError):
                generate("10.0.5.20", d, profile=bad)


class AwsSigningTest(unittest.TestCase):
    def test_sigv4_matches_aws_documented_example(self):
        # The IAM ListUsers example from the AWS Signature Version 4 documentation.
        import datetime
        from lure.aws import _sign
        h = _sign("GET", "iam.amazonaws.com", "us-east-1", "iam", b"",
                  {"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
                  ("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", None),
                  query="Action=ListUsers&Version=2010-05-08",
                  now=datetime.datetime(2015, 8, 30, 12, 36, 0, tzinfo=datetime.timezone.utc))
        self.assertTrue(h["Authorization"].endswith(
            "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"), h["Authorization"])


class DemoTest(unittest.TestCase):
    def test_demo_catches_the_simulated_attacker(self):
        import io, contextlib
        from lure.demo import demo
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            st = demo(open_browser=False)
        highs = [a for a in st["alerts"] if a["severity"] == "high"]
        self.assertEqual(len(highs), 4)
        self.assertEqual(len(next(iter(st["paths"].values()))), 4)


class SelfTestTest(unittest.TestCase):
    def test_fires_bait_and_sees_alert(self):
        import asyncio, io, socket, threading, time
        from lure.generate import generate
        from lure.listen import Alerter, run
        from lure.selftest import run as selftest

        def free():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]
        rdp, http, vpn = free(), free(), free()
        with tempfile.TemporaryDirectory() as d:
            generate("127.0.0.1", d, http_port=http, rdp_port=rdp, vpn_port=vpn)
            log = os.path.join(d, "alerts.jsonl")
            with open(os.path.join(d, "manifest.json")) as f:
                alerter = Alerter(json.load(f), out=lambda l: None, log=log, merge_window=8)
            loop = asyncio.new_event_loop()

            def serve():
                try:
                    loop.run_until_complete(run(alerter, rdp, http, openvpn_ports=[vpn]))
                except RuntimeError:
                    pass
            t = threading.Thread(target=serve, daemon=True)
            t.start()
            time.sleep(1)
            out = io.StringIO()
            ok = selftest(os.path.join(d, "manifest.json"), rdp=rdp, http=http, out=lambda s: out.write(s + "\n"))
            loop.call_soon_threadsafe(loop.stop)
            self.assertTrue(ok, out.getvalue())
            self.assertIn("alert written: high", out.getvalue())
            with open(log) as f:
                self.assertGreaterEqual(sum(1 for _ in f), 1)

    def test_reports_unreachable_listener(self):
        import io
        from lure.generate import generate
        from lure.selftest import run as selftest
        with tempfile.TemporaryDirectory() as d:
            generate("127.0.0.1", d)
            out = io.StringIO()
            ok = selftest(os.path.join(d, "manifest.json"), rdp=1, http=1, out=lambda s: out.write(s + "\n"))
            self.assertFalse(ok)
            self.assertIn("FAIL", out.getvalue())


class InitTest(unittest.TestCase):
    def test_init_writes_baits_and_refuses_overwrite(self):
        import io
        from lure.init import init, my_ip
        self.assertRegex(my_ip(), r"^\d+\.\d+\.\d+\.\d+$")
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            m = init(os.path.join(d, "baits"), listener="10.0.0.9", out=lambda s: out.write(s + "\n"))
            self.assertEqual(m["listener"], "10.0.0.9")
            self.assertTrue(os.path.exists(os.path.join(d, "baits", "manifest.json")))
            self.assertIn("lure listen", out.getvalue())
            self.assertIn("lure test", out.getvalue())
            self.assertIsNone(init(os.path.join(d, "baits"), listener="10.0.0.9", out=lambda s: None))


class FounderFixesTest(unittest.TestCase):
    """15 Nov 2026: demo alerts looked real, alerts did not say who or how, real brand names in baits."""

    def _alerter(self, d, **kw):
        m = generate("127.0.0.1", d)
        return m, Alerter(m, out=lambda l: None, log=os.path.join(d, "alerts.jsonl"), **kw)

    def test_every_alert_says_who_what_how_next(self):
        with tempfile.TemporaryDirectory() as d:
            m, a = self._alerter(d)
            rdp = next(b for b in m["baits"] if b["service"] == "rdp")
            ev = a.event("rdp", "192.168.1.40", 5000, rdp["username"])
            x = ev["explain"]
            self.assertIn("192.168.1.40", x["who"])
            self.assertIn("own network", x["who"])
            self.assertIn(rdp["file"], x["what"])
            self.assertIn("Remote Desktop", x["how"])
            self.assertTrue(x["next"])
            self.assertIn("this computer", a.event("http", "127.0.0.1", 1, None)["explain"]["who"].lower())

    def test_demo_alerts_are_marked_and_say_nothing_real_happened(self):
        with tempfile.TemporaryDirectory() as d:
            m, a = self._alerter(d, demo=True)
            ev = a.event("rdp", "127.0.0.1", 1, m["baits"][0]["username"])
            self.assertTrue(ev["demo"])
            self.assertIn("demo", ev["explain"]["next"][0].lower())
            st = a.state()
            self.assertTrue(st["demo"])
            self.assertTrue(st["incidents"][0]["demo"])

    def test_one_incident_per_source_and_one_click_handles_it(self):
        with tempfile.TemporaryDirectory() as d:
            m, a = self._alerter(d)
            users = [b["username"] for b in m["baits"] if b["service"] == "http" and not b["username"].startswith("~")]
            for i, u in enumerate(users[:3]):
                a.event("http", "10.0.0.7", 100 + i, u)
            a.event("http", "10.0.0.8", 1, users[3])
            inc = a.state()["incidents"]
            self.assertEqual(len(inc), 2)
            big = next(i for i in inc if i["source"] == "10.0.0.7")
            self.assertEqual(len(big["steps"]), 3)
            self.assertTrue(a.acknowledge(big["ids"]))
            inc = a.state()["incidents"]
            self.assertFalse(inc[0]["handled"])
            self.assertTrue(next(i for i in inc if i["source"] == "10.0.0.7")["handled"])

    def test_bait_files_are_grouped(self):
        with tempfile.TemporaryDirectory() as d:
            m, a = self._alerter(d)
            files = a.state()["files"]
            self.assertEqual(len(files), len({b["file"] for b in m["baits"]}))
            sheet = next(f for f in files if f["file"].endswith(".xlsx"))
            self.assertGreater(sheet["logins"], 1)

    def test_no_real_company_names_in_any_profile(self):
        import glob
        from lure.generate import PROFILES
        brands = ["infosys", "tcs", "wipro", "accenture", "airtel", "jio", "siemens", "abb", "honeywell", "schneider",
                  "zoho", "freshworks", "hcl", "finacle", "fis", "temenos", "ncr", "philips", "ge healthcare", "agfa",
                  "lexisnexis", "pine labs", "shopify", "fedena", "manupatra", "scc online", "tata"]
        vendors = [v for p in PROFILES.values() for v in p["vendors"]]
        for f in glob.glob(os.path.join(os.path.dirname(__file__), "..", "profiles", "*.json")):
            with open(f) as fh:
                vendors += json.load(fh)["vendors"]
        for v in vendors:
            self.assertNotIn(v.lower().split()[0], brands, v)
            self.assertNotIn(v.lower(), brands, v)

    def test_home_profile_writes_a_plain_notes_file_not_a_spreadsheet(self):
        with tempfile.TemporaryDirectory() as d:
            m = generate("192.168.1.2", d, profile="home")
            files = {b["file"] for b in m["baits"]}
            self.assertFalse(any(f.endswith(".xlsx") for f in files))
            note = next(f for f in files if f.endswith(".txt"))
            with open(os.path.join(d, note)) as fh:
                text = fh.read()
            for b in m["baits"]:
                if b["file"] == note and not b.get("dns_label"):
                    self.assertIn(b["username"], text)

    def test_rotate_keeps_custom_ports(self):
        from lure.generate import rotate
        with tempfile.TemporaryDirectory() as d:
            generate("10.0.0.2", d, rdp_port=13389, http_port=8081)
            m = rotate(os.path.join(d, "manifest.json"))
            self.assertEqual(m["ports"], {"http": 8081, "rdp": 13389})

    def test_ntfy_gets_a_readable_message(self):
        from lure.listen import _ntfy, webhook_payload
        ev = {"severity": "high", "bait_file": "a.rdp", "source": "10.0.0.9:5", "service": "rdp", "username": "u", "time": "t"}
        self.assertEqual(_ntfy("https://ntfy.sh/my-secret-topic"), ("https://ntfy.sh/", "my-secret-topic"))
        body = webhook_payload("https://ntfy.sh/my-secret-topic", ev)
        self.assertEqual(body["topic"], "my-secret-topic")
        self.assertIn("Who:", body["message"])
        self.assertIsNone(_ntfy("https://example.com/hook"))

    def test_desktop_popup_command_per_platform(self):
        from unittest import mock
        from lure import notify
        seen = []
        for plat in ("win32", "darwin", "linux"):
            with mock.patch.object(notify.sys, "platform", plat), mock.patch.object(notify.shutil, "which", return_value="/usr/bin/notify-send"):
                self.assertTrue(notify.desktop("Lure: Bait used", "It's from 10.0.0.9", run=lambda c, **k: seen.append(c)))
        self.assertEqual(seen[0][0], "powershell")
        self.assertIn("It''s from", seen[0][-1])
        self.assertEqual(seen[1][0], "osascript")
        self.assertEqual(seen[2][0], "notify-send")

    def test_email_needs_app_password_and_sends(self):
        from unittest import mock
        from lure import notify
        cfg = {"to": "me@gmail.com", "user": "me@gmail.com", "host": "smtp.gmail.com", "port": 587}
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(OSError):
                notify.email(cfg, "s", "b")
        sent = []

        class FakeSMTP:
            def __init__(self, *a, **k): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def starttls(self): pass
            def login(self, u, p): sent.append(("login", u, p))
            def send_message(self, m): sent.append(("msg", m["To"], m["Subject"]))
        with mock.patch.dict(os.environ, {"LURE_SMTP_PASSWORD": "app-pw"}):
            notify.email(cfg, "Lure alert", "body", smtp=FakeSMTP)
        self.assertEqual(sent, [("login", "me@gmail.com", "app-pw"), ("msg", "me@gmail.com", "Lure alert")])

    def test_notify_config_lives_outside_the_bait_folder(self):
        from lure import notify
        with tempfile.TemporaryDirectory() as d:
            p = notify.save_config({"desktop": True}, os.path.join(d, "cfg", "notify.json"))
            self.assertEqual(notify.load_config(p), {"desktop": True})
        self.assertNotIn("baits", notify.config_path())

    def test_init_asks_home_or_work_and_how_to_be_told(self):
        from lure.init import init
        answers = iter(["home", "2"])
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "notify.json")
            m = init(os.path.join(d, "baits"), listener="10.0.0.9", out=lambda s: None,
                     ask=lambda q: next(answers), notify_path=cfg)
            self.assertEqual(m["profile"], "home")
            with open(cfg) as f:
                self.assertEqual(json.load(f), {"desktop": True})


class UpdateTest(unittest.TestCase):
    def test_version_order(self):
        from lure.update import parse
        order = ["0.1.0a1", "0.1.0b2", "0.1.0b3", "0.1.0rc1", "0.1.0", "0.1.1", "0.2.0"]
        self.assertEqual(sorted(order, key=parse), order)
        self.assertIsNone(parse("not-a-version"))

    def test_offers_only_newer_and_respects_prerelease_choice(self):
        from lure.update import newest
        rel = {"0.1.0b2": [{}], "0.1.0b3": [{}], "0.1.0b4": [{"yanked": True}], "0.0.9": [{}]}
        self.assertEqual(newest(rel, "0.1.0b2"), "0.1.0b3")
        self.assertIsNone(newest(rel, "0.1.0b3"))
        self.assertIsNone(newest({"0.2.0b1": [{}]}, "0.1.0"))
        self.assertEqual(newest({"0.2.0": [{}]}, "0.1.0"), "0.2.0")

    def test_nothing_installs_without_yes(self):
        from lure import update
        data = {"releases": {"9.9.9": [{}]}}
        installs = []
        out = []
        fetch = lambda url: data if "pypi" in url else {"body": "Fixed the dashboard."}
        code = update.run(ask=lambda q: "no", out=out.append, fetch=fetch, install=lambda c: installs.append(c) or 0)
        self.assertEqual(code, 0)
        self.assertEqual(installs, [])
        self.assertIn("Fixed the dashboard.", "\n".join(out))

    def test_yes_installs_the_exact_version(self):
        from unittest import mock
        from lure import update
        installs = []
        fetch = lambda url: {"releases": {"9.9.9": [{}]}} if "pypi" in url else {"body": "x"}
        with mock.patch.object(update, "__file__", "/usr/lib/python3/site-packages/lure/update.py"):
            update.run(ask=lambda q: "yes", out=lambda s: None, fetch=fetch, install=lambda c: installs.append(c) or 0)
        self.assertEqual(installs[0][-1], "silentmesh-lure==9.9.9")

    def test_daily_check_is_cached_and_can_be_turned_off(self):
        from unittest import mock
        from lure import update
        calls = []
        fetch = lambda url: calls.append(url) or {"releases": {"9.9.9": [{}]}}
        with tempfile.TemporaryDirectory() as d:
            c = os.path.join(d, "u.json")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(update.check(fetch, now=1000, cache=c), "9.9.9")
                self.assertEqual(update.check(fetch, now=2000, cache=c), "9.9.9")
                self.assertEqual(len(calls), 1)
            with mock.patch.dict(os.environ, {"LURE_NO_UPDATE_CHECK": "1"}):
                self.assertIsNone(update.check(fetch, now=999999, cache=c))
            self.assertIsNone(update.check(lambda u: 1 / 0, now=10 ** 9, cache=os.path.join(d, "x.json")))


class ConsoleTest(unittest.TestCase):
    def test_test_now_endpoint_runs_the_tester_and_refuses_cross_site(self):
        import threading, urllib.request
        from lure.ui import serve
        with tempfile.TemporaryDirectory() as d:
            m = generate("127.0.0.1", d)
            a = Alerter(m, out=lambda l: None)
            fired = threading.Event()
            port = free_port()
            srv = serve(a, "127.0.0.1", port, tester=fired.set)
            try:
                def post(origin):
                    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/test", data=b"{}", method="POST",
                                                 headers={"Content-Type": "application/json", "Origin": origin})
                    try:
                        return urllib.request.urlopen(req, timeout=3).status
                    except urllib.error.HTTPError as e:
                        return e.code
                self.assertEqual(post("http://evil.example"), 403)
                self.assertFalse(fired.is_set())
                self.assertEqual(post(f"http://127.0.0.1:{port}"), 200)
                self.assertTrue(fired.wait(3))
                page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3).read().decode()
                self.assertIn("Run test", page)
                self.assertIn("Live feed", page)
                self.assertIn("why this was flagged", page)
                self.assertIn("cannot tell you", page)
            finally:
                srv.shutdown()


class FontsTest(unittest.TestCase):
    def test_bundled_fonts_are_served_and_nothing_else(self):
        import urllib.request, urllib.error
        from lure.ui import serve, FONTS
        a = Alerter({"baits": []}, out=lambda l: None)
        port = free_port()
        srv = serve(a, "127.0.0.1", port)
        try:
            base = f"http://127.0.0.1:{port}"
            for name in FONTS:
                r = urllib.request.urlopen(base + "/fonts/" + name, timeout=5)
                self.assertEqual(r.status, 200)
                self.assertEqual(r.headers["Content-Type"], "font/woff2")
                self.assertEqual(r.read()[:4], b"wOF2")
            for bad in ("/fonts/nope.woff2", "/fonts/../ui.py", "/fonts/..%2Fui.py", "/fonts/", "/fonts/OFL.txt"):
                try:
                    code = urllib.request.urlopen(base + bad, timeout=5).status
                except urllib.error.HTTPError as e:
                    code = e.code
                self.assertEqual(code, 404, bad)
            r = urllib.request.urlopen(base + "/", timeout=5)
            self.assertIn("font-src 'self'", r.headers["Content-Security-Policy"])
            page = r.read().decode()
            self.assertNotIn("googleapis", page)
            self.assertNotIn("\u2014", page)
        finally:
            srv.shutdown()


class AwsTagTest(unittest.TestCase):
    def test_bait_user_tag_passes_iam_pattern(self):
        import re
        src = open(os.path.join(os.path.dirname(__file__), "..", "lure", "aws.py")).read()
        value = re.search(r'"Tags\.member\.1\.Value": "([^"]+)"', src).group(1)
        self.assertRegex(value, r"^[\w\s.:/=+\-@]{0,256}$")


class McpToolDescriptionTest(unittest.TestCase):
    def test_every_tool_declares_behaviour_annotations(self):
        from lure.mcp import TOOLS
        for t in TOOLS:
            a = t["annotations"]
            self.assertEqual(set(a), {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}, t["name"])
            self.assertFalse(a["openWorldHint"], t["name"])
            if a["readOnlyHint"]:
                self.assertFalse(a["destructiveHint"], t["name"])
