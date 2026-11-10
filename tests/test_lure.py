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
        self.assertIsNotNone(self.a.event("http", "10.1.1.1", 1, "u1", now=0))
        self.assertIsNone(self.a.event("http", "10.1.1.1", 2, "u1", now=10))
        self.assertIsNotNone(self.a.event("http", "10.1.1.1", 3, "u1", now=700))
        self.a.event("rdp", "10.2.2.2", 1, None, now=701)
        self.a.event("rdp", "10.3.3.3", 1, None, now=702)
        self.assertIsNone(self.a.event("rdp", "10.4.4.4", 1, None, now=703))


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
                self.assertIn("SilentMesh", page)
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
