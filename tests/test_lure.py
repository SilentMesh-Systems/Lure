import asyncio
import base64
import json
import os
import socket
import sys
import tempfile
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
    def test_bait_set_is_complete_and_unique(self):
        with tempfile.TemporaryDirectory() as d:
            m = generate("10.0.5.20", d)
            names = {b["username"] for b in m["baits"]}
            self.assertEqual(len(names), len(m["baits"]))
            for f in ["jump-host.rdp", "plant-vendor-vpn.ovpn", "passwords.xlsx", "manifest.json"]:
                self.assertTrue(os.path.exists(os.path.join(d, f)), f)
            with zipfile.ZipFile(os.path.join(d, "passwords.xlsx")) as z:
                self.assertIsNone(z.testzip())
                sheet = z.read("xl/worksheets/sheet1.xml").decode()
            for b in m["baits"]:
                if b["file"] == "passwords.xlsx":
                    self.assertIn(b["username"], sheet)
            with open(os.path.join(d, "jump-host.rdp")) as f:
                self.assertIn("10.0.5.20:3389", f.read())


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
            path = os.path.join(d, "manifest.json")
            self.assertEqual(record(path, "jump-host.rdp", "ENG-WS-07:Desktop"), 1)
            self.assertEqual(record(path, "passwords.xlsx", "\\\\files\\eng"), 2)
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
