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
