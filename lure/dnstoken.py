"""DNS tokens: a bait hostname that alerts when anyone looks it up.

Delegate a spare subdomain (for example `backup.example.com`) to the listener
host with an NS record. Bait files then mention hostnames such as
`nas-archive07.backup.example.com`. Anyone who tries to reach one, from any
tool and through almost any firewall, makes a DNS lookup that ends at the
listener. The label tells Lure which bait was found.

Only names under the delegated zone are answered; everything else is refused.
"""

import asyncio
import struct


def parse_qname(packet):
    """Return (query id, lower-case query name) from a DNS query, or None."""
    if len(packet) < 12:
        return None
    qid = packet[:2]
    labels, i = [], 12
    while i < len(packet):
        n = packet[i]
        if n == 0:
            return qid, ".".join(labels).lower()
        if n & 0xC0 or i + 1 + n > len(packet) or len(labels) > 40:
            return None
        labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return None


def answer(packet, rcode=3):
    """A minimal reply: echo the question, no answers, NXDOMAIN by default."""
    qid = packet[:2]
    flags = struct.pack(">H", 0x8400 | rcode)  # response, authoritative
    end = 12
    while end < len(packet) and packet[end] != 0:
        end += 1 + packet[end]
    question = packet[12:end + 5]
    return qid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + question


class _DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, alerter, zone):
        self.alerter, self.zone = alerter, zone.lower().strip(".")
        self.by_label = {b["dns_label"]: b for b in alerter.manifest.get("baits", []) if b.get("dns_label")}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        q = parse_qname(data)
        if not q:
            return
        _, name = q
        if not (name == self.zone or name.endswith("." + self.zone)):
            self.transport.sendto(answer(data, rcode=5), addr)  # refused: not our zone
            return
        label = name[: -len(self.zone)].rstrip(".").split(".")[-1] if name != self.zone else ""
        bait = self.by_label.get(label)
        self.alerter.event("dns", addr[0], addr[1], bait["username"] if bait else None,
                           source_detail=name)
        self.transport.sendto(answer(data), addr)


async def serve(alerter, zone, port=53):
    loop = asyncio.get_running_loop()
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: _DNSProtocol(alerter, zone), local_addr=("0.0.0.0", port))
    except OSError as e:
        raise SystemExit(f"lure: cannot listen for DNS on UDP {port} ({e.strerror}). Use --dns-port, or run with "
                         "permission to bind port 53.") from None
    return transport
