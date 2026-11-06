# Changelog

## 0.1.0-beta (8 Nov 2026)
- `lure record` stores where each bait was actually planted; alerts include it.
- `--vpn-count` / `--vpn-port`: one VPN bait per placement, each on its own port.
- Tested against a real RDP client (FreeRDP 3).
- First public beta: bait generator (passwords.xlsx, saved RDP, vendor VPN profile) and listener (RDP, HTTP, OpenVPN) with dedupe and rate limit.
