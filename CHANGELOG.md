# Changelog

## 0.1.0-beta (8 Nov 2026)
- Baits rewritten to be believed: real-looking usernames, human file names, backdated files and Office metadata, a messy workbook with notes, a planted "temporary" admin and an old sheet.
- New baits: browser password export, .git-credentials (real git sends it), and a leaky email; baits reference each other.
- Profiles: plant, office, bank, hospital. `lure rotate` replaces baits while old ones keep alerting.
- Dashboard shows the attacker's path; a login-less probe is folded into the bait alert that follows; unknown logins are kept as medium alerts.
- Clear message when a listener port is busy.
- Local dashboard: `lure listen --ui` (127.0.0.1:8765), bait status, live alert feed, mark investigated; alert history kept in alerts.jsonl.
- `lure record` stores where each bait was actually planted; alerts include it.
- `--vpn-count` / `--vpn-port`: one VPN bait per placement, each on its own port.
- Tested against a real RDP client (FreeRDP 3).
- First public beta: bait generator (passwords.xlsx, saved RDP, vendor VPN profile) and listener (RDP, HTTP, OpenVPN) with dedupe and rate limit.
