# Changelog

## 0.1.0-beta (8 Nov 2026)
- Preview: `lure aws create|watch` for AWS bait keys (no-permission IAM user; CloudTrail event history watch). SigV4 signing verified against the AWS documented example; live loop not yet run.
- QR-code bait (standard-library QR encoder, verified with OpenCV) and a browser bookmarks bait; the listener spots tokens in the URL path.
- Custom profiles from JSON (`--profile file.json`), with legal, education and retail examples in profiles/.
- Monthly rotation recipe (cron or MCP).
- `lure watch`: alerts when a bait username appears in real authentication logs (SSH, VPN, RADIUS, web, Windows 4625/4771 exports).
- DNS baits: `--dns-zone` adds a bait hostname; the listener answers the delegated zone and alerts on lookups.
- Webhook alerts formatted for Slack, Teams, Discord and Telegram.
- `lure rotate` moves old bait files into retired/.
- MCP server: `lure mcp` exposes status, alerts, baits, generate, record, rotate and acknowledge to AI agents over stdio; standard library only; passwords never returned.
- `home` profile: router, NAS and CCTV baits for personal and small-office networks.
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
