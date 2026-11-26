# Changelog

## 0.1.0b4 (unreleased)
Security and reliability release from SilentMesh's own audit of 0.1.0b3. Upgrading is recommended for everyone.

Security fixes
- Windows desktop popups (`--desktop`): alert text could break out of the PowerShell command that shows the popup. The text is now passed separately and is never part of the command.
- A burst of junk logins could use up the alert budget so that a real bait login raised no alert. Bait logins are now never dropped by the budget, and a burst raises its own "flood" alert.
- Slack, Teams and Discord alerts: login names chosen by whoever touched the listener could carry links, mentions or formatting. They are now escaped, Discord never pings, and very long names are shortened for display.
- The HTTP listener read only one 4 KB chunk, so a login after large headers or split across packets could be missed. It now reads the whole request (headers up to 16 KB, body up to 8 KB).

Reliability
- Alerts are written and printed at once and delivered to webhook, email, popup and syslog on a background worker, so a slow or broken channel never holds up the listener. A bad webhook URL or syslog setting is reported instead of breaking alerts.
- The alert log is append-only and safe to share between `lure listen`, `lure watch`, `lure aws watch` and the MCP server: unique ids across processes, acknowledgements are appended instead of rewriting the file, and the dashboard shows other processes' alerts without a restart. Existing logs keep working.
- A damaged line in the alert log no longer stops `lure listen` from starting; it is skipped and copied to `alerts.jsonl.corrupt`.
- Repeat uses of the same bait from the same address are recorded (with an attempt number) in the timeline instead of disappearing, without notifying you again.
- `lure listen` and `lure watch` pick up `lure rotate` and `lure record` within about 10 seconds, without a restart.
- Dedupe, budget and warning state are updated under one lock across threads.

New
- Login styles: besides Basic auth, the HTTP listener now recognises Digest, login forms, JSON login bodies and query strings.
- Tamper alarm: `--alive-url` pings a dead-man service (healthchecks.io, Cronitor, Better Stack, Uptime Kuma) every `--alive-minutes` (default 5), so you hear about it if Lure is stopped; `--alive-file` writes a small status file for local monitoring.

## 0.1.0b3 (17 Nov 2026)
- Anonymous usage statistics (command, version, OS, alert severity and service only; never IPs, bait names or alert contents), on by default and stated on first run; off with LURE_NO_TELEMETRY=1 or DO_NOT_TRACK=1.
- Weekly "still listening" message, plus one at start, to your alert channels; `--heartbeat-days` sets the interval, 0 turns it off.
- Bait email uses your organisation's domain (`lure init` asks; `--email-domain` on generate) instead of the giveaway `<profile>-it.local`; rotate keeps it.
- `lure init` reminds you to tell IT before planting baits on shared drives.
Fixes from the founder's own test on Windows, 15 Nov 2026.
- Dashboard rebuilt as an operator console in the SilentMesh console design: an incident queue with one incident per source, a detail pane (why it was flagged, timeline with ATT&CK technique, impact including what Lure cannot see, what to do, handling), a 24-hour histogram, live feed, bait inventory, integrations, CSV and JSON export, keyboard shortcuts, and Run test that fires a real bait login at your own listener. Fonts are bundled, so the dashboard makes no outside requests.
- Every alert now says who (this computer, a device on your network, or the internet), what bait, how it was used, and what to do, in the dashboard, webhooks, email and popups.
- Demo alerts are marked as demo everywhere, with a banner on the dashboard, so a demo can never look like a real attack.
- Alerts without a webhook: `--desktop` popups on Windows, Linux and macOS, `--email-to` through your own Gmail or Outlook (app password from LURE_SMTP_PASSWORD, never saved), and readable ntfy push messages.
- `lure init` asks two questions: home or work computer, and how you want to be told. The choice is saved outside the bait folder.
- No real company names in baits: vendors are roles such as "AMC vendor" or "automation vendor" in every profile.
- Home profile writes a plain `passwords.txt` style note and a Wi-Fi QR, not an office spreadsheet.
- Windows: commands print as `py -m lure`; if port 3389 is taken by Remote Desktop, the RDP bait uses 13389, and listen, test and rotate read ports from the manifest.
- Updates by approval: `lure listen` checks PyPI once a day and only tells you; `lure update` shows what changed and installs only when you type yes. Off with --no-update-check or LURE_NO_UPDATE_CHECK=1. Releases publish only after tests pass, the tag matches the version, and a reviewer approves.

## 0.1.0-beta.2 (10 Nov 2026)
- MCP server speaks spec 2026-07-28 (`server/discover`, stateless requests) and still answers 2025 `initialize`.
- `lure test`: fires real bait logins at the listener and confirms the alert.
- `lure init`: one-command first setup, plus a no-argument guide and a three-command README start.
- Registry metadata (`server.json`), `silentmesh-lure` command, plant profile example.
- `lure demo`: plants baits on localhost, starts the dashboard and plays an attacker, so you see it work in under a minute.
- README hero: badges, animated demo, one-line try-it.
- Release workflow publishes to PyPI (silentmesh-lure) via trusted publishing.

## 0.1.0-beta (8 Nov 2026)
- Preview: `lure aws create|watch` for AWS bait keys (no-permission IAM user; CloudTrail event history watch). SigV4 signing verified against the AWS documented example; live loop not yet run.
- QR-code bait (standard-library QR encoder, verified with OpenCV) and a browser bookmarks bait; the listener spots tokens in the URL path.
- Custom profiles from JSON (`--profile file.json`), with legal, education and retail examples in profiles/.
- Monthly rotation recipe (cron or MCP).
- `lure watch`: alerts when a bait username appears in real authentication logs (SSH, VPN, RADIUS, web, Windows 4625/4771 exports).
- DNS baits: `--dns-zone` adds a bait hostname; the listener answers the delegated zone and alerts on lookups.
- Webhook alerts formatted for Slack, Teams, Discord and Telegram.
- `lure rotate` moves old bait files into retired/.
- `lure init` and a no-argument guide: a first install on one machine with no decisions; README opens with three commands.
- `lure test`: fires a real RDP and HTTP bait login at the listener and confirms the alert landed, so a new install proves itself in seconds.
- MCP: now speaks spec 2026-07-28 (`server/discover`, per-request `_meta` version, -32022 on unsupported versions) and keeps the legacy `initialize` handshake for 2025-11-25 and 2025-06-18 clients.
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
