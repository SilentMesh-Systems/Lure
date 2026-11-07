# Lure by SilentMesh v0.1.0-beta

**Planted credentials that give the attacker away.** A quiet safety net for any network, from a home router to a data centre. Free and open source (Apache-2.0).

## What it does
`lure generate` writes six believable bait files with fake logins:
- a messy password workbook
- a saved Remote Desktop file
- a vendor VPN profile
- a browser password export
- a `.git-credentials` file
- a leaky email

They point at each other the way real ones do. `lure listen` waits on a spare machine. When anyone tries a bait login, you get one alert naming the file, where you planted it, and the path the attacker took.

## Highlights
- **Alerts on use, not on open:** antivirus scans, backups and indexing never page you.
- **Nothing is sent to us:** alerts go to your own webhook, syslog, terminal or dashboard.
- **Local dashboard** (`lure listen --ui`), with bait status, a live alert feed and the attacker's path.
- **MCP server** (`lure mcp`) with 7 tools, so AI agents can check, rotate and triage. It never returns passwords.
- **Profiles:** `it` (default), `office`, `home`, `bank`, `hospital` and `plant`.
- **`lure rotate`:** fresh baits; old ones keep alerting, which catches credentials stolen earlier.
- **`lure record`:** stores exactly where each bait was planted.
- **Runs on Python 3.9 and newer,** standard library only. Tested on Linux (x86-64 and ARM, including Raspberry Pi) and Windows.

## Verified before release
- **Automated tests:** 22 tests pass on CI for Linux x86-64, Linux ARM and Windows.
- **Real-client tests:**
  - real `git` sends the `.git-credentials` bait
  - a real RDP client (FreeRDP 3) uses the RDP bait
  - the HTTP baits work with curl and browsers
  - the official MCP Python SDK client connects to the MCP server

## Known limits
- It sees bait logins only when they are tried against the listener. A bait username typed into a real VPN or Active Directory is not seen yet (planned).
- macOS is not yet supported.
- This is a beta, supported on a best-effort basis.

## Install
```
git clone https://github.com/SilentMesh-Systems/Lure && cd Lure
python3 -m lure generate --listener <listener IP> --out baits
python3 -m lure listen --manifest baits/manifest.json --ui
```
