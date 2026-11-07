<img src="assets/lure-mark-128.png" width="96" alt="SilentMesh Lure mark">

# SilentMesh Lure (beta)

*Lure by SilentMesh*

**Planted credentials that give the attacker away.** Deceive, never disrupt.

Free credential lures for everyone, on any network: offices, data centres, banks, hospitals and industrial plants.

Attackers often get in with a stolen VPN or jump-host login, then look for more saved passwords on the machines they reach: admin desktops, file shares, home directories and old emails. Lure plants fake ones for them to find. If anyone tries to use one, you get an alert that says which file was found and where you planted it.

- **No agent, nothing on the control network.** Bait files go on IT-side machines: engineering workstations, jump hosts, vendor shares.
- **Alerts on use, not on open.** Opening, copying, backing up or antivirus-scanning a bait file does nothing. Only a login attempt with a bait credential fires an alert.
- **Your alerts go only to you.** The listener sends alerts to your own webhook, syslog or terminal. No SilentMesh service is involved, and nothing is sent to us.
- **Tested on Linux (x86-64 and ARM, including Raspberry Pi) and Windows,** Python 3.9 and newer, standard library only. macOS is not yet supported. Apache-2.0.

## Quick start

No install step: clone the repo and run it with `python3 -m lure` from the repo folder (or `pip install .`).

1. Pick a listener host: any spare Linux machine or VM on the IT side that nobody legitimately logs into.

2. Generate the bait set, pointing it at that host:

   ```
   python3 -m lure generate --listener 10.0.5.20 --out baits
   ```

   This writes six bait files, written to be believed:

   | Bait | What it looks like | Where to plant it |
   |---|---|---|
   | A spreadsheet such as `passwords_FINAL_v2.xlsx` | A real workbook from "IT Support", months old, with a Notes column, a "temporary" shared admin row ("TODO: rotate after the audit") and an "Old - do not use" sheet | A file share or a Documents folder |
   | `DO NOT DELETE - JUMP-SRV-01.rdp` | A saved Remote Desktop connection with a username filled in | An admin or engineering workstation desktop |
   | `Infosys support VPN (old).ovpn` | A vendor VPN profile with its login in a comment, and a hint about the RDP file | A jump host or vendor laptop share |
   | `passwords.csv` | A browser password export | A Downloads folder |
   | `.git-credentials` | A git credential store; real `git` will send this login | A home directory |
   | `Re- Infosys remote access.eml` | An email that leaks a temporary login and points at the VPN profile and the spreadsheet | A mailbox export or Documents folder |
   | `manifest.json` | Which username belongs to which bait (no passwords). **Keep it off the network.** | Only on the listener host |

   Names, vendors and dates change on every run. Usernames look like real accounts (`r.patil_adm`, `svc_vcenter2`, `vendor.infosys`), never random strings, and the files are backdated weeks or months. The baits point at each other, so each one found makes the next more convincing.

   Pick vocabulary that fits the place with `--profile it` (default: NAS, vCenter, intranet), `office` (payroll, Tally, HR), `bank` (core banking, payment switch), `hospital` (HIS, PACS, lab) or `plant` (SCADA, historian, MES).

   After planting, record exactly where each bait lives, so the alert can say so:

   ```
   python3 -m lure record jump-host.rdp "ENG-WS-07:C:\Users\eng\Desktop"
   python3 -m lure record passwords.xlsx "\\files01\engineering"
   ```

   Planting VPN profiles in several places? Generate one per place with `--vpn-count 3`. Each gets its own listener port, so the alert names the exact file even though the VPN login itself is encrypted.

   Rotate the whole set from time to time with `lure rotate`. Fresh baits are written, and the old ones stay in the manifest as retired: anyone who stole them earlier still triggers an alert.

3. Run the listener on the listener host:

   ```
   python3 -m lure listen --manifest baits/manifest.json \
       --webhook https://your-alerts.example/hook --syslog 10.0.1.5:514
   ```

   It listens on RDP (3389), HTTP (8080) and OpenVPN (1194). Binding ports below 1024 is not needed.

4. Test it. From another machine, open the `.rdp` bait and try to connect. You should get one alert like this:

   ```json
   {"severity": "high", "service": "rdp", "source": "10.0.7.31:51544",
    "username": "r.patil_adm", "bait_file": "DO NOT DELETE - JUMP-SRV-01.rdp",
    "planted_on": "an admin or engineering workstation desktop",
    "location": "FIN-WS-07:C:\\Users\\admin\\Desktop",
    "why": "a bait credential was used: someone found and tried it"}
   ```

## Local dashboard

```
python3 -m lure listen --manifest baits/manifest.json --ui
```

Then open http://127.0.0.1:8765 on the listener host. It shows every bait (quiet or triggered, and where it is planted) and a live alert feed with a "Mark investigated" button. The dashboard listens on 127.0.0.1 only by default, needs nothing installed, and sends nothing anywhere. Alerts are also kept in `alerts.jsonl` next to the manifest, so the history survives a restart.

## How detection works

A bait file cannot know when it is used. Something has to see the login attempt, and in Lure that is the listener:

1. `lure generate` writes baits whose addresses point **only at your listener host**, never at a real system.
2. You plant them, and record where with `lure record`.
3. Anyone who tries a bait has to connect to the listener, so the listener sees the attempt. It reads the bait username from the RDP connection request or the HTTP login; VPN baits are told apart by port.
4. The listener matches the username or port to the manifest.
5. You get one alert with the exact bait file, where you planted it, the time, and the source address.

What it does not see: a bait username typed into one of your **real** systems (your actual VPN or Active Directory). Watching real authentication logs for bait usernames is planned for v0.2.

Tested with a real RDP client (FreeRDP 3), which sends the username Lure reads.

## The attacker's path

Alerts from the same source address are joined into a path on the dashboard, oldest first: for example the spreadsheet, then the RDP file, then the VPN. You see how far someone got and in what order.

## How alerts are graded

- **high:** a bait username was used. Someone found a planted file and tried it.
- **medium:** something connected to the listener host without a bait username, or tried an unknown login. A bare request that is followed within seconds by a bait login (browsers and git always try once without a login) is folded into that one high alert.
- **retired:** a high alert from a rotated-out bait, meaning it was taken before the last rotation.
  Nothing legitimate should connect at all, so a medium alert is still worth a look. A scanner you run yourself is the usual cause.

The same source, service and username alert once per 10 minutes, with at most 20 alerts per 10 minutes overall, so one attacker cannot flood your pager.

## Data handling

Lure runs entirely on your own machines. The listener records the connecting IP and port, the service, the time and the username it was offered. It sends that only to the sinks you configure. Passwords sent to the listener are never read or stored. SilentMesh receives no data.

## Use responsibly

Only plant baits on systems you own or are authorised to protect. The person who runs the listener controls the data it records (IP addresses and usernames can be personal data, for example under India's DPDP Act 2023) and is responsible for handling it under their own law.

## Limits

- This is a beta. It catches people who find and use credentials. It does not detect an attacker who never touches the baits.
- The OpenVPN login is encrypted, so VPN baits are identified by their port, not their username.
- Do not point a bait at a real system. In industrial sites, keep baits off the control network.

## Going further

Lure is free for everyone. For industrial sites, the full SilentMesh product adds decoy PLCs and controllers on the plant network itself (Modbus/TCP, S7comm, IEC 60870-5-104, DNP3, OPC UA, SMB), off the control path and fail-open. See https://silentmesh.me.

## Running the tests

```
python3 -m unittest discover -s tests
```

## Licence

Apache License 2.0. See LICENSE.
