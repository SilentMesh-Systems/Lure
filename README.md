<img src="assets/lure-mark-128.png" width="96" alt="SilentMesh Lure mark">

# SilentMesh Lure (beta)

*Lure by SilentMesh*

**Planted credentials that give the attacker away.** Deceive, never disrupt.

Free credential lures for everyone, on any network. Built with plants in mind.

Attackers often get in with a stolen VPN or jump-host login, then look for more saved passwords on the machines they reach. In industrial plants that means engineering workstations and vendor shares. Lure plants fake ones for them to find. If anyone tries to use one, you get an alert that says which file was found and where you planted it.

- **No agent, nothing on the control network.** Bait files go on IT-side machines: engineering workstations, jump hosts, vendor shares.
- **Alerts on use, not on open.** Opening, copying, backing up or antivirus-scanning a bait file does nothing. Only a login attempt with a bait credential fires an alert.
- **Your alerts go only to you.** The listener sends alerts to your own webhook, syslog or terminal. No SilentMesh service is involved, and nothing is sent to us.
- **Runs anywhere Python 3.9+ runs:** Linux (x86-64 and ARM, including Raspberry Pi), Windows and macOS. Standard library only. Apache-2.0.

## Quick start

No install step: clone the repo and run it with `python3 -m lure` from the repo folder (or `pip install .`).

1. Pick a listener host: any spare Linux machine or VM on the IT side that nobody legitimately logs into.

2. Generate the bait set, pointing it at that host:

   ```
   python3 -m lure generate --listener 10.0.5.20 --out baits
   ```

   This writes:

   | File | What it looks like | Where to plant it |
   |---|---|---|
   | `passwords.xlsx` | A real spreadsheet of logins: jump host, SCADA web, historian, vendor VPN | An engineering share or a workstation's Documents folder |
   | `jump-host.rdp` | A saved Remote Desktop connection with a username filled in | An engineering workstation desktop |
   | `plant-vendor-vpn.ovpn` | A vendor remote-support VPN profile with its login in a comment | A jump host or a vendor laptop share |
   | `manifest.json` | Which username belongs to which bait (no passwords). **Keep it off the network:** anyone who reads it knows which logins are fake. | Only on the listener host |

   After planting, record exactly where each bait lives, so the alert can say so:

   ```
   python3 -m lure record jump-host.rdp "ENG-WS-07:C:\Users\eng\Desktop"
   python3 -m lure record passwords.xlsx "\\files01\engineering"
   ```

   Planting VPN profiles in several places? Generate one per place with `--vpn-count 3`. Each gets its own listener port, so the alert names the exact file even though the VPN login itself is encrypted.

3. Run the listener on the listener host:

   ```
   python3 -m lure listen --manifest baits/manifest.json \
       --webhook https://your-alerts.example/hook --syslog 10.0.1.5:514
   ```

   It listens on RDP (3389), HTTP (8080) and OpenVPN (1194). Binding ports below 1024 is not needed.

4. Test it. From another machine, open `jump-host.rdp` and try to connect. You should get one alert like this:

   ```json
   {"severity": "high", "service": "rdp", "source": "10.0.7.31:51544",
    "username": "eng_maint_95aead", "bait_file": "jump-host.rdp",
    "planted_on": "engineering workstation desktop",
    "why": "a bait credential was used: someone found and tried it"}
   ```

## How detection works

A bait file cannot know when it is used. Something has to see the login attempt, and in Lure that is the listener:

1. `lure generate` writes baits whose addresses point **only at your listener host**, never at a real system.
2. You plant them, and record where with `lure record`.
3. Anyone who tries a bait has to connect to the listener, so the listener sees the attempt. It reads the bait username from the RDP connection request or the HTTP login; VPN baits are told apart by port.
4. The listener matches the username or port to the manifest.
5. You get one alert with the exact bait file, where you planted it, the time, and the source address.

What it does not see: a bait username typed into one of your **real** systems (your actual VPN or Active Directory). Watching real authentication logs for bait usernames is planned for v0.2.

Tested with a real RDP client (FreeRDP 3), which sends the username Lure reads.

## How alerts are graded

- **high:** a bait username was used. Someone found a planted file and tried it.
- **medium:** something connected to the listener host without a bait username. Nothing legitimate should connect at all, so this is still worth a look. A scanner you run yourself is the usual cause.

The same source, service and username alert once per 10 minutes, with at most 20 alerts per 10 minutes overall, so one attacker cannot flood your pager.

## Data handling

Lure runs entirely on your own machines. The listener records the connecting IP and port, the service, the time and the username it was offered. It sends that only to the sinks you configure. Passwords sent to the listener are never read or stored. SilentMesh receives no data.

## Use responsibly

Only plant baits on systems you own or are authorised to protect. The person who runs the listener controls the data it records (IP addresses and usernames can be personal data, for example under India's DPDP Act 2023) and is responsible for handling it under their own law.

## Limits

- This is a beta. It catches people who find and use credentials. It does not detect an attacker who never touches the baits.
- The OpenVPN login is encrypted, so VPN baits are identified by their port, not their username.
- Do not plant baits on the control network, and do not point a bait at a real system.

## Going further

Lure is the free, IT-side part of SilentMesh. The full product adds decoy PLCs and controllers on the plant network itself (Modbus/TCP, S7comm, IEC 60870-5-104, DNP3, OPC UA, SMB), off the control path and fail-open. See https://silentmesh.me.

## Running the tests

```
python3 -m unittest discover -s tests
```

## Licence

Apache License 2.0. See LICENSE.
