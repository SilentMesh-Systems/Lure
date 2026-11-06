# SilentMesh Tripwire (beta)

Free credential tripwires for converged IT/OT networks.

Attackers who reach a plant usually come in through stolen VPN or jump-host logins, then look for more saved passwords on engineering workstations. Tripwire plants fake ones for them to find. If anyone tries to use one, you get an alert that says which file was found and where you planted it.

- **No agent, nothing on the control network.** Bait files go on IT-side machines: engineering workstations, jump hosts, vendor shares.
- **Alerts on use, not on open.** Opening, copying, backing up or antivirus-scanning a bait file does nothing. Only a login attempt with a bait credential fires an alert.
- **Your alerts go only to you.** The listener sends alerts to your own webhook, syslog or terminal. No SilentMesh service is involved, and nothing is sent to us.
- **Python 3.9+, standard library only.** Apache-2.0.

## Quick start

1. Pick a tripwire host: any spare Linux machine or VM on the IT side that nobody legitimately logs into.

2. Generate the bait set, pointing it at that host:

   ```
   python3 -m tripwire generate --listener 10.0.5.20 --out baits
   ```

   This writes:

   | File | What it looks like | Where to plant it |
   |---|---|---|
   | `passwords.xlsx` | A real spreadsheet of logins: jump host, SCADA web, historian, vendor VPN | An engineering share or a workstation's Documents folder |
   | `jump-host.rdp` | A saved Remote Desktop connection with a username filled in | An engineering workstation desktop |
   | `plant-vendor-vpn.ovpn` | A vendor remote-support VPN profile with its login in a comment | A jump host or a vendor laptop share |
   | `manifest.json` | Which username belongs to which bait. **Keep this off the network.** | Only on the tripwire host |

3. Run the listener on the tripwire host:

   ```
   python3 -m tripwire listen --manifest baits/manifest.json \
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

## How alerts are graded

- **high:** a bait username was used. Someone found a planted file and tried it.
- **medium:** something connected to the tripwire host without a bait username. Nothing legitimate should connect at all, so this is still worth a look. A scanner you run yourself is the usual cause.

The same source, service and username alert once per 10 minutes, with at most 20 alerts per 10 minutes overall, so one attacker cannot flood your pager.

## Data handling

Tripwire runs entirely on your own machines. The listener records the connecting IP and port, the service, the time and the username it was offered. It sends that only to the sinks you configure. Passwords sent to the listener are never read or stored. SilentMesh receives no data.

## Limits

- This is a beta. It catches people who find and use credentials. It does not detect an attacker who never touches the baits.
- The OpenVPN listener records the connection only; it does not read the username.
- Do not plant baits on the control network, and do not point a bait at a real system.

## Going further

Tripwire is the free, IT-side part of SilentMesh. The full product adds decoy PLCs and controllers on the plant network itself (Modbus/TCP, S7comm, IEC 60870-5-104, DNP3, OPC UA, SMB), off the control path and fail-open. See https://silentmesh.me.

## Running the tests

```
python3 -m unittest discover -s tests
```

## Licence

Apache License 2.0. See LICENSE.
