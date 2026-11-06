"""Generate bait files that hold decoy credentials.

Each bait gets its own decoy username, so a later login attempt tells you
exactly which file was found and where it was planted. Nothing in a bait
file phones home when it is opened: the alert fires only when someone uses
the credential against the listener host (see listen.py). Antivirus scans,
backups and search indexing therefore never raise an alert.
"""

import json
import os
import secrets
import zipfile
from datetime import datetime, timezone
from xml.sax.saxutils import escape

FIRST_NAMES = ["svc_hist", "eng_maint", "scada_ro", "ops_backup", "vendor_sup"]


def _token(prefix):
    return f"{prefix}{secrets.token_hex(3)}"


def _password():
    # Looks like a real, slightly lazy plant password. It is never valid anywhere.
    words = ["Plant", "Turbine", "Boiler", "Kiln", "Mill", "Grid"]
    return f"{secrets.choice(words)}@{secrets.randbelow(9000) + 1000}!"


def _xlsx(path, rows):
    """Write a minimal but valid .xlsx (opens in Excel and LibreOffice)."""
    def cell(ref, value):
        return f'<c r="{ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'

    cols = "ABCD"
    sheet_rows = []
    for r, row in enumerate(rows, start=1):
        cells = "".join(cell(f"{cols[c]}{r}", v) for c, v in enumerate(row))
        sheet_rows.append(f'<row r="{r}">{cells}</row>')
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>'
    )
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            "</Types>"
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>"
        ),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Logins" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            "</Relationships>"
        ),
        "xl/worksheets/sheet1.xml": sheet,
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)


def generate(listener, out_dir, site="plant"):
    """Write the bait set into out_dir and return the manifest.

    listener: the hostname or IP of the host running `tripwire listen`.
    Pick one nothing legitimate ever logs into.
    """
    os.makedirs(out_dir, exist_ok=True)
    baits = []

    rdp_user, rdp_pw = _token("eng_maint_"), _password()
    rdp_file = os.path.join(out_dir, "jump-host.rdp")
    with open(rdp_file, "w", newline="\r\n") as f:
        f.write(
            f"full address:s:{listener}:3389\n"
            f"username:s:{rdp_user}\n"
            "prompt for credentials:i:1\n"
            "screen mode id:i:2\n"
            "authentication level:i:2\n"
        )
    baits.append({"file": "jump-host.rdp", "service": "rdp", "username": rdp_user, "plant_on": "engineering workstation desktop"})

    vpn_user, vpn_pw = _token("vendor_sup_"), _password()
    with open(os.path.join(out_dir, f"{site}-vendor-vpn.ovpn"), "w") as f:
        f.write(
            "client\ndev tun\nproto tcp\n"
            f"remote {listener} 1194\n"
            "auth-user-pass\nnobind\npersist-key\npersist-tun\nverb 3\n"
            f"# vendor remote support login: {vpn_user} / {vpn_pw}\n"
        )
    baits.append({"file": f"{site}-vendor-vpn.ovpn", "service": "openvpn", "username": vpn_user, "plant_on": "jump host or vendor laptop share"})

    web_user, web_pw = _token("scada_ro_"), _password()
    hist_user, hist_pw = _token("svc_hist_"), _password()
    _xlsx(os.path.join(out_dir, "passwords.xlsx"), [
        ["System", "Address", "Username", "Password"],
        ["Jump host (RDP)", f"{listener}:3389", rdp_user, rdp_pw],
        ["SCADA web (read-only)", f"http://{listener}:8080/", web_user, web_pw],
        ["Historian service", f"http://{listener}:8080/historian", hist_user, hist_pw],
        ["Vendor VPN", f"{listener}:1194", vpn_user, vpn_pw],
    ])
    for u, p, what in [(web_user, web_pw, "SCADA web"), (hist_user, hist_pw, "Historian")]:
        baits.append({"file": "passwords.xlsx", "service": "http", "username": u,
                      "plant_on": f"engineering share ({what} row)"})

    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "listener": listener,
        "site": site,
        "baits": baits,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest
