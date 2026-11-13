"""Generate bait files that hold decoy credentials.

The baits are written to be believed. Usernames look like real accounts, file
names look like a busy admin saved them, timestamps are months old, and the
files point at each other, so finding one makes the next more convincing.
Each bait still has its own username, so a login attempt says exactly which
file was found and where it was planted.

Nothing in a bait phones home when it is opened. The alert fires only when
someone uses a credential against the listener host (see listen.py), so
antivirus scans, backups and search indexing never raise an alert.
"""

import json
import ipaddress
import re
import os
import random
import secrets
import time
import zipfile
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

_rng = random.SystemRandom()

FIRST = list("aabcdghjkmnprssstv")
SURNAMES = ["patil", "sharma", "iyer", "rao", "nair", "verma", "kulkarni", "reddy", "menon", "das",
            "joshi", "pillai", "gupta", "bose", "khan", "shetty", "naidu", "bhat", "kumar", "mehta",
            "fernandes", "singh", "chandra", "hegde", "murthy", "dutta", "ghosh", "pandey", "jain", "saxena"]
PEOPLE = ["Ravi", "Suresh", "Anita", "Prakash", "Deepa", "Karthik", "Meena", "Vinod", "Farhan", "Lakshmi"]

# What the baits talk about, per kind of site. Systems point at the listener's
# HTTP port; the paths make each row look like a different application.
PROFILES = {
    "it": {
        "systems": [("NAS admin", "/nas", "nas.admin"), ("vCenter (read-only)", "/vcenter", "svc_vcenter"),
                    ("Intranet admin", "/intranet", "intranet.adm")],
        "jump": "JUMP-SRV-01", "vendors": ["Infosys", "TCS", "Wipro", "Accenture"],
        "words": ["Welcome", "Summer", "Monsoon", "Company", "Admin", "Diwali"],
        "sheet": ["passwords_FINAL_v2.xlsx", "IT logins - keep safe.xlsx", "admin_accounts_2025.xlsx"],
        "event": "the audit", "dept": "IT Support",
    },
    "home": {
        "systems": [("Router admin", "/router", "admin.router"), ("NAS / photo backup", "/nas", "family.nas"),
                    ("CCTV recorder", "/cctv", "cctv.view")],
        "jump": "HOME-PC", "vendors": ["Airtel", "Jio", "ACT", "Excitel"],
        "words": ["Family", "Home", "Sunshine", "Cricket", "Diwali", "Monsoon"],
        "sheet": ["my passwords.xlsx", "passwords (keep safe).xlsx", "home logins 2025.xlsx"],
        "event": "the router change", "dept": "Home",
    },
    "plant": {
        "systems": [("SCADA web (read-only)", "/scada", "scada_ro"), ("Historian", "/historian", "svc_historian"),
                    ("MES reports", "/mes", "mes.report")],
        "jump": "JUMP-OT-01", "vendors": ["Siemens", "ABB", "Honeywell", "Schneider"],
        "words": ["Turbine", "Boiler", "Kiln", "Plant", "Grid", "Shutdown"],
        "sheet": ["passwords_FINAL_v2.xlsx", "plant logins (do not share).xlsx", "OT_access_list_2025.xlsx"],
        "event": "the shutdown", "dept": "Plant IT",
    },
    "office": {
        "systems": [("Payroll portal", "/payroll", "payroll.admin"), ("Tally server", "/tally", "tally_svc"),
                    ("HR system", "/hr", "hr.admin")],
        "jump": "FINANCE-PC-02", "vendors": ["Tally partner", "Zoho", "Freshworks", "HCL"],
        "words": ["Welcome", "Office", "Summer", "Diwali", "Monsoon", "Finance"],
        "sheet": ["passwords_FINAL_v2.xlsx", "office logins.xlsx", "accounts_2025.xlsx"],
        "event": "year-end closing", "dept": "Admin Office",
    },
    "bank": {
        "systems": [("Core banking (read-only)", "/cbs", "cbs_viewer"), ("Payment switch console", "/switch", "switch.ops"),
                    ("Treasury reports", "/treasury", "treasury_rpt")],
        "jump": "JUMP-DC-01", "vendors": ["Finacle", "FIS", "Temenos", "NCR"],
        "words": ["Ledger", "Branch", "Treasury", "Vault", "Quarter", "Rupee"],
        "sheet": ["passwords_FINAL_v2.xlsx", "branch IT access.xlsx", "DC_access_list_2025.xlsx"],
        "event": "the RBI audit", "dept": "DC Operations",
    },
    "hospital": {
        "systems": [("HIS admin", "/his", "his.admin"), ("PACS viewer", "/pacs", "pacs_ro"),
                    ("Lab system", "/lis", "lis_svc")],
        "jump": "JUMP-MED-01", "vendors": ["Philips", "GE Healthcare", "Siemens Healthineers", "Agfa"],
        "words": ["Ward", "Clinic", "Health", "Doctor", "Night", "Shift"],
        "sheet": ["passwords_FINAL_v2.xlsx", "biomedical logins.xlsx", "HIS_access_2025.xlsx"],
        "event": "the NABH audit", "dept": "Biomedical IT",
    },
}


REQUIRED_KEYS = ("systems", "jump", "vendors", "words", "sheet", "event", "dept")


def load_profile(profile):
    """A built-in profile name, or a path to a JSON profile (see profiles/ for examples)."""
    if profile in PROFILES:
        return PROFILES[profile]
    if str(profile).endswith(".json") and os.path.exists(profile):
        with open(profile) as f:
            p = json.load(f)
        missing = [k for k in REQUIRED_KEYS if k not in p]
        if missing:
            raise ValueError(f"profile {profile} is missing: {', '.join(missing)}")
        if len(p["systems"]) < 2 or not all(len(s) == 3 for s in p["systems"]):
            raise ValueError("profile systems must be at least two [title, path, username base] entries")
        p["systems"] = [tuple(s) for s in p["systems"]]
        return p
    raise ValueError(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)} or give a .json profile file")


class _Names:
    """Hands out believable usernames, never the same one twice in a set."""

    def __init__(self, taken=()):
        self.taken = set(taken)

    def _unique(self, make):
        for _ in range(500):
            name = make()
            if name not in self.taken:
                self.taken.add(name)
                return name
        raise RuntimeError("could not find a unique username")

    def person(self, role="adm"):
        return self._unique(lambda: f"{_rng.choice(FIRST)}.{_rng.choice(SURNAMES)}"
                            + _rng.choice(["_" + role, "_" + role, "", "2", "_ot", "_it"]))

    def service(self, base):
        return self._unique(lambda: base + _rng.choice(["", "2", "_old", "01", "_rw", "_bkp", "3"]))

    def vendor(self, vendor):
        v = vendor.lower().split()[0]
        return self._unique(lambda: _rng.choice([f"{v}.support", f"vendor.{v}", f"{v}_remote", f"{v}.svc"])
                            + _rng.choice(["", "1", "2", "_in"]))


def _password(words):
    # Looks like a real, slightly lazy password. It is never valid anywhere.
    w = _rng.choice(words)
    return _rng.choice([f"{w}@{_rng.randint(2019, 2026)}!", f"{w}#{_rng.randint(100, 9999)}",
                        f"{w}{_rng.randint(10, 99)}$", f"{w.lower()}@{_rng.randint(1000, 9999)}"])


def _old_date(min_days=40, max_days=240):
    return datetime.now(timezone.utc) - timedelta(days=_rng.randint(min_days, max_days),
                                                  hours=_rng.randint(0, 23), minutes=_rng.randint(0, 59))


def _backdate(path, when):
    ts = when.timestamp()
    os.utime(path, (ts, ts))


def _xlsx(path, sheets, author, created, modified):
    """Write a valid .xlsx with several sheets and real-looking document metadata."""
    def cell(ref, value):
        return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape(value)}</t></is></c>'

    def sheet_xml(rows):
        cols = "ABCDEFGH"
        out = []
        for r, row in enumerate(rows, start=1):
            out.append(f'<row r="{r}">' + "".join(cell(f"{cols[c]}{r}", v) for c, v in enumerate(row)) + "</row>")
        widths = '<cols><col min="1" max="1" width="26" customWidth="1"/><col min="2" max="2" width="34" customWidth="1"/>' \
                 '<col min="3" max="4" width="20" customWidth="1"/><col min="5" max="5" width="44" customWidth="1"/>' \
                 '<col min="6" max="6" width="12" customWidth="1"/></cols>'
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                f'{widths}<sheetData>{"".join(out)}</sheetData></worksheet>')

    iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for i in range(1, len(sheets) + 1))
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            f"{overrides}</Types>"),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>"),
        "docProps/core.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:creator>{escape(author)}</dc:creator><cp:lastModifiedBy>{escape(author)}</cp:lastModifiedBy>"
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{iso(created)}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{iso(modified)}</dcterms:modified>'
            "</cp:coreProperties>"),
        "docProps/app.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            "<Application>Microsoft Excel</Application></Properties>"),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
            + "".join(f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i}"/>'
                      for i, (name, _) in enumerate(sheets, start=1))
            + "</sheets></workbook>"),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                      f'Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1))
            + "</Relationships>"),
    }
    for i, (_, rows) in enumerate(sheets, start=1):
        parts[f"xl/worksheets/sheet{i}.xml"] = sheet_xml(rows)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)


_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _check_host(value, what):
    """A listener or zone goes into RDP, VPN and URL baits verbatim: only a bare
    hostname or IP address may, so nothing can smuggle extra lines into them."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not isinstance(value, str) or not _HOSTNAME.match(value):
        raise ValueError(f"{what} must be a hostname or IP address, got {value!r}")
    return value


def generate(listener, out_dir, site="site", vpn_count=1, vpn_port=1194, profile="it",
             http_port=8080, rdp_port=3389, retired=None, dns_zone=None):
    """Write a convincing bait set into out_dir and return the manifest.

    listener: the hostname or IP of the host running `lure listen`. Pick one
    nothing legitimate ever logs into. profile: it (default), office, home, plant, bank or hospital.
    retired: baits from an earlier set (see rotate); they stay in the manifest
    so a credential stolen months ago still raises an alert.
    """
    _check_host(listener, "listener")
    if dns_zone:
        _check_host(dns_zone.strip("."), "dns zone")
    p = load_profile(profile)
    os.makedirs(out_dir, exist_ok=True)
    names = _Names(b["username"] for b in (retired or []))
    baits, files = [], []
    person, helper = _rng.sample(PEOPLE, 2)
    vendor = _rng.choice(p["vendors"])
    jump = p["jump"]
    web = f"http://{listener}:{http_port}"
    when = _old_date()

    def add(file, service, username, plant_on, leads_to=(), **extra):
        baits.append(dict({"file": file, "service": service, "username": username, "plant_on": plant_on,
                           "leads_to": list(leads_to), "location": None}, **extra))

    sheet_name = _rng.choice(p["sheet"])
    rdp_name = _rng.choice([f"DO NOT DELETE - {jump}.rdp", f"{jump} (admin).rdp", f"{jump.lower()}.rdp"])
    vpn_names = [f"{vendor} support VPN{' (old)' if i == 0 else ' ' + str(i + 1)}.ovpn"
                 for i in range(max(1, vpn_count))]
    csv_name = "passwords.csv"
    eml_name = f"Re- {vendor} remote access.eml"
    git_name = ".git-credentials"

    # 1. The saved Remote Desktop connection: the crown jewel an intruder wants.
    rdp_user, rdp_pw = names.person("adm"), _password(p["words"])
    with open(os.path.join(out_dir, rdp_name), "w", newline="\r\n") as f:
        f.write(f"full address:s:{listener}:{rdp_port}\nusername:s:{rdp_user}\n"
                "prompt for credentials:i:1\nscreen mode id:i:2\nauthentication level:i:2\n"
                "redirectclipboard:i:1\nsession bpp:i:32\n")
    files.append(rdp_name)
    add(rdp_name, "rdp", rdp_user, "an admin or engineering workstation desktop")

    # 2. Vendor VPN profiles, one listener port each (the VPN login is encrypted).
    vpns = []
    for i, name in enumerate(vpn_names):
        u, pw = names.vendor(vendor), _password(p["words"])
        port = vpn_port + i
        with open(os.path.join(out_dir, name), "w") as f:
            f.write("client\ndev tun\nproto tcp\n"
                    f"remote {listener} {port}\n"
                    "auth-user-pass\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nverb 3\n"
                    f"# {vendor} remote support login: {u} / {pw}\n"
                    f"# for the internal servers, ask {person} for the {jump} RDP file\n")
        files.append(name)
        add(name, "openvpn", u, "jump host or vendor laptop share", [rdp_name], port=port)
        vpns.append((u, pw, port))

    # 3. The messy spreadsheet: notes, a "temporary" shared admin, an old sheet.
    sys_rows = []
    for title, path, base in p["systems"]:
        u, pw = names.service(base), _password(p["words"])
        sys_rows.append([title, f"{web}{path}", u, pw])
        add(sheet_name, "http", u, f"file share ({title} row)", [rdp_name])
    shared_user, shared_pw = names.person("adm"), _password(p["words"])
    add(sheet_name, "http", shared_user, "file share (shared admin row)", [rdp_name], note="the planted mistake")
    old_rows = []
    for title, path, base in p["systems"][:2]:
        u = names.service(base)
        old_rows.append([title, f"{web}{path}", u, _password(p["words"]), "disabled after migration?", ""])
        add(sheet_name, "http", u, f"file share (old sheet, {title})", note="old credentials, still a bait")
    mod = when.strftime("%d-%b")
    rows = [["System", "Address", "Username", "Password", "Notes", "Updated"],
            [f"{jump} (RDP)", f"{listener}:{rdp_port}", rdp_user, rdp_pw,
             f"via {jump}, saved RDP on the admin desktop", mod]]
    rows += [r + [_rng.choice(["", "read-only", "ask " + helper + " before changing", "same as last year"]), mod]
             for r in sys_rows]
    rows.append(["Shared admin (temporary)", f"{web}/admin", shared_user, shared_pw,
                 f"TODO: rotate after {p['event']}", mod])
    dns_label = None
    if dns_zone:
        dns_label = _rng.choice(["nas-archive", "backup", "fs-old", "vault", "share-arch"]) + str(_rng.randint(2, 19)).zfill(2)
        du, dpw = names.service("backup"), _password(p["words"])
        rows.append(["Backup NAS (old)", f"\\\\{dns_label}.{dns_zone}\\backup", du, dpw, "still mounted on some PCs", mod])
        add(sheet_name, "dns", du, "file share (backup NAS row)", dns_label=dns_label)
    rows.append([f"{vendor} VPN", f"{listener}:{vpns[0][2]}", vpns[0][0], vpns[0][1],
                 f"vendor only, profile on jump host ({vpn_names[0]})", mod])
    _xlsx(os.path.join(out_dir, sheet_name),
          [("Logins", rows), ("Old - do not use", [rows[0]] + old_rows)],
          author=p["dept"], created=when - timedelta(days=_rng.randint(60, 400)), modified=when)
    files.append(sheet_name)

    # 4. A browser password export, the kind left in Downloads.
    csv_rows = []
    for title, path, base in p["systems"][:2]:
        u, pw = names.person("ro"), _password(p["words"])
        csv_rows.append(f"{title},{web}{path}/login,{u},{pw}")
        add(csv_name, "http", u, "a user's Downloads folder")
    with open(os.path.join(out_dir, csv_name), "w") as f:
        f.write("name,url,username,password\n" + "\n".join(csv_rows) + "\n")
    files.append(csv_name)

    # 5. A git credential store, as found in a home directory.
    gu, gpw = names.service("build"), _password(p["words"])
    with open(os.path.join(out_dir, git_name), "w") as f:
        f.write(f"http://{quote(gu, safe='')}:{quote(gpw, safe='')}@{listener}:{http_port}\n")
    files.append(git_name)
    add(git_name, "http", gu, "a developer or admin home directory")

    # 6. An email that leaks a login and points at the other baits.
    eu, epw = names.vendor(vendor), _password(p["words"])
    sent = (when + timedelta(days=_rng.randint(1, 20))).strftime("%a, %d %b %Y %H:%M:%S +0530")
    with open(os.path.join(out_dir, eml_name), "w", newline="\r\n") as f:
        f.write(f"From: {person} <{person.lower()}@{profile}-it.local>\n"
                f"To: {vendor} Support <support@{vendor.lower().split()[0]}.example>\n"
                f"Subject: Re: {vendor} remote access\nDate: {sent}\n\n"
                f"Hi,\n\nTemporary web login for your engineer until the VPN is sorted:\n\n"
                f"  {web}/vendor\n  user: {eu}\n  pass: {epw}\n\n"
                f"The VPN profile is on the jump host ({vpn_names[0]}). Full list is in {sheet_name} on the share.\n"
                + (f"Old backups are still on \\\\{dns_label}.{dns_zone}\\backup if you need them.\n" if dns_label else "") + "\n"
                f"Regards,\n{person}\n{p['dept']}\n")
    files.append(eml_name)
    add(eml_name, "http", eu, "a mailbox export or Documents folder", [vpn_names[0], sheet_name])

    # 7. A QR code on an "IT helpdesk" notice: scanning it opens a URL with a token.
    from .qr import encode, to_png
    qr_label = _rng.choice(["vpn-setup", "wifi-guest", "helpdesk", "mfa-reset"]) + "-" + str(_rng.randint(10, 99))
    qr_name = _rng.choice(["IT helpdesk - scan to set up VPN.png", "guest wifi QR (print).png", "MFA reset QR - IT.png"])
    to_png(encode(f"{web}/q/{qr_label}"), os.path.join(out_dir, qr_name), scale=10)
    files.append(qr_name)
    add(qr_name, "http", "~" + qr_label, "printed on a notice board, or in a shared Pictures folder", path_token=qr_label)

    # 8. Browser bookmarks: an exported favourites file with admin consoles in it.
    bm_label = _rng.choice(["admin-console", "backup-portal", "firewall-ui", "hypervisor"]) + "-" + str(_rng.randint(10, 99))
    bm_name = "bookmarks.html"
    links = [(f"{title} (admin)", f"{web}{path}") for title, path, _ in p["systems"]]
    links.insert(1, ("Admin console (do not share)", f"{web}/go/{bm_label}"))
    with open(os.path.join(out_dir, bm_name), "w") as f:
        f.write("<!DOCTYPE NETSCAPE-Bookmark-file-1>\n<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n"
                "<TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n    <DT><H3>IT</H3>\n    <DL><p>\n"
                + "".join(f'        <DT><A HREF="{u}">{escape(n)}</A>\n' for n, u in links)
                + "    </DL><p>\n</DL><p>\n")
    files.append(bm_name)
    add(bm_name, "http", "~" + bm_label, "an admin's browser profile or Documents folder", path_token=bm_label)

    for name in files:
        _backdate(os.path.join(out_dir, name), when - timedelta(minutes=_rng.randint(0, 600)))

    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "listener": listener,
        "site": site,
        "profile": profile,
        "dns_zone": dns_zone,
        "baits": baits + [dict(b, retired=True) for b in (retired or [])],
    }
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def rotate(manifest_path, out_dir=None, **kwargs):
    """Replace the bait set with fresh credentials.

    The old baits stay in the manifest marked retired, so anyone who stole them
    earlier still triggers an alert. Returns the new manifest.
    """
    with open(manifest_path) as f:
        old = json.load(f)
    retired = [dict(b, retired=True) for b in old.get("baits", [])]
    out_dir = out_dir or os.path.dirname(os.path.abspath(manifest_path))
    # Move the old bait files aside so the folder holds only the fresh set.
    old_dir = os.path.join(out_dir, "retired", datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    for name in sorted({b["file"] for b in old.get("baits", []) if not b.get("retired")}):
        src = os.path.join(out_dir, name)
        if os.path.exists(src):
            os.makedirs(old_dir, exist_ok=True)
            os.replace(src, os.path.join(old_dir, name))
    kwargs.setdefault("dns_zone", old.get("dns_zone"))
    return generate(old["listener"], out_dir, site=old.get("site", "site"),
                    profile=kwargs.pop("profile", old.get("profile", "it")), retired=retired, **kwargs)


def record(manifest_path, bait, location):
    """Record where a bait was actually planted, e.g. "ENG-WS-07:C:\\Users\\eng\\Desktop".

    bait is a username or a file name; a file name updates every bait in that
    file (the spreadsheet holds several). Returns the number of baits updated.
    """
    with open(manifest_path) as f:
        manifest = json.load(f)
    n = 0
    for b in manifest.get("baits", []):
        if not b.get("retired") and bait in (b["username"], b["file"]):
            b["location"] = location
            n += 1
    if n:
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
    return n
