"""MCP server: lets an AI agent plant baits and read alerts.

Run `lure mcp --manifest baits/manifest.json` from an MCP client (Claude
Desktop, Claude Code, any MCP-capable agent). It speaks the Model Context
Protocol (spec 2026-07-28, plus the 2025 handshake versions) over stdio, using only the standard library.

The server works on one bait set: the manifest it was started with, and the
alerts.jsonl beside it that `lure listen` writes. It never contacts anything
on the network and never returns bait passwords, only usernames, files and
alerts. Run `lure listen` separately; the agent reads what it records.
"""

import json
import os
import sys

from . import __version__
from .generate import PROFILES, STORYLINES, generate, record, rotate

PROTOCOL = "2026-07-28"
LEGACY = ["2025-11-25", "2025-06-18"]  # handshake-era versions, still served via `initialize`
SUPPORTED = [PROTOCOL] + LEGACY
_META = "io.modelcontextprotocol/"
INSTRUCTIONS = ("Lure plants fake credentials and reports when an attacker uses one. "
                "Start with lure_status. A high alert means someone found and tried a bait.")

# (read-only, destructive, idempotent); none of the tools reach outside this machine.
_ANNOTATIONS = {
    "lure_status": (True, False, True),
    "lure_alerts": (True, False, True),
    "lure_baits": (True, False, True),
    "lure_generate": (False, False, False),
    "lure_record": (False, True, True),
    "lure_rotate": (False, True, False),
    "lure_acknowledge": (False, False, True),
}

TOOLS = [
    {"name": "lure_status",
     "description": "Read-only summary of the bait set: live and retired bait counts, which baits have been used, open alerts, the attacker's path per source address, and a one-line verdict. Reads the local manifest and alert log only; changes nothing and needs no network or credentials. Call this first to answer 'are we compromised?'.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "lure_alerts",
     "description": "Read-only list of alerts from the local alert log, newest first, filtered by severity and open state. high = a bait credential was used; medium = something touched the listener without one. Changes nothing. Use it to answer 'has anyone used a bait?' and to get the alert id for lure_acknowledge.",
     "inputSchema": {"type": "object", "properties": {
         "severity": {"type": "string", "enum": ["high", "medium", "any"], "default": "any"},
         "open_only": {"type": "boolean", "default": False, "description": "only alerts not yet marked investigated"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20}},
         "additionalProperties": False}},
    {"name": "lure_baits",
     "description": "Read-only list of every live (non-retired) bait: file, username, service, where it should be planted, where it was recorded as planted, and whether it has fired. Passwords are never returned. Changes nothing.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "lure_generate",
     "description": "Create a new bait set: writes bait files and manifest.json into the manifest's folder on this machine. Refuses with an error if a bait set already exists there, so it never overwrites; use lure_rotate to replace a set. Writes local files only: it does not plant anything, contact the network or start the listener.",
     "inputSchema": {"type": "object", "properties": {
         "listener": {"type": "string", "description": "host or IP of the machine that runs `lure listen`"},
         "profile": {"type": "string", "enum": sorted(PROFILES), "default": "it"},
         "storyline": {"type": "string", "enum": sorted(STORYLINES),
                       "description": "the story the baits tell together; omitted: picked at random"},
         "vpn_count": {"type": "integer", "minimum": 1, "maximum": 10, "default": 1}},
         "required": ["listener"], "additionalProperties": False}},
    {"name": "lure_record",
     "description": "Record where a bait was planted, so later alerts name the exact host and path. Updates the location field in manifest.json, overwriting any earlier location; a file name updates every live bait in that file. Returns how many baits were updated. Errors if no live bait matches; never creates baits and does not touch the planted host.",
     "inputSchema": {"type": "object", "properties": {
         "bait": {"type": "string", "description": "bait file name or username"},
         "location": {"type": "string", "description": "host and path, e.g. FIN-WS-07:C:\\Users\\admin\\Desktop"}},
         "required": ["bait", "location"], "additionalProperties": False}},
    {"name": "lure_rotate",
     "description": "Replace the live baits with a fresh set: writes new bait files and marks the old ones retired in manifest.json. Not reversible, but nothing is lost: retired baits stay in the manifest and still alert if used. You must replant the new files and restart `lure listen` afterwards. Local files only.",
     "inputSchema": {"type": "object", "properties": {
         "profile": {"type": "string", "enum": sorted(PROFILES)},
         "storyline": {"type": "string", "enum": sorted(STORYLINES)}}, "additionalProperties": False}},
    {"name": "lure_acknowledge",
     "description": "Mark one alert as investigated, by its id from lure_alerts. Sets acknowledged=true in the local alert log; the alert itself is kept, never deleted. Repeating it is harmless. Errors if no alert has that id.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}},
                     "required": ["id"], "additionalProperties": False}},
]

for _t in TOOLS:
    _ro, _destr, _idem = _ANNOTATIONS[_t["name"]]
    _t["annotations"] = {"readOnlyHint": _ro, "destructiveHint": _destr,
                          "idempotentHint": _idem, "openWorldHint": False}


class Server:
    def __init__(self, manifest_path, log_path=None):
        self.manifest_path = os.path.abspath(manifest_path)
        self.dir = os.path.dirname(self.manifest_path)
        self.log_path = log_path or os.path.join(self.dir, "alerts.jsonl")

    # --- data -----------------------------------------------------------
    def _manifest(self):
        try:
            with open(self.manifest_path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {"baits": []}

    def _alerts(self):
        try:
            with open(self.log_path) as f:
                return [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []

    @staticmethod
    def _public(b, fired):
        return {k: b.get(k) for k in ("file", "username", "service", "port", "plant_on", "location", "actor", "retired")
                if b.get(k) is not None} | {"triggered": b["username"] in fired}

    # --- tools ----------------------------------------------------------
    def lure_status(self):
        m, alerts = self._manifest(), self._alerts()
        fired = {a["username"] for a in alerts if a.get("severity") == "high"}
        live = [b for b in m.get("baits", []) if not b.get("retired")]
        paths = {}
        for a in alerts:
            if a.get("severity") == "high":
                ip = a["source"].rsplit(":", 1)[0]
                if not paths.get(ip) or paths[ip][-1] != a["bait_file"]:
                    paths.setdefault(ip, []).append(a["bait_file"])
        return {"profile": m.get("profile"), "listener": m.get("listener"), "live_baits": len(live),
                "retired_baits": len(m.get("baits", [])) - len(live),
                "triggered_baits": sorted({b["file"] for b in m.get("baits", []) if b["username"] in fired}),
                "open_alerts": sum(1 for a in alerts if not a.get("acknowledged")),
                "total_alerts": len(alerts), "attacker_paths": paths,
                "verdict": ("Someone has used a bait: treat it as an intrusion." if fired else "Quiet: no bait has been used.")}

    def lure_alerts(self, severity="any", open_only=False, limit=20):
        out = [a for a in reversed(self._alerts())
               if (severity == "any" or a.get("severity") == severity) and not (open_only and a.get("acknowledged"))]
        return {"alerts": out[:limit], "shown": min(limit, len(out)), "matching": len(out)}

    def lure_baits(self):
        alerts = self._alerts()
        fired = {a["username"] for a in alerts if a.get("severity") == "high"}
        return {"baits": [self._public(b, fired) for b in self._manifest().get("baits", []) if not b.get("retired")]}

    def lure_generate(self, listener, profile="it", vpn_count=1, storyline=None):
        if os.path.exists(self.manifest_path) and self._manifest().get("baits"):
            raise ValueError("a bait set already exists here; use lure_rotate to replace it")
        m = generate(listener, self.dir, profile=profile, vpn_count=vpn_count, storyline=storyline)
        return {"written": sorted({b["file"] for b in m["baits"]}), "baits": len(m["baits"]), "folder": self.dir,
                "storyline": m["storyline"],
                "next": "Plant the files, record each with lure_record, and run `lure listen` on the listener host."}

    def lure_record(self, bait, location):
        n = record(self.manifest_path, bait, location)
        if not n:
            raise ValueError(f"no live bait named {bait!r}")
        return {"updated": n, "location": location}

    def lure_rotate(self, profile=None, storyline=None):
        kw = {k: v for k, v in (("profile", profile), ("storyline", storyline)) if v}
        m = rotate(self.manifest_path, **kw)
        live = [b for b in m["baits"] if not b.get("retired")]
        return {"fresh": sorted({b["file"] for b in live}), "retired_still_alerting": len(m["baits"]) - len(live),
                "next": "Replant the fresh files and restart `lure listen` so it loads the new manifest."}

    def lure_acknowledge(self, id):
        alerts = self._alerts()
        hit = False
        for a in alerts:
            if a.get("id") == id:
                a["acknowledged"] = hit = True
        if not hit:
            raise ValueError(f"no alert with id {id}")
        with open(self.log_path, "w") as f:
            f.writelines(json.dumps(a) + "\n" for a in alerts)
        return {"acknowledged": id}

    # --- protocol -------------------------------------------------------
    def handle(self, msg):
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            return None  # notifications need no reply
        params = msg.get("params")
        if not isinstance(params, dict):
            params = {}
        meta = params.get("_meta")
        ver = meta.get(_META + "protocolVersion") if isinstance(meta, dict) else None
        modern = ver == PROTOCOL
        if ver is not None and not modern and method != "initialize":
            return self._error(mid, -32022, "unsupported protocol version",
                               {"supported": SUPPORTED, "requested": ver})
        try:
            if method == "initialize":
                asked = params.get("protocolVersion")
                result = {"protocolVersion": asked if asked in LEGACY else LEGACY[0],
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": "lure", "title": "SilentMesh Lure", "version": __version__},
                          "instructions": INSTRUCTIONS}
            elif method == "server/discover":
                result = {"resultType": "complete", "supportedVersions": SUPPORTED,
                          "capabilities": {"tools": {}}, "instructions": INSTRUCTIONS,
                          "ttlMs": 3600000, "cacheScope": "public"}
                modern = True
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
                if modern:
                    result.update(ttlMs=3600000, cacheScope="public")
            elif method == "tools/call":
                name, args = params.get("name"), params.get("arguments") or {}
                if name not in {t["name"] for t in TOOLS}:
                    return self._error(mid, -32602, f"unknown tool {name!r}")
                try:
                    data = getattr(self, name)(**args)
                    result = {"content": [{"type": "text", "text": json.dumps(data, indent=2)}],
                              "structuredContent": data, "isError": False}
                except (ValueError, TypeError, OSError) as e:
                    result = {"content": [{"type": "text", "text": str(e)}], "isError": True}
            else:
                return self._error(mid, -32601, f"method not found: {method}")
            if modern:
                result.setdefault("resultType", "complete")
                result["_meta"] = {_META + "serverInfo": {"name": "lure", "title": "SilentMesh Lure",
                                                         "version": __version__}}
            return {"jsonrpc": "2.0", "id": mid, "result": result}
        except Exception as e:  # never crash the agent's session
            return self._error(mid, -32603, f"internal error: {e}")

    @staticmethod
    def _error(mid, code, message, data=None):
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": mid, "error": err}


def serve_stdio(manifest_path, log_path=None, stdin=None, stdout=None):
    server = Server(manifest_path, log_path)
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply = Server._error(None, -32700, "parse error")
        else:
            reply = server.handle(msg)
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
