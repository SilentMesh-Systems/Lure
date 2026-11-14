"""Local dashboard: `lure listen --ui` serves a page showing every bait and every alert.

It binds to 127.0.0.1 by default, so it is reachable only from the listener
host itself. Nothing leaves the machine. Changing state (acknowledging an
alert) needs a JSON POST from the dashboard's own origin, so a web page the
operator happens to visit cannot do it for them.
"""

import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from ._mark import MARK_PNG_B64

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lure</title>
<style>
:root{--void:#000;--glass:rgba(255,255,255,.035);--rim:rgba(125,255,92,.18);--text:#EEF6EA;--dim:rgba(238,246,234,.5);--lime:#7DFF5C;--hot:#E9FFD9;--ember:#FF7A59}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:var(--void);color:var(--text);font:14px/1.55 ui-sans-serif,system-ui,sans-serif;
 background-image:radial-gradient(900px 420px at 15% -10%,rgba(125,255,92,.10),transparent 60%),radial-gradient(700px 380px at 110% 10%,rgba(125,255,92,.05),transparent 60%)}
.top{display:flex;align-items:center;gap:14px;padding:22px 28px}
.top img{width:40px;height:40px;border-radius:11px;box-shadow:0 0 24px rgba(125,255,92,.25)}
.top .name{font:500 17px ui-sans-serif,system-ui;letter-spacing:.02em}.top .name span{color:var(--lime)}
.top .tag{margin-left:auto;font:11px ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);border:1px solid var(--rim);border-radius:999px;padding:5px 12px}
.live{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--lime);margin-right:8px;box-shadow:0 0 10px var(--lime);animation:p 2.4s ease-in-out infinite}
@keyframes p{50%{opacity:.35}}@media (prefers-reduced-motion:reduce){.live{animation:none}}
main{max-width:1180px;margin:0 auto;padding:0 28px 48px;display:grid;grid-template-columns:1.6fr 1fr;gap:24px}
@media (max-width:860px){main{grid-template-columns:1fr}}
.glass{background:var(--glass);border:1px solid var(--rim);border-radius:22px;padding:22px;backdrop-filter:blur(6px)}
.hero{grid-column:1/-1;display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.ring{width:132px;height:132px;border-radius:50%;display:grid;place-items:center;
 background:conic-gradient(var(--lime) var(--deg,0deg),rgba(255,255,255,.06) 0);box-shadow:0 0 40px rgba(125,255,92,.12)}
.ring>div{width:108px;height:108px;border-radius:50%;background:#030403;display:grid;place-items:center;text-align:center}
.ring b{font:300 34px ui-sans-serif,system-ui;display:block}.ring small{font:10px ui-monospace,monospace;letter-spacing:.14em;color:var(--dim);text-transform:uppercase}
.headline{flex:1;min-width:240px}.headline h1{font:300 30px ui-sans-serif,system-ui;margin:0;letter-spacing:-.01em}
.headline p{margin:6px 0 0;color:var(--dim)}.headline .calm{color:var(--lime)}.headline .alarm{color:var(--ember)}
.nums{display:flex;gap:26px}.nums div{text-align:right}.nums b{display:block;font:300 28px ui-sans-serif}.nums span{font:10px ui-monospace,monospace;letter-spacing:.14em;color:var(--dim);text-transform:uppercase}
h2{font:500 11px ui-monospace,monospace;letter-spacing:.22em;text-transform:uppercase;color:var(--dim);margin:0 0 16px}
.feed{display:flex;flex-direction:column;gap:12px}
.ev{position:relative;padding:14px 16px 14px 22px;border-radius:16px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);overflow:hidden}
.ev:before{content:"";position:absolute;left:0;top:10%;bottom:10%;width:3px;border-radius:3px;background:var(--lime);box-shadow:0 0 14px var(--lime)}
.ev.medium:before{background:#F2C14E;box-shadow:0 0 12px #F2C14E}.ev.ack{opacity:.4}.ev.ack:before{box-shadow:none}
.ev .row{display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap}
.ev .what{font-weight:500}.ev .when{font:12px ui-monospace,monospace;color:var(--dim)}
.ev .where{margin-top:4px;color:var(--hot);font:13px ui-monospace,monospace;word-break:break-all}
.ev .src{margin-top:2px;color:var(--dim);font:12px ui-monospace,monospace}
.ev button{margin-top:10px;background:transparent;color:var(--lime);border:1px solid var(--rim);border-radius:999px;padding:5px 14px;font-size:12px;cursor:pointer}
.ev button:hover,.ev button:focus-visible{background:rgba(125,255,92,.1);outline:none}
.tiles{display:grid;grid-template-columns:1fr;gap:10px}
.tile{display:flex;gap:12px;align-items:center;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.02)}
.dot{flex:none;width:10px;height:10px;border-radius:50%;background:rgba(125,255,92,.35)}
.tile.hit{border-color:rgba(255,122,89,.35);background:rgba(255,122,89,.05)}.tile.hit .dot{background:var(--ember);box-shadow:0 0 12px var(--ember)}
.tile .f{font:13px ui-monospace,monospace}.tile .w{font-size:12px;color:var(--dim);word-break:break-all}
.empty{color:var(--dim);text-align:center;padding:28px 10px}
footer{grid-column:1/-1;text-align:center;color:var(--dim);font:11px ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;margin-top:8px}
</style></head><body>
<div class="top"><img alt="Lure" src="data:image/png;base64,__MARK__"><div class="name">SilentMesh <span>Lure</span></div><div class="tag"><span class="live"></span>local only · v__VERSION__</div></div>
<main>
<section class="glass hero">
 <div class="ring" id="ring"><div><b id="pct">0</b><small>quiet</small></div></div>
 <div class="headline"><h1 id="hl">Listening.</h1><p id="sub">Every bait is quiet.</p></div>
 <div class="nums"><div><b id="n-baits">0</b><span>planted</span></div><div><b id="n-open">0</b><span>open</span></div><div><b id="n-all">0</b><span>all alerts</span></div></div>
</section>
<section class="glass"><h2>Alert feed</h2><div class="feed" id="feed"></div></section>
<section class="glass"><h2>Attacker path</h2><div class="feed" id="paths"></div><h2 style="margin-top:24px">Baits</h2><div class="tiles" id="tiles"></div></section>
<footer>Deceive, never disrupt.</footer>
</main>
<script>
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=String(text);return e;}
function render(st){
  var feed=document.getElementById('feed');feed.textContent='';var open=0;
  if(!st.alerts.length)feed.appendChild(el('div','empty','Silence. Lure speaks only when someone uses a bait.'));
  st.alerts.forEach(function(a){
    if(!a.acknowledged)open++;
    var c=el('div','ev '+a.severity+(a.acknowledged?' ack':''));
    var r=el('div','row');
    r.appendChild(el('div','what',a.severity==='high'?((a.retired?'Retired bait used: ':'Bait used: ')+(a.bait_file||'')):'Someone touched the listener'));
    r.appendChild(el('div','when',(a.time||'').replace('T',' ').replace('+00:00',' UTC')));
    c.appendChild(r);
    if(a.location||a.planted_on)c.appendChild(el('div','where',a.location||a.planted_on));
    c.appendChild(el('div','src','from '+a.source+' over '+a.service+(a.username?' as '+a.username:'')));
    if(!a.acknowledged){var b=el('button',null,'Mark investigated');b.onclick=function(){ack(a.id);};c.appendChild(b);}
    feed.appendChild(c);
  });
  var tiles=document.getElementById('tiles');tiles.textContent='';var hit=0;
  st.baits.forEach(function(b){
    if(b.triggered)hit++;
    var t=el('div','tile'+(b.triggered?' hit':''));t.appendChild(el('span','dot'));
    var x=el('div');x.appendChild(el('div','f',b.file+(b.port?' :'+b.port:'')));x.appendChild(el('div','w',(b.triggered?'TRIGGERED · ':'')+(b.location||b.plant_on||'')+(b.actor?' · '+b.actor:'')));
    t.appendChild(x);tiles.appendChild(t);
  });
  var pe=document.getElementById('paths');pe.textContent='';var ips=Object.keys(st.paths||{});
  if(!ips.length)pe.appendChild(el('div','empty','No trail yet.'));
  ips.forEach(function(ip){var c=el('div','ev');c.appendChild(el('div','what',ip));
    st.paths[ip].forEach(function(s,i){c.appendChild(el('div','src',(i+1)+'. '+s.file+'  ('+s.service+', '+(s.time||'').slice(11,19)+' UTC)'));});pe.appendChild(c);});
  var n=st.baits.length,q=n?Math.round(100*(n-hit)/n):100;
  document.getElementById('pct').textContent=q+'%';
  document.getElementById('ring').style.setProperty('--deg',(q*3.6)+'deg');
  document.getElementById('n-baits').textContent=n;document.getElementById('n-open').textContent=open;document.getElementById('n-all').textContent=st.alerts.length;
  var hl=document.getElementById('hl'),sub=document.getElementById('sub');
  if(open){hl.textContent=open+(open>1?' open alerts.':' open alert.');sub.textContent=hit+' bait'+(hit===1?' has':'s have')+' been used. Someone is looking for credentials.';sub.className='alarm';}
  else{hl.textContent='Listening.';sub.textContent=hit?'Everything seen so far is marked investigated.':'Every bait is quiet.';sub.className='calm';}
}
function load(){fetch('/api/state').then(function(r){return r.json();}).then(render).catch(function(){});}
function ack(id){fetch('/api/ack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})}).then(load);}
load();setInterval(load,3000);
</script></body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    alerter = None
    allowed_origins = ()
    allowed_hosts = ()
    port = 0

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        # DNS rebinding: a hostile page that points its own name at 127.0.0.1
        # must not read the alerts. Only this dashboard's own host names pass.
        host = self.headers.get("Host", "")
        if host in self.allowed_hosts:
            return True
        # A literal IP address cannot be rebound, so a dashboard served on
        # 0.0.0.0 still opens by the machine's address. Names other than
        # localhost are refused.
        name, _, port = host.rpartition(":")
        if port != str(self.port):
            return False
        try:
            ipaddress.ip_address(name.strip("[]"))
            return True
        except ValueError:
            return False

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "forbidden", "text/plain")
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.replace("__VERSION__", __version__).replace("__MARK__", MARK_PNG_B64), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self._send(200, json.dumps(self.alerter.state()), "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, "forbidden", "text/plain")
        if self.path != "/api/ack":
            return self._send(404, "not found", "text/plain")
        # Refuse cross-site requests: JSON only, and the Origin must be this dashboard.
        origin = self.headers.get("Origin")
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json" or \
                (origin is not None and origin not in self.allowed_origins):
            return self._send(403, "forbidden", "text/plain")
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 4096)
            alert_id = int(json.loads(self.rfile.read(n) or b"{}").get("id"))
        except (ValueError, TypeError, AttributeError):
            return self._send(400, "bad request", "text/plain")
        ok = self.alerter.acknowledge(alert_id)
        self._send(200 if ok else 404, json.dumps({"ok": ok}), "application/json")


def serve(alerter, host="127.0.0.1", port=8765):
    """Start the dashboard in a background thread and return the server."""
    handler = type("Handler", (_Handler,), {
        "alerter": alerter,
        "allowed_origins": (f"http://{host}:{port}", f"http://localhost:{port}", f"http://127.0.0.1:{port}"),
        "allowed_hosts": (f"{host}:{port}", f"localhost:{port}", f"127.0.0.1:{port}"),
        "port": port,
    })
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
