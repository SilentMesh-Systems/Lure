"""Local dashboard: `lure listen --ui` serves a page showing every bait and every alert.

It binds to 127.0.0.1 by default, so it is reachable only from the listener
host itself. Nothing leaves the machine. Changing state (acknowledging an
alert) needs a JSON POST from the dashboard's own origin, so a web page the
operator happens to visit cannot do it for them.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from ._mark import MARK_PNG_B64

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lure: SilentMesh</title>
<style>
:root{--bg:#05070A;--p:#0B0F14;--p2:#111821;--line:rgba(255,255,255,.07);--text:#E8EDF2;--dim:#7D8896;--faint:#4A5562;
--red:#FF3B5C;--redg:rgba(255,59,92,.14);--green:#22D38A;--greeng:rgba(34,211,138,.12);--amber:#FFB020;--amberg:rgba(255,176,32,.12);--blue:#4C8DFF;--violet:#9B7BFF}
*{box-sizing:border-box}[hidden]{display:none!important}html,body{height:100%}
body{margin:0;background:radial-gradient(1200px 600px at 70% -200px,rgba(76,141,255,.08),transparent 70%),var(--bg);color:var(--text);
 font:13px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Inter,Roboto,sans-serif;font-variant-numeric:tabular-nums}
button{font:inherit;cursor:pointer}
.mono{font-family:ui-monospace,"Cascadia Mono",Menlo,Consolas,monospace}
/* top */
.top{display:flex;align-items:center;gap:22px;padding:0 28px;height:58px;border-bottom:1px solid var(--line);background:rgba(5,7,10,.7);backdrop-filter:blur(10px);position:sticky;top:0;z-index:20}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.3px}.logo img{width:26px;height:26px;border-radius:7px}.logo span{color:var(--green)}
.nav{display:flex;gap:2px;height:100%}.nav button{background:none;border:0;color:var(--dim);padding:0 16px;height:100%;border-bottom:2px solid transparent;font-weight:500}
.nav button:hover{color:var(--text)}.nav button.on{color:var(--text);border-bottom-color:var(--blue)}
.nav .n{background:var(--red);color:#fff;border-radius:9px;padding:0 6px;font-size:11px;margin-left:6px;font-weight:700}
.grow{flex:1}
.chip-host{color:var(--dim);font-size:12px}.chip-host b{color:var(--text);font-weight:600}
.btn{border:1px solid var(--line);background:var(--p2);color:var(--text);padding:8px 14px;border-radius:9px;font-weight:600;transition:all .15s}
.btn:hover{border-color:rgba(255,255,255,.18);transform:translateY(-1px)}
.btn.go{background:linear-gradient(180deg,#2a7cff,#1f63d6);border-color:#3b82f6;color:#fff;box-shadow:0 6px 18px rgba(47,111,235,.35)}
.btn.red{background:var(--redg);border-color:rgba(255,59,92,.4);color:#ff9fb0}
.btn:disabled{opacity:.45;transform:none;cursor:default}
.menu{position:relative}.menu summary{list-style:none}.menu summary::-webkit-details-marker{display:none}
.menu .items{position:absolute;right:0;top:calc(100% + 6px);background:var(--p2);border:1px solid var(--line);border-radius:10px;padding:6px;min-width:170px;z-index:30;box-shadow:0 20px 40px rgba(0,0,0,.5)}
.menu a{display:block;color:var(--text);text-decoration:none;padding:8px 10px;border-radius:7px}.menu a:hover{background:rgba(255,255,255,.05)}
.toast{position:fixed;right:24px;bottom:24px;background:var(--p2);border:1px solid var(--line);border-radius:12px;padding:12px 16px;box-shadow:0 20px 50px rgba(0,0,0,.6);z-index:50;max-width:380px;transition:all .3s}
.toast.ok{border-color:rgba(34,211,138,.4)}.toast.bad{border-color:rgba(255,59,92,.4)}
.wrap{padding:22px 28px 40px;display:flex;flex-direction:column;gap:18px;max-width:1600px;margin:0 auto}
/* status band */
.band{position:relative;overflow:hidden;border-radius:16px;padding:22px 26px;display:flex;align-items:center;gap:26px;border:1px solid var(--line)}
.band.secure{background:linear-gradient(90deg,rgba(34,211,138,.16),rgba(34,211,138,.02) 60%),var(--p)}
.band.attack{background:linear-gradient(90deg,rgba(255,59,92,.28),rgba(255,59,92,.04) 65%),var(--p);border-color:rgba(255,59,92,.35)}
.band.demo{background:linear-gradient(90deg,rgba(255,176,32,.2),rgba(255,176,32,.03) 65%),var(--p);border-color:rgba(255,176,32,.3)}
.band.attack:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,59,92,.18),transparent);transform:translateX(-100%);animation:sweep 2.8s infinite}
@keyframes sweep{to{transform:translateX(100%)}}
.beacon{position:relative;width:54px;height:54px;flex:none}
.beacon i{position:absolute;inset:14px;border-radius:50%;background:var(--c)}
.beacon i:nth-child(2),.beacon i:nth-child(3){inset:0;background:none;border:2px solid var(--c);opacity:0;animation:ring 2s infinite}
.beacon i:nth-child(3){animation-delay:1s}
@keyframes ring{0%{transform:scale(.35);opacity:.9}100%{transform:scale(1);opacity:0}}
.state .k{font-size:11px;letter-spacing:2.5px;color:var(--dim);font-weight:700}
.state .v{font-size:30px;font-weight:800;letter-spacing:.5px;line-height:1.1;margin-top:2px}
.state .s{color:var(--dim);margin-top:4px}
.kpis{margin-left:auto;display:flex;gap:30px}
.kpi .k{font-size:11px;color:var(--dim);letter-spacing:1px;text-transform:uppercase}.kpi .v{font-size:26px;font-weight:700;margin-top:2px}
.kpi .v.r{color:var(--red)}.kpi .v.g{color:var(--green)}
/* grid */
.g{display:grid;grid-template-columns:minmax(0,1.75fr) minmax(360px,1fr);gap:18px}
.card{background:var(--p);border:1px solid var(--line);border-radius:16px;overflow:hidden}
.ch{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line)}
.ch h3{margin:0;font-size:13px;font-weight:600}.ch .sub{color:var(--faint);font-size:12px}
.legend{display:flex;gap:14px;color:var(--dim);font-size:11px}.legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
svg text{font-family:ui-sans-serif,system-ui,sans-serif}
.flow{stroke-dasharray:6 8;animation:flow 1s linear infinite}@keyframes flow{to{stroke-dashoffset:-14}}
.pulse{animation:pn 1.6s ease-in-out infinite;transform-origin:center;transform-box:fill-box}@keyframes pn{50%{opacity:.35}}
@media (prefers-reduced-motion:reduce){.flow,.pulse,.band:after,.beacon i{animation:none!important}}
/* incident panel */
.ip{padding:18px;display:flex;flex-direction:column;gap:16px}
.ih{display:flex;gap:16px;align-items:center}
.dial{width:84px;height:84px;flex:none;position:relative}
.dial svg{transform:rotate(-90deg)}.dial .n{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:24px;font-weight:800;line-height:1}
.dial .n small{display:block;font-size:8px;letter-spacing:1.5px;color:var(--dim);font-weight:700;margin-top:4px}
.ih .t{font-size:16px;font-weight:700}.ih .w{color:var(--dim);margin-top:3px}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tag{font-size:11px;font-weight:600;padding:4px 9px;border-radius:7px;background:rgba(155,123,255,.12);color:#c3b2ff;border:1px solid rgba(155,123,255,.25)}
.tag.t{background:rgba(76,141,255,.1);color:#9cc0ff;border-color:rgba(76,141,255,.25)}
.lbl{font-size:11px;letter-spacing:1.5px;color:var(--faint);font-weight:700;text-transform:uppercase;margin-bottom:8px}
.tl{display:flex;flex-direction:column}
.ts{display:grid;grid-template-columns:62px 14px 1fr;gap:10px;padding:6px 0;align-items:start;cursor:pointer}
.ts .tm{color:var(--faint);font-size:11px}.ts .d{width:9px;height:9px;border-radius:50%;background:var(--red);margin-top:4px;box-shadow:0 0 0 4px var(--redg)}
.ts .x b{font-weight:600}.ts .x span{color:var(--dim)}.ts .more{color:var(--dim);font-size:12px;margin-top:4px;display:none}.ts.open .more{display:block}
.acts{display:flex;gap:8px;flex-wrap:wrap}
.steps{display:flex;flex-direction:column;gap:6px}.steps label{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border-radius:9px;background:rgba(255,255,255,.025);cursor:pointer}
.steps input{accent-color:var(--green);margin-top:2px}
.none{padding:40px 20px;text-align:center;color:var(--dim)}.none b{display:block;color:var(--text);font-size:15px;margin-bottom:6px}
.none .ok{width:56px;height:56px;border-radius:50%;margin:0 auto 14px;display:grid;place-items:center;background:var(--greeng);color:var(--green);font-size:26px;font-weight:800}
/* feed */
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;color:var(--faint);font-weight:600;letter-spacing:1px;text-transform:uppercase;padding:10px 18px}
td{padding:11px 18px;border-top:1px solid var(--line);white-space:nowrap}
tr.r{cursor:pointer;transition:background .12s}tr.r:hover td{background:rgba(255,255,255,.025)}
.sv{display:inline-flex;align-items:center;gap:6px;font-weight:700;font-size:11px;letter-spacing:.5px}
.sv i{width:8px;height:8px;border-radius:2px}.sv.c{color:var(--red)}.sv.c i{background:var(--red)}.sv.m{color:var(--amber)}.sv.m i{background:var(--amber)}.sv.d{color:var(--dim)}.sv.d i{background:var(--faint)}
.ipx{color:#9cc0ff;font-weight:600}
.f{font-family:ui-monospace,monospace;font-size:12px;color:var(--text)}
.sm{color:var(--dim)}
.bar{display:flex;gap:8px;padding:12px 18px;border-bottom:1px solid var(--line)}
.bar input,.bar select{background:var(--p2);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:7px 11px;font:inherit}.bar input{width:280px}
.view{display:none}.view.on{display:flex;flex-direction:column;gap:18px}
.integ{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.ic{background:var(--p);border:1px solid var(--line);border-radius:14px;padding:18px;display:flex;flex-direction:column;gap:8px}
.ic .h{display:flex;justify-content:space-between;align-items:center}.ic b{font-size:14px}
.on-chip{font-size:11px;font-weight:700;padding:3px 9px;border-radius:7px}.on-chip.y{background:var(--greeng);color:var(--green)}.on-chip.n{background:rgba(255,255,255,.05);color:var(--dim)}
.ic code{font:12px ui-monospace,monospace;color:#9cc0ff;background:rgba(76,141,255,.08);padding:6px 8px;border-radius:7px;display:block;white-space:normal}
.notice{border-radius:12px;padding:12px 16px;display:flex;gap:10px;align-items:center;border:1px solid var(--line);background:var(--p)}
.notice b{color:var(--green)}.notice code{font:12px ui-monospace,monospace;color:#9cc0ff}
@media (max-width:1100px){.g{grid-template-columns:1fr}.kpis{display:none}.integ{grid-template-columns:1fr}}
</style></head><body>
<div class="top">
 <div class="logo"><img alt="" src="data:image/png;base64,__MARK__">Lure <span>by SilentMesh</span></div>
 <div class="nav"><button class="on" data-v="overview">Overview</button><button data-v="incidents">Incidents<span class="n" id="nb" hidden></span></button><button data-v="baits">Baits</button><button data-v="integrations">Integrations</button></div>
 <div class="grow"></div>
 <div class="chip-host">Listener <b class="mono" id="host">—</b></div>
 <details class="menu"><summary class="btn">Export</summary><div class="items"><a href="/api/export?fmt=csv">Alerts as CSV</a><a href="/api/export?fmt=json">Alerts as JSON</a></div></details>
 <button class="btn go" id="test">Run attack test</button>
</div>
<div class="wrap">
 <div class="notice" id="upd" hidden></div>
 <section class="band secure" id="band">
  <div class="beacon" id="beacon" style="--c:var(--green)"><i></i><i></i><i></i></div>
  <div class="state"><div class="k" id="b-k">STATUS</div><div class="v" id="b-v">SECURE</div><div class="s" id="b-s">All baits untouched</div></div>
  <div class="kpis">
   <div class="kpi"><div class="k">Active intrusions</div><div class="v" id="k1">0</div></div>
   <div class="kpi"><div class="k">Baits taken</div><div class="v" id="k2">0</div></div>
   <div class="kpi"><div class="k">Threat score</div><div class="v" id="k3">0</div></div>
   <div class="kpi"><div class="k">Watching since</div><div class="v" id="k4">0</div></div>
  </div>
 </section>

 <div class="view on" id="v-overview">
  <div class="g">
   <div class="card"><div class="ch"><h3>Attack graph</h3><span class="sub">who took which bait, in order</span><div class="grow"></div>
    <div class="legend"><span><i style="background:var(--red)"></i>Attacker</span><span><i style="background:#ff8ba0"></i>Bait taken</span><span><i style="background:#2a3442"></i>Bait waiting</span></div></div>
    <svg id="graph" viewBox="0 0 900 430" width="100%" style="display:block"></svg></div>
   <div class="card" id="incard"></div>
  </div>
  <div class="card"><div class="ch"><h3>Live detections</h3><span class="sub" id="fc"></span></div>
   <table><thead><tr><th>Severity</th><th>Time</th><th>Source</th><th>Technique</th><th>Bait</th></tr></thead><tbody id="feed"></tbody></table></div>
 </div>

 <div class="view" id="v-incidents"><div class="g">
  <div class="card"><div class="ch"><h3>Incidents</h3><div class="grow"></div><select id="if" style="background:var(--p2);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:6px 10px"><option value="open">Open</option><option value="handled">Handled</option><option value="all">All</option></select></div>
   <table><thead><tr><th>Severity</th><th>Source</th><th>Baits</th><th>Score</th><th>Last seen</th></tr></thead><tbody id="ilist"></tbody></table></div>
  <div class="card" id="incard2"></div></div></div>

 <div class="view" id="v-baits"><div class="card"><div class="bar"><input id="bq" placeholder="Search baits"></div>
  <table><thead><tr><th>Status</th><th>Bait file</th><th>Logins</th><th>Belongs on</th><th>Planted at</th></tr></thead><tbody id="blist"></tbody></table></div></div>

 <div class="view" id="v-integrations"><div class="integ" id="integ"></div></div>
</div>
<div class="toast" id="toast" hidden></div>
<script>
var ST=null,SEL=null;
var TAC={"T1552.001":"Credential Access","T1555.003":"Credential Access","T1021.001":"Lateral Movement","T1133":"Initial Access","T1078":"Initial Access","T1078.004":"Initial Access","T1046":"Discovery"};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=String(x);return e;}
function sv(n,a){return document.createElementNS('http://www.w3.org/2000/svg',n);}
function attr(e,o){for(var k in o)e.setAttribute(k,o[k]);return e;}
function ago(t){if(!t)return '—';var s=(Date.now()-Date.parse(t))/1000;if(s<60)return 'now';if(s<3600)return Math.round(s/60)+'m';if(s<86400)return Math.round(s/3600)+'h';return Math.round(s/86400)+'d';}
function hms(t){return (t||'').slice(11,19);}
function score(i){if(i.severity!=='high')return 25;return Math.min(99,48+i.baits*13+(i.steps.length>2?6:0));}
function toast(m,c){var t=document.getElementById('toast');t.textContent=m;t.className='toast '+(c||'');t.hidden=false;clearTimeout(t._h);t._h=setTimeout(function(){t.hidden=true;},5000);}
document.querySelectorAll('.nav button').forEach(function(b){b.onclick=function(){go(b.dataset.v);};});
function go(v){document.querySelectorAll('.nav button').forEach(function(x){x.classList.toggle('on',x.dataset.v===v);});document.querySelectorAll('.view').forEach(function(x){x.classList.toggle('on',x.id==='v-'+v);});}
document.getElementById('if').onchange=function(){render(ST);};document.getElementById('bq').oninput=function(){render(ST);};
function render(st){ST=st;var inc=st.incidents||[],open=inc.filter(function(i){return !i.handled;}),files=st.files||[],alerts=st.alerts||[];
 document.getElementById('host').textContent=(st.listening||{}).listener||'—';
 var band=document.getElementById('band'),bc=document.getElementById('beacon'),taken=files.filter(function(f){return f.used;}).length,top=open[0];
 var maxs=open.reduce(function(m,i){return Math.max(m,score(i));},0);
 if(st.demo){band.className='band demo';bc.style.setProperty('--c','var(--amber)');document.getElementById('b-k').textContent='DEMO MODE';document.getElementById('b-v').textContent='SIMULATED INTRUSION';document.getElementById('b-s').textContent='A pretend attacker on this computer. Nothing real happened.';}
 else if(open.length){band.className='band attack';bc.style.setProperty('--c','var(--red)');document.getElementById('b-k').textContent='STATUS';document.getElementById('b-v').textContent='INTRUSION IN PROGRESS';document.getElementById('b-s').textContent=top.from.charAt(0).toUpperCase()+top.from.slice(1)+' took '+top.baits+' bait'+(top.baits===1?'':'s')+' · '+ago(top.last)+' ago';}
 else{band.className='band secure';bc.style.setProperty('--c','var(--green)');document.getElementById('b-k').textContent='STATUS';document.getElementById('b-v').textContent='SECURE';document.getElementById('b-s').textContent=files.length+' baits armed · nothing touched'+(inc.length?' since the last incident was handled':'');}
 var k1=document.getElementById('k1');k1.textContent=open.length;k1.className='v '+(open.length?'r':'g');
 document.getElementById('k2').textContent=taken+'/'+files.length;var k3=document.getElementById('k3');k3.textContent=maxs;k3.className='v '+(maxs>=70?'r':(maxs?'':'g'));
 document.getElementById('k4').textContent=(st.since||'').slice(11,16)+' UTC';
 var nb=document.getElementById('nb');nb.hidden=!open.length;nb.textContent=open.length;
 document.getElementById('test').disabled=!!st.demo;
 var u=document.getElementById('upd');u.hidden=!st.update;if(st.update){u.textContent='';u.appendChild(el('b',null,'Update '+st.update));u.appendChild(document.createTextNode(' is ready. It installs only when you approve it: run '));u.appendChild(el('code',null,'lure update'));}
 if(!SEL||!inc.some(function(i){return i.source===SEL;}))SEL=(open[0]||inc[0]||{}).source||null;
 graph(inc,files);incCard(document.getElementById('incard'),inc);incCard(document.getElementById('incard2'),inc);feed(alerts);ilist(inc);baits(files);integ(st.channels||{});}
function graph(inc,files){var g=document.getElementById('graph');while(g.firstChild)g.removeChild(g.firstChild);
 var defs=sv('defs');defs.innerHTML='<radialGradient id="ga"><stop offset="0" stop-color="#ff3b5c" stop-opacity=".55"/><stop offset="1" stop-color="#ff3b5c" stop-opacity="0"/></radialGradient><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#ff3b5c"/></marker>';g.appendChild(defs);
 var att=inc.filter(function(i){return i.severity==='high';}).slice(0,4),W=900,H=430;
 if(!files.length)return;
 var cx=560,cy=H/2,R=175,n=files.length,pos={};
 files.forEach(function(f,k){var a=(-70+140*(n===1?0.5:k/(n-1)))*Math.PI/180;pos[f.file]={x:cx+R*Math.cos(a)*1.0-60,y:cy+R*Math.sin(a)*1.15};});
 var ax=110;att.forEach(function(i,k){var y=att.length===1?cy:60+k*((H-120)/(att.length-1||1));i._x=ax;i._y=y;});
 // edges
 att.forEach(function(i){var seen={},ord=0;i.steps.forEach(function(s){if(!s.bait||seen[s.bait]||!pos[s.bait])return;seen[s.bait]=1;ord++;var p=pos[s.bait];
  var mx=(i._x+p.x)/2,path=sv('path');attr(path,{d:'M'+(i._x+22)+' '+i._y+' C '+mx+' '+i._y+', '+mx+' '+p.y+', '+(p.x-16)+' '+p.y,fill:'none',stroke:i.handled?'#3a4452':'#ff3b5c','stroke-width':2,'marker-end':i.handled?'':'url(#ar)','class':i.handled?'':'flow',opacity:i.handled?.6:.9});g.appendChild(path);
  var bx=mx,by=(i._y+p.y)/2,c=sv('circle');attr(c,{cx:bx,cy:by,r:10,fill:'#0B0F14',stroke:'#ff3b5c','stroke-width':1.5});g.appendChild(c);var t=sv('text');attr(t,{x:bx,y:by+4,'text-anchor':'middle','font-size':11,'font-weight':700,fill:'#ff8ba0'});t.textContent=ord;g.appendChild(t);});});
 // bait nodes
 files.forEach(function(f){var p=pos[f.file],c=sv('circle');attr(c,{cx:p.x,cy:p.y,r:f.used?13:9,fill:f.used?'#ff3b5c':'#1a222d',stroke:f.used?'#ff8ba0':'#2a3442','stroke-width':2});g.appendChild(c);
  var t=sv('text'),name=f.file.length>30?f.file.slice(0,28)+'…':f.file;attr(t,{x:p.x+20,y:p.y+4,'font-size':12,fill:f.used?'#E8EDF2':'#5c6876','font-weight':f.used?600:400});t.textContent=name;g.appendChild(t);});
 // attackers
 if(!att.length){var t=sv('text');attr(t,{x:150,y:cy-6,'font-size':18,'font-weight':700,fill:'#22D38A','text-anchor':'middle'});t.textContent='No attacker';g.appendChild(t);var t2=sv('text');attr(t2,{x:150,y:cy+16,'font-size':12,fill:'#7D8896','text-anchor':'middle'});t2.textContent='All baits waiting';g.appendChild(t2);return;}
 att.forEach(function(i){var halo=sv('circle');attr(halo,{cx:i._x,cy:i._y,r:46,fill:'url(#ga)','class':i.handled?'':'pulse'});if(!i.handled)g.appendChild(halo);
  var c=sv('circle');attr(c,{cx:i._x,cy:i._y,r:22,fill:i.handled?'#2a3442':'#ff3b5c',stroke:'#ffd0d8','stroke-width':2});g.appendChild(c);
  var t=sv('text');attr(t,{x:i._x,y:i._y+42,'text-anchor':'middle','font-size':12,'font-weight':700,fill:'#E8EDF2'});t.textContent=i.source;g.appendChild(t);
  var t2=sv('text');attr(t2,{x:i._x,y:i._y+57,'text-anchor':'middle','font-size':11,fill:'#7D8896'});t2.textContent=i.demo?'demo attacker':i.from;g.appendChild(t2);});}
function tactics(i){var t={},q={};i.steps.forEach(function(s){if(s.attack){q[s.attack]=1;if(TAC[s.attack])t[TAC[s.attack]]=1;}});return {t:Object.keys(t),q:Object.keys(q)};}
function incCard(box,inc){box.textContent='';var i=inc.filter(function(x){return x.source===SEL;})[0];
 var h=el('div','ch');h.appendChild(el('h3',null,'Incident'));box.appendChild(h);
 if(!i){var n=el('div','none');n.appendChild(el('div','ok','✓'));n.appendChild(el('b',null,'No incidents'));n.appendChild(document.createTextNode('Press Run attack test to see a detection end to end.'));box.appendChild(n);return;}
 var p=el('div','ip'),hd=el('div','ih'),s=score(i),col=i.handled?'#4A5562':(s>=70?'#FF3B5C':'#FFB020');
 var d=el('div','dial'),C=2*Math.PI*36,svg='<svg width="84" height="84"><circle cx="42" cy="42" r="36" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="7"/><circle cx="42" cy="42" r="36" fill="none" stroke="'+col+'" stroke-width="7" stroke-linecap="round" stroke-dasharray="'+(C*s/100)+' '+C+'"/></svg>';d.innerHTML=svg;var nn=el('div','n');nn.appendChild(document.createTextNode(s));nn.appendChild(el('small',null,'SCORE'));nn.style.color=col;d.appendChild(nn);hd.appendChild(d);
 var tt=el('div');tt.appendChild(el('div','t',(i.demo?'Demo · ':'')+(i.handled?'Handled · ':'')+i.baits+' bait'+(i.baits===1?'':'s')+' taken'));tt.appendChild(el('div','w',i.who));hd.appendChild(tt);p.appendChild(hd);
 var tx=tactics(i),tg=el('div','tags');tx.t.forEach(function(x){tg.appendChild(el('span','tag',x));});tx.q.forEach(function(x){tg.appendChild(el('span','tag t',x));});p.appendChild(tg);
 var tl=el('div');tl.appendChild(el('div','lbl','Storyline'));var l=el('div','tl');i.steps.forEach(function(st){var r=el('div','ts');r.appendChild(el('span','tm mono',hms(st.time)));r.appendChild(el('span','d'));var x=el('div','x');x.appendChild(el('b',null,(st.bait||'listener')+' '));x.appendChild(el('span',null,'· '+(st.service||'').toUpperCase()));x.appendChild(el('div','more',st.how));r.appendChild(x);r.onclick=function(){r.classList.toggle('open');};l.appendChild(r);});tl.appendChild(l);p.appendChild(tl);
 var rs=el('div');rs.appendChild(el('div','lbl','Respond'));var stp=el('div','steps');i.next.forEach(function(n){var lb=el('label'),cb=el('input');cb.type='checkbox';lb.appendChild(cb);lb.appendChild(el('span',null,n));stp.appendChild(lb);});rs.appendChild(stp);p.appendChild(rs);
 if(!i.handled){var a=el('div','acts'),b=el('button','btn red','Mark handled');b.onclick=function(){post('/api/ack',{ids:i.ids}).then(function(){toast('Incident from '+i.source+' marked handled.','ok');load();});};a.appendChild(b);p.appendChild(a);}
 box.appendChild(p);}
function sevCell(a){var s=el('span','sv '+(a.acknowledged?'d':(a.severity==='high'?'c':'m')));s.appendChild(el('i'));s.appendChild(document.createTextNode(a.demo?'DEMO':(a.acknowledged?'HANDLED':(a.severity==='high'?'CRITICAL':'MEDIUM'))));return s;}
function feed(alerts){var tb=document.getElementById('feed');tb.textContent='';document.getElementById('fc').textContent=alerts.length+' total';
 if(!alerts.length){var r=el('tr'),c=el('td','none','No detections yet.');c.colSpan=5;r.appendChild(c);tb.appendChild(r);return;}
 alerts.slice(0,12).forEach(function(a){var x=a.explain||{},r=el('tr','r');r.onclick=function(){SEL=a.source.replace(/:\d+$/,'');render(ST);};
  var c=el('td');c.appendChild(sevCell(a));r.appendChild(c);r.appendChild(el('td','mono sm',hms(a.time)));r.appendChild(el('td','ipx mono',a.source.replace(/:\d+$/,'')));
  var t=el('td');t.appendChild(el('span','tag t',x.attack||''));t.appendChild(document.createTextNode(' '+(TAC[x.attack]||'')));r.appendChild(t);r.appendChild(el('td','f',a.bait_file||'listener'));tb.appendChild(r);});}
function ilist(inc){var f=document.getElementById('if').value,tb=document.getElementById('ilist');tb.textContent='';var l=inc.filter(function(i){return f==='all'||(f==='open'?!i.handled:i.handled);});
 if(!l.length){var r=el('tr'),c=el('td','none',f==='open'?'No open incidents.':'Nothing here.');c.colSpan=5;r.appendChild(c);tb.appendChild(r);}
 l.forEach(function(i){var r=el('tr','r');r.onclick=function(){SEL=i.source;render(ST);};var c=el('td');c.appendChild(sevCell({severity:i.severity,acknowledged:i.handled,demo:i.demo}));r.appendChild(c);
  r.appendChild(el('td','ipx mono',i.source));r.appendChild(el('td',null,i.baits));r.appendChild(el('td',null,score(i)));r.appendChild(el('td','sm',ago(i.last)));tb.appendChild(r);});}
function baits(files){var q=document.getElementById('bq').value.toLowerCase(),tb=document.getElementById('blist');tb.textContent='';
 files.filter(function(f){return !q||(f.file+(f.plant_on||'')+(f.location||'')).toLowerCase().indexOf(q)>=0;}).forEach(function(f){var r=el('tr'),c=el('td'),s=el('span','sv '+(f.used?'c':'d'));s.appendChild(el('i'));s.appendChild(document.createTextNode(f.used?'TAKEN':(f.retired?'RETIRED':'ARMED')));if(!f.used&&!f.retired){s.style.color='var(--green)';s.firstChild.style.background='var(--green)';}c.appendChild(s);r.appendChild(c);
  r.appendChild(el('td','f',f.file));r.appendChild(el('td',null,f.logins));r.appendChild(el('td','sm',f.plant_on||''));r.appendChild(el('td','sm mono',f.location||'—'));tb.appendChild(r);});}
function integ(ch){var b=document.getElementById('integ');b.textContent='';
 [['Console','This page.',true,null],['Desktop popup','Alert on this computer.',ch.desktop,'--desktop'],['Email',ch.email||'Gmail or Outlook, with an app password.',ch.email,'--email-to you@gmail.com'],
  ['Phone and chat',ch.webhook||'ntfy, Telegram, Discord, Slack or Teams.',ch.webhook,'--webhook https://ntfy.sh/your-topic'],['SIEM','Syslog to your collector.',ch.syslog,'--syslog 10.0.0.5:514'],['AI agents','Let an agent read alerts and manage baits.',false,'lure mcp']]
 .forEach(function(x){var c=el('div','ic'),h=el('div','h');h.appendChild(el('b',null,x[0]));h.appendChild(el('span','on-chip '+(x[2]?'y':'n'),x[2]?'ON':'OFF'));c.appendChild(h);c.appendChild(el('div','sm',x[1]));if(!x[2]&&x[3])c.appendChild(el('code',null,x[3]));b.appendChild(c);});}
function load(){fetch('/api/state').then(function(r){return r.json();}).then(render).catch(function(){});}
function post(p,b){return fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});}
document.getElementById('test').onclick=function(){var b=this,before=(ST.alerts||[]).length,t0=Date.now();b.disabled=true;b.textContent='Attacking…';
 post('/api/test').then(function(r){if(!r.ok)throw 0;var iv=setInterval(function(){fetch('/api/state').then(function(x){return x.json();}).then(function(s){render(s);
  if((s.alerts||[]).length>before){clearInterval(iv);toast('Detected in '+((Date.now()-t0)/1000).toFixed(1)+' s. The test attack is in the graph.','ok');done();}else if(Date.now()-t0>10000){clearInterval(iv);toast('No new detection in 10 s. A repeat within 10 minutes is merged into the earlier alert.','bad');done();}});},600);})
 .catch(function(){toast('Attack test is not available here.','bad');done();});function done(){b.disabled=false;b.textContent='Run attack test';}};
if(location.hash)go(location.hash.slice(1));
load();setInterval(load,3000);
</script></body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    alerter = None
    tester = None
    allowed_origins = ()

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

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            from .init import cmd
            base = cmd("")
            page = PAGE.replace("<code>lure ", "<code>" + base).replace("'lure update'", "'" + base + "update'")
            self._send(200, page.replace("__VERSION__", __version__).replace("__MARK__", MARK_PNG_B64), "text/html; charset=utf-8")
        elif self.path.startswith("/api/export"):
            fmt = "csv" if "fmt=csv" in self.path else "json"
            alerts = self.alerter.state()["alerts"]
            if fmt == "json":
                body, ctype = json.dumps(alerts, indent=2), "application/json"
            else:
                import csv, io
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(["time", "severity", "source", "service", "username", "bait_file", "planted", "attack", "what_happened", "handled"])
                safe = lambda v: ("'" + v) if isinstance(v, str) and v[:1] in "=+-@\t\r" else v
                for r in alerts:
                    x = r.get("explain") or {}
                    w.writerow(map(safe, [r.get("time"), r.get("severity"), r.get("source"), r.get("service"), r.get("username"),
                                r.get("bait_file"), r.get("location") or r.get("planted_on"), x.get("attack"), x.get("how"),
                                bool(r.get("acknowledged"))]))
                body, ctype = buf.getvalue(), "text/csv; charset=utf-8"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="lure-alerts.{fmt}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/api/state":
            self._send(200, json.dumps(self.alerter.state()), "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path not in ("/api/ack", "/api/test"):
            return self._send(404, "not found", "text/plain")
        # Refuse cross-site requests: JSON only, and the Origin must be this dashboard.
        origin = self.headers.get("Origin")
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json" or \
                (origin is not None and origin not in self.allowed_origins):
            return self._send(403, "forbidden", "text/plain")
        if self.path == "/api/test":
            if not self.tester:
                return self._send(409, json.dumps({"ok": False}), "application/json")
            threading.Thread(target=self.tester, daemon=True).start()
            return self._send(200, json.dumps({"ok": True}), "application/json")
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 4096)
            body = json.loads(self.rfile.read(n) or b"{}")
            alert_id = [int(i) for i in body["ids"]][:500] if "ids" in body else int(body.get("id"))
        except (ValueError, TypeError, AttributeError, KeyError):
            return self._send(400, "bad request", "text/plain")
        ok = self.alerter.acknowledge(alert_id)
        self._send(200 if ok else 404, json.dumps({"ok": ok}), "application/json")


def serve(alerter, host="127.0.0.1", port=8765, tester=None):
    """Start the dashboard in a background thread and return the server.

    tester: optional callable that fires a real bait login at the listener ("Test now").
    """
    handler = type("Handler", (_Handler,), {
        "alerter": alerter, "tester": staticmethod(tester) if tester else None,
        "allowed_origins": (f"http://{host}:{port}", f"http://localhost:{port}", f"http://127.0.0.1:{port}"),
    })
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
