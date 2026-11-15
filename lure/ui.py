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
<title>Lure: Operator Console</title>
<style>
*,*::before,*::after{box-sizing:border-box}[hidden]{display:none!important}
body{background:#0d1117;color:#c9d1d9;font-family:'SF Mono','Cascadia Mono',Consolas,'Liberation Mono',monospace;margin:0;min-height:100vh;font-size:12px}
button{font-family:inherit}
.header{background:#161b22;border-bottom:1px solid #21262d;padding:14px 24px;display:flex;align-items:center;gap:14px}
.header img{width:30px;height:30px;border-radius:7px}
.logo{color:#5FE07F;font-size:18px;font-weight:700;letter-spacing:3px}.logo-sub{color:#484f58;font-size:11px;letter-spacing:2px;margin-top:2px;text-transform:uppercase}
.header-right{margin-left:auto;display:flex;align-items:center;gap:14px}
.refresh{font-size:10px;color:#484f58}
.pill{display:flex;align-items:center;gap:8px;background:#0d1117;border:1px solid #21262d;border-radius:20px;padding:5px 14px;font-size:11px;letter-spacing:1px}
.dot{width:8px;height:8px;border-radius:50%;background:#3fb950;box-shadow:0 0 8px #3fb95066}
.pill.bad .dot{background:#f85149;box-shadow:0 0 8px #f8514966;animation:p 1.1s infinite}.pill.bad{color:#f85149}.pill.ok{color:#3fb950}
.pill.demo .dot{background:#e3b341;box-shadow:0 0 8px #e3b34166}.pill.demo{color:#e3b341}
@keyframes p{50%{opacity:.3}}@media (prefers-reduced-motion:reduce){.dot{animation:none!important}}
.host{color:#bc8cff}.host b{color:#f0f6fc}
.cmdbar{display:flex;align-items:center;gap:10px;padding:10px 24px;border-bottom:1px solid #21262d;flex-wrap:wrap}
.cmdbar .spacer{flex:1}
.tb-btn{padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9;font-weight:600}
.tb-btn:hover{background:#30363d}.tb-btn:disabled{opacity:.5;cursor:default}
.tb-btn.primary{background:#0f2a17;color:#5FE07F;border-color:#3fb95066}.tb-btn.primary:hover{background:#163a20}
.cmd-status{font-size:11px;color:#8b949e}.cmd-status.ok{color:#3fb950}.cmd-status.bad{color:#f85149}
.menu{position:relative}.menu summary{list-style:none}.menu summary::-webkit-details-marker{display:none}
.menu .items{position:absolute;top:calc(100% + 4px);left:0;z-index:30;min-width:220px;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:4px}
.menu .items a{display:block;color:#c9d1d9;padding:7px 10px;text-decoration:none;border-radius:4px}.menu .items a:hover{background:#21262d}
.strip{padding:10px 24px;font-size:12px;line-height:1.6;border-bottom:1px solid}
.strip.demo{background:#2d2200;border-color:#e3b34144;color:#f2d68a}.strip.demo b{color:#e3b341}
.strip.alarm{background:#2a1515;border-color:#f8514944;color:#f0c9c6}.strip.alarm b{color:#f85149}
.strip.upd{background:#0f1a12;border-color:#3fb95033;color:#c9d1d9}.strip.upd b{color:#5FE07F}
code{color:#5FE07F;background:#161b22;border:1px solid #21262d;border-radius:4px;padding:1px 6px}
.modules{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:16px 24px;border-bottom:1px solid #21262d}
.mod{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;position:relative;overflow:hidden}
.mod::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:#3fb950}
.mod.warn::before{background:#e3b341}.mod.bad::before{background:#f85149}.mod.off::before{background:#30363d}
.mod-h{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px}
.mod-name{font-size:11px;font-weight:700;letter-spacing:1.5px;color:#f0f6fc;text-transform:uppercase}
.st{font-size:9px;letter-spacing:1px;padding:2px 8px;border-radius:10px;font-weight:700;border:1px solid}
.st.ok{background:#1a3a1a;color:#3fb950;border-color:#3fb95044}.st.warn{background:#2d2200;color:#e3b341;border-color:#e3b34144}
.st.bad{background:#3a1a1a;color:#f85149;border-color:#f8514944}.st.off{background:#21262d;color:#8b949e;border-color:#30363d}
.mod-desc{color:#8b949e;font-size:11px;line-height:1.6;margin-bottom:10px}
.mod-m{font-size:11px;color:#8b949e;margin-top:3px}.mod-m span{color:#c9d1d9}
.stats{display:flex;border-bottom:1px solid #21262d}
.stat{flex:1;padding:14px 24px;border-right:1px solid #21262d}.stat:last-child{border-right:0}
.stat-l{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:1px}
.stat-v{font-size:26px;font-weight:700;color:#f0f6fc;margin-top:4px}.stat-v.red{color:#f85149}.stat-v.green{color:#3fb950}.stat-v.blue{color:#58a6ff}.stat-v.yellow{color:#e3b341;font-size:14px;margin-top:10px}
.tabs{display:flex;border-bottom:1px solid #21262d;padding:0 24px}
.tab{padding:12px 20px;cursor:pointer;color:#8b949e;border:0;background:none;border-bottom:2px solid transparent;margin-bottom:-1px;font-size:12px;letter-spacing:.5px}
.tab:hover{color:#c9d1d9}.tab.on{color:#f0f6fc;border-bottom-color:#5FE07F}
.cnt{background:#3a1a1a;color:#f85149;border-radius:10px;padding:0 6px;margin-left:6px;font-size:10px}
.panel{display:none;padding:16px 24px 32px}.panel.on{display:block}
.sec-h{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.sec-t{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1.5px}.badge{background:#21262d;color:#8b949e;font-size:10px;padding:2px 8px;border-radius:10px}
.toolbar{display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.toolbar select,.toolbar input{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:6px 10px;font:inherit}
.toolbar input{min-width:240px}.toolbar .spacer{flex:1}
table{width:100%;border-collapse:collapse}
thead th{background:#161b22;color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:1px;padding:8px 12px;text-align:left;border-bottom:1px solid #21262d;font-weight:600}
tbody tr{border-bottom:1px solid #161b22}tbody tr:hover td{background:#161b22}tbody tr.click{cursor:pointer}tbody tr.sel td{background:#1c2128}
td{padding:9px 12px;vertical-align:top}
.t-time{color:#8b949e;white-space:nowrap}.t-ip{color:#58a6ff;font-weight:600;white-space:nowrap}
.proto{color:#bc8cff;background:#2d1f6e22;border:1px solid #bc8cff33;border-radius:4px;padding:2px 8px;font-size:10px;display:inline-block;letter-spacing:.5px;text-transform:uppercase}
.tech{color:#e3b341;white-space:nowrap}.tech small{display:block;color:#8b949e;font-size:10px}
.sev{font-size:9px;letter-spacing:1px;font-weight:700;padding:2px 8px;border-radius:10px;text-transform:uppercase;display:inline-block;white-space:nowrap}
.sev.HIGH{background:#3a1a1a;color:#f85149;border:1px solid #f8514944}.sev.MEDIUM{background:#2d2200;color:#e3b341;border:1px solid #e3b34144}
.sev.DEMO{background:#2d2200;color:#e3b341;border:1px dashed #e3b34188}.sev.DONE{background:#21262d;color:#8b949e;border:1px solid #30363d}
.sev.OK{background:#1a3a1a;color:#3fb950;border:1px solid #3fb95044}
.what{color:#c9d1d9;max-width:520px}.what small{display:block;color:#8b949e;margin-top:2px}
.empty td{text-align:center;color:#484f58;padding:48px;font-size:13px}
.row-btn{padding:2px 8px;font-size:11px;border-radius:4px;border:1px solid #30363d;background:#21262d;color:#58a6ff;cursor:pointer}
.split{display:grid;grid-template-columns:minmax(380px,1fr) 1.3fr;gap:16px}
.detail{background:#161b22;border:1px solid #21262d;border-radius:8px}
.d-h{padding:16px 20px;border-bottom:1px solid #21262d;display:flex;gap:12px;align-items:flex-start}
.d-h h3{margin:0;color:#f0f6fc;font-size:14px}.d-h .sub{color:#8b949e;margin-top:4px;line-height:1.6}.d-h .grow{flex:1}
.kv{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid #21262d}
.kv>div{padding:12px 20px;border-right:1px solid #21262d}.kv>div:last-child{border-right:0}
.kv .k{color:#8b949e;font-size:10px;letter-spacing:1.5px;text-transform:uppercase}.kv .v{color:#f0f6fc;margin-top:4px;font-size:13px}
.d-sec{padding:16px 20px;border-bottom:1px solid #21262d}.d-sec:last-child{border-bottom:0}
.d-t{color:#8b949e;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:10px}
.chain{display:flex;flex-direction:column;gap:0}
.step{display:grid;grid-template-columns:70px 18px 1fr;gap:10px;align-items:start;padding:6px 0}
.step .tm{color:#8b949e}.step .nd{width:10px;height:10px;border-radius:50%;background:#f85149;margin-top:3px;box-shadow:0 0 0 3px #3a1a1a}
.step .tx{color:#c9d1d9;line-height:1.55}.step .tx .tech{font-size:10px;margin-left:6px}
.todo{display:flex;flex-direction:column;gap:6px}
.todo label{display:flex;gap:10px;padding:8px 12px;background:#0d1117;border:1px solid #21262d;border-radius:6px;cursor:pointer;line-height:1.55}
.todo input{accent-color:#3fb950;margin-top:2px}
.act{display:flex;gap:10px;padding:14px 20px}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:18px}
.card h4{margin:0 0 6px;color:#f0f6fc;font-size:13px}.card p{margin:0;color:#8b949e;font-size:11px;line-height:1.6}
.card .row{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
@media (max-width:1100px){.modules{grid-template-columns:repeat(2,1fr)}.split{grid-template-columns:1fr}.cards{grid-template-columns:1fr}.kv{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<div class="header">
 <img alt="" src="data:image/png;base64,__MARK__">
 <div><div class="logo">LURE</div><div class="logo-sub">SilentMesh · credential tripwires</div></div>
 <div class="header-right">
  <div class="refresh" id="refresh"></div>
  <div class="pill host">LISTENER <b id="h-host">—</b></div>
  <div class="pill ok" id="pill"><span class="dot"></span><span id="pill-t">CONNECTING</span></div>
 </div>
</div>
<div class="cmdbar">
 <button class="tb-btn primary" id="test-btn" title="Fires one real bait login at this listener and waits for the alert">Run test</button>
 <details class="menu"><summary class="tb-btn">Export</summary><div class="items"><a href="/api/export?fmt=csv">Alerts, CSV</a><a href="/api/export?fmt=json">Alerts, JSON</a></div></details>
 <button class="tb-btn" id="ack-all" title="Marks every open incident as handled">Mark all handled</button>
 <div class="cmd-status" id="cmd-status"></div>
 <div class="spacer"></div>
 <div class="refresh">v__VERSION__ · runs on this computer only</div>
</div>
<div class="strip demo" id="s-demo" hidden><b>DEMO MODE.</b> A pretend attacker is using the baits on this computer so you can see the console at work. Nothing real happened. Your real console opens with <code>lure listen --ui</code>.</div>
<div class="strip alarm" id="s-alarm" hidden></div>
<div class="strip upd" id="s-upd" hidden></div>
<div class="modules">
 <div class="mod" id="m-listen"><div class="mod-h"><div class="mod-name">Listener</div><div class="st ok" id="m-listen-st">ACTIVE</div></div>
  <div class="mod-desc">Answers the logins written in the baits. Nothing legitimate logs in here, so any login is a signal.</div>
  <div class="mod-m">Address: <span id="m-host">—</span></div><div class="mod-m">Ports: <span id="m-ports">—</span></div></div>
 <div class="mod" id="m-baits"><div class="mod-h"><div class="mod-name">Bait set</div><div class="st ok" id="m-baits-st">ARMED</div></div>
  <div class="mod-desc">Fake files holding fake logins. Opening, copying or scanning them does nothing. Only using a login alerts.</div>
  <div class="mod-m">Files: <span id="m-files">—</span> · logins: <span id="m-logins">—</span></div><div class="mod-m">Profile: <span id="m-profile">—</span></div></div>
 <div class="mod" id="m-chan"><div class="mod-h"><div class="mod-name">Alert delivery</div><div class="st ok" id="m-chan-st">—</div></div>
  <div class="mod-desc">Where a new incident is sent the moment it happens.</div>
  <div class="mod-m">Channels: <span id="m-chans">—</span></div><div class="mod-m">Log: <span>alerts.jsonl next to the manifest</span></div></div>
 <div class="mod" id="m-upd"><div class="mod-h"><div class="mod-name">Software</div><div class="st ok" id="m-upd-st">CURRENT</div></div>
  <div class="mod-desc">Updates are offered, never installed for you. You review the change and approve it.</div>
  <div class="mod-m">Version: <span>__VERSION__</span></div><div class="mod-m">Update: <span id="m-updv">none waiting</span></div></div>
</div>
<div class="stats">
 <div class="stat"><div class="stat-l">Open incidents</div><div class="stat-v" id="s-open">0</div></div>
 <div class="stat"><div class="stat-l">Bait logins used</div><div class="stat-v blue" id="s-used">0</div></div>
 <div class="stat"><div class="stat-l">Unique sources</div><div class="stat-v" id="s-ips">0</div></div>
 <div class="stat"><div class="stat-l">Last hour</div><div class="stat-v green" id="s-hour">0</div></div>
 <div class="stat"><div class="stat-l">Monitoring since</div><div class="stat-v yellow" id="s-since">—</div></div>
</div>
<div class="tabs">
 <button class="tab on" data-t="feed">Live alert feed</button>
 <button class="tab" data-t="inc">Incidents<span class="cnt" id="t-cnt" hidden></span></button>
 <button class="tab" data-t="baits">Baits</button>
 <button class="tab" data-t="integ">Integrations</button>
</div>
<div class="panel on" id="p-feed">
 <div class="sec-h"><div class="sec-t">Bait use and listener contact</div><div class="badge" id="f-count">0 alerts</div></div>
 <div class="toolbar"><select id="f-sev"><option value="">All severities</option><option value="high">High only</option><option value="medium">Medium only</option></select>
  <input id="f-q" type="search" placeholder="Filter: IP, bait, service, technique"><button class="tb-btn" id="f-clear">Clear filters</button></div>
 <table><thead><tr><th>Time (UTC)</th><th>Source IP</th><th>Service</th><th>Severity</th><th>What happened</th><th title="MITRE ATT&amp;CK technique the attempt shows">ATT&amp;CK</th><th>Status</th></tr></thead><tbody id="feed"></tbody></table>
</div>
<div class="panel" id="p-inc">
 <div class="sec-h"><div class="sec-t">Incidents, one per source</div><div class="badge" id="i-count">0</div></div>
 <div class="split">
  <div><div class="toolbar"><select id="i-f"><option value="open">Open</option><option value="handled">Handled</option><option value="all">All</option></select></div>
   <table><thead><tr><th>Source</th><th>Baits</th><th>Last seen</th><th>Status</th></tr></thead><tbody id="ilist"></tbody></table></div>
  <div class="detail" id="idetail"></div>
 </div>
</div>
<div class="panel" id="p-baits">
 <div class="sec-h"><div class="sec-t">Bait inventory</div><div class="badge" id="b-count">0 files</div></div>
 <div class="toolbar"><input id="b-q" type="search" placeholder="Filter: file name or location"></div>
 <table><thead><tr><th>File</th><th>Logins</th><th>Where it belongs</th><th>Planted at</th><th>Status</th></tr></thead><tbody id="blist"></tbody></table>
</div>
<div class="panel" id="p-integ"><div class="cards" id="integ"></div></div>
<script>
var ST=null,SEL=null;
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=String(x);return e;}
function td(c,x){return el('td',c,x);}
function ip(src){return (src||'').replace(/:\d+$/,'');}
function ago(t){if(!t)return '—';var s=(Date.now()-Date.parse(t))/1000;if(s<60)return 'just now';if(s<3600)return Math.round(s/60)+'m ago';if(s<86400)return Math.round(s/3600)+'h ago';return Math.round(s/86400)+'d ago';}
function ts(t){return (t||'').replace('T',' ').slice(0,19);}
function status(msg,cls){var c=document.getElementById('cmd-status');c.textContent=msg;c.className='cmd-status '+(cls||'');}
document.querySelectorAll('.tab').forEach(function(b){b.onclick=function(){go(b.dataset.t);};});
function go(t){document.querySelectorAll('.tab').forEach(function(x){x.classList.toggle('on',x.dataset.t===t);});document.querySelectorAll('.panel').forEach(function(p){p.classList.toggle('on',p.id==='p-'+t);});}
['f-sev','f-q','b-q','i-f'].forEach(function(id){document.getElementById(id).oninput=function(){if(ST)render(ST);};});
document.getElementById('f-clear').onclick=function(){document.getElementById('f-sev').value='';document.getElementById('f-q').value='';render(ST);};
function sevOf(a){if(a.demo)return 'DEMO';if(a.acknowledged)return 'DONE';return a.severity==='high'?'HIGH':'MEDIUM';}
function render(st){ST=st;document.getElementById('refresh').textContent='updated '+new Date().toLocaleTimeString();
 var alerts=st.alerts||[],inc=st.incidents||[],open=inc.filter(function(i){return !i.handled;}),files=st.files||[],ch=st.channels||{},L=st.listening||{},P=L.ports||{};
 var pill=document.getElementById('pill'),pt=document.getElementById('pill-t');
 if(st.demo){pill.className='pill demo';pt.textContent='DEMO';}else if(open.length){pill.className='pill bad';pt.textContent=open.length+' OPEN INCIDENT'+(open.length>1?'S':'');}else{pill.className='pill ok';pt.textContent='ALL QUIET';}
 document.getElementById('h-host').textContent=L.listener||'—';
 document.getElementById('s-demo').hidden=!st.demo;document.getElementById('test-btn').disabled=!!st.demo;
 var sa=document.getElementById('s-alarm');sa.hidden=!(open.length&&!st.demo);
 if(open.length&&!st.demo){var i0=open[0];sa.textContent='';sa.appendChild(el('b',null,'BAIT USED. '));sa.appendChild(document.createTextNode(i0.from.charAt(0).toUpperCase()+i0.from.slice(1)+' tried '+i0.baits+' bait login'+(i0.baits===1?'':'s')+' '+ago(i0.last)+'. '));var lk=el('button','row-btn','Open incident');lk.onclick=function(){SEL=i0.source;go('inc');render(ST);};sa.appendChild(lk);}
 var su=document.getElementById('s-upd');su.hidden=!st.update;if(st.update){su.textContent='';su.appendChild(el('b',null,'UPDATE '+st.update+' AVAILABLE. '));su.appendChild(document.createTextNode('Nothing installs without you. Run '));su.appendChild(el('code',null,'lure update'));su.appendChild(document.createTextNode(' to read the changes and approve.'));}
 document.getElementById('m-host').textContent=L.listener||'—';
 document.getElementById('m-ports').textContent=[P.rdp?'RDP '+P.rdp:null,P.http?'HTTP '+P.http:null,(P.openvpn||[]).length?'VPN '+P.openvpn.join(','):null].filter(Boolean).join(' · ')||'—';
 var used=files.filter(function(f){return f.used;}).length,logins=files.reduce(function(n,f){return n+f.logins;},0);
 document.getElementById('m-files').textContent=files.length;document.getElementById('m-logins').textContent=logins;document.getElementById('m-profile').textContent=st.profile||'—';
 var bs=document.getElementById('m-baits-st'),bm=document.getElementById('m-baits');bs.textContent=used?used+' USED':'ARMED';bs.className='st '+(used?'bad':'ok');bm.className='mod'+(used?' bad':'');
 var names=[];if(ch.desktop)names.push('popup');if(ch.email)names.push('email');if(ch.webhook)names.push(ch.webhook);if(ch.syslog)names.push('syslog');
 document.getElementById('m-chans').textContent=['console'].concat(names).join(', ');
 var cs=document.getElementById('m-chan-st'),cm=document.getElementById('m-chan');cs.textContent=names.length?names.length+1+' ON':'CONSOLE ONLY';cs.className='st '+(names.length?'ok':'warn');cm.className='mod'+(names.length?'':' warn');
 var us=document.getElementById('m-upd-st');us.textContent=st.update?'UPDATE READY':'CURRENT';us.className='st '+(st.update?'warn':'ok');document.getElementById('m-upd').className='mod'+(st.update?' warn':'');document.getElementById('m-updv').textContent=st.update?st.update+' waiting for your approval':'none waiting';
 var so=document.getElementById('s-open');so.textContent=open.length;so.className='stat-v '+(open.length?'red':'green');
 document.getElementById('s-used').textContent=alerts.filter(function(a){return a.severity==='high';}).length;
 document.getElementById('s-ips').textContent=inc.length;
 document.getElementById('s-hour').textContent=alerts.filter(function(a){return Date.now()-Date.parse(a.time)<3600000;}).length;
 document.getElementById('s-since').textContent=ts(st.since).slice(0,16)+' UTC';
 var tc=document.getElementById('t-cnt');tc.hidden=!open.length;tc.textContent=open.length;
 feed(alerts);incidents(inc);baits(files);integ(ch);}
function feed(alerts){var sev=document.getElementById('f-sev').value,q=document.getElementById('f-q').value.toLowerCase(),tb=document.getElementById('feed');tb.textContent='';
 var rows=alerts.filter(function(a){var x=a.explain||{};return (!sev||a.severity===sev)&&(!q||[a.source,a.bait_file,a.service,x.attack,x.how,a.username].join(' ').toLowerCase().indexOf(q)>=0);});
 document.getElementById('f-count').textContent=rows.length+' alert'+(rows.length===1?'':'s');
 if(!rows.length){var r=el('tr','empty'),c=td(null,alerts.length?'No alert matches these filters.':'No alerts yet. Lure stays silent until someone uses a bait login. Press Run test to see one arrive.');c.colSpan=7;r.appendChild(c);tb.appendChild(r);return;}
 rows.forEach(function(a){var x=a.explain||{},r=el('tr','click');r.onclick=function(){SEL=ip(a.source);go('inc');render(ST);};
  r.appendChild(td('t-time',ts(a.time)));r.appendChild(td('t-ip',ip(a.source)));var s=td();s.appendChild(el('span','proto',a.service));r.appendChild(s);
  var v=td();v.appendChild(el('span','sev '+(a.severity==='high'?'HIGH':'MEDIUM'),a.severity));r.appendChild(v);
  var w=td('what');w.appendChild(document.createTextNode(x.how||''));if(a.location||a.planted_on)w.appendChild(el('small',null,'bait: '+(a.bait_file||'')+(a.location?' · planted at '+a.location:'')));r.appendChild(w);
  var t=td('tech');t.appendChild(document.createTextNode(x.attack||''));t.appendChild(el('small',null,x.attack_name||''));r.appendChild(t);
  var st=td();st.appendChild(el('span','sev '+sevOf(a),a.demo?'demo':(a.acknowledged?'handled':'open')));r.appendChild(st);tb.appendChild(r);});}
function incidents(all){var f=document.getElementById('i-f').value,tb=document.getElementById('ilist');tb.textContent='';
 var list=all.filter(function(i){return f==='all'||(f==='open'?!i.handled:i.handled);});document.getElementById('i-count').textContent=list.length;
 if(!SEL||!all.some(function(i){return i.source===SEL;}))SEL=list.length?list[0].source:null;
 if(!list.length){var r=el('tr','empty'),c=td(null,f==='open'?'No open incidents. You are all caught up.':'Nothing here yet.');c.colSpan=4;r.appendChild(c);tb.appendChild(r);}
 list.forEach(function(i){var r=el('tr','click'+(i.source===SEL?' sel':''));r.onclick=function(){SEL=i.source;render(ST);};
  var c=td();c.appendChild(el('div','t-ip',i.source));c.appendChild(el('div','t-time',i.from));r.appendChild(c);r.appendChild(td(null,i.baits));r.appendChild(td('t-time',ago(i.last)));
  var s=td();s.appendChild(el('span','sev '+(i.demo?'DEMO':(i.handled?'DONE':(i.severity==='high'?'HIGH':'MEDIUM'))),i.demo?'demo':(i.handled?'handled':'open')));r.appendChild(s);tb.appendChild(r);});
 var d=document.getElementById('idetail');d.textContent='';var i=all.filter(function(x){return x.source===SEL;})[0];
 if(!i){var e=el('div','d-sec');e.appendChild(el('div','sec-t','Select an incident to see what happened and what to do.'));d.appendChild(e);return;}
 var h=el('div','d-h'),g=el('div','grow');g.appendChild(el('h3',null,(i.demo?'Demo: ':'')+(i.severity==='high'?i.baits+' bait login'+(i.baits===1?'':'s')+' used from '+i.source:'Listener touched by '+i.source)));g.appendChild(el('div','sub',i.who));h.appendChild(g);
 h.appendChild(el('span','sev '+(i.demo?'DEMO':(i.handled?'DONE':'HIGH')),i.demo?'demo':(i.handled?'handled':'open')));d.appendChild(h);
 var kv=el('div','kv');[['Source',i.source],['First seen',ts(i.first).slice(11)+' UTC'],['Last seen',ago(i.last)],['Attempts',i.steps.length]].forEach(function(p){var c=el('div');c.appendChild(el('div','k',p[0]));c.appendChild(el('div','v',p[1]));kv.appendChild(c);});d.appendChild(kv);
 var s1=el('div','d-sec');s1.appendChild(el('div','d-t','Attack chain'));var ch=el('div','chain');
 i.steps.forEach(function(s){var r=el('div','step');r.appendChild(el('span','tm',ts(s.time).slice(11)));r.appendChild(el('span','nd'));var tx=el('span','tx',s.how);if(s.attack)tx.appendChild(el('span','tech',s.attack));r.appendChild(tx);ch.appendChild(r);});s1.appendChild(ch);d.appendChild(s1);
 var s2=el('div','d-sec');s2.appendChild(el('div','d-t','Response checklist'));var td2=el('div','todo');i.next.forEach(function(n){var l=el('label'),cb=el('input');cb.type='checkbox';l.appendChild(cb);l.appendChild(el('span',null,n));td2.appendChild(l);});s2.appendChild(td2);d.appendChild(s2);
 if(!i.handled){var a=el('div','act'),b=el('button','tb-btn primary','Mark incident handled');b.onclick=function(){ack(i.ids);};a.appendChild(b);d.appendChild(a);}}
function baits(files){var q=document.getElementById('b-q').value.toLowerCase(),tb=document.getElementById('blist');tb.textContent='';
 var rows=files.filter(function(f){return !q||(f.file+' '+(f.plant_on||'')+' '+(f.location||'')).toLowerCase().indexOf(q)>=0;});document.getElementById('b-count').textContent=files.length+' files';
 rows.forEach(function(f){var r=el('tr');r.appendChild(td('t-ip',f.file));r.appendChild(td(null,f.logins));r.appendChild(td('what',f.plant_on||''));r.appendChild(td('t-time',f.location||'not recorded (lure record)'));
  var s=td();s.appendChild(el('span','sev '+(f.used?'HIGH':(f.retired?'DONE':'OK')),f.used?'used':(f.retired?'retired':'untouched')));r.appendChild(s);tb.appendChild(r);});}
function integ(ch){var box=document.getElementById('integ');box.textContent='';
 [['Console','This page. Always on.',true],['Desktop popup',ch.desktop?'Shows each alert on this computer.':'Add --desktop to lure listen.',ch.desktop],
  ['Email',ch.email?'Sends to '+ch.email+'.':'Add --email-to you@gmail.com and set LURE_SMTP_PASSWORD to an app password.',ch.email],
  ['Phone and chat',ch.webhook?'Sends to '+ch.webhook+'.':'Add --webhook with an ntfy, Telegram, Discord, Slack or Teams link.',ch.webhook],
  ['Syslog and SIEM',ch.syslog?'Sends to your syslog server.':'Add --syslog HOST:514.',ch.syslog],
  ['AI agents (MCP)','Run lure mcp to let an AI agent read alerts and manage baits.',false]].forEach(function(x){var c=el('div','card'),r=el('div','row');r.appendChild(el('h4',null,x[0]));r.appendChild(el('span','st '+(x[2]?'ok':'off'),x[2]?'ON':'OFF'));c.appendChild(r);c.appendChild(el('p',null,x[1]));box.appendChild(c);});}
function load(){fetch('/api/state').then(function(r){return r.json();}).then(render).catch(function(){var p=document.getElementById('pill');p.className='pill bad';document.getElementById('pill-t').textContent='LISTENER OFFLINE';});}
function post(p,b){return fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});}
function ack(ids){post('/api/ack',{ids:ids}).then(load);}
document.getElementById('ack-all').onclick=function(){var ids=[];(ST.incidents||[]).forEach(function(i){if(!i.handled)ids=ids.concat(i.ids);});if(!ids.length){status('Nothing open to mark.','');return;}ack(ids);status('Marked '+ids.length+' alert'+(ids.length===1?'':'s')+' handled.','ok');};
document.getElementById('test-btn').onclick=function(){var b=this;b.disabled=true;status('Firing a bait login at the listener...','');var before=(ST.alerts||[]).length,t0=Date.now();
 post('/api/test').then(function(r){if(!r.ok)throw 0;var iv=setInterval(function(){fetch('/api/state').then(function(x){return x.json();}).then(function(s){render(s);if((s.alerts||[]).length>before){clearInterval(iv);status('Test passed: alert arrived in '+((Date.now()-t0)/1000).toFixed(1)+' s.','ok');b.disabled=false;}else if(Date.now()-t0>10000){clearInterval(iv);status('No new alert within 10 s. A repeat test within 10 minutes is folded into the earlier alert; otherwise check the listener ports and firewall.','bad');b.disabled=false;}});},700);})
 .catch(function(){status('Test is not available here.','bad');b.disabled=false;});};
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
