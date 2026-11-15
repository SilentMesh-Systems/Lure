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
<title>Lure</title>
<style>
:root{--bg:#07080A;--side:#0B0D0F;--panel:#101316;--panel2:#151a1e;--line:#1f262b;--text:#EEF2EE;--dim:#8A938C;--faint:#5c645e;
--green:#5FE07F;--greenbg:rgba(95,224,127,.10);--red:#FF5D47;--redbg:rgba(255,93,71,.10);--amber:#F2C14E;--amberbg:rgba(242,193,78,.10)}
*{box-sizing:border-box}[hidden]{display:none!important}html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:grid;grid-template-columns:220px 1fr;grid-template-rows:56px 1fr;height:100vh;overflow:hidden}
button{font:inherit;cursor:pointer}
.mono{font-family:ui-monospace,"Cascadia Mono",Menlo,monospace}
/* sidebar */
aside{grid-row:1/3;background:var(--side);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:14px 10px;gap:4px}
.brand{display:flex;align-items:center;gap:10px;padding:4px 10px 18px}
.brand img{width:26px;height:26px;border-radius:7px}.brand b{font-weight:600}.brand span{color:var(--green)}
.nav{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:var(--dim);background:none;border:0;text-align:left;width:100%}
.nav:hover{background:var(--panel);color:var(--text)}.nav.on{background:var(--panel2);color:var(--text)}
.nav svg{width:17px;height:17px;flex:none}.nav .badge{margin-left:auto;background:var(--red);color:#fff;border-radius:10px;padding:0 7px;font-size:12px;font-weight:600}
.side-foot{margin-top:auto;padding:10px 12px;color:var(--faint);font-size:12px}
/* topbar */
header{display:flex;align-items:center;gap:14px;padding:0 22px;border-bottom:1px solid var(--line)}
.pill{display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border-radius:999px;font-weight:600;font-size:13px}
.pill i{width:8px;height:8px;border-radius:50%;background:currentColor}
.pill.ok{background:var(--greenbg);color:var(--green)}.pill.bad{background:var(--redbg);color:var(--red)}.pill.demo{background:var(--amberbg);color:var(--amber)}
.pill.bad i{animation:p 1.2s infinite}@keyframes p{50%{opacity:.3}}@media (prefers-reduced-motion:reduce){.pill i{animation:none}}
header .msg{color:var(--dim)}header .grow{flex:1}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);padding:7px 14px;border-radius:8px;font-weight:500}
.btn:hover{border-color:var(--faint)}.btn.primary{background:var(--text);color:var(--bg);border-color:var(--text)}.btn.primary:hover{background:var(--green);border-color:var(--green)}
.btn:disabled{opacity:.5;cursor:default}
main{overflow:auto;padding:22px;display:flex;flex-direction:column;gap:18px}
.banner{display:flex;gap:12px;align-items:center;border-radius:10px;padding:11px 14px}
.banner.demo{background:var(--amberbg);border:1px solid rgba(242,193,78,.35);color:#F7DC93}
.banner.upd{background:var(--panel);border:1px solid var(--line)}
code{font:13px ui-monospace,monospace;color:var(--green);background:rgba(255,255,255,.04);padding:1px 6px;border-radius:5px}
.view{display:none;flex-direction:column;gap:18px}.view.on{display:flex}
h2{margin:0;font-size:18px;font-weight:600}.sub{color:var(--dim);margin-top:2px}
/* tiles */
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.tile .k{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.tile .v{font-size:28px;font-weight:600;margin-top:4px}.tile .v.red{color:var(--red)}.tile .v.green{color:var(--green)}
.tile .h{color:var(--faint);font-size:12px;margin-top:2px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card-h{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.card-h h3{margin:0;font-size:14px;font-weight:600}.link{color:var(--dim);background:none;border:0;padding:0}.link:hover{color:var(--text)}
.grid2{display:grid;grid-template-columns:2fr 1fr;gap:12px}
/* chart */
.bars{display:flex;align-items:flex-end;gap:5px;height:110px;padding-top:6px}
.bars div{flex:1;background:var(--panel2);border-radius:3px;min-height:3px;position:relative}
.bars div.hit{background:var(--red)}
.axis{display:flex;justify-content:space-between;color:var(--faint);font-size:11px;margin-top:6px}
/* rows */
.row{display:flex;align-items:center;gap:12px;padding:10px 6px;border-top:1px solid var(--line)}
.row:first-child{border-top:0}.row.click{cursor:pointer;border-radius:8px}.row.click:hover{background:var(--panel2)}
.sev{flex:none;width:9px;height:9px;border-radius:50%}.sev.high{background:var(--red)}.sev.medium{background:var(--amber)}.sev.done{background:var(--faint)}.sev.demo{background:var(--amber)}
.row .main{flex:1;min-width:0}.row .t1{font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.row .t2{color:var(--dim);font-size:13px}
.row .when{color:var(--faint);font-size:12px;white-space:nowrap}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600}
.chip.red{background:var(--redbg);color:var(--red)}.chip.green{background:var(--greenbg);color:var(--green)}.chip.grey{background:var(--panel2);color:var(--dim)}.chip.amber{background:var(--amberbg);color:var(--amber)}
.empty{color:var(--dim);text-align:center;padding:36px 16px}.empty b{display:block;color:var(--text);font-size:15px;margin-bottom:4px}
/* incidents split */
.split{display:grid;grid-template-columns:340px 1fr;gap:12px;min-height:480px}
.list{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:8px;overflow:auto}
.tabs{display:flex;gap:4px;padding:4px 4px 8px}.tab{background:none;border:0;color:var(--dim);padding:5px 10px;border-radius:6px}.tab.on{background:var(--panel2);color:var(--text)}
.row.sel{background:var(--panel2)}
.detail{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;display:flex;flex-direction:column;gap:18px}
.dh{display:flex;gap:14px;align-items:flex-start}.dh h2{font-size:20px}.dh .grow{flex:1}
.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.fact{background:var(--panel2);border-radius:10px;padding:10px 12px}.fact .k{color:var(--dim);font-size:12px}.fact .v{margin-top:2px;font-weight:500}
.sec{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.tl{position:relative;padding-left:20px;display:flex;flex-direction:column;gap:12px}
.tl:before{content:"";position:absolute;left:5px;top:6px;bottom:6px;width:2px;background:var(--line)}
.tl>div{position:relative}.tl>div:before{content:"";position:absolute;left:-19px;top:5px;width:10px;height:10px;border-radius:50%;background:var(--red)}
.tl .tm{color:var(--faint);font-size:12px}
.check{display:flex;flex-direction:column;gap:6px}.check label{display:flex;gap:10px;align-items:flex-start;padding:9px 12px;background:var(--panel2);border-radius:8px;cursor:pointer}
.check input{margin-top:3px;accent-color:var(--green)}
.tech{color:var(--faint);font-size:12px}
/* table */
.toolbar{display:flex;gap:8px;align-items:center}
.toolbar input{background:var(--panel);border:1px solid var(--line);color:var(--text);padding:7px 12px;border-radius:8px;width:260px;font:inherit}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--dim);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.06em;padding:8px 10px}
td{padding:11px 10px;border-top:1px solid var(--line);vertical-align:middle}
td.f{font-family:ui-monospace,monospace;font-size:13px}
.chan{display:flex;align-items:center;gap:12px}.chan .main{flex:1}
@media (max-width:980px){body{grid-template-columns:1fr}aside{display:none}.tiles{grid-template-columns:repeat(2,1fr)}.grid2,.split{grid-template-columns:1fr}.facts{grid-template-columns:1fr}}
</style></head><body>
<aside>
 <div class="brand"><img alt="" src="data:image/png;base64,__MARK__"><b>SilentMesh <span>Lure</span></b></div>
 <button class="nav on" data-v="overview"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>Overview</button>
 <button class="nav" data-v="incidents"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/></svg>Incidents<span class="badge" id="nav-badge" hidden></span></button>
 <button class="nav" data-v="baits"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><circle cx="12" cy="14" r="2.2"/></svg>Baits</button>
 <button class="nav" data-v="alerts"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M6 16V11a6 6 0 1112 0v5l2 2H4z"/><path d="M10 20a2 2 0 004 0"/></svg>Alert channels</button>
 <div class="side-foot">Runs on this computer only<br>v__VERSION__</div>
</aside>
<header>
 <span class="pill ok" id="pill"><i></i><span id="pill-t">Protected</span></span>
 <span class="msg" id="pill-m"></span><span class="grow"></span>
 <span class="msg" id="test-msg"></span>
 <button class="btn primary" id="test-btn" title="Fires one bait login at your own listener, so you can see a real alert arrive">Test now</button>
</header>
<main>
 <div class="banner demo" id="demo" hidden><b>Demo mode.</b> A pretend attacker is using your baits on this computer. Nothing real happened. Your real console opens with <code>lure listen --ui</code>.</div>
 <div class="banner upd" id="upd" hidden></div>

 <section class="view on" id="v-overview">
  <div class="tiles">
   <div class="tile"><div class="k">Open incidents</div><div class="v" id="t-open">0</div><div class="h" id="t-open-h">Nothing needs you</div></div>
   <div class="tile"><div class="k">Baits in place</div><div class="v" id="t-baits">0</div><div class="h" id="t-baits-h"></div></div>
   <div class="tile"><div class="k">Last activity</div><div class="v" id="t-last">None</div><div class="h" id="t-last-h">No bait used yet</div></div>
   <div class="tile"><div class="k">Alerts reach you by</div><div class="v" id="t-chan" style="font-size:18px;margin-top:10px">Console</div><div class="h"><button class="link" data-go="alerts">Add a channel</button></div></div>
  </div>
  <div class="grid2">
   <div class="card"><div class="card-h"><h3>Bait use, last 14 days</h3><span class="tech" id="chart-sum"></span></div><div class="bars" id="bars"></div><div class="axis"><span id="ax0"></span><span>Today</span></div></div>
   <div class="card"><div class="card-h"><h3>Latest incidents</h3><button class="link" data-go="incidents">View all</button></div><div id="latest"></div></div>
  </div>
 </section>

 <section class="view" id="v-incidents">
  <div><h2>Incidents</h2><div class="sub">One incident per source. Everything a source did is grouped under it.</div></div>
  <div class="split">
   <div class="list"><div class="tabs"><button class="tab on" data-f="open">Open</button><button class="tab" data-f="handled">Handled</button><button class="tab" data-f="all">All</button></div><div id="inc-list"></div></div>
   <div class="detail" id="inc-detail"></div>
  </div>
 </section>

 <section class="view" id="v-baits">
  <div class="toolbar"><div style="flex:1"><h2>Baits</h2><div class="sub">Fake files with fake logins. Opening or copying them does nothing. Trying a login from one raises an incident.</div></div><input id="q" placeholder="Search baits" aria-label="Search baits"></div>
  <div class="card" style="padding:6px 8px"><table><thead><tr><th>File</th><th>Where it belongs</th><th>Logins</th><th>Status</th></tr></thead><tbody id="bait-rows"></tbody></table></div>
 </section>

 <section class="view" id="v-alerts">
  <div><h2>Alert channels</h2><div class="sub">Where Lure tells you about a new incident. Change them with <code>lure init</code> or the options below.</div></div>
  <div class="card" id="chans"></div>
 </section>
</main>
<script>
var ST=null,FILTER='open',SEL=null;
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=String(x);return e;}
function ago(t){if(!t)return '';var s=(Date.now()-Date.parse(t))/1000;if(s<60)return 'Just now';if(s<3600)return Math.round(s/60)+' min ago';if(s<86400)return Math.round(s/3600)+' h ago';return Math.round(s/86400)+' d ago';}
function hm(t){return (t||'').slice(11,19);}
function show(v){document.querySelectorAll('.view').forEach(function(x){x.classList.toggle('on',x.id==='v-'+v);});document.querySelectorAll('.nav').forEach(function(n){n.classList.toggle('on',n.dataset.v===v);});}
document.querySelectorAll('.nav').forEach(function(n){n.onclick=function(){show(n.dataset.v);};});
document.addEventListener('click',function(e){var g=e.target.closest('[data-go]');if(g)show(g.dataset.go);});
document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){FILTER=t.dataset.f;document.querySelectorAll('.tab').forEach(function(x){x.classList.toggle('on',x===t);});SEL=null;renderInc();};});
document.getElementById('q').oninput=function(){renderBaits();};
function title(i){if(i.severity!=='high')return 'Listener touched by '+i.from;return (i.demo?'Demo: ':'')+i.baits+(i.baits===1?' bait':' baits')+' used from '+i.from;}
function sevClass(i){return i.handled?'done':(i.demo?'demo':i.severity);}
function incRow(i,click){var r=el('div','row'+(click?' click':'')+(SEL===i.source&&click?' sel':''));r.appendChild(el('span','sev '+sevClass(i)));var m=el('div','main');m.appendChild(el('div','t1',title(i)));m.appendChild(el('div','t2',i.steps.length+(i.steps.length===1?' attempt':' attempts')+(i.handled?' · handled':'')));r.appendChild(m);r.appendChild(el('span','when',ago(i.last)));
 r.onclick=function(){SEL=i.source;show('incidents');renderInc();};return r;}
function render(st){ST=st;var inc=st.incidents||[],open=inc.filter(function(i){return !i.handled;});
 var pill=document.getElementById('pill'),pt=document.getElementById('pill-t'),pm=document.getElementById('pill-m');
 if(st.demo){pill.className='pill demo';pt.textContent='Demo';pm.textContent='Showing a pretend attack';}
 else if(open.length){pill.className='pill bad';pt.textContent=open.length+(open.length===1?' open incident':' open incidents');pm.textContent='Someone tried a fake login. Open Incidents to see who and what to do.';}
 else{pill.className='pill ok';pt.textContent='Protected';pm.textContent='Listening since '+(st.since||'').slice(0,16).replace('T',' ')+' UTC';}
 document.getElementById('demo').hidden=!st.demo;document.getElementById('test-btn').hidden=!!st.demo;
 var u=document.getElementById('upd');u.hidden=!st.update;if(st.update){u.textContent='';u.appendChild(el('b',null,'Lure '+st.update+' is available.'));u.appendChild(document.createTextNode(' Nothing installs without your approval. Run '));u.appendChild(el('code',null,'lure update'));u.appendChild(document.createTextNode(' to read what changed and decide.'));}
 var b=document.getElementById('nav-badge');b.hidden=!open.length;b.textContent=open.length;
 var to=document.getElementById('t-open');to.textContent=open.length;to.className='v'+(open.length?' red':' green');
 document.getElementById('t-open-h').textContent=open.length?'Needs your attention':'Nothing needs you';
 var files=st.files||[],used=files.filter(function(f){return f.used;}).length;
 document.getElementById('t-baits').textContent=files.length;document.getElementById('t-baits-h').textContent=used?used+' used so far':'None used';
 var last=(st.alerts||[])[0];document.getElementById('t-last').textContent=last?ago(last.time):'None';document.getElementById('t-last-h').textContent=last?(last.bait_file||'Listener touched'):'No bait used yet';
 var c=st.channels||{},names=['Console'];if(c.desktop)names.push('Popup');if(c.email)names.push('Email');if(c.webhook)names.push(c.webhook);if(c.syslog)names.push('Syslog');
 document.getElementById('t-chan').textContent=names.join(', ');
 chart(st.alerts||[]);
 var lt=document.getElementById('latest');lt.textContent='';
 if(!inc.length){var e=el('div','empty');e.appendChild(el('b',null,'No incidents'));e.appendChild(document.createTextNode('Lure stays silent until someone tries a login from a bait. Press Test now to see one.'));lt.appendChild(e);}
 inc.slice(0,5).forEach(function(i){lt.appendChild(incRow(i,true));});
 renderInc();renderBaits();renderChans();}
function chart(alerts){var bars=document.getElementById('bars');bars.textContent='';var days=[],now=new Date();now.setUTCHours(0,0,0,0);
 for(var d=13;d>=0;d--){var k=new Date(now-d*86400000).toISOString().slice(0,10);days.push({k:k,n:0});}
 alerts.forEach(function(a){if(a.severity!=='high')return;var k=(a.time||'').slice(0,10);days.forEach(function(x){if(x.k===k)x.n++;});});
 var max=Math.max.apply(null,days.map(function(x){return x.n;}).concat([1])),tot=0;
 days.forEach(function(x){tot+=x.n;var b=el('div',x.n?'hit':'');b.style.height=(x.n?Math.max(8,100*x.n/max):3)+'%';b.title=x.k+': '+x.n+(x.n===1?' bait used':' baits used');bars.appendChild(b);});
 document.getElementById('ax0').textContent=days[0].k.slice(5);document.getElementById('chart-sum').textContent=tot?tot+' in 14 days':'Quiet';}
function renderInc(){if(!ST)return;var all=ST.incidents||[];
 var list=all.filter(function(i){return FILTER==='all'||(FILTER==='open'?!i.handled:i.handled);});
 var le=document.getElementById('inc-list');le.textContent='';
 if(!list.length){var e=el('div','empty');e.appendChild(el('b',null,FILTER==='open'?'No open incidents':'Nothing here'));e.appendChild(document.createTextNode(FILTER==='open'?'You are all caught up.':'Handled incidents appear here.'));le.appendChild(e);}
 if(!SEL||!list.some(function(i){return i.source===SEL;}))SEL=list.length?list[0].source:null;
 list.forEach(function(i){le.appendChild(incRow(i,true));});
 var d=document.getElementById('inc-detail');d.textContent='';var i=all.filter(function(x){return x.source===SEL;})[0];
 if(!i){var e2=el('div','empty');e2.appendChild(el('b',null,'Select an incident'));e2.appendChild(document.createTextNode('Its full story and next steps appear here.'));d.appendChild(e2);return;}
 var h=el('div','dh');var ht=el('div','grow');ht.appendChild(el('h2',null,title(i)));ht.appendChild(el('div','sub',i.who));h.appendChild(ht);
 h.appendChild(el('span','chip '+(i.handled?'grey':(i.demo?'amber':'red')),i.handled?'Handled':(i.demo?'Demo':'Open')));d.appendChild(h);
 var f=el('div','facts');[['Source',i.source],['First seen',(i.first||'').replace('T',' ').slice(0,19)+' UTC'],['Baits used',String(i.baits)]].forEach(function(p){var x=el('div','fact');x.appendChild(el('div','k',p[0]));x.appendChild(el('div','v',p[1]));f.appendChild(x);});d.appendChild(f);
 var s1=el('div');s1.appendChild(el('div','sec','What happened'));var tl=el('div','tl');i.steps.forEach(function(s){var x=el('div');x.appendChild(el('div','tm',hm(s.time)+' UTC'));x.appendChild(el('div',null,s.how));tl.appendChild(x);});s1.appendChild(tl);d.appendChild(s1);
 var s2=el('div');s2.appendChild(el('div','sec','What to do'));var ck=el('div','check');i.next.forEach(function(n){var l=el('label');var cb=el('input');cb.type='checkbox';l.appendChild(cb);l.appendChild(el('span',null,n));ck.appendChild(l);});s2.appendChild(ck);d.appendChild(s2);
 if(!i.handled){var bt=el('button','btn primary','Mark as handled');bt.style.alignSelf='flex-start';bt.onclick=function(){ack(i.ids);};d.appendChild(bt);}
}
function renderBaits(){if(!ST)return;var q=document.getElementById('q').value.toLowerCase(),tb=document.getElementById('bait-rows');tb.textContent='';
 var files=(ST.files||[]).filter(function(f){return !q||(f.file+' '+(f.plant_on||'')+' '+(f.location||'')).toLowerCase().indexOf(q)>=0;});
 if(!files.length){var r=el('tr'),c=el('td','empty','No bait matches "'+q+'".');c.colSpan=4;r.appendChild(c);tb.appendChild(r);}
 files.forEach(function(f){var r=el('tr');r.appendChild(el('td','f',f.file));var w=f.location?'Planted at '+f.location:(f.plant_on||'');r.appendChild(el('td',null,w.charAt(0).toUpperCase()+w.slice(1)));
  r.appendChild(el('td',null,f.logins));var s=el('td');s.appendChild(el('span','chip '+(f.used?'red':(f.retired?'grey':'green')),f.used?'Used':(f.retired?'Retired':'Untouched')));r.appendChild(s);tb.appendChild(r);});}
function renderChans(){var c=ST.channels||{},box=document.getElementById('chans');box.textContent='';
 [['Console','This page. Always on.',true,''],
  ['Popup on this computer',c.desktop?'On':'Off. Add --desktop to lure listen.',c.desktop,''],
  ['Email',c.email?'On, to '+c.email:'Off. Add --email-to you@gmail.com and set LURE_SMTP_PASSWORD to an app password.',c.email,''],
  ['Phone or chat',c.webhook?'On, through '+c.webhook:'Off. Add --webhook with an ntfy, Telegram, Discord, Slack or Teams link.',c.webhook,''],
  ['Syslog / SIEM',c.syslog?'On':'Off. Add --syslog HOST:514.',c.syslog,'']].forEach(function(x){var r=el('div','row chan');var m=el('div','main');m.appendChild(el('div','t1',x[0]));m.appendChild(el('div','t2',x[1]));r.appendChild(m);r.appendChild(el('span','chip '+(x[2]?'green':'grey'),x[2]?'On':'Off'));box.appendChild(r);});}
function load(){fetch('/api/state').then(function(r){return r.json();}).then(render).catch(function(){});}
function post(p,b){return fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});}
function ack(ids){post('/api/ack',{ids:ids}).then(load);}
document.getElementById('test-btn').onclick=function(){var b=this,m=document.getElementById('test-msg');b.disabled=true;m.textContent='Sending a test login...';
 post('/api/test').then(function(r){m.textContent=r.ok?'Test sent. A new incident from this computer should appear within seconds.':'Test is not available in this view.';}).catch(function(){m.textContent='Could not reach the listener.';}).then(function(){setTimeout(function(){b.disabled=false;m.textContent='';load();},6000);load();});};
if(location.hash)show(location.hash.slice(1));
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
