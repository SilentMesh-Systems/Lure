"""Local dashboard: `lure listen --ui` serves a page showing every bait and every alert.

It binds to 127.0.0.1 by default, so it is reachable only from the listener
host itself. Nothing leaves the machine. Changing state (acknowledging an
alert) needs a JSON POST from the dashboard's own origin, so a web page the
operator happens to visit cannot do it for them.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from ._mark import MARK_PNG_B64

# Bundled fonts (SIL OFL 1.1, see fonts/OFL.txt). Served by name from this
# whitelist only, so no request path ever reaches the filesystem.
_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
FONTS = ("plex-mono-400.woff2", "plex-mono-500.woff2", "instrument-sans-500.woff2", "instrument-serif-400.woff2")
CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
       "font-src 'self'; connect-src 'self'")

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lure console</title>
<style>
@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:400;font-display:swap;src:url(/fonts/plex-mono-400.woff2) format('woff2')}
@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:500;font-display:swap;src:url(/fonts/plex-mono-500.woff2) format('woff2')}
@font-face{font-family:'Instrument Sans';font-style:normal;font-weight:500;font-display:swap;src:url(/fonts/instrument-sans-500.woff2) format('woff2')}
@font-face{font-family:'Instrument Serif';font-style:normal;font-weight:400;font-display:swap;src:url(/fonts/instrument-serif-400.woff2) format('woff2')}
:root{color-scheme:dark;--black:#08090A;--page:#0D0F0E;--panel:#101312;--terminal:#050606;--signal:#5FE07F;--white:#F2F4F1;
 --t1:#F2F4F1;--t2:rgba(242,244,241,.66);--t3:rgba(242,244,241,.56);--t4:rgba(242,244,241,.50);
 --hair:rgba(255,255,255,.07);--hair2:rgba(255,255,255,.14);--sel:rgba(255,255,255,.045);
 --serif:'Instrument Serif',Georgia,'Times New Roman',serif;--sans:'Instrument Sans','Helvetica Neue',Arial,sans-serif;
 --mono:'IBM Plex Mono',ui-monospace,'SFMono-Regular',Menlo,Consolas,monospace}
html,body{height:100%}
body{margin:0;background:var(--page);color:var(--t1);font:400 12px/1.55 var(--mono);overflow:hidden}
*{box-sizing:border-box}[hidden]{display:none!important}
button,input{font:inherit;color:inherit}button{cursor:pointer}
a{color:inherit}
:focus-visible{outline:1px solid var(--white);outline-offset:2px}
::selection{background:rgba(242,244,241,.2)}
.lbl{font:500 10px/1 var(--sans);letter-spacing:.2em;text-transform:uppercase;color:var(--t3)}
.h{font:400 20px/1.15 var(--serif);letter-spacing:.05em;text-transform:uppercase;margin:0}
.dim{color:var(--t3)}.mid{color:var(--t2)}.num{font-variant-numeric:tabular-nums}
code{font:inherit;color:var(--t1)}
/* frame */
.app{display:grid;grid-template-columns:148px minmax(0,1fr);grid-template-rows:auto auto minmax(0,1fr);height:100%}
.sim{grid-column:1/-1;grid-row:1;padding:5px 16px;border-bottom:1px solid var(--hair);color:var(--t3);font-size:11px;letter-spacing:.02em}
.sim b{color:var(--t2);font-weight:500}
.top{grid-column:1/-1;grid-row:2;display:flex;align-items:center;gap:18px;padding:10px 16px;border-bottom:1px solid var(--hair);background:var(--black);flex-wrap:wrap}
.lockup{display:flex;align-items:center;gap:12px}
.lockup svg{width:24px;height:24px}
.lockup .name{font:400 19px/1 var(--serif);letter-spacing:.05em;text-transform:uppercase}
.lockup .kick{font-size:10px;color:var(--t4);letter-spacing:.04em}
.grow{flex:1}
.site{color:var(--t2)}
.chips{display:flex;border:1px solid var(--hair2);border-radius:5px;overflow:hidden}
.chips button{background:none;border:0;padding:6px 11px;color:var(--t3);border-right:1px solid var(--hair);font:500 10px/1 var(--sans);letter-spacing:.2em;text-transform:uppercase}
.chips button:last-child{border-right:0}
.chips button[aria-pressed="true"]{color:var(--t1);background:var(--sel)}
.live{display:flex;align-items:center;gap:8px;color:var(--t2)}
.live .dot{color:var(--signal)}
.live.idle .dot{visibility:hidden}
.btn{background:none;border:1px solid var(--hair2);border-radius:5px;padding:7px 12px;font:500 10px/1 var(--sans);letter-spacing:.2em;text-transform:uppercase;color:var(--t2);white-space:nowrap;text-decoration:none;display:inline-block}
.btn:hover{color:var(--t1);border-color:rgba(255,255,255,.28)}
.btn:disabled{opacity:.4;cursor:default}
.btn kbd,.kbd{font:400 10px/1 var(--mono);letter-spacing:0;color:var(--t4);border:1px solid var(--hair);border-radius:3px;padding:2px 5px;margin-left:8px;text-transform:none}
.btn.solid{background:var(--white);color:var(--black);border-color:var(--white)}
.btn.solid kbd{color:rgba(8,9,10,.6);border-color:rgba(8,9,10,.25)}
.btn.solid:hover{opacity:.9}
.upd{color:var(--t2);font-size:11px}.upd b{color:var(--t1);font-weight:500}
.menu{position:relative}
.menu .items{position:absolute;right:0;top:calc(100% + 6px);background:var(--panel);border:1px solid var(--hair2);border-radius:5px;padding:4px;min-width:150px;z-index:15}
.menu .items a{display:block;padding:8px 10px;border-radius:3px;color:var(--t2);text-decoration:none}
.menu .items a:hover,.menu .items a:focus-visible{background:var(--sel);color:var(--t1)}
/* rail */
.rail{grid-row:3;border-right:1px solid var(--hair);background:var(--black);padding:12px 0;display:flex;flex-direction:column;gap:2px}
.rail button{display:flex;justify-content:space-between;align-items:center;width:100%;background:none;border:0;border-left:2px solid transparent;padding:10px 14px;color:var(--t3);text-align:left;font:500 10px/1 var(--sans);letter-spacing:.2em;text-transform:uppercase}
.rail button:hover{color:var(--t2)}
.rail button[aria-current="page"]{color:var(--t1);border-left-color:var(--white);background:var(--sel)}
.rail .count{font:400 11px/1 var(--mono);letter-spacing:0;color:var(--t3)}
.rail .sp{flex:1}
.rail .foot{padding:10px 14px;color:var(--t4);font-size:10.5px;line-height:1.6}
main{grid-row:3;min-width:0;min-height:0;overflow:hidden}
.view{display:none;height:100%;min-height:0}
.view.on{display:flex;flex-direction:column}
/* strip + chart */
.strip{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border-bottom:1px solid var(--hair)}
.stat{padding:12px 16px;border-right:1px solid var(--hair);min-width:0}
.stat:last-child{border-right:0}
.stat .v{font:400 26px/1.1 var(--serif);letter-spacing:.04em;margin-top:8px}
.stat .s{color:var(--t4);font-size:11px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chart{border-bottom:1px solid var(--hair);padding:10px 16px 6px}
.chart .row{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
.legend{display:flex;gap:14px;color:var(--t3);font-size:11px}
.legend i{display:inline-block;width:8px;height:8px;margin-right:6px;background:var(--white);vertical-align:-1px}
.chart svg{display:block;width:100%;height:84px;margin-top:8px}
/* split */
.split{flex:1;min-height:0;display:grid;grid-template-columns:minmax(330px,40%) minmax(0,1fr)}
.pane{min-height:0;min-width:0;display:flex;flex-direction:column}
.pane+.pane{border-left:1px solid var(--hair)}
.scroll{overflow:auto;min-height:0;flex:1}
.tools{display:flex;gap:8px;padding:10px 12px;border-bottom:1px solid var(--hair);flex-wrap:wrap;align-items:center}
.tools input{flex:1;min-width:140px;background:var(--terminal);border:1px solid var(--hair2);border-radius:5px;padding:7px 10px;color:var(--t1)}
.tools input::placeholder{color:var(--t4)}
.fchip{background:none;border:1px solid var(--hair);border-radius:5px;padding:5px 9px;color:var(--t3);font:500 10px/1 var(--sans);letter-spacing:.2em;text-transform:uppercase}
.fchip[aria-pressed="true"]{color:var(--t1);border-color:var(--hair2);background:var(--sel)}
/* severity: weight and opacity, never colour */
.sev{display:inline-block;min-width:62px;text-align:center;padding:3px 7px;border-radius:3px;font:500 9.5px/1.2 var(--sans);letter-spacing:.18em;text-transform:uppercase;border:1px solid transparent}
.sev.high{border-color:var(--white);color:var(--t1)}
.sev.medium{border-color:rgba(242,244,241,.5);color:var(--t2)}
.sev.muted{border-color:rgba(242,244,241,.22);color:var(--t3)}
/* queue */
.q{list-style:none;margin:0;padding:0}
.q li{display:grid;grid-template-columns:70px minmax(0,1fr) auto;gap:4px 12px;padding:12px 14px 12px 12px;border-bottom:1px solid var(--hair);border-left:2px solid transparent;cursor:pointer;align-items:center}
.q li:hover{background:rgba(255,255,255,.025)}
.q li[aria-selected="true"]{background:var(--sel);border-left-color:var(--white)}
.q li.acked .ttl{color:var(--t3)}
.q .ttl{color:var(--t1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.q .meta{grid-column:2/3;color:var(--t3);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.q .age{color:var(--t3);font-size:11px;text-align:right}
.q .st{grid-column:3;color:var(--t4);font-size:10.5px;text-align:right}
.empty{padding:30px 16px;color:var(--t3);max-width:62ch}
.empty b{color:var(--t1);font-weight:400}
.q li.empty{max-width:none}
/* detail */
.dhead{padding:16px 20px 14px;border-bottom:1px solid var(--hair)}
.dhead .r1{display:flex;gap:12px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.dhead .t{color:var(--t2);margin:8px 0 14px;max-width:78ch}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.sect{padding:16px 20px;border-bottom:1px solid var(--hair)}
.sect>.lbl{display:block;margin-bottom:12px}
.why{display:grid;grid-template-columns:130px minmax(0,1fr);gap:6px 16px;margin:0}
.why dt{color:var(--t3)}.why dd{margin:0;color:var(--t1);overflow-wrap:anywhere}
.why dd.mid{color:var(--t2)}
.reads{list-style:none;margin:0;padding:0}.reads li{margin-bottom:2px}
.tl{list-style:none;margin:0;padding:0}
.tl li{display:grid;grid-template-columns:64px 84px minmax(0,1fr) 78px;gap:10px;padding:5px 0;align-items:baseline}
.tl .p{color:var(--t3)}.tl .a{color:var(--t1);overflow-wrap:anywhere}.tl .att{text-align:right;color:var(--t3)}
.check{list-style:none;margin:0;padding:0}
.check li{padding:4px 0}
.check label{display:grid;grid-template-columns:18px minmax(0,1fr);gap:10px;align-items:baseline;cursor:pointer;color:var(--t2)}
.check input{appearance:none;-webkit-appearance:none;width:12px;height:12px;border:1px solid var(--hair2);border-radius:2px;margin:0;position:relative;top:1px;background:none;cursor:pointer}
.check input:checked{background:var(--white);border-color:var(--white)}
.check input:checked+span{color:var(--t3);text-decoration:line-through}
.stchip{display:inline-block;padding:1px 7px;border:1px solid var(--hair2);border-radius:10px;font-size:10.5px;color:var(--t2)}
.stchip.open{color:var(--t1);border-color:rgba(242,244,241,.5)}
.stchip.handled{color:var(--t3)}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:9px 12px;font:500 10px/1 var(--sans);letter-spacing:.2em;text-transform:uppercase;color:var(--t3);border-bottom:1px solid var(--hair2);position:sticky;top:0;background:var(--black);white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid var(--hair);vertical-align:top}
td.nw{white-space:nowrap}
td.ip button{background:none;border:0;padding:0;text-align:left}
td.ip button:hover{text-decoration:underline}
.viewbody{overflow:auto;flex:1;min-height:0}
.wrapx{overflow-x:auto}
.padded{padding:18px 20px}
.banner{border:1px solid var(--hair2);border-radius:8px;padding:14px 16px;margin:16px 20px 0;display:flex;gap:16px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.banner .x{color:var(--t2);max-width:84ch}
.note{color:var(--t2);max-width:84ch;margin:10px 0 0}
tr.fresh td{animation:fade 120ms linear}
@keyframes fade{from{opacity:0}to{opacity:1}}
/* palette + toast */
.ov{position:fixed;inset:0;background:rgba(5,6,6,.72);display:none;align-items:flex-start;justify-content:center;padding:12vh 16px 0;z-index:10}
.ov.on{display:flex}
.box{width:min(560px,100%);background:var(--panel);border:1px solid var(--hair2);border-radius:8px;overflow:hidden}
.box input{width:100%;background:none;border:0;border-bottom:1px solid var(--hair2);padding:14px 16px;color:var(--t1);font-size:13px}
.box input:focus-visible{outline:none}
.cmds{list-style:none;margin:0;padding:6px;max-height:320px;overflow:auto}
.cmds li{display:flex;justify-content:space-between;padding:9px 10px;border-radius:5px;color:var(--t2);cursor:pointer}
.cmds li[aria-selected="true"]{background:var(--sel);color:var(--t1)}
.cmds li .kbd{margin:0}
#toast{position:fixed;left:164px;bottom:16px;background:var(--terminal);border:1px solid var(--hair2);border-radius:5px;padding:9px 13px;color:var(--t1);opacity:0;pointer-events:none;transition:opacity 120ms linear;z-index:20;max-width:min(520px,calc(100% - 32px))}
#toast.on{opacity:1}
@media (max-width:900px){
 body{overflow:auto}
 .app{display:block;height:auto}
 .rail{flex-direction:row;overflow-x:auto;padding:0;border-right:0;border-bottom:1px solid var(--hair)}
 .rail button{width:auto;border-left:0;border-bottom:2px solid transparent;gap:10px;white-space:nowrap}
 .rail button[aria-current="page"]{border-bottom-color:var(--white);border-left-color:transparent}
 .rail .sp,.rail .foot{display:none}
 main,.view,.view.on{height:auto;overflow:visible}
 .strip{grid-template-columns:repeat(2,minmax(0,1fr))}
 .stat{border-bottom:1px solid var(--hair)}.stat:last-child{grid-column:1/-1}
 .split{display:block}
 .pane+.pane{border-left:0;border-top:1px solid var(--hair)}
 .scroll{overflow:visible}
 .q li{grid-template-columns:70px minmax(0,1fr) auto}
 .q .st{display:none}
 #toast{left:16px}
 .why{grid-template-columns:1fr;gap:2px 0}.why dd{margin-bottom:8px}
 .tl li{grid-template-columns:60px 70px minmax(0,1fr)}
 .tl .att{display:none}
 .top{gap:12px}
}
@media (prefers-reduced-motion:reduce){tr.fresh td{animation:none}#toast{transition:none}}
</style></head><body>
<template id="cmdbase"><code>lure </code></template>
<div class="app">
 <div class="sim" id="sim" hidden><b>demo</b> · every alert on this page is a pretend attack on this computer, played by the lure demo. nothing real happened and nothing left this machine.</div>

 <header class="top">
  <div class="lockup">
   <svg viewBox="0 0 80 80" fill="none" stroke="#F2F4F1" stroke-width="5" stroke-linecap="square" aria-hidden="true"><path d="M40 8H72V72H8V8H58M58 24H24V56H56V38"/></svg>
   <div><div class="name">Lure</div><div class="kick">credential tripwires</div></div>
  </div>
  <div class="site num" id="site">listener</div>
  <div class="upd" id="upd" hidden></div>
  <div class="grow"></div>
  <div class="chips" role="group" aria-label="time range" id="range">
   <button aria-pressed="false" data-r="60">1h</button>
   <button aria-pressed="true" data-r="1440">24h</button>
  </div>
  <div class="live idle" id="live"><span class="dot" aria-hidden="true">●</span><span id="livetxt">connecting</span></div>
  <button class="btn" id="testBtn">Run test</button>
  <div class="menu" id="expMenu">
   <button class="btn" id="expBtn" aria-haspopup="true" aria-expanded="false">Export</button>
   <div class="items" id="expItems" hidden><a href="/api/export?fmt=csv">Alerts as csv</a><a href="/api/export?fmt=json">Alerts as json</a></div>
  </div>
  <button class="btn" id="palBtn">Commands<kbd>ctrl k</kbd></button>
 </header>

 <nav class="rail" aria-label="views">
  <button data-v="incidents" aria-current="page">Incidents <span class="count" id="c-inc"></span></button>
  <button data-v="feed">Live feed <span class="count" id="c-feed"></span></button>
  <button data-v="baits">Baits <span class="count" id="c-bait"></span></button>
  <button data-v="integrations">Integrations</button>
  <div class="sp"></div>
  <div class="foot">j k move<br>a handle<br>g live feed<br>/ search<br>ctrl k commands<br><span class="num">v__VERSION__</span></div>
 </nav>

 <main>
  <section class="view on" id="v-incidents" aria-label="incidents">
   <div class="strip" id="strip"></div>
   <div class="chart">
    <div class="row">
     <span class="lbl" id="chartTitle">bait logins, last 24h, 30 minute buckets</span>
     <span class="legend"><span><i></i>high</span><span><i style="opacity:.45"></i>medium</span></span>
    </div>
    <svg id="chart" viewBox="0 0 960 84" preserveAspectRatio="none" role="img" aria-label="bait logins over time by severity"></svg>
   </div>
   <div class="split">
    <div class="pane">
     <div class="tools">
      <input id="q" type="search" placeholder="search   /" aria-label="search incidents">
      <button class="fchip" id="hideAck" aria-pressed="false">hide handled</button>
     </div>
     <div class="scroll"><ul class="q" id="queue" role="listbox" aria-label="incident queue"></ul></div>
    </div>
    <div class="pane"><div class="scroll" id="detail" aria-live="polite"></div></div>
   </div>
  </section>

  <section class="view" id="v-feed" aria-label="live feed">
   <div class="tools">
    <input id="fq" type="search" placeholder="filter: source, bait, user, service" aria-label="filter live feed">
    <span class="dim" id="feedInfo"></span>
   </div>
   <div class="viewbody wrapx">
    <table>
     <thead><tr><th>time</th><th>severity</th><th>source</th><th>service</th><th>user tried</th><th>bait</th><th>att&amp;ck</th><th>status</th></tr></thead>
     <tbody id="feedBody"></tbody>
    </table>
   </div>
  </section>

  <section class="view" id="v-baits" aria-label="baits">
   <div class="viewbody">
    <div class="banner" id="baitBanner"></div>
    <div class="tools" style="margin-top:16px;border-top:1px solid var(--hair)"><input id="bq" type="search" placeholder="filter baits" aria-label="filter baits"><span class="dim" id="baitInfo"></span></div>
    <div class="wrapx">
     <table>
      <thead><tr><th>state</th><th>bait file</th><th>logins tried</th><th>belongs on</th><th>planted at</th></tr></thead>
      <tbody id="baitBody"></tbody>
     </table>
    </div>
    <div class="padded dim">a bait is a file holding a login that no real person uses. lure alerts when the login is tried at its listener, not when the file is opened.</div>
   </div>
  </section>

  <section class="view" id="v-integrations" aria-label="integrations">
   <div class="viewbody">
    <div class="padded">
     <span class="lbl">alert destinations</span>
     <p class="note">every alert also appears on this page and in the alert log. destinations are set when the listener starts. lure sends to them only what you configure, and nothing else leaves this machine.</p>
    </div>
    <div class="wrapx"><table>
     <thead><tr><th>destination</th><th>state</th><th>sends to</th><th>to turn on, start the listener with</th></tr></thead>
     <tbody id="destBody"></tbody>
    </table></div>
   </div>
  </section>
 </main>
</div>

<div class="ov" id="pal" role="dialog" aria-modal="true" aria-label="commands">
 <div class="box">
  <input id="palIn" placeholder="type a command" aria-label="command">
  <ul class="cmds" id="cmds" role="listbox"></ul>
 </div>
</div>
<div id="toast" role="status"></div>

<script>
(function(){
'use strict';
var $=function(id){return document.getElementById(id);};
var BASE=(($('cmdbase').content.textContent)||'lure ').replace(/^\s+/,'');
var UPDATE_CMD='lure update';
var SVC={http:'web login',rdp:'rdp',openvpn:'vpn'};
var S={view:'incidents',sel:0,src:null,q:'',hideAck:false,range:1440,fq:'',bq:'',checks:{},sig:'',st:null,ok:false};

function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=String(x);return e;}
function add(p){for(var i=1;i<arguments.length;i++){var c=arguments[i];if(c==null)continue;p.appendChild(typeof c==='string'?document.createTextNode(c):c);}return p;}
function clear(n){while(n.firstChild)n.removeChild(n.firstChild);return n;}
function svc(s){return SVC[s]||String(s||'');}
function ms(t){var v=Date.parse(t);return isNaN(v)?null:v;}
function ago(t){var v=ms(t);if(v==null)return 'never';var m=Math.max(0,Math.round((Date.now()-v)/60000));if(m<1)return 'now';if(m<60)return m+'m';if(m<1440){var h=Math.floor(m/60),r=m%60;return h+'h'+(r?(r<10?'0':'')+r+'m':'');}return Math.floor(m/1440)+'d';}
function clock(t){var v=ms(t);if(v==null)return '';var d=new Date(v);return d.toTimeString().slice(0,8);}
function plural(n,w){return n+' '+w+(n===1?'':'s');}
function uniq(a){var o=[];a.forEach(function(x){if(o.indexOf(x)<0)o.push(x);});return o;}
function toast(m){var t=$('toast');t.textContent=m;t.classList.add('on');clearTimeout(toast.h);toast.h=setTimeout(function(){t.classList.remove('on');},3600);}
function sevTag(sev,state){var cls=state?'muted':(sev==='high'?'high':'medium');return el('span','sev '+cls,state||(sev==='high'?'high':'medium'));}
function from(i){var f=String(i.from||'');return f.indexOf(i.source)>=0?'':f;}
function incState(i){return i.handled?'handled':(i.demo?'demo':'');}
function services(i){return uniq(i.steps.map(function(s){return svc(s.service);}));}
function headline(i){var sv=services(i);
 if(i.baits>1)return 'same source used '+i.baits+' baits: '+sv.join(', ');
 var b=(i.steps[0]||{}).bait;return 'bait login tried over '+sv.join(', ')+(b?': '+b:'');}
function summary(i){var b=uniq(i.steps.map(function(s){return s.bait||'listener';}));return plural(i.steps.length,'login')+' · '+b.slice(0,2).join(', ')+(b.length>2?' and '+(b.length-2)+' more':'');}

/* ---------- queue ---------- */
function incidents(){return (S.st&&S.st.incidents)||[];}
function visible(){var q=S.q.trim().toLowerCase();return incidents().filter(function(i){
 if(S.hideAck&&i.handled)return false;if(!q)return true;
 var hay=[i.source,i.from,i.severity,services(i).join(' ')].concat(i.steps.map(function(s){return (s.bait||'')+' '+(s.attack||'');})).join(' ').toLowerCase();
 return hay.indexOf(q)>=0;});}
function renderQueue(){
 var list=visible(),qn=$('queue');
 if(S.src){var k=list.map(function(i){return i.source;}).indexOf(S.src);if(k>=0)S.sel=k;}
 if(S.sel>=list.length)S.sel=Math.max(0,list.length-1);
 clear(qn);
 if(!list.length){var li=el('li','empty');li.style.display='block';li.style.cursor='default';li.textContent=incidents().length?'no incidents match.':'no incidents.';qn.appendChild(li);renderDetail(null);return;}
 list.forEach(function(i,n){
  var li=el('li',i.handled?'acked':'');li.setAttribute('role','option');li.setAttribute('aria-selected',n===S.sel?'true':'false');li.dataset.n=n;li.tabIndex=n===S.sel?0:-1;
  add(li,add(el('span'),sevTag(i.severity,incState(i))),el('span','ttl',i.source+(from(i)?' · '+from(i):'')),el('span','age num',ago(i.last)),el('span','meta',summary(i)),el('span','st',i.handled?'handled':(i.demo?'demo':'open')));
  qn.appendChild(li);});
 var cur=list[S.sel];S.src=cur?cur.source:null;renderDetail(cur);}

/* ---------- detail ---------- */
function dl(rows){var d=el('dl','why');rows.forEach(function(r){d.appendChild(el('dt',null,r[0]));var dd=r[1] instanceof Node?add(el('dd',r[2]||null),r[1]):el('dd',r[2]||null,r[1]);d.appendChild(dd);});return d;}
function sect(label,body){return add(el('div','sect'),el('span','lbl',label),body);}
function renderDetail(i){
 var box=$('detail');
 var sig=Math.floor(Date.now()/60000)+'|'+(i?JSON.stringify(i):('none'+(S.st&&S.st.listening?S.st.listening.listener:'')+incidents().length));
 if(sig===S.sig)return;S.sig=sig;var same=S.dsrc===(i&&i.source),keep=same?box.scrollTop:0;S.dsrc=i&&i.source;clear(box);
 if(!i){var lst=(S.st&&S.st.listening&&S.st.listening.listener)||'its listener';
  var e=el('div','empty');
  if(incidents().length)add(e,'select an incident.');
  else add(e,el('b',null,'No incidents.'),' Lure is listening on ',el('span','num',lst),'. Run test to see one.');
  box.appendChild(e);return;}
 var h=el('div','dhead'),r1=el('div','r1');
 add(r1,sevTag(i.severity,incState(i)),el('span','lbl','bait credential used'),el('span','num',i.source),from(i)?el('span','dim',from(i)):null);
 var t=el('p','t num');
 add(t,'first seen '+clock(i.first)+' ('+ago(i.first)+' ago) · last seen '+clock(i.last)+' ('+ago(i.last)+' ago) · '+plural(i.steps.length,'login')+' · '+plural(i.baits,'bait')+' · ',el('span','stchip '+(i.handled?'handled':'open'),i.handled?'handled':'open'));
 var acts=el('div','actions'),hb=el('button','btn solid');hb.dataset.a='handle';
 if(i.handled){hb.textContent='Handled';hb.disabled=true;}else add(hb,'Handle',el('kbd',null,'a'));
 var cb=el('button','btn','Copy source');cb.dataset.a='copy';
 var fb=add(el('button','btn'),'Show in feed',el('kbd',null,'g'));fb.dataset.a='feed';
 var xb=el('a','btn','Export');xb.href='/api/export?fmt=csv';
 add(acts,hb,cb,fb,xb);
 add(h,r1,el('h2','h',headline(i)),t,acts);box.appendChild(h);
 var reads=el('ul','reads');i.steps.forEach(function(s){reads.appendChild(el('li',null,s.how||''));});
 box.appendChild(sect('why this was flagged',dl([
  ['rule','a bait credential was used. no real person or system holds these logins, so any use is a signal.'],
  ['method','deterministic match on the login name. no model in the loop. the same login gives the same verdict.'],
  ['read',reads]])));
 var tl=el('ul','tl');i.steps.slice().sort(function(a,b){return (ms(b.time)||0)-(ms(a.time)||0);}).forEach(function(s){
  add(tl,add(el('li'),el('span','num dim',clock(s.time)),el('span','p',svc(s.service)),el('span','a',s.bait||'listener'),el('span','att num',s.attack||'')));});
 box.appendChild(sect('timeline, newest first',tl));
 var baits=uniq(i.steps.map(function(s){return s.bait||'listener';}));
 box.appendChild(sect('impact',dl([
  ['who',i.who||i.source],
  ['baits taken',baits.join(', ')],
  ['logins tried',plural(i.steps.length,'login')+' over '+services(i).join(', ')+'. the listener refused every one.'],
  ['cannot tell you','Lure sees only logins that reach its listener. It cannot say what else this source did.','mid']])));
 var ul=el('ul','check');(i.next||[]).forEach(function(n,k){var key=i.source+'|'+k,lb=el('label'),c=el('input');c.type='checkbox';c.checked=!!S.checks[key];
  c.onchange=function(){S.checks[key]=c.checked;};add(ul,add(el('li'),add(lb,c,el('span',null,n))));});
 var tick=el('div','dim','ticks stay on this page only and are not saved.');tick.style.marginTop='10px';
 box.appendChild(sect('what to do',add(el('div'),ul,tick)));
 box.appendChild(sect('handling',dl([
  ['status',el('span','stchip '+(i.handled?'handled':'open'),i.handled?'handled':'open')],
  ['alerts',plural((i.ids||[]).length,'alert')+' from this source'],
  ['handled means','the alerts are marked as seen in the alert log. it does not block the source or change anything on the network.','mid']])));
 box.scrollTop=keep;}

/* ---------- strip + chart ---------- */
function renderStrip(){
 var st=S.st||{},inc=incidents(),open=inc.filter(function(i){return !i.handled;}),al=st.alerts||[],files=st.files||[];
 var srcs=uniq(al.map(function(a){return String(a.source||'').replace(/:\d+$/,'');}));
 var taken=files.filter(function(f){return f.used;}).length,last=null;al.forEach(function(a){if(ms(a.time)!=null&&(last==null||ms(a.time)>ms(last)))last=a.time;});
 var cells=[['open incidents',open.length,open.length?(open.some(function(i){return i.severity==='high';})?'highest high':'highest medium'):(inc.length?'all handled':'none so far')],
  ['bait logins used',al.length,'since '+(st.since?clock(st.since):'start')],
  ['unique sources',srcs.length,srcs.length===1?'one address':'addresses seen'],
  ['baits taken',taken+' of '+files.length,'files with a login tried'],
  ['last event',last?ago(last):'none',last?clock(last):'nothing yet']];
 var s=clear($('strip'));cells.forEach(function(c){add(s,add(el('div','stat'),el('div','lbl',c[0]),el('div','v num',c[1]),el('div','s',c[2])));});}
var NS='http://www.w3.org/2000/svg';
function sv(n,a){var e=document.createElementNS(NS,n);for(var k in a)e.setAttribute(k,a[k]);return e;}
function renderChart(){
 var al=(S.st&&S.st.alerts)||[],range=S.range,n=range===60?30:48,size=range/n,b=[],k;
 for(k=0;k<n;k++)b.push({high:0,medium:0});
 al.forEach(function(a){var v=ms(a.time);if(v==null)return;var m=(Date.now()-v)/60000;if(m>range||m<0)return;var idx=n-1-Math.min(n-1,Math.floor(m/size));b[idx][a.severity==='high'?'high':'medium']++;});
 var max=1;b.forEach(function(x){max=Math.max(max,x.high+x.medium);});
 var W=960,base=66,top=6,bw=W/n,svg=clear($('chart'));
 [0.5,1].forEach(function(f){var y=base-(base-top)*f;svg.appendChild(sv('line',{x1:0,x2:W,y1:y,y2:y,stroke:'#F2F4F1','stroke-opacity':.07}));});
 svg.appendChild(sv('line',{x1:0,x2:W,y1:base,y2:base,stroke:'#F2F4F1','stroke-opacity':.14}));
 b.forEach(function(x,idx){var y=base;[['medium',.45],['high',1]].forEach(function(p){var c=x[p[0]];if(!c)return;var h=(base-top)*c/max;y-=h;
  svg.appendChild(sv('rect',{x:idx*bw+2,y:y,width:bw-4,height:Math.max(1,h-1),fill:'#F2F4F1','fill-opacity':p[1]}));});});
 var l=range===60?['-60m','-45m','-30m','-15m','now']:['-24h','-18h','-12h','-6h','now'];
 l.forEach(function(t,k){var tx=sv('text',{x:k*(W-1)/4,y:80,'font-family':'IBM Plex Mono, monospace','font-size':10,fill:'#F2F4F1','fill-opacity':.56,'text-anchor':k===0?'start':(k===4?'end':'middle')});tx.textContent=t;svg.appendChild(tx);});
 svg.appendChild(sv('line',{x1:W-1,x2:W-1,y1:top,y2:base,stroke:'#F2F4F1','stroke-opacity':.5}));
 $('chartTitle').textContent='bait logins, last '+(range===60?'hour, 2 minute':'24h, 30 minute')+' buckets · peak '+(al.length?max:0)+' per bucket';}

/* ---------- feed ---------- */
function renderFeed(){
 var al=(S.st&&S.st.alerts)||[],q=S.fq.trim().toLowerCase(),tb=clear($('feedBody'));
 var list=al.filter(function(a){if(!q)return true;return [a.source,a.username,a.bait_file,a.service,svc(a.service),(a.explain||{}).attack].join(' ').toLowerCase().indexOf(q)>=0;});
 $('feedInfo').textContent=list.length+' of '+plural(al.length,'alert');
 if(!list.length){var r=el('tr'),c=el('td','dim',al.length?'no alerts match.':'no alerts yet. a bait login appears here the moment it reaches the listener.');c.colSpan=8;tb.appendChild(add(r,c));return;}
 list.slice(0,500).forEach(function(a){var x=a.explain||{},r=el('tr');
  var ip=String(a.source||'').replace(/:\d+$/,''),ipb=el('button','num',a.source);ipb.title='filter to this source';ipb.onclick=function(){S.fq=ip;$('fq').value=ip;renderFeed();};
  add(r,el('td','num dim nw',clock(a.time)),add(el('td'),sevTag(a.severity,a.demo?'demo':'')),add(el('td','ip nw'),ipb),el('td','nw',svc(a.service)),el('td',null,a.username),el('td',null,a.bait_file||'listener'),el('td','num dim nw',x.attack||''),el('td','dim nw',a.acknowledged?'handled':'open'));
  tb.appendChild(r);});}

/* ---------- baits ---------- */
function renderBaits(){
 var st=S.st||{},files=st.files||[],L=st.listening||{},p=L.ports||{},q=S.bq.trim().toLowerCase();
 var ports=[];if(p.rdp)ports.push('rdp '+p.rdp);if(p.http)ports.push('web login '+p.http);if(p.openvpn&&p.openvpn.length)ports.push('vpn '+p.openvpn.join(', '));
 var bn=clear($('baitBanner'));add(bn,add(el('div','x'),el('span','lbl','listener'),add(el('div',null),el('span','num',(L.listener||'unknown')+(ports.length?' · '+ports.join(' · '):'')))),
  add(el('div','dim num'),plural(files.length,'bait file')+' · '+plural((st.baits||[]).length,'login')+(st.profile?' · profile '+st.profile:'')));
 var tb=clear($('baitBody'));
 var list=files.filter(function(f){return !q||[f.file,f.plant_on,f.location].join(' ').toLowerCase().indexOf(q)>=0;});
 $('baitInfo').textContent=list.length+' of '+files.length;
 if(!list.length){var r=el('tr'),c=el('td','dim','no baits match.');c.colSpan=5;tb.appendChild(add(r,c));return;}
 list.forEach(function(f){var stt=f.used?'taken':(f.retired?'retired':'armed');
  add(tb,add(el('tr'),add(el('td','nw'),el('span','sev '+(f.used?'high':'muted'),stt)),el('td',null,f.file),el('td','num',f.logins),el('td','mid',f.plant_on||''),el('td','dim',f.location||'not recorded')));});}

/* ---------- integrations ---------- */
function renderDest(){
 var ch=(S.st&&S.st.channels)||{},tb=clear($('destBody'));
 [['this console',true,'this page, on this machine',null],
  ['desktop popup',!!ch.desktop,'a notification on this computer','--desktop'],
  ['email',!!ch.email,ch.email||'your inbox, over smtp with an app password','--email-to you@example.com'],
  ['webhook',!!ch.webhook,ch.webhook||'ntfy, telegram, discord, slack or teams','--webhook https://ntfy.sh/your-topic'],
  ['syslog',!!ch.syslog,ch.syslog?'your collector':'your siem collector','--syslog 10.0.0.5:514'],
  ['ai agents',null,'an mcp client reads alerts and manages baits','mcp']]
 .forEach(function(d){var cmd=d[3]?(d[3]==='mcp'?BASE+'mcp':BASE+'listen ... '+d[3]):'';
  var stt=d[1]===null?'separate':(d[1]?'on':'off');
  add(tb,add(el('tr'),el('td','nw',d[0]),add(el('td','nw'),el('span','stchip '+(d[1]?'open':'handled'),stt)),el('td','mid',d[2]),add(el('td'),d[1]?el('span','dim','already on'):el('code',null,cmd))));});}

/* ---------- top ---------- */
function renderTop(){
 var st=S.st||{},L=st.listening||{},p=L.ports||{},inc=incidents();
 $('sim').hidden=!st.demo;
 var parts=['listener '+(L.listener||'unknown')];if(p.rdp)parts.push('rdp '+p.rdp);if(p.http)parts.push('web '+p.http);if(p.openvpn&&p.openvpn.length)parts.push('vpn '+p.openvpn[0]);
 if(st.demo)parts.push('demo data');
 $('site').textContent=parts.join(' · ');
 var lv=$('live');lv.classList.toggle('idle',!S.ok);$('livetxt').textContent=S.ok?'live · listening':'not reachable';
 var u=clear($('upd'));u.hidden=!st.update;if(st.update)add(u,el('b',null,'update '+st.update),' · run ',el('code',null,UPDATE_CMD),' to review. nothing installs without your approval.');
 $('testBtn').disabled=!!st.demo;$('testBtn').title=st.demo?'not available in the demo':'fire one real bait login at the listener';
 $('c-inc').textContent=inc.filter(function(i){return !i.handled;}).length;
 $('c-feed').textContent=(st.alerts||[]).length;$('c-bait').textContent=(st.files||[]).length;}

function renderAll(){renderTop();renderStrip();renderChart();renderQueue();if(S.view==='feed')renderFeed();if(S.view==='baits')renderBaits();if(S.view==='integrations')renderDest();}

/* ---------- data ---------- */
function load(){return fetch('/api/state',{cache:'no-store'}).then(function(r){if(!r.ok)throw 0;return r.json();}).then(function(st){S.st=st;S.ok=true;renderAll();return st;}).catch(function(){S.ok=false;renderTop();});}
function post(p,b){return fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});}

/* ---------- actions ---------- */
function cur(){return visible()[S.sel];}
function act(a){var i=cur();if(!i)return;
 if(a==='handle'){if(i.handled)return;post('/api/ack',{ids:i.ids}).then(function(r){if(!r.ok)throw 0;toast('incident from '+i.source+' marked handled.');load();}).catch(function(){toast('could not mark handled. the listener did not accept it.');});}
 if(a==='feed'){S.fq=i.source;$('fq').value=i.source;setView('feed');}
 if(a==='copy'){var done=function(){toast('copied '+i.source);},fail=function(){toast('copy blocked here. source is '+i.source);};
  try{navigator.clipboard.writeText(i.source).then(done,fail);}catch(e){fail();}}}
function runTest(){var b=$('testBtn');if(b.disabled)return;var before=((S.st||{}).alerts||[]).length,t0=Date.now();b.disabled=true;b.textContent='Testing';
 post('/api/test').then(function(r){if(!r.ok)throw r.status;var iv=setInterval(function(){load().then(function(st){
  if(st&&(st.alerts||[]).length>before){clearInterval(iv);toast('test login detected in '+((Date.now()-t0)/1000).toFixed(1)+' s.');done();}
  else if(Date.now()-t0>10000){clearInterval(iv);toast('no new alert in 10 s. a repeat within 10 minutes is merged into the earlier alert.');done();}});},700);})
 .catch(function(){toast('run test is not available here.');done();});
 function done(){b.textContent='Run test';b.disabled=!!(S.st&&S.st.demo);}}

function setView(v){S.view=v;
 document.querySelectorAll('.view').forEach(function(e){e.classList.toggle('on',e.id==='v-'+v);});
 document.querySelectorAll('.rail button').forEach(function(b){if(b.dataset.v===v)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});
 if(location.hash!=='#'+v)history.replaceState(null,'','#'+v);
 renderAll();}
function setRange(r){S.range=r;document.querySelectorAll('#range button').forEach(function(b){b.setAttribute('aria-pressed',+b.dataset.r===r?'true':'false');});renderChart();}

/* ---------- palette ---------- */
var CMDS=[['Go to incidents','i',function(){setView('incidents');}],['Go to live feed','g',function(){setView('feed');}],['Go to baits','',function(){setView('baits');}],['Go to integrations','',function(){setView('integrations');}],
 ['Handle selected incident','a',function(){setView('incidents');act('handle');}],['Copy source of selected incident','',function(){act('copy');}],['Run test','',runTest],
 ['Export alerts as csv','',function(){location.href='/api/export?fmt=csv';}],['Export alerts as json','',function(){location.href='/api/export?fmt=json';}],
 ['Range: last hour','',function(){setRange(60);}],['Range: last 24 hours','',function(){setRange(1440);}]];
var pSel=0,pList=CMDS;
function palRender(){var u=clear($('cmds'));if(!pList.length){u.appendChild(el('li',null,'no match'));return;}
 pList.forEach(function(c,n){var li=el('li');li.setAttribute('role','option');li.setAttribute('aria-selected',n===pSel?'true':'false');li.dataset.n=n;add(li,el('span',null,c[0]));if(c[1])li.appendChild(el('span','kbd',c[1]));u.appendChild(li);});}
function palOpen(){$('pal').classList.add('on');$('palIn').value='';pList=CMDS;pSel=0;palRender();$('palIn').focus();}
function palClose(){if(!$('pal').classList.contains('on'))return;$('pal').classList.remove('on');$('palBtn').focus();}
function palRun(n){var c=pList[n];if(!c)return;palClose();c[2]();}

/* ---------- wiring ---------- */
document.querySelectorAll('.rail button').forEach(function(b){b.onclick=function(){setView(b.dataset.v);};});
document.querySelectorAll('#range button').forEach(function(b){b.onclick=function(){setRange(+b.dataset.r);};});
$('hideAck').onclick=function(){S.hideAck=!S.hideAck;this.setAttribute('aria-pressed',S.hideAck?'true':'false');S.src=null;S.sel=0;renderQueue();};
$('q').oninput=function(){S.q=this.value;S.src=null;S.sel=0;renderQueue();};
$('fq').oninput=function(){S.fq=this.value;renderFeed();};
$('bq').oninput=function(){S.bq=this.value;renderBaits();};
$('queue').onclick=function(e){var li=e.target.closest('li[data-n]');if(!li)return;S.sel=+li.dataset.n;S.src=null;renderQueue();var s=$('queue').querySelector('[aria-selected="true"]');if(s)s.focus();};
$('detail').onclick=function(e){var b=e.target.closest('button[data-a]');if(b)act(b.dataset.a);};
$('testBtn').onclick=runTest;
$('palBtn').onclick=palOpen;
$('expBtn').onclick=function(){var it=$('expItems'),o=it.hidden;it.hidden=!o;this.setAttribute('aria-expanded',o?'true':'false');if(o)it.querySelector('a').focus();};
document.addEventListener('click',function(e){if(!$('expMenu').contains(e.target)){$('expItems').hidden=true;$('expBtn').setAttribute('aria-expanded','false');}});
$('pal').onclick=function(e){if(e.target===this)palClose();};
$('palIn').oninput=function(){var q=this.value.trim().toLowerCase();pList=CMDS.filter(function(c){return c[0].toLowerCase().indexOf(q)>=0;});pSel=0;palRender();};
$('cmds').onclick=function(e){var li=e.target.closest('li[data-n]');if(li)palRun(+li.dataset.n);};
$('palIn').onkeydown=function(e){if(e.key==='ArrowDown'){pSel=Math.min(pList.length-1,pSel+1);palRender();e.preventDefault();}else if(e.key==='ArrowUp'){pSel=Math.max(0,pSel-1);palRender();e.preventDefault();}else if(e.key==='Enter')palRun(pSel);};
function move(d){var l=visible();if(!l.length)return;S.sel=Math.max(0,Math.min(l.length-1,S.sel+d));S.src=null;renderQueue();var s=$('queue').querySelector('[aria-selected="true"]');if(s){s.focus();s.scrollIntoView({block:'nearest'});}}
document.addEventListener('keydown',function(e){
 if(e.key==='Escape'){palClose();$('expItems').hidden=true;return;}
 if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();palOpen();return;}
 var tag=(e.target.tagName||'').toLowerCase();if(tag==='input'||e.ctrlKey||e.metaKey||e.altKey)return;
 if($('pal').classList.contains('on'))return;
 if(e.key==='/'){e.preventDefault();setView('incidents');$('q').focus();}
 else if((e.key==='j'||e.key==='ArrowDown')&&S.view==='incidents'){e.preventDefault();move(1);}
 else if((e.key==='k'||e.key==='ArrowUp')&&S.view==='incidents'){e.preventDefault();move(-1);}
 else if(e.key==='a'&&S.view==='incidents')act('handle');
 else if(e.key==='g'){if(S.view==='incidents'&&cur())act('feed');else setView('feed');}
 else if(e.key==='i')setView('incidents');});
var h=location.hash.slice(1);if(['incidents','feed','baits','integrations'].indexOf(h)>=0)S.view=h;
setView(S.view);
load();setInterval(load,3000);setInterval(function(){if(S.st){renderStrip();renderChart();}},30000);
})();
</script></body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    alerter = None
    tester = None
    allowed_origins = ()

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype, cache="no-store"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            from .init import cmd
            base = cmd("")
            page = PAGE.replace("<code>lure ", "<code>" + base).replace("'lure update'", "'" + base + "update'")
            self._send(200, page.replace("__VERSION__", __version__).replace("__MARK__", MARK_PNG_B64), "text/html; charset=utf-8")
        elif self.path.startswith("/fonts/"):
            name = self.path[len("/fonts/"):]
            if name not in FONTS:
                return self._send(404, "not found", "text/plain")
            with open(os.path.join(_FONT_DIR, name), "rb") as fh:
                self._send(200, fh.read(), "font/woff2", cache="public, max-age=86400")
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
