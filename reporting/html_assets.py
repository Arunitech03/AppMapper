"""Static CSS + JS assets for the HTML report — professional consulting design system."""

# ruff: noqa: E501  -- CSS/JS rule lines read better unwrapped.

from __future__ import annotations

CSS = """
:root{
 --bg:#FFFFFF; --fg:#0F172A; --muted:#475569; --line:#E2E8F0; --card:#F8FAFC;
 --accent:#2563EB; --auth:#9333EA; --radius:12px;
 --crit-bg:#FEE2E2; --crit:#B91C1C; --high-bg:#FFEDD5; --high:#EA580C;
 --med-bg:#FEF3C7; --med:#D97706; --low-bg:#DBEAFE; --low:#2563EB;
 --info-bg:#F1F5F9; --info:#64748B; --pos-bg:#DCFCE7; --pos:#15803D;
 --teal:#0D9488; --purple:#9333EA; --orange:#EA580C; --amber:#D97706; --gray:#64748B; --blue:#2563EB; --red:#DC2626;
 --hover:#EFF6FF;
}
[data-theme=dark]{
 --bg:#0F172A; --fg:#F8FAFC; --muted:#94A3B8; --line:#334155; --card:#1E293B;
 --accent:#60A5FA; --hover:#334155;
 --crit-bg:#3b1417; --high-bg:#3a230f; --med-bg:#332805; --low-bg:#102447; --info-bg:#1b2230; --pos-bg:#0f2a1a;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{font:15px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
 margin:0;background:var(--bg);color:var(--fg)}
a{color:var(--accent);text-decoration:none}
.layout{display:grid;grid-template-columns:248px minmax(0,1fr);gap:0;align-items:start}
/* Sidebar */
nav.side{position:sticky;top:0;height:100vh;overflow:auto;padding:1.4rem 1rem;
 border-right:1px solid var(--line);background:var(--card);font-size:14px}
nav.side .brand{font-weight:700;font-size:15px;margin-bottom:1rem;color:var(--fg)}
nav.side h4{margin:1rem 0 .35rem;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
 color:var(--muted);border-top:1px solid var(--line);padding-top:.8rem}
nav.side h4:first-of-type{border-top:none;padding-top:0}
nav.side a{display:block;padding:5px 10px;border-radius:8px;color:var(--muted);margin:1px 0}
nav.side a:hover{background:var(--hover);color:var(--fg)}
nav.side a.active{background:var(--accent);color:#fff}
main{padding:2rem 2.4rem;max-width:1120px}
main>section,main>div.evidence-divider{margin-bottom:32px}
h1{font-size:1.8rem;font-weight:700;border-bottom:2px solid var(--line);padding-bottom:.4em;margin:.2em 0 .8em}
main h2,details.ev>summary.sec{font-size:1.3rem;font-weight:700;margin:0 0 .8em;padding-bottom:.3em;border-bottom:1px solid var(--line)}
h3{font-size:1.05rem;margin:1.2em 0 .5em}
p{color:var(--fg)}
.muted{color:var(--muted)}
.toolbar{display:flex;gap:.5rem;align-items:center;margin:.4rem 0 1.5rem;flex-wrap:wrap}
.btn{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;padding:6px 14px;font-size:13px;cursor:pointer;font-weight:500}
.btn:hover{background:var(--hover)}
code{background:var(--info-bg);padding:1px 5px;border-radius:4px;font-size:.92em}
pre{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:16px;overflow:auto;line-height:1.5}
pre code{background:none;padding:0;font-size:13.5px}
ul{padding-left:1.3em}
/* Tables */
.tablewrap{border:1px solid var(--line);border-radius:var(--radius);overflow:auto;margin:1em 0;max-height:none}
table{border-collapse:collapse;width:100%;font-size:14px;background:var(--bg)}
thead th{position:sticky;top:0;background:#0F172A;color:#fff;text-align:left;padding:9px 12px;font-weight:600;z-index:1}
td{padding:8px 12px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:nth-child(even){background:var(--card)}
tbody tr:hover{background:var(--hover)}
/* KPI cards */
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin:1rem 0}
.kpi{border:1px solid var(--line);border-left:5px solid var(--gray);border-radius:var(--radius);padding:16px;background:var(--card)}
.kpi .v{font-size:1.9rem;font-weight:800;line-height:1;color:var(--fg)}
.kpi .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.45rem;font-weight:600}
.kpi.blue{border-left-color:var(--blue);background:#EFF6FF}
.kpi.teal{border-left-color:var(--teal);background:#F0FDFA}
.kpi.purple{border-left-color:var(--purple);background:#FAF5FF}
.kpi.orange{border-left-color:var(--orange);background:#FFF7ED}
.kpi.red{border-left-color:var(--red);background:#FEF2F2}
.kpi.amber{border-left-color:var(--amber);background:#FFFBEB}
.kpi.gray{border-left-color:var(--gray);background:var(--card)}
[data-theme=dark] .kpi{background:var(--card)!important}
/* Auth cards (purple accent) */
.authcards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.9rem;margin:1rem 0}
.authcard{border:1px solid var(--line);border-top:4px solid var(--auth);border-radius:var(--radius);padding:14px;background:var(--card)}
.authcard .v{font-size:1.3rem;font-weight:700}
.authcard .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.3rem;font-weight:600}
/* Identity card */
.idcard{border:1px solid var(--line);border-left:5px solid var(--auth);border-radius:var(--radius);padding:16px;background:var(--card);max-width:480px}
.idcard .row{display:flex;justify-content:space-between;padding:5px 0;border-top:1px solid var(--line)}
.idcard .row:first-child{border-top:none}
.idcard .k{color:var(--muted);font-size:13px}
.idcard .val{font-weight:600}
/* Alert / callout panels */
.panel{border:1px solid var(--line);border-left:5px solid var(--info);border-radius:var(--radius);padding:14px 16px;margin:.8rem 0;background:var(--info-bg)}
.panel .title{font-weight:700;margin-bottom:.3rem}
.panel .meta{font-size:13.5px;margin:.15rem 0;color:var(--fg)}
.panel.sev-critical{border-left-color:var(--crit);background:var(--crit-bg)}
.panel.sev-high{border-left-color:var(--high);background:var(--high-bg)}
.panel.sev-medium{border-left-color:var(--med);background:var(--med-bg)}
.panel.sev-low{border-left-color:var(--low);background:var(--low-bg)}
.panel.sev-info{border-left-color:var(--info);background:var(--info-bg)}
/* Severity + status badges */
.sev,.badge{display:inline-block;border-radius:8px;padding:1px 9px;font-size:12px;font-weight:700;white-space:nowrap}
.sev-critical{background:var(--crit-bg);color:var(--crit)}
.sev-high{background:var(--high-bg);color:var(--high)}
.sev-medium{background:var(--med-bg);color:var(--med)}
.sev-low{background:var(--low-bg);color:var(--low)}
.sev-info{background:var(--info-bg);color:var(--info)}
.b-observed,.b-internal,.b-positive{background:var(--pos-bg);color:var(--pos)}
.b-referenced{background:var(--med-bg);color:var(--med)}
.b-hidden,.b-admin{background:var(--crit-bg);color:var(--crit)}
.b-write{background:var(--high-bg);color:var(--high)}
.b-read{background:var(--low-bg);color:var(--low)}
.b-thirdparty,.b-runtime{background:var(--info-bg);color:var(--info)}
/* Service cards */
.svccards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem;margin:1rem 0}
.svccard{border:1px solid var(--line);border-radius:var(--radius);padding:14px;background:var(--card)}
.svccard .name{font-weight:700;font-size:1.02rem}
.svccard .meta{font-size:13px;color:var(--muted);margin:.25rem 0;word-break:break-all}
.svccard .badges{margin-top:.5rem;display:flex;gap:.4rem;flex-wrap:wrap}
/* Pentest Prioritization Matrix */
.pbadge{display:inline-block;border-radius:8px;padding:1px 9px;font-size:12px;font-weight:700;white-space:nowrap}
.pbadge.p1{background:var(--crit-bg);color:var(--crit)}
.pbadge.p2{background:var(--high-bg);color:var(--high)}
.pbadge.p3{background:var(--med-bg);color:var(--med)}
tbody tr.p1{box-shadow:inset 4px 0 0 var(--crit)}
tbody tr.p2{box-shadow:inset 4px 0 0 var(--high)}
tbody tr.p3{box-shadow:inset 4px 0 0 var(--med)}
/* Architecture snapshot — coloured outline boxes + arrows */
.flow{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;margin:1rem 0}
.flow .node{border:2px solid var(--accent);color:var(--accent);background:transparent;border-radius:10px;padding:.55rem .9rem;font-weight:600;font-size:14px}
.flow .arr{color:var(--muted);font-weight:800;font-size:1.1rem}
.flow .node.n-blue{border-color:var(--blue);color:var(--blue)}
.flow .node.n-purple{border-color:var(--auth);color:var(--auth)}
.flow .node.n-teal{border-color:var(--teal);color:var(--teal)}
.flow .node.n-green{border-color:var(--pos);color:var(--pos)}
.flow .node.n-gray{border-color:var(--gray);color:var(--gray)}
/* Tier headers (secrets) */
.tier{font-weight:700;margin:1rem 0 .4rem;padding:.3rem .7rem;border-radius:8px;display:inline-block}
.tier.high{background:var(--crit-bg);color:var(--crit)}
.tier.medium{background:var(--med-bg);color:var(--med)}
.tier.info{background:var(--info-bg);color:var(--info)}
/* Evidence */
.evidence-divider{margin:2.4rem 0 1rem;padding:.6rem 0;border-top:2px dashed var(--line);color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.08em;font-weight:600}
details.ev{border:1px solid var(--line);border-radius:var(--radius);margin:.6rem 0;background:var(--card)}
details.ev>summary{cursor:pointer;padding:.7rem 1rem;font-weight:600;list-style:none}
details.ev>summary::-webkit-details-marker{display:none}
details.ev>summary::before{content:'▶ ';color:var(--muted)}
details.ev[open]>summary::before{content:'▼ '}
details.ev>summary:hover{background:var(--hover)}
details.ev .body{padding:0 1rem .8rem}
details.role{border:1px solid var(--line);border-radius:8px;margin:.4rem 0;background:var(--bg)}
details.role>summary{cursor:pointer;padding:.5rem .8rem;font-weight:600}
@media(max-width:860px){.layout{grid-template-columns:1fr}nav.side{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line)}}
@media print{
 nav.side,.toolbar{display:none}
 .layout{grid-template-columns:1fr}
 main{max-width:none;padding:0}
 thead{display:table-header-group}
 .kpi,.authcard,.svccard,.panel,.idcard,tr{break-inside:avoid}
 details.ev>.body{display:block!important}
 *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""

JS = """
function _setEv(open){document.querySelectorAll('details.ev,details.role').forEach(function(d){d.open=open;});}
function expandAll(){_setEv(true);}
function collapseAll(){_setEv(false);}
function toggleTheme(){var r=document.documentElement;r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';}
// Scroll-spy: highlight the sidebar link of the section currently in view.
window.addEventListener('DOMContentLoaded',function(){
 var links={};document.querySelectorAll('nav.side a[href^="#"]').forEach(function(a){links[a.getAttribute('href').slice(1)]=a;});
 var obs=new IntersectionObserver(function(entries){
   entries.forEach(function(e){
     if(e.isIntersecting){
       Object.values(links).forEach(function(a){a.classList.remove('active');});
       var a=links[e.target.id];if(a)a.classList.add('active');
     }
   });
 },{rootMargin:'-10% 0px -80% 0px',threshold:0});
 document.querySelectorAll('main section[id]').forEach(function(s){obs.observe(s);});
});
// PDF export: expand every collapsible before printing, restore afterwards.
var _printState=[];
window.addEventListener('beforeprint',function(){
 _printState=[];document.querySelectorAll('details').forEach(function(d){_printState.push(d.open);d.open=true;});
});
window.addEventListener('afterprint',function(){
 var i=0;document.querySelectorAll('details').forEach(function(d){d.open=_printState[i++];});
});
"""
