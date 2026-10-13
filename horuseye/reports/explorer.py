"""
HorusEye — interactive explorer (single self-contained offline HTML).

Produces one ``.html`` file with the assessment data embedded and an interactive
UI rendered by vanilla JS + inline SVG — no server, no database, no framework,
no external/CDN requests. It opens from ``file://`` and is safe to hand to a
client. Three views: an Overview dashboard, an Attack-Paths graph (the union of
the computed routes to the target, with clickable edges → evidence and
remediation choke points), and a filterable Findings explorer with full
evidence.

Build it with ``ReportGenerator.export_explorer`` / ``horuseye --explorer FILE``.
"""
from __future__ import annotations

import html
import json
from typing import Dict, List


def build_graph_view(paths: List[Dict], impact: List[Dict]) -> Dict:
    """Turn described paths + remediation impact into nodes/edges for drawing.

    The graph shown is the union of the attack routes (not the whole directory),
    which is what an operator needs: the ways from the foothold to the target.
    """
    choke = {(h["from"], h["to"], h["type"]) for h in (impact or []) if h.get("breaks_path")}
    nodes: Dict[str, Dict] = {}
    edges: Dict[tuple, Dict] = {}
    starts, goals = set(), set()

    for p in paths or []:
        if p.get("start"):
            starts.add(p["start"])
        if p.get("goal"):
            goals.add(p["goal"])
        prev_depth = 0
        node_seq = [p.get("start", "")] + [s["to"] for s in p.get("steps", [])]
        for depth, name in enumerate(node_seq):
            if not name:
                continue
            n = nodes.setdefault(name, {"id": name, "label": name, "depth": depth})
            n["depth"] = min(n["depth"], depth)
        for s in p.get("steps", []):
            key = (s["from"], s["to"], s["type"])
            edges.setdefault(key, {
                "from": s["from"], "to": s["to"], "type": s["type"],
                "trust": s.get("trust", "observed"), "detail": s.get("detail", ""),
                "command": "", "choke": key in choke,
            })
        # attach the first command line per step
        for s, cmd in zip(p.get("steps", []), p.get("commands", [])):
            key = (s["from"], s["to"], s["type"])
            if key in edges and not edges[key]["command"]:
                edges[key]["command"] = (cmd or "").split("\n")[0]

    for name, n in nodes.items():
        n["kind"] = "start" if name in starts else ("goal" if name in goals else "mid")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def build_explorer(findings: List[Dict], paths: List[Dict], impact: List[Dict],
                   domain_data: Dict, generated_at: str) -> str:
    counts = {}
    for f in findings:
        s = (f.get("severity") or "INFO").upper()
        counts[s] = counts.get(s, 0) + 1
    try:
        from horuseye.core.knowledge import mitre_coverage
        mitre = mitre_coverage(findings)
    except Exception:
        mitre = []

    pr = domain_data.get("parse_report", {}) or {}
    data = {
        "meta": {
            "domain": domain_data.get("domain", "N/A"),
            "dc": domain_data.get("dc_ip", "N/A"),
            "generated": generated_at,
            "total": len(findings),
            "counts": counts,
            "warnings": pr.get("warnings", []),
            "sources": pr.get("sources", []),
            "parse_counts": pr.get("counts", {}),
        },
        "mitre": mitre,
        "findings": findings,
        "paths": paths or [],
        "graph": build_graph_view(paths, impact),
    }
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return _TEMPLATE.replace("/*__DATA__*/", blob).replace(
        "__DOMAIN__", html.escape(str(data["meta"]["domain"])))


# ── Single-file template (CSS + JS inline, no external requests) ────────────
_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HorusEye Explorer — __DOMAIN__</title>
<style>
 :root{--bg:#0d0d0d;--panel:#151515;--panel2:#1b1b1b;--line:#2a2a2a;--fg:#e6e6e6;
   --muted:#9a9a9a;--gold:#C09A3C;--red:#E4002B;--code:#00ff9c;
   --crit:#ff4444;--high:#ff8800;--med:#ffcc00;--low:#88cc00;--info:#888}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);
   font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px}
 header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;
   align-items:center;gap:18px;flex-wrap:wrap;background:var(--panel)}
 header h1{margin:0;color:var(--red);font-size:18px}
 header .meta{color:var(--muted);font-size:13px}
 .tiles{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
 .tile{background:var(--panel2);border:1px solid var(--line);border-radius:8px;
   padding:6px 12px;text-align:center;min-width:64px}
 .tile b{display:block;font-size:20px} .tile span{font-size:11px;color:var(--muted);letter-spacing:.06em}
 nav{display:flex;gap:4px;padding:10px 20px 0;border-bottom:1px solid var(--line);background:var(--panel)}
 nav button{background:none;border:none;color:var(--muted);padding:8px 16px;cursor:pointer;
   font-size:14px;border-bottom:2px solid transparent}
 nav button.active{color:var(--fg);border-bottom-color:var(--red)}
 main{padding:18px 20px}
 .view{display:none} .view.active{display:block}
 h2{color:var(--gold);border-bottom:1px solid var(--line);padding-bottom:6px;font-size:15px;margin-top:4px}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
 @media(max-width:800px){.grid{grid-template-columns:1fr}}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th{color:var(--gold);text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);cursor:pointer}
 td{padding:6px 8px;border-bottom:1px solid #202020;vertical-align:top}
 .pill{color:#111;font-weight:700;padding:1px 7px;border-radius:9px;font-size:11px;white-space:nowrap}
 .sev-CRITICAL{background:var(--crit)} .sev-HIGH{background:var(--high)}
 .sev-MEDIUM{background:var(--med)} .sev-LOW{background:var(--low)} .sev-INFO{background:var(--info)}
 code,pre{background:#000;color:var(--code);font-family:ui-monospace,Consolas,monospace;border-radius:5px}
 code{padding:1px 5px;font-size:12px} pre{padding:8px 10px;overflow-x:auto;border:1px solid var(--line);font-size:12px}
 .controls{display:flex;gap:8px;align-items:center;margin:10px 0;flex-wrap:wrap}
 .controls input,.controls select{background:var(--panel2);border:1px solid var(--line);
   color:var(--fg);padding:6px 10px;border-radius:7px}
 .fbtn{background:var(--panel2);border:1px solid var(--line);color:var(--muted);
   padding:4px 10px;border-radius:14px;cursor:pointer;font-size:12px}
 .fbtn.active{color:#fff;border-color:var(--red)}
 .frow{cursor:pointer} .frow:hover{background:#181818}
 .detail{background:var(--panel2);border-left:2px solid var(--red)}
 .lab{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em;margin:10px 0 3px}
 ul{margin:3px 0 3px 16px;padding:0} li{margin:2px 0}
 .graphwrap{display:flex;gap:14px;flex-wrap:wrap}
 .graphsvg{flex:1 1 560px;min-width:320px;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:auto}
 .side{flex:1 1 300px;min-width:260px}
 .node rect{cursor:pointer} .node text{font-size:11px;fill:var(--fg);pointer-events:none}
 .edge{cursor:pointer} .legend span{display:inline-block;margin-right:12px;color:var(--muted);font-size:12px}
 .muted{color:var(--muted)} .tag{font-size:11px;color:var(--muted)}
 a{color:#5ab0ff}
 footer{color:var(--muted);font-size:11px;padding:16px 20px;border-top:1px solid var(--line)}
</style></head><body>
<header>
 <h1>𓂀 HorusEye Explorer</h1>
 <div class="meta" id="hmeta"></div>
 <div class="tiles" id="tiles"></div>
</header>
<nav>
 <button data-view="overview" class="active">Overview</button>
 <button data-view="paths">Attack Paths</button>
 <button data-view="findings">Findings</button>
</nav>
<main>
 <section id="overview" class="view active"></section>
 <section id="paths" class="view"></section>
 <section id="findings" class="view"></section>
</main>
<footer>Generated offline by HorusEye — authorized security testing only. No data leaves this file. 𓂀</footer>
<script id="data" type="application/json">/*__DATA__*/</script>
<script>
"use strict";
var DATA = JSON.parse(document.getElementById("data").textContent);
var SEV = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
var SEVC = {CRITICAL:"var(--crit)",HIGH:"var(--high)",MEDIUM:"var(--med)",LOW:"var(--low)",INFO:"var(--info)"};
function esc(s){s=(s==null?"":""+s);return s.replace(/[&<>"]/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c];});}
function el(id){return document.getElementById(id);}

// ── Header ──
(function(){
 var m=DATA.meta;
 el("hmeta").innerHTML="Domain <b>"+esc(m.domain)+"</b> &middot; DC "+esc(m.dc)
   +" &middot; "+esc(m.generated)+" &middot; "+m.total+" findings";
 var t=el("tiles"),h="";
 SEV.forEach(function(s){var n=m.counts[s]||0;if(!n)return;
   h+='<div class="tile"><b style="color:'+SEVC[s]+'">'+n+'</b><span>'+s+'</span></div>';});
 t.innerHTML=h;
})();

// ── Tabs ──
Array.prototype.forEach.call(document.querySelectorAll("nav button"),function(b){
 b.onclick=function(){
   Array.prototype.forEach.call(document.querySelectorAll("nav button"),function(x){x.classList.remove("active");});
   Array.prototype.forEach.call(document.querySelectorAll(".view"),function(x){x.classList.remove("active");});
   b.classList.add("active"); el(b.dataset.view).classList.add("active");
 };
});

// ── Overview ──
(function(){
 var m=DATA.meta,h="";
 h+='<div class="grid">';
 // risk summary
 h+='<div class="card"><h2>Risk summary</h2><table>';
 SEV.forEach(function(s){var n=m.counts[s]||0;
   h+='<tr><td><span class="pill sev-'+s+'">'+s+'</span></td><td>'+n+'</td></tr>';});
 h+='</table>';
 if(m.warnings&&m.warnings.length){h+='<div class="lab">Import warnings</div><ul>';
   m.warnings.forEach(function(w){h+='<li class="muted">⚠️ '+esc(w)+'</li>';});h+='</ul>';}
 h+='<div class="lab">Sources</div><div class="muted">'+esc((m.sources||[]).join(", ")||"—")+'</div>';
 h+='</div>';
 // top exposures
 h+='<div class="card"><h2>Top exposures</h2><table>';
 var top=DATA.findings.slice().sort(bySeverity).slice(0,8);
 top.forEach(function(f){h+='<tr><td><span class="pill sev-'+(f.severity||"INFO")+'">'
   +(f.severity||"INFO")+'</span></td><td>'+esc(f.title)+'</td></tr>';});
 h+='</table></div>';
 // mitre
 h+='<div class="card"><h2>MITRE ATT&amp;CK coverage</h2><table><tr><th>Technique</th><th>Name</th><th>Max</th><th>#</th></tr>';
 (DATA.mitre||[]).forEach(function(mt){
   h+='<tr><td><a href="https://attack.mitre.org/techniques/'+mt.id.replace(".","/")+'/" target="_blank">'+mt.id+'</a></td>'
     +'<td>'+esc(mt.name)+'</td><td><span class="pill sev-'+mt.max_severity+'">'+mt.max_severity+'</span></td><td>'+mt.count+'</td></tr>';});
 h+='</table></div>';
 // paths summary
 h+='<div class="card"><h2>Attack paths</h2>';
 if(DATA.paths.length){h+='<p>'+DATA.paths.length+' route(s) to the target. Shortest: <b>'
   +DATA.paths[0].hops+' hop(s)</b>. See the <a href="#" onclick="gotoPaths();return false">Attack Paths</a> view.</p>';}
 else{h+='<p class="muted">No path to the target from the chosen foothold. Add --owned or collect session/local-admin data.</p>';}
 h+='</div></div>';
 el("overview").innerHTML=h;
})();
function gotoPaths(){document.querySelector('nav button[data-view="paths"]').click();}
function bySeverity(a,b){return SEV.indexOf(a.severity||"INFO")-SEV.indexOf(b.severity||"INFO");}

// ── Attack Paths (SVG) ──
(function(){
 var g=DATA.graph, h="";
 if(!g.nodes.length){el("paths").innerHTML='<div class="card"><h2>Attack Paths</h2>'
   +'<p class="muted">No attack paths computed for this run.</p></div>';return;}
 // layout: columns by depth
 var byDepth={}, maxDepth=0;
 g.nodes.forEach(function(n){(byDepth[n.depth]=byDepth[n.depth]||[]).push(n);maxDepth=Math.max(maxDepth,n.depth);});
 var colW=210, rowH=58, padX=20, padY=30, boxW=170, boxH=34;
 var pos={};
 Object.keys(byDepth).forEach(function(d){
   byDepth[d].forEach(function(n,i){pos[n.id]={x:padX+d*colW,y:padY+i*rowH,w:boxW,h:boxH};});});
 var height=padY*2+Math.max.apply(null,Object.keys(byDepth).map(function(d){return byDepth[d].length;}))*rowH;
 var width=padX*2+(maxDepth+1)*colW;
 var svg='<svg class="graphsvg" viewBox="0 0 '+width+' '+Math.max(height,160)
   +'" style="min-height:220px" xmlns="http://www.w3.org/2000/svg">';
 svg+='<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">'
   +'<path d="M0,0 L7,3 L0,6 Z" fill="#888"/></marker>'
   +'<marker id="arrc" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">'
   +'<path d="M0,0 L7,3 L0,6 Z" fill="var(--red)"/></marker></defs>';
 // edges
 g.edges.forEach(function(e,i){var a=pos[e.from],b=pos[e.to];if(!a||!b)return;
   var x1=a.x+a.w,y1=a.y+a.h/2,x2=b.x,y2=b.y+b.h/2;
   var col=e.choke?"var(--red)":"#888";
   svg+='<line class="edge" data-edge="'+i+'" x1="'+x1+'" y1="'+y1+'" x2="'+x2+'" y2="'+y2
     +'" stroke="'+col+'" stroke-width="'+(e.choke?2.2:1.4)+'" '
     +(e.trust==="inferred"?'stroke-dasharray="5,4" ':'')
     +'marker-end="url(#'+(e.choke?'arrc':'arr')+')"/>';
   svg+='<text x="'+((x1+x2)/2)+'" y="'+((y1+y2)/2-4)+'" text-anchor="middle" '
     +'fill="#aaa" font-size="10" pointer-events="none">'+esc(e.type)+'</text>';});
 // nodes
 g.nodes.forEach(function(n){var p=pos[n.id];
   var fill=n.kind==="goal"?"#3a1414":(n.kind==="start"?"#14321c":"var(--panel2)");
   var stroke=n.kind==="goal"?"var(--red)":(n.kind==="start"?"#3fae6a":"var(--line)");
   var lbl=n.label.split("@")[0]; if(lbl.length>22)lbl=lbl.slice(0,21)+"…";
   svg+='<g class="node" data-node="'+esc(n.id)+'">'
     +'<rect x="'+p.x+'" y="'+p.y+'" width="'+p.w+'" height="'+p.h+'" rx="7" fill="'+fill+'" stroke="'+stroke+'"/>'
     +'<text x="'+(p.x+8)+'" y="'+(p.y+p.h/2+4)+'">'+esc(lbl)+'</text></g>';});
 svg+='</svg>';

 h+='<h2>Attack Paths to target</h2>';
 h+='<div class="legend" style="margin-bottom:8px">'
   +'<span><b style="color:#3fae6a">▬</b> foothold</span>'
   +'<span><b style="color:var(--red)">▬</b> target</span>'
   +'<span style="color:var(--red)">━ choke point (breaks path)</span>'
   +'<span>╌ inferred step</span></div>';
 h+='<div class="graphwrap">'+svg+'<div class="side card" id="pdetail">'
   +'<div class="muted">Click a node or edge to inspect it.</div>';
 // choke summary
 var chokes=g.edges.filter(function(e){return e.choke;});
 if(chokes.length){h+='<div class="lab">Remediation — break the path</div><ul>';
   chokes.forEach(function(e){h+='<li>✂ remove <b>'+esc(e.type)+'</b> '+esc(short(e.from))+' → '+esc(short(e.to))+'</li>';});
   h+='</ul>';}
 h+='</div></div>';
 el("paths").innerHTML=h;

 // interactions
 Array.prototype.forEach.call(document.querySelectorAll("#paths .edge"),function(ln){
   ln.onclick=function(){var e=g.edges[+ln.dataset.edge];
     el("pdetail").innerHTML='<div class="lab">Edge</div><b>'+esc(e.type)+'</b> '
       +(e.trust==="inferred"?'<span class="tag">(inferred)</span>':'<span class="tag">(observed)</span>')
       +'<div class="muted" style="margin:4px 0">'+esc(short(e.from))+' → '+esc(short(e.to))+'</div>'
       +'<div>'+esc(e.detail)+'</div>'
       +(e.command?'<div class="lab">Command</div><pre>'+esc(e.command)+'</pre>':'')
       +(e.choke?'<div class="lab">Remediation impact</div><div>Choke point — removing this breaks the path with no alternative.</div>':'');};});
 Array.prototype.forEach.call(document.querySelectorAll("#paths .node"),function(nd){
   nd.onclick=function(){var id=nd.dataset.node;
     var rel=DATA.findings.filter(function(f){return (f.affected||"").indexOf(id)>=0
       || (f.evidence||[]).some(function(ev){return (ev.object||"").indexOf(id)>=0;});});
     var h='<div class="lab">Node</div><b>'+esc(id)+'</b>';
     if(rel.length){h+='<div class="lab">Findings here ('+rel.length+')</div>';
       rel.forEach(function(f){h+='<div><span class="pill sev-'+(f.severity||"INFO")+'">'
         +(f.severity||"INFO")+'</span> '+esc(f.title)+'</div>';});}
     else{h+='<div class="muted" style="margin-top:6px">No findings directly on this node.</div>';}
     el("pdetail").innerHTML=h;};});
})();
function short(s){s=s||"";return s.split("@")[0];}

// ── Findings ──
(function(){
 var state={sev:"ALL",q:""};
 var h='<h2>Findings</h2><div class="controls">';
 h+='<span class="fbtn active" data-sev="ALL">All</span>';
 SEV.forEach(function(s){if(DATA.meta.counts[s])h+='<span class="fbtn" data-sev="'+s+'">'+s+'</span>';});
 h+='<input id="fq" placeholder="search title / affected / rule…" style="flex:1;min-width:160px">';
 h+='</div><table id="ftab"><thead><tr><th data-k="severity">Severity</th><th data-k="score">Score</th>'
   +'<th data-k="confidence">Conf.</th><th data-k="rule_id">Rule</th><th data-k="affected">Affected</th><th>Title</th></tr></thead><tbody></tbody></table>';
 el("findings").innerHTML=h;
 var tbody=document.querySelector("#ftab tbody");
 var sortK="severity",sortDir=1;

 function render(){
   var rows=DATA.findings.filter(function(f){
     if(state.sev!=="ALL"&&(f.severity||"INFO")!==state.sev)return false;
     if(state.q){var s=(f.title+" "+f.affected+" "+(f.rule_id||f.type)).toLowerCase();
       if(s.indexOf(state.q.toLowerCase())<0)return false;}
     return true;});
   rows.sort(function(a,b){
     if(sortK==="severity")return (SEV.indexOf(a.severity||"INFO")-SEV.indexOf(b.severity||"INFO"))*sortDir;
     if(sortK==="score")return ((b.score||0)-(a.score||0))*sortDir;
     var av=(""+(a[sortK]||"")),bv=(""+(b[sortK]||""));return av.localeCompare(bv)*sortDir;});
   var out="";
   rows.forEach(function(f,i){
     out+='<tr class="frow" data-i="'+i+'"><td><span class="pill sev-'+(f.severity||"INFO")+'">'
       +(f.severity||"INFO")+'</span></td><td>'+(f.score==null?"":f.score)+'</td>'
       +'<td class="tag">'+esc(f.confidence||"")+'</td><td><code>'+esc(f.rule_id||f.type)+'</code></td>'
       +'<td class="muted">'+esc(f.affected)+'</td><td>'+esc(f.title)+'</td></tr>'
       +'<tr class="detail" id="d'+i+'" style="display:none"><td colspan="6">'+detail(f)+'</td></tr>';});
   tbody.innerHTML=out||'<tr><td colspan="6" class="muted">No findings match.</td></tr>';
   Array.prototype.forEach.call(document.querySelectorAll("#ftab .frow"),function(r){
     r.onclick=function(){var d=el("d"+r.dataset.i);d.style.display=d.style.display==="none"?"table-row":"none";};});
   window._frows=rows;
 }
 function detail(f){
   var h="";
   if(f.description)h+='<p>'+esc(f.description)+'</p>';
   if(f.confidence)h+='<div class="tag">confidence '+esc(f.confidence)+' — '+esc(f.confidence_reason||"")+'</div>';
   if(f.evidence&&f.evidence.length){h+='<div class="lab">Evidence ('+f.evidence.length+')</div><ul>';
     f.evidence.slice(0,60).forEach(function(e){h+='<li><code>'+esc(e.object)+'</code>'
       +(e.detail?' — '+esc(e.detail):'')+' <span class="tag">('+esc(e.source)+(e.file?", "+esc(e.file):"")+')</span></li>';});
     if(f.evidence.length>60)h+='<li class="tag">+'+(f.evidence.length-60)+' more</li>';h+='</ul>';}
   if(f.commands&&f.commands.length){h+='<div class="lab">Validate</div>';
     f.commands.forEach(function(c){h+='<pre>'+esc(c)+'</pre>';});}
   if(f.remediation&&f.remediation.length){h+='<div class="lab">Remediation</div><ul>';
     f.remediation.forEach(function(r){h+='<li>'+esc(r)+'</li>';});h+='</ul>';}
   if(f.detection&&f.detection.length){h+='<div class="lab">Detection</div><ul>';
     f.detection.forEach(function(d){h+='<li>'+esc(d)+'</li>';});h+='</ul>';}
   if(f.mitre&&f.mitre.length){h+='<div class="lab">ATT&CK</div><div>';
     f.mitre.forEach(function(m){h+='<a href="https://attack.mitre.org/techniques/'+m.id.replace(".","/")
       +'/" target="_blank">'+m.id+'</a> ';});h+='</div>';}
   return h;
 }
 Array.prototype.forEach.call(document.querySelectorAll("#findings .fbtn"),function(b){
   b.onclick=function(){Array.prototype.forEach.call(document.querySelectorAll("#findings .fbtn"),
     function(x){x.classList.remove("active");});b.classList.add("active");state.sev=b.dataset.sev;render();};});
 el("fq").oninput=function(){state.q=this.value;render();};
 Array.prototype.forEach.call(document.querySelectorAll("#ftab th[data-k]"),function(th){
   th.onclick=function(){var k=th.dataset.k;if(sortK===k)sortDir=-sortDir;else{sortK=k;sortDir=1;}render();};});
 render();
})();
</script>
</body></html>"""
