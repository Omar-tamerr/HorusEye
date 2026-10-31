"""
HorusEye — interactive explorer (single self-contained offline HTML).

Produces one ``.html`` file with the assessment data embedded and an interactive
UI rendered by vanilla JS + inline SVG — no server, no database, no framework,
no external/CDN requests. It opens from ``file://`` and is safe to hand to a
client. Three views:

* **Overview** — severity tiles, top exposures, ATT&CK coverage, import warnings.
* **Attack paths** — the computed routes from the foothold to the target as an
  interactive graph (route picker, node types, observed vs inferred edges,
  choke points), a step-by-step walkthrough with validation commands, an
  inspector for any node or relationship, and a "fix this first" panel.
* **Findings** — filterable, searchable, sortable, with full evidence.

``demo`` (optional) turns on website-only extras for the public live demo: a top
bar linking back to the site, a "synthetic data" label, and link-preview meta
tags. Normal ``--explorer`` reports never include them.
"""
from __future__ import annotations

import html
import json
from typing import Dict, List, Optional
from urllib.parse import quote

# Stylized Eye of Horus, drawn as SVG so it renders on every device (the
# U+13080 hieroglyph is missing from many phone fonts).
EYE_SVG = (
    '<svg class="eye-ic" viewBox="0 0 64 42" aria-hidden="true">'
    '<path d="M2 9 Q32 -7 62 9"/>'
    '<path d="M5 20 Q32 1 59 20 Q32 36 5 20 Z"/>'
    '<circle class="pupil" cx="32" cy="19" r="7"/>'
    '<path d="M29 29 L26.5 40"/>'
    '<path d="M39 28 Q45 39 53 34 Q57 31 53 28"/>'
    '</svg>'
)

_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 42'>"
    "<g fill='none' stroke='%23C09A3C' stroke-width='4' stroke-linecap='round'>"
    "<path d='M2 9 Q32 -7 62 9'/><path d='M5 20 Q32 1 59 20 Q32 36 5 20 Z'/>"
    "<path d='M29 29 L26.5 40'/><path d='M39 28 Q45 39 53 34 Q57 31 53 28'/></g>"
    "<circle cx='32' cy='19' r='7' fill='%23C09A3C'/></svg>"
)
FAVICON = "data:image/svg+xml," + quote(_FAVICON_SVG, safe="/:=' %")


# ── Graph view model ─────────────────────────────────────────────────────────
def _node_types(domain_data: Optional[Dict]):
    d = domain_data or {}

    def names(rows, key):
        return {str(r.get(key) or "").strip().upper()
                for r in (rows or []) if isinstance(r, dict) and r.get(key)}

    groups = names(d.get("groups"), "name")
    users = names(d.get("users"), "name")
    comps = (names(d.get("computers"), "name") | names(d.get("local_admins"), "computer")
             | names(d.get("sessions"), "ComputerName"))
    return groups, users, comps, str(d.get("domain") or "").strip().upper()


def _otype(name: str, types) -> str:
    groups, users, comps, dom = types
    n = (name or "").strip().upper()
    if dom and n == dom:
        return "domain"
    if n in comps:
        return "computer"
    if n in groups:
        return "group"
    if n in users:
        return "user"
    if "@" not in n and "." in n:
        return "computer"
    return "principal"


def build_graph_view(paths: List[Dict], impact: List[Dict],
                     domain_data: Optional[Dict] = None) -> Dict:
    """Turn described paths + remediation impact into nodes/edges for drawing.

    The graph is the union of the attack routes (not the whole directory) —
    what an operator needs. Each node/edge records which routes it is on.
    """
    types = _node_types(domain_data)
    imp: Dict[tuple, Dict] = {}
    for h in impact or []:
        imp.setdefault((h.get("from"), h.get("to"), h.get("type"), h.get("detail", "")), h)
        imp.setdefault((h.get("from"), h.get("to"), h.get("type")), h)

    nodes: Dict[str, Dict] = {}
    edges: Dict[tuple, Dict] = {}
    for pi, p in enumerate(paths or []):
        seq = [p.get("start", "")] + [s.get("to", "") for s in p.get("steps", []) or []]
        for depth, name in enumerate(seq):
            if not name:
                continue
            n = nodes.get(name)
            if n is None:
                otype = _otype(name, types)
                label = name.split("@")[0]
                if otype == "computer" and "." in label:
                    label = label.split(".")[0]
                n = nodes[name] = {"id": name, "label": label, "depth": depth,
                                   "otype": otype, "paths": []}
            n["depth"] = min(n["depth"], depth)
            if pi not in n["paths"]:
                n["paths"].append(pi)
        cmds = p.get("commands", []) or []
        for si, s in enumerate(p.get("steps", []) or []):
            key = (s.get("from"), s.get("to"), s.get("type"), s.get("detail", ""))
            e = edges.get(key)
            if e is None:
                h = imp.get(key) or imp.get(key[:3])
                e = edges[key] = {
                    "id": len(edges), "from": s.get("from"), "to": s.get("to"),
                    "type": s.get("type"), "detail": s.get("detail", ""),
                    "trust": s.get("trust", "observed"),
                    "command": cmds[si] if si < len(cmds) else "",
                    "choke": bool(h and h.get("breaks_path")),
                    "alt": None if h is None else bool(h.get("alternative_remains")),
                    "paths": [],
                }
            if pi not in e["paths"]:
                e["paths"].append(pi)

    starts = {p.get("start") for p in paths or []}
    goals = {p.get("goal") for p in paths or []}
    for name, n in nodes.items():
        n["kind"] = "start" if name in starts else ("goal" if name in goals else "mid")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


# ── Page assembly ────────────────────────────────────────────────────────────
def _demo_head(demo: Dict, title: str, description: str) -> str:
    e = lambda s: html.escape(str(s or ""), quote=True)  # noqa: E731
    out = [f'<meta name="description" content="{e(description)}">',
           f'<meta property="og:type" content="website">',
           f'<meta property="og:title" content="{e(title)}">',
           f'<meta property="og:description" content="{e(description)}">',
           f'<meta name="twitter:card" content="summary_large_image">',
           f'<meta name="twitter:title" content="{e(title)}">',
           f'<meta name="twitter:description" content="{e(description)}">']
    if demo.get("page_url"):
        out += [f'<meta property="og:url" content="{e(demo["page_url"])}">',
                f'<link rel="canonical" href="{e(demo["page_url"])}">']
    if demo.get("og_image"):
        out += [f'<meta property="og:image" content="{e(demo["og_image"])}">',
                '<meta property="og:image:width" content="1200">',
                '<meta property="og:image:height" content="630">',
                f'<meta property="og:image:alt" content="HorusEye — See the path. Know the fix.">',
                f'<meta name="twitter:image" content="{e(demo["og_image"])}">']
    return "\n".join(out)


def _demo_bar(demo: Dict) -> str:
    e = lambda s: html.escape(str(s or ""), quote=True)  # noqa: E731
    parts = ['<div class="demobar">',
             f'<a class="home" href="{e(demo.get("home_url") or "./")}">← <span class="hsm">HorusEye </span>home</a>',
             '<span class="demotag">Live demo</span>',
             '<span class="demonote">Synthetic ACME.LAB data — no real systems</span>',
             '<span class="sp"></span>']
    if demo.get("repo_url"):
        parts.append(f'<a class="ghl" href="{e(demo["repo_url"])}" target="_blank" rel="noopener">GitHub</a>')
    if demo.get("install_url"):
        parts.append(f'<a class="get" href="{e(demo["install_url"])}">Get HorusEye</a>')
    parts.append("</div>")
    return "".join(parts)


def build_explorer(findings: List[Dict], paths: List[Dict], impact: List[Dict],
                   domain_data: Dict, generated_at: str,
                   demo: Optional[Dict] = None, version: Optional[str] = None) -> str:
    if version is None:
        try:
            from horuseye import __version__ as version
        except Exception:  # pragma: no cover
            version = ""
    counts: Dict[str, int] = {}
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
        },
        "mitre": mitre,
        "findings": findings,
        "paths": paths or [],
        "graph": build_graph_view(paths, impact, domain_data),
        "default_view": (demo or {}).get("default_view") or "overview",
    }
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    dom = str(data["meta"]["domain"])
    ver = f"v{version}" if version else ""

    if demo:
        title = f"HorusEye Live Demo — attack paths in {dom}"
        desc = ("Interactive HorusEye report on a synthetic Active Directory: two attack "
                "routes to domain control, the one fix that breaks both, and every finding "
                "with evidence, remediation and detection guidance.")
        head = _demo_head(demo, title, desc)
        bar = _demo_bar(demo)
        home = html.escape(str(demo.get("home_url") or "./"), quote=True)
        footer = (f"Live demo generated by HorusEye {ver} from the bundled acme-lab example — "
                  f"synthetic data, no real systems. <a href=\"{home}\">← Back to the HorusEye site</a>")
    else:
        title = f"HorusEye Explorer — {dom}"
        head = bar = ""
        footer = (f"Generated offline by HorusEye {ver} — authorized security testing only. "
                  "No data leaves this file.")

    page = _TEMPLATE
    for token, value in (("__TITLE__", html.escape(title)), ("__HEAD_EXTRA__", head),
                         ("__FAVICON__", FAVICON), ("__DEMOBAR__", bar),
                         ("__FOOTER__", footer), ("__EYE__", EYE_SVG)):
        page = page.replace(token, value)
    return page.replace("/*__DATA__*/", blob)   # data last: never re-scanned


# ── Single-file template (CSS + JS inline, no external requests) ────────────
_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
__HEAD_EXTRA__
<link rel="icon" href="__FAVICON__">
<style>
 :root{--bg:#0b0b0d;--panel:#141417;--panel2:#1a1a1e;--line:#27272c;--fg:#e9e9ec;
   --muted:#9a9aa3;--dim:#6a6a72;--gold:#C09A3C;--red:#E4002B;--red2:#ff2d52;--green:#3fae6a;
   --amber:#f0a429;--code:#00ff9c;--crit:#ff4444;--high:#ff8800;--med:#ffcc00;--low:#88cc00;--info:#888}
 *{box-sizing:border-box}
 html{scroll-behavior:smooth}
 body{margin:0;background:var(--bg);color:var(--fg);line-height:1.5;
   font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px}
 a{color:#5ab0ff}
 code,pre,.mono{font-family:ui-monospace,"SF Mono",Consolas,monospace}
 .eye-ic{width:30px;height:20px;flex:none;color:var(--gold)}
 .eye-ic path{fill:none;stroke:currentColor;stroke-width:3.4;stroke-linecap:round;stroke-linejoin:round}
 .eye-ic .pupil{fill:currentColor}

 /* demo bar (website demo only) */
 .demobar{display:flex;align-items:center;gap:12px;padding:8px 20px;background:#110a0c;
   border-bottom:1px solid #3a1820;font-size:13px;flex-wrap:wrap}
 .demobar a{text-decoration:none}
 .demobar .home{color:#fff;font-weight:600}
 .demobar .home:hover{color:var(--gold)}
 .demotag{background:var(--red);color:#fff;font-weight:700;font-size:11px;letter-spacing:.1em;
   text-transform:uppercase;padding:2px 8px;border-radius:9px}
 .demonote{color:var(--muted)}
 .demobar .sp{flex:1}
 .demobar .ghl{color:var(--muted)} .demobar .ghl:hover{color:#fff}
 .demobar .get{background:linear-gradient(180deg,var(--red2),var(--red));color:#fff;font-weight:700;
   padding:5px 12px;border-radius:8px;white-space:nowrap}

 header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;
   gap:14px;flex-wrap:wrap;background:var(--panel)}
 header .brand{display:flex;align-items:center;gap:10px}
 header h1{margin:0;font-size:18px;color:#fff;letter-spacing:.2px}
 header h1 b{color:var(--red2)}
 header .meta{color:var(--muted);font-size:13px}
 .tiles{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
 .tile{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:5px 12px;
   text-align:center;min-width:62px}
 .tile b{display:block;font-size:19px;line-height:1.2} .tile span{font-size:10.5px;color:var(--muted);letter-spacing:.06em}
 nav.tabs{display:flex;gap:2px;padding:0 20px;border-bottom:1px solid var(--line);background:var(--panel);
   overflow-x:auto;position:sticky;top:0;z-index:5}
 nav.tabs button{background:none;border:none;color:var(--muted);padding:12px 16px;cursor:pointer;
   font-size:14px;border-bottom:2px solid transparent;white-space:nowrap;font-family:inherit}
 nav.tabs button:hover{color:#fff}
 nav.tabs button.active{color:#fff;border-bottom-color:var(--red)}
 main{padding:18px 20px;max-width:1400px;margin:0 auto}
 .view{display:none} .view.active{display:block}
 h2{color:#fff;font-size:18px;margin:0 0 4px}
 h3{color:#fff;font-size:15px;margin:2px 0 6px}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
 .lab{color:var(--gold);font-size:11px;text-transform:uppercase;letter-spacing:.09em;font-weight:700;margin:12px 0 4px}
 .card>.lab:first-child{margin-top:0}
 .muted{color:var(--muted)} .small{font-size:12.5px} .red{color:var(--red2)} .amber{color:var(--amber)}
 .arrow{color:var(--dim)}
 .pill{color:#111;font-weight:700;padding:1px 7px;border-radius:9px;font-size:11px;white-space:nowrap}
 .sev-CRITICAL{background:var(--crit)} .sev-HIGH{background:var(--high)}
 .sev-MEDIUM{background:var(--med)} .sev-LOW{background:var(--low)} .sev-INFO{background:var(--info)}
 .tag{display:inline-block;font-size:11px;border:1px solid var(--line);color:var(--muted);
   padding:1px 8px;border-radius:9px;margin:0 4px 0 0;white-space:nowrap}
 .tag.t-choke{border-color:var(--red);color:var(--red2)} .tag.amber{border-color:#6b4a12}
 .tag.t-rel{color:#fff}
 .btn{display:inline-block;background:var(--panel2);border:1px solid var(--line);color:#fff;
   padding:7px 13px;border-radius:8px;text-decoration:none;font-size:13px}
 .btn:hover{border-color:var(--gold)}
 .cmd{display:flex;align-items:flex-start;gap:8px;background:#000;border:1px solid var(--line);
   border-radius:7px;padding:7px 8px 7px 10px;margin:5px 0}
 .cmd code{flex:1;color:var(--code);font-size:12px;white-space:pre-wrap;word-break:break-all}
 .cmd button{background:var(--panel2);border:1px solid var(--line);color:var(--muted);border-radius:6px;
   padding:2px 8px;font-size:11px;cursor:pointer;flex:none;font-family:inherit}
 .cmd button:hover{color:#fff}
 ul,ol{margin:4px 0 4px 18px;padding:0} li{margin:3px 0}

 /* overview */
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th{color:var(--gold);text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);font-size:12px}
 td{padding:7px 8px;border-bottom:1px solid #1f1f23;vertical-align:top}

 /* attack paths */
 .phead{display:flex;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:12px}
 .phead .psum{color:var(--muted);font-size:13.5px}
 .chips{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
 .chip{background:var(--panel2);border:1px solid var(--line);color:var(--muted);padding:6px 12px;
   border-radius:16px;cursor:pointer;font-size:12.5px;font-family:inherit}
 .chip:hover{color:#fff}
 .chip.on{color:#fff;border-color:var(--gold);background:#1f1a10}
 .gwrap{background-color:var(--panel);
   background-image:radial-gradient(#25252b 1px,transparent 1px);background-size:22px 22px;
   border:1px solid var(--line);border-radius:14px;overflow-x:auto;overflow-y:hidden}
 #gsvg{display:block}
 #gsvg text{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
 .node{cursor:pointer;outline:none}
 .node rect.box{fill:#1b1b20;stroke:#34343c;stroke-width:1.5;transition:stroke .15s}
 .node:hover rect.box,.node:focus rect.box{stroke:#77777f}
 .node.start rect.box{fill:#10251a;stroke:var(--green)}
 .node.goal rect.box{fill:#2a0f14;stroke:var(--red);filter:drop-shadow(0 0 9px rgba(228,0,43,.5))}
 .node.sel rect.box{stroke:var(--gold);stroke-width:3}
 .node .icbg{fill:#26262d}
 .node.start .icbg{fill:#163a25} .node.goal .icbg{fill:#3d121a}
 .node .ic{font-size:15px}
 .node .lbl{fill:#fff;font-size:13px;font-weight:650}
 .node .sub{fill:var(--muted);font-size:11px}
 .node .badge{font-size:10px;font-weight:800;letter-spacing:.14em}
 .node.start .badge{fill:var(--green)} .node.goal .badge{fill:var(--red2)}
 .edge{cursor:pointer;outline:none}
 .edge .line{fill:none;stroke:#4c4c56;stroke-width:2.2}
 .edge.on .line{stroke:var(--gold)}
 .edge.choke .line{stroke:var(--red)}
 .edge.inferred .line{stroke-dasharray:7 6}
 .edge.sel .line{stroke-width:4}
 .edge .flow{fill:none;stroke:#fff;stroke-opacity:.6;stroke-width:2.2;stroke-dasharray:3 13;
   stroke-linecap:round;display:none;animation:flow 1.1s linear infinite;pointer-events:none}
 .edge.on .flow{display:inline}
 .edge .hit{fill:none;stroke:transparent;stroke-width:18}
 .edge .pill rect{fill:#121215;stroke:#3a3a42;stroke-width:1.2}
 .edge.on .pill rect{stroke:#7a6430}
 .edge.choke .pill rect{stroke:var(--red);fill:#1d0b0f}
 .edge.sel .pill rect{stroke:var(--gold);stroke-width:2}
 .edge .pill text{fill:#dcdce0;font-size:11px;font-weight:650}
 .edge.choke .pill text{fill:#ff8a9c}
 .dim{opacity:.16}
 @keyframes flow{to{stroke-dashoffset:-32}}
 @media (prefers-reduced-motion:reduce){.edge .flow{animation:none}}
 .legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:12px;margin:8px 2px 16px;align-items:center}
 .legend i{display:inline-block;vertical-align:middle;margin-right:6px}
 .legend .sq{width:14px;height:11px;border-radius:3px;border:1.5px solid}
 .legend .sq.start{background:#10251a;border-color:var(--green)}
 .legend .sq.goal{background:#2a0f14;border-color:var(--red)}
 .legend .ln{width:22px;height:0;border-top:2.5px solid var(--gold)}
 .legend .ln.choke{border-top-color:var(--red)}
 .legend .ln.dash{border-top:2.5px dashed #8a8a94}
 .pgrid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:16px;align-items:start}
 .side{display:grid;gap:16px}
 .steps{list-style:none;margin:8px 0;padding:0;counter-reset:s}
 .step{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0;cursor:pointer;
   background:var(--panel2);transition:border-color .15s}
 .step:hover{border-color:#44444c} .step.sel{border-color:var(--gold)}
 .step .stop{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
 .step .num{background:var(--gold);color:#111;font-weight:800;border-radius:50%;width:22px;height:22px;
   display:inline-flex;align-items:center;justify-content:center;font-size:12px;flex:none}
 .step .rel{color:var(--gold);font-size:12px;font-weight:700}
 .step p{margin:6px 0 2px;color:#cfcfd4}
 .reached{border:1px solid #4a1520;background:#1a0b0e;border-radius:10px;padding:9px 12px;margin:8px 0}
 .rcard{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0;background:var(--panel2)}
 .fixes li{margin:6px 0}
 .fixes a{color:#fff;text-decoration:none;border-bottom:1px dotted #555}
 .fixes a:hover{color:var(--gold)}
 .flist{list-style:none;margin:4px 0;padding:0} .flist li{margin:5px 0}
 .flist a{color:#e9e9ec;text-decoration:none} .flist a:hover{color:var(--gold)}

 /* findings */
 .controls{display:flex;gap:8px;align-items:center;margin:10px 0;flex-wrap:wrap}
 .controls input{background:var(--panel2);border:1px solid var(--line);color:var(--fg);
   padding:7px 10px;border-radius:8px;flex:1;min-width:180px;font-family:inherit}
 .fbtn{background:var(--panel2);border:1px solid var(--line);color:var(--muted);
   padding:4px 11px;border-radius:14px;cursor:pointer;font-size:12px;font-family:inherit}
 .fbtn.active{color:#fff;border-color:var(--red)}
 .tscroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
 #ftab th{cursor:pointer;white-space:nowrap}
 .frow{cursor:pointer} .frow:hover{background:#18181c}
 .frow.open{background:#18181c}
 .detail td{background:var(--panel2);border-left:2px solid var(--red);padding:10px 14px}
 footer{color:var(--muted);font-size:12px;padding:18px 20px;border-top:1px solid var(--line);margin-top:24px}

 @media(max-width:900px){.pgrid{grid-template-columns:1fr}}
 @media(max-width:800px){.grid{grid-template-columns:1fr}}
 @media(max-width:720px){
   main{padding:14px 12px} header{padding:12px} nav.tabs{padding:0 6px}
   .tiles{margin-left:0} .demonote{display:none} .demobar{padding:8px 12px}
   .chips{margin-left:0} .hm{display:none}
 }
 @media(max-width:460px){.hsm,.demobar .ghl{display:none} .demobar{gap:8px;flex-wrap:nowrap}}
</style></head><body>
__DEMOBAR__
<header>
 <div class="brand">__EYE__<h1>Horus<b>Eye</b> Explorer</h1></div>
 <div class="meta" id="hmeta"></div>
 <div class="tiles" id="tiles"></div>
</header>
<nav class="tabs" aria-label="Views">
 <button data-view="overview">Overview</button>
 <button data-view="paths">Attack Paths</button>
 <button data-view="findings">Findings</button>
</nav>
<main>
 <section id="v-overview" class="view"></section>
 <section id="v-paths" class="view"></section>
 <section id="v-findings" class="view"></section>
</main>
<footer>__FOOTER__</footer>
<script id="data" type="application/json">/*__DATA__*/</script>
<script>
"use strict";
var D = JSON.parse(document.getElementById("data").textContent);
var SEV = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
var SEVC = {CRITICAL:"var(--crit)",HIGH:"var(--high)",MEDIUM:"var(--med)",LOW:"var(--low)",INFO:"var(--info)"};
var VIEWS = ["overview","paths","findings"];
var G = D.graph;
var S = {route: D.paths.length ? 0 : -1, edge: null, node: null};
var F = {sev: "ALL", q: "", open: {}, sortK: "severity", sortDir: 1};

function esc(s){s=(s==null?"":String(s));return s.replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];});}
function $(id){return document.getElementById(id);}
function each(sel,fn){Array.prototype.forEach.call(document.querySelectorAll(sel),fn);}
function short(s){s=s||"";var i=s.indexOf("@");return i>0?s.slice(0,i):s;}
function plural(n,w){return n+" "+w+(n===1?"":"s");}
function pill(s){s=s||"INFO";return '<span class="pill sev-'+s+'">'+s+'</span>';}
function bySev(a,b){return SEV.indexOf(a.severity||"INFO")-SEV.indexOf(b.severity||"INFO");}
function uniq(a){var o=[];a.forEach(function(x){if(o.indexOf(x)<0)o.push(x);});return o;}

var ICON = {user:"👤",group:"👥",computer:"🖥️",domain:"🏛️",principal:"🔑"};
var TYPE = {user:"User",group:"Group",computer:"Computer",domain:"Domain",principal:"Principal"};
var RIGHTS = {genericall:"GenericAll",genericwrite:"GenericWrite",writedacl:"WriteDacl",
  writeowner:"WriteOwner",owns:"Owns",allextendedrights:"AllExtendedRights",
  addkeycredentiallink:"AddKeyCredentialLink",writespn:"WriteSPN"};
var ELABEL = {MemberOf:"Member of",AdminTo:"Admin to",HasSession:"Has session",
  ForceChangePassword:"Reset password",AddMember:"Add member",DCSync:"DCSync",
  Unconstrained:"Unconstrained deleg.",ConstrainedDeleg:"Constrained deleg."};
function edgeLabel(e){
  if(e.type==="ACL"){var r=String(e.detail||"").split(" ")[0];return RIGHTS[r]||r||"ACL";}
  return ELABEL[e.type]||e.type;
}
function explain(e){
  var a="<b>"+esc(short(e.from))+"</b>", b="<b>"+esc(short(e.to))+"</b>";
  switch(e.type){
    case "MemberOf": return a+" is a member of "+b+" and inherits all of its rights.";
    case "AdminTo": return a+" is a local administrator on "+b+".";
    case "HasSession": return b+" is signed in to "+a+", so their credentials are in memory there.";
    case "ForceChangePassword": return a+" can reset "+b+"'s password without knowing the current one.";
    case "AddMember": return a+" can add members to "+b+", including itself.";
    case "ACL": return a+" holds <b>"+esc(edgeLabel(e))+"</b> over "+b+", enough to take control of it.";
    case "DCSync": return a+" can replicate secrets from the domain controllers, including the krbtgt hash.";
    case "Unconstrained": return a+" is trusted for unconstrained delegation: if a domain controller is made to authenticate to it, the DC's ticket can be captured.";
    case "ConstrainedDeleg": return a+" can impersonate users to services on "+b+" (S4U delegation).";
  }
  return a+" → "+b+" ("+esc(e.type)+").";
}
function fixText(e){
  var a=short(e.from), b=short(e.to);
  switch(e.type){
    case "MemberOf": return "Remove "+a+" from "+b+".";
    case "AdminTo": return "Remove "+a+" from the local Administrators group on "+b+" (use Windows LAPS for local admin).";
    case "HasSession": return "Keep "+b+" off "+a+": Tier-0 accounts should only sign in to Tier-0 systems.";
    case "ForceChangePassword": return "Remove the password-reset right "+a+" holds on "+b+".";
    case "AddMember": return "Remove "+a+"'s right to change the membership of "+b+".";
    case "ACL": return "Remove the "+edgeLabel(e)+" permission "+a+" holds on "+b+".";
    case "DCSync": return "Remove replication rights (Get-Changes / Get-Changes-All) from "+a+".";
    case "Unconstrained": return "Disable unconstrained delegation on "+a+" (use constrained or resource-based delegation).";
    case "ConstrainedDeleg": return "Restrict what "+a+" may delegate to on "+b+".";
  }
  return "Remove this relationship.";
}
function edgeCmd(e,cmd){return e&&e.type==="MemberOf"?"":cmdBlock(cmd);}  // membership: nothing to run
function cmdBlock(cmd){
  var lines=String(cmd||"").split("\n"), notes=[], run=[];
  lines.forEach(function(l){var t=l.trim();if(!t)return;
    if(t.charAt(0)==="#")notes.push(t.replace(/^#\s*/,""));else run.push(t);});
  if(!notes.length&&!run.length)return "";
  var h='<div class="lab">Validate <span class="muted" style="text-transform:none;letter-spacing:0;font-weight:400">(authorized testing only)</span></div>';
  notes.forEach(function(n){h+='<div class="muted small">'+esc(n)+'</div>';});
  run.forEach(function(c){h+='<div class="cmd"><code>'+esc(c)+'</code><button type="button" data-copy="'+esc(c)+'">copy</button></div>';});
  return h;
}
function edgeById(id){for(var i=0;i<G.edges.length;i++)if(G.edges[i].id===id)return G.edges[i];return null;}
function nodeById(id){for(var i=0;i<G.nodes.length;i++)if(G.nodes[i].id===id)return G.nodes[i];return null;}
function edgeFor(s){for(var i=0;i<G.edges.length;i++){var e=G.edges[i];
  if(e.from===s.from&&e.to===s.to&&e.type===s.type&&(e.detail||"")===(s.detail||""))return e;}return null;}
function routeLinks(list){return list.map(function(i){return '<a href="#" data-route="'+i+'">Route '+(i+1)+'</a>';}).join(", ");}
function tokens(s){var out=[];String(s||"").split(/\s*(?:→|,)\s*/).forEach(function(t){
  t=t.trim();if(!t)return;var a=t.indexOf("@"),b=a>=0?t.indexOf("@",a+1):-1;
  if(b>0){out.push(t.slice(0,b));out.push(t.slice(b+1));}else out.push(t);});
  return out.map(function(x){return x.toUpperCase();});}
function findingsFor(ids){var want=ids.map(function(x){return String(x).toUpperCase();});
  return D.findings.filter(function(f){var tk=tokens(f.affected);
    (f.evidence||[]).forEach(function(e){tk=tk.concat(tokens(e.object));});
    return want.some(function(w){return tk.indexOf(w)>=0;});}).sort(bySev);}
function relatedFindings(ids){var fs=findingsFor(ids);
  if(!fs.length)return '<div class="lab">Related findings</div><p class="muted small">None directly on this item.</p>';
  return '<div class="lab">Related findings ('+fs.length+')</div><ul class="flist">'+fs.slice(0,8).map(function(f){
    return '<li>'+pill(f.severity)+' <a href="#" data-find="'+esc(f.id)+'">'+esc(f.title)+'</a></li>';}).join("")+'</ul>';}
function copyText(t,btn){
  function done(){var o=btn.textContent;btn.textContent="copied ✓";setTimeout(function(){btn.textContent=o;},1300);}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,fallback);}else fallback();
  function fallback(){var ta=document.createElement("textarea");ta.value=t;ta.style.position="fixed";ta.style.opacity="0";
    document.body.appendChild(ta);ta.select();try{document.execCommand("copy");done();}catch(x){}document.body.removeChild(ta);}
}

// ── Header + tabs ───────────────────────────────────────────────────────────
(function(){
  var m=D.meta;
  $("hmeta").innerHTML="Domain <b>"+esc(m.domain)+"</b> · DC "+esc(m.dc)+" · "+esc(m.generated)+" · "+plural(m.total,"finding");
  var h="";SEV.forEach(function(s){var n=m.counts[s]||0;if(!n)return;
    h+='<div class="tile"><b style="color:'+SEVC[s]+'">'+n+'</b><span>'+s+'</span></div>';});
  $("tiles").innerHTML=h;
})();
function show(v){
  if(VIEWS.indexOf(v)<0)v=D.default_view||"overview";
  each("nav.tabs button",function(b){b.classList.toggle("active",b.getAttribute("data-view")===v);});
  VIEWS.forEach(function(x){$("v-"+x).classList.toggle("active",x===v);});
  if(v==="paths")drawGraph();
}
each("nav.tabs button",function(b){b.onclick=function(){var v=b.getAttribute("data-view");
  if(location.hash==="#"+v)show(v);else location.hash=v;};});
window.addEventListener("hashchange",function(){show(location.hash.slice(1));});

// ── Overview ────────────────────────────────────────────────────────────────
(function(){
  var m=D.meta,h='<div class="grid">';
  h+='<div class="card"><div class="lab">Risk summary</div><table>';
  SEV.forEach(function(s){h+='<tr><td>'+pill(s)+'</td><td>'+(m.counts[s]||0)+'</td></tr>';});
  h+='</table>';
  if(m.warnings&&m.warnings.length){h+='<div class="lab">Import warnings</div><ul>';
    m.warnings.forEach(function(w){h+='<li class="muted">⚠️ '+esc(w)+'</li>';});h+='</ul>';}
  h+='<div class="lab">Sources</div><div class="muted">'+esc((m.sources||[]).join(", ")||"—")+'</div></div>';
  h+='<div class="card"><div class="lab">Attack paths</div>';
  if(D.paths.length){
    var chokes=G.edges.filter(function(e){return e.choke;}).length;
    var starts=uniq(D.paths.map(function(p){return short(p.start);}));
    h+='<h3>'+plural(D.paths.length,"route")+' from '+esc(starts.join(", "))+' to the target</h3>'
      +'<p class="muted">Shortest: '+plural(D.paths[0].hops,"step")+'. '
      +(chokes?'<span class="red">'+plural(chokes,"choke point")+'</span> — '+(chokes===1?'one fix breaks':'fixing any one breaks')+' every route.':'No single fix breaks every route.')+'</p>'
      +'<a class="btn" href="#paths">Explore the attack paths →</a>';
  }else h+='<p class="muted">No attack path found from the chosen foothold. Provide --owned, or collect session and local-admin data (SharpHound -c All).</p>';
  h+='</div>';
  h+='<div class="card"><div class="lab">Top exposures</div><table>';
  D.findings.slice().sort(bySev).slice(0,8).forEach(function(f){
    h+='<tr><td>'+pill(f.severity)+'</td><td><a href="#" data-find="'+esc(f.id)+'">'+esc(f.title)+'</a></td></tr>';});
  h+='</table></div>';
  h+='<div class="card"><div class="lab">MITRE ATT&amp;CK coverage</div><table><tr><th>Technique</th><th class="hm">Name</th><th>Max</th><th>#</th></tr>';
  (D.mitre||[]).forEach(function(t){h+='<tr><td><a href="https://attack.mitre.org/techniques/'+t.id.replace(".","/")+'/" target="_blank" rel="noopener">'+t.id+'</a></td>'
    +'<td class="hm">'+esc(t.name)+'</td><td>'+pill(t.max_severity)+'</td><td>'+t.count+'</td></tr>';});
  h+='</table></div></div>';
  $("v-overview").innerHTML=h;
})();

// ── Attack paths ────────────────────────────────────────────────────────────
(function(){
  if(!G.nodes.length){$("v-paths").innerHTML='<div class="card"><h2>Attack paths</h2><p class="muted">No attack path was computed for this run. Provide a foothold with --owned USER@DOMAIN, or collect session and local-admin data (SharpHound -c All).</p></div>';return;}
  $("v-paths").innerHTML='<div class="phead"><div><h2>Attack paths</h2><div class="psum" id="psum"></div></div><div class="chips" id="routes"></div></div>'
    +'<div class="gwrap" id="gbox"><svg id="gsvg" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Attack path graph"></svg></div>'
    +'<div class="legend"><span><i class="sq start"></i>Foothold</span><span><i class="sq goal"></i>Target</span>'
    +'<span><i class="ln"></i>Selected route</span><span><i class="ln choke"></i>✂ Choke point</span>'
    +'<span><i class="ln dash"></i>Inferred step</span><span>Click any node or relationship to inspect it</span></div>'
    +'<div class="pgrid"><div class="card" id="walk"></div><div class="side"><div class="card" id="inspect"></div><div class="card" id="fix"></div></div></div>';
  $("gsvg").addEventListener("click",function(){if(S.edge!==null||S.node!==null){S.edge=null;S.node=null;renderPaths();}});
})();

function renderPaths(){if(!G.nodes.length)return;renderRoutes();renderSummary();drawGraph();renderWalk();renderInspector();renderFix();}
function renderRoutes(){
  var h='<button type="button" class="chip'+(S.route<0?' on':'')+'" data-route="-1">All routes</button>';
  D.paths.forEach(function(p,i){h+='<button type="button" class="chip'+(S.route===i?' on':'')+'" data-route="'+i+'">Route '+(i+1)+' · '
    +plural(p.hops,"step")+(p.inferred_steps?' · inferred':'')+'</button>';});
  $("routes").innerHTML=h;
}
function renderSummary(){
  var starts=uniq(D.paths.map(function(p){return short(p.start);}));
  var goals=uniq(D.paths.map(function(p){return short(p.goal);}));
  var chokes=G.edges.filter(function(e){return e.choke;}).length;
  $("psum").innerHTML=plural(D.paths.length,"route")+' from <b>'+esc(starts.join(", "))+'</b> to <b>'+esc(goals.join(", "))+'</b>'
    +' · shortest '+plural(D.paths[0].hops,"step")+' · '
    +(chokes?'<span class="red">'+plural(chokes,"choke point")+'</span>':'no single choke point');
}
function marker(id,col){return '<marker id="'+id+'" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="'+col+'"/></marker>';}
function drawGraph(){
  var box=$("gbox"),svg=$("gsvg");if(!box||!svg||!G.nodes.length)return;
  var W=box.clientWidth;if(!W)return;             // hidden: drawn when shown
  var cols={},maxD=0,maxR=0,P={},nW,nH=54,svgW,svgH,rowH,top,r=S.route;
  G.nodes.forEach(function(n){(cols[n.depth]=cols[n.depth]||[]).push(n);if(n.depth>maxD)maxD=n.depth;});
  // Left-to-right when every column fits at a readable width; otherwise top-to-bottom.
  var V=W<(maxD+1)*236+24;
  Object.keys(cols).forEach(function(d){
    cols[d].sort(function(a,b){return (Math.min.apply(null,a.paths)-Math.min.apply(null,b.paths))||(a.id<b.id?-1:a.id>b.id?1:0);});
    if(cols[d].length>maxR)maxR=cols[d].length;});
  if(!V){
    var ncol=maxD+1,colW=Math.max(236,(W-24)/ncol);rowH=112;top=42;
    nW=Math.min(212,colW-100);svgW=Math.max(W-2,Math.ceil(ncol*colW)+24);svgH=top+maxR*rowH+6;
    Object.keys(cols).forEach(function(d){var L=cols[d],off=(maxR-L.length)*rowH/2;
      L.forEach(function(n,i){var cx=12+d*colW+colW/2,cy=top+off+i*rowH+rowH/2-8;
        P[n.id]={x:cx-nW/2,y:cy-nH/2,cx:cx,cy:cy};});});
  }else{
    rowH=134;top=34;svgW=W-2;svgH=top+(maxD+1)*rowH-40;
    nW=Math.min(220,(svgW-16)/maxR-12);
    Object.keys(cols).forEach(function(d){var L=cols[d],slot=(svgW-16)/L.length;
      L.forEach(function(n,i){var cx=8+slot*i+slot/2,cy=top+d*rowH+nH/2;
        P[n.id]={x:cx-nW/2,y:cy-nH/2,cx:cx,cy:cy};});});
  }
  var fan={};G.edges.forEach(function(e){fan[e.from]=(fan[e.from]||0)+1;});
  var h='<defs>'+marker("m-dim","#4c4c56")+marker("m-on","#C09A3C")+marker("m-choke","#E4002B")+'</defs>';
  G.edges.forEach(function(e){
    var a=P[e.from],b=P[e.to];if(!a||!b)return;
    var x1,y1,x2,y2,c1x,c1y,c2x,c2y;
    if(!V){x1=a.x+nW;y1=a.cy;x2=b.x-3;y2=b.cy;var dx=Math.max(48,Math.abs(x2-x1)/2);c1x=x1+dx;c1y=y1;c2x=x2-dx;c2y=y2;}
    else{x1=a.cx;y1=a.y+nH;x2=b.cx;y2=b.y-3;var dy=Math.max(36,Math.abs(y2-y1)/2);c1x=x1;c1y=y1+dy;c2x=x2;c2y=y2-dy;}
    var d="M"+x1.toFixed(1)+","+y1.toFixed(1)+" C"+c1x.toFixed(1)+","+c1y.toFixed(1)+" "+c2x.toFixed(1)+","+c2y.toFixed(1)+" "+x2.toFixed(1)+","+y2.toFixed(1);
    var on=r<0||e.paths.indexOf(r)>=0;
    var cls="edge"+(on?" on":" dim")+(e.choke?" choke":"")+(e.trust==="inferred"?" inferred":"")+(S.edge===e.id?" sel":"");
    var mk=e.choke?"m-choke":(on?"m-on":"m-dim");
    var t=fan[e.from]>1?0.64:0.5,u=1-t,k0=u*u*u,k1=3*u*u*t,k2=3*u*t*t,k3=t*t*t;
    var mx=k0*x1+k1*c1x+k2*c2x+k3*x2,my=k0*y1+k1*c1y+k2*c2y+k3*y2;
    var lab=(e.choke?"✂ ":"")+edgeLabel(e)+(e.trust==="inferred"?" (inferred)":"");
    var pw=Math.round(lab.length*6.5+18),ph=21;
    h+='<g class="'+cls+'" data-edge="'+e.id+'" tabindex="0" role="button" aria-label="'+esc(short(e.from)+" "+edgeLabel(e)+" "+short(e.to))+'">'
      +'<path class="line" d="'+d+'" marker-end="url(#'+mk+')"/><path class="flow" d="'+d+'"/><path class="hit" d="'+d+'"/>'
      +'<g class="pill" transform="translate('+(mx-pw/2).toFixed(1)+','+(my-ph/2).toFixed(1)+')"><rect width="'+pw+'" height="'+ph+'" rx="10.5"/>'
      +'<text x="'+(pw/2)+'" y="14.5" text-anchor="middle">'+esc(lab)+'</text></g></g>';
  });
  G.nodes.forEach(function(n){
    var p=P[n.id],on=r<0||n.paths.indexOf(r)>=0;
    var cls="node "+n.kind+(on?"":" dim")+(S.node===n.id?" sel":"");
    var avail=nW-58,cw=7.9,lbl=n.label,maxc=Math.max(4,Math.floor(avail*1.3/cw));
    if(lbl.length>maxc)lbl=lbl.slice(0,maxc-1)+"…";
    var fit=lbl.length*cw>avail?' textLength="'+avail.toFixed(0)+'" lengthAdjust="spacingAndGlyphs"':'';
    h+='<g class="'+cls+'" data-node="'+esc(n.id)+'" tabindex="0" role="button" aria-label="'+esc(TYPE[n.otype]+" "+n.id)+'">'
      +(n.kind!=="mid"?'<text class="badge" x="'+(p.x+3).toFixed(1)+'" y="'+(p.y-8).toFixed(1)+'">'+(n.kind==="start"?"FOOTHOLD":"TARGET")+'</text>':'')
      +'<rect class="box" x="'+p.x.toFixed(1)+'" y="'+p.y.toFixed(1)+'" width="'+nW.toFixed(1)+'" height="'+nH+'" rx="12"/>'
      +'<circle class="icbg" cx="'+(p.x+25).toFixed(1)+'" cy="'+p.cy.toFixed(1)+'" r="16"/>'
      +'<text class="ic" x="'+(p.x+25).toFixed(1)+'" y="'+(p.cy+5.5).toFixed(1)+'" text-anchor="middle">'+(ICON[n.otype]||"🔑")+'</text>'
      +'<text class="lbl" x="'+(p.x+49).toFixed(1)+'" y="'+(p.cy-2).toFixed(1)+'"'+fit+'>'+esc(lbl)+'</text>'
      +'<text class="sub" x="'+(p.x+49).toFixed(1)+'" y="'+(p.cy+14).toFixed(1)+'">'+esc(TYPE[n.otype]||"Principal")+'</text></g>';
  });
  svg.setAttribute("viewBox","0 0 "+svgW+" "+svgH);svg.setAttribute("width",svgW);svg.setAttribute("height",svgH);
  svg.innerHTML=h;
  each("#gsvg [data-edge]",function(el){
    el.onclick=function(ev){ev.stopPropagation();S.edge=+el.getAttribute("data-edge");S.node=null;renderPaths();};
    el.onkeydown=function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();el.onclick(ev);}};});
  each("#gsvg [data-node]",function(el){
    el.onclick=function(ev){ev.stopPropagation();S.node=el.getAttribute("data-node");S.edge=null;renderPaths();};
    el.onkeydown=function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();el.onclick(ev);}};});
}
function renderWalk(){
  var el=$("walk"),r=S.route;
  if(!D.paths.length){el.innerHTML='<p class="muted">No attack route found.</p>';return;}
  if(r<0){
    el.innerHTML='<div class="lab">All routes</div><h3>'+plural(D.paths.length,"route")+' to the target</h3>'
      +D.paths.map(function(p,i){return '<div class="rcard"><b>Route '+(i+1)+'</b> · '+plural(p.hops,"step")+' · '
        +esc(short(p.start))+' <span class="arrow">→</span> '+esc(short(p.goal))
        +(p.inferred_steps?' · <span class="amber">'+p.inferred_steps+' inferred</span>':'')
        +'<div class="muted small">'+esc(p.rationale||"")+'</div><a href="#" data-route="'+i+'">Walk through this route →</a></div>';}).join("");
    return;}
  var p=D.paths[r];
  var h='<div class="lab">Route '+(r+1)+' — step by step</div><h3>'+esc(short(p.start))+' <span class="arrow">→</span> '+esc(short(p.goal))+'</h3>'
    +'<p class="muted small">'+plural(p.hops,"step")+' · '+(p.inferred_steps?p.inferred_steps+' inferred step(s) need an extra action to work':'every step is a relationship observed in the data')+'</p><ol class="steps">';
  p.steps.forEach(function(s,i){var e=edgeFor(s),cmd=(p.commands||[])[i]||"";
    h+='<li class="step'+(e&&S.edge===e.id?' sel':'')+'"'+(e?' data-edge-sel="'+e.id+'"':'')+'>'
      +'<div class="stop"><span class="num">'+(i+1)+'</span><span><b>'+esc(short(s.from))+'</b> <span class="rel">'+esc(e?edgeLabel(e):s.type)+'</span> <b>'+esc(short(s.to))+'</b></span>'
      +(e&&e.choke?'<span class="tag t-choke">✂ choke point</span>':'')+(s.trust==="inferred"?'<span class="tag amber">inferred</span>':'')+'</div>'
      +'<p>'+(e?explain(e):esc(s.detail||""))+'</p>'+edgeCmd(e,cmd)+'</li>';});
  h+='</ol><div class="reached">🎯 Target reached: <b>'+esc(p.goal)+'</b></div>'
    +'<p class="muted small"><b>Why this ranks #'+(r+1)+':</b> '+esc(p.rationale||"")+'</p>';
  el.innerHTML=h;
}
function renderInspector(){
  var el=$("inspect");
  var e=S.edge!==null?edgeById(S.edge):null, n=S.node!==null?nodeById(S.node):null;
  if(e){
    el.innerHTML='<div class="lab">Relationship</div><h3>'+esc(short(e.from))+' <span class="arrow">→</span> '+esc(short(e.to))+'</h3>'
      +'<div><span class="tag t-rel">'+esc(edgeLabel(e))+'</span><span class="tag">'+(e.trust==="inferred"?"inferred":"observed")+'</span>'
      +(e.choke?'<span class="tag t-choke">✂ choke point</span>':'')+'</div>'
      +'<p>'+explain(e)+'</p>'
      +(e.trust==="inferred"?'<p class="muted small">Inferred: the data makes this step possible, but it needs an extra action (coercion or delegation abuse) to work.</p>':'')
      +edgeCmd(e,e.command)
      +'<div class="lab">Remediation impact</div><p>'+(e.choke?'<b class="red">✂ Choke point.</b> Removing this relationship breaks every route shown.'
        :(e.alt?'Another route remains if only this is fixed.':'Not analysed for this run.'))+'</p>'
      +'<div class="lab">Fix</div><p>'+esc(fixText(e))+'</p>'
      +'<div class="lab">On routes</div><p>'+routeLinks(e.paths)+'</p>'+relatedFindings([e.from,e.to]);
    return;}
  if(n){
    var role=n.kind==="start"?"Foothold — where the routes begin.":(n.kind==="goal"?"Target — the asset these routes reach.":"Stepping stone on the way to the target.");
    el.innerHTML='<div class="lab">'+esc(TYPE[n.otype]||"Principal")+'</div><h3>'+(ICON[n.otype]||"")+' '+esc(n.id)+'</h3>'
      +'<p class="muted">'+role+'</p><div class="lab">On routes</div><p>'+routeLinks(n.paths)+'</p>'+relatedFindings([n.id]);
    return;}
  el.innerHTML='<div class="lab">Inspector</div><p class="muted">Click any node or relationship in the graph to see what it means, how to validate it, and how to fix it.</p>';
}
function renderFix(){
  var chokes=G.edges.filter(function(e){return e.choke;}),others=G.edges.filter(function(e){return !e.choke;});
  var h='<div class="lab">Remediation</div><h3>✂ Fix this first</h3>';
  if(chokes.length){h+='<p class="muted small">'+(chokes.length===1?'This one change breaks':'Any one of these changes breaks')+' every route shown:</p><ol class="fixes">'
    +chokes.map(function(e){return '<li><a href="#" data-edge-sel="'+e.id+'">'+esc(fixText(e))+'</a></li>';}).join("")+'</ol>';}
  else h+='<p class="muted small">No single change breaks every route. Work through the fixes below, starting with Route 1.</p>';
  if(others.length){h+='<div class="lab">Also on these routes</div><p class="muted small">Each closes a route, but another route stays open:</p><ul class="fixes">'
    +others.map(function(e){return '<li><a href="#" data-edge-sel="'+e.id+'">'+esc(fixText(e))+'</a></li>';}).join("")+'</ul>';}
  $("fix").innerHTML=h;
}

// ── Findings ────────────────────────────────────────────────────────────────
(function(){
  var h='<h2>Findings</h2><div class="controls"><span class="fbtn active" data-sev="ALL">All</span>';
  SEV.forEach(function(s){if(D.meta.counts[s])h+='<span class="fbtn" data-sev="'+s+'">'+s+'</span>';});
  h+='<input id="fq" type="search" placeholder="Search title, affected object or rule…" aria-label="Search findings"></div>'
    +'<div class="tscroll"><table id="ftab"><thead><tr><th data-k="severity">Severity</th><th class="hm" data-k="score">Score</th>'
    +'<th class="hm" data-k="confidence">Conf.</th><th class="hm" data-k="rule_id">Rule</th><th data-k="affected">Affected</th><th>Title</th></tr></thead><tbody></tbody></table></div>';
  $("v-findings").innerHTML=h;
  each("#v-findings .fbtn",function(b){b.onclick=function(){F.sev=b.getAttribute("data-sev");syncFilterUI();renderFindings();};});
  $("fq").oninput=function(){F.q=this.value;renderFindings();};
  each("#ftab th[data-k]",function(th){th.onclick=function(){var k=th.getAttribute("data-k");
    if(F.sortK===k)F.sortDir=-F.sortDir;else{F.sortK=k;F.sortDir=1;}renderFindings();};});
  renderFindings();
})();
function syncFilterUI(){each("#v-findings .fbtn",function(x){x.classList.toggle("active",x.getAttribute("data-sev")===F.sev);});$("fq").value=F.q;}
function findingDetail(f){
  var h="";
  if(f.description)h+='<p>'+esc(f.description)+'</p>';
  if(f.confidence)h+='<div class="muted small">Confidence <b>'+esc(f.confidence)+'</b> — '+esc(f.confidence_reason||"")+'</div>';
  if(f.evidence&&f.evidence.length){h+='<div class="lab">Evidence ('+f.evidence.length+')</div><ul>';
    f.evidence.slice(0,60).forEach(function(e){h+='<li><code>'+esc(e.object)+'</code>'+(e.detail?' — '+esc(e.detail):'')
      +' <span class="muted small">('+esc(e.source)+(e.file?", "+esc(e.file):"")+')</span></li>';});
    if(f.evidence.length>60)h+='<li class="muted">+'+(f.evidence.length-60)+' more</li>';h+='</ul>';}
  if(f.commands&&f.commands.length)h+=cmdBlock(f.commands.join("\n"));
  if(f.remediation&&f.remediation.length){h+='<div class="lab">Remediation</div><ul>';f.remediation.forEach(function(x){h+='<li>'+esc(x)+'</li>';});h+='</ul>';}
  if(f.detection&&f.detection.length){h+='<div class="lab">Detection</div><ul>';f.detection.forEach(function(x){h+='<li>'+esc(x)+'</li>';});h+='</ul>';}
  if(f.mitre&&f.mitre.length){h+='<div class="lab">MITRE ATT&amp;CK</div><div>'+f.mitre.map(function(m){
    return '<a href="https://attack.mitre.org/techniques/'+m.id.replace(".","/")+'/" target="_blank" rel="noopener">'+m.id+'</a> '+esc(m.name);}).join("<br>")+'</div>';}
  return h;
}
function renderFindings(){
  var rows=D.findings.filter(function(f){
    if(F.sev!=="ALL"&&(f.severity||"INFO")!==F.sev)return false;
    if(F.q){var s=(f.title+" "+f.affected+" "+(f.rule_id||f.type)).toLowerCase();if(s.indexOf(F.q.toLowerCase())<0)return false;}
    return true;});
  rows.sort(function(a,b){
    if(F.sortK==="severity")return bySev(a,b)*F.sortDir;
    if(F.sortK==="score")return ((b.score||0)-(a.score||0))*F.sortDir;
    return String(a[F.sortK]||"").localeCompare(String(b[F.sortK]||""))*F.sortDir;});
  var out="";
  rows.forEach(function(f){var open=!!F.open[f.id];
    out+='<tr class="frow'+(open?' open':'')+'" data-fid="'+esc(f.id)+'"><td>'+pill(f.severity)+'</td><td class="hm">'+(f.score==null?"":f.score)+'</td>'
      +'<td class="hm muted">'+esc(f.confidence||"")+'</td><td class="hm"><code>'+esc(f.rule_id||f.type)+'</code></td>'
      +'<td class="muted">'+esc(f.affected)+'</td><td>'+esc(f.title)+'</td></tr>'
      +'<tr class="detail" style="display:'+(open?'table-row':'none')+'"><td colspan="6">'+findingDetail(f)+'</td></tr>';});
  var tb=document.querySelector("#ftab tbody");
  tb.innerHTML=out||'<tr><td colspan="6" class="muted">No findings match.</td></tr>';
  each("#ftab .frow",function(tr){tr.onclick=function(ev){if(ev.target.closest("[data-copy],a"))return;
    var id=tr.getAttribute("data-fid");F.open[id]=!F.open[id];renderFindings();};});
}
function openFinding(id){
  F.sev="ALL";F.q="";F.open={};F.open[id]=true;syncFilterUI();renderFindings();
  if(location.hash!=="#findings")location.hash="findings";else show("findings");
  setTimeout(function(){var tr=document.querySelector('#ftab tr[data-fid="'+(window.CSS&&CSS.escape?CSS.escape(id):id)+'"]');
    if(tr)tr.scrollIntoView({behavior:"smooth",block:"center"});},60);
}

// ── Global interactions ─────────────────────────────────────────────────────
document.addEventListener("click",function(ev){
  var t=ev.target,b;
  if(!t||!t.closest)return;
  if((b=t.closest("[data-copy]"))){ev.preventDefault();ev.stopPropagation();copyText(b.getAttribute("data-copy"),b);return;}
  if((b=t.closest("[data-route]"))){ev.preventDefault();S.route=+b.getAttribute("data-route");S.edge=null;S.node=null;
    renderPaths();if(location.hash!=="#paths")location.hash="paths";return;}
  if((b=t.closest("[data-edge-sel]"))){ev.preventDefault();S.edge=+b.getAttribute("data-edge-sel");S.node=null;renderPaths();
    var gb=$("gbox");if(gb&&gb.getBoundingClientRect().top<0)gb.scrollIntoView({behavior:"smooth",block:"start"});return;}
  if((b=t.closest("[data-find]"))){ev.preventDefault();openFinding(b.getAttribute("data-find"));return;}
});
var _rt;window.addEventListener("resize",function(){clearTimeout(_rt);_rt=setTimeout(function(){
  if($("v-paths").classList.contains("active"))drawGraph();},120);});
renderPaths();
show(location.hash.slice(1)||D.default_view||"overview");
</script>
</body></html>"""
