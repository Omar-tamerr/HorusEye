"""Report generator — CLI tables, and HTML / Markdown / JSON exports.

Reports are written for two audiences at once: operators get the validation
command for each finding and the ordered attack path to Domain Admin; defenders
get the severity-ranked risk picture, MITRE ATT&CK coverage, remediation steps
and detection guidance. HTML is a self-contained dark-theme page; Markdown
embeds Mermaid attack-path diagrams and pastes cleanly into reports and wikis.
"""
import html
import json
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

SEV_COLOR = {"CRITICAL": "bold red", "HIGH": "bold yellow", "MEDIUM": "yellow",
             "LOW": "dim white", "INFO": "dim"}
SEV_HEX = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00",
           "LOW": "#88cc00", "INFO": "#888888"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
TOOL = "HorusEye v2.5"


class ReportGenerator:
    def __init__(self, findings: list, domain_data: dict, console=None,
                 generated_at: str = None):
        self.findings = findings
        self.domain_data = domain_data
        self.attack_paths = []        # set by the CLI when --graph/--explorer runs
        self.remediation = []         # per-edge remediation impact for the shortest path
        self.remediation_plans = []   # alternative fix plans, each breaking every route
        self.keep = []                # relationships marked business-required (--keep)
        self.conditional_paths = []   # routes needing an assumed / not-assessed step
        self.exposure = None          # domain-wide: who can reach Tier-0, and the fix
        self.retest = None            # comparison with a --diff baseline, when given
        self.quick_wins = []          # Critical/High findings that are a Low-effort fix, ranked
        self.status_summary = None    # remediation status merged from --status
        # Timestamp is injectable so reports are byte-reproducible for the same
        # input + config (e.g. CI sets SOURCE_DATE_EPOCH). Defaults to now.
        self.generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.generated_iso = generated_at or datetime.now().isoformat(timespec="seconds")
        if console is None and RICH:
            from rich.console import Console as RC
            self.console = RC()
        else:
            self.console = console

    # ── Shared summary ─────────────────────────────────────────────────────
    def _counts(self) -> dict:
        c = {s: 0 for s in SEV_ORDER}
        for f in self.findings:
            c[(f.get("severity") or "INFO").upper()] = c.get((f.get("severity") or "INFO").upper(), 0) + 1
        return c

    def _mitre(self) -> list:
        try:
            from horuseye.core.knowledge import mitre_coverage
            return mitre_coverage(self.findings)
        except Exception:
            return []

    # ── CLI ────────────────────────────────────────────────────────────────
    def print_cli_report(self, severity_filter: str = "all"):
        filtered = self._filter(severity_filter)
        if not filtered:
            self._p("[yellow]No findings to display.[/yellow]")
            return
        if RICH and self.console:
            self._print_rich(filtered)
        else:
            self._print_plain(filtered)

    # ── HTML ─────────────────────────────────────────────────────────────────
    def export_html(self, filepath: str):
        c = self._counts()
        dom = html.escape(str(self.domain_data.get("domain", "N/A")))
        dc = html.escape(str(self.domain_data.get("dc_ip", "N/A")))
        gen = self.generated_at

        tiles = "".join(
            f'<div class="tile" style="border-color:{SEV_HEX[s]}">'
            f'<div class="n" style="color:{SEV_HEX[s]}">{c[s]}</div>'
            f'<div class="l">{s}</div></div>'
            for s in SEV_ORDER if c[s]
        )

        mitre_rows = "".join(
            f'<tr><td><a href="https://attack.mitre.org/techniques/{m["id"].replace(".", "/")}/"'
            f' target="_blank">{m["id"]}</a></td><td>{html.escape(m["name"])}</td>'
            f'<td><span class="pill" style="background:{SEV_HEX[m["max_severity"]]}">'
            f'{m["max_severity"]}</span></td><td>{m["count"]}</td></tr>'
            for m in self._mitre()
        )
        mitre_block = (f'<h2>MITRE ATT&amp;CK Coverage</h2><table class="mitre">'
                       f'<tr><th>Technique</th><th>Name</th><th>Max severity</th>'
                       f'<th>Findings</th></tr>{mitre_rows}</table>') if mitre_rows else ""

        paths_block = self._html_quick_wins() + self._html_exposure() + self._html_paths()

        cards = ""
        for f in sorted(self.findings, key=lambda x: SEV_ORDER.index((x.get("severity") or "INFO").upper())):
            cards += self._html_card(f)

        page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL} Report — {dom}</title>
<style>
  :root{{--bg:#0d0d0d;--panel:#151515;--line:#262626;--fg:#e6e6e6;--muted:#9a9a9a;
         --gold:#C09A3C;--red:#E4002B;--code:#00ff9c}}
  *{{box-sizing:border-box}}
  body{{background:var(--bg);color:var(--fg);font-family:-apple-system,Segoe UI,Roboto,sans-serif;
       margin:0;padding:32px;line-height:1.5}}
  .wrap{{max-width:1100px;margin:0 auto}}
  h1{{color:var(--red);margin:0 0 4px}} h2{{color:var(--gold);border-bottom:1px solid var(--line);
       padding-bottom:6px;margin-top:40px}}
  .meta{{color:var(--muted);font-size:14px}}
  .tiles{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}
  .tile{{background:var(--panel);border:1px solid;border-radius:10px;padding:14px 22px;min-width:96px;text-align:center}}
  .tile .n{{font-size:30px;font-weight:700}} .tile .l{{font-size:12px;color:var(--muted);letter-spacing:.08em}}
  table{{width:100%;border-collapse:collapse;margin:14px 0;font-size:14px}}
  th{{background:#1c1c1c;color:var(--gold);text-align:left;padding:8px 10px;border:1px solid var(--line)}}
  td{{padding:8px 10px;border:1px solid var(--line);vertical-align:top}}
  .pill{{color:#111;font-weight:700;padding:1px 8px;border-radius:10px;font-size:12px}}
  .card{{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;
        padding:16px 20px;margin:14px 0}}
  .card h3{{margin:0 0 4px;font-size:17px}} .sev{{font-weight:700;font-size:12px;letter-spacing:.08em}}
  .aff{{color:var(--gold);font-family:ui-monospace,Consolas,monospace;font-size:13px}}
  code,pre{{background:#000;color:var(--code);border-radius:6px;font-family:ui-monospace,Consolas,monospace;font-size:13px}}
  code{{padding:2px 6px}} pre{{padding:10px 12px;overflow-x:auto;border:1px solid var(--line)}}
  .lab{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin:12px 0 4px}}
  ul{{margin:4px 0 4px 18px;padding:0}} li{{margin:2px 0}}
  a{{color:#5ab0ff}} .path{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:12px 0}}
  .hop{{font-family:ui-monospace,Consolas,monospace;font-size:13px}} .edge{{color:var(--red)}}
  footer{{color:var(--muted);font-size:12px;margin-top:40px;border-top:1px solid var(--line);padding-top:12px}}
  .xbig{{font-size:34px;font-weight:800;margin:6px 0 2px}} .xbar{{height:12px;background:#222;border-radius:6px;overflow:hidden;margin:8px 0 14px}}
  .xbar i{{display:block;height:100%;background:var(--red)}} .left{{color:var(--muted);white-space:nowrap}}
  .eff{{display:inline-block;border:1px solid;border-radius:10px;padding:0 8px;font-size:12px;font-weight:700}}
  .eff-Low{{color:#3fae6a;border-color:#1f5a35}} .eff-Medium{{color:#f0a429;border-color:#6b4a12}} .eff-High{{color:#ff6b6b;border-color:#6b1f1f}}
  .qw{{display:inline-block;background:#163a25;color:#7be3a1;border-radius:10px;padding:0 8px;font-size:12px;font-weight:700}}
  .qwrow{{background:var(--panel);border:1px solid #1f5a35;border-left:4px solid #3fae6a;border-radius:10px;padding:12px 16px;margin:10px 0}}
  .st{{font-size:12px;color:var(--muted)}} .warnfix{{color:#ff6b6b;font-weight:700}}
</style></head><body><div class="wrap">
<h1>𓂀 {TOOL} — Attack-Path Report</h1>
<div class="meta">Domain <b>{dom}</b> &nbsp;•&nbsp; DC {dc} &nbsp;•&nbsp; Generated {gen}
 &nbsp;•&nbsp; {len(self.findings)} findings</div>
<div class="tiles">{tiles}</div>
{paths_block}
{mitre_block}
<h2>Findings</h2>
{cards}
<footer>Generated by {TOOL} — authorized security testing only. 𓂀</footer>
</div></body></html>"""
        Path(filepath).write_text(page, encoding="utf-8")
        self._p(f"[green]📄 HTML report → {filepath}[/green]")

    @staticmethod
    def _first_fix(f: dict) -> str:
        opts = [o for o in f.get("fix_options") or [] if o.get("id")]
        return opts[0]["fix"] if opts else (f.get("remediation") or [""])[0]

    @staticmethod
    def _source_text(f: dict) -> str:
        parts = []
        for src in f.get("source") or []:
            bits = [src.get("collector", ""), src.get("file", ""), src.get("object", ""), src.get("sid", "")]
            parts.append(" | ".join(b for b in bits if b))
        return "; ".join(parts[:5]) + (f" (+{len(parts) - 5} more)" if len(parts) > 5 else "")

    def _html_quick_wins(self) -> str:
        esc = html.escape
        if not self.findings or "effort" not in self.findings[0]:
            return ""
        if not self.quick_wins:
            return ('<h2>Quick Wins</h2><p class="meta">No Critical or High finding is a Low-effort '
                    'fix. Start with the exposure plan and the highest-severity findings.</p>')
        rows = []
        for f in self.quick_wins:
            sev = (f.get("severity") or "").upper()
            rows.append(f'<div class="qwrow"><b>{f["quick_win_rank"]}. {esc(f.get("title", ""))}</b> '
                        f'<span class="pill" style="background:{SEV_HEX.get(sev, "#888")}">{sev}</span> '
                        f'<span class="eff eff-Low">effort Low</span>'
                        f'<div><b>Why critical:</b> {esc(f.get("why_critical", ""))}</div>'
                        f'<div><b>Why easy:</b> {esc(f.get("effort_reason", ""))}</div>'
                        f'<div><b>Do:</b> {esc(self._first_fix(f))}</div></div>')
        return ('<h2>Quick Wins</h2><p class="meta">Critical or High severity, and a Low-effort fix. '
                'Best first: the most users cut off from Tier-0.</p>' + "".join(rows))

    def _html_card(self, f: dict) -> str:
        from horuseye.core.status import LABELS
        sev = (f.get("severity") or "INFO").upper()
        hexc = SEV_HEX.get(sev, "#888")
        esc = html.escape
        cmds = "".join(f"<pre>{esc(c)}</pre>" for c in f.get("commands", []))
        mitre = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{m["id"].replace(".", "/")}/" '
            f'target="_blank">{m["id"]}</a>' for m in f.get("mitre", []))
        det = "".join(f"<li>{esc(d)}</li>" for d in f.get("detection", []))
        score = f.get("score")
        conf = (f.get("confidence") or "").upper()
        ev_items = f.get("evidence", []) or []
        ev_html = ""
        if ev_items:
            rows = "".join(
                f"<li><code>{esc(e.get('object',''))}</code>"
                + (f" ({esc(e.get('detail',''))})" if e.get('detail') else "")
                + f" <span class='meta'>[{esc(e.get('source',''))}]</span></li>"
                for e in ev_items[:50])
            more = f"<li class='meta'>+{len(ev_items)-50} more</li>" if len(ev_items) > 50 else ""
            ev_html = (f'<details><summary class="meta">Evidence ({len(ev_items)})</summary>'
                       f'<ul>{rows}{more}</ul></details>')
        effort = f.get("effort")
        todo = ""
        for o in f.get("fix_options") or []:
            todo += "<li>" + esc(o.get("fix", ""))
            if o.get("effort") and o.get("id"):
                todo += f' <span class="eff eff-{o["effort"]}">{o["effort"]}</span>'
            if o.get("users_cut_off"):
                todo += f' <span class="meta">({o["users_cut_off"]:,} users cut off)</span>'
            todo += "</li>"
        todo += "".join(f"<li>{esc(r)}</li>" for r in f.get("remediation", []))
        alt = f.get("keep_alternative")
        if alt:
            todo += ("<li>If this access is needed (<code>--keep '" + esc(alt["keep"]) + "'</code>), "
                     "the fewest changes that still cut every user off: "
                     + "; ".join(esc(c["fix"]) for c in alt["changes"]) + "</li>")
        status = ""
        if f.get("status"):
            check = ('<span class="warnfix"> · marked fixed but still found</span>'
                     if f.get("status_check") == "marked_fixed_still_found" else "")
            status = ('<div class="lab">Status</div><div class="st"><b>'
                      + esc(LABELS.get(f["status"], f["status"])) + "</b>"
                      + (" · changed " + esc(f["status_changed"]) if f.get("status_changed") else "")
                      + check + "</div>"
                      + ('<p class="st">' + esc(f["notes"]) + "</p>" if f.get("notes") else ""))
        badges = ""
        if f.get("quick_win"):
            badges += f' <span class="qw">Quick Win #{f["quick_win_rank"]}</span>'
        if effort:
            badges += f' <span class="eff eff-{effort}">effort {effort}</span>'
        ease = {"Low": "an easy", "High": "a hard"}.get(effort, "a moderate")
        why = (f'<div class="lab">Why it is critical</div><p>{esc(f["why_critical"])}</p>'
               if f.get("why_critical") else "")
        how_hard = (f'<div class="lab">Why it is {ease} fix</div><p>{esc(f.get("effort_reason", ""))}</p>'
                    if effort else "")
        conf_txt = f" · confidence {conf}: {esc(f.get('confidence_reason', ''))}" if conf else ""
        return f"""<div class="card" style="border-left-color:{hexc}">
  <h3>{esc(f.get("title",""))}</h3>
  <div><span class="sev" style="color:{hexc}">{sev}</span>{badges}
    {f'<span class="meta"> · score {score}</span>' if score is not None else ''}
    {f'<span class="meta"> · {mitre}</span>' if mitre else ''}</div>
  <div class="aff">{esc(f.get("affected",""))}</div>
  {f'<p>{esc(f.get("description",""))}</p>' if f.get("description") else ''}
  {why}
  {how_hard}
  {f'<div class="lab">What to do</div><ul>{todo}</ul>' if todo else ''}
  {f'<div class="lab">How to verify</div>{cmds}' if cmds else ''}
  <div class="lab">Source</div><p class="meta">{esc(self._source_text(f) or "detector")}{conf_txt}</p>
  {ev_html}
  {status}
  {f'<div class="lab">Detection</div><ul>{det}</ul>' if det else ''}
</div>"""

    @staticmethod
    def _html_chain(p: dict) -> str:
        chain = f'<span class="hop">{html.escape(p["start"])}</span>'
        for s in p["steps"]:
            trust = s.get("trust", "observed")
            tag = "" if trust == "observed" else f" ({html.escape(trust.replace('_', ' '))})"
            chain += (f' <span class="edge">──{html.escape(s["type"])}{tag}──▶</span> '
                      f'<span class="hop">{html.escape(s["to"])}</span>')
        return chain

    def _html_paths(self) -> str:
        out = ""
        if self.attack_paths:
            blocks = "".join(
                f'<div class="path"><b>Path {i}</b> <span class="meta">({p["hops"]} hop(s))'
                f'</span><br>{self._html_chain(p)}</div>'
                for i, p in enumerate(self.attack_paths, 1))
            out = f"<h2>Attack Paths to Domain Admin</h2>{blocks}" + self._html_plans()
        if self.conditional_paths:
            blocks = "".join(
                f'<div class="path"><b>{html.escape(p["label"])}</b> <span class="meta">'
                f'({html.escape(p["rationale"])})</span><br>{self._html_chain(p)}</div>'
                for p in self.conditional_paths)
            out += ('<h2>Conditional Routes</h2><p class="meta">These need a step that is assumed '
                    'or not assessed. They are not counted as attack paths.</p>' + blocks)
        return out

    @staticmethod
    def _exposure_goal(x: dict) -> str:
        t = x.get("targets") or ["Tier-0"]
        return "Tier-0" if t == ["Tier-0"] else ", ".join(t)

    @staticmethod
    def _users(n: int) -> str:
        return f"{n:,} user{'s' if n != 1 else ''}"

    def _html_exposure(self) -> str:
        x = self.exposure
        if not x or not x.get("computed"):
            return ""
        esc = html.escape
        pct = x["percent"]
        out = [f'<h2>Domain Exposure</h2><div class="xbig" style="color:'
               f'{"var(--red)" if pct else "#3fae6a"}">{x["users_exposed"]:,} of {x["users_total"]:,} '
               f'users ({pct:g}%)</div><div class="meta">can reach {esc(self._exposure_goal(x))}'
               + (f' — every user, through {esc(", ".join(x["via_broad_groups"]))}'
                  if x.get("via_broad_groups") else "")
               + f'</div><div class="xbar"><i style="width:{pct:g}%"></i></div>']
        plan = x.get("plan")
        if plan:
            k = len(plan["changes"])
            rows = "".join(
                f'<tr><td>{i}</td><td>{esc(c["fix"])}<br><span class="meta">{esc(c["effect"])}</span></td>'
                f'<td class="left">{self._users(c["users_after"])} left</td></tr>'
                for i, c in enumerate(plan["changes"], 1))
            out.append(f'<p><b>Fewest changes to reach 0%</b> <span class="meta">({k} change'
                       f'{"s" if k != 1 else ""}, made together)</span></p>'
                       f'<table><tr><th>#</th><th>Change</th><th>Exposed after</th></tr>{rows}</table>')
        elif x.get("plan_note") and x["users_exposed"]:
            out.append(f'<p class="meta">{esc(x["plan_note"])}</p>')
        if x.get("top_fixes"):
            rows = "".join(f'<tr><td>{esc(c["fix"])}</td><td class="left">'
                           f'{self._users(c["users_cut_off"])} cut off</td></tr>' for c in x["top_fixes"])
            out.append(f'<p><b>Biggest single fixes</b> <span class="meta">(each on its own)</span></p>'
                       f'<table><tr><th>Change</th><th>Effect</th></tr>{rows}</table>')
        out.append('<p class="meta">Counts enabled users, not Tier-0 accounts. Not modeled: '
                   + esc("; ".join(x.get("not_modeled") or [])) + '.</p>')
        return "".join(out)

    def _md_quick_wins(self) -> list:
        if not self.findings or "effort" not in self.findings[0]:
            return []
        out = ["## Quick Wins", "",
               "Critical or High severity, and a Low-effort fix. Best first: the most users "
               "cut off from Tier-0.", ""]
        if not self.quick_wins:
            return out + ["No Critical or High finding is a Low-effort fix. Start with the exposure "
                          "plan and the highest-severity findings.", ""]
        for f in self.quick_wins:
            sev = (f.get("severity") or "").upper()
            out += [f"{f['quick_win_rank']}. **{f.get('title', '')}** ({sev}, effort Low)  ",
                    f"   Why critical: {f.get('why_critical', '')}  ",
                    f"   Why easy: {f.get('effort_reason', '')}  ",
                    f"   Do: {self._first_fix(f)}", ""]
        return out

    def _md_exposure(self) -> list:
        x = self.exposure
        if not x or not x.get("computed"):
            return []
        out = ["## Domain Exposure", "",
               f"**{x['users_exposed']:,} of {x['users_total']:,} users ({x['percent']:g}%) can reach "
               f"{self._exposure_goal(x)}.**"
               + (f" Every user is exposed through {', '.join(x['via_broad_groups'])}."
                  if x.get("via_broad_groups") else ""), ""]
        plan = x.get("plan")
        if plan:
            k = len(plan["changes"])
            out += [f"### Fewest changes to reach 0% ({k} change{'s' if k != 1 else ''}, made together)", "",
                    "| # | Change | Exposed after |", "|---|---|---|"]
            out += [f"| {i} | {c['fix']} | {self._users(c['users_after'])} |"
                    for i, c in enumerate(plan["changes"], 1)]
            out.append("")
        elif x.get("plan_note") and x["users_exposed"]:
            out += [x["plan_note"], ""]
        if x.get("top_fixes"):
            out += ["### Biggest single fixes", "", "| Change | Users cut off |", "|---|---|"]
            out += [f"| {c['fix']} | {c['users_cut_off']:,} |" for c in x["top_fixes"]]
            out.append("")
        out += ["*Counts enabled users, not Tier-0 accounts. Not modeled: "
                + "; ".join(x.get("not_modeled") or []) + ".*", ""]
        return out

    @staticmethod
    def _plan_meta(p: dict) -> str:
        n, m = len(p["changes"]), p.get("memberships_removed", 0)
        return (f"{n} change{'s' if n != 1 else ''} · "
                + (f"removes {m} group membership{'s' if m != 1 else ''}" if m
                   else "no one leaves a group"))

    def _html_plans(self) -> str:
        if not self.remediation_plans:
            return ""
        esc = html.escape
        out = ['<h2>Remediation Options</h2><p class="meta">Each option breaks every route in '
               'the imported graph, including routes not shown. Mark access people need for their job '
               'with <code>--keep SRC-&gt;DST</code> and no option will remove it.</p>']
        if self.keep:
            out.append('<p class="meta">Kept as required: '
                       + esc(", ".join(k.replace("->", " → ") for k in self.keep)) + '</p>')
        for i, p in enumerate(self.remediation_plans, 1):
            items = "".join(
                f'<li>{esc(c["fix"])}<br><span class="meta">{esc(c["effect"])}'
                f'{" " + esc(c["note"]) if c.get("note") else ""}</span></li>'
                for c in p["changes"])
            out.append(f'<div class="path"><b>Option {i} · {esc(p["title"])}</b> '
                       f'<span class="meta">({esc(self._plan_meta(p))})</span><br>'
                       f'<span class="meta">{esc(p["summary"])}</span><ol>{items}</ol></div>')
        return "".join(out)

    # ── Interactive offline explorer ───────────────────────────────────────────
    def export_explorer(self, filepath: str):
        from horuseye.reports.explorer import build_explorer
        page = build_explorer(self.findings, self.attack_paths, self.remediation,
                              self.domain_data, self.generated_at,
                              plans=self.remediation_plans, keep=self.keep,
                              exposure=self.exposure)
        Path(filepath).write_text(page, encoding="utf-8")
        self._p(f"[green]🧭 Explorer → {filepath}[/green]")

    # ── Markdown (with Mermaid attack-path diagrams) ───────────────────────────
    def export_markdown(self, filepath: str):
        c = self._counts()
        d = self.domain_data
        out = [f"# {TOOL} — Attack-Path Report", ""]
        out.append(f"**Domain:** `{d.get('domain','N/A')}`  |  **DC:** `{d.get('dc_ip','N/A')}`  "
                   f"|  **Generated:** {self.generated_at}")
        out += ["", "## Summary", "",
                "| Severity | " + " | ".join(SEV_ORDER) + " |",
                "|" + "---|" * (len(SEV_ORDER) + 1),
                "| Findings | " + " | ".join(str(c[s]) for s in SEV_ORDER) + " |", ""]

        out += self._md_quick_wins()
        out += self._md_exposure()

        if self.attack_paths:
            out += ["## Attack Paths to Domain Admin", ""]
            for i, p in enumerate(self.attack_paths, 1):
                out.append(f"### Path {i} — {p['hops']} hop(s): `{p['start']}` → `{p['goal']}`")
                out += ["", "```mermaid", "graph LR"]
                nodes = [p["start"]] + [s["to"] for s in p["steps"]]
                for j in range(len(p["steps"])):
                    a, b, lbl = nodes[j], nodes[j + 1], p["steps"][j]["type"]
                    out.append(f'  {self._mid(a)}["{a}"] -->|{lbl}| {self._mid(b)}["{b}"]')
                out += ["```", ""]
                for step, cmd in zip(p["steps"], p["commands"]):
                    out.append(f"- **{step['type']}** → `{step['to']}` — {step['detail']}")
                    for line in cmd.splitlines():
                        if line.strip() and not line.strip().startswith("#"):
                            out.append(f"  ```bash\n  {line}\n  ```")
                out.append("")

        if self.conditional_paths:
            out += ["## Conditional Routes", "",
                    "These need a step that is assumed or not assessed. They are not counted as "
                    "attack paths.", ""]
            for p in self.conditional_paths:
                out += [f"### {p['label']}", "", f"*{p['rationale']}*", ""]
                for s in p["steps"]:
                    trust = s.get("trust", "observed").replace("_", " ")
                    out.append(f"- **{s['type']}** ({trust}) → `{s['to']}` — {s['detail']}")
                out += [""] + [f"> Assumption: {a}" for a in p["assumptions"]] + [""]

        if self.remediation_plans:
            out += ["## Remediation Options", "",
                    "Each option breaks every route in the imported graph, including routes "
                    "not shown. "
                    "Mark access people need for their job with `--keep 'SRC->DST'` and no "
                    "option will remove it.", ""]
            if self.keep:
                out += ["Kept as required: " + ", ".join(f"`{k}`" for k in self.keep), ""]
            for i, p in enumerate(self.remediation_plans, 1):
                out += [f"### Option {i} — {p['title']} ({self._plan_meta(p)})", "",
                        p["summary"], ""]
                for j, c in enumerate(p["changes"], 1):
                    note = f" {c['note']}" if c.get("note") else ""
                    out += [f"{j}. **{c['fix']}**  ", f"   {c['effect']}{note}"]
                out.append("")

        out += ["## Findings", ""]
        for f in sorted(self.findings, key=lambda x: SEV_ORDER.index((x.get("severity") or "INFO").upper())):
            out.append(f"### [{(f.get('severity') or 'INFO').upper()}] {f.get('title','')}")
            if f.get("score") is not None:
                out.append(f"*Score {f['score']}* · confidence {(f.get('confidence') or '').upper()} · "
                           + " ".join(m["id"] for m in f.get("mitre", [])))
            out += ["", f"**Affected:** `{f.get('affected','')}`", ""]
            ev_items = f.get("evidence", []) or []
            if ev_items:
                out.append(f"**Evidence ({len(ev_items)}):**")
                for e in ev_items[:50]:
                    d = f" — {e.get('detail','')}" if e.get('detail') else ""
                    out.append(f"- `{e.get('object','')}`{d} ({e.get('source','')})")
                if len(ev_items) > 50:
                    out.append(f"- *+{len(ev_items)-50} more*")
                out.append("")
            if f.get("description"):
                out += [f.get("description"), ""]
            if f.get("why_critical"):
                out += [f"**Why it is critical:** {f['why_critical']}", ""]
            if f.get("effort"):
                qw = f" · **Quick Win #{f['quick_win_rank']}**" if f.get("quick_win") else ""
                out += [f"**Effort: {f['effort']}**{qw}. {f.get('effort_reason', '')}", ""]
            todo = [f"- {o['fix']}" + (f" (effort {o['effort']})" if o.get("id") else "")
                    for o in f.get("fix_options") or []]
            todo += [f"- {r}" for r in f.get("remediation", [])]
            if f.get("keep_alternative"):
                alt = f["keep_alternative"]
                todo.append(f"- If this access is needed (`--keep '{alt['keep']}'`), the fewest "
                            f"changes that still cut every user off: "
                            + "; ".join(c["fix"] for c in alt["changes"]))
            if todo:
                out += ["**What to do:**"] + todo + [""]
            if f.get("commands"):
                out += ["**How to verify:**", "```bash"] + list(f["commands"]) + ["```", ""]
            src = self._source_text(f)
            if src or f.get("confidence"):
                out += [f"**Source:** {src or 'detector'} · confidence "
                        f"{(f.get('confidence') or '').upper()}", ""]
            if f.get("status") and (f["status"] != "open" or f.get("notes")):
                from horuseye.core.status import LABELS
                check = " · **marked fixed but still found**" if f.get("status_check") else ""
                changed = f" (changed {f['status_changed']})" if f.get("status_changed") else ""
                out += [f"**Status:** {LABELS.get(f['status'], f['status'])}{changed}{check}", ""]
                if f.get("notes"):
                    out += [f"> {f['notes']}", ""]
            if f.get("detection"):
                out += ["**Detection:**"] + [f"- {x}" for x in f["detection"]] + [""]
        out += ["---", f"*Generated by {TOOL} — authorized security testing only.*"]
        Path(filepath).write_text("\n".join(out), encoding="utf-8")
        self._p(f"[green]📝 Markdown report → {filepath}[/green]")

    @staticmethod
    def _mid(name: str) -> str:
        import re
        return "n" + re.sub(r"[^A-Za-z0-9]", "", name)[:24]

    # ── JSON ─────────────────────────────────────────────────────────────────
    def export_json(self, filepath: str):
        data = {
            "tool": TOOL,
            "schema": "horuseye.report/4",
            "generated": self.generated_iso,
            "author": "Omar Tamer",
            "domain": self.domain_data.get("domain", ""),
            "dc_ip": self.domain_data.get("dc_ip", ""),
            "summary": {
                "total": len(self.findings),
                "by_severity": self._counts(),
                "mitre": self._mitre(),
            },
            "parse_report": self.domain_data.get("parse_report", {}),
            "attack_paths": self.attack_paths,
            "conditional_paths": self.conditional_paths,
            "remediation_plans": self.remediation_plans,
            "keep": self.keep,
            "exposure": self.exposure,
            "quick_wins": [f.get("id") for f in self.quick_wins],
            "status": self.status_summary,
            "findings": self.findings,
        }
        if self.retest:
            data["retest"] = self.retest
        Path(filepath).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        self._p(f"[green]📄 JSON report → {filepath}[/green]")

    # ── CSV (one row per finding, for spreadsheets) ─────────────────────────
    CSV_COLUMNS = ("id", "title", "affected", "severity", "effort", "effort_reason", "quick_win",
                   "why_critical", "fix", "validation_command", "source", "status", "notes")

    @staticmethod
    def _cell(v) -> str:
        """Spreadsheet-safe text. A value starting with =, +, -, @ or a tab or
        carriage return can run as a formula in Excel, and AD names come from
        the directory, so those get a leading apostrophe."""
        s = "" if v is None else str(v)
        return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

    def export_csv(self, filepath: str):
        import csv
        from horuseye.core.status import LABELS
        sev_i = {s: i for i, s in enumerate(SEV_ORDER)}
        eff_i = {"Low": 0, "Medium": 1, "High": 2}
        rows = sorted(self.findings, key=lambda f: (
            0 if f.get("quick_win") else 1, f.get("quick_win_rank") or 0,
            sev_i.get((f.get("severity") or "INFO").upper(), 9), eff_i.get(f.get("effort"), 3),
            str(f.get("id", ""))))
        with open(filepath, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(self.CSV_COLUMNS)
            for f in rows:
                w.writerow([self._cell(v) for v in (
                    f.get("id", ""), f.get("title", ""), f.get("affected", ""),
                    (f.get("severity") or "").upper(), f.get("effort", ""), f.get("effort_reason", ""),
                    "yes" if f.get("quick_win") else "no", f.get("why_critical", ""),
                    self._first_fix(f), (f.get("commands") or [""])[0], self._source_text(f),
                    LABELS.get(f.get("status") or "open", f.get("status", "")), f.get("notes", ""))])
        self._p(f"[green]📊 CSV → {filepath}[/green]")

    # ── Helpers ────────────────────────────────────────────────────────────
    def _filter(self, severity_filter: str) -> list:
        if severity_filter == "all":
            return self.findings
        order = ["critical", "high", "medium", "low", "info"]
        idx = order.index(severity_filter.lower()) if severity_filter.lower() in order else 99
        keep = [o.upper() for o in order[:idx + 1]]
        return [f for f in self.findings if (f.get("severity") or "").upper() in keep]

    def _print_rich(self, findings: list):
        self.console.print()
        t = Table(box=box.DOUBLE_EDGE, show_header=True,
                  title=f"[bold red]𓂀 {len(findings)} Finding(s)[/bold red]",
                  border_style="red")
        t.add_column("Severity", style="bold", width=10)
        t.add_column("Score", justify="right", width=5)
        t.add_column("Type", style="cyan", width=22)
        t.add_column("Title", style="white", width=42)
        t.add_column("Affected", style="yellow", width=20)
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            color = SEV_COLOR.get(sev, "white")
            t.add_row(f"[{color}]{sev}[/{color}]", str(f.get("score", "")),
                      f.get("type", ""), f.get("title", "")[:42], f.get("affected", "")[:20])
        self.console.print(t)
        self.console.print()
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            color = SEV_COLOR.get(sev, "white")
            cmds = f.get("commands", [])
            ai = f.get("ai_narrative", "")
            rem = f.get("remediation", [])
            body = f"[bold white]Affected:[/bold white] [yellow]{f.get('affected','N/A')}[/yellow]\n"
            if ai:
                body += f"[bold white]AI:[/bold white]       [magenta]{ai}[/magenta]\n"
            body += "\n".join(f"[green]$ {c}[/green]" for c in cmds[:3])
            if rem:
                body += f"\n[dim]Fix: {rem[0]}[/dim]"
            self.console.print(Panel(
                body,
                title=f"[{color}][{sev}] {f.get('type','')} — {f.get('title','')[:55]}[/{color}]",
                border_style=color.replace("bold ", ""), padding=(0, 2)))

    def _print_plain(self, findings: list):
        print(f"\n{'='*60}  𓂀 {len(findings)} FINDINGS  {'='*10}")
        for f in findings:
            print(f"  [{(f.get('severity') or '').upper()}] {f.get('type','')} — {f.get('title','')}")
            for cmd in f.get("commands", [])[:2]:
                print(f"      $ {cmd}")
        print(f"{'='*70}\n")

    def _p(self, msg: str):
        import re
        if RICH and self.console:
            self.console.print(msg)
        else:
            print(re.sub(r"\[/?[^\]]*\]", "", msg))
