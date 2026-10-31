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
TOOL = "HorusEye v2.3"


class ReportGenerator:
    def __init__(self, findings: list, domain_data: dict, console=None,
                 generated_at: str = None):
        self.findings = findings
        self.domain_data = domain_data
        self.attack_paths = []        # set by the CLI when --graph/--explorer runs
        self.remediation = []         # per-edge remediation impact for the shortest path
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

        paths_block = self._html_paths()

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

    def _html_card(self, f: dict) -> str:
        sev = (f.get("severity") or "INFO").upper()
        hexc = SEV_HEX.get(sev, "#888")
        esc = html.escape
        cmds = "".join(f"<pre>{esc(c)}</pre>" for c in f.get("commands", []))
        mitre = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{m["id"].replace(".", "/")}/" '
            f'target="_blank">{m["id"]}</a>' for m in f.get("mitre", []))
        rem = "".join(f"<li>{esc(r)}</li>" for r in f.get("remediation", []))
        det = "".join(f"<li>{esc(d)}</li>" for d in f.get("detection", []))
        score = f.get("score")
        conf = (f.get("confidence") or "").upper()
        ev_items = f.get("evidence", []) or []
        ev_html = ""
        if ev_items:
            rows = "".join(
                f"<li><code>{esc(e.get('object',''))}</code>"
                + (f" — {esc(e.get('detail',''))}" if e.get('detail') else "")
                + f" <span class='meta'>({esc(e.get('source',''))})</span></li>"
                for e in ev_items[:50])
            more = f"<li class='meta'>+{len(ev_items)-50} more</li>" if len(ev_items) > 50 else ""
            ev_html = f'<div class="lab">Evidence ({len(ev_items)})</div><ul>{rows}{more}</ul>'
        return f"""<div class="card" style="border-left-color:{hexc}">
  <h3>{esc(f.get("title",""))}</h3>
  <div><span class="sev" style="color:{hexc}">{sev}</span>
    {f'<span class="meta"> · score {score}</span>' if score is not None else ''}
    {f'<span class="meta"> · confidence {conf}</span>' if conf else ''}
    {f'<span class="meta"> · {mitre}</span>' if mitre else ''}</div>
  <div class="aff">{esc(f.get("affected",""))}</div>
  {f'<p>{esc(f.get("description",""))}</p>' if f.get("description") else ''}
  {ev_html}
  {f'<div class="lab">Validate</div>{cmds}' if cmds else ''}
  {f'<div class="lab">Remediation</div><ul>{rem}</ul>' if rem else ''}
  {f'<div class="lab">Detection</div><ul>{det}</ul>' if det else ''}
</div>"""

    def _html_paths(self) -> str:
        if not self.attack_paths:
            return ""
        blocks = ""
        for i, p in enumerate(self.attack_paths, 1):
            chain = f'<span class="hop">{html.escape(p["start"])}</span>'
            for s in p["steps"]:
                chain += (f' <span class="edge">──{html.escape(s["type"])}──▶</span> '
                          f'<span class="hop">{html.escape(s["to"])}</span>')
            blocks += (f'<div class="path"><b>Path {i}</b> '
                       f'<span class="meta">({p["hops"]} hop(s))</span><br>{chain}</div>')
        return f"<h2>Attack Paths to Domain Admin</h2>{blocks}"

    # ── Interactive offline explorer ───────────────────────────────────────────
    def export_explorer(self, filepath: str):
        from horuseye.reports.explorer import build_explorer
        page = build_explorer(self.findings, self.attack_paths, self.remediation,
                              self.domain_data, self.generated_at)
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
            if f.get("commands"):
                out += ["**Validate:**", "```bash"] + list(f["commands"]) + ["```", ""]
            if f.get("remediation"):
                out += ["**Remediation:**"] + [f"- {r}" for r in f["remediation"]] + [""]
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
            "schema": "horuseye.report/3",
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
            "findings": self.findings,
        }
        Path(filepath).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        self._p(f"[green]📄 JSON report → {filepath}[/green]")

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
