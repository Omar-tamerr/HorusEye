"""Report generator — CLI table + HTML export."""
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

SEV_COLOR = {"CRITICAL":"bold red","HIGH":"bold yellow","MEDIUM":"yellow","LOW":"dim white","INFO":"dim"}

class ReportGenerator:
    def __init__(self, findings: list, domain_data: dict, console=None):
        self.findings    = findings
        self.domain_data = domain_data
        if console is None and RICH:
            from rich.console import Console as RC
            self.console = RC()
        else:
            self.console = console

    def print_cli_report(self, severity_filter: str = "all"):
        filtered = self._filter(severity_filter)
        if not filtered:
            self._p("[yellow]No findings to display.[/yellow]")
            return

        if RICH and self.console:
            self._print_rich(filtered)
        else:
            self._print_plain(filtered)

    def export_html(self, filepath: str):
        findings_rows = ""
        for f in self.findings:
            sev   = f.get("severity","INFO")
            color = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00",
                     "LOW":"#88cc00","INFO":"#888888"}.get(sev,"#888")
            cmds  = "<br>".join(f"<code>{c}</code>" for c in f.get("commands",[]))
            findings_rows += f"""
            <tr>
              <td><span style="color:{color};font-weight:bold">{sev}</span></td>
              <td>{f.get("type","")}</td>
              <td>{f.get("title","")}</td>
              <td>{f.get("affected","")}</td>
              <td>{cmds}</td>
              <td>{f.get("ai_narrative","")}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>HorusEye Report — {self.domain_data.get("domain","")}</title>
<style>
  body{{background:#0d0d0d;color:#e0e0e0;font-family:'Courier New',monospace;padding:20px}}
  h1{{color:#E4002B}} h2{{color:#C09A3C}}
  table{{width:100%;border-collapse:collapse;margin-top:20px}}
  th{{background:#1a1a1a;color:#C09A3C;padding:10px;border:1px solid #333;text-align:left}}
  td{{padding:8px;border:1px solid #222;vertical-align:top}}
  tr:nth-child(even){{background:#111}}
  code{{background:#1a1a1a;padding:2px 6px;border-radius:3px;color:#00ff88;font-size:12px}}
  .banner{{color:#E4002B;font-size:12px;white-space:pre}}
</style></head><body>
<pre class="banner">𓂀 HorusEye v2.0 — AD Attack Report</pre>
<h1>Domain: {self.domain_data.get("domain","N/A")}</h1>
<p>DC: {self.domain_data.get("dc_ip","N/A")} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | 
Findings: {len(self.findings)} | Made by Omar Tamer 🇪🇬</p>
<table>
  <tr><th>Severity</th><th>Type</th><th>Title</th><th>Affected</th><th>Commands</th><th>AI Analysis</th></tr>
  {findings_rows}
</table>
</body></html>"""

        Path(filepath).write_text(html)
        self._p(f"[green]📄 HTML report → {filepath}[/green]")

    def export_json(self, filepath: str):
        data = {
            "generated":   datetime.now().isoformat(),
            "tool":        "HorusEye v2.0",
            "author":      "Omar Tamer 🇪🇬",
            "domain":      self.domain_data.get("domain",""),
            "dc_ip":       self.domain_data.get("dc_ip",""),
            "findings":    self.findings,
        }
        Path(filepath).write_text(json.dumps(data, indent=2))
        self._p(f"[green]📄 JSON report → {filepath}[/green]")

    def _filter(self, severity_filter: str) -> list:
        if severity_filter == "all":
            return self.findings
        order = ["critical","high","medium","low","info"]
        idx   = order.index(severity_filter.lower()) if severity_filter.lower() in order else 99
        keep  = [o.upper() for o in order[:idx+1]]
        return [f for f in self.findings if f.get("severity","").upper() in keep]

    def _print_rich(self, findings: list):
        self.console.print()
        t = Table(box=box.DOUBLE_EDGE, show_header=True,
                  title=f"[bold red]𓂀 {len(findings)} Attack Path(s)[/bold red]",
                  border_style="red")
        t.add_column("Severity",  style="bold", width=10)
        t.add_column("Type",      style="cyan",  width=25)
        t.add_column("Title",     style="white", width=45)
        t.add_column("Affected",  style="yellow",width=20)
        for f in findings:
            sev   = f.get("severity","INFO")
            color = SEV_COLOR.get(sev,"white")
            t.add_row(f"[{color}]{sev}[/{color}]",
                      f.get("type",""), f.get("title","")[:45], f.get("affected","")[:20])
        self.console.print(t)
        self.console.print()

        for f in findings:
            sev   = f.get("severity","INFO")
            color = SEV_COLOR.get(sev,"white")
            cmds  = f.get("commands",[])
            ai    = f.get("ai_narrative","")
            self.console.print(Panel(
                (f"[bold white]Affected:[/bold white] [yellow]{f.get('affected','N/A')}[/yellow]\n" +
                 (f"[bold white]AI:[/bold white]       [magenta]{ai}[/magenta]\n" if ai else "") +
                 ("\n".join(f"[green]$ {c}[/green]" for c in cmds[:3]))),
                title=f"[{color}][{sev}] {f.get('type','')} — {f.get('title','')[:55]}[/{color}]",
                border_style=color.replace("bold ",""), padding=(0,2)
            ))

    def _print_plain(self, findings: list):
        print(f"\n{'='*60}  𓂀 {len(findings)} FINDINGS  {'='*10}")
        for f in findings:
            print(f"  [{f.get('severity','')}] {f.get('type','')} — {f.get('title','')}")
            for cmd in f.get("commands",[])[:2]:
                print(f"      $ {cmd}")
        print(f"{'='*70}\n")

    def _p(self, msg: str):
        import re
        if RICH and self.console:
            self.console.print(msg)
        else:
            print(re.sub(r"\[/?[^\]]*\]","",msg))
