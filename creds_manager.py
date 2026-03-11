"""
HorusEye v2 — Valid Credentials Manager
Central store: all found/cracked/sprayed creds → valid_credentials.txt
Author: Omar Tamer 🇪🇬
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    from rich import box
    RICH = True
except ImportError:
    RICH = False

CREDS_FILE = "valid_credentials.txt"
CREDS_JSON  = "valid_credentials.json"


class CredsManager:
    def __init__(self, console=None, output_dir: str = "./horuseye_output"):
        # Always have a working console
        if console is None and RICH:
            from rich.console import Console as RichConsole
            self.console = RichConsole()
        else:
            self.console = console  # could still be None if rich not installed

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.creds_file = self.output_dir / CREDS_FILE
        self.creds_json  = self.output_dir / CREDS_JSON
        self._creds: List[Dict] = []
        self._load_existing()

    # ── Core API ──────────────────────────────────────────────────────────

    def save(self, cred: Dict):
        """Save a valid credential. Deduplicates automatically."""
        cred.setdefault("domain",   "")
        cred.setdefault("username", "")
        cred.setdefault("password", "")
        cred.setdefault("hash",     "")
        cred.setdefault("source",   "unknown")
        cred.setdefault("is_da",    False)
        cred.setdefault("is_admin", False)
        cred.setdefault("ts",       datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        key = f"{cred['domain']}\\{cred['username']}:{cred['password']}"
        existing = {f"{c['domain']}\\{c['username']}:{c['password']}" for c in self._creds}
        if key in existing:
            return

        self._creds.append(cred)
        self._write_txt(cred)
        self._write_json()

    def save_many(self, creds: List[Dict]):
        for c in creds:
            self.save(c)

    def has_creds(self) -> bool:
        return len(self._creds) > 0

    def has_da(self) -> bool:
        return any(c.get("is_da") for c in self._creds)

    def get_all(self) -> List[Dict]:
        return self._creds.copy()

    def get_da_creds(self) -> List[Dict]:
        return [c for c in self._creds if c.get("is_da")]

    def get_by_source(self, source: str) -> List[Dict]:
        return [c for c in self._creds if c.get("source") == source]

    def print_summary(self):
        if not self._creds:
            return

        if RICH and self.console:
            self._print_summary_rich()
        else:
            self._print_summary_plain()

    # ── Display ───────────────────────────────────────────────────────────

    def _print_summary_rich(self):
        self.console.print()
        self.console.print(Rule("[bold red][ 𓂀 VALID CREDENTIALS SUMMARY ][/bold red]"))
        self.console.print()

        t = Table(
            box=box.DOUBLE_EDGE, show_header=True,
            title=f"[bold red]🔑 {len(self._creds)} Valid Credential(s) Found[/bold red]",
            border_style="red"
        )
        t.add_column("Domain\\Username",   style="bold cyan")
        t.add_column("Password / Hash",    style="bold green")
        t.add_column("Source",             style="yellow")
        t.add_column("DA?",  justify="center")
        t.add_column("Admin?", justify="center")
        t.add_column("Found At", style="dim")

        for c in self._creds:
            secret    = c.get("password") or f"NTLM:{c.get('hash','')[:16]}..."
            da_tag    = "[bold red]💀 YES[/bold red]" if c.get("is_da")    else "[dim]No[/dim]"
            admin_tag = "[bold yellow]✓[/bold yellow]"  if c.get("is_admin") else "[dim]No[/dim]"
            t.add_row(
                f"{c['domain']}\\{c['username']}",
                secret, c.get("source",""),
                da_tag, admin_tag, c.get("ts","")
            )

        self.console.print(t)
        self.console.print()
        self.console.print(Panel(
            f"[bold white]💾 Saved to:[/bold white]\n"
            f"  [cyan]{self.creds_file}[/cyan]  (human-readable)\n"
            f"  [cyan]{self.creds_json}[/cyan]  (JSON)\n\n"
            f"[bold yellow]⚡ Quick use:[/bold yellow]\n"
            f"  [green]crackmapexec smb TARGET -u USER -p PASS[/green]\n"
            f"  [green]secretsdump.py DOMAIN/USER:PASS@DC_IP[/green]",
            title="[bold red][ CREDENTIALS FILE ][/bold red]",
            border_style="yellow", padding=(0, 3)
        ))

    def _print_summary_plain(self):
        print(f"\n{'='*60}")
        print(f"  𓂀  VALID CREDENTIALS ({len(self._creds)} found)")
        print(f"{'='*60}")
        print(f"  {'Domain\\User':<35}  {'Password':<25}  Source")
        print(f"  {'-'*35}  {'-'*25}  {'-'*12}")
        for c in self._creds:
            secret = c.get("password") or f"NTLM:{c.get('hash','')[:12]}..."
            da = " [DA]" if c.get("is_da") else ""
            print(f"  {c['domain']}\\{c['username']:<33}  {secret:<25}  {c.get('source','')}{da}")
        print(f"\n  Saved to: {self.creds_file}")
        print(f"{'='*60}\n")

    # ── File I/O ──────────────────────────────────────────────────────────

    def _write_txt(self, cred: Dict):
        da_flag    = " [DA]"    if cred.get("is_da")    else ""
        admin_flag = " [ADMIN]" if cred.get("is_admin") else ""
        with open(self.creds_file, "a") as f:
            if cred.get("password"):
                f.write(
                    f"{cred['domain']}\\{cred['username']}:{cred['password']}"
                    f"  # {cred['source']}{da_flag}{admin_flag}  [{cred['ts']}]\n"
                )
            else:
                f.write(
                    f"{cred['domain']}\\{cred['username']}  NTLM:{cred.get('hash','')}"
                    f"  # {cred['source']}{da_flag}{admin_flag}  [{cred['ts']}]\n"
                )

    def _write_json(self):
        with open(self.creds_json, "w") as f:
            json.dump({
                "generated":   datetime.now().isoformat(),
                "tool":        "HorusEye v2.0 🇪🇬",
                "author":      "Omar Tamer",
                "count":       len(self._creds),
                "credentials": self._creds
            }, f, indent=2)

    def _load_existing(self):
        if self.creds_json.exists():
            try:
                data = json.loads(self.creds_json.read_text())
                self._creds = data.get("credentials", [])
                if self._creds:
                    self._p(f"📂 Loaded {len(self._creds)} existing credential(s) from previous session")
            except Exception:
                pass

    # ── Utility ───────────────────────────────────────────────────────────

    def _p(self, msg: str):
        """Print with Rich if available, plain otherwise."""
        if RICH and self.console:
            self.console.print(msg)
        else:
            clean = re.sub(r"\[/?[^\]]*\]", "", msg)
            print(clean)

    @staticmethod
    def format_for_spray(creds: List[Dict]) -> List[str]:
        return [f"{c['domain']}\\{c['username']}:{c['password']}"
                for c in creds if c.get("password")]

    @staticmethod
    def format_for_impacket(cred: Dict) -> str:
        if cred.get("hash"):
            return f"{cred['domain']}/{cred['username']}  -hashes :{cred['hash']}"
        return f"{cred['domain']}/{cred['username']}:{cred['password']}"
