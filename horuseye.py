#!/usr/bin/env python3
"""
HorusEye — AI-Powered Active Directory Attack Platform
Author: Omar Tamer 🇪🇬
"""

import argparse
import sys
import os
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich import box
import time

console = Console()

# Egypt flag colors: red #E4002B, white #FFFFFF, black #000000, gold eagle
BANNER = r"""
[bold red]
 ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗
 ██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝
 ███████║██║   ██║██████╔╝██║   ██║███████╗
 ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║
 ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold red][bold white]
 ███████╗██╗   ██╗███████╗
 ██╔════╝╚██╗ ██╔╝██╔════╝
 █████╗   ╚████╔╝ █████╗  
 ██╔══╝    ╚██╔╝  ██╔══╝  
 ███████╗   ██║   ███████╗
 ╚══════╝   ╚═╝   ╚══════╝[/bold white]
"""

EYE_ART = r"""[bold yellow]
        .^.
       /|||\ 
      / ||| \
     /  |||  \
    / ~~~~~~~~\
   /  ( 𓂀 )  \        [bold white]𓂀  HorusEye  𓂀[/bold white]
  /____________\       [bold red]🇪🇬 Made by Omar Tamer[/bold red]
[/bold yellow]"""


def print_banner():
    console.print(BANNER)
    console.print(EYE_ART)
    console.print()
    console.print(Panel.fit(
        "[bold white]𓂀  AI-Powered Active Directory Attack Platform  𓂀[/bold white]\n"
        "[dim]BloodHound • ldapdomaindump • CrackMapExec • Certipy • Manual Input[/dim]\n"
        "[dim cyan]Kerberoasting • AS-REP Roasting • DCSync • ACL Abuse • ADCS ESC1-8[/dim cyan]\n"
        "[dim cyan]GPO Abuse • Delegation • Username Wordlist • Password Spraying[/dim cyan]\n\n"
        "         [bold red]🇪🇬[/bold red]  [bold white]Made with ❤️  by Omar Tamer[/bold white]  [bold red]🇪🇬[/bold red]",
        border_style="red",
        padding=(1, 8)
    ))
    console.print()


def animated_task(label: str, steps: list, color: str = "cyan"):
    with Progress(
        SpinnerColumn(spinner_name="dots12", style=f"bold {color}"),
        TextColumn(f"[bold {color}]{{task.description}}"),
        BarColumn(bar_width=35, style="red", complete_style="green"),
        TextColumn("[bold white]{task.percentage:>3.0f}%"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(label, total=len(steps))
        for step in steps:
            progress.update(task, description=f"[bold {color}]{step}")
            time.sleep(0.3)
            progress.advance(task)
    console.print(f"  [bold green]✓[/bold green] [dim]{label}[/dim]")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="HorusEye 𓂀 — AI-Powered AD Attack Platform by Omar Tamer 🇪🇬",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  𓂀  HorusEye — Usage Examples
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [AD Analysis]
  horuseye --bloodhound ./bh_data/ --domain corp.local
  horuseye --bloodhound ./bh/ --certipy certipy.json --domain corp.local
  horuseye --ldap ./ldap_output/ --cme cme.txt --domain corp.local
  horuseye --bloodhound ./bh/ --domain corp.local --report report.html

  [Username Wordlist]
  horuseye --make-wordlist --users-file users.txt --output wordlist.txt
  horuseye --bloodhound ./bh/ --domain corp.local --make-wordlist --output usernames.txt
  horuseye --make-wordlist --firstname John --lastname Smith --domain corp.local

  [Password Spraying]
  horuseye --spray --users-file wordlist.txt --password 'Password123' --dc 192.168.1.10 --domain corp.local
  horuseye --spray --users-file wordlist.txt --passwords-file passes.txt --dc DC_IP --domain corp.local --delay 3
  horuseye --spray --users-file users.txt --password 'Welcome1' --domain corp.local --dc DC_IP --safe

  [Full Attack Chain]
  horuseye --bloodhound ./bh/ --certipy c.json --domain corp.local --make-wordlist --output users.txt --report report.html

  [Config]
  horuseye --config --claude-key YOUR_KEY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )

    # ── Input Sources ──────────────────────────────────────────────────────
    inputs = parser.add_argument_group("📥 AD Input Sources")
    inputs.add_argument("--bloodhound", metavar="DIR", help="BloodHound JSON output directory")
    inputs.add_argument("--ldap", metavar="DIR", help="ldapdomaindump output directory")
    inputs.add_argument("--cme", metavar="FILE", help="CrackMapExec output file")
    inputs.add_argument("--certipy", metavar="FILE", help="Certipy JSON output file")
    inputs.add_argument("--manual", action="store_true", help="Manual interactive input mode")

    # ── Target ─────────────────────────────────────────────────────────────
    target = parser.add_argument_group("🎯 Target")
    target.add_argument("--domain", metavar="DOMAIN", help="Target domain (e.g. corp.local)")
    target.add_argument("--dc", metavar="IP", help="Domain Controller IP")

    # ── Username Wordlist ──────────────────────────────────────────────────
    wordlist = parser.add_argument_group("📝 Username Wordlist Generator")
    wordlist.add_argument("--make-wordlist", action="store_true",
                          help="Generate username wordlist from AD data or custom input")
    wordlist.add_argument("--users-file", metavar="FILE",
                          help="Input file with names (one per line: 'John Smith' or 'jsmith')")
    wordlist.add_argument("--firstname", metavar="NAME", help="Single first name for wordlist")
    wordlist.add_argument("--lastname", metavar="NAME", help="Single last name for wordlist")
    wordlist.add_argument("--output", metavar="FILE", default="usernames.txt",
                          help="Output file for wordlist (default: usernames.txt)")
    wordlist.add_argument("--formats", metavar="FORMATS",
                          default="all",
                          help="Username formats: all, jsmith, john.smith, smithj, john_smith, etc.")

    # ── Password Spraying ──────────────────────────────────────────────────
    spray = parser.add_argument_group("💦 Password Spraying")
    spray.add_argument("--spray", action="store_true", help="Run password spraying attack")
    spray.add_argument("--password", metavar="PASS", help="Single password to spray")
    spray.add_argument("--passwords-file", metavar="FILE", help="File with passwords to spray (one per line)")
    spray.add_argument("--delay", metavar="SECONDS", type=float, default=1.0,
                       help="Delay between attempts in seconds (default: 1.0)")
    spray.add_argument("--safe", action="store_true",
                       help="Safe mode: auto-detect lockout policy and stop before lockout")
    spray.add_argument("--threads", metavar="N", type=int, default=5,
                       help="Number of threads (default: 5)")
    spray.add_argument("--jitter", metavar="SECONDS", type=float, default=0.5,
                       help="Random jitter added to delay (default: 0.5)")

    # ── AI Options ─────────────────────────────────────────────────────────
    ai_opts = parser.add_argument_group("🤖 AI Options (Claude)")
    ai_opts.add_argument("--claude-key", metavar="KEY", help="Anthropic Claude API key")
    ai_opts.add_argument("--no-ai", action="store_true", help="Run without AI (rules only)")
    ai_opts.add_argument("--deep", action="store_true", help="Deep AI analysis (more detailed)")

    # ── Output ─────────────────────────────────────────────────────────────
    out = parser.add_argument_group("📤 Output")
    out.add_argument("--report", metavar="FILE", help="Export HTML report")
    out.add_argument("--json", metavar="FILE", help="Export JSON findings")
    out.add_argument("--severity", choices=["critical", "high", "all"], default="all")
    out.add_argument("--config", action="store_true", help="Save API keys")

    args = parser.parse_args()

    # ── Config ─────────────────────────────────────────────────────────────
    if args.config:
        from utils.config import save_config
        save_config(claude_key=args.claude_key)
        return

    from utils.config import load_config
    config = load_config()
    claude_key = args.claude_key or config.get("claude_key")

    # ── Route to correct mode ───────────────────────────────────────────────
    has_ad_input = any([args.bloodhound, args.ldap, args.cme, args.certipy, args.manual])

    if args.make_wordlist and not has_ad_input:
        # Standalone wordlist mode
        from features.wordlist_generator import WordlistGenerator
        gen = WordlistGenerator(console)
        gen.run_standalone(args)
        return

    if args.spray and not has_ad_input:
        # Standalone spray mode
        if not args.dc or not args.domain:
            console.print("[bold red]❌ --spray requires --dc and --domain[/bold red]")
            sys.exit(1)
        if not args.users_file:
            console.print("[bold red]❌ --spray requires --users-file[/bold red]")
            sys.exit(1)
        from features.password_sprayer import PasswordSprayer
        sprayer = PasswordSprayer(console)
        sprayer.run(args)
        return

    if not has_ad_input:
        parser.print_help()
        console.print("\n[bold red]❌ Please specify at least one input source or mode.[/bold red]")
        sys.exit(1)

    if not args.domain:
        console.print("[bold red]❌ Please specify --domain[/bold red]")
        sys.exit(1)

    try:
        run_analysis(args, config, claude_key)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️  Analysis interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]❌ Error: {e}[/bold red]")
        if os.environ.get("HORUSEYE_DEBUG"):
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_analysis(args, config, claude_key):
    from parsers.bloodhound_parser import BloodHoundParser
    from parsers.ldap_parser import LDAPParser, CMEParser, CertipyParser, ManualInputCollector
    from core.attack_detector import AttackDetector
    from core.path_scorer import PathScorer
    from ai.claude_analyzer import ClaudeAnalyzer
    from reports.report_generator import ReportGenerator
    from features.wordlist_generator import WordlistGenerator

    domain_data = {
        "domain": args.domain, "dc": args.dc,
        "users": [], "groups": [], "computers": [],
        "gpos": [], "acls": [], "sessions": [],
        "trusts": [], "adcs": {}, "cme_data": {},
        "raw_sources": []
    }

    console.print(Rule("[bold red][ 𓂀 PARSING INPUT DATA ][/bold red]"))
    console.print()

    if args.bloodhound:
        animated_task("Parsing BloodHound data", [
            "Reading JSON files", "Extracting users & groups",
            "Mapping ACL edges", "Processing sessions", "Building graph"
        ], "cyan")
        bh_data = BloodHoundParser(args.bloodhound).parse()
        domain_data["users"].extend(bh_data.get("users", []))
        domain_data["groups"].extend(bh_data.get("groups", []))
        domain_data["computers"].extend(bh_data.get("computers", []))
        domain_data["acls"].extend(bh_data.get("acls", []))
        domain_data["sessions"].extend(bh_data.get("sessions", []))
        domain_data["raw_sources"].append("bloodhound")
        console.print(f"  [dim]└─ {len(bh_data.get('users',[]))} users, {len(bh_data.get('groups',[]))} groups, {len(bh_data.get('acls',[]))} ACL edges[/dim]\n")

    if args.ldap:
        animated_task("Parsing ldapdomaindump data", [
            "domain_users.json", "domain_groups.json",
            "domain_computers.json", "domain_policy.json", "domain_trusts.json"
        ], "cyan")
        ldap_data = LDAPParser(args.ldap).parse()
        domain_data["users"].extend(ldap_data.get("users", []))
        domain_data["groups"].extend(ldap_data.get("groups", []))
        domain_data["gpos"].extend(ldap_data.get("gpos", []))
        domain_data["trusts"].extend(ldap_data.get("trusts", []))
        domain_data["raw_sources"].append("ldapdomaindump")

    if args.cme:
        animated_task("Parsing CrackMapExec output", [
            "Admin hosts", "Shares", "Sessions", "Password policy"
        ], "cyan")
        domain_data["cme_data"] = CMEParser(args.cme).parse()
        domain_data["raw_sources"].append("crackmapexec")

    if args.certipy:
        animated_task("Parsing Certipy ADCS output", [
            "Certificate templates", "ESC1-ESC8 checks",
            "CA permissions", "Enrollment rights"
        ], "magenta")
        adcs_data = CertipyParser(args.certipy).parse()
        domain_data["adcs"] = adcs_data
        domain_data["raw_sources"].append("certipy")
        console.print(f"  [dim]└─ {len(adcs_data.get('vulnerabilities', []))} ADCS vulnerabilities[/dim]\n")

    if args.manual:
        manual_data = ManualInputCollector(console).collect()
        domain_data["users"].extend(manual_data.get("users", []))
        domain_data["raw_sources"].append("manual")

    # Deduplicate users
    seen, unique = set(), []
    for u in domain_data["users"]:
        n = u.get("name", "")
        if n and n not in seen:
            seen.add(n)
            unique.append(u)
    domain_data["users"] = unique

    # ── Wordlist from AD data ───────────────────────────────────────────────
    if args.make_wordlist and domain_data["users"]:
        console.print(Rule("[bold red][ 𓂀 USERNAME WORDLIST ][/bold red]"))
        gen = WordlistGenerator(console)
        gen.generate_from_users(domain_data["users"], args.output, args.formats)

    # ── Attack Detection ────────────────────────────────────────────────────
    console.print(Rule("[bold red][ 𓂀 DETECTING ATTACK PATHS ][/bold red]"))
    console.print()

    animated_task("HorusEye Attack Detection Engine", [
        "Kerberoasting", "AS-REP Roasting", "DCSync rights",
        "ACL abuse paths", "Pass-the-Hash", "Unconstrained delegation",
        "Constrained delegation", "GPO misconfigurations",
        "ADCS ESC1-ESC8", "Domain trusts", "Scoring & ranking"
    ], "red")

    findings = AttackDetector(domain_data).detect_all()
    scored = PathScorer().score(findings)

    critical = len([f for f in scored if f.get("severity") == "CRITICAL"])
    high = len([f for f in scored if f.get("severity") == "HIGH"])
    console.print(f"\n  [bold red]𓂀 {len(scored)} attack paths — {critical} CRITICAL, {high} HIGH[/bold red]\n")

    if args.severity == "critical":
        scored = [f for f in scored if f.get("severity") == "CRITICAL"]
    elif args.severity == "high":
        scored = [f for f in scored if f.get("severity") in ["CRITICAL", "HIGH"]]

    # ── AI Analysis ─────────────────────────────────────────────────────────
    if not args.no_ai:
        if claude_key:
            console.print(Rule("[bold red][ 𓂀 CLAUDE AI ANALYSIS ][/bold red]"))
            console.print()
            animated_task("Sending findings to Claude AI", [
                "Building context", "Sending to Claude API",
                "AI reasoning", "Parsing narratives", "Generating chain"
            ], "magenta")
            scored = ClaudeAnalyzer(claude_key, deep=args.deep).analyze(scored, domain_data)
            console.print("  [bold green]✓ AI analysis complete[/bold green]\n")
        else:
            console.print("[yellow]⚠️  No Claude API key — use --config to set. Running rules-only mode.[/yellow]\n")

    # ── Report ──────────────────────────────────────────────────────────────
    reporter = ReportGenerator(scored, domain_data)
    reporter.print_cli_report(args.severity)

    if args.report:
        animated_task(f"Generating HTML report", ["Building structure", "Embedding findings", "Finalizing"], "green")
        reporter.export_html(args.report)
        console.print(f"\n[bold green]📄 HTML report → [cyan]{args.report}[/cyan][/bold green]")

    if args.json:
        reporter.export_json(args.json)
        console.print(f"[bold green]📄 JSON report → [cyan]{args.json}[/cyan][/bold green]")

    # ── Password Spraying ───────────────────────────────────────────────────
    if args.spray:
        if not args.dc:
            console.print("[bold red]❌ --spray requires --dc[/bold red]")
        else:
            # Auto-use generated wordlist if available
            spray_file = args.users_file or (args.output if args.make_wordlist else None)
            if not spray_file:
                console.print("[bold red]❌ --spray requires --users-file or --make-wordlist --output[/bold red]")
            else:
                args.users_file = spray_file
                from features.password_sprayer import PasswordSprayer
                PasswordSprayer(console).run(args)


if __name__ == "__main__":
    main()
