#!/usr/bin/env python3
"""
HorusEye v2.0 — AI-Powered Active Directory Attack Platform
Author: Omar Tamer 🇪🇬
"""

import argparse, sys, os, json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import time

console = Console()

BANNER = r"""
[bold red]
 ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗
 ██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝
 ███████║██║   ██║██████╔╝██║   ██║███████╗
 ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║
 ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold red][bold white]
 ███████╗██╗   ██╗███████╗  [bold red]v2.0[/bold red]
 ██╔════╝╚██╗ ██╔╝██╔════╝
 █████╗   ╚████╔╝ █████╗
 ██╔══╝    ╚██╔╝  ██╔══╝
 ███████╗   ██║   ███████╗
 ╚══════╝   ╚═╝   ╚══════╝[/bold white]"""

EYE = r"""[bold yellow]
       .^.
      /|||\ 
     / ||| \     [bold white]𓂀  HorusEye v2.0  𓂀[/bold white]
    /  𓂀  \    [bold red]🇪🇬 Omar Tamer — Egypt[/bold red]
   /________\[/bold yellow]"""


def print_banner():
    console.print(BANNER)
    console.print(EYE)
    console.print()
    console.print(Panel.fit(
        "[bold white]𓂀  AI-Powered Active Directory Attack Platform  𓂀[/bold white]\n"
        "[dim]BloodHound • Certipy • ldapdomaindump • CrackMapExec • Manual[/dim]\n"
        "[dim cyan]Auto-Exploit • Auto-Pivot • Auto-Persist • WinRM Privesc[/dim cyan]\n"
        "[dim cyan]Hash Cracking • Lateral Movement • LSASS Dump • Team Collab[/dim cyan]\n\n"
        "      [bold red]🇪🇬[/bold red]  [bold white]Made with ❤️  by Omar Tamer[/bold white]  [bold red]🇪🇬[/bold red]\n\n"
        "  [dim]linkedin.com/in/omar-tamer-1a986b2a7[/dim]  [dim]•[/dim]  "
        "[dim]medium.com/@OmarTamer0[/dim]  [dim]•[/dim]  "
        "[dim]omar-tamerr.github.io[/dim]",
        border_style="red", padding=(1, 8)
    ))
    console.print()


def animated_task(label, steps, color="cyan"):
    with Progress(
        SpinnerColumn(spinner_name="dots12", style=f"bold {color}"),
        TextColumn(f"[bold {color}]{{task.description}}"),
        BarColumn(bar_width=30, style="red", complete_style="green"),
        TextColumn("[white]{task.percentage:>3.0f}%"),
        console=console, transient=True
    ) as p:
        task = p.add_task(label, total=len(steps))
        for step in steps:
            p.update(task, description=f"[bold {color}]{step}")
            time.sleep(0.28)
            p.advance(task)
    console.print(f"  [bold green]✓[/bold green] [dim]{label}[/dim]")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="HorusEye v2.0 𓂀 — AI-Powered AD Attack Platform by Omar Tamer 🇪🇬",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  𓂀  HorusEye v2.0 — Usage Examples
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [Full Interactive Mode]
  horuseye --bloodhound ./bh/ --certipy c.json --domain corp.local --dc 10.0.0.5 --interactive

  [Auto-Exploit Chain]
  horuseye --bloodhound ./bh/ --domain corp.local --dc 10.0.0.5 --auto-exploit --auto-pivot

  [WinRM Privilege Check]
  horuseye --winrm 10.0.0.10 -u jsmith -p 'Pass123' --domain corp.local

  [Kerberoast + Crack + Pivot]
  horuseye --bloodhound ./bh/ --domain corp.local --dc 10.0.0.5 --auto-chain

  [LSASS Dump]
  horuseye --lsass-dump 10.0.0.10 -u admin -p 'Pass' --domain corp.local

  [Lateral Movement Map]
  horuseye --pivot --target-network 10.0.0.0/24 -u jsmith -p 'Pass' --domain corp.local

  [Attack Timeline]
  horuseye --bloodhound ./bh/ --domain corp.local --timeline

  [Domain Takeover Checklist]
  horuseye --bloodhound ./bh/ --domain corp.local --da-checklist

  [Team Collaboration Server]
  horuseye --team-server --port 9999
  horuseye --team-connect 192.168.1.50:9999 --bloodhound ./bh/ --domain corp.local

  [Username Wordlist + Spray]
  horuseye --make-wordlist --users-file names.txt --output users.txt
  horuseye --spray --users-file users.txt --password 'Pass123' --domain corp.local --dc DC_IP --safe
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )

    # ── Input Sources ──────────────────────────────────────────────────────
    g = parser.add_argument_group("📥 AD Input Sources")
    g.add_argument("--bloodhound", metavar="DIR")
    g.add_argument("--ldap",       metavar="DIR")
    g.add_argument("--cme",        metavar="FILE",  help="CrackMapExec output file")
    g.add_argument("--nxc",        metavar="FILE",  help="NetExec (nxc) output file — modern CME replacement")
    g.add_argument("--certipy",    metavar="FILE")
    g.add_argument("--manual",     action="store_true")

    # ── Target ────────────────────────────────────────────────────────────
    g2 = parser.add_argument_group("🎯 Target")
    g2.add_argument("--domain",  metavar="DOMAIN")
    g2.add_argument("--dc",      metavar="IP")

    # ── Automation ────────────────────────────────────────────────────────
    g3 = parser.add_argument_group("⚡ Automation")
    g3.add_argument("--interactive",  action="store_true", help="AI-guided interactive mode")
    g3.add_argument("--auto-exploit", action="store_true", help="Auto exploit best path to DA")
    g3.add_argument("--auto-pivot",   action="store_true", help="Auto re-enumerate after creds found")
    g3.add_argument("--auto-persist", action="store_true", help="Auto-suggest persistence after DA")
    g3.add_argument("--auto-chain",   action="store_true", help="Kerberoast→crack→validate→pivot chain")
    g3.add_argument("--timeline",     action="store_true", help="Show attack timeline T+0 to DA")
    g3.add_argument("--da-checklist", action="store_true", help="Domain takeover step-by-step checklist")

    # ── Exploitation ──────────────────────────────────────────────────────
    g4 = parser.add_argument_group("💀 Exploitation")
    g4.add_argument("--winrm",      metavar="HOST", help="WinRM connect + whoami /priv analysis")
    g4.add_argument("--lsass-dump", metavar="HOST", help="Auto LSASS dump (selects best method)")
    g4.add_argument("--pivot",      action="store_true", help="Lateral movement mapping")
    g4.add_argument("--target-network", metavar="CIDR", help="Network range for pivot scan")
    g4.add_argument("-u", "--username", metavar="USER")
    g4.add_argument("-p", "--password", metavar="PASS")
    g4.add_argument("-H", "--hash",     metavar="HASH", help="NTLM hash for PTH")

    # ── Hash Cracking ─────────────────────────────────────────────────────
    g5 = parser.add_argument_group("🧬 Hash Cracking")
    g5.add_argument("--crack",        metavar="FILE", help="Crack hashes from file")
    g5.add_argument("--hash-type",    default="kerberoast", choices=["kerberoast","asrep","ntlm","netntlmv2","mscache2"])
    g5.add_argument("--wordlist",     metavar="FILE")
    g5.add_argument("--rules",        default="fast", choices=["fast","medium","aggressive","corporate"])
    g5.add_argument("--crack-timeout", type=int, default=300)

    # ── Wordlist + Spray ──────────────────────────────────────────────────
    g6 = parser.add_argument_group("📝 Wordlist + Spray")
    g6.add_argument("--make-wordlist", action="store_true")
    g6.add_argument("--users-file",    metavar="FILE")
    g6.add_argument("--firstname",     metavar="NAME")
    g6.add_argument("--lastname",      metavar="NAME")
    g6.add_argument("--output",        metavar="FILE", default="usernames.txt")
    g6.add_argument("--spray",         action="store_true")
    g6.add_argument("--passwords-file",metavar="FILE")
    g6.add_argument("--delay",         type=float, default=1.0)
    g6.add_argument("--jitter",        type=float, default=0.5)
    g6.add_argument("--threads",       type=int,   default=5)
    g6.add_argument("--safe",          action="store_true")

    # ── Team Collab ───────────────────────────────────────────────────────
    g7 = parser.add_argument_group("🤝 Team Collaboration")
    g7.add_argument("--team-server",  action="store_true", help="Start team collaboration server")
    g7.add_argument("--team-connect", metavar="HOST:PORT",  help="Connect to team server")
    g7.add_argument("--team-port",    type=int, default=9999)

    # ── AI + Output ───────────────────────────────────────────────────────
    g8 = parser.add_argument_group("🤖 AI + Output")
    g8.add_argument("--claude-key",  metavar="KEY")
    g8.add_argument("--no-ai",       action="store_true")
    g8.add_argument("--deep",        action="store_true")
    g8.add_argument("--report",      metavar="FILE")
    g8.add_argument("--json",        metavar="FILE")
    g8.add_argument("--severity",    choices=["critical","high","all"], default="all")
    g8.add_argument("--config",      action="store_true")

    args = parser.parse_args()

    if args.config:
        from utils.config import save_config
        save_config(claude_key=args.claude_key)
        return

    from utils.config import load_config
    config = load_config()
    claude_key = args.claude_key or config.get("claude_key")

    try:
        _route(args, config, claude_key)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️  Interrupted[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]❌ {e}[/bold red]")
        if os.environ.get("HORUSEYE_DEBUG"):
            import traceback; traceback.print_exc()


def _route(args, config, claude_key):
    # ── Standalone modes ──────────────────────────────────────────────────

    if args.team_server:
        from features.team_collab import TeamServer
        TeamServer(console).start(args.team_port)
        return

    if args.team_connect:
        from features.team_collab import TeamClient
        TeamClient(console).connect(args.team_connect)
        # continue with normal analysis + broadcast results
        return

    if args.crack:
        from engine.hash_cracker import HashCrackingEngine
        with open(args.crack) as f:
            hashes = [l.strip() for l in f if l.strip()]
        HashCrackingEngine(console).crack(
            hashes, args.hash_type, args.wordlist, args.rules, args.crack_timeout
        )
        return

    if args.winrm:
        from engine.lateral_movement import LateralMovementEngine
        if not all([args.username, args.password, args.domain]):
            console.print("[red]❌ --winrm requires -u, -p, --domain[/red]"); return
        LateralMovementEngine(console).check_winrm_privileges(
            args.winrm, args.username, args.password, args.domain
        )
        return

    if args.lsass_dump:
        from engine.lsass_dumper import LsassDumper
        if not all([args.username, args.password, args.domain]):
            console.print("[red]❌ --lsass-dump requires -u, -p, --domain[/red]"); return
        LsassDumper(console).dump(
            args.lsass_dump, args.username, args.password, args.domain
        )
        return

    if args.pivot and not any([args.bloodhound, args.ldap]):
        from engine.lateral_movement import LateralMovementEngine
        if not all([args.username, args.password, args.domain, args.dc]):
            console.print("[red]❌ --pivot requires -u, -p, --domain, --dc[/red]"); return
        LateralMovementEngine(console).map_network(
            args.username, args.password, args.domain, args.target_network
        )
        return

    if args.make_wordlist and not args.bloodhound:
        from features.wordlist_generator import WordlistGenerator
        WordlistGenerator(console).run_standalone(args)
        return

    if args.spray and not args.bloodhound:
        from features.password_sprayer import PasswordSprayer
        if not all([args.dc, args.domain, args.users_file]):
            console.print("[red]❌ --spray requires --dc, --domain, --users-file[/red]"); return
        PasswordSprayer(console).run(args)
        return

    # ── Main AD analysis mode ─────────────────────────────────────────────
    has_input = any([args.bloodhound, args.ldap, args.cme, args.nxc, args.certipy, args.manual])
    if not has_input:
        from utils.help_printer import show_help
        show_help(no_banner=True)
        return

    if not args.domain:
        console.print("[red]❌ --domain required[/red]"); return

    run_main_analysis(args, config, claude_key)


def run_main_analysis(args, config, claude_key):
    from parsers.all_parsers import parse_all_sources
    from core.attack_detector import AttackDetector
    from core.path_scorer import PathScorer
    from engine.auto_chain import AutoChainEngine
    from engine.timeline import AttackTimeline
    from engine.da_checklist import DomainTakeoverChecklist
    from engine.lateral_movement import LateralMovementEngine
    from features.team_collab import TeamBroadcaster
    from features.creds_manager import CredsManager
    from features.wordlist_generator import WordlistGenerator
    from features.password_sprayer import PasswordSprayer
    from reports.report_generator import ReportGenerator

    creds_mgr = CredsManager(console)
    team = TeamBroadcaster(console, args.team_connect if hasattr(args, "team_connect") else None)

    # ── Parse ────────────────────────────────────────────────────────────
    domain_data = parse_all_sources(args, console, animated_task)

    # ── Wordlist ─────────────────────────────────────────────────────────
    if args.make_wordlist and domain_data["users"]:
        WordlistGenerator(console).generate_from_users(domain_data["users"], args.output)

    # ── Detect ───────────────────────────────────────────────────────────
    console.print(Rule("[bold red][ 𓂀 DETECTING ATTACK PATHS ][/bold red]"))
    console.print()
    animated_task("HorusEye Attack Detection Engine", [
        "Kerberoasting", "AS-REP Roasting", "DCSync rights",
        "ACL abuse", "Pass-the-Hash", "Unconstrained delegation",
        "Constrained delegation", "GPO misconfigurations",
        "ADCS ESC1-ESC8", "Domain trusts", "Scoring"
    ], "red")

    findings = AttackDetector(domain_data).detect_all()
    scored   = PathScorer().score(findings)

    crit = len([f for f in scored if f.get("severity") == "CRITICAL"])
    high = len([f for f in scored if f.get("severity") == "HIGH"])
    console.print(f"\n  [bold red]𓂀 {len(scored)} paths — {crit} CRITICAL, {high} HIGH[/bold red]\n")

    # ── AI analysis ──────────────────────────────────────────────────────
    if not args.no_ai and claude_key:
        console.print(Rule("[bold red][ 𓂀 CLAUDE AI ANALYSIS ][/bold red]"))
        animated_task("Claude AI reasoning", [
            "Building context", "Sending to Claude", "Parsing narratives", "Attack chain"
        ], "magenta")
        from ai.claude_analyzer import ClaudeAnalyzer
        scored = ClaudeAnalyzer(claude_key, args.deep).analyze(scored, domain_data)
        console.print("  [bold green]✓ AI analysis complete[/bold green]\n")
    elif not claude_key:
        console.print("[yellow]⚠️  No Claude key — rules-only mode. Use --config to set key.[/yellow]\n")

    # ── Broadcast to team ─────────────────────────────────────────────────
    team.broadcast({"event": "findings", "count": len(scored), "critical": crit})

    # ── Print results ────────────────────────────────────────────────────
    reporter = ReportGenerator(scored, domain_data)
    reporter.print_cli_report(args.severity)

    # ── Timeline ─────────────────────────────────────────────────────────
    if args.timeline:
        AttackTimeline(console).render(scored, domain_data)

    # ── DA Checklist ─────────────────────────────────────────────────────
    if args.da_checklist:
        DomainTakeoverChecklist(console).run(scored, domain_data, args)

    # ── Auto-chain (Kerberoast→crack→validate→pivot) ──────────────────────
    if args.auto_chain or args.auto_exploit:
        engine = AutoChainEngine(console, claude_key)
        new_creds = engine.run(scored, domain_data, args)
        for c in new_creds:
            creds_mgr.save(c)
            team.broadcast({"event": "creds_found", "creds": c})

    # ── Interactive mode ─────────────────────────────────────────────────
    if args.interactive:
        from engine.interactive_mode import InteractiveMode
        im = InteractiveMode(console, claude_key, creds_mgr, team)
        im.run(scored, domain_data, args)

    # ── Auto-pivot ───────────────────────────────────────────────────────
    if args.auto_pivot and creds_mgr.has_creds():
        console.print(Rule("[bold red][ 𓂀 AUTO-PIVOT ][/bold red]"))
        for cred in creds_mgr.get_all():
            lm = LateralMovementEngine(console)
            lm.map_network(cred["username"], cred["password"], args.domain,
                           args.target_network, dc_ip=args.dc)

    # ── Auto-persist suggestions ──────────────────────────────────────────
    if args.auto_persist and creds_mgr.has_da():
        from engine.persistence import PersistenceEngine
        PersistenceEngine(console).suggest(creds_mgr.get_da_creds(), domain_data)

    # ── Spray ─────────────────────────────────────────────────────────────
    if args.spray:
        spray_file = args.users_file or (args.output if args.make_wordlist else None)
        if spray_file:
            args.users_file = spray_file
            new_creds = PasswordSprayer(console).run(args)
            for c in (new_creds or []):
                creds_mgr.save(c)
                team.broadcast({"event": "creds_found", "creds": c})

    # ── Reports ───────────────────────────────────────────────────────────
    if args.report:
        animated_task("Generating HTML report", ["Building", "Embedding", "Finalizing"], "green")
        reporter.export_html(args.report)
        console.print(f"[green]📄 HTML → [cyan]{args.report}[/cyan][/green]")
    if args.json:
        reporter.export_json(args.json)
        console.print(f"[green]📄 JSON → [cyan]{args.json}[/cyan][/green]")

    # ── Always print creds summary ────────────────────────────────────────
    creds_mgr.print_summary()


if __name__ == "__main__":
    main()
