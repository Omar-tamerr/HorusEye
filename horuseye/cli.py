#!/usr/bin/env python3
"""
HorusEye v2.4 — AI-Powered Active Directory Attack Platform
Author: Omar Tamer 🇪🇬
"""

import argparse, sys, os, json

# ── UTF-8 bootstrap ─────────────────────────────────────────────────────────
# The banner and findings use box-drawing glyphs, hieroglyphs (𓂀) and emoji.
# On a legacy Windows console the default code page is cp1252, which raises
# UnicodeEncodeError the moment Rich tries to render them. Force UTF-8 on the
# streams before anything prints so the tool runs out-of-the-box on Windows.
if sys.platform == "win32":
    for _stream in ("stdout", "stderr"):
        try:
            getattr(sys, _stream).reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.markup import escape
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
 ███████╗██╗   ██╗███████╗  [bold red]v2.4[/bold red]
 ██╔════╝╚██╗ ██╔╝██╔════╝
 █████╗   ╚████╔╝ █████╗
 ██╔══╝    ╚██╔╝  ██╔══╝
 ███████╗   ██║   ███████╗
 ╚══════╝   ╚═╝   ╚══════╝[/bold white]"""

EYE = r"""[bold yellow]
       .^.
      /|||\ 
     / ||| \     [bold white]𓂀  HorusEye v2.4  𓂀[/bold white]
    /  𓂀  \    [bold red]🇪🇬 Omar Tamer — Egypt[/bold red]
   /________\\[/bold yellow]"""


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
        description="HorusEye v2.4 𓂀 — AI-Powered AD Attack Platform by Omar Tamer 🇪🇬",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  𓂀  HorusEye v2.4 — Usage Examples
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
    g.add_argument("--webapps",    metavar="FILE",
                   help="Web app -> AD service account claims (horuseye.webapps/1-draft); "
                        "see examples/acme-lab-webapp")
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
    g3.add_argument("--graph",        action="store_true", help="Compute shortest attack path(s) to Domain Admin")
    g3.add_argument("--owned",        metavar="PRINCIPALS", help="Comma-separated owned principals to path from (default: any domain user)")
    g3.add_argument("--target",       metavar="ASSETS", help="Comma-separated critical assets to path to (default: Tier-0)")
    g3.add_argument("--max-paths",    type=int, default=5, help="Max attack paths to show with --graph (default: 5)")
    g3.add_argument("--keep",         metavar="SRC->DST", action="append",
                    help="Access people need for their job, e.g. 'JDOE@CORP.LOCAL->HELPDESK@CORP.LOCAL'; "
                         "remediation options never remove it (repeatable or comma-separated)")

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
    g7.add_argument("--team-port",    type=int, default=31337)

    # ── AI + Output ───────────────────────────────────────────────────────
    g8 = parser.add_argument_group("🤖 AI + Output")
    g8.add_argument("--claude-key",  metavar="KEY")
    g8.add_argument("--no-ai",       action="store_true")
    g8.add_argument("--deep",        action="store_true", help="Deeper AI analysis (higher reasoning effort)")
    g8.add_argument("--ai-model",    metavar="MODEL", default="claude-opus-5-5", help="Claude model for narratives (default: claude-opus-5-5)")
    g8.add_argument("--ai-redact",   action="store_true", help="Mask domain/principal names before sending to the API")
    g8.add_argument("--report",      metavar="FILE")
    g8.add_argument("--json",        metavar="FILE")
    g8.add_argument("--markdown",    metavar="FILE", help="Export Markdown report with Mermaid attack-path diagrams")
    g8.add_argument("--explorer",    metavar="FILE", help="Export the interactive offline HTML explorer (dashboard + graph + findings)")
    g8.add_argument("--diff",        metavar="OLD.json", help="Compare against a previous JSON report (retest: new / fixed / unchanged)")
    g8.add_argument("--fail-on",     metavar="GATE", action="append",
                    choices=["critical","high","medium","low","new-route","exposure-up"],
                    help="CI gate, repeatable. critical/high/medium/low: exit 2 if a finding at/above it exists. "
                         "new-route / exposure-up (need --diff): exit 4 if a new attack route appeared or "
                         "more users can reach Tier-0 than in the baseline")
    g8.add_argument("--severity",    choices=["critical","high","all"], default="all")
    g8.add_argument("--config",      action="store_true")
    g8.add_argument("--check-deps",  action="store_true", help="Check external toolchain (hashcat, nxc, impacket, certipy, ...) on PATH")
    from horuseye import __version__ as _ver
    g8.add_argument("--version",     action="version", version=f"HorusEye {_ver}")

    args = parser.parse_args()

    if args.check_deps:
        from horuseye.utils.deps import check_dependencies
        check_dependencies(console)
        return

    if args.config:
        from horuseye.utils.config import save_config
        save_config(claude_key=args.claude_key)
        return

    from horuseye.utils.config import load_config
    config = load_config()
    claude_key = args.claude_key or config.get("claude_key")

    try:
        exit_code = _route(args, config, claude_key)
        if exit_code:
            sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️  Interrupted[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]❌ {e}[/bold red]")
        if os.environ.get("HORUSEYE_DEBUG"):
            import traceback; traceback.print_exc()
        from horuseye.core.exit_codes import ERROR
        sys.exit(ERROR)


def _has_input(args) -> bool:
    """True when at least one AD data source was supplied."""
    return any([args.bloodhound, args.ldap, args.cme, args.nxc, args.certipy, args.manual])


def _fixed_timestamp():
    """Honor SOURCE_DATE_EPOCH (reproducible-builds convention) so reports are
    byte-identical for the same input. Returns None for a normal (now) run."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch:
        return None
    try:
        return datetime.utcfromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return None


def _parse_hostport(s: str, default_port: int = 31337):
    """Split a HOST:PORT string into (host, int(port))."""
    host, _, port = (s or "").partition(":")
    try:
        return host, int(port) if port else default_port
    except ValueError:
        return host, default_port


def _route(args, config, claude_key):
    # ── Standalone modes ──────────────────────────────────────────────────

    if args.team_server:
        from horuseye.features.team_collab import TeamServer
        TeamServer(console).start(args.team_port)
        return

    if args.team_connect and not _has_input(args):
        # Pure watch/join mode: no local data to analyse, so attach to the
        # session and stay connected until interrupted. (With an input source,
        # we fall through to run_main_analysis, where TeamBroadcaster opens the
        # connection and streams findings/creds as they are produced.)
        from horuseye.features.team_collab import TeamClient
        host, port = _parse_hostport(args.team_connect)
        client = TeamClient(console)
        if client.connect(host, port):
            console.print("[dim]Watching session — press Ctrl+C to leave.[/dim]")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                client.disconnect()
        return

    if args.crack:
        from horuseye.engine.hash_cracker import HashCrackingEngine
        with open(args.crack) as f:
            hashes = [l.strip() for l in f if l.strip()]
        HashCrackingEngine(console).crack(
            hashes, args.hash_type, args.wordlist, args.rules, args.crack_timeout
        )
        return

    if args.winrm:
        from horuseye.engine.lateral_movement import LateralMovementEngine
        if not all([args.username, args.password, args.domain]):
            console.print("[red]❌ --winrm requires -u, -p, --domain[/red]"); return
        LateralMovementEngine(console).check_winrm_privileges(
            args.winrm, args.username, args.password, args.domain
        )
        return

    if args.lsass_dump:
        from horuseye.engine.lsass_dumper import LsassDumper
        if not all([args.username, args.password, args.domain]):
            console.print("[red]❌ --lsass-dump requires -u, -p, --domain[/red]"); return
        LsassDumper(console).dump(
            args.lsass_dump, args.username, args.password, args.domain
        )
        return

    if args.pivot and not any([args.bloodhound, args.ldap]):
        from horuseye.engine.lateral_movement import LateralMovementEngine
        if not all([args.username, args.password, args.domain, args.dc]):
            console.print("[red]❌ --pivot requires -u, -p, --domain, --dc[/red]"); return
        LateralMovementEngine(console).map_network(
            args.username, args.password, args.domain, args.target_network
        )
        return

    if args.make_wordlist and not args.bloodhound:
        from horuseye.features.wordlist_generator import WordlistGenerator
        WordlistGenerator(console).run_standalone(args)
        return

    if args.spray and not args.bloodhound:
        from horuseye.features.password_sprayer import PasswordSprayer
        if not all([args.dc, args.domain, args.users_file]):
            console.print("[red]❌ --spray requires --dc, --domain, --users-file[/red]"); return
        PasswordSprayer(console).run(args)
        return

    # ── Main AD analysis mode ─────────────────────────────────────────────
    if not _has_input(args):
        from horuseye.utils.help_printer import show_help
        show_help(no_banner=True)
        return

    if not args.domain:
        console.print("[red]❌ --domain required[/red]"); return

    return run_main_analysis(args, config, claude_key)


_EDGE_STYLE = {
    "MemberOf": "dim", "ACL": "bold yellow", "ForceChangePassword": "yellow",
    "AddMember": "yellow", "AdminTo": "cyan", "HasSession": "magenta",
    "DCSync": "bold red", "Unconstrained": "bold red", "ConstrainedDeleg": "red",
    "AllowedToAct": "red", "HasSIDHistory": "yellow", "ReadLAPSPassword": "cyan",
    "ReadGMSAPassword": "yellow", "GPLink": "yellow", "ADCS": "bold red",
}


def _keep_list(args):
    """--keep values, split on commas, in the order given."""
    out = []
    for item in getattr(args, "keep", None) or []:
        out += [k.strip() for k in str(item).split(",") if k.strip()]
    return out


def _print_plans(plans, keep):
    if keep:
        console.print("  [dim]Kept as required (--keep): "
                      + escape(", ".join(k.replace("->", " → ") for k in keep)) + "[/dim]")
    if not plans:
        if keep:
            console.print("  [yellow]No set of changes breaks every route without removing "
                          "access marked --keep.[/yellow]\n")
        return
    console.print("  [bold cyan]𓂀 Remediation options[/bold cyan] "
                  "[dim](each breaks every route in the imported graph, including routes not shown)[/dim]")
    for i, p in enumerate(plans, 1):
        n, m = len(p["changes"]), p["memberships_removed"]
        mem = (f"removes {m} group membership{'s' if m != 1 else ''}" if m
               else "no one leaves a group")
        console.print(f"  [bold white]Option {i} · {escape(p['title'])}[/bold white]  "
                      f"[dim]{n} change{'s' if n != 1 else ''} · {mem}[/dim]")
        for c in p["changes"]:
            console.print(f"    [green]✂[/green] {escape(c['fix'])}")
            note = f" {c['note']}" if c.get("note") else ""
            console.print(f"      [dim]{escape(c['effect'] + note)}[/dim]")
    console.print("  [dim]Access someone needs for their job? Mark it with --keep 'SRC->DST' "
                  "and HorusEye plans around it.[/dim]\n")


def _bar(pct: float, width: int = 30) -> str:
    full = int(round(width * pct / 100.0))
    return "█" * full + "░" * (width - full)


def _users(n: int) -> str:
    return f"{n:,} user{'s' if n != 1 else ''}"


def render_exposure(x):
    """Print the domain-wide exposure: who can reach the targets, and the
    fewest changes that bring it to zero."""
    if not x or not x.get("computed"):
        return
    goal = "Tier-0" if x.get("targets") == ["Tier-0"] else ", ".join(x.get("targets") or [])
    console.print(Rule(f"[bold red][ 𓂀 DOMAIN EXPOSURE ][/bold red]"))
    console.print()
    n, tot, pct = x["users_exposed"], x["users_total"], x["percent"]
    color = "bold red" if pct >= 25 else ("bold yellow" if pct else "bold green")
    console.print(f"  [{color}]{n:,} of {tot:,} users ({pct:g}%) can reach {escape(goal)}[/{color}]")
    console.print(f"  [{color.split()[-1]}]{_bar(pct)}[/{color.split()[-1]}]")
    if x.get("via_broad_groups"):
        console.print(f"  [dim]Every user is exposed through "
                      f"{escape(', '.join(x['via_broad_groups']))}.[/dim]")
    if not n:
        console.print("  [green]No enabled user has a route in the imported data.[/green]\n")
        return
    plan = x.get("plan")
    if plan:
        k = len(plan["changes"])
        console.print(f"\n  [bold cyan]𓂀 Fewest changes to reach 0%[/bold cyan] "
                      f"[dim]({k} change{'s' if k != 1 else ''}, together)[/dim]")
        for i, c in enumerate(plan["changes"], 1):
            left = c["users_after"]
            tail = ("[bold green]→ 0 users left[/bold green]" if left == 0
                    else f"[dim]→ {_users(left)} left[/dim]")
            console.print(f"    [green]✂ {i}.[/green] {escape(c['fix'])}  {tail}")
    elif x.get("plan_note"):
        console.print(f"\n  [yellow]{escape(x['plan_note'])}[/yellow]")
    if x.get("top_fixes"):
        console.print("\n  [bold cyan]𓂀 Biggest single fixes[/bold cyan] [dim](each on its own)[/dim]")
        for c in x["top_fixes"]:
            console.print(f"    [green]✂[/green] {escape(c['fix'])}  "
                          f"[bold]{_users(c['users_cut_off'])} cut off[/bold]")
    console.print(f"\n  [dim]Counts enabled users, not Tier-0 accounts. Not modeled: "
                  f"{escape('; '.join(x.get('not_modeled') or []))}.[/dim]\n")


def render_attack_paths(domain_data, args):
    """Build the attack graph, print the shortest path(s) to DA, and return the
    described paths for inclusion in reports."""
    from horuseye.core.graph import AttackGraph

    owned = [o.strip() for o in (args.owned or "").split(",") if o.strip()]
    targets = [t.strip() for t in (getattr(args, "target", "") or "").split(",") if t.strip()]
    goal_label = ", ".join(targets) if targets else "Domain Admin"
    console.print(Rule(f"[bold red][ 𓂀 ATTACK PATHS TO {goal_label.upper()} ][/bold red]"))
    console.print()
    graph = AttackGraph(domain_data)
    keep = _keep_list(args)
    for a, b in graph.unmatched_keep(keep):
        console.print(f"  [yellow]--keep {escape(a)}->{escape(b)} matches no relationship "
                      f"in the data (check the names).[/yellow]")
    paths = graph.shortest_paths(owned=owned or None, max_paths=max(1, args.max_paths),
                                 targets=targets or None)
    conditional = [graph.describe(p) for p in
                   graph.conditional_paths(owned=owned or None, max_paths=max(1, args.max_paths),
                                           targets=targets or None)]

    if not paths:
        origin = (", ".join(owned) if owned else
                  "any domain user or the imported vantages" if graph.vantages else "any domain user")
        console.print(f"  [yellow]No attack path to {goal_label} found from {origin}.[/yellow]")
        console.print("  [dim]Provide a foothold with --owned USER@DOMAIN, or ingest local-admin/"
                      "session data (SharpHound -c All) for richer paths.[/dim]\n")
        _print_conditional(conditional)
        return []

    described = []
    for i, path in enumerate(paths, 1):
        desc = graph.describe(path)
        described.append(desc)
        tag = f" · {desc['inferred_steps']} inferred step(s)" if desc["inferred_steps"] else ""
        if desc["validated_steps"]:
            tag += f" · {desc['validated_steps']} validated"
        console.print(f"  [bold white]Path {i}[/bold white]  "
                      f"[dim]({desc['hops']} hop{'s' if desc['hops'] != 1 else ''}: "
                      f"{escape(desc['start'])} → {escape(desc['goal'])}{tag})[/dim]")
        _print_steps(desc)

    # Remediation impact: which single fix breaks the shortest path.
    impact = graph.remediation_impact(owned=owned or None, targets=targets or None,
                                      max_paths=max(1, args.max_paths), keep=keep)
    chokes = [h for h in impact if h["breaks_path"]]
    if chokes:
        console.print("  [bold cyan]𓂀 Remediation impact[/bold cyan] [dim](one fix breaks every route shown):[/dim]")
        for h in chokes:
            req = "  [yellow](marked as required with --keep)[/yellow]" if h.get("kept") else ""
            console.print(f"    [green]✂[/green]  remove [bold]{h['type']}[/bold] "
                          f"{h['from']} → {h['to']}  [dim](no alternative path remains)[/dim]{req}")
        console.print()
    _print_plans(graph.remediation_plans(owned=owned or None, targets=targets or None,
                                         keep=keep), keep)
    _print_conditional(conditional)
    console.print(f"  [bold red]𓂀 {len(described)} path(s) to {goal_label}. "
                  f"Shortest: {described[0]['hops']} hop(s).[/bold red]\n")
    return described


_TRUST_TAG = {"inferred": " [italic yellow](inferred)[/italic yellow]",
              "validated": " [bold green](validated)[/bold green]",
              "assumed": " [italic magenta](assumed)[/italic magenta]",
              "not_assessed": " [italic magenta](not assessed)[/italic magenta]"}


def _print_steps(desc):
    console.print(f"    [green]{escape(desc['start'])}[/green]")
    for step, cmd in zip(desc["steps"], desc["commands"]):
        style = _EDGE_STYLE.get(step["type"], "white")
        kind = " [dim]· reachability, not control[/dim]" if step.get("kind") == "reachability" else ""
        console.print(f"      [dim]│[/dim] [{style}]{step['type']}[/{style}] "
                      f"[dim]({escape(step['detail'])})[/dim]{_TRUST_TAG.get(step['trust'], '')}{kind}")
        first_cmd = cmd.split(chr(10))[0]
        console.print(f"      [dim]▼[/dim] [bold white]{escape(step['to'])}[/bold white]  "
                      f"[dim]{escape(first_cmd)}[/dim]")
    console.print()


def _print_conditional(conditional):
    """Routes that need an unproven step: shown apart, never counted as paths."""
    if not conditional:
        return
    console.print("  [bold magenta]𓂀 Conditional routes[/bold magenta] [dim](need a step that "
                  "is assumed or not assessed; not counted as attack paths)[/dim]")
    for desc in conditional:
        console.print(f"  [bold magenta]{escape(desc['label'])}[/bold magenta]  "
                      f"[dim]({escape(desc['rationale'])})[/dim]")
        _print_steps(desc)


def _drift_without_baseline(args) -> bool:
    gates = [g for g in (getattr(args, "fail_on", None) or []) if g in ("new-route", "exposure-up")]
    if gates and not getattr(args, "diff", None):
        console.print(f"[bold red]✖ --fail-on {gates[0]} compares against a baseline: "
                      f"add --diff OLD.json.[/bold red]")
        return True
    return False


def run_main_analysis(args, config, claude_key):
    from horuseye.parsers.all_parsers import parse_all_sources
    from horuseye.core.attack_detector import AttackDetector
    from horuseye.core.path_scorer import PathScorer
    from horuseye.engine.auto_chain import AutoChainEngine
    from horuseye.engine.timeline import AttackTimeline
    from horuseye.engine.da_checklist import DomainTakeoverChecklist
    from horuseye.engine.lateral_movement import LateralMovementEngine
    from horuseye.features.team_collab import TeamBroadcaster
    from horuseye.features.creds_manager import CredsManager
    from horuseye.features.wordlist_generator import WordlistGenerator
    from horuseye.features.password_sprayer import PasswordSprayer
    from horuseye.reports.report_generator import ReportGenerator

    if _drift_without_baseline(args):
        from horuseye.core.exit_codes import ERROR
        return ERROR

    creds_mgr = CredsManager(console)
    team = TeamBroadcaster(console, args.team_connect if hasattr(args, "team_connect") else None)

    # ── Parse ────────────────────────────────────────────────────────────
    domain_data = parse_all_sources(args, console, animated_task)
    if getattr(args, "webapps", None):
        from horuseye.parsers.webapps import load_webapps   # raises on invalid input → exit 1
        before = len(domain_data.get("parse_report", {}).get("warnings", []))
        load_webapps(args.webapps, domain_data)
        apps = domain_data.get("webapps", [])
        console.print(f"[green]🌐 Web apps: {len(apps)} imported from {escape(args.webapps)}[/green]")
        for w in domain_data["parse_report"]["warnings"][before:]:
            console.print(f"  [yellow]⚠ {escape(w)}[/yellow]")

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

    # Attach remediation / MITRE ATT&CK / detection guidance to every finding
    # so the report serves defenders as well as operators.
    from horuseye.core.knowledge import enrich
    enrich(scored)

    crit = len([f for f in scored if f.get("severity") == "CRITICAL"])
    high = len([f for f in scored if f.get("severity") == "HIGH"])
    console.print(f"\n  [bold red]𓂀 {len(scored)} findings — {crit} CRITICAL, {high} HIGH[/bold red]\n")

    # ── AI analysis ──────────────────────────────────────────────────────
    if not args.no_ai and claude_key:
        console.print(Rule("[bold red][ 𓂀 CLAUDE AI ANALYSIS ][/bold red]"))
        animated_task("Claude AI reasoning", [
            "Building context", "Sending to Claude", "Parsing narratives", "Attack chain"
        ], "magenta")
        from horuseye.ai.claude_analyzer import ClaudeAnalyzer
        scored = ClaudeAnalyzer(claude_key, args.deep, args.ai_model,
                                args.ai_redact, console).analyze(scored, domain_data)
        console.print("  [bold green]✓ AI analysis complete[/bold green]\n")
    elif not claude_key:
        console.print("[yellow]⚠️  No Claude key — rules-only mode. Use --config to set key.[/yellow]\n")

    # ── Broadcast to team ─────────────────────────────────────────────────
    team.broadcast({"event": "findings", "count": len(scored), "critical": crit})

    # ── Print results ────────────────────────────────────────────────────
    reporter = ReportGenerator(scored, domain_data, generated_at=_fixed_timestamp())
    reporter.print_cli_report(args.severity)

    # ── Timeline ─────────────────────────────────────────────────────────
    if args.timeline:
        AttackTimeline(console).render(scored, domain_data)

    # ── Attack-path graph ─────────────────────────────────────────────────
    graph_paths = []
    if args.graph:
        graph_paths = render_attack_paths(domain_data, args)
        reporter.attack_paths = graph_paths
    # Domain exposure: every user, not one foothold. Cheap, so always on.
    from horuseye.core.graph import AttackGraph
    owned = [o.strip() for o in (args.owned or "").split(",") if o.strip()] or None
    targets = [t.strip() for t in (getattr(args, "target", "") or "").split(",") if t.strip()] or None
    keep = _keep_list(args)
    g = AttackGraph(domain_data)
    reporter.exposure = g.exposure(targets=targets, keep=keep)
    reporter.keep = keep
    render_exposure(reporter.exposure)

    # Reports carry the remediation impact and options; the explorer also
    # needs the paths, and a retest diff compares them. Compute quietly if the
    # --graph view didn't produce them.
    if (args.graph or getattr(args, "explorer", None) or args.json or args.report
            or args.markdown or args.diff):
        if not reporter.attack_paths:
            reporter.attack_paths = [g.describe(p) for p in
                                     g.shortest_paths(owned=owned, targets=targets,
                                                      max_paths=max(1, args.max_paths))]
        reporter.remediation = g.remediation_impact(owned=owned, targets=targets,
                                                    max_paths=max(1, args.max_paths), keep=keep)
        reporter.remediation_plans = g.remediation_plans(owned=owned, targets=targets, keep=keep)
        reporter.conditional_paths = [g.describe(p) for p in
                                      g.conditional_paths(owned=owned, targets=targets,
                                                          max_paths=max(1, args.max_paths))]
        reporter.keep = keep

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
        from horuseye.engine.interactive_mode import InteractiveMode
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
        from horuseye.engine.persistence import PersistenceEngine
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

    # ── Retest comparison (printed after the reports, embedded in the JSON) ──
    retest = compute_retest(args.diff, scored, reporter) if args.diff else None
    reporter.retest = retest

    # ── Reports ───────────────────────────────────────────────────────────
    if args.report:
        animated_task("Generating HTML report", ["Building", "Embedding", "Finalizing"], "green")
        reporter.export_html(args.report)
        console.print(f"[green]📄 HTML → [cyan]{args.report}[/cyan][/green]")
    if args.json:
        reporter.export_json(args.json)
        console.print(f"[green]📄 JSON → [cyan]{args.json}[/cyan][/green]")
    if args.markdown:
        reporter.export_markdown(args.markdown)
        console.print(f"[green]📝 Markdown → [cyan]{args.markdown}[/cyan][/green]")
    if getattr(args, "explorer", None):
        animated_task("Building interactive explorer", ["Graph", "Findings", "Embedding"], "green")
        reporter.export_explorer(args.explorer)
        console.print(f"[green]🧭 Explorer → [cyan]{args.explorer}[/cyan][/green]")

    # ── Retest diff ────────────────────────────────────────────────────────
    if args.diff:
        render_diff(args.diff, retest)

    # ── Always print creds summary ────────────────────────────────────────
    creds_mgr.print_summary()

    # ── CI gate ──────────────────────────────────────────────────────────────
    if args.fail_on:
        from horuseye.core.diff import DRIFT_GATES, drift_gate_failures, fail_level_exceeded
        from horuseye.core.exit_codes import (DRIFT, FINDINGS, INCOMPLETE, OK,
                                              assessment_is_incomplete)
        if assessment_is_incomplete(domain_data):
            console.print("[bold red]✖ assessment incomplete — a source was given but no "
                          "usable objects were parsed; not trusting a clean result "
                          "(exit 3).[/bold red]")
            return INCOMPLETE
        levels = [g for g in args.fail_on if g not in DRIFT_GATES]
        tripped = [g for g in levels if fail_level_exceeded(scored, g)]
        drift = drift_gate_failures(args.fail_on, (retest or {}).get("routes"),
                                    (retest or {}).get("exposure"))
        if tripped:
            console.print(f"[bold red]✖ findings at or above {tripped[0].upper()} "
                          f"— failing (exit 2).[/bold red]")
        for reason in drift:
            console.print(f"[bold red]✖ {escape(reason)} — failing (exit 4).[/bold red]")
        if tripped:
            return FINDINGS
        if drift:
            return DRIFT
        return OK
    return 0


def compute_retest(old_path, current, reporter):
    """Compare this run with a previous JSON report: findings, attack routes
    and exposure. Returns a JSON-ready dict, or {"error": ...}."""
    from horuseye.core.diff import diff_exposure, diff_findings, diff_routes, load_report
    try:
        prev = load_report(old_path)
    except Exception as e:
        return {"baseline": old_path, "error": str(e)}
    f = diff_findings(prev.get("findings") or [], current)
    r = diff_routes(prev.get("attack_paths") or [], reporter.attack_paths or [])
    x = diff_exposure(prev.get("exposure"), reporter.exposure)
    return {"baseline": old_path, "baseline_generated": prev.get("generated", ""),
            "findings": f, "routes": r, "exposure": x}


def render_diff(old_path, retest):
    """Print a retest comparison against a previous JSON report."""
    console.print(Rule("[bold red][ 𓂀 RETEST DIFF ][/bold red]"))
    console.print()
    if not retest or retest.get("error"):
        console.print(f"  [red]Could not read {escape(str(old_path))}: "
                      f"{escape(str((retest or {}).get('error', '')))}[/red]\n")
        return
    x = retest["exposure"]
    if x["comparable"]:
        delta = (x["after"] or 0) - (x["before"] or 0)
        color = "bold red" if x["rose"] else ("bold green" if delta < 0 else "bold white")
        arrow = "▲" if delta > 0 else ("▼" if delta < 0 else "=")
        console.print(f"  [bold]Exposure[/bold]  {x['before']:,} → [{color}]{x['after']:,} users "
                      f"({x['before_pct']:g}% → {x['after_pct']:g}%) {arrow}[/{color}]")
        if x["newly_exposed"]:
            names = ", ".join(x["newly_exposed"][:8]) + (f" +{len(x['newly_exposed']) - 8} more"
                                                          if len(x["newly_exposed"]) > 8 else "")
            console.print(f"    [bold red]✚ gained a route:[/bold red] {escape(names)}")
        if x["no_longer_exposed"]:
            console.print(f"    [bold green]✓ no longer exposed:[/bold green] "
                          f"{len(x['no_longer_exposed']):,} user(s)")
    elif x.get("reason"):
        console.print(f"  [dim]Exposure: {escape(x['reason'])}[/dim]")
    r = retest["routes"]
    if not r.get("comparable", True):
        console.print(f"  [dim]Routes: {escape(r['reason'])}[/dim]")
    if r["new"] or r["closed"] or r["still_open"]:
        console.print(f"  [bold]Routes[/bold]  [bold red]✚ new: {len(r['new'])}[/bold red]   "
                      f"[bold green]✓ closed: {len(r['closed'])}[/bold green]   "
                      f"[dim]= still open: {len(r['still_open'])}[/dim]")
        for p in r["new"]:
            chain = " → ".join([p.get("start", "")] + [s.get("to", "") for s in p.get("steps", [])])
            console.print(f"    [bold red]✚ NEW ROUTE[/bold red] {escape(chain)}")
        for p in r["closed"]:
            chain = " → ".join([p.get("start", "")] + [s.get("to", "") for s in p.get("steps", [])])
            console.print(f"    [bold green]✓ CLOSED[/bold green] [dim]{escape(chain)}[/dim]")
    d = retest["findings"]
    console.print(f"  [bold green]✓ Fixed:[/bold green] {len(d['fixed'])}   "
                  f"[bold red]✚ New:[/bold red] {len(d['new'])}   "
                  f"[dim]= Unchanged: {len(d['unchanged'])}[/dim]\n")
    for f in d["new"]:
        console.print(f"  [bold red]✚ NEW[/bold red]  [{(f.get('severity') or '').upper()}] "
                      f"{f.get('title','')}")
    for f in d["fixed"]:
        console.print(f"  [bold green]✓ FIXED[/bold green]  [{(f.get('severity') or '').upper()}] "
                      f"{f.get('title','')}")
    console.print()


if __name__ == "__main__":
    main()
