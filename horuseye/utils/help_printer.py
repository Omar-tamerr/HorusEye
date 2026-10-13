"""
HorusEye — Help Printer
Offline, Rich-formatted help shown when HorusEye runs with no input source.
It describes the real (flat) command-line interface; for the exhaustive option
list use ``horuseye --help`` (argparse). Author: Omar Tamer 🇪🇬
"""
try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

R, W, C, G, Y, D, M, GO = ("bold red", "bold white", "cyan", "green",
                           "yellow", "dim", "magenta", "bold yellow")


# ── Shared helpers ─────────────────────────────────────────────────────────────
def rule(title="", color="red"):
    if RICH:
        from rich.rule import Rule
        console.print(Rule(title, style=color))
    else:
        print(f"\n{'-' * 60}  {title}")


def section(title, color="cyan"):
    if RICH:
        console.print(f"\n[bold {color}]{title}[/bold {color}]")
    else:
        print(f"\n{title}")


def flag(name, desc, default=None, indent=4):
    pad = " " * indent
    if RICH:
        line = Text()
        line.append(pad)
        line.append(f"{name:<26}", style="green")
        line.append(desc, style="white")
        if default:
            line.append(f"  (default: {default})", style="dim")
        console.print(line)
    else:
        dflt = f"  (default: {default})" if default else ""
        print(f"{pad}{name:<26}{desc}{dflt}")


def example(cmd, comment=""):
    if RICH:
        console.print(f"    [dim]$[/dim] [cyan]{cmd}[/cyan]")
        if comment:
            console.print(f"    [dim]  # {comment}[/dim]")
    else:
        print(f"    $ {cmd}")
        if comment:
            print(f"      # {comment}")


def blank():
    print()


BANNER = r"""
 ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗
 ██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝
 ███████║██║   ██║██████╔╝██║   ██║███████╗
 ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║
 ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"""


def print_banner():
    if RICH:
        console.print(BANNER, style="bold red")
    else:
        print(BANNER)


def show_help(topic=None, no_banner=False):
    """Accurate overview of the real HorusEye CLI. ``topic`` is accepted for
    backward compatibility but the help is unified — every call shows the same
    accurate reference (there are no phase subcommands)."""
    if not no_banner:
        print_banner()

    rule("USAGE", "red")
    blank()
    if RICH:
        console.print("    [cyan]horuseye[/cyan] [green]--<source>[/green] [dim]<file|dir>[/dim] "
                      "[green]--domain[/green] [dim]corp.local[/dim] [dim][options][/dim]")
        console.print("    [dim]HorusEye is a flat-flag CLI. Run[/dim] "
                      "[cyan]horuseye --help[/cyan] [dim]for the full option list.[/dim]")
    else:
        print("    horuseye --<source> <file|dir> --domain corp.local [options]")
        print("    Run: horuseye --help for the full option list.")
    blank()

    section("📥 INPUT SOURCES (at least one)", "cyan")
    flag("--bloodhound DIR", "SharpHound JSON directory or .zip")
    flag("--ldap DIR", "ldapdomaindump output directory")
    flag("--nxc FILE", "NetExec output")
    flag("--cme FILE", "CrackMapExec output")
    flag("--certipy FILE", "Certipy ADCS JSON (ESC1-ESC8)")
    flag("--manual", "Interactive prompt when you have no files")

    section("🎯 TARGET", "cyan")
    flag("--domain DOMAIN", "Target domain (required for analysis)")
    flag("--dc IP", "Domain Controller IP (used in commands)")

    section("🗺️  ANALYSIS & PATHS", "yellow")
    flag("--graph", "Shortest attack path(s) to Domain Admin")
    flag("--owned PRINCIPALS", "Comma-separated foothold (default: any user)")
    flag("--target ASSETS", "Critical assets to path to (default: Tier-0)")
    flag("--timeline", "Attack timeline T+0 → DA")
    flag("--da-checklist", "Domain-takeover checklist (auto-ticked)")
    flag("--severity LEVEL", "Filter findings: critical | high | all", "all")

    section("📄 OUTPUT & AUTOMATION", "green")
    flag("--report FILE", "HTML report (dark theme)")
    flag("--markdown FILE", "Markdown report (Mermaid path diagrams)")
    flag("--json FILE", "JSON report (schema horuseye.report/3)")
    flag("--diff OLD.json", "Retest: new / fixed / unchanged vs a prior run")
    flag("--fail-on LEVEL", "Exit non-zero if a finding ≥ LEVEL (CI gate)")
    flag("--check-deps", "Report which external tools are on PATH")

    section("🤖 AI (optional)", "magenta")
    flag("--deep", "Deeper AI analysis (higher effort)")
    flag("--ai-model MODEL", "Narrative model", "claude-opus-5-5")
    flag("--ai-redact", "Mask domain/host/user/IP/email before sending")
    flag("--no-ai", "Skip AI entirely (fully offline)")

    blank()
    rule("EXAMPLES", "red")
    blank()
    example("horuseye --bloodhound ./bh/ --certipy certipy.json --domain corp.local --dc 10.0.0.5",
            "Analyse BloodHound + Certipy")
    example("horuseye --bloodhound ./bh/ --domain corp.local --graph --owned 'bob@corp.local'",
            "Shortest path from a foothold to Domain Admin")
    example("horuseye --bloodhound ./bh/ --domain corp.local --report r.html --markdown r.md --json r.json",
            "Full report set for an engagement")
    example("horuseye --bloodhound ./bh/ --domain corp.local --diff last.json --fail-on high",
            "Retest and gate CI on HIGH+ findings")
    blank()
    if RICH:
        console.print("    [dim]github.com/Omar-tamerr/HorusEye[/dim]")
    blank()
