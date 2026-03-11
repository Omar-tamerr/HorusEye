"""
HorusEye v3.0 - Help Printer
Hardcoded, offline, Rich-formatted help system.
Author: Omar Tamer 🇪🇬
"""

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.table import Table
    from rich import box
    RICH = True
except ImportError:
    RICH = False

import sys

console = Console() if RICH else None

# ── Palette ────────────────────────────────────────────────────────────────────
R  = "bold red"
W  = "bold white"
C  = "cyan"
G  = "green"
Y  = "yellow"
D  = "dim"
M  = "magenta"
GO = "bold yellow"


# ── Shared helpers ─────────────────────────────────────────────────────────────
def c_print(text, style=""):
    if RICH:
        console.print(text, style=style)
    else:
        print(text)


def rule(title="", color="red"):
    if RICH:
        from rich.rule import Rule
        console.print(Rule(title, style=color))
    else:
        print(f"\n{'─' * 60}  {title}")


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
        line.append(f"{name:<30}", style="green")
        line.append(desc, style="white")
        if default:
            line.append(f"  (default: {default})", style="dim")
        console.print(line)
    else:
        dflt = f"  (default: {default})" if default else ""
        print(f"{pad}{name:<30}{desc}{dflt}")


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


# ── BANNER ─────────────────────────────────────────────────────────────────────
BANNER = """
 ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗
 ██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝
 ███████║██║   ██║██████╔╝██║   ██║███████╗
 ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║
 ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
 ███████╗██╗   ██╗███████╗
 ██╔════╝╚██╗ ██╔╝██╔════╝
 █████╗   ╚████╔╝ █████╗   v3.0
 ██╔══╝    ╚██╔╝  ██╔══╝
 ███████╗   ██║   ███████╗
 ╚══════╝   ╚═╝   ╚══════╝"""


def print_banner():
    if RICH:
        console.print(BANNER, style="bold red")
        console.print(Panel.fit(
            "[bold white]𓂀  AI-Powered Active Directory Attack Platform  𓂀[/bold white]\n"
            "[dim]5-Phase Engagement Pipeline  |  13 Attack Types  |  AI-Driven Evasion[/dim]\n\n"
            "      [bold red]🇪🇬[/bold red]  [bold white]Made with ❤️  by Omar Tamer[/bold white]  [bold red]🇪🇬[/bold red]\n\n"
            "  [dim]linkedin.com/in/omar-tamer-1a986b2a7[/dim]  [dim]•[/dim]  "
            "[dim]medium.com/@OmarTamer0[/dim]  [dim]•[/dim]  "
            "[dim]omar-tamerr.github.io[/dim]",
            border_style="red", padding=(1, 6)
        ))
    else:
        print(BANNER)
        print("𓂀  AI-Powered Active Directory Attack Platform  𓂀")
        print("By Omar Tamer | github.com/omar-tamerr/HorusEye")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN HELP
# ══════════════════════════════════════════════════════════════════════════════
def help_main(no_banner=False):
    if not no_banner:
        print_banner()
    blank()
    rule("USAGE", "red")
    blank()

    if RICH:
        console.print("    [cyan]horuseye[/cyan] [yellow]<phase>[/yellow] [dim][options][/dim]")
        console.print("    [cyan]horuseye[/cyan] [yellow]--auto[/yellow]  [dim][options]    # run all phases automatically[/dim]")
    else:
        print("    horuseye <phase> [options]")
        print("    horuseye --auto  [options]")

    blank()
    rule("PHASES", "red")
    blank()

    phases = [
        ("recon",      "red",    "Profile the environment before touching anything",
         "Discovers DCs, maps the network, detects EDR, builds impersonation\n"
         "                         profile. Start here when you have zero knowledge."),
        ("enum",       "yellow", "Map the domain and find every attack path",
         "Parses BloodHound, Certipy, ldapdomaindump, NXC, CrackMapExec.\n"
         "                         Detects 13 attack types scored by exploitability."),
        ("exploit",    "red",    "Execute the highest value attack paths",
         "Kerberoasting, AS-REP, hash cracking, password spraying.\n"
         "                         Handles hashes, tickets, and certificates directly."),
        ("pivot",      "magenta","Expand access across the network",
         "NXC validation, lateral movement mapping, LSASS dump.\n"
         "                         Pass-the-Hash, Pass-the-Ticket, WinRM shell."),
        ("objective",  "green",  "Reach the end goal",
         "DCSync, persistence, Golden Ticket, attack timeline.\n"
         "                         DA checklist, team collaboration, report export."),
    ]

    for name, col, short, detail in phases:
        if RICH:
            console.print(f"    [bold {col}]{name:<14}[/bold {col}][white]{short}[/white]")
            console.print(f"    {'':14}[dim]{detail}[/dim]")
        else:
            print(f"    {name:<14}{short}")
            print(f"    {'':14}{detail}")
        blank()

    rule("GLOBAL OPTIONS", "red")
    blank()
    flag("--auto",              "Run all phases in order automatically")
    flag("--domain DOMAIN",     "Target domain name (e.g. corp.local)")
    flag("--dc IP",             "Domain Controller IP address")
    flag("--target CIDR",       "Network range (e.g. 10.10.10.0/24)")
    flag("--no-ai",             "Skip Claude AI analysis (faster, offline)")
    flag("--config",            "Configure API keys and preferences")
    flag("--version",           "Show version information")
    flag("-h, --help",          "Show help (add after any phase for phase help)")

    blank()
    rule("QUICK EXAMPLES", "red")
    blank()
    example("horuseye recon --target 10.10.10.0/24 --mode silent",
            "Zero knowledge, start silent")
    example("horuseye enum --bloodhound ./bh/ --certipy certipy.json",
            "You have BloodHound output")
    example("horuseye exploit --kerberoast -u user -p pass --domain corp.local",
            "Kerberoast and auto-crack")
    example("horuseye pivot --map --target-network 10.10.10.0/24 -u svc-sql -p pass",
            "Map network with found creds")
    example("horuseye objective --dcsync --dc 10.10.10.5 -u svc-sql -p pass",
            "DCSync for all hashes")
    example("horuseye --auto --target 10.10.10.0/24 --domain corp.local --dc 10.10.10.5",
            "Full auto run")

    blank()
    rule("PHASE HELP", "red")
    blank()
    if RICH:
        console.print("    [dim]Run[/dim] [cyan]horuseye <phase> --help[/cyan] [dim]for detailed options[/dim]")
        console.print("    [dim]Example:[/dim] [cyan]horuseye recon --help[/cyan]")
    else:
        print("    Run: horuseye <phase> --help for detailed options")

    blank()
    if RICH:
        console.print(f"    [dim]github.com/omar-tamerr/HorusEye[/dim]")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  RECON HELP
# ══════════════════════════════════════════════════════════════════════════════
def help_recon(no_banner=False):
    if not no_banner:
        print_banner()
    blank()

    if RICH:
        console.print(Panel(
            "[bold white]Profile the environment silently before any enumeration or exploitation.\n"
            "Answers: what is on this network, what tools are trusted here,\n"
            "and what is the right way to stay invisible.[/bold white]",
            title="[bold red]𓂀  PHASE 1: RECON[/bold red]",
            border_style="red"
        ))
    else:
        print("PHASE 1: RECON")
        print("Profile the environment before touching anything.")

    blank()
    section("WHEN TO USE", "red")
    if RICH:
        console.print("    [dim]You just got on the network and know nothing[/dim]")
        console.print("    [dim]You want to avoid triggering EDR during enumeration[/dim]")
        console.print("    [dim]You need to know what impersonation profile to use[/dim]")
    else:
        print("    You just got on the network and know nothing")
        print("    You want to avoid triggering EDR")

    blank()
    section("PROFILING MODE  [--mode]", "yellow")
    blank()

    if RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="bold green",  width=12)
        t.add_column(style="white",       width=55)
        t.add_column(style="dim",         width=20)
        t.add_row("silent",
                  "Pure passive. Listen to existing traffic only.\n"
                  "Zero active probing. Completely invisible.\n"
                  "Builds picture over 15-30 minutes.",
                  "Use when: SOC present,\nhigh security env")
        t.add_row("", "", "")
        t.add_row("active",
                  "Low volume probing blended into background noise.\n"
                  "Builds picture in 2-5 minutes.\n"
                  "Tiny detection risk during profiling only.",
                  "Use when: standard\nengagement, speed matters")
        console.print(t)
    else:
        print("    silent   Pure passive. Zero active probing. 15-30 minutes.")
        print("    active   Low volume probing. 2-5 minutes. Small risk.")

    blank()
    section("EVASION MODE  [--evasion]", "yellow")
    blank()

    if RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="bold green", width=12)
        t.add_column(style="white",      width=55)
        t.add_column(style="dim",        width=20)
        t.add_row("live",
                  "Claude generates a unique never-seen-before evasion\n"
                  "pattern for every action in real time.\n"
                  "Requires internet + API key. Adds 2-5s latency.",
                  "Use when: mature EDR,\nmaximum stealth needed")
        t.add_row("", "", "")
        t.add_row("library",
                  "Pre-generated pattern library. Works fully offline.\n"
                  "No latency, no API dependency during engagement.\n"
                  "Fast and reliable.",
                  "Use when: air-gapped,\nno internet available")
        t.add_row("", "", "")
        t.add_row("hybrid",
                  "Library as base, Claude enhances when online.\n"
                  "Best of both worlds. Recommended default.",
                  "Recommended")
        console.print(t)
    else:
        print("    live     Claude generates novel patterns in real time.")
        print("    library  Pre-generated library. Works offline.")
        print("    hybrid   Library + Claude when available. Recommended.")

    blank()
    section("OPTIONS", "yellow")
    blank()
    flag("--target CIDR",       "Network range to profile",                         required=True)
    flag("--mode MODE",         "silent or active",                                 "active")
    flag("--evasion MODE",      "live, library, or hybrid",                         "hybrid")
    flag("--timeout INT",       "Profiling timeout in minutes",                     "10")
    flag("--output FILE",       "Save recon profile to file for later use")
    flag("--load FILE",         "Load existing recon profile instead of scanning")
    flag("--domain DOMAIN",     "Target domain name if known")
    flag("--dc IP",             "Domain Controller IP if known")

    blank()
    section("OUTPUT", "yellow")
    if RICH:
        items = [
            "Domain Controller IP and hostname",
            "Full network topology and roadmap tree",
            "EDR and AV stack detected on network",
            "Trusted tools present (SCCM, Veeam, RSAT, etc.)",
            "Selected impersonation target with AI reasoning",
            "Evasion profile generated for this specific environment",
        ]
        for item in items:
            console.print(f"    [green]✓[/green] [white]{item}[/white]")
    else:
        print("    DC discovery, network topology, EDR detection,")
        print("    impersonation target, evasion profile")

    blank()
    section("EXAMPLES", "yellow")
    blank()
    example("horuseye recon --target 10.10.10.0/24",
            "Active recon, hybrid evasion (defaults)")
    example("horuseye recon --target 10.10.10.0/24 --mode silent --evasion live",
            "Maximum stealth")
    example("horuseye recon --target 10.10.10.0/24 --output corp.profile",
            "Save profile for later")
    example("horuseye recon --load corp.profile",
            "Skip scan, use saved profile")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  ENUM HELP
# ══════════════════════════════════════════════════════════════════════════════
def help_enum(no_banner=False):
    if not no_banner:
        print_banner()
    blank()

    if RICH:
        console.print(Panel(
            "[bold white]Map the domain and detect every attack path available.\n"
            "Accepts output from any major AD recon tool or runs its own\n"
            "silent LDAP enumeration without dropping SharpHound.[/bold white]",
            title="[bold yellow]𓂀  PHASE 2: ENUM[/bold yellow]",
            border_style="yellow"
        ))

    blank()
    section("WHEN TO USE", "yellow")
    if RICH:
        console.print("    [dim]After recon, or when you already have BloodHound/Certipy output[/dim]")
        console.print("    [dim]When you need to understand the full attack surface before acting[/dim]")
        console.print("    [dim]When you want AI analysis of which path to take first[/dim]")

    blank()
    section("INPUT SOURCES  (use one or combine all)", "yellow")
    blank()
    flag("--bloodhound DIR",    "BloodHound JSON folder from SharpHound")
    flag("--certipy FILE",      "Certipy JSON output for ADCS ESC1-8 detection")
    flag("--ldap DIR",          "ldapdomaindump output folder")
    flag("--cme FILE",          "CrackMapExec scan output")
    flag("--nxc FILE",          "NetExec scan output (modern CME replacement)")
    flag("--manual",            "Interactive input when no files available")
    flag("--silent-enum",       "Built-in silent LDAP enumeration (no SharpHound)")

    blank()
    section("ATTACK TYPES DETECTED", "yellow")
    blank()

    if RICH:
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        t.add_column("Severity",   style="bold",   width=12)
        t.add_column("Attack Type",style="white",  width=30)
        t.add_column("What It Finds", style="dim", width=40)

        attacks = [
            ("CRITICAL", "Kerberoasting",         "SPNs, DA member service accounts"),
            ("CRITICAL", "DCSync",                "Replicating Directory Changes rights"),
            ("CRITICAL", "ADCS ESC1-8",           "All Certipy vulnerability classes"),
            ("CRITICAL", "Unconstrained Deleg.",  "Full impersonation capability"),
            ("HIGH",     "AS-REP Roasting",       "DONT_REQUIRE_PREAUTH accounts"),
            ("HIGH",     "ACL Abuse",             "GenericAll, WriteDacl, WriteOwner"),
            ("HIGH",     "Constrained Deleg.",    "msDS-AllowedToDelegateTo abuse"),
            ("HIGH",     "GPO Abuse",             "Write access on Group Policy Objects"),
            ("MEDIUM",   "Domain Trusts",         "Cross-domain relationships"),
            ("MEDIUM",   "Privileged Sessions",   "DA sessions on reachable hosts"),
            ("MEDIUM",   "Pass-the-Hash paths",   "Reusable NTLM hash opportunities"),
            ("LOW",      "Weak Password Policy",  "Lockout threshold, complexity, length"),
            ("LOW",      "Stale Admin Accounts",  "Inactive elevated privilege accounts"),
        ]

        sev_colors = {
            "CRITICAL": "bold red",
            "HIGH":     "bold yellow",
            "MEDIUM":   "bold cyan",
            "LOW":      "dim",
        }

        for sev, name, detail in attacks:
            t.add_row(
                f"[{sev_colors[sev]}]{sev}[/{sev_colors[sev]}]",
                name,
                detail
            )
        console.print(t)
    else:
        print("    CRITICAL: Kerberoasting, DCSync, ADCS ESC1-8, Unconstrained Delegation")
        print("    HIGH:     AS-REP, ACL Abuse, Constrained Delegation, GPO Abuse")
        print("    MEDIUM:   Domain Trusts, Privileged Sessions, Pass-the-Hash")
        print("    LOW:      Weak Password Policy, Stale Admin Accounts")

    blank()
    section("OPTIONS", "yellow")
    blank()
    flag("--domain DOMAIN",     "Target domain name")
    flag("--dc IP",             "Domain Controller IP")
    flag("--severity LEVEL",    "Filter: critical, high, all",              "all")
    flag("--no-ai",             "Skip Claude attack narrative analysis")
    flag("--deep",              "Deep AI analysis, more detailed narratives")
    flag("--output FILE",       "Save findings to file")
    flag("--json FILE",         "Export findings as JSON")

    blank()
    section("EXAMPLES", "yellow")
    blank()
    example("horuseye enum --bloodhound ./bh/ --certipy certipy.json --domain corp.local",
            "Full analysis with BloodHound and Certipy")
    example("horuseye enum --silent-enum --domain corp.local --dc 10.10.10.5",
            "No files, silent LDAP enumeration")
    example("horuseye enum --bloodhound ./bh/ --severity critical --deep",
            "Critical only with deep AI analysis")
    example("horuseye enum --bloodhound ./bh/ --certipy certipy.json --nxc nxc.txt --domain corp.local",
            "Combine all sources")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  EXPLOIT HELP
# ══════════════════════════════════════════════════════════════════════════════
def help_exploit(no_banner=False):
    if not no_banner:
        print_banner()
    blank()

    if RICH:
        console.print(Panel(
            "[bold white]Execute the highest value attack paths found during enumeration.\n"
            "Handles any credential material a real engagement produces.\n"
            "All found credentials saved automatically to valid_credentials.txt[/bold white]",
            title="[bold red]𓂀  PHASE 3: EXPLOIT[/bold red]",
            border_style="red"
        ))

    blank()
    section("ATTACK EXECUTION", "red")
    blank()
    flag("--kerberoast",        "Request TGS for all Kerberoastable SPNs, auto-crack")
    flag("--asrep",             "AS-REP roast all vulnerable accounts (no creds needed)")
    flag("--auto-chain",        "Kerberoast > crack > validate > pivot automatically")

    blank()
    section("CREDENTIAL MATERIAL  (real engagement inputs)", "red")
    blank()

    if RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="bold green", width=20)
        t.add_column(style="white",      width=60)
        t.add_row("--ntlmv2 FILE",
                  "NetNTLMv2 from Responder or Inveigh\n"
                  "Attempts crack. If fails, maps NTLM relay targets.")
        t.add_row("--ntlm-hash HASH",
                  "NTLM hash for immediate Pass-the-Hash\n"
                  "No cracking needed. Validates across network via NXC.")
        t.add_row("--ticket FILE",
                  "Kerberos TGT or TGS (.ccache or .kirbi)\n"
                  "Pass-the-Ticket. Maps what this ticket unlocks.")
        t.add_row("--cert FILE",
                  "Certificate from ADCS attack (.pfx)\n"
                  "PKINIT auth. Converts to NTLM hash.")
        console.print(t)
    else:
        print("    --ntlmv2 FILE      NetNTLMv2 from Responder. Crack or relay.")
        print("    --ntlm-hash HASH   NTLM hash for Pass-the-Hash via NXC.")
        print("    --ticket FILE      TGT/TGS for Pass-the-Ticket.")
        print("    --cert FILE        ADCS certificate for PKINIT auth.")

    blank()
    section("HASH CRACKING", "red")
    blank()
    flag("--crack FILE",        "Crack hashes from file")
    flag("--hash-type TYPE",    "kerberoast, asrep, ntlm, ntlmv2, mscache2  (auto-detected)")
    flag("--wordlist FILE",     "Custom wordlist path or name")
    flag("--rules PROFILE",     "fast, medium, aggressive, corporate",       "fast")
    flag("--crack-timeout INT", "Seconds per hashcat round",                 "300")

    blank()
    if RICH:
        console.print("    [dim]Cracking rounds:[/dim]")
        console.print("    [green]Round 1[/green]  [white]AD-specific corporate patterns[/white]  "
                      "[dim](Corp2024!, Welcome2024!, Summer2024!)[/dim]")
        console.print("    [green]Round 2[/green]  [white]Wordlist + hashcat rule mutations[/white]  "
                      "[dim](rockyou + best64/dive/d3ad0ne)[/dim]")
        console.print("    [green]Round 3[/green]  [white]Hybrid mask attack[/white]  "
                      "[dim](word + year/number suffix)[/dim]")
    else:
        print("    Round 1: AD corporate patterns  Round 2: Wordlist+rules  Round 3: Hybrid mask")

    blank()
    section("PASSWORD SPRAYING", "red")
    blank()
    flag("--spray",             "Run password spray against domain")
    flag("--users-file FILE",   "Username list")
    flag("--password PASS",     "Single password to spray")
    flag("--passwords-file",    "Multiple passwords file")
    flag("--delay FLOAT",       "Delay between attempts",                    "1.0s")
    flag("--jitter FLOAT",      "Random jitter added to delay",              "0.5s")
    flag("--threads INT",       "Concurrent threads",                        "5")
    flag("--safe",              "Auto-stop on first lockout detected")

    blank()
    section("WORDLIST GENERATION", "red")
    blank()
    flag("--make-wordlist",     "Generate 18 username variants per AD user")
    flag("--firstname NAME",    "Single first name for variant generation")
    flag("--lastname NAME",     "Single last name for variant generation")
    flag("--output FILE",       "Output wordlist file",                      "usernames.txt")

    blank()
    section("OPTIONS", "red")
    blank()
    flag("-u, --username USER", "Username for authentication")
    flag("-p, --password PASS", "Password for authentication")
    flag("-H, --hash HASH",     "NTLM hash for Pass-the-Hash")
    flag("--domain DOMAIN",     "Target domain")
    flag("--dc IP",             "Domain Controller IP")

    blank()
    section("EXAMPLES", "red")
    blank()
    example("horuseye exploit --kerberoast --domain corp.local --dc 10.10.10.5 -u user -p pass",
            "Kerberoast and auto-crack")
    example("horuseye exploit --crack hashes.txt --hash-type kerberoast --rules aggressive",
            "Crack existing hash file")
    example("horuseye exploit --ntlmv2 responder.txt --domain corp.local",
            "Handle NetNTLMv2 from Responder")
    example("horuseye exploit --spray --users-file users.txt --password 'Summer2024!' --safe",
            "Safe password spray")
    example("horuseye exploit --auto-chain --domain corp.local --dc 10.10.10.5 -u user -p pass",
            "Full auto chain to DA")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  PIVOT HELP
# ══════════════════════════════════════════════════════════════════════════════
def help_pivot(no_banner=False):
    if not no_banner:
        print_banner()
    blank()

    if RICH:
        console.print(Panel(
            "[bold white]Expand access across the network using credentials from exploitation.\n"
            "Maps every reachable host, validates access at scale,\n"
            "and sets up the path to your final objective.[/bold white]",
            title="[bold magenta]𓂀  PHASE 4: PIVOT[/bold magenta]",
            border_style="magenta"
        ))

    blank()
    section("WHEN TO USE", "magenta")
    if RICH:
        console.print("    [dim]After exploit has given you valid credentials or hashes[/dim]")
        console.print("    [dim]When you need to know where those credentials work at scale[/dim]")
        console.print("    [dim]When you need admin access on a specific high-value host[/dim]")

    blank()
    section("LATERAL MOVEMENT", "magenta")
    blank()
    flag("--map",               "Map entire network with current credentials via NXC")
    flag("--target-network CIDR","Network range to map  (e.g. 10.10.10.0/24)")
    flag("--nxc-validate",      "Test all found credentials across network via NXC")
    flag("--nxc-enum HOST",     "Full NXC enumeration on specific host")

    blank()
    if RICH:
        console.print("    [dim]--map output: reachable hosts, admin access, open protocols,[/dim]")
        console.print("    [dim]              interesting shares, logged-in users per host[/dim]")
        console.print("    [dim]              Results feed back into roadmap tree automatically[/dim]")

    blank()
    section("CREDENTIAL ATTACKS", "magenta")
    blank()
    flag("--pth HOST",          "Pass-the-Hash against specific host")
    flag("--ptt FILE",          "Pass-the-Ticket (.ccache file)")
    flag("--winrm HOST",        "WinRM interactive shell + whoami /priv analysis")

    blank()
    section("LSASS DUMP", "magenta")
    blank()
    flag("--lsass HOST",        "Dump LSASS on target, auto-selects method by EDR")
    blank()

    if RICH:
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        t.add_column("EDR Detected",    style="bold red",  width=30)
        t.add_column("Method Selected", style="green",     width=20)
        t.add_column("Stealth",         style="dim",       width=10)
        t.add_row("CrowdStrike / SentinelOne", "nanodump",          "10/10")
        t.add_row("Windows Defender",          "comsvcs rundll32",  "8/10")
        t.add_row("Nothing detected",          "comsvcs rundll32",  "8/10")
        t.add_row("Fallback",                  "procdump",          "5/10")
        console.print(t)
    else:
        print("    CrowdStrike/SentinelOne > nanodump")
        print("    Windows Defender        > comsvcs rundll32")
        print("    Nothing detected        > comsvcs rundll32")
        print("    Fallback                > procdump")

    blank()
    section("OPTIONS", "magenta")
    blank()
    flag("-u, --username USER", "Username")
    flag("-p, --password PASS", "Password")
    flag("-H, --hash HASH",     "NTLM hash")
    flag("--domain DOMAIN",     "Target domain")
    flag("--dc IP",             "Domain Controller IP")
    flag("--threads INT",       "Concurrent threads",                        "10")

    blank()
    section("EXAMPLES", "magenta")
    blank()
    example("horuseye pivot --map --target-network 10.10.10.0/24 -u svc-sql -p 'ServicePass2024!'",
            "Map network after getting creds")
    example("horuseye pivot --pth 10.10.10.5 -u Administrator -H <ntlm_hash>",
            "Pass-the-Hash on DC")
    example("horuseye pivot --lsass 10.10.10.10 -u svc-sql -p 'ServicePass2024!'",
            "Auto LSASS dump")
    example("horuseye pivot --nxc-validate --target-network 10.10.10.0/24",
            "Validate all found credentials")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  OBJECTIVE HELP
# ══════════════════════════════════════════════════════════════════════════════
def help_objective(no_banner=False):
    if not no_banner:
        print_banner()
    blank()

    if RICH:
        console.print(Panel(
            "[bold white]Reach Domain Admin, establish persistence, and document everything.\n"
            "The final phase of the engagement.[/bold white]",
            title="[bold green]𓂀  PHASE 5: OBJECTIVE[/bold green]",
            border_style="green"
        ))

    blank()
    section("DOMAIN ADMIN", "green")
    blank()
    flag("--dcsync",            "Execute DCSync, dump all domain hashes")
    flag("--auto-exploit",      "Full automated path to DA from current position")

    blank()
    section("PERSISTENCE", "green")
    blank()
    flag("--golden-ticket",     "Create Golden Ticket from krbtgt hash (requires DCSync)")
    flag("--skeleton-key",      "Install Skeleton Key on DC (requires DA)")
    flag("--auto-persist",      "Suggest and execute best persistence for current access")

    blank()
    section("TRACKING", "green")
    blank()
    flag("--checklist",         "25-item domain takeover checklist, auto-checks progress")
    flag("--timeline",          "Visual T+0 to DA timeline with exact commands per step")

    blank()
    section("REPORTING", "green")
    blank()
    flag("--report FILE",       "Generate full HTML report (dark theme)")
    flag("--json FILE",         "Export all findings as JSON")
    flag("--severity LEVEL",    "Filter report: critical, high, all",        "all")

    blank()
    section("TEAM COLLABORATION", "green")
    blank()
    flag("--team-server",       "Start collab server for multi-operator session")
    flag("--team-connect HOST", "Join existing team session  (HOST:PORT)")
    flag("--team-port INT",     "Server port",                               "31337")

    blank()
    if RICH:
        console.print("    [dim]Team collab features:[/dim]")
        console.print("    [dim]  Real-time credential broadcasting to all operators[/dim]")
        console.print("    [dim]  Full state sync for operators who join late[/dim]")
        console.print("    [dim]  Live finding broadcast as they are discovered[/dim]")
        console.print("    [dim]  Chat between operators during engagement[/dim]")

    blank()
    section("OPTIONS", "green")
    blank()
    flag("-u, --username USER", "Username")
    flag("-p, --password PASS", "Password")
    flag("-H, --hash HASH",     "NTLM hash")
    flag("--domain DOMAIN",     "Target domain")
    flag("--dc IP",             "Domain Controller IP")

    blank()
    section("EXAMPLES", "green")
    blank()
    example("horuseye objective --dcsync --dc 10.10.10.5 -u svc-sql -p 'ServicePass2024!'",
            "DCSync for all hashes")
    example("horuseye objective --golden-ticket --dc 10.10.10.5 -u Administrator -H <krbtgt>",
            "Golden Ticket after DA")
    example("horuseye objective --checklist --timeline --report report.html",
            "Full engagement wrap-up")
    example("horuseye objective --team-server --team-port 31337",
            "Start team collab server")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO MODE HELP
# ══════════════════════════════════════════════════════════════════════════════
def help_auto(no_banner=False):
    if not no_banner:
        print_banner()
    blank()

    if RICH:
        console.print(Panel(
            "[bold white]Runs all five phases in order automatically.\n"
            "Each phase passes its output directly into the next.\n"
            "You watch the engagement unfold. Intervene at any point.[/bold white]",
            title="[bold red]𓂀  AUTO MODE[/bold red]",
            border_style="red"
        ))

    blank()
    section("FLOW", "red")
    blank()

    if RICH:
        flow = [
            ("recon",     "red",    "Profile environment, detect EDR, build impersonation profile"),
            ("enum",      "yellow", "Silent enumeration, detect all 13 attack path types"),
            ("exploit",   "red",    "Execute highest scored path, crack hashes"),
            ("pivot",     "magenta","Validate credentials via NXC, map admin access"),
            ("objective", "green",  "Reach DA, establish persistence, export timeline"),
        ]
        for i, (phase, col, desc) in enumerate(flow):
            console.print(f"    [bold {col}]{phase:<12}[/bold {col}] [white]{desc}[/white]")
            if i < len(flow) - 1:
                console.print(f"    [dim]{'':12} |[/dim]")
    else:
        print("    recon > enum > exploit > pivot > objective")

    blank()
    section("OPTIONS", "red")
    blank()
    flag("--target CIDR",       "Network range  (required)")
    flag("--domain DOMAIN",     "Target domain  (required)")
    flag("--dc IP",             "Domain Controller IP  (required)")
    flag("--mode MODE",         "Recon mode: silent or active",              "active")
    flag("--evasion MODE",      "live, library, or hybrid",                  "hybrid")
    flag("--no-ai",             "Skip AI analysis")
    flag("--pause",             "Pause and confirm before each phase")
    flag("--stop-at PHASE",     "Stop after phase: recon, enum, exploit, pivot")

    blank()
    section("EXAMPLES", "red")
    blank()
    example("horuseye --auto --target 10.10.10.0/24 --domain corp.local --dc 10.10.10.5",
            "Full auto run")
    example("horuseye --auto --target 10.10.10.0/24 --domain corp.local --pause",
            "Pause before each phase")
    example("horuseye --auto --target 10.10.10.0/24 --domain corp.local --stop-at enum",
            "Auto recon and enum only")
    example("horuseye --auto --target 10.10.10.0/24 --domain corp.local --mode silent --evasion live",
            "Maximum stealth auto run")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTER
# ══════════════════════════════════════════════════════════════════════════════
def show_help(topic=None, no_banner=False):
    """
    Main entry point. Call with topic string or None for main help.

    Usage in horuseye.py:
        from utils.help_printer import show_help
        show_help()                        # main help with banner
        show_help(no_banner=True)          # main help, banner already shown
        show_help("recon")                 # recon phase help with banner
        show_help("recon", no_banner=True) # recon phase help, no banner
    """
    dispatch = {
        "recon":     help_recon,
        "enum":      help_enum,
        "exploit":   help_exploit,
        "pivot":     help_pivot,
        "objective": help_objective,
        "auto":      help_auto,
    }

    if topic and topic.lower() in dispatch:
        dispatch[topic.lower()](no_banner=no_banner)
    else:
        help_main(no_banner=no_banner)


# ── Standalone test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    topic = sys.argv[1] if len(sys.argv) > 1 else None
    show_help(topic)
