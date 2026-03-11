"""
HorusEye v2 — Attack Timeline Generator
Visual ASCII timeline: T+0min foothold → T+Xmin Domain Admin
Author: Omar Tamer 🇪🇬
"""

import re
from datetime import datetime
from typing import List, Dict, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    RICH = True
except ImportError:
    RICH = False

# ── Attack timing estimates (minutes) ────────────────────────────────────────

ATTACK_TIMES: Dict[str, Dict] = {
    "ASREP_ROASTING":             {"exec": 1,  "crack": 15, "label": "AS-REP Roast"},
    "KERBEROASTING":              {"exec": 2,  "crack": 20, "label": "Kerberoast"},
    "DCSYNC":                     {"exec": 3,  "crack": 0,  "label": "DCSync"},
    "ACL_ABUSE":                  {"exec": 5,  "crack": 0,  "label": "ACL Abuse"},
    "GPO_ABUSE":                  {"exec": 10, "crack": 0,  "label": "GPO Abuse"},
    "UNCONSTRAINED_DELEGATION":   {"exec": 15, "crack": 0,  "label": "Unconstrained Deleg."},
    "CONSTRAINED_DELEGATION":     {"exec": 8,  "crack": 0,  "label": "Constrained Deleg."},
    "PASS_THE_HASH":              {"exec": 3,  "crack": 0,  "label": "Pass-the-Hash"},
    "ADCS_ESC1":                  {"exec": 2,  "crack": 0,  "label": "ADCS ESC1"},
    "ADCS_ESC4":                  {"exec": 5,  "crack": 0,  "label": "ADCS ESC4"},
    "ADCS_ESC6":                  {"exec": 2,  "crack": 0,  "label": "ADCS ESC6"},
    "ADCS_ESC8":                  {"exec": 10, "crack": 0,  "label": "ADCS ESC8"},
    "DOMAIN_TRUST":               {"exec": 20, "crack": 0,  "label": "Domain Trust"},
    "WEAK_PASSWORD_POLICY":       {"exec": 30, "crack": 0,  "label": "Password Spray"},
    "PRIVILEGED_SESSION_EXPOSURE":{"exec": 5,  "crack": 0,  "label": "Session Hijack"},
}

PHASE_MAP: Dict[str, str] = {
    "ASREP_ROASTING": "ESCALATION", "KERBEROASTING": "ESCALATION",
    "ACL_ABUSE": "ESCALATION",      "GPO_ABUSE": "ESCALATION",
    "ADCS_ESC1": "ESCALATION",      "ADCS_ESC4": "ESCALATION",
    "ADCS_ESC6": "ESCALATION",      "ADCS_ESC8": "ESCALATION",
    "DCSYNC": "DA",
    "PASS_THE_HASH": "LATERAL",     "DOMAIN_TRUST": "LATERAL",
    "UNCONSTRAINED_DELEGATION": "DA","CONSTRAINED_DELEGATION": "ESCALATION",
    "PRIVILEGED_SESSION_EXPOSURE": "LATERAL",
}

PHASE_ICONS = {
    "FOOTHOLD": "🎯", "ESCALATION": "⚡",
    "LATERAL":  "🔄", "DA":         "💀",
    "PERSIST":  "🔒", "EXFIL":      "📤",
}

PHASE_COLORS_PLAIN = {
    "FOOTHOLD": "", "ESCALATION": "", "LATERAL": "", "DA": "***",
    "PERSIST": "**", "EXFIL": "",
}


class AttackTimeline:
    def __init__(self, console=None):
        # Auto-create console if not provided and Rich is available
        if console is None and RICH:
            from rich.console import Console as RichConsole
            self.console = RichConsole()
        else:
            self.console = console  # may be None if Rich not installed
        self.events: List[Dict] = []

    # ── Public API ────────────────────────────────────────────────────────

    def build_from_findings(self, findings: List[Dict], domain: str,
                             initial_creds: Optional[Dict] = None) -> List[Dict]:
        """Build timeline events from scored findings list."""
        self.events = []
        current_min = 0

        # Phase 0: Foothold
        self.events.append({
            "phase": "FOOTHOLD", "t_min": 0,
            "title": "Initial Access",
            "detail": f"Low-privilege domain user obtained on {domain}",
            "severity": "INFO", "type": "FOOTHOLD", "commands": []
        })

        # Phase 1: Recon
        current_min += 5
        self.events.append({
            "phase": "FOOTHOLD", "t_min": current_min,
            "title": "BloodHound Enumeration",
            "detail": f"SharpHound collection — {len(findings)} attack paths identified",
            "severity": "INFO", "type": "RECON",
            "commands": ["SharpHound.exe -c All"]
        })

        # Phase 2: Attack chain from top findings
        scored = sorted(findings, key=lambda f: -f.get("score", 0))
        da_reached = False

        for finding in scored[:8]:
            ftype  = finding.get("type", "")
            timing = ATTACK_TIMES.get(ftype, {"exec": 5, "crack": 0, "label": ftype})
            phase  = PHASE_MAP.get(ftype, "ESCALATION")
            current_min += timing["exec"]

            event = {
                "phase":        phase,
                "t_min":        current_min,
                "title":        timing["label"],
                "detail":       finding.get("title", ""),
                "affected":     finding.get("affected", ""),
                "severity":     finding.get("severity", "HIGH"),
                "score":        finding.get("score", 0),
                "type":         ftype,
                "commands":     finding.get("commands", [])[:2],
                "ai_narrative": finding.get("ai_narrative", ""),
            }

            if timing["crack"] > 0:
                self.events.append(event)
                current_min += timing["crack"]
                self.events.append({
                    "phase": phase, "t_min": current_min,
                    "title": "Hash Cracked ✓",
                    "detail": f"Offline crack complete for {finding.get('affected','')}",
                    "severity": "CRITICAL", "type": "CRACK",
                    "commands": ["hashcat -m 13100 hash.txt rockyou.txt"]
                })
            else:
                self.events.append(event)

            if phase == "DA" and not da_reached:
                da_reached = True
                current_min += 2
                self.events.append({
                    "phase": "DA", "t_min": current_min,
                    "title": "💀 DOMAIN ADMIN ACHIEVED",
                    "detail": f"Full domain compromise of {domain}",
                    "severity": "CRITICAL", "type": "DA_ACHIEVED",
                    "commands": [
                        f"secretsdump.py {domain}/user@DC_IP -just-dc",
                        "mimikatz # lsadump::dcsync /domain:domain /all"
                    ]
                })
                current_min += 5
                self.events.append({
                    "phase": "PERSIST", "t_min": current_min,
                    "title": "Golden Ticket Created",
                    "detail": "Forged Kerberos ticket — 10-year validity",
                    "severity": "CRITICAL", "type": "PERSIST",
                    "commands": [
                        "mimikatz # kerberos::golden /domain:domain /sid:S-1-5 /krbtgt:HASH /user:Administrator"
                    ]
                })
                break

        if not da_reached:
            current_min += 5
            self.events.append({
                "phase": "DA", "t_min": current_min,
                "title": "💀 DOMAIN ADMIN ACHIEVED",
                "detail": f"Full domain compromise of {domain} via chained attacks",
                "severity": "CRITICAL", "type": "DA_ACHIEVED", "commands": []
            })

        return self.events

    def print_timeline(self, domain: str):
        """Print attack timeline — works with or without Rich."""
        if not self.events:
            self._p("⚠️  No timeline events. Call build_from_findings() first.")
            return

        if RICH and self.console:
            self._print_rich(domain)
        else:
            self._print_plain(domain)

    def export_timeline_txt(self, filepath: str, domain: str):
        """Export timeline to plain text file."""
        total = max(e["t_min"] for e in self.events) if self.events else 0
        lines = [
            "𓂀 HorusEye v2.0 — Attack Timeline",
            f"Target    : {domain}",
            f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Made by Omar Tamer 🇪🇬",
            "=" * 60, ""
        ]
        for event in self.events:
            lines.append(f"T+{event['t_min']:>3}m  [{event['phase']}]  {event['title']}")
            if event.get("detail"):
                lines.append(f"         {event['detail']}")
            for cmd in event.get("commands", []):
                lines.append(f"         $ {cmd}")
            lines.append("")
        lines.append(f"TOTAL TIME TO DA: {total} minutes")
        with open(filepath, "w") as f:
            f.write("\n".join(lines))
        self._p(f"📄 Timeline saved → {filepath}")

    # ── Rich display ──────────────────────────────────────────────────────

    def _print_rich(self, domain: str):
        total_time = max(e["t_min"] for e in self.events)
        phase_colors = {
            "FOOTHOLD": "cyan",   "ESCALATION": "yellow",
            "LATERAL":  "blue",   "DA":          "red",
            "PERSIST":  "magenta","EXFIL":       "orange1",
        }

        self.console.print()
        self.console.print(Rule(f"[bold red][ 𓂀 ATTACK TIMELINE — {domain} ][/bold red]"))
        self.console.print()
        self.console.print(Panel(
            f"[bold white]🎯 Target:[/bold white]      [cyan]{domain}[/cyan]\n"
            f"[bold white]⏱️  Time to DA:[/bold white]  [bold red]{total_time} minutes[/bold red]\n"
            f"[bold white]📋 Steps:[/bold white]       [cyan]{len(self.events)}[/cyan]",
            title="[bold red][ TIMELINE SUMMARY ][/bold red]",
            border_style="red", padding=(0, 4)
        ))
        self.console.print()

        # Phase legend
        phases_seen = list(dict.fromkeys(e["phase"] for e in self.events))
        legend = "  "
        for ph in phases_seen:
            c = phase_colors.get(ph, "white")
            legend += f"[{c}]{PHASE_ICONS.get(ph,'•')} {ph}[/{c}]   "
        self.console.print(legend)
        self.console.print()

        bar_width = 60
        self.console.print(f"  [dim]T+0{'─' * (bar_width - 8)}T+{total_time}m[/dim]")
        self.console.print()

        prev_phase = None
        for i, event in enumerate(self.events):
            phase  = event["phase"]
            t_min  = event["t_min"]
            title  = event["title"]
            detail = event.get("detail", "")
            ftype  = event.get("type", "")
            color  = phase_colors.get(phase, "white")
            sev_color = {"CRITICAL": "bold red", "HIGH": "bold yellow",
                         "MEDIUM": "yellow"}.get(event.get("severity",""), "white")

            if phase != prev_phase:
                self.console.print(f"\n  [{color}]{'━' * 55}[/{color}]")
                self.console.print(f"  [{color}]{PHASE_ICONS.get(phase,'•')} {phase} PHASE[/{color}]")
                self.console.print(f"  [{color}]{'━' * 55}[/{color}]")
                prev_phase = phase

            connector = "└─" if i == len(self.events) - 1 else "├─"
            time_str  = f"T+{t_min:>3}m"

            if ftype == "DA_ACHIEVED":
                self.console.print(f"\n  [bold red]{'█' * 55}[/bold red]")
                self.console.print(f"  [bold red on black]  {time_str}  💀  {title}  [/bold red on black]")
                self.console.print(f"  [bold red]{'█' * 55}[/bold red]\n")
            else:
                self.console.print(
                    f"  [dim]{time_str}[/dim]  [{color}]{connector}[/{color}] "
                    f"[{sev_color}]{title}[/{sev_color}]"
                )
                if detail:
                    self.console.print(f"             [dim]   {detail[:70]}[/dim]")
                cmds = event.get("commands", [])
                if cmds:
                    self.console.print(f"             [green on black]   $ {cmds[0][:65]}[/green on black]")
                ai = event.get("ai_narrative", "")
                if ai:
                    self.console.print(f"             [dim magenta]   🤖 {ai[:80]}[/dim magenta]")

        self.console.print()
        self.console.print(Panel(
            f"[bold red]⏱️  TOTAL TIME TO DOMAIN COMPROMISE: {total_time} MINUTES[/bold red]\n\n"
            f"[dim]𓂀 HorusEye v2.0 — Omar Tamer 🇪🇬[/dim]",
            border_style="red", padding=(1, 4)
        ))
        self.console.print()

    # ── Plain display ─────────────────────────────────────────────────────

    def _print_plain(self, domain: str):
        total_time = max(e["t_min"] for e in self.events)
        print(f"\n{'=' * 60}")
        print(f"  𓂀  ATTACK TIMELINE — {domain}")
        print(f"  Total time to DA: {total_time} minutes  |  {len(self.events)} steps")
        print(f"{'=' * 60}")
        prev_phase = None
        for event in self.events:
            phase  = event["phase"]
            t_min  = event["t_min"]
            title  = event["title"]
            detail = event.get("detail", "")
            ftype  = event.get("type", "")
            if phase != prev_phase:
                print(f"\n  ── {PHASE_ICONS.get(phase,'•')} {phase} ──")
                prev_phase = phase
            if ftype == "DA_ACHIEVED":
                print(f"\n  {'*' * 55}")
                print(f"  T+{t_min:>3}m  💀  {title}")
                print(f"  {'*' * 55}\n")
            else:
                print(f"  T+{t_min:>3}m  ├─ {title}")
                if detail:
                    print(f"              {detail[:70]}")
                for cmd in event.get("commands", [])[:1]:
                    print(f"              $ {cmd[:65]}")
        print(f"\n  TOTAL: {total_time} minutes to Domain Admin")
        print(f"{'=' * 60}\n")

    # ── Utility ───────────────────────────────────────────────────────────

    def _p(self, msg: str):
        if RICH and self.console:
            self.console.print(msg)
        else:
            clean = re.sub(r"\[/?[^\]]*\]", "", msg)
            print(clean)
