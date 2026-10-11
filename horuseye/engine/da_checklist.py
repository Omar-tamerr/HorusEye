"""
Domain Takeover Checklist.

Renders a step-by-step domain-takeover checklist and auto-ticks the recon
items that the detection engine has actually confirmed, so the progress bar
reflects the current run instead of a hardcoded placeholder.
"""
from __future__ import annotations

from typing import Dict, List

# Checklist item → the finding type(s) that satisfy it. Items with no mapping
# are manual steps the operator ticks off themselves.
_ITEMS = [
    ("DTC-01", "Initial foothold (low-priv domain user)",      None),
    ("DTC-02", "BloodHound / AD enumeration ingested",         "_recon"),
    ("DTC-03", "AS-REP roastable accounts identified",         "ASREP_ROASTING"),
    ("DTC-04", "Kerberoastable SPNs identified",               "KERBEROASTING"),
    ("DTC-05", "ACL abuse paths mapped",                       "ACL_ABUSE"),
    ("DTC-06", "ADCS templates checked (ESC1-ESC8)",           "ADCS_ESC"),
    ("DTC-07", "Unconstrained delegation hosts found",         "UNCONSTRAINED_DELEGATION"),
    ("DTC-08", "Constrained delegation checked",               "CONSTRAINED_DELEGATION"),
    ("DTC-09", "GPO write access checked",                     "GPO_ABUSE"),
    ("DTC-10", "Domain trusts enumerated",                     "DOMAIN_TRUST"),
    ("DTC-11", "Password policy reviewed",                     "WEAK_PASSWORD_POLICY"),
    ("DTC-12", "Privileged sessions located",                 "PRIVILEGED_SESSION"),
    ("DTC-13", "DCSync rights identified",                     "DCSYNC"),
    ("DTC-14", "Password spraying completed",                  None),
    ("DTC-15", "Hashes cracked",                               None),
    ("DTC-16", "Lateral movement — admin hosts mapped",        "PASS_THE_HASH"),
    ("DTC-17", "LSASS dumped on admin host",                   None),
    ("DTC-18", "Domain Admin obtained",                        None),
    ("DTC-19", "krbtgt hash extracted",                        None),
    ("DTC-20", "Persistence established",                      None),
]


class DomainTakeoverChecklist:
    def __init__(self, console=None):
        self.console = console

    def run(self, findings: List[Dict], domain_data: Dict, args=None):
        _p = (lambda m: self.console.print(m)) if self.console else (lambda m: print(_plain(m)))

        present = {f.get("type", "") for f in (findings or [])}
        has_recon = bool(domain_data and domain_data.get("raw_sources"))

        def is_done(mapping) -> bool:
            if mapping is None:
                return False
            if mapping == "_recon":
                return has_recon
            return mapping in present

        states = [(iid, name, is_done(m)) for iid, name, m in _ITEMS]
        done = sum(1 for _, _, d in states if d)
        total = len(states)
        pct = int(done / total * 100) if total else 0
        bar_fill = int(pct / 4)
        bar = "█" * bar_fill + "░" * (25 - bar_fill)
        color = "green" if pct > 70 else "yellow" if pct > 40 else "red"

        _p("")
        _p(f"[bold cyan]𓂀 Domain Takeover Checklist[/bold cyan]")
        _p(f"  [{color}][{bar}] {pct}%[/{color}]  ({done}/{total} confirmed this run)")
        _p("")
        for iid, name, d in states:
            icon = "[green]✅[/green]" if d else "⬜"
            style = "white" if d else "dim"
            _p(f"  {icon}  [{iid}]  [{style}]{name}[/{style}]")
        _p("")
        _p("  [dim]✅ = confirmed by this run's findings · ⬜ = manual / not yet observed[/dim]")


def _plain(msg: str) -> str:
    import re
    return re.sub(r"\[/?[^\]]*\]", "", msg)
