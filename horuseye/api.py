"""
HorusEye — stable public Python API.

For embedding HorusEye in other tools and pipelines without going through the
CLI. These functions are the supported, versioned surface; the modules behind
them may change, but these signatures are kept stable within a major version.

    from horuseye import api

    data = api.parse_sources(bloodhound="./bh/", domain="corp.local", dc="10.0.0.5")
    result = api.analyze(data, owned=["bob@corp.local"])
    for f in result["findings"]:
        print(f["severity"], f["rule_id"], f["affected"], f["confidence"])
    for p in result["paths"]:
        print(p["start"], "→", p["goal"], f"({p['hops']} hops)")

Everything is deterministic and offline (no AI); add narratives separately via
``horuseye.ai.claude_analyzer`` if desired.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Dict, List, Optional

from horuseye.core.attack_detector import AttackDetector
from horuseye.core.graph import AttackGraph
from horuseye.core.knowledge import enrich, mitre_coverage
from horuseye.core.path_scorer import PathScorer

__all__ = ["detect", "attack_paths", "remediation_impact", "remediation_plans", "exposure",
           "triage", "analyze", "parse_sources"]


def detect(domain_data: Dict) -> List[Dict]:
    """Run detection, scoring and knowledge enrichment; return ranked findings."""
    findings = AttackDetector(domain_data).detect_all()
    scored = PathScorer().score(findings)
    enrich(scored)
    return scored


def attack_paths(domain_data: Dict, owned: Optional[List[str]] = None,
                 targets: Optional[List[str]] = None, max_paths: int = 5) -> List[Dict]:
    """Return described shortest attack path(s) to the target(s)."""
    g = AttackGraph(domain_data)
    return [g.describe(p) for p in g.shortest_paths(owned=owned, targets=targets,
                                                    max_paths=max_paths)]


def remediation_impact(domain_data: Dict, owned: Optional[List[str]] = None,
                       targets: Optional[List[str]] = None,
                       max_paths: int = 5, keep: Optional[List[str]] = None) -> List[Dict]:
    """Per-edge remediation impact across the displayed paths: which single
    relationship removal breaks every route (choke points)."""
    return AttackGraph(domain_data).remediation_impact(owned=owned, targets=targets,
                                                       max_paths=max_paths, keep=keep)


def remediation_plans(domain_data: Dict, owned: Optional[List[str]] = None,
                      targets: Optional[List[str]] = None,
                      keep: Optional[List[str]] = None) -> List[Dict]:
    """Alternative fix plans that each break every route, with who loses what
    access per change. ``keep`` (``["SRC->DST", ...]``) marks relationships
    people need for their job; no plan removes them."""
    return AttackGraph(domain_data).remediation_plans(owned=owned, targets=targets, keep=keep)


def exposure(domain_data: Dict, targets: Optional[List[str]] = None,
             keep: Optional[List[str]] = None) -> Dict:
    """Domain-wide exposure: how many enabled users can reach the targets
    (Tier-0 by default), the fewest changes that bring it to zero (each with
    the users left after it), and the biggest single fixes."""
    return AttackGraph(domain_data).exposure(targets=targets, keep=keep)


def triage(findings: List[Dict], domain_data: Dict, targets: Optional[List[str]] = None,
           keep: Optional[List[str]] = None, exposure_result: Optional[Dict] = None) -> List[Dict]:
    """Add effort, impact, "why critical", fix options, source and the Quick
    Win flag to each finding (in place; severity is never changed). Returns
    the Quick Wins, best first."""
    from horuseye.core.triage import triage as _triage
    g = AttackGraph(domain_data)
    x = exposure_result if exposure_result is not None else g.exposure(targets=targets, keep=keep)
    return _triage(findings, domain_data, g, x, targets=targets, keep=keep)


def analyze(domain_data: Dict, owned: Optional[List[str]] = None,
            targets: Optional[List[str]] = None, max_paths: int = 5,
            keep: Optional[List[str]] = None) -> Dict:
    """One call: findings + ranked paths + a summary (counts + ATT&CK coverage)."""
    findings = detect(domain_data)
    x = exposure(domain_data, targets, keep)
    wins = triage(findings, domain_data, targets, keep, exposure_result=x)
    severities = {}
    for f in findings:
        s = (f.get("severity") or "INFO").upper()
        severities[s] = severities.get(s, 0) + 1
    return {
        "findings": findings,
        "paths": attack_paths(domain_data, owned, targets, max_paths),
        "remediation_impact": remediation_impact(domain_data, owned, targets, max_paths, keep),
        "remediation_plans": remediation_plans(domain_data, owned, targets, keep),
        "exposure": x,
        "quick_wins": [f["id"] for f in wins],
        "summary": {
            "total": len(findings),
            "by_severity": severities,
            "mitre": mitre_coverage(findings),
            "parse_report": domain_data.get("parse_report", {}),
        },
    }


def parse_sources(bloodhound: str = None, ldap: str = None, cme: str = None,
                  nxc: str = None, certipy: str = None, domain: str = None,
                  dc: str = None, console=None) -> Dict:
    """Parse one or more exports into a ``domain_data`` dict, as the CLI does.

    ``console`` is optional; a quiet default is used so this stays library-safe.
    """
    from horuseye.parsers.all_parsers import parse_all_sources

    class _Quiet:
        def print(self, *a, **k):
            pass

    args = SimpleNamespace(bloodhound=bloodhound, ldap=ldap, cme=cme, nxc=nxc,
                           certipy=certipy, manual=False, domain=domain, dc=dc)
    return parse_all_sources(args, console or _Quiet(), lambda *a, **k: None)
