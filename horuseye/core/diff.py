"""
HorusEye — retest diff.

Compare the current findings against a previous ``--json`` export using the
stable finding id (hash of type + affected). Answers the retest question
directly: what's newly introduced, what's been fixed, what still stands.
"""
from __future__ import annotations

import json
from typing import Dict, List

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def load_previous(path: str) -> List[Dict]:
    """Load findings from a prior HorusEye JSON report (schema v1 or v2)."""
    data = json.loads(open(path, encoding="utf-8").read())
    if isinstance(data, dict):
        return data.get("findings", []) or []
    return data if isinstance(data, list) else []


def _key(f: Dict) -> str:
    return f.get("id") or f"{f.get('type','')}|{f.get('affected','')}"


def diff_findings(previous: List[Dict], current: List[Dict]) -> Dict[str, List[Dict]]:
    """Return {'new', 'fixed', 'unchanged'} finding lists keyed by id."""
    prev = {_key(f): f for f in previous or []}
    cur = {_key(f): f for f in current or []}
    new = [cur[k] for k in cur if k not in prev]
    fixed = [prev[k] for k in prev if k not in cur]
    unchanged = [cur[k] for k in cur if k in prev]
    sev = lambda f: -SEV_RANK.get((f.get("severity") or "INFO").upper(), 0)
    return {
        "new": sorted(new, key=sev),
        "fixed": sorted(fixed, key=sev),
        "unchanged": sorted(unchanged, key=sev),
    }


def fail_level_exceeded(findings: List[Dict], threshold: str) -> bool:
    """True if any finding is at or above ``threshold`` severity (for CI gates)."""
    t = SEV_RANK.get((threshold or "").upper())
    if t is None:
        return False
    return any(SEV_RANK.get((f.get("severity") or "INFO").upper(), 0) >= t
               for f in findings or [])
