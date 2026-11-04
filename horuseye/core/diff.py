"""
HorusEye — retest diff.

Compare the current findings against a previous ``--json`` export using the
stable finding id (hash of type + affected). Answers the retest question
directly: what's newly introduced, what's been fixed, what still stands.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

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


# ── Route and exposure drift (v2.4) ──────────────────────────────────────────
# Answers "did a fix hold?": a route closed last time can come back with the
# next delegation or permission change. Routes are compared by their steps, so
# a report from before v2.4 (no step ids) still compares; exposure by the users
# counted, so you see exactly who gained a route.

def load_report(path: str) -> Dict:
    """A prior HorusEye JSON report as a dict (a bare v1 list becomes findings)."""
    data = json.loads(open(path, encoding="utf-8").read())
    if isinstance(data, list):
        return {"findings": data}
    return data if isinstance(data, dict) else {}


def _n(name: str) -> str:
    n = (name or "").strip().upper()
    return n.split("@")[0] if "@" in n else n


def _step_key(s: Dict) -> tuple:
    t = s.get("type", "")
    right = (s.get("detail") or "").split(":")[0].split(" ")[0] if t in ("ACL", "ADCS") else ""
    return (t, right, _n(s.get("from", "")), _n(s.get("to", "")))


def route_key(path: Dict) -> tuple:
    """Identity of one route: its ordered steps (type, right, from, to)."""
    return tuple(_step_key(s) for s in path.get("steps") or [])


def diff_routes(previous: List[Dict], current: List[Dict]) -> Dict:
    """{'new', 'closed', 'still_open'} routes between two runs. Routes from
    different footholds aren't a retest: then nothing is compared, and
    ``reason`` says so."""
    prev = {route_key(p): p for p in previous or [] if p.get("steps")}
    cur = {route_key(p): p for p in current or [] if p.get("steps")}
    starts_prev = {_n(p.get("start", "")) for p in prev.values()}
    starts_cur = {_n(p.get("start", "")) for p in cur.values()}
    if starts_prev and starts_cur and starts_prev != starts_cur:
        return {"new": [], "closed": [], "still_open": [], "comparable": False,
                "reason": "The two runs start from different footholds (--owned), so their "
                          "routes aren't compared."}
    return {"new": [cur[k] for k in cur if k not in prev],
            "closed": [prev[k] for k in prev if k not in cur],
            "still_open": [cur[k] for k in cur if k in prev],
            "comparable": True, "reason": ""}


def diff_exposure(previous: Optional[Dict], current: Optional[Dict]) -> Dict:
    """Exposure before/after, and who gained or lost a route. ``comparable`` is
    False when either run has no exposure (e.g. a report from before v2.4) or
    the two measured different targets."""
    out = {"comparable": False, "before": None, "after": None, "before_pct": None,
           "after_pct": None, "newly_exposed": [], "no_longer_exposed": [], "rose": False,
           "reason": ""}
    if current and current.get("computed"):
        out.update(after=current.get("users_exposed"), after_pct=current.get("percent"))
    if not (previous and previous.get("computed")):
        out["reason"] = "The baseline has no exposure figures (it was made before v2.4)."
        return out
    if not (current and current.get("computed")):
        out["reason"] = "This run has no user list, so exposure wasn't measured."
        return out
    if (previous.get("targets") or ["Tier-0"]) != (current.get("targets") or ["Tier-0"]):
        out["reason"] = "The two runs measured exposure to different targets."
        return out
    before = {_n(u): u for u in previous.get("exposed_users") or []}
    after = {_n(u): u for u in current.get("exposed_users") or []}
    out.update(comparable=True, before=previous.get("users_exposed"),
               before_pct=previous.get("percent"),
               newly_exposed=sorted(after[k] for k in after if k not in before),
               no_longer_exposed=sorted(before[k] for k in before if k not in after))
    out["rose"] = bool(out["newly_exposed"]) or (out["after"] or 0) > (out["before"] or 0)
    return out


DRIFT_GATES = ("new-route", "exposure-up")


def drift_gate_failures(gates, routes: Optional[Dict], exposure: Optional[Dict]) -> List[str]:
    """Which drift gates (``new-route``, ``exposure-up``) the comparison trips,
    each with a one-line reason."""
    out = []
    if "new-route" in (gates or ()) and routes and routes.get("new"):
        n = len(routes["new"])
        out.append(f"{n} new attack route{'s' if n != 1 else ''} since the baseline")
    if "exposure-up" in (gates or ()) and exposure and exposure.get("comparable") and exposure.get("rose"):
        gained = len(exposure.get("newly_exposed") or [])
        out.append(f"exposure rose from {exposure['before']:,} to {exposure['after']:,} users"
                   + (f" ({gained} newly exposed)" if gained else ""))
    return out
