"""
HorusEye — Path Scorer

Ranks findings on a 0-100 scale combining *impact* (severity) with *ease of
exploitation* (how much work stands between the finding and code execution /
Domain Admin). A CRITICAL finding that is a single documented command away
from DA outranks a CRITICAL that needs a crack-then-pivot chain.
"""
from __future__ import annotations

from typing import Dict, List

SEVERITY_SCORES = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 10}

# Ease multiplier: 1.0 = immediate/deterministic, lower = more effort or luck.
# Kept conservative so severity still dominates the ordering.
_EASE = {
    "DCSYNC":                   1.00,   # one secretsdump away from krbtgt
    "ACL_ABUSE":                0.95,
    "ADCS_ESC":                 0.95,
    "UNCONSTRAINED_DELEGATION": 0.85,   # needs coercion
    "CONSTRAINED_DELEGATION":   0.85,
    "GPO_ABUSE":                0.85,
    "PASS_THE_HASH":            0.90,
    "PRIVILEGED_SESSION":       0.80,   # needs local admin first
    "ASREP_ROASTING":           0.75,   # offline crack required
    "KERBEROASTING":            0.70,   # offline crack required
    "DOMAIN_TRUST":             0.60,
    "WEAK_PASSWORD_POLICY":     0.55,
    "STALE_ADMIN":              0.40,
}


class PathScorer:
    def score(self, findings: List[Dict]) -> List[Dict]:
        for f in findings:
            base = SEVERITY_SCORES.get((f.get("severity") or "LOW").upper(), 25)
            ease = _EASE.get(f.get("type", ""), 0.7)
            f["ease"] = round(ease, 2)
            f["score"] = round(base * ease)
        # Sort by score desc, then severity rank desc, then stable by title.
        return sorted(
            findings,
            key=lambda x: (
                -x.get("score", 0),
                -SEVERITY_SCORES.get((x.get("severity") or "LOW").upper(), 25),
                x.get("title", ""),
            ),
        )
