"""
HorusEye — finding schema.

A single, documented contract for every finding the detector emits, so reports,
the graph, retest diff and the AI layer all read the same shape. The detection
*rule* (what was observed, with its evidence) is kept separate from presentation
(title/description) and from enrichment (ATT&CK / remediation / detection, added
later by ``core.knowledge``) and AI narratives.

Finding keys
------------
Required: ``type``, ``rule_id``, ``title``, ``affected``, ``severity``.
Schema-attached (``attach_schema``): ``confidence``, ``confidence_reason``,
``evidence`` (list of source references — the actual objects/ACEs behind the
finding, so it can be reproduced from source data).
Added elsewhere: ``id`` (detector), ``score``/``ease`` (scorer),
``mitre``/``remediation``/``detection`` (knowledge), ``ai_narrative`` (AI).

Confidence
----------
``HIGH``   — read directly from a directory attribute or an ACE (observed fact).
``MEDIUM`` — inferred, point-in-time, or config-dependent (e.g. a session that
             may be stale, a trust whose exploitability depends on its settings).
``LOW``    — heuristic.
"""
from __future__ import annotations

from typing import Dict, List

CONFIDENCE_LEVELS = ("HIGH", "MEDIUM", "LOW")

# Per-type default confidence + the reason that justifies it. A detector may set
# `confidence`/`confidence_reason` on a finding to override the default.
_CONFIDENCE: Dict[str, tuple] = {
    "KERBEROASTING":            ("HIGH",   "hasSPN read directly from the directory"),
    "ASREP_ROASTING":           ("HIGH",   "DONT_REQ_PREAUTH flag read directly"),
    "DCSYNC":                   ("HIGH",   "replication ACEs present on the domain object"),
    "ACL_ABUSE":                ("HIGH",   "ACE present in the directory"),
    "GPO_ABUSE":                ("HIGH",   "write ACE on a Group Policy object"),
    "UNCONSTRAINED_DELEGATION": ("HIGH",   "TRUSTED_FOR_DELEGATION flag read directly"),
    "CONSTRAINED_DELEGATION":   ("HIGH",   "msDS-AllowedToDelegateTo / T2A4D read directly"),
    "PASS_THE_HASH":            ("MEDIUM", "inferred from overlapping local-admin rights"),
    "ADCS_ESC":                 ("HIGH",   "reported by Certipy template analysis"),
    "DOMAIN_TRUST":             ("MEDIUM", "trust exists; exploitability depends on its config"),
    "PRIVILEGED_SESSION":       ("MEDIUM", "session data is point-in-time and may be stale"),
    "WEAK_PASSWORD_POLICY":     ("HIGH",   "policy values read directly"),
    "STALE_ADMIN":              ("MEDIUM", "heuristic on adminCount + account state"),
}


def ev(source: str, obj: str, detail: str = "") -> Dict[str, str]:
    """One evidence reference: which source produced which object, and how.

    ``source`` is the data origin (e.g. ``"acl"``, ``"bloodhound"``, ``"certipy"``,
    ``"nxc"``); ``obj`` is the concrete object/relationship; ``detail`` is the
    specific right/flag/value observed.
    """
    e = {"source": source, "object": obj}
    if detail:
        e["detail"] = detail
    return e


def attach_schema(findings: List[Dict]) -> List[Dict]:
    """Fill the schema fields every finding must carry. Non-destructive: an
    existing value (e.g. a detector-supplied confidence or evidence list) is
    kept. Returns the same list."""
    for f in findings or []:
        ftype = f.get("type", "")
        conf, reason = _CONFIDENCE.get(ftype, ("MEDIUM", "default confidence for this rule"))
        f.setdefault("confidence", conf)
        f.setdefault("confidence_reason", reason)
        f.setdefault("rule_id", ftype)
        f.setdefault("evidence", [])
    return findings
