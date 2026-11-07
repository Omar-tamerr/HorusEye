"""
HorusEye: fix effort.

How hard a fix is to make: time to apply plus who feels it (blast radius).
``Low`` / ``Medium`` / ``High``, each with a plain reason and the id of the
rule that produced it. The rules are deterministic, documented in
``docs/effort.md`` and tested; no AI is involved.

Effort is separate from severity. These functions read findings and changes
and return a rating; they never write ``severity`` (a test checks that).

Two entry points:

* ``rate_change(change, ctx)`` for one relationship change from a remediation
  option or the exposure plan (``{from, to, type, detail, ...}``).
* ``rate_finding(finding, edges, ctx)`` for a finding, from its type and the
  graph relationships it is linked to (see ``core/triage.py``).
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

from horuseye.core.principals import norm

LEVELS = ("Low", "Medium", "High")
_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# Accounts named like a service account (heuristic, documented as such).
_SERVICE_NAME = re.compile(r"^(SVC|SRV|SA|SQL|APP|IIS|SVCACCT|SERVICE)[-_.]", re.I)
# Directory sync accounts that legitimately hold replication rights.
_SYNC_NAME = re.compile(r"^(MSOL_|AAD_|AADSYNC|SYNC_|ADSYNC)", re.I)

# Finding types with a minimum effort, whatever relationships they link to.
_TYPE_FLOOR = {
    "UNCONSTRAINED_DELEGATION": ("High", "effort.delegation",
                                 "Changes delegation on a server; services that rely on it can break. Plan and test."),
    "CONSTRAINED_DELEGATION": ("High", "effort.delegation",
                               "Changes delegation on a service; the app may stop authenticating. Plan and test."),
    "DOMAIN_TRUST": ("High", "effort.trust",
                     "Trust changes affect every user and app that crosses the trust."),
    "WEAK_PASSWORD_POLICY": ("High", "effort.domain_policy",
                             "A domain-wide policy: every user is affected at their next password change."),
    "KERBEROASTING": ("Medium", "effort.service_account",
                      "Rotate the service account to a long random password or a gMSA; the app must be "
                      "updated. May break the service, test first."),
    "PRIVILEGED_SESSION": ("Medium", "effort.session",
                           "Changes how an admin works: sign out, and enforce tiering with a deny-logon policy."),
    "GPO_ABUSE": ("Medium", "effort.gpo_rights",
                  "Removes GPO edit rights from a group; confirm who manages this GPO first."),
    "ADCS_ESC": ("Medium", "effort.adcs_template",
                 "A certificate template or CA change affects everyone who enrolls; test enrollment."),
}
_TYPE_ONLY = {   # findings that are not graph steps: rated by type alone
    "ASREP_ROASTING": ("Low", "effort.preauth",
                       "Turn Kerberos pre-authentication back on for one account."),
    "STALE_ADMIN": ("Low", "effort.stale_account",
                    "Disable or remove an account no one uses."),
}


class EffortContext:
    """What the rules need to know about the domain: Tier-0 objects, service
    and sync accounts, group sizes and GPO links. Built once per run."""

    def __init__(self, domain_data: Dict, graph=None):
        d = domain_data or {}
        self.graph = graph
        self.tier0 = set()
        if graph is not None:
            self.tier0 = set(graph.goal_nodes()) | {graph.domain_node}
        self.service = set()
        for u in d.get("users") or []:
            if not isinstance(u, dict):
                continue
            name = norm(u.get("name", ""))
            if u.get("hasspn") or u.get("spns") or _SERVICE_NAME.match(name) \
                    or (name.endswith("$") and u.get("gmsa")):
                self.service.add(name)
        for s in d.get("spns") or []:
            if isinstance(s, dict) and s.get("user"):
                self.service.add(norm(s["user"]))
        for app in d.get("webapps") or []:
            if isinstance(app, dict) and (app.get("account") or {}).get("name"):
                self.service.add(norm(app["account"]["name"]))
        self.gpo_links: Dict[str, int] = {}
        if graph is not None:
            for edges in graph.adj.values():
                for e in edges:
                    if e.type == "GPLink":
                        self.gpo_links[e.src] = self.gpo_links.get(e.src, 0) + 1

    def is_service(self, name: str) -> bool:
        n = norm(name)
        return n in self.service or bool(_SERVICE_NAME.match(n))

    def is_sync(self, name: str) -> bool:
        return bool(_SYNC_NAME.match(norm(name)))

    def is_tier0(self, name: str) -> bool:
        if norm(name) in self.tier0:
            return True
        # Ask the privilege model too: a Tier-0 object need not be on any route.
        idx = getattr(self.graph, "idx", None)
        return bool(idx and idx.is_tier0_target(name))

    def short(self, name: str) -> str:
        return str(name or "").split("@")[0]


def _r(level: str, rule: str, reason: str) -> Dict:
    return {"level": level, "rule": rule, "reason": reason}


def _max(a: Dict, b: Dict) -> Dict:
    return b if _RANK[b["level"]] > _RANK[a["level"]] else a


def rate_change(change: Dict, ctx: EffortContext) -> Dict:
    """Effort to make one relationship change (remove the relationship)."""
    t = change.get("type", "")
    src, dst = change.get("from", ""), change.get("to", "")
    a, b = ctx.short(src), ctx.short(dst)
    if t in ("Unconstrained", "ConstrainedDeleg", "AllowedToAct"):
        out = _r("High", "effort.delegation",
                 f"Changes delegation on {a}; services that rely on it can break. Plan and test.")
    elif t == "GPLink":
        n = ctx.gpo_links.get(norm(src), 0)
        out = (_r("High", "effort.gpo_link", f"{a} applies to {n} objects; changing it touches all of them.")
               if n >= 3 else
               _r("Medium", "effort.gpo_link", f"Changing {a} affects what it is linked to; test first."))
    elif t == "DCSync":
        out = (_r("High", "effort.sync_account",
                  f"{a} looks like a directory sync account that needs replication rights; "
                  f"move it to a supported, protected setup instead of removing the right.")
               if ctx.is_sync(src) else
               _r("Low", "effort.dcsync",
                  f"Remove replication rights from {a}, which is not a domain controller or sync service."))
    elif t == "MemberOf":
        out = _r("Medium", "effort.membership",
                 f"{a} loses everything {b} grants, not just this route; check they don't need it.")
    elif t == "HasSession":
        out = _r("Medium", "effort.session",
                 f"Changes how {b} works: sign out of {a}, and enforce tiering with a deny-logon policy.")
    elif t == "ADCS":
        out = _r("Medium", "effort.adcs_template",
                 "A certificate template or CA change affects everyone who enrolls; test enrollment.")
    elif t == "ExecutesAs":
        out = _r("Medium", "effort.app_fix", f"A code or configuration fix in {a.split(':', 1)[-1]}; test the app.")
    elif t == "HasSIDHistory":
        out = _r("Medium", "effort.sid_history",
                 f"Clear SID history on {a} once the migration it came from is confirmed finished.")
    elif t in ("ACL", "ForceChangePassword", "AddMember", "AdminTo",
               "ReadLAPSPassword", "ReadGMSAPassword"):
        out = (_r("Medium", "effort.tier0_permission",
                  f"Removes a permission on {b}, a Tier-0 object: use your change process.")
               if ctx.is_tier0(dst) else
               _r("Low", "effort.permission",
                  f"Remove one permission {a} holds on {b}; nothing else depends on it."))
    else:
        out = _r("Medium", "effort.default", "No specific rule for this change; review before applying.")
    # Taking access away from an account an app runs as can break the app.
    if out["level"] == "Low" and t != "DCSync" and ctx.is_service(src):
        out = _r("Medium", "effort.service_account",
                 f"{a} is a service account: removing its access may break the service, test first.")
    if t == "DCSync" and out["level"] == "Low" and ctx.is_service(src):
        out = _r("Medium", "effort.service_account",
                 f"{a} is a service account: check nothing it runs needs replication, then remove it.")
    return out


def rate_finding(finding: Dict, changes: Iterable[Dict], ctx: EffortContext) -> Dict:
    """Effort to fix a finding: the hardest of its linked relationship changes,
    raised to the finding type's minimum, and to High when the fix is many
    separate changes. Never reads or writes severity."""
    t = finding.get("type", "")
    changes = list(changes)
    if t == "ADCS_ESC" and str(finding.get("rule_id", "")).upper().endswith(("ESC8", "ESC11")):
        return _r("High", "effort.adcs_relay",
                  "Fix the CA's web or RPC enrollment (EPA, HTTPS, signing); every enrollment client is affected.")
    if t in _TYPE_ONLY and not changes:
        lvl, rule, reason = _TYPE_ONLY[t]
        out = _r(lvl, rule, reason)
        if t == "ASREP_ROASTING" and ctx.is_service(finding.get("affected", "")):
            out = _r("Medium", "effort.service_account",
                     "A service account: turning pre-authentication on may break an old client, test first.")
        return out
    out: Optional[Dict] = None
    for c in changes:
        r = rate_change(c, ctx)
        out = r if out is None else _max(out, r)
    if len(changes) > 10:
        out = _r("High", "effort.many_changes",
                 f"{len(changes)} separate changes (for example, one per host); plan a rollout.")
    elif len(changes) >= 3 and (out is None or out["level"] == "Low"):
        out = _r("Medium", "effort.many_changes", f"{len(changes)} separate changes to make and verify.")
    if t in _TYPE_FLOOR:
        lvl, rule, reason = _TYPE_FLOOR[t]
        out = _r(lvl, rule, reason) if out is None else _max(out, _r(lvl, rule, reason))
    return out or _r("Medium", "effort.default", "No specific rule for this finding; review before fixing.")


def at_least(level: str, floor: str) -> bool:
    return _RANK.get(level, 1) >= _RANK.get(floor, 1)


def rate_changes(changes: List[Dict], ctx: EffortContext) -> List[Dict]:
    """Annotate remediation / exposure-plan changes in place with ``effort``."""
    for c in changes or []:
        r = rate_change(c, ctx)
        c["effort"], c["effort_reason"], c["effort_rule"] = r["level"], r["reason"], r["rule"]
    return changes
