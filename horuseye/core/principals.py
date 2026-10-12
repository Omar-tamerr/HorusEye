"""
HorusEye — principal classification shared by the detector and the graph.

Real SharpHound exports are dominated by *expected* rights: Domain Admins hold
GenericAll on nearly everything, Domain Controllers replicate the directory,
SELF and CREATOR OWNER appear on every object. Reporting those as findings
buries the real paths. This module decides, once, which principals are:

    noise   — pseudo-principals that never represent an attacker (SELF, SYSTEM, ...)
    tier0   — already domain-admin-equivalent; their rights are not escalations
    broad   — groups every user belongs to (Everyone, Domain Users, ...);
              anything they can do, *any* domain user can do
    normal  — everything else
"""
from __future__ import annotations

from typing import Dict, Set

# Group names that confer domain-takeover-equivalent privilege.
TIER0_GROUPS = (
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "ADMINISTRATORS",
    "DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS", "ACCOUNT OPERATORS",
    "BACKUP OPERATORS", "PRINT OPERATORS", "SERVER OPERATORS",
    "GROUP POLICY CREATOR OWNERS", "DNSADMINS", "KEY ADMINS",
    "ENTERPRISE KEY ADMINS", "CERT PUBLISHERS",
)

# Principals that hold directory-replication rights in a default domain.
EXPECTED_REPLICATORS = {
    "DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS", "ADMINISTRATORS",
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "READ-ONLY DOMAIN CONTROLLERS",
    "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
}
_EXPECTED_REPLICATOR_SIDS = ("S-1-5-9", "S-1-5-32-544")
_EXPECTED_REPLICATOR_RIDS = ("-498", "-512", "-516", "-519", "-521")

_NOISE_NAMES = {"SELF", "PRINCIPAL SELF", "CREATOR OWNER", "SYSTEM", "LOCAL SYSTEM"}
_NOISE_SIDS = ("S-1-5-18", "S-1-3-0", "S-1-5-10")

_PRIV_SIDS = ("S-1-5-9", "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549",
              "S-1-5-32-550", "S-1-5-32-551")
_PRIV_RIDS = ("-498", "-512", "-516", "-518", "-519", "-521", "-526", "-527")

BROAD_NAMES = {"EVERYONE", "AUTHENTICATED USERS", "DOMAIN USERS", "USERS",
               "DOMAIN COMPUTERS", "ANONYMOUS LOGON"}
_BROAD_SIDS = ("S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-32-545")
_BROAD_RIDS = ("-513", "-515")


def norm(name: str) -> str:
    """Upper-case and drop a trailing @DOMAIN for comparisons (USER@CORP → USER)."""
    n = (name or "").strip().upper()
    return n.split("@")[0] if "@" in n else n


def short(name: str) -> str:
    """SAM-style short name for command templates (keeps original casing)."""
    n = (name or "").strip()
    return n.split("@")[0] if "@" in n else n


def _sid_match(raw: str, sids) -> bool:
    # SharpHound prefixes well-known SIDs with the domain: CORP.LOCAL-S-1-1-0
    return any(raw == s or raw.endswith("-" + s) for s in sids)


def _is_domain_sid(raw: str) -> bool:
    return raw.startswith("S-1-5-21-") or "-S-1-5-21-" in raw


class PrincipalIndex:
    """Precomputed privilege model for one domain_data dict."""

    def __init__(self, domain_data: Dict):
        data = domain_data or {}
        self.domain = (data.get("domain") or "").upper()
        self.privileged: Set[str] = set()
        for u in data.get("users", []):
            if u.get("admincount"):
                self.privileged.add(norm(u.get("name", "")))
        for g in data.get("groups", []):
            gname = (g.get("name", "") or "").upper()
            if g.get("admincount") or any(t in gname for t in TIER0_GROUPS):
                self.privileged.add(norm(g.get("name", "")))
                for member in g.get("members", []) or []:
                    self.privileged.add(norm(member))
        self.privileged.discard("")

    # ── Queries ──────────────────────────────────────────────────────────────
    def is_privileged(self, name: str) -> bool:
        return norm(name) in self.privileged

    def is_domain_object(self, name: str) -> bool:
        return bool(self.domain) and (name or "").strip().upper() == self.domain

    def is_tier0_target(self, name: str) -> bool:
        """Reaching this node means owning the domain."""
        return (self.is_privileged(name) or self.is_domain_object(name)
                or norm(name) in TIER0_GROUPS)

    def is_expected_replicator(self, name: str) -> bool:
        raw = (name or "").strip().upper()
        return (norm(name) in EXPECTED_REPLICATORS
                or _sid_match(raw, _EXPECTED_REPLICATOR_SIDS)
                or (_is_domain_sid(raw) and raw.endswith(_EXPECTED_REPLICATOR_RIDS)))

    def classify(self, name: str) -> str:
        raw = (name or "").strip().upper()
        n = norm(name)
        if not raw or n in _NOISE_NAMES or _sid_match(raw, _NOISE_SIDS):
            return "noise"
        if (self.is_privileged(name) or n in TIER0_GROUPS
                or _sid_match(raw, _PRIV_SIDS)
                or (_is_domain_sid(raw) and raw.endswith(_PRIV_RIDS))):
            return "tier0"
        if (n in BROAD_NAMES or _sid_match(raw, _BROAD_SIDS)
                or (_is_domain_sid(raw) and raw.endswith(_BROAD_RIDS))):
            return "broad"
        return "normal"
