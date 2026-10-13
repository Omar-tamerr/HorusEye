"""
HorusEye — synthetic AD data generator.

Produces deterministic, obviously-fake ``domain_data`` (corp.local, generated
names) for benchmarks, stress tests, labeled precision/recall fixtures, and
reproducible demos. No real or client data is involved.

``generate_domain`` returns ``(domain_data, ground_truth)`` where ground_truth
is the set of ``(type, affected)`` pairs that a correct detector must report —
so tests can measure recall directly.
"""
from __future__ import annotations

import random
from typing import Dict, List, Set, Tuple

DOMAIN = "CORP.LOCAL"


def generate_domain(seed: int = 0, users: int = 100, computers: int = 20,
                    groups: int = 10) -> Tuple[Dict, Set[Tuple[str, str]]]:
    """Build a synthetic domain with a known set of planted weaknesses.

    Scale is driven by ``users``/``computers``/``groups``; the planted findings
    are fixed so recall is checkable. Deterministic for a given ``seed``.
    """
    rng = random.Random(seed)
    data: Dict = {
        "domain": DOMAIN, "dc_ip": "10.0.0.5",
        "users": [], "groups": [], "computers": [], "acls": [], "sessions": [],
        "gpos": [{"name": "DEFAULT DOMAIN POLICY"}], "trusts": [],
        "spns": [], "asrep_users": [], "local_admins": [], "delegation_targets": [],
        "adcs": {}, "cme_data": {}, "nxc_data": {},
    }
    truth: Set[Tuple[str, str]] = set()

    def uname(i): return f"USER{i:05d}@{DOMAIN}"
    def cname(i): return f"HOST{i:05d}.{DOMAIN}"

    # Tier-0 group so planted Tier-0 escalations resolve.
    da_members = [uname(0), uname(1)]
    data["groups"].append({"name": f"DOMAIN ADMINS@{DOMAIN}", "admincount": True,
                           "members": da_members})
    for i in range(groups):
        members = [uname(rng.randrange(users)) for _ in range(rng.randint(2, 8))]
        data["groups"].append({"name": f"GROUP{i:03d}@{DOMAIN}", "members": members})

    for i in range(users):
        u = {"name": uname(i), "enabled": True}
        if i < 2:
            u["admincount"] = True            # DA members
        data["users"].append(u)

    for i in range(computers):
        data["computers"].append({"name": cname(i), "enabled": True})

    # ── Planted, labeled weaknesses ─────────────────────────────────────────
    # 1 privileged kerberoastable (CRITICAL) + several ordinary (HIGH)
    data["spns"].append({"user": uname(0), "spns": ["MSSQLSvc/sql:1433"]})
    truth.add(("KERBEROASTING", uname(0)))
    for i in (10, 11, 12):
        data["spns"].append({"user": uname(i), "spns": [f"HTTP/svc{i}"]})
        truth.add(("KERBEROASTING", uname(i)))
    # AS-REP roastable
    data["asrep_users"].append(uname(20))
    truth.add(("ASREP_ROASTING", uname(20)))
    # DCSync: a non-Tier-0 principal with both replication rights
    for r in ("GetChanges", "GetChangesAll"):
        data["acls"].append({"principal": uname(30), "target": DOMAIN, "right": r,
                             "source_file": "domains.json"})
    truth.add(("DCSYNC", uname(30)))
    # ACL abuse on a Tier-0 target (CRITICAL)
    data["acls"].append({"principal": uname(31), "target": f"DOMAIN ADMINS@{DOMAIN}",
                        "right": "GenericAll", "source_file": "groups.json"})
    truth.add(("ACL_ABUSE", f"{uname(31)} → DOMAIN ADMINS@{DOMAIN}"))
    # GPO abuse
    data["acls"].append({"principal": uname(32), "target": "DEFAULT DOMAIN POLICY",
                        "right": "WriteDacl", "source_file": "gpos.json"})
    truth.add(("GPO_ABUSE", f"{uname(32)} → DEFAULT DOMAIN POLICY"))
    # Unconstrained delegation
    data["computers"][0]["unconstrained_delegation"] = True
    truth.add(("UNCONSTRAINED_DELEGATION", cname(0)))
    # Constrained delegation
    data["computers"][1]["trustedtoauth"] = True
    data["delegation_targets"].append({"principal": cname(1), "target": cname(2)})
    truth.add(("CONSTRAINED_DELEGATION", cname(1)))
    # Trust
    data["trusts"].append({"target_domain": "PARTNER.LOCAL",
                          "direction": "Bidirectional", "type": "Forest"})
    truth.add(("DOMAIN_TRUST", "PARTNER.LOCAL"))
    # Weak policy
    data["password_policy"] = {"min_length": "5", "lockout_threshold": "0"}
    truth.add(("WEAK_PASSWORD_POLICY", DOMAIN))
    # Privileged session (DA on a workstation)
    data["sessions"].append({"UserName": uname(0), "ComputerName": cname(5)})
    truth.add(("PRIVILEGED_SESSION", f"{uname(0)}@{cname(5)}"))

    # Realistic noise: expected Tier-0 ACEs and broad-group noise that must NOT
    # become findings (precision).
    data["acls"].append({"principal": f"DOMAIN ADMINS@{DOMAIN}",
                        "target": uname(40), "right": "GenericAll",
                        "source_file": "users.json"})
    data["acls"].append({"principal": "CORP.LOCAL-S-1-5-18", "target": uname(41),
                        "right": "GenericAll", "source_file": "users.json"})

    return data, truth


def write_bloodhound(data: Dict, out_dir: str) -> List[str]:
    """Emit a minimal SharpHound-style JSON set from a synthetic domain, for use
    as an example dataset. Returns the files written."""
    import json
    import os
    os.makedirs(out_dir, exist_ok=True)
    written = []

    def dump(name, payload):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        written.append(path)

    dump("users.json", {"meta": {"type": "users", "count": len(data["users"])},
                        "data": [{"ObjectIdentifier": f"S-1-5-21-1-1-1-{1000+i}",
                                  "Properties": _props(u)} for i, u in enumerate(data["users"])]})
    dump("computers.json", {"meta": {"type": "computers", "count": len(data["computers"])},
                            "data": [{"ObjectIdentifier": f"S-1-5-21-1-1-1-{5000+i}",
                                      "Properties": _props(c)} for i, c in enumerate(data["computers"])]})
    return written


def _props(obj: Dict) -> Dict:
    p = {"name": obj.get("name", "")}
    for k_in, k_out in (("admincount", "admincount"), ("enabled", "enabled"),
                        ("unconstrained_delegation", "unconstraineddelegation"),
                        ("trustedtoauth", "trustedtoauth")):
        if k_in in obj:
            p[k_out] = obj[k_in]
    return p
