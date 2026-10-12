"""Noise reduction: expected rights in a real SharpHound export must not be
reported as findings, while genuine non-default grants still are."""
from horuseye.core.attack_detector import AttackDetector, ACL_AGGREGATE_THRESHOLD
from horuseye.core.principals import PrincipalIndex


def _domain(acls, **extra):
    data = {"domain": "CORP.LOCAL", "dc_ip": "10.0.0.5", "acls": acls,
            "users": [{"name": "ADMINISTRATOR@CORP.LOCAL", "admincount": True}],
            "groups": [{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True,
                        "members": ["ADMINISTRATOR@CORP.LOCAL"]}]}
    data.update(extra)
    return data


def _of(findings, ftype):
    return [f for f in findings if f["type"] == ftype]


# ── Principal classification ─────────────────────────────────────────────────
def test_classify_principals():
    idx = PrincipalIndex(_domain([]))
    assert idx.classify("SELF") == "noise"
    assert idx.classify("CORP.LOCAL-S-1-5-18") == "noise"          # SYSTEM
    assert idx.classify("DOMAIN ADMINS@CORP.LOCAL") == "tier0"
    assert idx.classify("ACCOUNT OPERATORS@CORP.LOCAL") == "tier0"
    assert idx.classify("S-1-5-21-1-2-3-512") == "tier0"           # DA by RID
    assert idx.classify("DOMAIN USERS@CORP.LOCAL") == "broad"
    assert idx.classify("CORP.LOCAL-S-1-5-11") == "broad"          # Authenticated Users
    assert idx.classify("HELPDESK@CORP.LOCAL") == "normal"
    # RID suffix must match exactly: ...-1512 is an ordinary account, not DA.
    assert idx.classify("S-1-5-21-1-2-3-1512") == "normal"


# ── DCSync ───────────────────────────────────────────────────────────────────
def test_expected_replicators_not_reported():
    acls = [{"principal": p, "target": "CORP.LOCAL", "right": r}
            for p in ("DOMAIN CONTROLLERS@CORP.LOCAL", "ENTERPRISE DOMAIN CONTROLLERS@CORP.LOCAL",
                      "ADMINISTRATORS@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL")
            for r in ("GetChanges", "GetChangesAll")]
    assert _of(AttackDetector(_domain(acls)).detect_all(), "DCSYNC") == []


def test_get_changes_alone_is_not_dcsync():
    acls = [{"principal": "SVC-SYNC@CORP.LOCAL", "target": "CORP.LOCAL", "right": "GetChanges"}]
    assert _of(AttackDetector(_domain(acls)).detect_all(), "DCSYNC") == []


def test_non_default_replication_grant_is_reported():
    acls = [{"principal": "SVC-SYNC@CORP.LOCAL", "target": "CORP.LOCAL", "right": r}
            for r in ("GetChanges", "GetChangesAll")]
    dcsync = _of(AttackDetector(_domain(acls)).detect_all(), "DCSYNC")
    assert len(dcsync) == 1 and dcsync[0]["severity"] == "CRITICAL"


# ── ACL abuse ────────────────────────────────────────────────────────────────
def test_tier0_and_noise_principals_filtered():
    acls = [
        {"principal": "DOMAIN ADMINS@CORP.LOCAL", "target": "HELPDESK@CORP.LOCAL", "right": "GenericAll"},
        {"principal": "ACCOUNT OPERATORS@CORP.LOCAL", "target": "BOB@CORP.LOCAL", "right": "GenericAll"},
        {"principal": "CREATOR OWNER", "target": "BOB@CORP.LOCAL", "right": "Owns"},
        {"principal": "CORP.LOCAL-S-1-5-18", "target": "BOB@CORP.LOCAL", "right": "GenericAll"},
    ]
    assert _of(AttackDetector(_domain(acls)).detect_all(), "ACL_ABUSE") == []


def test_duplicate_aces_collapse():
    ace = {"principal": "HELPDESK@CORP.LOCAL", "target": "BOB@CORP.LOCAL", "right": "GenericWrite"}
    findings = AttackDetector(_domain([ace, dict(ace, inherited=True)])).detect_all()
    assert len(_of(findings, "ACL_ABUSE")) == 1


def test_mass_grant_is_aggregated():
    n = ACL_AGGREGATE_THRESHOLD + 10
    acls = [{"principal": "HELPDESK@CORP.LOCAL", "target": f"USER{i}@CORP.LOCAL",
             "right": "ForceChangePassword"} for i in range(n)]
    acls.append({"principal": "HELPDESK@CORP.LOCAL", "target": "ADMINISTRATOR@CORP.LOCAL",
                 "right": "ForceChangePassword"})
    acl = _of(AttackDetector(_domain(acls)).detect_all(), "ACL_ABUSE")
    assert len(acl) == 1
    assert acl[0]["severity"] == "CRITICAL"          # one of the targets is Tier-0
    assert f"{n + 1} objects" in acl[0]["affected"]
    assert "ADMINISTRATOR@CORP.LOCAL" in acl[0]["targets"]


def test_broad_group_grant_is_flagged():
    acls = [{"principal": "DOMAIN USERS@CORP.LOCAL", "target": "SVC-BACKUP@CORP.LOCAL",
             "right": "GenericWrite"}]
    acl = _of(AttackDetector(_domain(acls)).detect_all(), "ACL_ABUSE")
    assert acl and "every domain user" in acl[0]["description"]


def test_gpo_write_not_double_reported():
    acls = [{"principal": "HELPDESK@CORP.LOCAL", "target": "SERVERS POLICY", "right": "WriteDacl"}]
    findings = AttackDetector(_domain(acls, gpos=[{"name": "SERVERS POLICY"}])).detect_all()
    assert len(_of(findings, "GPO_ABUSE")) == 1
    assert _of(findings, "ACL_ABUSE") == []


# ── Finding ids ──────────────────────────────────────────────────────────────
def test_finding_ids_are_stable_and_unique():
    acls = [{"principal": "HELPDESK@CORP.LOCAL", "target": "BOB@CORP.LOCAL", "right": "GenericAll"},
            {"principal": "HELPDESK@CORP.LOCAL", "target": "ALICE@CORP.LOCAL", "right": "GenericAll"}]
    first = AttackDetector(_domain(acls)).detect_all()
    second = AttackDetector(_domain(acls)).detect_all()
    ids = [f["id"] for f in first]
    assert ids == [f["id"] for f in second]
    assert len(ids) == len(set(ids))


# ── Context from local-admin / delegation data ───────────────────────────────
from horuseye.core.attack_detector import BROAD_ADMIN_THRESHOLD  # noqa: E402


def test_constrained_delegation_lists_targets():
    data = _domain([], computers=[{"name": "APP01.CORP.LOCAL", "trustedtoauth": True}],
                   delegation_targets=[{"principal": "APP01.CORP.LOCAL", "target": "SQL01.CORP.LOCAL"}])
    cd = _of(AttackDetector(data).detect_all(), "CONSTRAINED_DELEGATION")
    assert cd[0]["targets"] == ["SQL01.CORP.LOCAL"]
    assert "SQL01.CORP.LOCAL" in cd[0]["description"]


def test_privileged_session_names_exposed_admins():
    data = _domain([], sessions=[{"UserName": "ADMINISTRATOR@CORP.LOCAL", "ComputerName": "WS01"}],
                   local_admins=[{"principal": "HELPDESK@CORP.LOCAL", "computer": "WS01"},
                                 {"principal": "DOMAIN ADMINS@CORP.LOCAL", "computer": "WS01"}])
    ps = _of(AttackDetector(data).detect_all(), "PRIVILEGED_SESSION")
    assert "HELPDESK@CORP.LOCAL" in ps[0]["description"]
    assert "DOMAIN ADMINS" not in ps[0]["description"]   # Tier-0 admins are expected


def test_broad_local_admin_threshold():
    below = [{"principal": "HELPDESK@CORP.LOCAL", "computer": f"WS{i}"}
             for i in range(BROAD_ADMIN_THRESHOLD - 1)]
    at = [{"principal": "HELPDESK@CORP.LOCAL", "computer": f"WS{i}"}
          for i in range(BROAD_ADMIN_THRESHOLD)]
    tier0 = [{"principal": "DOMAIN ADMINS@CORP.LOCAL", "computer": f"WS{i}"} for i in range(50)]
    assert _of(AttackDetector(_domain([], local_admins=below + tier0)).detect_all(), "PASS_THE_HASH") == []
    pth = _of(AttackDetector(_domain([], local_admins=at)).detect_all(), "PASS_THE_HASH")
    assert len(pth) == 1 and pth[0]["affected"] == "HELPDESK@CORP.LOCAL"
