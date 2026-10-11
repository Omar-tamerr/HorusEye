"""Detection-engine coverage.

These tests are the regression guard that stops the detector from ever
quietly collapsing back to the old 2-finding stub. They assert that every
README attack type fires from the data the parsers produce, that the
Tier-0 privilege model escalates direct-to-DA paths to CRITICAL, and that
CRITICAL is actually reachable.
"""
import pytest

from core.attack_detector import AttackDetector
from core.path_scorer import PathScorer


@pytest.fixture
def rich_domain():
    """A domain_data dict shaped exactly like parsers.all_parsers output,
    seeded to trigger all 13 detections."""
    return {
        "domain": "CORP.LOCAL",
        "dc_ip": "10.0.0.5",
        "users": [
            {"name": "SVC-SQL@CORP.LOCAL", "hasspn": True, "enabled": True},
            {"name": "BACKUP-SVC@CORP.LOCAL", "dontreqpreauth": True, "enabled": True},
            {"name": "HELPDESK@CORP.LOCAL", "enabled": True},
            {"name": "ADMINISTRATOR@CORP.LOCAL", "admincount": True, "enabled": True},
            {"name": "OLD-ADMIN@CORP.LOCAL", "admincount": True, "enabled": False},
            {"name": "SVC-NEVEREXP@CORP.LOCAL", "admincount": True,
             "enabled": True, "pwdneverexpires": True},
            {"name": "KRBSVC@CORP.LOCAL", "hasspn": True, "admincount": True,
             "enabled": True},  # privileged kerberoastable -> CRITICAL
        ],
        # The parser derives these two lists from the user flags above; the
        # detector consumes the lists, so mirror that contract here.
        "spns": [
            {"user": "SVC-SQL@CORP.LOCAL", "spns": ["MSSQLSvc/sql01:1433"]},
            {"user": "KRBSVC@CORP.LOCAL", "spns": ["HTTP/krb"]},
        ],
        "asrep_users": ["BACKUP-SVC@CORP.LOCAL"],
        "groups": [
            {"name": "DOMAIN ADMINS", "admincount": True,
             "members": ["ADMINISTRATOR@CORP.LOCAL", "KRBSVC@CORP.LOCAL"]},
        ],
        "computers": [
            {"name": "WEB01.CORP.LOCAL", "unconstrained_delegation": True},
            {"name": "APP01.CORP.LOCAL", "trustedtoauth": True},
        ],
        "acls": [
            {"principal": "HELPDESK@CORP.LOCAL", "target": "CORP.LOCAL", "right": "DCSync"},
            {"principal": "HELPDESK@CORP.LOCAL", "target": "CORP.LOCAL", "right": "GetChangesAll"},
            {"principal": "HELPDESK@CORP.LOCAL", "target": "ADMINISTRATOR@CORP.LOCAL", "right": "GenericAll"},
            {"principal": "HELPDESK@CORP.LOCAL", "target": "DEFAULT POLICY", "right": "WriteDacl"},
        ],
        "gpos": [{"name": "DEFAULT POLICY"}],
        "trusts": [
            {"target_domain": "PARTNER.LOCAL", "direction": "Bidirectional",
             "type": "Forest", "transitive": True},
        ],
        "sessions": [
            {"UserName": "ADMINISTRATOR@CORP.LOCAL", "ComputerName": "WS01.CORP.LOCAL"},
        ],
        "adcs": {"vulnerabilities": [
            {"esc": "ESC1", "template": "VulnWebServer",
             "description": "SAN + client auth", "severity": "CRITICAL"},
        ]},
        "password_policy": {"min_length": "5", "lockout_threshold": "0"},
        "cme_data": {"admin_hosts": [
            {"ip": "10.0.0.11", "username": "svc"}, {"ip": "10.0.0.12", "username": "svc"},
        ]},
        "nxc_data": {},
        "raw_sources": ["bloodhound"],
    }


def _types(findings):
    return {f["type"] for f in findings}


def test_all_thirteen_types_detected(rich_domain):
    findings = AttackDetector(rich_domain).detect_all()
    expected = {
        "KERBEROASTING", "ASREP_ROASTING", "DCSYNC", "ACL_ABUSE", "GPO_ABUSE",
        "UNCONSTRAINED_DELEGATION", "CONSTRAINED_DELEGATION", "PASS_THE_HASH",
        "ADCS_ESC", "DOMAIN_TRUST", "PRIVILEGED_SESSION",
        "WEAK_PASSWORD_POLICY", "STALE_ADMIN",
    }
    assert expected <= _types(findings), expected - _types(findings)


def test_critical_is_reachable(rich_domain):
    findings = AttackDetector(rich_domain).detect_all()
    crits = [f for f in findings if f["severity"] == "CRITICAL"]
    assert crits, "no CRITICAL findings — scorer bucket would be dead"
    assert any(f["type"] == "DCSYNC" for f in crits)


def test_dcsync_collapses_replication_rights(rich_domain):
    findings = AttackDetector(rich_domain).detect_all()
    dcsync = [f for f in findings if f["type"] == "DCSYNC"]
    # DCSync + GetChangesAll on one principal => a single finding, not two.
    assert len(dcsync) == 1
    assert "HELPDESK" in dcsync[0]["affected"].upper()


def test_privileged_kerberoast_is_critical(rich_domain):
    findings = AttackDetector(rich_domain).detect_all()
    kerb = {f["affected"].split("@")[0]: f for f in findings if f["type"] == "KERBEROASTING"}
    assert kerb["KRBSVC"]["severity"] == "CRITICAL"   # DA member
    assert kerb["SVC-SQL"]["severity"] == "HIGH"      # ordinary service acct


def test_acl_abuse_on_tier0_is_critical(rich_domain):
    findings = AttackDetector(rich_domain).detect_all()
    acl = [f for f in findings if f["type"] == "ACL_ABUSE"
           and "ADMINISTRATOR" in f["affected"].upper()]
    assert acl and acl[0]["severity"] == "CRITICAL"


def test_gpo_write_detected_separately_from_acl(rich_domain):
    findings = AttackDetector(rich_domain).detect_all()
    gpo = [f for f in findings if f["type"] == "GPO_ABUSE"]
    assert gpo and "DEFAULT POLICY" in gpo[0]["affected"].upper()


def test_findings_have_required_shape(rich_domain):
    for f in AttackDetector(rich_domain).detect_all():
        assert f["type"] and f["title"] and f["severity"]
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert isinstance(f.get("commands", []), list)


def test_empty_domain_is_safe():
    # No sources, no crash, no findings.
    assert AttackDetector({"domain": "X"}).detect_all() == []


def test_malformed_acl_does_not_crash():
    data = {"domain": "X", "acls": [{"bogus": True}, {"right": None}]}
    # Must not raise despite missing principal/target/right keys.
    assert isinstance(AttackDetector(data).detect_all(), list)


def test_scorer_orders_critical_first(rich_domain):
    scored = PathScorer().score(AttackDetector(rich_domain).detect_all())
    scores = [f["score"] for f in scored]
    assert scores == sorted(scores, reverse=True)
    assert scored[0]["severity"] == "CRITICAL"
    # DCSync (ease 1.0) should be the single highest-scoring path.
    assert scored[0]["type"] == "DCSYNC" and scored[0]["score"] == 100
