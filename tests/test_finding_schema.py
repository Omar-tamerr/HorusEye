"""Stage A: finding schema — every finding carries rule_id, confidence (with a
documented meaning), and reproducible evidence; schema stays backward-compatible."""
from horuseye.core.attack_detector import AttackDetector
from horuseye.core.finding import CONFIDENCE_LEVELS, attach_schema, ev


def _rich_domain():
    return {
        "domain": "CORP.LOCAL", "dc_ip": "10.0.0.5",
        "spns": [{"user": "SVC@CORP.LOCAL", "spns": ["MSSQLSvc/sql:1433"]}],
        "asrep_users": ["NOPRE@CORP.LOCAL"],
        "acls": [
            {"principal": "HELPDESK@CORP.LOCAL", "target": "CORP.LOCAL", "right": "GetChanges"},
            {"principal": "HELPDESK@CORP.LOCAL", "target": "CORP.LOCAL", "right": "GetChangesAll"},
            {"principal": "HELPDESK@CORP.LOCAL", "target": "ADMINISTRATOR@CORP.LOCAL", "right": "GenericAll"},
        ],
        "users": [{"name": "ADMINISTRATOR@CORP.LOCAL", "admincount": True}],
        "groups": [{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True,
                    "members": ["ADMINISTRATOR@CORP.LOCAL"]}],
        "computers": [{"name": "WEB01@CORP.LOCAL", "unconstrained_delegation": True}],
        "trusts": [{"target_domain": "PARTNER.LOCAL", "direction": "Bidirectional", "type": "Forest"}],
    }


def test_every_finding_has_schema_fields():
    for f in AttackDetector(_rich_domain()).detect_all():
        assert f["rule_id"], f
        assert f["confidence"] in CONFIDENCE_LEVELS, f
        assert f["confidence_reason"], f
        assert isinstance(f["evidence"], list), f
        assert f["id"] and f["type"] and f["severity"]


def test_evidence_is_reproducible_from_source():
    findings = AttackDetector(_rich_domain()).detect_all()
    dcsync = next(f for f in findings if f["type"] == "DCSYNC")
    # Evidence must name the actual replication rights that were observed.
    details = {e["detail"] for e in dcsync["evidence"]}
    assert {"getchanges", "getchangesall"} <= details
    assert all(e["source"] == "acl" for e in dcsync["evidence"])


def test_rule_id_is_more_specific_than_type_for_acl():
    findings = AttackDetector(_rich_domain()).detect_all()
    acl = next(f for f in findings if f["type"] == "ACL_ABUSE")
    assert acl["rule_id"] == "ACL_ABUSE.genericall"      # rule_id ≠ bare type


def test_attach_schema_is_non_destructive():
    f = [{"type": "ACL_ABUSE", "confidence": "LOW", "confidence_reason": "custom",
          "rule_id": "custom.rule", "evidence": [ev("acl", "X", "GenericAll")]}]
    attach_schema(f)
    assert f[0]["confidence"] == "LOW"          # not overwritten
    assert f[0]["rule_id"] == "custom.rule"
    assert f[0]["confidence_reason"] == "custom"


def test_unknown_type_gets_safe_defaults():
    f = [{"type": "SOMETHING_NEW"}]
    attach_schema(f)
    assert f[0]["confidence"] == "MEDIUM"
    assert f[0]["rule_id"] == "SOMETHING_NEW"
    assert f[0]["evidence"] == []


def test_aggregated_acl_keeps_all_evidence():
    # 8 targets → aggregated presentation, but evidence retains every ACE.
    acls = [{"principal": "HELPDESK@CORP.LOCAL", "target": f"U{i}@CORP.LOCAL",
             "right": "GenericWrite"} for i in range(8)]
    data = {"domain": "CORP.LOCAL", "acls": acls,
            "users": [{"name": "ADMINISTRATOR@CORP.LOCAL", "admincount": True}],
            "groups": [{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}]}
    acl = next(f for f in AttackDetector(data).detect_all() if f["type"] == "ACL_ABUSE")
    assert "8 objects" in acl["affected"]        # aggregated title
    assert len(acl["evidence"]) == 8             # but no evidence lost
