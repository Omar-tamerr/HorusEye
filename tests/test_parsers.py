"""BloodHound parser coverage — the detector is only as good as the data it
is handed, so lock in the fields the parser must surface from SharpHound JSON."""
import json

from parsers.bloodhound_parser import BloodHoundParser


def _write(dirpath, name, payload):
    (dirpath / name).write_text(json.dumps(payload), encoding="utf-8")


def test_bloodhound_extracts_core_fields(tmp_path):
    _write(tmp_path, "users.json", {"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": "S-1-1105",
         "Properties": {"name": "SVC@CORP.LOCAL", "hasspn": True,
                        "serviceprincipalnames": ["MSSQLSvc/sql:1433"], "enabled": True}},
        {"ObjectIdentifier": "S-1-1106",
         "Properties": {"name": "NOPREAUTH@CORP.LOCAL", "dontreqpreauth": True}},
    ]})
    _write(tmp_path, "computers.json", {"meta": {"type": "computers"}, "data": [
        {"ObjectIdentifier": "S-1-1200",
         "Properties": {"name": "WEB01@CORP.LOCAL", "unconstraineddelegation": True}},
    ]})
    _write(tmp_path, "domains.json", {"meta": {"type": "domains"}, "data": [
        {"ObjectIdentifier": "S-1-root", "Properties": {"name": "CORP.LOCAL"},
         "Aces": [{"PrincipalSID": "S-1-1106", "RightName": "DCSync"}],
         "Trusts": [{"TargetDomainName": "PARTNER.LOCAL", "TrustDirection": "Bidirectional"}]},
    ]})

    out = BloodHoundParser(str(tmp_path)).parse()

    assert any(s["user"].startswith("SVC") for s in out["spns"])
    assert any("NOPREAUTH" in u for u in out["asrep_users"])
    assert any(c["unconstrained_delegation"] for c in out["computers"])
    assert any(a["right"] == "DCSync" for a in out["acls"])
    assert any(t["target_domain"] == "PARTNER.LOCAL" for t in out["trusts"])


def test_bloodhound_ce_camelcase_aliases(tmp_path):
    # BloodHound CE emits camelCase property names; the parser must accept both.
    _write(tmp_path, "users.json", {"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": "S-1-1",
         "Properties": {"name": "X@CORP", "dontRequirePreAuth": True}},
    ]})
    out = BloodHoundParser(str(tmp_path)).parse()
    assert any("X@CORP" in u for u in out["asrep_users"])


def test_empty_directory_returns_empty_sets(tmp_path):
    out = BloodHoundParser(str(tmp_path)).parse()
    assert out["users"] == [] and out["acls"] == []


def test_missing_path_does_not_crash():
    out = BloodHoundParser("/no/such/path").parse()
    assert out["users"] == []
