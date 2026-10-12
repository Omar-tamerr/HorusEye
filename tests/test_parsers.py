"""BloodHound parser coverage — the detector is only as good as the data it
is handed, so lock in the fields the parser must surface from SharpHound JSON."""
import json

from horuseye.parsers.bloodhound_parser import BloodHoundParser


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


def _computers(tmp_path, computer):
    _write(tmp_path, "users.json", {"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": "S-1-5-21-1-1-1-1107", "Properties": {"name": "HELPDESK@CORP.LOCAL"}},
        {"ObjectIdentifier": "S-1-5-21-1-1-1-500", "Properties": {"name": "ADMINISTRATOR@CORP.LOCAL"}},
    ]})
    _write(tmp_path, "computers.json", {"meta": {"type": "computers"}, "data": [computer]})
    return BloodHoundParser(str(tmp_path)).parse()


def test_local_admins_legacy_format(tmp_path):
    out = _computers(tmp_path, {
        "ObjectIdentifier": "S-1-5-21-1-1-1-2000", "Properties": {"name": "WS01.CORP.LOCAL"},
        "LocalAdmins": {"Results": [{"ObjectIdentifier": "S-1-5-21-1-1-1-1107", "ObjectType": "User"}]},
    })
    assert {"principal": "HELPDESK@CORP.LOCAL", "computer": "WS01.CORP.LOCAL"} in out["local_admins"]


def test_local_admins_ce_format(tmp_path):
    out = _computers(tmp_path, {
        "ObjectIdentifier": "S-1-5-21-1-1-1-2001", "Properties": {"name": "WS02.CORP.LOCAL"},
        "LocalGroups": [
            {"ObjectIdentifier": "S-1-5-21-9-9-9-544", "Name": "ADMINISTRATORS@WS02.CORP.LOCAL",
             "Results": [{"ObjectIdentifier": "S-1-5-21-1-1-1-1107", "ObjectType": "User"}]},
            {"ObjectIdentifier": "S-1-5-21-9-9-9-555", "Name": "REMOTE DESKTOP USERS@WS02.CORP.LOCAL",
             "Results": [{"ObjectIdentifier": "S-1-5-21-1-1-1-500", "ObjectType": "User"}]},
        ],
    })
    admins = [a["principal"] for a in out["local_admins"]]
    assert admins == ["HELPDESK@CORP.LOCAL"]   # RDP group is not admin


def test_session_sources_merged_and_deduped(tmp_path):
    sess = {"Results": [{"UserSID": "S-1-5-21-1-1-1-500"}]}
    out = _computers(tmp_path, {
        "ObjectIdentifier": "S-1-5-21-1-1-1-2002", "Properties": {"name": "SRV01.CORP.LOCAL"},
        "Sessions": sess, "PrivilegedSessions": sess, "RegistrySessions": sess,
    })
    assert len(out["sessions"]) == 1
    assert out["sessions"][0]["UserName"] == "ADMINISTRATOR@CORP.LOCAL"


def test_delegation_targets_extracted(tmp_path):
    out = _computers(tmp_path, {
        "ObjectIdentifier": "S-1-5-21-1-1-1-2003",
        "Properties": {"name": "APP01.CORP.LOCAL", "trustedtoauth": True},
        "AllowedToDelegate": [{"ObjectIdentifier": "S-1-5-21-1-1-1-2002", "ObjectType": "Computer"}],
    })
    assert out["delegation_targets"] == [
        {"principal": "APP01.CORP.LOCAL", "target": "S-1-5-21-1-1-1-2002"}]
