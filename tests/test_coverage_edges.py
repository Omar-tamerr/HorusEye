"""Graph coverage added in v2.4: ADCS (Certipy), RBCD, SID history, LAPS / gMSA
readers, and GPOs applied through OU links."""
import json

from horuseye.core.attack_detector import AttackDetector
from horuseye.core.graph import AttackGraph
from horuseye.parsers.bloodhound_parser import BloodHoundParser
from horuseye.parsers.ldap_parser import CertipyParser


def _data(**kw):
    base = {"domain": "CORP.LOCAL", "dc_ip": "10.0.0.5", "users": [], "groups": [],
            "computers": [], "acls": [], "sessions": [], "local_admins": [],
            "delegation_targets": []}
    base.update(kw)
    return base


DA = {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True, "members": ["ADMIN@CORP.LOCAL"]}


# ── Certipy ──────────────────────────────────────────────────────────────────
CERTIPY_V4 = {
    "Certificate Authorities": {
        "0": {
            "CA Name": "CORP-CA",
            "DNS Name": "ca01.corp.local",
            "Web Enrollment": "Enabled",
            "User Specified SAN": "Disabled",
            "Permissions": {"Owner": "CORP.LOCAL\\Administrators",
                            "Access Rights": {"ManageCa": ["CORP.LOCAL\\Domain Admins"],
                                              "Enroll": ["CORP.LOCAL\\Authenticated Users"]}},
            "[!] Vulnerabilities": {
                "ESC8": "Web Enrollment is enabled and Request Disposition is set to Issue"},
        }
    },
    "Certificate Templates": {
        "0": {
            "Template Name": "VulnUser",
            "Display Name": "Vuln User",
            "Certificate Authorities": ["CORP-CA"],
            "Enabled": True,
            "Client Authentication": True,
            "Enrollee Supplies Subject": True,
            "Permissions": {
                "Enrollment Permissions": {"Enrollment Rights": [
                    "CORP.LOCAL\\Domain Admins", "CORP.LOCAL\\Domain Users"]},
                "Object Control Permissions": {
                    "Owner": "CORP.LOCAL\\Administrator",
                    "Write Property Principals": ["CORP.LOCAL\\Domain Admins"]}},
            "[!] Vulnerabilities": {
                "ESC1": "'CORP.LOCAL\\\\Domain Users' can enroll, enrollee supplies subject "
                        "and template allows client authentication"},
        },
        "1": {
            "Template Name": "Disabled1",
            "Enabled": False,
            "Permissions": {"Enrollment Permissions": {"Enrollment Rights": [
                "CORP.LOCAL\\Domain Users"]}},
            "[!] Vulnerabilities": {"ESC1": "'CORP.LOCAL\\\\Domain Users' can enroll"},
        },
        "2": {
            "Template Name": "WebSrv",
            "Enabled": True,
            "Certificate Authorities": ["CORP-CA"],
            "Permissions": {"Object Control Permissions": {
                "Write Dacl Principals": ["CORP.LOCAL\\HELPDESK"]}},
            "[!] Vulnerabilities": {"ESC4": "'CORP.LOCAL\\\\HELPDESK' has dangerous permissions"},
        },
    },
}


def _certipy(tmp_path, payload=CERTIPY_V4):
    f = tmp_path / "20261104_Certipy.json"
    f.write_text(json.dumps(payload))
    return CertipyParser(str(f)).parse()


def test_certipy_reads_the_real_output_layout(tmp_path):
    out = _certipy(tmp_path)
    esc = {(v["esc"], v["template"] or v["ca"]) for v in out["vulnerabilities"]}
    assert {("ESC1", "VulnUser"), ("ESC4", "WebSrv"), ("ESC8", "CORP-CA")} <= esc
    ca = out["cas"][0]
    assert ca["web_enrollment"] is True and ca["user_specified_san"] is False
    esc1 = next(v for v in out["vulnerabilities"] if v["esc"] == "ESC1" and v["template"] == "VulnUser")
    assert esc1["principals"] == ["CORP.LOCAL\\Domain Users"]
    assert "CORP.LOCAL\\Domain Users" in esc1["enrollment_rights"]
    assert esc1["ca"] == "CORP-CA"


def test_certipy_flat_legacy_layout_still_parses(tmp_path):
    legacy = {"Certificate Templates": {"0": {
        "Template Name": "Old", "Enabled": True, "Enrollment Rights": ["CORP\\Domain Users"],
        "Vulnerabilities": {"ESC1": "enrollee supplies subject"}}}}
    out = _certipy(tmp_path, legacy)
    assert out["vulnerabilities"][0]["esc"] == "ESC1"
    assert out["vulnerabilities"][0]["enrollment_rights"] == ["CORP\\Domain Users"]


def test_web_enrollment_disabled_string_is_false(tmp_path):
    out = _certipy(tmp_path, {"Certificate Authorities": {"0": {
        "CA Name": "X", "Web Enrollment": "Disabled"}}})
    assert out["cas"][0]["web_enrollment"] is False


def test_esc1_for_domain_users_is_a_route_for_everyone(tmp_path):
    adcs = _certipy(tmp_path)
    g = AttackGraph(_data(groups=[DA], adcs=adcs))
    path = g.shortest_paths()[0]                  # default start: any domain user
    assert [e.type for e in path] == ["ADCS"]
    desc = g.describe(path)
    assert desc["steps"][0]["id"].startswith("ADCS:ESC1/VulnUser:DOMAIN USERS->")
    assert "certipy req" in desc["commands"][0] and "-template VulnUser" in desc["commands"][0]
    assert "-ca CORP-CA" in desc["commands"][0]


def test_adcs_edges_skip_tier0_and_disabled_templates(tmp_path):
    g = AttackGraph(_data(groups=[DA], adcs=_certipy(tmp_path)))
    adcs = [e for edges in g.adj.values() for e in edges if e.type == "ADCS"]
    srcs = {(e.src, e.detail.split(":")[0]) for e in adcs}
    assert ("DOMAIN ADMINS", "ESC1 VulnUser") not in srcs     # already Tier-0
    assert not any("Disabled1" in d for _, d in srcs)          # template turned off
    assert ("HELPDESK", "ESC4 WebSrv") in srcs                 # write rights on the template


def test_esc8_relay_is_inferred_and_open_to_any_domain_user(tmp_path):
    g = AttackGraph(_data(groups=[DA], adcs=_certipy(tmp_path)))
    relay = [e for e in g.adj.get("DOMAIN USERS", []) if e.detail.startswith("ESC8")]
    assert relay and relay[0].trust == "inferred"
    fix = g.fix_text(relay[0])
    assert "web enrollment" in fix.lower()


def test_adcs_fix_names_the_template(tmp_path):
    g = AttackGraph(_data(groups=[DA], adcs=_certipy(tmp_path)))
    e = next(e for e in g.adj["DOMAIN USERS"] if e.detail.startswith("ESC1"))
    assert "VulnUser" in g.fix_text(e)
    change = g._change(e)
    assert change["kind"] == "permission" and change["loses"] == ["enroll in VulnUser (ESC1)"]


def test_detector_reports_ca_level_vulns_with_the_ca_name(tmp_path):
    findings = AttackDetector(_data(adcs=_certipy(tmp_path))).detect_all()
    titles = {f["title"] for f in findings if f["type"] == "ADCS_ESC"}
    assert "ADCS ESC8: CORP-CA" in titles and "ADCS ESC1: VulnUser" in titles


# ── RBCD, SID history, LAPS, gMSA ────────────────────────────────────────────
def test_rbcd_already_configured_is_an_inferred_route():
    data = _data(groups=[DA],
                 rbcd=[{"principal": "BOB@CORP.LOCAL", "computer": "SRV01.CORP.LOCAL"}],
                 sessions=[{"UserName": "ADMIN@CORP.LOCAL", "ComputerName": "SRV01.CORP.LOCAL"}])
    g = AttackGraph(data)
    path = g.shortest_paths(owned=["BOB@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["AllowedToAct", "HasSession"]
    assert path[0].trust == "inferred"
    assert "impacket-getST" in g.describe(path)["commands"][0]


def test_rbcd_write_rights_are_computer_takeover():
    data = _data(groups=[DA],
                 computers=[{"name": "SRV01.CORP.LOCAL"}],
                 acls=[{"principal": "BOB@CORP.LOCAL", "target": "SRV01.CORP.LOCAL",
                        "right": "WriteAccountRestrictions"}],
                 sessions=[{"UserName": "ADMIN@CORP.LOCAL", "ComputerName": "SRV01.CORP.LOCAL"}])
    g = AttackGraph(data)
    path = g.shortest_paths(owned=["BOB@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["ACL", "HasSession"]
    assert "impacket-rbcd" in g.describe(path)["commands"][0]


def test_sid_history_carries_the_other_principals_rights():
    data = _data(groups=[DA], sid_history=[{"principal": "OLDUSER@CORP.LOCAL",
                                            "target": "DOMAIN ADMINS@CORP.LOCAL"}])
    path = AttackGraph(data).shortest_paths(owned=["OLDUSER@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["HasSIDHistory"]


def test_laps_reader_reaches_a_domain_admin_session():
    data = _data(groups=[DA],
                 acls=[{"principal": "BOB@CORP.LOCAL", "target": "WS01.CORP.LOCAL",
                        "right": "ReadLAPSPassword"}],
                 sessions=[{"UserName": "ADMIN@CORP.LOCAL", "ComputerName": "WS01.CORP.LOCAL"}])
    g = AttackGraph(data)
    path = g.shortest_paths(owned=["BOB@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["ReadLAPSPassword", "HasSession"]
    assert "-M laps" in g.describe(path)["commands"][0]


def test_gmsa_reader_reaches_dcsync():
    data = _data(acls=[{"principal": "BOB@CORP.LOCAL", "target": "GMSA-SQL$@CORP.LOCAL",
                        "right": "ReadGMSAPassword"},
                       {"principal": "GMSA-SQL$@CORP.LOCAL", "target": "CORP.LOCAL",
                        "right": "GetChangesAll"}])
    path = AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["ReadGMSAPassword", "DCSync"]


# ── GPOs through OU links (parsed from SharpHound) ─────────────────────────────
def _bh_dir(tmp_path, blocks=False, enforced=False):
    def w(kind, rows):
        (tmp_path / f"x_{kind}.json").write_text(json.dumps({"meta": {"type": kind}, "data": rows}))
    w("users", [{"ObjectIdentifier": "S-1-5-21-1-500", "Properties": {"name": "ADMIN@CORP.LOCAL", "admincount": True}},
                {"ObjectIdentifier": "S-1-5-21-1-1103", "Properties": {"name": "BOB@CORP.LOCAL"}}])
    w("groups", [{"ObjectIdentifier": "S-1-5-21-1-512", "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True},
                  "Members": [{"ObjectIdentifier": "S-1-5-21-1-500"}]},
                 {"ObjectIdentifier": "S-1-5-21-1-516", "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL"},
                  "Members": [{"ObjectIdentifier": "S-1-5-21-1-1000"}]},
                 {"ObjectIdentifier": "S-1-5-21-1-1200", "Properties": {"name": "HELPDESK@CORP.LOCAL"},
                  "Members": [{"ObjectIdentifier": "S-1-5-21-1-1103"}]}])
    w("computers", [{"ObjectIdentifier": "S-1-5-21-1-1000", "Properties": {"name": "DC01.CORP.LOCAL"},
                     "AllowedToAct": [{"ObjectIdentifier": "S-1-5-21-1-1103", "ObjectType": "User"}]},
                    {"ObjectIdentifier": "S-1-5-21-1-2001", "Properties": {"name": "WS01.CORP.LOCAL"}}])
    w("gpos", [{"ObjectIdentifier": "AAAA-1111", "Properties": {"name": "SERVER HARDENING@CORP.LOCAL"},
                "Aces": [{"PrincipalSID": "S-1-5-21-1-1200", "RightName": "GenericWrite"}]}])
    w("ous", [{"ObjectIdentifier": "OU-DC", "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL",
                                                          "blocksinheritance": blocks},
               "Links": [], "ChildObjects": [{"ObjectIdentifier": "S-1-5-21-1-1000", "ObjectType": "Computer"}]},
              {"ObjectIdentifier": "OU-WS", "Properties": {"name": "WORKSTATIONS@CORP.LOCAL"},
               "ChildObjects": [{"ObjectIdentifier": "S-1-5-21-1-2001", "ObjectType": "Computer"}]}])
    w("domains", [{"ObjectIdentifier": "S-1-5-21-1", "Properties": {"name": "CORP.LOCAL"},
                   "Links": [{"GUID": "aaaa-1111", "IsEnforced": enforced}],
                   "ChildObjects": [{"ObjectIdentifier": "OU-DC", "ObjectType": "OU"},
                                    {"ObjectIdentifier": "OU-WS", "ObjectType": "OU"}]}])
    d = BloodHoundParser(str(tmp_path)).parse()
    d.update(domain="CORP.LOCAL", dc_ip="10.0.0.5")
    return d


def test_parser_reads_containers_links_rbcd(tmp_path):
    d = _bh_dir(tmp_path)
    dom = next(c for c in d["containers"] if c["kind"] == "domain")
    assert dom["links"] == [{"gpo": "SERVER HARDENING@CORP.LOCAL", "enforced": False}]
    assert {c["name"] for c in dom["children"]} == {"DOMAIN CONTROLLERS@CORP.LOCAL", "WORKSTATIONS@CORP.LOCAL"}
    assert d["rbcd"] == [{"principal": "BOB@CORP.LOCAL", "computer": "DC01.CORP.LOCAL"}]


def test_gpo_linked_at_the_domain_reaches_the_domain_controller(tmp_path):
    d = _bh_dir(tmp_path)
    d.pop("rbcd")                             # leave only the GPO route
    g = AttackGraph(d)
    path = g.shortest_paths(owned=["BOB@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["MemberOf", "ACL", "GPLink"]
    assert path[-1].dst == "DC01.CORP.LOCAL" and path[-1].trust == "inferred"
    assert "pygpoabuse" in g.describe(path)["commands"][1]


def test_blocked_inheritance_stops_an_unenforced_link(tmp_path):
    d = _bh_dir(tmp_path, blocks=True)
    d.pop("rbcd")
    assert AttackGraph(d).shortest_paths(owned=["BOB@CORP.LOCAL"]) == []
    d = _bh_dir(tmp_path, blocks=True, enforced=True)
    d.pop("rbcd")
    assert AttackGraph(d).shortest_paths(owned=["BOB@CORP.LOCAL"])


def test_gpo_link_is_never_proposed_as_the_fix(tmp_path):
    d = _bh_dir(tmp_path)
    d.pop("rbcd")
    plans = AttackGraph(d).remediation_plans(owned=["BOB@CORP.LOCAL"])
    assert plans
    for p in plans:
        assert all(c["type"] != "GPLink" for c in p["changes"])


# ── Footholds hold what every domain user can do ────────────────────────────────
def test_owned_user_also_takes_routes_open_to_every_user(tmp_path):
    data = _data(groups=[DA, {"name": "HELPDESK@CORP.LOCAL", "members": ["BOB@CORP.LOCAL"]}],
                 acls=[{"principal": "HELPDESK@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
                        "right": "GenericAll"}],
                 adcs=_certipy(tmp_path))
    g = AttackGraph(data)
    paths = g.shortest_paths(owned=["BOB@CORP.LOCAL"])
    kinds = {tuple(e.type for e in p) for p in paths}
    assert ("MemberOf", "ADCS") in kinds                       # through Domain Users
    implicit = [e for p in paths for e in p if e.kind == "implicit"]
    assert implicit and implicit[0].dst == "DOMAIN USERS"
    # Removing BOB from HELPDESK no longer looks like it breaks every route.
    impact = {(h["type"], h["to"]): h for h in g.remediation_impact(owned=["BOB@CORP.LOCAL"])}
    assert impact[("MemberOf", "HELPDESK@CORP.LOCAL")]["breaks_path"] is False
    for plan in g.remediation_plans(owned=["BOB@CORP.LOCAL"]):
        assert not any("every domain user is a member" in c["detail"] for c in plan["changes"])
        assert any(c["type"] == "ADCS" for c in plan["changes"])
    fix = next(c for c in g.remediation_plans(owned=["BOB@CORP.LOCAL"])[0]["changes"] if c["type"] == "ADCS")
    assert fix["effect"].startswith("Every domain user loses only this right")
