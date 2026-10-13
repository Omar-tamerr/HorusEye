"""Public API facade — the supported programmatic surface stays stable."""
from horuseye import api
from horuseye.synthetic import generate_domain


def test_detect_returns_scored_enriched_findings():
    data, _ = generate_domain(seed=1, users=80, computers=15, groups=6)
    findings = api.detect(data)
    assert findings
    f = findings[0]
    # scored + enriched + schema fields all present through the facade
    for key in ("rule_id", "confidence", "evidence", "score", "mitre", "remediation"):
        assert key in f, key


def test_analyze_bundles_findings_paths_summary():
    data, _ = generate_domain(seed=1, users=80, computers=15, groups=6)
    # Give a reachable path for the graph.
    data["acls"].append({"principal": "DOMAIN USERS@CORP.LOCAL",
                         "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"})
    data["groups"].append({"name": "DOMAIN USERS@CORP.LOCAL"})
    result = api.analyze(data)
    assert result["summary"]["total"] == len(result["findings"])
    assert result["summary"]["by_severity"]
    assert isinstance(result["paths"], list) and result["paths"]
    assert isinstance(result["remediation_impact"], list)


def test_attack_paths_respects_owned_and_target():
    data = {"domain": "CORP.LOCAL", "groups": [{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
            "acls": [{"principal": "BOB@CORP.LOCAL", "target": "JEWEL@CORP.LOCAL", "right": "GenericAll"}]}
    paths = api.attack_paths(data, owned=["BOB@CORP.LOCAL"], targets=["JEWEL@CORP.LOCAL"])
    assert paths and paths[0]["goal"] == "JEWEL@CORP.LOCAL"


def test_parse_sources_is_library_safe(tmp_path):
    # Minimal BloodHound dir; parse_sources must work with no console/stdout.
    import json
    (tmp_path / "domains.json").write_text(json.dumps(
        {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": "S-1-root", "Properties": {"name": "CORP.LOCAL"},
             "Aces": [{"PrincipalSID": "S-1-root", "RightName": "GenericAll"}]}]}),
        encoding="utf-8")
    data = api.parse_sources(bloodhound=str(tmp_path), domain="CORP.LOCAL", dc="10.0.0.5")
    assert data["domain"] == "CORP.LOCAL"
    assert "parse_report" in data


def test_api_all_exports_present():
    for name in api.__all__:
        assert hasattr(api, name)
