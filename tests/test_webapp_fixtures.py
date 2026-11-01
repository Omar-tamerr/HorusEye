"""Draft web app → AD service account import (examples/acme-lab-webapp).

The fixture checks run today. The acceptance tests describe how the importer
must behave once the format is agreed; they are expected to fail until it
exists (strict xfail, so they flag themselves when it lands).
"""
import json
import re
from pathlib import Path

import pytest

from horuseye import api
from horuseye.core.graph import AttackGraph

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "examples" / "acme-lab"
FIX = ROOT / "examples" / "acme-lab-webapp"
UNCONFIRMED, CONFIRMED = FIX / "portal-unconfirmed.json", FIX / "portal-confirmed.json"
ACCOUNT = "WEB-SVC@ACME.LAB"
PENDING = pytest.mark.xfail(strict=True, reason="web app importer not built yet: format under "
                                                "discussion in the GitHub issue")


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _lab():
    return api.parse_sources(bloodhound=str(LAB), domain="ACME.LAB", dc="10.10.0.5")


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}.{k}", k, v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


# ── Fixture checks (run today) ───────────────────────────────────────────────
def test_fixtures_share_the_mapping_and_differ_only_in_claim_3():
    a, b = _load(UNCONFIRMED), _load(CONFIRMED)
    assert a["schema"] == b["schema"] == "horuseye.webapps/1-draft"
    (app_a,), (app_b,) = a["apps"], b["apps"]
    for key in ("id", "name", "host", "url"):
        assert app_a[key] == app_b[key]
    for claim in ("exposed", "uses_account"):
        assert app_a["claims"][claim] == app_b["claims"][claim]
    assert app_a["claims"]["uses_account"]["account"]["name"] == ACCOUNT
    assert app_a["claims"]["privileges_obtainable"] == {"status": "not_assessed", "evidence": []}
    assert app_b["claims"]["privileges_obtainable"]["status"] == "confirmed"


def test_fixtures_carry_no_credential_values():
    banned_keys = re.compile(r"pass(word|wd)?|secret|token|cookie|hash|ticket|api_?key|private_?key|^ntlm?$",
                             re.I)
    banned_values = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])|\$krb5|-----BEGIN|password\s*[=:]",
                               re.I)
    for path in (UNCONFIRMED, CONFIRMED):
        for where, key, value in _walk(_load(path)):
            assert not banned_keys.search(key), f"{path.name}{where}"
            if isinstance(value, str):
                assert not banned_values.search(value), f"{path.name}{where}"


def test_claim_statuses_match_their_evidence():
    for path in (UNCONFIRMED, CONFIRMED):
        for claim in _load(path)["apps"][0]["claims"].values():
            assert claim["status"] in {"confirmed", "assumed", "not_assessed"}
            if claim["status"] == "confirmed":
                assert claim["evidence"], f"{path.name}: confirmed claim without evidence"
            else:
                assert not claim["evidence"]


def test_execution_evidence_links_to_its_request_and_the_account_sid():
    claims = _load(CONFIRMED)["apps"][0]["claims"]
    sid = claims["uses_account"]["account"]["sid"]
    ev = claims["privileges_obtainable"]["evidence"]
    requests = {e["id"] for e in ev if e["type"] == "http_request"}
    (execution,) = [e for e in ev if e["type"] == "execution_identity"]
    assert execution["triggered_by"] in requests
    assert execution["effective_sid"] == sid


def test_account_sid_matches_the_synthetic_directory():
    users = _load(LAB / "users.json")["data"]
    sids = {u["Properties"]["name"]: u["ObjectIdentifier"] for u in users}
    for path in (UNCONFIRMED, CONFIRMED):
        account = _load(path)["apps"][0]["claims"]["uses_account"]["account"]
        assert sids[account["name"]] == account["sid"]


def test_known_path_from_the_account_in_the_synthetic_directory():
    g = AttackGraph(_lab())
    paths = g.shortest_paths(owned=[ACCOUNT])
    assert paths, "WEB-SVC should have a route to Domain Admin in acme-lab"
    first = g.describe(paths[0])
    assert [s["type"] for s in first["steps"]] == ["AdminTo", "HasSession"]
    assert first["goal"] == "ADMINISTRATOR@ACME.LAB"
    assert all(s["trust"] == "observed" for s in first["steps"])


def test_account_is_not_owned_by_default():
    # Without an import (and without --owned), WEB-SVC is not a foothold.
    assert "WEB-SVC" not in AttackGraph(_lab()).start_nodes()


# ── Acceptance tests for the importer (proposed API, names may change) ───────
def _imported(path):
    from horuseye.parsers.webapps import load_webapps   # proposed
    data = _lab()
    load_webapps(str(path), data)
    return data, AttackGraph(data)


@PENDING
def test_claims_1_and_2_do_not_make_the_account_owned():
    _, g = _imported(UNCONFIRMED)
    assert "WEB-SVC" not in g.start_nodes()
    assert not g.shortest_paths()          # no normal route without claim 3


@PENDING
def test_without_claim_3_routes_are_conditional():
    _, g = _imported(UNCONFIRMED)
    routes = [g.describe(p) for p in g.conditional_paths()]
    assert routes
    r = routes[0]
    assert r["conditional"] is True
    assert ACCOUNT in " ".join(r["assumptions"])
    assert [s["trust"] for s in r["steps"]][:2] == ["validated", "assumed"]
    assert f"if {ACCOUNT} is compromised".lower() in r["label"].lower()


@PENDING
def test_with_claim_3_only_the_web_steps_are_validated():
    _, g = _imported(CONFIRMED)
    routes = [g.describe(p) for p in g.shortest_paths()]
    assert routes and routes[0]["conditional"] is False
    trust = [s["trust"] for s in routes[0]["steps"]]
    assert trust[:2] == ["validated", "validated"]
    assert set(trust[2:]) <= {"observed", "inferred"}   # AD steps stay graph-derived
    assert "WEB-SVC" not in g.start_nodes()             # still never "owned"


@PENDING
def test_credential_fields_are_rejected(tmp_path):
    from horuseye.parsers.webapps import load_webapps   # proposed
    doc = _load(CONFIRMED)
    doc["apps"][0]["claims"]["uses_account"]["account"]["password"] = "x"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError):
        load_webapps(str(bad), _lab())


@PENDING
def test_sid_mismatch_does_not_bind_the_account(tmp_path):
    doc = _load(CONFIRMED)
    doc["apps"][0]["claims"]["uses_account"]["account"]["sid"] = "S-1-5-21-ACME-9999"
    bad = tmp_path / "mismatch.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    data, g = _imported(bad)
    assert not g.shortest_paths() and not g.conditional_paths()
    assert any("WEB-SVC" in w for w in data["parse_report"]["warnings"])
