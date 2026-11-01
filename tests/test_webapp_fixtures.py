"""Web app → AD service account import, milestone 1 (examples/acme-lab-webapp).

Two fixtures share one app/account mapping; only the execution evidence for
claim 3 differs. These tests pin down the agreed behaviour: claims 1 and 2 never
make the account owned, routes without claim 3 stay conditional, claim 3
validates only the web steps, reachability is not control, and invalid
evidence fails the import.
"""
import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from horuseye import api
from horuseye.core.graph import AttackGraph
from horuseye.parsers.webapps import WebappImportError, load_webapps

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "examples" / "acme-lab"
FIX = ROOT / "examples" / "acme-lab-webapp"
UNCONFIRMED, CONFIRMED = FIX / "portal-unconfirmed.json", FIX / "portal-confirmed.json"
ACCOUNT = "WEB-SVC@ACME.LAB"


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _lab():
    return api.parse_sources(bloodhound=str(LAB), domain="ACME.LAB", dc="10.10.0.5")


def _imported(path):
    data = _lab()
    load_webapps(str(path), data)
    return data, AttackGraph(data)


def _variant(tmp_path, base, mutate, name="variant.json"):
    doc = copy.deepcopy(_load(base))
    mutate(doc)
    out = tmp_path / name
    out.write_text(json.dumps(doc), encoding="utf-8")
    return out


def _app(doc):
    return doc["apps"][0]


def _ev(doc, eid):
    return next(e for e in _app(doc)["evidence"] if e["id"] == eid)


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}.{k}", k, v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


# ── The fixtures themselves ──────────────────────────────────────────────────
def test_fixtures_share_the_mapping_and_differ_only_in_claim_3():
    a, b = _load(UNCONFIRMED), _load(CONFIRMED)
    assert a["schema"] == b["schema"] == "horuseye.webapps/1-draft"
    assert a["vantages"] == b["vantages"]
    for key in ("id", "name", "host", "url", "account"):
        assert _app(a)[key] == _app(b)[key]
    for claim in ("reachable_from_vantage", "uses_account"):
        assert _app(a)["claims"][claim] == _app(b)["claims"][claim]
    assert _app(b)["evidence"][:len(_app(a)["evidence"])] == _app(a)["evidence"]
    assert _app(a)["claims"]["privileges_obtainable"]["status"] == "not_assessed"
    assert _app(b)["claims"]["privileges_obtainable"]["status"] == "confirmed"


def test_fixtures_carry_no_credential_values():
    secret = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])|\$krb5|-----BEGIN|password\s*[=:]", re.I)
    for path in (UNCONFIRMED, CONFIRMED):
        for where, _key, value in _walk(_load(path)):
            if isinstance(value, str):
                assert not secret.search(value), f"{path.name}{where}"


def test_known_path_from_the_account_in_the_synthetic_directory():
    g = AttackGraph(_lab())
    first = g.describe(g.shortest_paths(owned=[ACCOUNT])[0])
    assert [s["type"] for s in first["steps"]] == ["AdminTo", "HasSession"]
    assert first["goal"] == "ADMINISTRATOR@ACME.LAB"


def test_directory_users_keep_their_sid():
    users = {u["name"]: u.get("sid") for u in _lab()["users"]}
    assert users[ACCOUNT] == "S-1-5-21-ACME-1106"


# ── Agreed behaviour ─────────────────────────────────────────────────────────
def test_claims_1_and_2_do_not_make_the_account_owned():
    _, g = _imported(UNCONFIRMED)
    assert "WEB-SVC" not in g.start_nodes()
    assert g.start_nodes() == {"VANTAGE:LAB-TESTER-1"}
    assert g.shortest_paths() == []             # no normal route without claim 3
    assert g.remediation_plans() == []          # nothing proven, nothing to fix yet


def test_without_claim_3_routes_are_conditional_and_the_claim_stays_not_assessed():
    data, g = _imported(UNCONFIRMED)
    (route,) = [g.describe(p) for p in g.conditional_paths()]
    assert route["conditional"] is True
    assert route["label"] == f"Hypothetical: if {ACCOUNT} is compromised"
    assert route["assumptions"] == [f"{ACCOUNT} is compromised through APP:acme-portal (not assessed)"]
    assert [s["trust"] for s in route["steps"]] == ["validated", "not_assessed", "observed", "observed"]
    assert "not proven" in route["rationale"]
    # Showing the what-if route never turns the claim into an assumption.
    assert data["webapps"][0]["claims"]["privileges_obtainable"]["status"] == "not_assessed"


def test_with_claim_3_only_the_web_steps_are_validated():
    _, g = _imported(CONFIRMED)
    (route,) = [g.describe(p) for p in g.shortest_paths()]
    assert route["conditional"] is False and route["assumptions"] == []
    assert [s["type"] for s in route["steps"]] == ["Reaches", "ExecutesAs", "AdminTo", "HasSession"]
    assert [s["trust"] for s in route["steps"]] == ["validated", "validated", "observed", "observed"]
    assert route["steps"][1]["evidence"] == ["req-2", "exec-1"]
    assert route["validated_steps"] == 2
    assert "WEB-SVC" not in g.start_nodes()     # still never "owned"
    assert g.conditional_paths() == []


def test_reachability_is_not_control():
    _, g = _imported(CONFIRMED)
    route = g.describe(g.shortest_paths()[0])
    assert route["steps"][0]["kind"] == "reachability"
    assert all(s["kind"] == "control" for s in route["steps"][1:])
    plans = g.remediation_plans()
    assert plans and all(c["type"] != "Reaches" for p in plans for c in p["changes"])
    assert all(h["type"] != "Reaches" for h in g.remediation_impact())
    fixes = [c["fix"] for p in plans for c in p["changes"]]
    assert any(f.startswith("Fix the vulnerable endpoint in acme-portal") for f in fixes)
    assert any("WEB-SVC from the local Administrators group on WEB01" in f for f in fixes)


def test_explicit_assumption_is_labelled_with_its_rationale(tmp_path):
    def assume(doc):
        _app(doc)["claims"]["privileges_obtainable"] = {
            "status": "assumed", "evidence": [],
            "rationale": "Same framework version as a known RCE; not tested"}
    _, g = _imported(_variant(tmp_path, UNCONFIRMED, assume))
    (route,) = [g.describe(p) for p in g.conditional_paths()]
    assert route["label"] == f"Assumed: if {ACCOUNT} is compromised"
    assert "Same framework version as a known RCE" in route["assumptions"][0]
    assert route["steps"][1]["trust"] == "assumed"


def test_execution_evidence_can_support_claims_2_and_3(tmp_path):
    def no_config(doc):
        app = _app(doc)
        app["evidence"] = [e for e in app["evidence"] if e["id"] != "cfg-1"]
        app["claims"]["uses_account"]["evidence"] = ["exec-1"]
    data, g = _imported(_variant(tmp_path, CONFIRMED, no_config))
    assert g.shortest_paths()
    assert data["parse_report"]["warnings"] == []


def test_config_conflict_is_surfaced_not_resolved(tmp_path):
    def conflict(doc):
        _ev(doc, "cfg-1")["identity"] = "ACME\\OTHER-SVC"
    data, g = _imported(_variant(tmp_path, CONFIRMED, conflict))
    (msg,) = data["webapps"][0]["conflicts"]
    assert "cfg-1" in msg and "OTHER-SVC" in msg and ACCOUNT in msg
    assert msg in data["parse_report"]["warnings"]
    assert g.shortest_paths()                   # the execution record still stands


def test_sid_mismatch_with_the_directory(tmp_path):
    def wrong_sid(doc):
        _app(doc)["account"]["sid"] = "S-1-5-21-ACME-9999"
    data, g = _imported(_variant(tmp_path, UNCONFIRMED, wrong_sid))
    assert any("S-1-5-21-ACME-1106" in w and "9999" in w for w in data["parse_report"]["warnings"])
    assert g.shortest_paths() == [] and g.conditional_paths() == []    # never binds by name

    def wrong_sid_confirmed(doc):
        _app(doc)["account"]["sid"] = "S-1-5-21-ACME-9999"
        _ev(doc, "exec-1")["effective_sid"] = "S-1-5-21-ACME-9999"
    with pytest.raises(WebappImportError, match="invalid confirmed privileges_obtainable"):
        _imported(_variant(tmp_path, CONFIRMED, wrong_sid_confirmed))


def _set(eid, key, value):
    def mutate(doc):
        _ev(doc, eid)[key] = value
    return mutate


def _claim(name, **fields):
    def mutate(doc):
        _app(doc)["claims"][name].update(fields)
    return mutate


INVALID = [
    ("duplicate evidence id", lambda d: _app(d)["evidence"].append(dict(_ev(d, "req-1"))),
     "duplicate evidence id"),
    ("trigger not in this app", _set("exec-1", "triggered_by", "req-9"), "not evidence in this app"),
    ("trigger is not a request", _set("exec-1", "triggered_by", "cfg-1"), "triggered_by an http_request"),
    ("executed as another SID", _set("exec-1", "effective_sid", "S-1-5-21-ACME-1103"),
     "not the mapped account"),
    ("executed on another host", _set("exec-1", "host", "FILE01.ACME.LAB"), "not the app host"),
    ("no execution record", _claim("privileges_obtainable", evidence=["req-2"]),
     "invalid confirmed privileges_obtainable: needs execution_identity"),
    ("claim cites unknown evidence", _claim("uses_account", evidence=["cfg-9"]), "cites 'cfg-9'"),
    ("confirmed without evidence", _claim("uses_account", evidence=[]), "must cite evidence"),
    ("not_assessed with evidence", _claim("privileges_obtainable", status="not_assessed"),
     "can't cite evidence"),
    ("assumed without rationale", _claim("privileges_obtainable", status="assumed"), "needs a rationale"),
    ("unknown vantage", _set("req-1", "vantage", "laptop-9"), "unknown vantage"),
    ("request without response summary", _set("req-1", "response", {"status": 200}),
     "integer status and a summary"),
    ("bad digest", _set("cfg-1", "artifact_sha256", "abc"), "64 lowercase hex"),
    ("credential field", lambda d: _app(d)["account"].update(password="x"), "credential-like"),
    ("raw response body", lambda d: _ev(d, "req-1")["response"].update(body="<html>"),
     "raw response bodies"),
    ("old claim name", lambda d: _app(d)["claims"].update(exposed={"status": "not_assessed"}),
     "unknown claim"),
    ("wrong schema", lambda d: d.update(schema="horuseye.webapps/0"), "schema must be"),
]


@pytest.mark.parametrize("mutate,expected", [(m, e) for _n, m, e in INVALID],
                         ids=[n for n, _m, _e in INVALID])
def test_invalid_files_fail_the_import(tmp_path, mutate, expected):
    with pytest.raises(WebappImportError, match=re.escape(expected)):
        _imported(_variant(tmp_path, CONFIRMED, mutate))


def test_relationship_ids_are_stable_and_unique():
    _, g1 = _imported(CONFIRMED)
    _, g2 = _imported(CONFIRMED)
    ids1 = [g1.rel_id(e) for es in g1.adj.values() for e in es]
    ids2 = [g2.rel_id(e) for es in g2.adj.values() for e in es]
    assert ids1 == ids2 and len(set(ids1)) == len(ids1)
    assert "AdminTo:WEB-SVC->WEB01.ACME.LAB" in ids1
    assert "ExecutesAs:APP:ACME-PORTAL->WEB-SVC" in ids1


def test_import_leaves_the_jdoe_demo_unchanged():
    before = AttackGraph(_lab())
    _, after = _imported(CONFIRMED)
    owned = ["JDOE@ACME.LAB"]
    assert [before.describe(p) for p in before.shortest_paths(owned=owned)] == \
        [after.describe(p) for p in after.shortest_paths(owned=owned)]
    assert before.remediation_plans(owned=owned) == after.remediation_plans(owned=owned)


# ── CLI end to end ───────────────────────────────────────────────────────────
def _cli(*args):
    return subprocess.run([sys.executable, "-m", "horuseye", "--bloodhound", str(LAB),
                           "--domain", "ACME.LAB", "--dc", "10.10.0.5", "--graph", *args],
                          cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                          env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"})


def test_cli_reports_conditional_routes_separately(tmp_path):
    out = tmp_path / "r.json"
    run = _cli("--webapps", str(UNCONFIRMED), "--json", str(out))
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Conditional routes" in run.stdout and "not assessed" in run.stdout
    report = _load(out)
    assert report["attack_paths"] == []
    assert report["conditional_paths"][0]["label"] == f"Hypothetical: if {ACCOUNT} is compromised"


def test_cli_rejects_an_invalid_import_with_exit_1(tmp_path):
    bad = _variant(tmp_path, CONFIRMED, _set("exec-1", "triggered_by", "req-9"))
    run = _cli("--webapps", str(bad))
    assert run.returncode == 1
    assert "not evidence in this app" in run.stdout + run.stderr
