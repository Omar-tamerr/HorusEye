"""Retest drift: routes and exposure compared with a baseline, and the CI gates
(--fail-on new-route / exposure-up) that catch a fix that didn't hold."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from horuseye.core.diff import diff_exposure, diff_routes, drift_gate_failures, route_key

ROOT = Path(__file__).resolve().parents[1]


def _route(start, *hops):
    steps, cur = [], start
    for typ, to, detail in hops:
        steps.append({"type": typ, "from": cur, "to": to, "detail": detail})
        cur = to
    return {"start": start, "goal": cur, "steps": steps}


R1 = _route("JDOE@CORP", ("MemberOf", "HELPDESK@CORP", "member of group"),
            ("ACL", "DOMAIN ADMINS@CORP", "genericall → object takeover"))
R2 = _route("JDOE@CORP", ("AdminTo", "WS01.CORP", "local administrator"),
            ("HasSession", "ADMIN@CORP", "credentials in memory"))


def test_routes_new_closed_still_open():
    d = diff_routes([R1], [R1, R2])
    assert d["comparable"] and [route_key(p) for p in d["new"]] == [route_key(R2)]
    assert d["still_open"] and not d["closed"]
    d = diff_routes([R1, R2], [R2])
    assert [p["steps"][0]["type"] for p in d["closed"]] == ["MemberOf"]


def test_route_identity_ignores_ids_and_name_suffixes():
    old = json.loads(json.dumps(R1))                     # a v2.3 report: no step ids
    new = json.loads(json.dumps(R1))
    for s in new["steps"]:
        s["id"] = "x"
        s["from"] = s["from"].lower()
    assert route_key(old) == route_key(new)


def test_routes_from_different_footholds_are_not_compared():
    other = _route("BOB@CORP", ("ACL", "DOMAIN ADMINS@CORP", "genericall → object takeover"))
    d = diff_routes([R1], [other])
    assert d["comparable"] is False and not d["new"] and "foothold" in d["reason"]


def _x(users, targets=None):
    return {"computed": True, "users_exposed": len(users), "users_total": 10,
            "percent": 10.0 * len(users), "exposed_users": users, "targets": targets or ["Tier-0"]}


def test_exposure_rise_names_who_gained_a_route():
    d = diff_exposure(_x(["A@CORP", "B@CORP"]), _x(["B@CORP", "C@CORP", "D@CORP"]))
    assert d["comparable"] and d["rose"]
    assert d["newly_exposed"] == ["C@CORP", "D@CORP"] and d["no_longer_exposed"] == ["A@CORP"]
    assert (d["before"], d["after"]) == (2, 3)


def test_same_count_but_someone_new_still_counts_as_a_rise():
    d = diff_exposure(_x(["A@CORP"]), _x(["B@CORP"]))
    assert d["rose"] and d["newly_exposed"] == ["B@CORP"]


def test_falling_exposure_is_not_a_rise():
    d = diff_exposure(_x(["A@CORP", "B@CORP"]), _x(["A@CORP"]))
    assert not d["rose"] and d["no_longer_exposed"] == ["B@CORP"]


def test_baseline_without_exposure_is_not_comparable():
    d = diff_exposure(None, _x(["A@CORP"]))
    assert d["comparable"] is False and "before v2.4" in d["reason"]
    assert d["after"] == 1


def test_different_targets_are_not_comparable():
    d = diff_exposure(_x(["A@CORP"]), _x(["A@CORP"], targets=["SQL01"]))
    assert d["comparable"] is False


def test_gates():
    routes = diff_routes([R1], [R1, R2])
    x = diff_exposure(_x(["A@CORP"]), _x(["A@CORP", "B@CORP"]))
    assert len(drift_gate_failures(["new-route", "exposure-up"], routes, x)) == 2
    assert drift_gate_failures(["high"], routes, x) == []
    assert drift_gate_failures(["exposure-up"], routes, diff_exposure(None, _x([]))) == []


# ── End to end through the CLI ───────────────────────────────────────────────────
def _run(*args, cwd):
    env = dict(os.environ, SOURCE_DATE_EPOCH="1793000000", PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, "-m", "horuseye", *args, "--no-ai"], cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=120)


def test_cli_exposure_up_gate_catches_a_reopened_route(tmp_path):
    lab = tmp_path / "lab"
    shutil.copytree(ROOT / "examples" / "acme-lab", lab)
    common = ["--domain", "ACME.LAB", "--dc", "10.10.0.5", "--owned", "JDOE@ACME.LAB"]
    base = _run("--bloodhound", str(lab), *common, "--json", str(tmp_path / "base.json"), cwd=ROOT)
    assert base.returncode == 0, base.stdout[-2000:]
    report = json.loads((tmp_path / "base.json").read_text(encoding="utf-8"))
    assert report["exposure"]["computed"] and report["attack_paths"]

    gates = ["--diff", str(tmp_path / "base.json"), "--fail-on", "exposure-up", "--fail-on", "new-route"]
    same = _run("--bloodhound", str(lab), *common, *gates, cwd=ROOT)
    assert same.returncode == 0, same.stdout[-2000:]

    groups = lab / "groups.json"                         # a new delegation reopens a route
    d = json.loads(groups.read_text(encoding="utf-8"))
    for g in d["data"]:
        if g["Properties"]["name"].startswith("DOMAIN ADMINS"):
            g.setdefault("Aces", []).append({"PrincipalSID": "S-1-5-21-ACME-1101", "RightName": "GenericAll"})
    groups.write_text(json.dumps(d), encoding="utf-8")
    drift = _run("--bloodhound", str(lab), *common, *gates, "--json", str(tmp_path / "after.json"), cwd=ROOT)
    assert drift.returncode == 4, drift.stdout[-2000:]
    retest = json.loads((tmp_path / "after.json").read_text(encoding="utf-8"))["retest"]
    assert retest["exposure"]["newly_exposed"] == ["SVC-SQL@ACME.LAB"]


def test_cli_drift_gate_needs_a_baseline():
    r = _run("--bloodhound", "examples/acme-lab", "--domain", "ACME.LAB", "--fail-on", "new-route", cwd=ROOT)
    assert r.returncode == 1 and "--diff" in r.stdout
