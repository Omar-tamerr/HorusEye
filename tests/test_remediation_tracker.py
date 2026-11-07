"""v2.5 remediation tracker: effort, Quick Wins, finding cards, status, CSV."""
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from horuseye import api
from horuseye.core import status
from horuseye.core.effort import EffortContext, rate_change, rate_finding
from horuseye.core.graph import AttackGraph
from horuseye.core.triage import quick_wins, triage
from horuseye.reports.explorer import build_explorer
from horuseye.reports.report_generator import ReportGenerator

ROOT = Path(__file__).resolve().parent.parent
ACME = ROOT / "examples" / "acme-lab"
KARNAK = ROOT / "examples" / "karnak-lab"


def _acme():
    return api.parse_sources(bloodhound=str(ACME), domain="ACME.LAB", dc="10.10.0.5")


def _karnak():
    return api.parse_sources(bloodhound=str(KARNAK), domain="KARNAK.LAB", dc="10.20.0.10",
                             certipy=str(KARNAK / "adcs" / "karnak_Certipy.json"))


def _triaged(data):
    findings = api.detect(data)
    wins = api.triage(findings, data)
    return findings, wins


def _ctx(**data):
    base = {"domain": "CORP.LOCAL", "users": [], "groups": [], "computers": [], "acls": [],
            "sessions": [], "local_admins": [], "delegation_targets": []}
    base.update(data)
    return EffortContext(base, AttackGraph(base))


def _change(t, a="BOB@CORP.LOCAL", b="WS01.CORP.LOCAL"):
    return {"type": t, "from": a, "to": b, "detail": ""}


# ── Effort rules ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("change,level,rule", [
    (_change("ForceChangePassword", "HELPDESK@CORP.LOCAL", "ALICE@CORP.LOCAL"), "Low", "effort.permission"),
    (_change("AdminTo", "HELPDESK@CORP.LOCAL", "WS01.CORP.LOCAL"), "Low", "effort.permission"),
    (_change("MemberOf", "BOB@CORP.LOCAL", "HELPDESK@CORP.LOCAL"), "Medium", "effort.membership"),
    (_change("HasSession", "WS01.CORP.LOCAL", "ADMIN@CORP.LOCAL"), "Medium", "effort.session"),
    (_change("Unconstrained", "WEB01.CORP.LOCAL", "CORP.LOCAL"), "High", "effort.delegation"),
    (_change("ConstrainedDeleg"), "High", "effort.delegation"),
    (_change("AllowedToAct"), "High", "effort.delegation"),
    (_change("ADCS", "DOMAIN USERS@CORP.LOCAL", "CORP.LOCAL"), "Medium", "effort.adcs_template"),
    (_change("DCSync", "BOB@CORP.LOCAL", "CORP.LOCAL"), "Low", "effort.dcsync"),
    (_change("DCSync", "MSOL_1a2b3c@CORP.LOCAL", "CORP.LOCAL"), "High", "effort.sync_account"),
    (_change("SomethingNew"), "Medium", "effort.default"),
])
def test_change_effort_rules(change, level, rule):
    r = rate_change(change, _ctx())
    assert (r["level"], r["rule"]) == (level, rule)
    assert r["reason"]


def test_permission_on_a_tier0_object_is_medium():
    ctx = _ctx(groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True, "members": []}])
    r = rate_change(_change("ACL", "HELPDESK@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"), ctx)
    assert (r["level"], r["rule"]) == ("Medium", "effort.tier0_permission")


def test_access_held_by_a_service_account_is_at_least_medium():
    ctx = _ctx(users=[{"name": "SVC-WEB@CORP.LOCAL", "hasspn": True}])
    held = rate_change(_change("AdminTo", "SVC-WEB@CORP.LOCAL", "WS01.CORP.LOCAL"), ctx)
    assert (held["level"], held["rule"]) == ("Medium", "effort.service_account")
    assert "may break the service" in held["reason"]
    # Removing someone's right OVER a service account doesn't touch the app.
    over = rate_change(_change("ForceChangePassword", "HELPDESK@CORP.LOCAL", "SVC-WEB@CORP.LOCAL"), ctx)
    assert over["level"] == "Low"
    dcsync = rate_change(_change("DCSync", "SVC-WEB@CORP.LOCAL", "CORP.LOCAL"), ctx)
    assert dcsync["level"] == "Medium"


def test_finding_effort_floors_and_many_changes():
    ctx = _ctx()
    low = [_change("AdminTo", "G@CORP.LOCAL", f"WS{i}.CORP.LOCAL") for i in range(12)]
    assert rate_finding({"type": "PASS_THE_HASH"}, low, ctx)["rule"] == "effort.many_changes"
    assert rate_finding({"type": "PASS_THE_HASH"}, low, ctx)["level"] == "High"
    assert rate_finding({"type": "PASS_THE_HASH"}, low[:3], ctx)["level"] == "Medium"
    assert rate_finding({"type": "GPO_ABUSE"}, low[:1], ctx)["level"] == "Medium"
    assert rate_finding({"type": "KERBEROASTING", "affected": "SVC@CORP.LOCAL"}, [], ctx)["level"] == "Medium"
    assert rate_finding({"type": "DOMAIN_TRUST"}, [], ctx)["level"] == "High"
    assert rate_finding({"type": "WEAK_PASSWORD_POLICY"}, [], ctx)["level"] == "High"
    assert rate_finding({"type": "STALE_ADMIN"}, [], ctx)["level"] == "Low"
    assert rate_finding({"type": "ASREP_ROASTING", "affected": "BOB@CORP.LOCAL"}, [], ctx)["level"] == "Low"
    assert rate_finding({"type": "ASREP_ROASTING", "affected": "SVC-BAK@CORP.LOCAL"}, [], ctx)["level"] == "Medium"
    assert rate_finding({"type": "ADCS_ESC", "rule_id": "ADCS_ESC.ESC8"}, [], ctx)["level"] == "High"
    assert rate_finding({"type": "UNKNOWN_TYPE"}, [], ctx)["rule"] == "effort.default"


def test_effort_is_documented_for_every_rule():
    doc = (ROOT / "docs" / "effort.md").read_text(encoding="utf-8")
    src = (ROOT / "horuseye" / "core" / "effort.py").read_text(encoding="utf-8")
    for rule in sorted(set(re.findall(r'"(effort\.[a-z0-9_]+)"', src))):
        assert f"`{rule}`" in doc, f"{rule} missing from docs/effort.md"


def test_triage_never_changes_severity():
    for data in (_acme(), _karnak()):
        findings = api.detect(data)
        before = [(f["id"], f["severity"]) for f in findings]
        api.triage(findings, data)
        assert [(f["id"], f["severity"]) for f in findings] == before
        assert all(f["effort"] in ("Low", "Medium", "High") and f["effort_reason"] for f in findings)


# ── Quick Wins ───────────────────────────────────────────────────────────────
def test_quick_win_is_critical_or_high_and_low_effort():
    for data in (_acme(), _karnak()):
        findings, wins = _triaged(data)
        for f in findings:
            expected = f["severity"] in ("CRITICAL", "HIGH") and f["effort"] == "Low"
            assert f["quick_win"] is expected


def test_quick_wins_on_the_labs():
    _, wins = _triaged(_acme())
    assert [w["rule_id"] for w in wins] == ["DCSYNC", "ACL_ABUSE.forcechangepassword"]
    _, wins = _triaged(_karnak())
    assert [w["rule_id"] for w in wins] == ["ACL_ABUSE.forcechangepassword"]
    assert wins[0]["impact"]["users_through"] == 156


def test_quick_win_ranking_order():
    def f(fid, cut, through, on, score):
        return {"id": fid, "quick_win": True, "score": score,
                "impact": {"users_cut_off": cut, "users_through": through, "on_route": on}}
    ranked = quick_wins([f("e", 0, 0, False, 99), f("a", 5, 0, True, 1), f("b", 0, 9, True, 1),
                         f("c", 0, 0, True, 50), f("d", 5, 0, True, 2), {"id": "x", "quick_win": False}])
    assert [w["id"] for w in ranked] == ["d", "a", "b", "c", "e"]
    assert [w["quick_win_rank"] for w in ranked] == [1, 2, 3, 4, 5]


def test_why_critical_states_the_measured_impact():
    findings, _ = _triaged(_karnak())
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["ADCS_ESC.ESC1"]["why_critical"] == \
        "Fixing this alone cuts 1,046 of 1,211 exposed users off from Tier-0."
    assert by_rule["KERBEROASTING"]["why_critical"] == "If SVC-SQL is compromised, it reaches Tier-0 in 2 steps."
    assert by_rule["ADCS_ESC.ESC1"]["fix_options"][0]["users_cut_off"] == 1046


def test_keep_alternative_is_a_plan_that_keeps_the_access():
    # The exposure plan relies on getting ADMINISTRATOR off WEB01; if that
    # session must stay, the alternative plan never removes it.
    data = _acme()
    findings, _ = _triaged(data)
    sess = next(f for f in findings if f["rule_id"] == "PRIVILEGED_SESSION")
    alt = sess["keep_alternative"]
    assert alt and alt["keep"] == "WEB01.ACME.LAB->ADMINISTRATOR@ACME.LAB"
    assert alt["changes"] and not set(sess["rel_ids"]) & {c["id"] for c in alt["changes"]}
    assert all(c["effort"] in ("Low", "Medium", "High") for c in alt["changes"])
    # And the alternative really cuts every user off.
    g = AttackGraph(data)
    keys = {g.edge_key(e) for es in g.adj.values() for e in es
            if g.rel_id(e) in {c["id"] for c in alt["changes"]}}
    assert g.cut_off_counts({"alt": keys})["alt"]["users_cut_off"] == g.exposure()["users_exposed"]
    # A finding whose fix is in no plan and cuts no one off gets none.
    assert next(f for f in findings if f["rule_id"] == "KERBEROASTING")["keep_alternative"] is None


def test_source_names_file_object_and_sid():
    findings, _ = _triaged(_acme())
    dcsync = next(f for f in findings if f["rule_id"] == "DCSYNC")
    src = dcsync["source"][0]
    assert src["file"].endswith("domains.json") and src["sid"] == "S-1-5-21-ACME-1104"


# ── Stable ids ───────────────────────────────────────────────────────────────
def test_finding_ids_are_stable_across_runs_and_processes():
    code = ("import json,sys;sys.path.insert(0,'.');from horuseye import api;"
            f"d=api.parse_sources(bloodhound=r'{KARNAK}',domain='KARNAK.LAB',dc='10.20.0.10',"
            f"certipy=r'{KARNAK / 'adcs' / 'karnak_Certipy.json'}');"
            "f=api.detect(d);w=api.triage(f,d);"
            "print(json.dumps([[x['id'],x['effort'],x['quick_win']] for x in f]+[[x['id'] for x in w]]))")
    outs = {subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                           env=dict(os.environ, PYTHONHASHSEED=seed), check=True).stdout
            for seed in ("1", "2")}
    assert len(outs) == 1
    ids = [row[0] for row in json.loads(outs.pop())[:-1]]
    assert all(re.match(r"^[0-9a-f]{12}$", i) for i in ids) and len(set(ids)) == len(ids)


# ── Status file ──────────────────────────────────────────────────────────────
def test_status_file_keeps_only_ids_status_notes_and_dates():
    doc = {"schema": status.SCHEMA, "extra": "dropped", "findings": {
        "aaaaaaaaaaaa": {"status": "fixed", "notes": "done", "changed": "2026-11-07", "password": "x"},
        "bbbbbbbbbbbb": {"status": "not-a-status"},
        "not-an-id": {"status": "open"},
        "cccccccccccc": {"status": "accepted_risk", "notes": "x" * 5000, "changed": "yesterday"}}}
    clean = status.clean(doc)
    assert set(clean) == {"aaaaaaaaaaaa", "cccccccccccc"}
    assert clean["aaaaaaaaaaaa"] == {"status": "fixed", "notes": "done", "changed": "2026-11-07"}
    assert len(clean["cccccccccccc"]["notes"]) == status.MAX_NOTES and clean["cccccccccccc"]["changed"] == ""
    with pytest.raises(status.StatusFileError):
        status.clean({"schema": "something/else", "findings": {}})


def test_status_round_trip(tmp_path):
    entries = {"aaaaaaaaaaaa": {"status": "in_progress", "notes": "ticket CHG-1", "changed": "2026-11-07"},
               "bbbbbbbbbbbb": {"status": "false_positive", "notes": "", "changed": "2026-11-01"}}
    path = tmp_path / "horuseye-status.json"
    status.save(str(path), entries)
    assert status.load(str(path)) == entries
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert set(saved) == {"schema", "findings"}
    assert all(set(e) == {"status", "notes", "changed"} for e in saved["findings"].values())


def test_status_merge_counts_and_marked_fixed_check():
    findings, _ = _triaged(_acme())
    dcsync = next(f for f in findings if f["rule_id"] == "DCSYNC")
    summary = status.merge(findings, {dcsync["id"]: {"status": "fixed", "notes": "n", "changed": "2026-11-07"},
                                      "ffffffffffff": {"status": "fixed", "notes": "", "changed": ""}})
    assert summary["counts"]["fixed"] == 1 and summary["counts"]["open"] == len(findings) - 1
    assert summary["marked_fixed_still_found"] == [dcsync["id"]]
    assert dcsync["status_check"] == "marked_fixed_still_found"
    assert summary["not_in_this_run"] == ["ffffffffffff"]


def _cli(*args, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "horuseye", *args], cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", env=dict(os.environ, PYTHONIOENCODING="utf-8"))


def test_status_with_diff_end_to_end(tmp_path):
    # Baseline run, then "fix" DCSync in a copy of the data and retest.
    base = tmp_path / "base.json"
    run = _cli("--bloodhound", str(ACME), "--domain", "ACME.LAB", "--dc", "10.10.0.5", "--json", str(base))
    assert run.returncode == 0, run.stdout[-2000:]
    found = {f["rule_id"]: f["id"] for f in json.loads(base.read_text(encoding="utf-8"))["findings"]}
    lab = tmp_path / "lab"
    shutil.copytree(ACME, lab)
    doms = json.loads((lab / "domains.json").read_text(encoding="utf-8"))
    doms["data"][0]["Aces"] = []
    (lab / "domains.json").write_text(json.dumps(doms), encoding="utf-8")
    st = tmp_path / "horuseye-status.json"
    status.save(str(st), {found["DCSYNC"]: {"status": "fixed", "notes": "ACE removed", "changed": "2026-11-07"},
                          found["ACL_ABUSE.forcechangepassword"]: {"status": "fixed", "notes": "",
                                                                    "changed": "2026-11-07"}})
    out = tmp_path / "retest.json"
    run = _cli("--bloodhound", str(lab), "--domain", "ACME.LAB", "--dc", "10.10.0.5",
               "--diff", str(base), "--status", str(st), "--json", str(out))
    assert run.returncode == 0, run.stdout[-2000:]
    summary = json.loads(out.read_text(encoding="utf-8"))["status"]
    assert [v["id"] for v in summary["verified_fixed"]] == [found["DCSYNC"]]
    assert summary["marked_fixed_still_found"] == [found["ACL_ABUSE.forcechangepassword"]]
    assert "verified fixed" in run.stdout and "marked fixed but still found" in run.stdout


# ── CSV ──────────────────────────────────────────────────────────────────────
def test_csv_columns_and_rows(tmp_path):
    data = _acme()
    findings, wins = _triaged(data)
    status.merge(findings, {})
    r = ReportGenerator(findings, data, console=None, generated_at="2026-11-07 00:00:00")
    r.quick_wins = wins
    out = tmp_path / "f.csv"
    r.export_csv(str(out))
    rows = list(csv.DictReader(out.read_text(encoding="utf-8-sig").splitlines()))
    assert list(rows[0].keys()) == list(ReportGenerator.CSV_COLUMNS)
    assert len(rows) == len(findings)
    assert [row["quick_win"] for row in rows[:2]] == ["yes", "yes"] and rows[0]["id"] == wins[0]["id"]
    assert all(row["effort"] in ("Low", "Medium", "High") and row["status"] == "Open" for row in rows)


def test_csv_neutralizes_spreadsheet_formulas():
    for evil in ("=HYPERLINK(\"http://x\")", "+1", "-2", "@SUM(A1)", "\tx"):
        assert ReportGenerator._cell(evil).startswith("'")
    assert ReportGenerator._cell("HELPDESK@ACME.LAB") == "HELPDESK@ACME.LAB"


# ── Reports and explorer ─────────────────────────────────────────────────────
def test_html_and_markdown_lead_with_quick_wins(tmp_path):
    data = _acme()
    findings, wins = _triaged(data)
    status.merge(findings, {})
    r = ReportGenerator(findings, data, console=None, generated_at="2026-11-07 00:00:00")
    r.quick_wins = wins
    r.export_html(str(tmp_path / "r.html"))
    r.export_markdown(str(tmp_path / "r.md"))
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    md = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert html.index("<h2>Quick Wins</h2>") < html.index("<h2>Findings</h2>")
    for part in ("Why it is critical", "fix</div>", "What to do", "How to verify", "Source"):
        assert part in html
    assert md.index("## Quick Wins") < md.index("## Findings")


def _explorer(data=None):
    data = data or _acme()
    findings, _ = _triaged(data)
    status.merge(findings, {})
    return build_explorer(findings, [], [], data, "2026-11-07", exposure=AttackGraph(data).exposure())


def test_explorer_storage_access_is_guarded():
    page = _explorer()
    for line in page.splitlines():
        if "localStorage" in line:
            assert "try{" in line and "catch(e)" in line, line.strip()[:120]


def _browser():
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        path = shutil.which(name)
        if path:
            return path
    for path in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                 r"C:\Program Files\Google\Chrome\Application\chrome.exe"):
        if os.path.exists(path):
            return path
    return None


@pytest.mark.skipif(_browser() is None, reason="no headless Chrome/Edge available")
@pytest.mark.parametrize("blocked", [False, True], ids=["storage-ok", "storage-blocked"])
def test_explorer_renders_with_and_without_storage(tmp_path, blocked):
    page = _explorer(_karnak())
    if blocked:   # every localStorage access throws, as in a locked-down browser
        page = page.replace("<script>\n", "<script>Object.defineProperty(window,'localStorage',"
                                          "{get:function(){throw new Error('blocked');}});</script>\n<script>\n", 1)
    f = tmp_path / "x.html"
    f.write_text(page, encoding="utf-8")
    run = subprocess.run([_browser(), "--headless=new", "--disable-gpu", "--no-sandbox",
                          f"--user-data-dir={tmp_path / 'profile'}", "--virtual-time-budget=1500",
                          "--dump-dom", f.resolve().as_uri() + "#findings"],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    dom = run.stdout
    rendered = re.findall(r'<tr class="frow[^"]*" data-fid="[0-9a-f]{12}"', dom)
    assert len(rendered) == 8, run.stderr[-800:]
    assert 'id="qwcard"' in dom and "Quick Win #1" in dom
    bar = re.search(r'<span id="stsum">(.*?)</span><button', dom, re.S)
    assert bar and ("blocks storage" in bar.group(1)) is blocked
    assert ("saved in this browser" in bar.group(1)) is not blocked
