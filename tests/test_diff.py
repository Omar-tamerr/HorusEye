"""Retest diff and CI fail-gate."""
import json

from horuseye.core.diff import diff_findings, fail_level_exceeded, load_previous


def _f(fid, sev="HIGH", title="t"):
    return {"id": fid, "severity": sev, "title": title, "type": "ACL_ABUSE", "affected": fid}


def test_diff_new_fixed_unchanged():
    prev = [_f("a"), _f("b"), _f("c")]
    cur = [_f("b"), _f("c"), _f("d")]
    d = diff_findings(prev, cur)
    assert {x["id"] for x in d["new"]} == {"d"}
    assert {x["id"] for x in d["fixed"]} == {"a"}
    assert {x["id"] for x in d["unchanged"]} == {"b", "c"}


def test_diff_falls_back_to_type_affected_without_id():
    prev = [{"type": "DCSYNC", "affected": "X", "severity": "CRITICAL"}]
    cur = [{"type": "DCSYNC", "affected": "X", "severity": "CRITICAL"}]
    d = diff_findings(prev, cur)
    assert not d["new"] and not d["fixed"] and len(d["unchanged"]) == 1


def test_diff_sorted_by_severity():
    prev = []
    cur = [_f("a", "LOW"), _f("b", "CRITICAL"), _f("c", "MEDIUM")]
    assert [x["severity"] for x in diff_findings(prev, cur)["new"]] == ["CRITICAL", "MEDIUM", "LOW"]


def test_fail_level():
    findings = [_f("a", "HIGH"), _f("b", "LOW")]
    assert fail_level_exceeded(findings, "high") is True
    assert fail_level_exceeded(findings, "critical") is False
    assert fail_level_exceeded(findings, "low") is True
    assert fail_level_exceeded([], "low") is False
    assert fail_level_exceeded(findings, "bogus") is False


def test_load_previous_v1_and_v2(tmp_path):
    v2 = tmp_path / "v2.json"
    v2.write_text(json.dumps({"schema": "horuseye.report/2", "findings": [_f("a")]}), encoding="utf-8")
    assert len(load_previous(str(v2))) == 1
    v1 = tmp_path / "v1.json"
    v1.write_text(json.dumps({"findings": [_f("a"), _f("b")]}), encoding="utf-8")
    assert len(load_previous(str(v1))) == 2
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps([_f("a")]), encoding="utf-8")
    assert len(load_previous(str(bare))) == 1
