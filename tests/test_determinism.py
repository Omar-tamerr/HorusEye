"""Stage D: deterministic output, exit-code taxonomy, JSON schema versioning."""
import json

from horuseye.core.exit_codes import (ERROR, FINDINGS, INCOMPLETE, OK,
                                       assessment_is_incomplete)
from horuseye.reports.report_generator import ReportGenerator


def _reporter(**kw):
    findings = [{"id": "a", "type": "DCSYNC", "title": "t", "affected": "X",
                 "severity": "CRITICAL", "confidence": "HIGH", "evidence": [],
                 "commands": ["cmd"], "mitre": [], "remediation": [], "detection": []}]
    return ReportGenerator(findings, {"domain": "CORP", "dc_ip": "1.1.1.1"},
                           generated_at="2026-01-01 00:00:00", **kw)


# ── Determinism ──────────────────────────────────────────────────────────────
def test_html_is_byte_identical_with_fixed_clock(tmp_path):
    a, b = tmp_path / "a.html", tmp_path / "b.html"
    _reporter().export_html(str(a))
    _reporter().export_html(str(b))
    assert a.read_bytes() == b.read_bytes()


def test_json_is_byte_identical_with_fixed_clock(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    _reporter().export_json(str(a))
    _reporter().export_json(str(b))
    assert a.read_bytes() == b.read_bytes()


def test_markdown_is_byte_identical_with_fixed_clock(tmp_path):
    a, b = tmp_path / "a.md", tmp_path / "b.md"
    _reporter().export_markdown(str(a))
    _reporter().export_markdown(str(b))
    assert a.read_bytes() == b.read_bytes()


def test_injected_timestamp_appears_in_output(tmp_path):
    out = tmp_path / "r.json"
    _reporter().export_json(str(out))
    assert json.loads(out.read_text(encoding="utf-8"))["generated"] == "2026-01-01 00:00:00"


# ── Exit codes ───────────────────────────────────────────────────────────────
def test_exit_codes_are_distinct():
    assert len({OK, ERROR, FINDINGS, INCOMPLETE}) == 4
    assert (OK, ERROR, FINDINGS, INCOMPLETE) == (0, 1, 2, 3)


def test_incomplete_detection():
    # A source parsed nothing usable → incomplete.
    assert assessment_is_incomplete(
        {"parse_report": {"counts": {"users": 0, "acls": 0, "computers": 0}}}) is True
    # Real data present → complete.
    assert assessment_is_incomplete(
        {"parse_report": {"counts": {"users": 5, "acls": 0, "computers": 2}}}) is False
    # No parse report (e.g. manual mode) → not flagged incomplete.
    assert assessment_is_incomplete({}) is False


# ── Schema versioning ────────────────────────────────────────────────────────
def test_json_schema_is_versioned_and_has_documented_keys(tmp_path):
    out = tmp_path / "r.json"
    _reporter().export_json(str(out))
    d = json.loads(out.read_text(encoding="utf-8"))
    assert d["schema"] == "horuseye.report/4"
    for key in ("tool", "schema", "generated", "domain", "summary",
                "parse_report", "attack_paths", "exposure", "findings"):
        assert key in d, key


def test_old_schema_reports_still_load():
    # diff.load_previous must read v1 (bare list / no schema) and v2/v3/v4.
    from horuseye.core.diff import load_previous
    import tempfile, os
    for payload in ([{"id": "x", "type": "T", "affected": "A"}],
                    {"schema": "horuseye.report/2", "findings": [{"id": "x"}]},
                    {"schema": "horuseye.report/3", "findings": [{"id": "x"}, {"id": "y"}]},
                    {"schema": "horuseye.report/4", "findings": [{"id": "x"}], "exposure": None}):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(payload).encode()); os.close(fd)
        try:
            assert len(load_previous(path)) >= 1
        finally:
            os.unlink(path)
