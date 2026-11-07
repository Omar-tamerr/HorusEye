"""Report exports: HTML / Markdown / JSON must carry findings, attack paths,
remediation and ATT&CK, and stay valid."""
import json

from horuseye.core.knowledge import enrich
from horuseye.reports.report_generator import ReportGenerator


def _reporter():
    findings = enrich([
        {"type": "DCSYNC", "title": "DCSync rights: HELPDESK", "affected": "HELPDESK@CORP.LOCAL",
         "severity": "CRITICAL", "score": 100, "description": "Can replicate secrets.",
         "commands": ["impacket-secretsdump CORP/HELPDESK@DC -just-dc"]},
        {"type": "KERBEROASTING", "title": "Kerberoastable: svc", "affected": "SVC@CORP.LOCAL",
         "severity": "HIGH", "score": 52, "commands": ["impacket-GetUserSPNs ..."]},
    ])
    r = ReportGenerator(findings, {"domain": "CORP.LOCAL", "dc_ip": "10.0.0.5"})
    r.attack_paths = [{
        "hops": 2, "start": "BOB@CORP.LOCAL", "goal": "DOMAIN ADMINS@CORP.LOCAL",
        "steps": [{"from": "BOB@CORP.LOCAL", "to": "HELPDESK@CORP.LOCAL", "type": "MemberOf", "detail": "member"},
                  {"from": "HELPDESK@CORP.LOCAL", "to": "DOMAIN ADMINS@CORP.LOCAL", "type": "ACL", "detail": "GenericAll"}],
        "commands": ["# inherit", "certipy shadow auto ..."],
    }]
    return r


def test_json_export_schema(tmp_path):
    out = tmp_path / "r.json"
    _reporter().export_json(str(out))
    d = json.loads(out.read_text(encoding="utf-8"))
    assert d["schema"] == "horuseye.report/4"
    assert d["summary"]["by_severity"]["CRITICAL"] == 1
    assert d["summary"]["mitre"]                      # aggregated techniques
    assert len(d["attack_paths"]) == 1
    assert d["findings"][0]["remediation"]            # enrichment survived


def test_markdown_has_mermaid_and_sections(tmp_path):
    out = tmp_path / "r.md"
    _reporter().export_markdown(str(out))
    md = out.read_text(encoding="utf-8")
    assert "```mermaid" in md and "graph LR" in md
    assert "Attack Paths to Domain Admin" in md
    assert "**What to do:**" in md       # remediation now lives in the finding card's "What to do"
    assert "-->|MemberOf|" in md


def test_html_is_self_contained_and_escaped(tmp_path):
    findings = enrich([{"type": "ACL_ABUSE", "title": "x <script>alert(1)</script>",
                        "affected": "A&B", "severity": "HIGH", "commands": []}])
    r = ReportGenerator(findings, {"domain": "corp", "dc_ip": "1.1.1.1"})
    out = tmp_path / "r.html"
    r.export_html(str(out))
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "<script>alert(1)</script>" not in page       # escaped
    assert "&lt;script&gt;" in page
    assert "MITRE ATT&amp;CK Coverage" in page


def test_cli_report_runs_without_console():
    # No rich console attached → plain path must not raise.
    ReportGenerator(_reporter().findings, {"domain": "x"}, console=False)._print_plain(
        _reporter().findings)
