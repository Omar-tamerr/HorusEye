"""Stage H: the offline interactive explorer — self-contained, correct data."""
import json
import re

from horuseye.reports.explorer import build_explorer, build_graph_view
from horuseye.reports.report_generator import ReportGenerator


def _paths():
    return [{
        "hops": 2, "start": "BOB@CORP.LOCAL", "goal": "DOMAIN ADMINS@CORP.LOCAL",
        "rationale": "2 hops", "inferred_steps": 0,
        "steps": [{"from": "BOB@CORP.LOCAL", "to": "HELPDESK@CORP.LOCAL",
                   "type": "MemberOf", "detail": "member", "trust": "observed"},
                  {"from": "HELPDESK@CORP.LOCAL", "to": "DOMAIN ADMINS@CORP.LOCAL",
                   "type": "ACL", "detail": "GenericAll", "trust": "observed"}],
        "commands": ["# inherit", "certipy shadow auto ..."],
    }]


def _impact():
    return [{"from": "BOB@CORP.LOCAL", "to": "HELPDESK@CORP.LOCAL", "type": "MemberOf",
             "breaks_path": True, "alternative_remains": False},
            {"from": "HELPDESK@CORP.LOCAL", "to": "DOMAIN ADMINS@CORP.LOCAL", "type": "ACL",
             "breaks_path": True, "alternative_remains": False}]


def test_graph_view_nodes_edges_and_chokes():
    g = build_graph_view(_paths(), _impact())
    assert len(g["nodes"]) == 3 and len(g["edges"]) == 2
    kinds = {n["id"]: n["kind"] for n in g["nodes"]}
    assert kinds["BOB@CORP.LOCAL"] == "start"
    assert kinds["DOMAIN ADMINS@CORP.LOCAL"] == "goal"
    assert all(e["choke"] for e in g["edges"])
    # depth increases along the path
    assert kinds and g["nodes"][0]["depth"] == 0


def test_graph_view_empty_is_safe():
    g = build_graph_view([], [])
    assert g == {"nodes": [], "edges": []}


def _findings():
    return [{"id": "a", "type": "DCSYNC", "rule_id": "DCSYNC", "title": "DCSync: x",
             "affected": "HELPDESK@CORP.LOCAL", "severity": "CRITICAL",
             "confidence": "HIGH", "evidence": [{"source": "acl", "object": "y", "detail": "dcsync"}],
             "commands": ["secretsdump"], "remediation": ["remove rights"],
             "detection": ["event 4662"], "mitre": [{"id": "T1003.006", "name": "DCSync"}], "score": 100}]


def test_build_explorer_is_self_contained_and_embeds_data():
    html = build_explorer(_findings(), _paths(), _impact(),
                          {"domain": "CORP.LOCAL", "dc_ip": "1.1.1.1",
                           "parse_report": {"warnings": ["w"], "sources": ["bloodhound"]}},
                          "2026-01-01 00:00:00")
    assert html.startswith("<!DOCTYPE html>")
    # Self-contained: no external resources are fetched at render time (no
    # external <script src>, <link>, or <img src>). User-clicked ATT&CK anchor
    # links to https are fine — they load only on click, not on render.
    assert "<script src" not in html and "<link" not in html
    assert "cdn" not in html.lower()
    assert not re.search(r'<img[^>]+src\s*=\s*"https?://', html)
    # Data round-trips.
    m = re.search(r'<script id="data"[^>]*>(.*?)</script>', html, re.S)
    data = json.loads(m.group(1).replace("<\\/", "</"))
    assert len(data["findings"]) == 1
    assert data["graph"]["edges"] and all(e["choke"] for e in data["graph"]["edges"])
    assert data["meta"]["warnings"] == ["w"]


def test_reporter_export_explorer(tmp_path):
    r = ReportGenerator(_findings(), {"domain": "CORP.LOCAL", "dc_ip": "1.1.1.1"},
                        console=type("Q", (), {"print": lambda *a, **k: None})(),
                        generated_at="2026-01-01 00:00:00")
    r.attack_paths = _paths()
    r.remediation = _impact()
    out = tmp_path / "e.html"
    r.export_explorer(str(out))
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>") and 'id="findings"' in page
