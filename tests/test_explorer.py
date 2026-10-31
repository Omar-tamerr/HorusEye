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
    assert "<script src" not in html
    assert not re.search(r'<link[^>]+href\s*=\s*"https?://', html)   # favicon is an inline data: URI
    assert "cdn" not in html.lower()
    assert not re.search(r'<img[^>]+src\s*=\s*"https?://', html)
    # A normal report never carries the website's demo extras.
    assert 'class="demobar"' not in html and "og:image" not in html
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
    assert page.startswith("<!DOCTYPE html>") and 'id="v-findings"' in page


# ── Upgraded attack-path view ────────────────────────────────────────────────
def _two_routes():
    return [
        {"hops": 2, "start": "BOB@CORP.LOCAL", "goal": "CORP.LOCAL", "rationale": "r1", "inferred_steps": 0,
         "steps": [{"from": "BOB@CORP.LOCAL", "to": "HELPDESK@CORP.LOCAL", "type": "MemberOf", "detail": "member of group", "trust": "observed"},
                   {"from": "HELPDESK@CORP.LOCAL", "to": "CORP.LOCAL", "type": "DCSync", "detail": "replicate", "trust": "observed"}],
         "commands": ["# inherit", "impacket-secretsdump CORP.LOCAL/USER@DC -just-dc"]},
        {"hops": 2, "start": "BOB@CORP.LOCAL", "goal": "ADMINISTRATOR@CORP.LOCAL", "rationale": "r2", "inferred_steps": 0,
         "steps": [{"from": "BOB@CORP.LOCAL", "to": "WEB01.CORP.LOCAL", "type": "AdminTo", "detail": "local administrator", "trust": "observed"},
                   {"from": "WEB01.CORP.LOCAL", "to": "ADMINISTRATOR@CORP.LOCAL", "type": "HasSession", "detail": "creds", "trust": "observed"}],
         "commands": ["nxc smb WEB01 -u USER -p PASS --sam", "# dump\nnxc smb WEB01 --lsa"]},
    ]


_DOMAIN = {"domain": "CORP.LOCAL",
           "users": [{"name": "BOB@CORP.LOCAL"}, {"name": "ADMINISTRATOR@CORP.LOCAL"}],
           "groups": [{"name": "HELPDESK@CORP.LOCAL"}],
           "computers": [{"name": "WEB01.CORP.LOCAL"}]}


def test_graph_view_node_types_labels_and_route_membership():
    g = build_graph_view(_two_routes(), [], _DOMAIN)
    by = {n["id"]: n for n in g["nodes"]}
    assert by["BOB@CORP.LOCAL"]["otype"] == "user" and by["BOB@CORP.LOCAL"]["paths"] == [0, 1]
    assert by["HELPDESK@CORP.LOCAL"]["otype"] == "group"
    assert by["WEB01.CORP.LOCAL"]["otype"] == "computer"
    assert by["WEB01.CORP.LOCAL"]["label"] == "WEB01"          # host name, not FQDN
    assert by["CORP.LOCAL"]["otype"] == "domain"
    edges = {(e["from"], e["type"]): e for e in g["edges"]}
    assert edges[("BOB@CORP.LOCAL", "AdminTo")]["paths"] == [1]
    # full multi-line command is kept (walkthrough shows notes + commands)
    assert "--lsa" in edges[("WEB01.CORP.LOCAL", "HasSession")]["command"]


def test_graph_view_impact_unknown_is_none_not_false():
    g = build_graph_view(_two_routes(), [], _DOMAIN)
    assert all(e["alt"] is None and e["choke"] is False for e in g["edges"])


def test_demo_mode_adds_site_extras_only_when_requested():
    demo = {"home_url": "./", "install_url": "./#install", "repo_url": "https://github.com/x/y",
            "page_url": "https://example.test/demo.html", "og_image": "https://example.test/og.png",
            "default_view": "paths"}
    page = build_explorer(_findings(), _two_routes(), [], _DOMAIN, "2026-01-01", demo=demo)
    assert 'class="demobar"' in page and 'href="./"' in page
    assert 'property="og:image" content="https://example.test/og.png"' in page
    assert 'name="twitter:card" content="summary_large_image"' in page
    m = re.search(r'<script id="data"[^>]*>(.*?)</script>', page, re.S)
    assert json.loads(m.group(1).replace("<\\/", "</"))["default_view"] == "paths"


def test_user_strings_cannot_break_out_of_the_page():
    # A hostile object name must stay inert inside the embedded JSON.
    evil = "</script><script>alert(1)</script>@CORP.LOCAL"
    paths = [{"hops": 1, "start": evil, "goal": "CORP.LOCAL", "rationale": "", "inferred_steps": 0,
              "steps": [{"from": evil, "to": "CORP.LOCAL", "type": "DCSync", "detail": "x", "trust": "observed"}],
              "commands": [""]}]
    page = build_explorer([], paths, [], {"domain": "CORP.LOCAL"}, "2026-01-01")
    assert "</script><script>alert(1)" not in page
