"""The explorer's live what-if: the embedded graph must give the same exposure
numbers as the engine, before and after cutting relationships."""
import json
import re

from horuseye.core.graph import AttackGraph
from horuseye.reports.explorer import build_explorer


def _data():
    return {
        "domain": "CORP.LOCAL", "dc_ip": "10.0.0.5",
        "users": [{"name": f"{u}@CORP.LOCAL", "enabled": True} for u in ("BOB", "ALICE", "CAROL", "DAVE")]
                 + [{"name": "ADMIN@CORP.LOCAL", "admincount": True, "enabled": True}],
        "groups": [{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True, "members": ["ADMIN@CORP.LOCAL"]},
                   {"name": "HELPDESK@CORP.LOCAL", "members": ["BOB@CORP.LOCAL", "ALICE@CORP.LOCAL"]},
                   {"name": "OPS@CORP.LOCAL", "members": ["CAROL@CORP.LOCAL"]}],
        "computers": [{"name": "WS01.CORP.LOCAL"}],
        "acls": [{"principal": "HELPDESK@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"}],
        "local_admins": [{"principal": "OPS@CORP.LOCAL", "computer": "WS01.CORP.LOCAL"}],
        "sessions": [{"UserName": "ADMIN@CORP.LOCAL", "ComputerName": "WS01.CORP.LOCAL"}],
        "delegation_targets": [],
    }


def _page_data(html):
    m = re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S)
    return json.loads(m.group(1).replace("<\\/", "</"))


def _js_count(xg, cut):
    """Python twin of the page's xState(): reverse search skipping cut edges."""
    radj = {}
    for i, (s, d, _f) in enumerate(xg["edges"]):
        radj.setdefault(d, []).append(i)
    seen, q = set(xg["goals"]), list(xg["goals"])
    while q:
        for i in radj.get(q.pop(), []):
            s = xg["edges"][i][0]
            if i not in cut and s not in seen:
                seen.add(s)
                q.append(s)
    if any(b in seen for b in xg["broad"]):
        return xg["total"]
    return sum(1 for p in xg["pop"] if p in seen)


def _explorer(data):
    g = AttackGraph(data)
    x = g.exposure()
    paths = [g.describe(p) for p in g.shortest_paths(owned=["BOB@CORP.LOCAL"])]
    html = build_explorer([], paths, [], data, "2026-01-01 00:00:00", exposure=x)
    return x, _page_data(html)


def test_explorer_embeds_exposure_and_whatif_graph():
    x, d = _explorer(_data())
    assert d["exposure"]["users_exposed"] == x["users_exposed"] == 3
    assert "exposed_users" not in d["exposure"]            # names come from the graph instead
    assert d["xg"]["total"] == 4
    assert _js_count(d["xg"], set()) == 3


def test_every_change_points_at_its_relationship():
    x, d = _explorer(_data())
    plan = d["exposure"]["plan"]["changes"]
    assert all(c["xi"] is not None for c in plan)
    assert all(c["xi"] is not None for c in d["exposure"]["top_fixes"])
    assert all(e["xi"] is not None for e in d["graph"]["edges"])     # drawn route edges too


def test_cutting_the_plan_in_the_page_reaches_zero_like_the_engine():
    x, d = _explorer(_data())
    xg, cut = d["xg"], set()
    for c in d["exposure"]["plan"]["changes"]:
        cut.add(c["xi"])
        assert _js_count(xg, cut) == c["users_after"]
    assert _js_count(xg, cut) == 0


def test_single_fix_in_the_page_matches_the_engine():
    x, d = _explorer(_data())
    for c in d["exposure"]["top_fixes"]:
        assert _js_count(d["xg"], {c["xi"]}) == c["users_after"]


def test_broad_group_exposure_counts_everyone_in_the_page():
    data = _data()
    data["acls"].append({"principal": "DOMAIN USERS@CORP.LOCAL", "target": "WS01.CORP.LOCAL",
                         "right": "GenericAll"})
    x, d = _explorer(data)
    assert x["users_exposed"] == 4 and _js_count(d["xg"], set()) == 4


def test_no_exposure_no_whatif():
    html = build_explorer([], [], [], {"domain": "X"}, "t")
    d = _page_data(html)
    assert d["exposure"] is None and d["xg"] is None
