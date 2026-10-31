"""Remediation options: alternative fix plans that each break every route, with
who loses what access — so the fix can be chosen with the business in mind."""
import json
import os
import re
import subprocess
import sys

from horuseye import api
from horuseye.core.graph import AttackGraph
from horuseye.reports.explorer import build_explorer

BOB = "BOB@CORP.LOCAL"


def _data(**kw):
    base = {"domain": "CORP.LOCAL", "dc_ip": "10.0.0.5", "users": [], "groups": [],
            "computers": [], "acls": [], "sessions": [], "local_admins": [],
            "delegation_targets": []}
    base.update(kw)
    return base


def _helpdesk(**extra):
    # BOB and ALICE are in HELPDESK. HELPDESK can reset SVC's password (SVC can
    # DCSync) and is local admin on WEB01, where a Domain Admin signs in.
    # Two routes from BOB; both start with BOB's HELPDESK membership.
    return _data(
        groups=[{"name": "HELPDESK@CORP.LOCAL", "members": [BOB, "ALICE@CORP.LOCAL"]},
                {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True,
                 "members": ["DA@CORP.LOCAL"]}],
        acls=[{"principal": "HELPDESK@CORP.LOCAL", "target": "SVC@CORP.LOCAL",
               "right": "ForceChangePassword"},
              {"principal": "SVC@CORP.LOCAL", "target": "CORP.LOCAL", "right": "DCSync"}],
        local_admins=[{"principal": "HELPDESK@CORP.LOCAL", "computer": "WEB01.CORP.LOCAL"}],
        sessions=[{"UserName": "DA@CORP.LOCAL", "ComputerName": "WEB01.CORP.LOCAL"}],
        **extra,
    )


def _breaks_every_route(g, plan, owned):
    cut = {(c["from"], c["to"], c["type"], c["detail"]) for c in plan["changes"]}
    keys = {g.edge_key(e) for es in g.adj.values() for e in es
            if (g.display[e.src], g.display[e.dst], e.type, e.detail) in cut}
    assert len(keys) == len(cut)
    starts, goals = g.start_nodes(owned), g.goal_nodes()
    return not g._bfs(starts - goals, goals, set(), banned_edges=keys)


def test_compares_removing_membership_with_narrowing_the_group():
    plans = AttackGraph(_helpdesk()).remediation_plans(owned=[BOB])
    ids = [p["id"] for p in plans]
    assert ids[:2] == ["fewest-changes", "keep-memberships"]

    fewest = plans[0]
    assert [(c["type"], c["from"], c["to"]) for c in fewest["changes"]] == \
        [("MemberOf", BOB, "HELPDESK@CORP.LOCAL")]
    assert fewest["memberships_removed"] == 1
    lost = fewest["changes"][0]
    assert lost["kind"] == "membership" and lost["affects"] == [BOB]
    # BOB loses everything the group grants, and the report says so.
    assert "reset SVC's password" in lost["loses"]
    assert "local admin on WEB01.CORP.LOCAL" in lost["loses"]
    assert "outside Active Directory" in lost["note"]

    narrow = plans[1]
    assert narrow["memberships_removed"] == 0
    assert {c["type"] for c in narrow["changes"]} == {"ForceChangePassword", "AdminTo"}
    for c in narrow["changes"]:
        # Every HELPDESK member loses only that one right.
        assert c["kind"] == "permission" and len(c["loses"]) == 1
        assert set(c["affects"]) == {BOB, "ALICE@CORP.LOCAL"}


def test_every_plan_breaks_every_route():
    g = AttackGraph(_helpdesk())
    plans = g.remediation_plans(owned=[BOB])
    assert len(plans) >= 2
    for p in plans:
        assert p["breaks_every_route"] and _breaks_every_route(g, p, [BOB])


def test_plans_close_routes_that_are_not_displayed():
    # WEB01 also has unconstrained delegation: a second (inferred) way from WEB01
    # to the domain that the displayed routes don't show. Plans must close it.
    data = _helpdesk(computers=[{"name": "WEB01.CORP.LOCAL", "unconstrained_delegation": True}])
    g = AttackGraph(data)
    shown = {e.type for p in g.shortest_paths(owned=[BOB]) for e in p}
    assert "Unconstrained" not in shown
    plans = g.remediation_plans(owned=[BOB])
    assert plans and all(_breaks_every_route(g, p, [BOB]) for p in plans)
    # Cutting only the session off WEB01 would leave the delegation route open.
    for p in plans:
        types = {c["type"] for c in p["changes"]}
        assert not ("HasSession" in types and "AdminTo" not in types
                    and "Unconstrained" not in types)


def test_kept_access_is_never_removed():
    keep = ["bob@corp.local -> HELPDESK@CORP.LOCAL"]          # case and spacing don't matter
    g = AttackGraph(_helpdesk())
    plans = g.remediation_plans(owned=[BOB], keep=keep)
    assert plans
    for p in plans:
        assert not any(c["type"] == "MemberOf" and c["from"] == BOB for c in p["changes"])
        assert _breaks_every_route(g, p, [BOB])
    assert len(plans[0]["changes"]) == 2
    impact = {(h["from"], h["to"]): h for h in g.remediation_impact(owned=[BOB], keep=keep)}
    assert impact[(BOB, "HELPDESK@CORP.LOCAL")]["kept"] is True
    assert impact[(BOB, "HELPDESK@CORP.LOCAL")]["breaks_path"] is True   # still structurally a choke


def test_no_plan_when_kept_access_is_the_only_route():
    data = _data(
        groups=[{"name": "HELPDESK@CORP.LOCAL", "members": [BOB]},
                {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "HELPDESK@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
               "right": "GenericAll"}],
    )
    keep = [f"{BOB}->HELPDESK@CORP.LOCAL", "HELPDESK@CORP.LOCAL->DOMAIN ADMINS@CORP.LOCAL"]
    assert AttackGraph(data).remediation_plans(owned=[BOB], keep=keep) == []
    assert AttackGraph(data).remediation_plans(owned=[BOB], keep=keep[:1])  # one kept: still fixable


def test_no_route_means_no_plans():
    assert AttackGraph(_data()).remediation_plans(owned=[BOB]) == []


def test_duplicate_rows_count_as_one_change():
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": BOB, "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"}] * 3,
    )
    plans = AttackGraph(data).remediation_plans(owned=[BOB])
    assert plans and len(plans[0]["changes"]) == 1


def test_membership_loss_respects_other_memberships():
    # BOB is in G1 and, directly, in G2. Leaving G1 costs G1's rights only.
    data = _data(
        groups=[{"name": "G1@CORP.LOCAL", "members": [BOB]},
                {"name": "G2@CORP.LOCAL", "members": [BOB, "G1@CORP.LOCAL"]}],
        acls=[{"principal": "G2@CORP.LOCAL", "target": "SVC@CORP.LOCAL",
               "right": "ForceChangePassword"}],
        local_admins=[{"principal": "G1@CORP.LOCAL", "computer": "WEB01.CORP.LOCAL"}],
    )
    g = AttackGraph(data)
    edge = next(e for e in g.adj["BOB"] if e.dst == "G1")
    change = g._change(edge)
    assert change["loses"] == ["local admin on WEB01.CORP.LOCAL"]


def test_group_right_affects_nested_members():
    data = _data(
        groups=[{"name": "G1@CORP.LOCAL", "members": [BOB]},
                {"name": "G2@CORP.LOCAL", "members": ["G1@CORP.LOCAL", "ALICE@CORP.LOCAL"]}],
        local_admins=[{"principal": "G2@CORP.LOCAL", "computer": "WEB01.CORP.LOCAL"}],
    )
    g = AttackGraph(data)
    change = g._change(g.adj["G2"][0])
    assert set(change["affects"]) == {BOB, "ALICE@CORP.LOCAL"}
    assert "2 members" in change["effect"]


def test_parse_and_unmatched_keep():
    g = AttackGraph(_helpdesk())
    assert g.parse_keep(["Bob@corp.local->helpdesk", ("BOB", "HELPDESK@X"), "junk"]) == \
        {("BOB", "HELPDESK")}
    assert g.unmatched_keep(["BOB->HELPDESK", "BOB->HELPDSK"]) == [("BOB", "HELPDSK")]


def test_api_exposes_plans():
    data = _helpdesk()
    assert api.remediation_plans(data, owned=[BOB])[0]["id"] == "fewest-changes"
    result = api.analyze(data, owned=[BOB], keep=[f"{BOB}->HELPDESK@CORP.LOCAL"])
    assert result["remediation_plans"]
    assert all(c["type"] != "MemberOf" for p in result["remediation_plans"] for c in p["changes"])


def test_plans_are_deterministic_across_processes():
    # String hashing is randomised per process; plan output must not depend on it.
    code = ("import json,sys;sys.path.insert(0,'.');"
            "from tests.test_remediation_plans import _helpdesk, BOB;"
            "from horuseye.core.graph import AttackGraph;"
            "d=_helpdesk(computers=[{'name':'WEB01.CORP.LOCAL','unconstrained_delegation':True}]);"
            "print(json.dumps(AttackGraph(d).remediation_plans(owned=[BOB])))")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outs = set()
    for seed in ("1", "2", "3"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        outs.add(subprocess.run([sys.executable, "-c", code], cwd=root, env=env,
                                capture_output=True, text=True, check=True).stdout)
    assert len(outs) == 1


def test_explorer_carries_plans_and_option_picker():
    g = AttackGraph(_helpdesk())
    paths = [g.describe(p) for p in g.shortest_paths(owned=[BOB])]
    keep = [f"{BOB}->HELPDESK@CORP.LOCAL"]
    page = build_explorer([], paths, g.remediation_impact(owned=[BOB], keep=keep),
                          _helpdesk(), "2026-01-01",
                          plans=g.remediation_plans(owned=[BOB], keep=keep), keep=keep)
    m = re.search(r'<script id="data"[^>]*>(.*?)</script>', page, re.S)
    data = json.loads(m.group(1).replace("<\\/", "</"))
    assert data["plans"] and data["keep"] == [f"{BOB} → HELPDESK@CORP.LOCAL"]
    assert any(e["kept"] for e in data["graph"]["edges"])
    assert "data-plan" in page and "Compare options" in page
