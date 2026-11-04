"""Domain exposure: how many users can reach Tier-0, and the fewest changes
that bring it to zero."""
import itertools
import random

from horuseye.core.graph import AttackGraph


def _data(**kw):
    base = {"domain": "CORP.LOCAL", "dc_ip": "10.0.0.5", "users": [], "groups": [],
            "computers": [], "acls": [], "sessions": [], "local_admins": [],
            "delegation_targets": []}
    base.update(kw)
    return base


def _users(*names, **flags):
    return [dict({"name": f"{n}@CORP.LOCAL", "enabled": True}, **flags.get(n, {})) for n in names]


DA = {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True, "members": ["ADMIN@CORP.LOCAL"]}


def test_route_through_a_group_counts_its_members():
    data = _data(users=_users("ADMIN", "BOB", "ALICE", "CAROL", ADMIN={"admincount": True}),
                 groups=[DA, {"name": "HELPDESK@CORP.LOCAL", "members": ["BOB@CORP.LOCAL", "ALICE@CORP.LOCAL"]}],
                 acls=[{"principal": "HELPDESK@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
                        "right": "GenericAll"}])
    x = AttackGraph(data).exposure()
    assert x["users_total"] == 3                    # ADMIN is Tier-0: a target, not exposed
    assert x["users_exposed"] == 2 and x["percent"] == 66.7
    assert x["exposed_users"] == ["ALICE@CORP.LOCAL", "BOB@CORP.LOCAL"]
    plan = x["plan"]
    assert plan["breaks_every_route"] and plan["users_after"] == 0
    assert [c["type"] for c in plan["changes"]] == ["ACL"]      # one change, nearest the target
    assert plan["changes"][0]["users_cut_off"] == 2
    assert x["top_fixes"][0]["users_cut_off"] == 2


def test_a_broad_group_route_exposes_every_user():
    data = _data(users=_users("ADMIN", "U1", "U2", "U3", ADMIN={"admincount": True}),
                 groups=[DA],
                 acls=[{"principal": "DOMAIN USERS@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
                        "right": "WriteDacl"}])
    x = AttackGraph(data).exposure()
    assert x["users_exposed"] == 3 and x["percent"] == 100.0
    assert x["via_broad_groups"] == ["DOMAIN USERS@CORP.LOCAL"]
    assert x["plan"]["changes"][0]["users_cut_off"] == 3


def test_disabled_users_are_not_counted():
    data = _data(users=_users("BOB", "OLD", OLD={"enabled": False}), groups=[DA],
                 acls=[{"principal": "DOMAIN USERS@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
                        "right": "GenericAll"}])
    x = AttackGraph(data).exposure()
    assert x["users_total"] == 1 and x["exposed_users"] == ["BOB@CORP.LOCAL"]


def test_no_route_means_zero_and_no_plan():
    data = _data(users=_users("BOB"), groups=[DA])
    x = AttackGraph(data).exposure()
    assert x["computed"] and x["users_exposed"] == 0 and x["plan"] is None


def test_no_user_list_is_not_computed():
    x = AttackGraph(_data(groups=[DA])).exposure()
    assert x["computed"] is False and x["plan_note"]


def test_unproven_steps_are_not_exposure():
    data = _data(users=_users("BOB"), groups=[DA])
    g = AttackGraph(data)
    g._edge("BOB@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL", "ExecutesAs", "what if", trust="not_assessed")
    assert g.exposure()["users_exposed"] == 0


def test_keep_is_respected_and_reported():
    data = _data(users=_users("BOB"), groups=[DA, {"name": "OPS@CORP.LOCAL", "members": ["BOB@CORP.LOCAL"]}],
                 acls=[{"principal": "OPS@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
                        "right": "GenericAll"}])
    g = AttackGraph(data)
    x = g.exposure(keep=["OPS->DOMAIN ADMINS"])
    assert x["plan"]["changes"][0]["type"] == "MemberOf"          # plans around the kept ACL
    x = AttackGraph(data).exposure(keep=["OPS->DOMAIN ADMINS", "BOB->OPS"])
    assert x["plan"] is None and "--keep" in x["plan_note"]


def test_over_the_change_limit_says_so():
    users = [f"U{i}" for i in range(6)]
    data = _data(users=_users(*users), groups=[DA],
                 acls=[{"principal": f"{u}@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
                        "right": "GenericAll"} for u in users])
    x = AttackGraph(data).exposure(max_changes=3)
    assert x["plan"] is None and "more than 3" in x["plan_note"]
    assert len(AttackGraph(data).exposure()["plan"]["changes"]) == 6


def test_explicit_targets_measure_exposure_to_them():
    data = _data(users=_users("BOB", "ALICE"),
                 acls=[{"principal": "BOB@CORP.LOCAL", "target": "SQL01.CORP.LOCAL", "right": "GenericAll"}])
    x = AttackGraph(data).exposure(targets=["SQL01.CORP.LOCAL"])
    assert x["users_exposed"] == 1 and x["targets"] == ["SQL01.CORP.LOCAL"]


# ── Exactness against brute force on small random domains ───────────────────────
def _random_domain(seed):
    r = random.Random(seed)
    users = [f"U{i}" for i in range(5)]
    groups = [f"G{i}" for i in range(3)]
    data = _data(users=_users(*users), groups=[DA] + [
        {"name": f"{g}@CORP.LOCAL", "members": [f"{u}@CORP.LOCAL" for u in users if r.random() < 0.35]}
        for g in groups])
    pool = [f"{x}@CORP.LOCAL" for x in users + groups]
    hosts = ["H1.CORP.LOCAL", "H2.CORP.LOCAL"]
    for _ in range(r.randint(2, 5)):
        data["acls"].append({"principal": r.choice(pool), "target": r.choice(pool + ["DOMAIN ADMINS@CORP.LOCAL"]),
                             "right": "GenericAll"})
    for _ in range(r.randint(0, 2)):
        data["local_admins"].append({"principal": r.choice(pool), "computer": r.choice(hosts)})
    if r.random() < 0.7:
        data["sessions"].append({"UserName": "ADMIN@CORP.LOCAL", "ComputerName": r.choice(hosts)})
    return data


def _brute(g):
    goals = g.goal_nodes()
    pop = set(g._population(goals, None))
    broad = g._broad_nodes()

    def exposed(banned):
        reach = g._can_reach(goals, banned_edges=banned)
        return pop if any(b in reach for b in broad) else pop & reach
    seen, cands = set(), []
    for edges in g.adj.values():
        for e in edges:
            k = g.edge_key(e)
            if e.src not in goals and k not in seen:
                seen.add(k)
                cands.append(k)
    base = len(exposed(set()))
    best_single = max([base - len(exposed({k})) for k in cands] or [0])
    min_size = None
    if base:
        for size in range(1, len(cands) + 1):
            if any(not exposed(set(c)) for c in itertools.combinations(cands, size)):
                min_size = size
                break
    return base, best_single, min_size


def test_plan_is_minimal_and_top_fix_is_the_best_single_change():
    checked = 0
    for seed in range(60):
        g = AttackGraph(_random_domain(seed))
        base, best_single, min_size = _brute(g)
        x = g.exposure()
        assert x["users_exposed"] == base
        if not base:
            continue
        checked += 1
        assert x["plan"] and len(x["plan"]["changes"]) == min_size, seed
        assert x["plan"]["users_after"] == 0
        if best_single:
            assert x["top_fixes"][0]["users_cut_off"] == best_single, seed
        else:
            assert x["top_fixes"] == []
    assert checked > 20


# ── The bundled exposure demo (examples/karnak-lab) ──────────────────────────────
def test_karnak_lab_tells_the_exposure_story():
    from pathlib import Path
    from horuseye import api
    lab = Path(__file__).resolve().parents[1] / "examples" / "karnak-lab"
    data = api.parse_sources(bloodhound=str(lab), certipy=str(lab / "adcs" / "karnak_Certipy.json"),
                             domain="KARNAK.LAB", dc="10.20.0.10")
    x = AttackGraph(data).exposure()
    assert (x["users_exposed"], x["users_total"], x["percent"]) == (1211, 1211, 100.0)
    steps = x["plan"]["changes"]
    assert [c["type"] for c in steps] == ["ADCS", "HasSession", "DCSync", "ACL"]
    assert [c["users_after"] for c in steps] == [165, 49, 8, 0]
    assert x["top_fixes"][0]["type"] == "ADCS" and x["top_fixes"][0]["users_cut_off"] == 1046
