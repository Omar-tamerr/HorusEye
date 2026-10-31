"""Attack-path graph: shortest route from a foothold to Domain Admin."""
from horuseye.core.graph import AttackGraph


def _data(**kw):
    base = {"domain": "CORP.LOCAL", "dc_ip": "10.0.0.5", "users": [], "groups": [],
            "computers": [], "acls": [], "sessions": [], "local_admins": [],
            "delegation_targets": []}
    base.update(kw)
    return base


def test_membership_chain_to_domain_admins():
    # BOB -member-> HELPDESK -GenericAll-> DOMAIN ADMINS
    data = _data(
        groups=[{"name": "HELPDESK@CORP.LOCAL", "members": ["BOB@CORP.LOCAL"]},
                {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True, "members": []}],
        acls=[{"principal": "HELPDESK@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
               "right": "GenericAll"}],
    )
    paths = AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"])
    assert paths, "expected a path to Domain Admins"
    types = [e.type for e in paths[0]]
    assert types == ["MemberOf", "ACL"]


def test_session_then_dcsync():
    # Own WS01 (local admin) -> ADMIN has session there -> ADMIN can DCSync
    data = _data(
        local_admins=[{"principal": "BOB@CORP.LOCAL", "computer": "WS01.CORP.LOCAL"}],
        sessions=[{"UserName": "SVC-ADM@CORP.LOCAL", "ComputerName": "WS01.CORP.LOCAL"}],
        acls=[{"principal": "SVC-ADM@CORP.LOCAL", "target": "CORP.LOCAL", "right": "GetChangesAll"},
              {"principal": "SVC-ADM@CORP.LOCAL", "target": "CORP.LOCAL", "right": "GetChanges"}],
    )
    path = AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["AdminTo", "HasSession", "DCSync"]
    assert path[-1].dst == "CORP.LOCAL"


def test_describe_emits_steps_and_commands():
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
               "right": "GenericAll"}],
    )
    g = AttackGraph(data)
    desc = g.describe(g.shortest_paths(owned=["BOB@CORP.LOCAL"])[0])
    assert desc["hops"] == 1
    assert desc["goal"].startswith("DOMAIN ADMINS")
    assert len(desc["steps"]) == len(desc["commands"]) == 1


def test_default_start_is_broad_group():
    # No owned principals: any domain user reaches DA via Domain Users ACL.
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "DOMAIN USERS@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
               "right": "GenericAll"}],
    )
    paths = AttackGraph(data).shortest_paths()
    assert paths and paths[0][0].type == "ACL"


def test_no_path_returns_empty():
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "ALICE@CORP.LOCAL", "right": "GenericAll"}],
    )
    assert AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"]) == []


def test_unconstrained_delegation_reaches_domain():
    data = _data(
        local_admins=[{"principal": "BOB@CORP.LOCAL", "computer": "WEB01.CORP.LOCAL"}],
        computers=[{"name": "WEB01.CORP.LOCAL", "unconstrained_delegation": True}],
    )
    path = AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"])[0]
    assert [e.type for e in path] == ["AdminTo", "Unconstrained"]


def test_alternate_paths_are_node_diverse():
    # Two independent routes BOB -> DA; expect more than one distinct path.
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "G1@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G1@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "BOB@CORP.LOCAL", "target": "G2@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G2@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"}],
    )
    paths = AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"], max_paths=3)
    middles = {tuple(e.dst for e in p) for p in paths}
    assert len(middles) >= 2


# ── Stage C: trust labels, targets, ranking, remediation impact ──────────────
def test_edges_labeled_observed_or_inferred():
    data = _data(
        local_admins=[{"principal": "BOB@CORP.LOCAL", "computer": "WEB01.CORP.LOCAL"}],
        computers=[{"name": "WEB01.CORP.LOCAL", "unconstrained_delegation": True}],
    )
    desc = AttackGraph(data).describe(AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"])[0])
    trust = {s["type"]: s["trust"] for s in desc["steps"]}
    assert trust["AdminTo"] == "observed"
    assert trust["Unconstrained"] == "inferred"
    assert desc["inferred_steps"] == 1
    assert "inferred" in desc["rationale"]


def test_configurable_target_other_than_tier0():
    # BOB can take over a non-Tier-0 "crown jewel" server via GenericAll.
    data = _data(acls=[{"principal": "BOB@CORP.LOCAL", "target": "FILESERVER@CORP.LOCAL",
                        "right": "GenericAll"}])
    g = AttackGraph(data)
    paths = g.shortest_paths(owned=["BOB@CORP.LOCAL"], targets=["FILESERVER@CORP.LOCAL"])
    assert paths and g.describe(paths[0])["goal"] == "FILESERVER@CORP.LOCAL"


def test_fully_observed_path_ranks_before_inferred():
    # Two routes to DA: one all-observed (2 hops), one with an inferred hop (2 hops).
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "G1@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G1@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"}],
        local_admins=[{"principal": "BOB@CORP.LOCAL", "computer": "WEB01@CORP.LOCAL"}],
        computers=[{"name": "WEB01@CORP.LOCAL", "unconstrained_delegation": True}],
    )
    paths = AttackGraph(data).shortest_paths(owned=["BOB@CORP.LOCAL"], max_paths=5)
    # The first ranked path must have no inferred edges.
    assert all(e.trust == "observed" for e in paths[0])


def test_remediation_impact_flags_choke_point():
    # Single linear path BOB → HELPDESK → DA: both edges are choke points.
    data = _data(
        groups=[{"name": "HELPDESK@CORP.LOCAL", "members": ["BOB@CORP.LOCAL"]},
                {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "HELPDESK@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL",
               "right": "GenericAll"}],
    )
    impact = AttackGraph(data).remediation_impact(owned=["BOB@CORP.LOCAL"])
    assert impact and all(h["breaks_path"] for h in impact)
    assert any(h["type"] == "ACL" for h in impact)


def test_remediation_impact_sees_alternative():
    # Two independent routes: removing one node leaves the other.
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "G1@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G1@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "BOB@CORP.LOCAL", "target": "G2@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G2@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"}],
    )
    impact = AttackGraph(data).remediation_impact(owned=["BOB@CORP.LOCAL"])
    # The intermediate group on the chosen path has an alternative via the other.
    assert any(h["alternative_remains"] for h in impact)


# ── Remediation impact: remove the edge, not the node ────────────────────────
def test_second_route_into_same_node_is_not_a_choke_point():
    # BOB→G1→X→DA and BOB→G2→X→DA. Removing the single edge G1→X leaves G2→X,
    # so it is NOT a choke point. (The old node-ban logic wrongly said it was.)
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "G1@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "BOB@CORP.LOCAL", "target": "G2@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G1@CORP.LOCAL", "target": "X@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G2@CORP.LOCAL", "target": "X@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "X@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"}],
    )
    impact = {(h["from"], h["to"]): h for h in
              AttackGraph(data).remediation_impact(owned=["BOB@CORP.LOCAL"])}
    into_x = [h for (f, t), h in impact.items() if t == "X@CORP.LOCAL"]
    assert into_x and all(h["alternative_remains"] for h in into_x)
    # The last hop X→DA is the only way in, so it IS a choke point.
    assert impact[("X@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL")]["breaks_path"]


def test_parallel_rights_are_separate_edges():
    # BOB has GenericAll AND WriteDacl on DA: removing one right leaves the other.
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "BOB@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "WriteDacl"}],
    )
    impact = AttackGraph(data).remediation_impact(owned=["BOB@CORP.LOCAL"])
    assert impact and all(h["alternative_remains"] for h in impact)


def test_impact_covers_every_displayed_path():
    data = _data(
        groups=[{"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True}],
        acls=[{"principal": "BOB@CORP.LOCAL", "target": "G1@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G1@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "BOB@CORP.LOCAL", "target": "G2@CORP.LOCAL", "right": "GenericAll"},
              {"principal": "G2@CORP.LOCAL", "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"}],
    )
    g = AttackGraph(data)
    path_edges = {(g.display[e.src], g.display[e.dst])
                  for p in g.shortest_paths(owned=["BOB@CORP.LOCAL"]) for e in p}
    impact_edges = {(h["from"], h["to"]) for h in g.remediation_impact(owned=["BOB@CORP.LOCAL"])}
    assert path_edges and path_edges == impact_edges
