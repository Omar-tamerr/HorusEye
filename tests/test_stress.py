"""Stage G: stress + precision/recall on synthetic domains.

Uses the deterministic generator so results are reproducible and the planted
weaknesses give a ground truth to measure recall against.
"""
import pytest

from horuseye.core.attack_detector import AttackDetector
from horuseye.core.graph import AttackGraph
from horuseye.synthetic import generate_domain


def test_recall_on_planted_findings():
    data, truth = generate_domain(seed=1, users=200, computers=40, groups=15)
    found = {(f["type"], f["affected"]) for f in AttackDetector(data).detect_all()}
    missing = truth - found
    assert not missing, f"detector missed planted findings: {missing}"


def test_precision_no_spurious_criticals():
    # Expected Tier-0 ACEs and SYSTEM noise in the fixture must NOT surface.
    data, _ = generate_domain(seed=2, users=200, computers=40, groups=15)
    findings = AttackDetector(data).detect_all()
    for f in findings:
        if f["type"] == "ACL_ABUSE":
            # No finding should be attributed to a Tier-0 or noise principal.
            assert "DOMAIN ADMINS" not in f["affected"].split("→")[0]
            assert "S-1-5-18" not in f["affected"]


def test_large_graph_completes_and_is_bounded():
    data, _ = generate_domain(seed=3, users=5000, computers=1000, groups=200)
    # Plant a reachable path: a broad group → DA via GenericAll.
    data["groups"].append({"name": "DOMAIN USERS@CORP.LOCAL"})
    data["acls"].append({"principal": "DOMAIN USERS@CORP.LOCAL",
                         "target": "DOMAIN ADMINS@CORP.LOCAL", "right": "GenericAll"})
    paths = AttackGraph(data).shortest_paths(max_paths=3)
    assert paths and len(paths) <= 3


def test_duplicate_relationships_do_not_inflate():
    data, _ = generate_domain(seed=4, users=50, computers=10, groups=5)
    # Duplicate every ACL edge (explicit + inherited).
    dupes = []
    for a in data["acls"]:
        dupes.append(dict(a))
        dupes.append(dict(a, inherited=True))
    data["acls"] = dupes
    findings = AttackDetector(data).detect_all()
    ids = [f["id"] for f in findings]
    assert len(ids) == len(set(ids)), "duplicate ACEs produced duplicate findings"


@pytest.mark.parametrize("bad", [
    {"domain": "X", "acls": [None]},
    {"domain": "X", "acls": [{"principal": None, "target": None, "right": None}]},
    {"domain": "X", "users": [{}], "groups": [{"members": [None]}]},
    {"domain": "X", "sessions": [{}], "local_admins": [{}]},
    {},
])
def test_malformed_input_never_crashes(bad):
    # Detector and graph must degrade gracefully, never raise.
    findings = AttackDetector(bad).detect_all()
    assert isinstance(findings, list)
    assert isinstance(AttackGraph(bad).shortest_paths(), list)


def test_disconnected_graph_has_no_path():
    data, _ = generate_domain(seed=5, users=30, computers=5, groups=3)
    # Strip edges that could connect an ordinary user to Tier-0.
    data["acls"] = [a for a in data["acls"] if "DOMAIN ADMINS" not in a.get("target", "")]
    data["sessions"] = []
    data["local_admins"] = []
    assert AttackGraph(data).shortest_paths(owned=["USER00040@CORP.LOCAL"]) == []
