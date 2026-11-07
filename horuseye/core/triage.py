"""
HorusEye: remediation triage: what is most critical that is an easy fix, and
what are the options?

For every finding this adds, without touching severity:

* ``rel_ids``        stable ids of the attack-graph relationships it names
* ``impact``         users cut off from Tier-0 if it is fixed, and whether it
                     is on a route at all (or, for account findings, whether
                     that account reaches Tier-0 if compromised)
* ``why_critical``   that impact in one sentence
* ``effort`` / ``effort_reason`` / ``effort_rule``   from ``core/effort.py``
* ``fix_options``    the fixes, each with its own effort, plus the ``--keep``
                     alternative when one exists
* ``source``         where the finding came from (file, collector, object, SID)
* ``quick_win``      severity Critical or High AND effort Low

``quick_wins()`` ranks Quick Wins by users cut off, then users with a route
through it, then whether it is on a route, then score, so the first one is the
best to do today.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

from horuseye.core.effort import EffortContext, rate_changes, rate_finding
from horuseye.core.principals import norm

QUICK_WIN_SEVERITIES = ("CRITICAL", "HIGH")
_ACCOUNT_TYPES = {"KERBEROASTING", "ASREP_ROASTING", "STALE_ADMIN"}


def _pairs(f: Dict):
    """(src, dst, detail) for evidence objects written ``A → B``."""
    for ev in f.get("evidence") or []:
        obj = str(ev.get("object") or "")
        if "→" in obj:
            a, b = (p.strip() for p in obj.split("→", 1))
            yield norm(a), norm(b), str(ev.get("detail") or "")


def linked_edges(f: Dict, graph) -> List:
    """The graph relationships a finding is about, read from its evidence."""
    t = f.get("type", "")
    out = []
    if t == "PRIVILEGED_SESSION":
        for ev in f.get("evidence") or []:
            if str(ev.get("detail")) != "HasSession":
                continue
            parts = str(ev.get("object") or "").split("@")
            if len(parts) >= 2:
                host, user = norm(parts[-1]), norm(parts[0])
                out += [e for e in graph.adj.get(host, []) if e.type == "HasSession" and e.dst == user]
    elif t in ("UNCONSTRAINED_DELEGATION", "CONSTRAINED_DELEGATION"):
        want = "Unconstrained" if t == "UNCONSTRAINED_DELEGATION" else "ConstrainedDeleg"
        out = [e for e in graph.adj.get(norm(f.get("affected", "")), []) if e.type == want]
    elif t == "ADCS_ESC":
        tmpl = str(f.get("affected", "")).upper()
        for edges in graph.adj.values():
            for e in edges:
                meta = graph.meta.get(graph.edge_key(e), {}) if hasattr(graph, "meta") else {}
                if e.type == "ADCS" and tmpl and tmpl in (str(meta.get("template", "")).upper(),
                                                          str(meta.get("ca", "")).upper()):
                    out.append(e)
    else:
        types = {"DCSYNC": {"DCSync"}, "PASS_THE_HASH": {"AdminTo"}}.get(t)
        for src, dst, _detail in _pairs(f):
            out += [e for e in graph.adj.get(src, []) if e.dst == dst and (not types or e.type in types)]
    seen, uniq = set(), []
    for e in out:
        k = graph.edge_key(e)
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    return uniq


def _source(f: Dict, sids: Dict[str, str]) -> List[Dict]:
    out, seen = [], set()
    for ev in f.get("evidence") or []:
        key = (ev.get("source"), ev.get("file"), ev.get("object"))
        if key in seen:
            continue
        seen.add(key)
        obj = str(ev.get("object") or "")
        sid = sids.get(norm(obj.split("→")[0].strip())) if obj else None
        out.append({k: v for k, v in (("collector", ev.get("source")), ("file", ev.get("file")),
                                      ("object", obj), ("sid", sid)) if v})
        if len(out) >= 20:
            break
    return out


def triage(findings: List[Dict], domain_data: Dict, graph, exposure: Optional[Dict] = None,
           targets: Optional[List[str]] = None, keep: Optional[List[str]] = None) -> List[Dict]:
    """Annotate findings in place (see module docstring). Returns the Quick
    Wins, ranked. Severity is never read for anything but the Quick Win test,
    and never written."""
    ctx = EffortContext(domain_data, graph)
    sids = {norm(u.get("name", "")): u["sid"] for u in domain_data.get("users") or []
            if isinstance(u, dict) and u.get("sid")}
    goal = ", ".join((exposure or {}).get("targets") or ["Tier-0"])
    kept = graph.parse_keep(keep)

    linked = {f["id"]: linked_edges(f, graph) for f in findings if f.get("id")}
    counts = graph.cut_off_counts({fid: {graph.edge_key(e) for e in es}
                                   for fid, es in linked.items()}, targets=targets)

    # Fix options from the exposure plan / biggest fixes, by relationship id.
    plan_by_id: Dict[str, Dict] = {}
    for c in ((exposure or {}).get("plan") or {}).get("changes", []) + list((exposure or {}).get("top_fixes") or []):
        plan_by_id.setdefault(c.get("id"), c)

    for f in findings:
        fid = f.get("id")
        edges = linked.get(fid, [])
        changes = [dict(graph._change(e), id=graph.rel_id(e)) for e in edges]
        f["rel_ids"] = [c["id"] for c in changes]
        imp = dict(counts.get(fid) or {"users_cut_off": 0, "on_route": False,
                                       "users_exposed": (exposure or {}).get("users_exposed", 0)})
        imp["relationships"] = len(edges)
        if not edges and f.get("type") in _ACCOUNT_TYPES and f.get("affected"):
            paths = graph.shortest_paths(owned=[f["affected"]], targets=targets, max_paths=1)
            imp["account_reaches_target"] = bool(paths)
            imp["account_hops"] = len(paths[0]) if paths else None
        f["impact"] = imp
        f["why_critical"] = _why(f, imp, goal)

        e = rate_finding(f, changes, ctx)
        f["effort"], f["effort_reason"], f["effort_rule"] = e["level"], e["reason"], e["rule"]

        opts = []
        for c in rate_changes(changes[:5], ctx):
            p = plan_by_id.get(c["id"]) or {}
            opts.append({"fix": c.get("fix", ""), "effect": c.get("effect", ""),
                         "effort": c["effort"], "effort_reason": c["effort_reason"],
                         "users_cut_off": p.get("users_cut_off"), "id": c["id"],
                         "kept": (norm(c.get("from", "")), norm(c.get("to", ""))) in kept})
        if len(changes) > 5:
            opts.append({"fix": f"…and {len(changes) - 5} more of the same kind.", "effort": e["level"],
                         "effort_reason": "", "id": None})
        f["fix_options"] = opts
        alt = None
        # The --keep alternative matters when the fix this finding names is
        # part of the recommended plan, or cuts users off on its own.
        in_plan = any(c["id"] in plan_by_id for c in changes)
        if edges and (imp["users_cut_off"] or in_plan):
            protect: Set[tuple] = {graph.edge_key(x) for x in edges}
            cut = graph.alternative_fix(protect, targets=targets)
            if cut:
                rate_changes(cut, ctx)
                a, b = edges[0].src, edges[0].dst
                alt = {"keep": f"{graph.display.get(a, a)}->{graph.display.get(b, b)}",
                       "changes": [{"fix": c.get("fix", ""), "effort": c["effort"], "id": c["id"]}
                                   for c in cut]}
        f["keep_alternative"] = alt
        f["source"] = _source(f, sids)
        f["quick_win"] = (str(f.get("severity", "")).upper() in QUICK_WIN_SEVERITIES
                          and f["effort"] == "Low")
    return quick_wins(findings)


def quick_wins(findings: List[Dict]) -> List[Dict]:
    """Quick Wins (Critical or High, Low effort), best first: users cut off,
    then users with a route through it, then on a route at all, then score,
    then id (stable)."""
    wins = [f for f in findings if f.get("quick_win")]
    wins.sort(key=lambda f: (-(f.get("impact") or {}).get("users_cut_off", 0),
                             -(f.get("impact") or {}).get("users_through", 0),
                             not (f.get("impact") or {}).get("on_route", False),
                             -(f.get("score") or 0), str(f.get("id", ""))))
    for i, f in enumerate(wins, 1):
        f["quick_win_rank"] = i
    return wins


def _why(f: Dict, imp: Dict, goal: str) -> str:
    n, total = imp.get("users_cut_off", 0), imp.get("users_exposed", 0)
    if n:
        return (f"Fixing this alone cuts {n:,} of {total:,} exposed users off from {goal}."
                if total else f"Fixing this alone cuts {n:,} users off from {goal}.")
    if imp.get("relationships") and imp.get("on_route"):
        through = imp.get("users_through", 0)
        who = f"{through:,} user{'s' if through != 1 else ''}" if through else "users"
        return (f"On routes to {goal} for {who}; each has another route, so fixing it alone "
                f"cuts no one off. Combine it with the exposure plan.")
    if imp.get("relationships"):
        return f"Not on any current route to {goal}; fix it so it can't become one."
    acct = str(f.get("affected", "")).split("@")[0]
    if imp.get("account_reaches_target"):
        hops = imp.get("account_hops")
        return f"If {acct} is compromised, it reaches {goal} in {hops} step{'s' if hops != 1 else ''}."
    if "account_reaches_target" in imp:
        return f"If {acct} is compromised, no route to {goal} was found in the data; the risk is the account itself."
    desc = str(f.get("description") or "").strip()
    first = desc.split(". ")[0].rstrip(".") + "." if desc else ""
    return f"Not a step in the attack graph. {first}".strip()
