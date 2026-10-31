"""
HorusEye — Attack-path graph engine.

BloodHound shows you the graph; this tells you the order to walk it. We build a
directed *control* graph where an edge ``A -> B`` means "control of A yields
control of B", then BFS from a foothold to the nearest target and return the
ordered steps — each with the command that advances it, the evidence behind it,
and whether the relationship is observed or inferred.

Edge sources (all from data the parsers already produce):
  MemberOf            member  -> group            (inherit the group's rights)
  ACL takeover        principal -> object         (GenericAll/WriteDacl/...)
  ForceChangePassword principal -> user           (reset the password)
  AddMember/AddSelf   principal -> group          (add yourself)
  AdminTo             principal -> computer        (local administrator)
  HasSession          computer -> user            (creds cached in memory)
  DCSync              principal -> <domain>        (replicate secrets)
  Unconstrained deleg computer -> <domain>         (coerce a DC — INFERRED)
  ConstrainedDeleg    principal -> target          (S4U impersonation — INFERRED)

Trust tiers
-----------
``observed`` — the edge is a relationship read directly from the data.
``inferred`` — the edge requires an additional abuse step (coercion, S4U) that
               the data makes *possible* but does not prove.

Nodes are identified by normalized name (upper-case, no @domain). Pathfinding is
deterministic and never consults an LLM.
"""
from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set

from horuseye.core.principals import BROAD_NAMES, PrincipalIndex, norm, short

# ACL rights that amount to taking control of the target object.
_TAKEOVER_RIGHTS = {
    "genericall", "genericwrite", "writedacl", "writeowner", "owns",
    "allextendedrights", "addkeycredentiallink", "writespn",
}
_RIGHT_NAMES = {
    "genericall": "GenericAll", "genericwrite": "GenericWrite", "writedacl": "WriteDacl",
    "writeowner": "WriteOwner", "owns": "Owns", "allextendedrights": "AllExtendedRights",
    "addkeycredentiallink": "AddKeyCredentialLink", "writespn": "WriteSPN",
}

_INFERRED_TYPES = {"Unconstrained", "ConstrainedDeleg"}

# Remediation plan strategies, in presentation order: (id, title, summary).
_PLAN_STRATEGIES = (
    ("fewest-changes", "Fewest changes",
     "The smallest set of changes that breaks every route."),
    ("keep-memberships", "Keep group memberships",
     "Narrow what the groups are allowed to do instead of removing anyone from them."),
    ("nearest-targets", "Fix nearest the targets",
     "Cut the steps closest to the targets, so the foothold and its groups keep "
     "as much of their access as possible."),
)
_SOURCE, _SINK = ("<source>",), ("<sink>",)    # flow-network terminals; never a node name


class Edge:
    __slots__ = ("src", "dst", "type", "detail", "trust")

    def __init__(self, src: str, dst: str, etype: str, detail: str = "",
                 trust: str = "observed"):
        self.src, self.dst, self.type, self.detail, self.trust = src, dst, etype, detail, trust


class AttackGraph:
    def __init__(self, domain_data: Dict):
        self.data = domain_data or {}
        self.idx = PrincipalIndex(self.data)
        self.domain_node = norm(self.data.get("domain", "") or "DOMAIN")
        self.adj: Dict[str, List[Edge]] = {}
        self.display: Dict[str, str] = {}      # node -> best display name
        self.is_computer: Set[str] = set()
        self._members_of: Optional[Dict[str, Set[str]]] = None   # group -> direct members, lazily
        self._build()

    # ── Construction ────────────────────────────────────────────────────────
    def _node(self, name: str, computer: bool = False) -> str:
        n = norm(name)
        cur = self.display.get(n)
        if cur is None or ("@" in (name or "") and "@" not in cur):
            self.display[n] = name or n
        if computer:
            self.is_computer.add(n)
        return n

    def _edge(self, src: str, dst: str, etype: str, detail: str = "",
              src_is_computer: bool = False, dst_is_computer: bool = False):
        s = self._node(src, src_is_computer)
        d = self._node(dst, dst_is_computer)
        if s and d and s != d:
            trust = "inferred" if etype in _INFERRED_TYPES else "observed"
            self.adj.setdefault(s, []).append(Edge(s, d, etype, detail, trust))

    @staticmethod
    def _dicts(seq):
        """Yield only dict entries — malformed rows (None, strings) are skipped
        so a single bad record can't crash graph construction."""
        for x in seq or []:
            if isinstance(x, dict):
                yield x

    def _build(self):
        d = self.data
        for g in self._dicts(d.get("groups")):
            gname = g.get("name", "")
            for m in g.get("members", []) or []:
                if m:
                    self._edge(m, gname, "MemberOf", "member of group")

        for ace in self._dicts(d.get("acls")):
            right = (ace.get("right", "") or "").strip().lower()
            principal, target = ace.get("principal", ""), ace.get("target", "")
            if not principal or not target:
                continue
            if self.idx.classify(principal) == "noise":
                continue
            if right == "forcechangepassword":
                self._edge(principal, target, "ForceChangePassword", "reset password")
            elif right in ("addmember", "addself"):
                self._edge(principal, target, "AddMember", "add to group")
            elif right in _TAKEOVER_RIGHTS:
                self._edge(principal, target, "ACL", f"{right} → object takeover")

        for la in self._dicts(d.get("local_admins")):
            p, host = la.get("principal", ""), la.get("computer", "")
            if p and host and self.idx.classify(p) != "noise":
                self._edge(p, host, "AdminTo", "local administrator",
                           dst_is_computer=True)

        for s in self._dicts(d.get("sessions")):
            user = s.get("UserName", "") or s.get("user", "")
            host = s.get("ComputerName", "") or s.get("ip", "")
            if user and host:
                self._edge(host, user, "HasSession", "credentials in memory",
                           src_is_computer=True)

        for ace in self._dicts(d.get("acls")):
            right = (ace.get("right", "") or "").strip().lower()
            if right in ("dcsync", "getchangesall", "all"):
                p = ace.get("principal", "")
                if p and not self.idx.is_expected_replicator(p):
                    self._edge(p, self.domain_node, "DCSync", "replicate domain secrets")

        for c in self._dicts(d.get("computers")):
            if c.get("unconstrained_delegation"):
                self._edge(c.get("name", ""), self.domain_node, "Unconstrained",
                           "coerce a DC, capture its TGT", src_is_computer=True)
        for dt in self._dicts(d.get("delegation_targets")):
            self._edge(dt.get("principal", ""), dt.get("target", ""),
                       "ConstrainedDeleg", "S4U impersonation")

    # ── Goal / start sets ─────────────────────────────────────────────────────
    def _all_nodes(self) -> Set[str]:
        return self.adj.keys() | {e.dst for edges in self.adj.values() for e in edges}

    def goal_nodes(self, targets: Optional[List[str]] = None) -> Set[str]:
        """Default goals are Tier-0 (+ the domain). ``targets`` overrides with an
        explicit set of critical assets (matched by normalized name)."""
        if targets:
            # Explicit critical assets; a target absent from the graph simply
            # yields no path rather than an error.
            return {norm(t) for t in targets if t}
        goals = {self.domain_node}
        for n in self._all_nodes():
            if self.idx.is_tier0_target(self.display.get(n, n)):
                goals.add(n)
        return goals

    def start_nodes(self, owned: Optional[List[str]] = None) -> Set[str]:
        if owned:
            return {norm(o) for o in owned if o}
        nodes = self._all_nodes()
        return {n for n in nodes if norm(self.display.get(n, n)) in BROAD_NAMES}

    # ── Pathfinding ────────────────────────────────────────────────────────────
    def shortest_paths(self, owned: Optional[List[str]] = None,
                       max_paths: int = 5,
                       targets: Optional[List[str]] = None) -> List[List[Edge]]:
        """Up to ``max_paths`` short, node-diverse paths from the start set to the
        nearest goal. ``targets`` overrides the default Tier-0 goals."""
        starts, goals = self.start_nodes(owned), self.goal_nodes(targets)
        if not starts or not goals:
            return []
        starts = {s for s in starts if s not in goals}
        paths, banned = [], set()
        for _ in range(max_paths):
            path = self._bfs(starts, goals, banned)
            if not path:
                break
            paths.append(path)
            intermediates = [e.dst for e in path[:-1]]
            if not intermediates:
                break
            banned.add(intermediates[len(intermediates) // 2])
        # Rank: fewer hops first, then fewer inferred edges, then stable by names.
        paths.sort(key=self._rank_key)
        return paths

    def _rank_key(self, path: List[Edge]):
        inferred = sum(1 for e in path if e.trust == "inferred")
        names = "→".join(e.dst for e in path)
        return (len(path), inferred, names)

    @staticmethod
    def edge_key(e: Edge) -> tuple:
        """Identity of one relationship: who, to whom, what kind, which right.
        Parallel edges (e.g. GenericAll and WriteDacl on the same object) stay
        distinct, so removing one doesn't silently remove the other."""
        return (e.src, e.dst, e.type, e.detail)

    def _bfs(self, starts: Set[str], goals: Set[str], banned: Set[str],
             banned_edges: Optional[Set[tuple]] = None) -> List[Edge]:
        banned_edges = banned_edges or set()
        q = deque()
        seen = set()
        for s in sorted(starts):          # sorted → deterministic across runs
            if s not in banned:
                q.append(s)
                seen.add(s)
        prev: Dict[str, Edge] = {}
        while q:
            node = q.popleft()
            if node in goals:
                return self._reconstruct(node, prev)
            for e in self.adj.get(node, []):
                if banned_edges and self.edge_key(e) in banned_edges:
                    continue              # this one relationship is removed
                if e.dst in seen or e.dst in banned:
                    continue
                seen.add(e.dst)
                prev[e.dst] = e
                q.append(e.dst)
        return []

    def _reconstruct(self, goal: str, prev: Dict[str, Edge]) -> List[Edge]:
        path, node = [], goal
        while node in prev:
            e = prev[node]
            path.append(e)
            node = e.src
        return list(reversed(path))

    # ── Remediation impact ─────────────────────────────────────────────────────
    def remediation_impact(self, owned: Optional[List[str]] = None,
                           targets: Optional[List[str]] = None,
                           max_paths: int = 5,
                           keep: Optional[List[str]] = None) -> List[Dict]:
        """For every edge on the displayed attack paths, remove just that one
        relationship and check whether the foothold can still reach *any*
        target. If it can't, the edge is a choke point — a single fix that
        breaks every route. Otherwise an alternative path remains.

        Only the edge itself is removed (not the node it points to), so a
        second route into the same object is correctly counted as an
        alternative. Returns ``[{from, to, type, detail, breaks_path,
        alternative_remains, kept}]`` in path order; empty if there is no
        path. ``kept`` marks relationships the business needs (``keep``)."""
        starts, goals = self.start_nodes(owned), self.goal_nodes(targets)
        paths = self.shortest_paths(owned=owned, max_paths=max_paths, targets=targets)
        if not paths:
            return []
        starts = {s for s in starts if s not in goals}
        kept = self.parse_keep(keep)
        out, done = [], set()
        for path in paths:
            for e in path:
                key = self.edge_key(e)
                if key in done:
                    continue
                done.add(key)
                remains = bool(self._bfs(starts, goals, set(), banned_edges={key}))
                out.append({
                    "from": self.display.get(e.src, e.src),
                    "to": self.display.get(e.dst, e.dst),
                    "type": e.type,
                    "detail": e.detail,
                    "breaks_path": not remains,
                    "alternative_remains": remains,
                    "kept": (e.src, e.dst) in kept,
                })
        return out

    # ── Remediation plans ──────────────────────────────────────────────────────
    @staticmethod
    def parse_keep(keep) -> Set[tuple]:
        """``["JDOE@CORP->HELPDESK@CORP", ...]`` → ``{("JDOE", "HELPDESK")}``.
        A kept pair covers every relationship from SRC to DST."""
        out = set()
        for item in keep or []:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                a, b = item
            else:
                a, sep, b = str(item).partition("->")
                if not sep:
                    continue
            a, b = norm(a), norm(b)
            if a and b:
                out.add((a, b))
        return out

    def unmatched_keep(self, keep) -> List[tuple]:
        """Kept pairs that match no relationship in the data (likely a typo)."""
        return sorted(k for k in self.parse_keep(keep)
                      if not any(e.dst == k[1] for e in self.adj.get(k[0], [])))

    def remediation_plans(self, owned: Optional[List[str]] = None,
                          targets: Optional[List[str]] = None,
                          keep: Optional[List[str]] = None,
                          max_changes: int = 20) -> List[Dict]:
        """Alternative sets of changes that each break *every* route from the
        foothold to the targets — including routes not displayed — so the fix
        can be chosen with the business in mind, not only by graph position.

        Each plan is a minimum-size cut of the control graph under a constraint:

          fewest-changes    nothing off-limits except ``keep``
          keep-memberships  group memberships are off-limits too, so the plan
                            narrows the groups' permissions instead
          nearest-targets   the minimum cut closest to the targets, which leaves
                            the foothold the most access

        ``keep`` lists relationships people need for their job (``"SRC->DST"``);
        no plan removes them. Every plan is re-verified by search, and each
        change states who is affected and what access they lose. Duplicate
        plans are dropped; plans are ordered by number of changes. Returns []
        when there is no route, or no plan of at most ``max_changes`` changes
        avoids the kept access."""
        starts, goals = self.start_nodes(owned), self.goal_nodes(targets)
        starts = {s for s in starts if s not in goals}
        if not starts or not goals or not self._bfs(starts, goals, set()):
            return []
        kept = self.parse_keep(keep)

        def is_kept(e):
            return (e.src, e.dst) in kept

        def kept_or_membership(e):
            return is_kept(e) or e.type == "MemberOf"

        attempts = {
            "fewest-changes": [(is_kept, "source")],
            "keep-memberships": [(kept_or_membership, "source")],
            # If the cut nearest the targets is the same as the fewest-changes
            # one, look for the nearest one that leaves memberships alone.
            "nearest-targets": [(is_kept, "sink"), (kept_or_membership, "sink")],
        }
        depth = self._depths(starts)
        plans, seen = [], set()
        for sid, title, summary in _PLAN_STRATEGIES:
            for protected, side in attempts[sid]:
                cut = self._min_cut(starts, goals, protected, side, max_changes)
                if not cut:
                    continue
                keys = frozenset(self.edge_key(e) for e in cut)
                if keys in seen or self._bfs(starts, goals, set(), banned_edges=set(keys)):
                    continue
                seen.add(keys)
                cut.sort(key=lambda e: (depth.get(e.src, 1 << 30), self.edge_key(e)))
                changes = [self._change(e) for e in cut]
                plans.append({
                    "id": sid, "title": title, "summary": summary,
                    "changes": changes,
                    "memberships_removed": sum(1 for c in changes if c["kind"] == "membership"),
                    "affected": sorted({a for c in changes for a in c["affects"]}),
                    "breaks_every_route": True,
                })
                break
        plans.sort(key=lambda p: len(p["changes"]))     # stable: strategy order breaks ties
        return plans

    def _min_cut(self, starts: Set[str], goals: Set[str], protected, side: str,
                 limit: int) -> Optional[List[Edge]]:
        """Fewest relationships whose removal disconnects every start from every
        goal (max-flow / min-cut, one unit per relationship; ``protected`` ones
        can't be cut). ``side`` picks, among the minimum cuts, the one closest
        to the foothold (``"source"``) or to the targets (``"sink"``). None if
        every cut needs more than ``limit`` changes or a protected one."""
        big = limit + 1
        net: Dict = {}

        def arc(u, v, cap, edge=None):
            fwd, rev = [v, cap, None, edge], [u, 0, None, None]
            fwd[2], rev[2] = rev, fwd
            net.setdefault(u, []).append(fwd)
            net.setdefault(v, []).append(rev)

        for s in sorted(starts):
            arc(_SOURCE, s, big)
        for g in sorted(goals):
            arc(g, _SINK, big)
        seen = set()
        for u in sorted(self.adj):
            if u in goals:
                continue                       # nothing past a target matters
            for e in self.adj[u]:
                key = self.edge_key(e)
                if key not in seen:            # duplicate rows are one relationship
                    seen.add(key)
                    arc(u, e.dst, big if protected(e) else 1, e)

        flow = 0
        while flow <= limit:                   # Edmonds–Karp; stops once over the limit
            prev = {_SOURCE: None}
            q = deque([_SOURCE])
            while q and _SINK not in prev:
                u = q.popleft()
                for a in net.get(u, ()):
                    if a[1] > 0 and a[0] not in prev:
                        prev[a[0]] = a
                        q.append(a[0])
            if _SINK not in prev:
                break
            path, v = [], _SINK
            while v != _SOURCE:
                a = prev[v]
                path.append(a)
                v = a[2][0]
            push = min(a[1] for a in path)
            for a in path:
                a[1] -= push
                a[2][1] += push
            flow += push
        if flow > limit:
            return None

        if side == "source":                   # residual-reachable from the source
            reach, q = {_SOURCE}, deque([_SOURCE])
            while q:
                u = q.popleft()
                for a in net.get(u, ()):
                    if a[1] > 0 and a[0] not in reach:
                        reach.add(a[0])
                        q.append(a[0])
            return [a[3] for u in reach for a in net.get(u, ())
                    if a[3] is not None and a[0] not in reach]
        reach, q = {_SINK}, deque([_SINK])     # can still reach the sink
        while q:
            v = q.popleft()
            for a in net.get(v, ()):
                if a[2][1] > 0 and a[0] not in reach:    # a[2] is the arc a[0] -> v
                    reach.add(a[0])
                    q.append(a[0])
        return [a[3] for u, arcs in net.items() if u not in reach for a in arcs
                if a[3] is not None and a[0] in reach]

    def _depths(self, starts: Set[str]) -> Dict[str, int]:
        depth, q = {s: 0 for s in starts}, deque(sorted(starts))
        while q:
            n = q.popleft()
            for e in self.adj.get(n, []):
                if e.dst not in depth:
                    depth[e.dst] = depth[n] + 1
                    q.append(e.dst)
        return depth

    def _members(self, group: str) -> List[str]:
        """Everyone who holds a group's rights: direct and nested members."""
        if self._members_of is None:
            self._members_of = {}
            for edges in self.adj.values():
                for e in edges:
                    if e.type == "MemberOf":
                        self._members_of.setdefault(e.dst, set()).add(e.src)
        out, seen, q = set(), {group}, deque([group])
        while q:
            for m in self._members_of.get(q.popleft(), ()):
                if m not in seen:
                    seen.add(m)
                    if m in self._members_of:
                        q.append(m)            # nested group: its members count
                    else:
                        out.add(m)
        return sorted(out)

    def _groups_of(self, node: str, without: Optional[tuple] = None) -> Set[str]:
        """Groups ``node`` belongs to, directly or nested — optionally as if
        the membership ``without`` were removed."""
        seen, q = set(), deque([node])
        while q:
            for e in self.adj.get(q.popleft(), []):
                if (e.type == "MemberOf" and e.dst not in seen
                        and self.edge_key(e) != without):
                    seen.add(e.dst)
                    q.append(e.dst)
        return seen

    def _right_text(self, e: Edge) -> str:
        b = short(self.display.get(e.dst, e.dst))
        if e.type == "ACL":
            right = (e.detail or "").split(" ")[0]
            return f"{_RIGHT_NAMES.get(right, right or 'control')} over {b}"
        return {
            "MemberOf": f"membership of {b}",
            "ForceChangePassword": f"reset {b}'s password",
            "AddMember": f"add members to {b}",
            "AdminTo": f"local admin on {b}",
            "HasSession": f"{b}'s credentials in memory",
            "DCSync": "replicate domain secrets (DCSync)",
            "Unconstrained": "unconstrained delegation",
            "ConstrainedDeleg": f"delegate to {b}",
        }.get(e.type, f"{e.type} on {b}")

    def fix_text(self, e: Edge) -> str:
        a = short(self.display.get(e.src, e.src))
        b = short(self.display.get(e.dst, e.dst))
        if e.type == "ACL":
            right = (e.detail or "").split(" ")[0]
            return f"Remove the {_RIGHT_NAMES.get(right, right or 'ACL')} permission {a} holds on {b}."
        return {
            "MemberOf": f"Remove {a} from {b}.",
            "AdminTo": f"Remove {a} from the local Administrators group on {b} "
                       f"(use Windows LAPS for local admin).",
            "HasSession": f"Keep {b} off {a}: Tier-0 accounts should only sign in to Tier-0 systems.",
            "ForceChangePassword": f"Remove the password-reset right {a} holds on {b}.",
            "AddMember": f"Remove {a}'s right to change the membership of {b}.",
            "DCSync": f"Remove replication rights (Get-Changes / Get-Changes-All) from {a}.",
            "Unconstrained": f"Disable unconstrained delegation on {a} "
                             f"(use constrained or resource-based delegation).",
            "ConstrainedDeleg": f"Restrict what {a} may delegate to on {b}.",
        }.get(e.type, "Remove this relationship.")

    def _change(self, e: Edge) -> Dict:
        """One change in a plan: the fix, and who loses what if it is made."""
        src, dst = self.display.get(e.src, e.src), self.display.get(e.dst, e.dst)
        a, b = short(src), short(dst)
        out = {"from": src, "to": dst, "type": e.type, "detail": e.detail,
               "trust": e.trust, "fix": self.fix_text(e)}
        if e.type == "MemberOf":
            lost = (self._groups_of(e.src)
                    - self._groups_of(e.src, without=self.edge_key(e)))
            loses = []
            for g in sorted(lost, key=lambda g: (g != e.dst, g)):
                if g != e.dst:
                    loses.append(f"membership of {short(self.display.get(g, g))}")
                loses += [self._right_text(x) for x in self.adj.get(g, [])
                          if x.type != "MemberOf"]
            out.update(kind="membership", affects=[src], loses=loses,
                       effect=(f"{a} loses everything {b} grants"
                               + (f": {', '.join(loses)}." if loses else ".")),
                       note=(f"Anything {b} grants outside Active Directory (file shares, "
                             f"apps) isn't in the data and would be lost too."))
        elif e.type == "HasSession":
            out.update(kind="sign-in", affects=[dst], loses=[],
                       effect=f"No permission is removed: {b} stops signing in to {a}.",
                       note="Enforce it with a deny-logon policy or an authentication policy silo.")
        elif e.type == "Unconstrained":
            out.update(kind="configuration", affects=[src], loses=["unconstrained delegation"],
                       effect=f"{a} loses unconstrained delegation.",
                       note="Services that rely on it need constrained or resource-based delegation.")
        else:
            right = self._right_text(e)
            members = self._members(e.src)
            if members:
                names = [short(self.display.get(m, m)) for m in members]
                who = ", ".join(names[:4]) + (f" +{len(names) - 4} more" if len(names) > 4 else "")
                n = len(members)
                effect = (f"{a}'s {n} member{'s' if n != 1 else ''} ({who}) "
                          f"lose{'s' if n == 1 else ''} only this right: {right}.")
                affects = [self.display.get(m, m) for m in members]
            else:
                effect = f"{a} loses only this right: {right}."
                affects = [src]
            out.update(kind="permission", affects=affects, loses=[right],
                       effect=effect, note="")
        return out

    # ── Rendering helpers ─────────────────────────────────────────────────────
    def describe(self, path: List[Edge]) -> Dict:
        """Turn a path into a report-ready dict: ordered steps (with trust and
        evidence), commands, a risk score, and a plain-English rank rationale."""
        steps, commands = [], []
        for e in path:
            src, dst = self.display.get(e.src, e.src), self.display.get(e.dst, e.dst)
            steps.append({"from": src, "to": dst, "type": e.type,
                          "detail": e.detail, "trust": e.trust})
            commands.append(self._command(e, src, dst))
        inferred = sum(1 for e in path if e.trust == "inferred")
        start = self.display.get(path[0].src, path[0].src) if path else ""
        end = self.display.get(path[-1].dst, path[-1].dst) if path else ""
        rationale = (f"{len(path)} hop(s)"
                     + (f", {inferred} requiring an inferred abuse step (coercion / S4U)"
                        if inferred else ", all steps are observed relationships")
                     + ". Shorter, fully-observed paths rank higher.")
        return {"hops": len(path), "start": start, "goal": end,
                "inferred_steps": inferred, "rationale": rationale,
                "steps": steps, "commands": commands}

    def _command(self, e: Edge, src: str, dst: str) -> str:
        dom = self.data.get("domain", "DOMAIN")
        dc = self.data.get("dc_ip") or "DC_IP"
        short = dst.split("@")[0]
        return {
            "MemberOf": f"# already inherit {dst}'s rights via group membership",
            "ForceChangePassword": f"net rpc password \"{short}\" -U {dom}/USER%PASS -S {dc}",
            "AddMember": f"net rpc group addmem \"{short}\" USER -U {dom}/USER%PASS -S {dc}",
            "ACL": f"# take over {dst} (shadow creds / targeted kerberoast)\n"
                   f"certipy shadow auto -u USER@{dom} -account {short}",
            "AdminTo": f"nxc smb {short} -u USER -p PASS --sam  # local admin on {dst}",
            "HasSession": f"# dump LSASS on {src} to recover {dst}'s credentials\n"
                          f"nxc smb {src.split('@')[0]} -u USER -p PASS --lsa",
            "DCSync": f"impacket-secretsdump {dom}/USER@{dc} -just-dc",
            "Unconstrained": f"# coerce a DC to auth to {src}, capture the TGT (printerbug/PetitPotam)",
            "ConstrainedDeleg": f"impacket-getST -spn SERVICE/{short} -impersonate Administrator "
                                f"{dom}/USER:PASS -dc-ip {dc}",
        }.get(e.type, f"# advance from {src} to {dst} ({e.type})")
