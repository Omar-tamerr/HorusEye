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

from horuseye.core.principals import BROAD_NAMES, PrincipalIndex, norm

# ACL rights that amount to taking control of the target object.
_TAKEOVER_RIGHTS = {
    "genericall", "genericwrite", "writedacl", "writeowner", "owns",
    "allextendedrights", "addkeycredentiallink", "writespn",
}

_INFERRED_TYPES = {"Unconstrained", "ConstrainedDeleg"}


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

    def _build(self):
        d = self.data
        for g in d.get("groups", []):
            gname = g.get("name", "")
            for m in g.get("members", []) or []:
                self._edge(m, gname, "MemberOf", "member of group")

        for ace in d.get("acls", []):
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

        for la in d.get("local_admins", []):
            p, host = la.get("principal", ""), la.get("computer", "")
            if p and host and self.idx.classify(p) != "noise":
                self._edge(p, host, "AdminTo", "local administrator",
                           dst_is_computer=True)

        for s in d.get("sessions", []):
            user = s.get("UserName", "") or s.get("user", "")
            host = s.get("ComputerName", "") or s.get("ip", "")
            if user and host:
                self._edge(host, user, "HasSession", "credentials in memory",
                           src_is_computer=True)

        for ace in d.get("acls", []):
            right = (ace.get("right", "") or "").strip().lower()
            if right in ("dcsync", "getchangesall", "all"):
                p = ace.get("principal", "")
                if p and not self.idx.is_expected_replicator(p):
                    self._edge(p, self.domain_node, "DCSync", "replicate domain secrets")

        for c in d.get("computers", []):
            if c.get("unconstrained_delegation"):
                self._edge(c.get("name", ""), self.domain_node, "Unconstrained",
                           "coerce a DC, capture its TGT", src_is_computer=True)
        for dt in d.get("delegation_targets", []):
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

    def _bfs(self, starts: Set[str], goals: Set[str], banned: Set[str]) -> List[Edge]:
        q = deque()
        seen = set()
        for s in starts:
            if s not in banned:
                q.append(s)
                seen.add(s)
        prev: Dict[str, Edge] = {}
        while q:
            node = q.popleft()
            if node in goals:
                return self._reconstruct(node, prev)
            for e in self.adj.get(node, []):
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
                           targets: Optional[List[str]] = None) -> List[Dict]:
        """For each edge on the shortest path, determine whether removing it
        disconnects the foothold from the target (a 'choke point' — the
        highest-value fix) and whether any alternative path remains.

        Returns ``[{from, to, type, breaks_path, alternative_remains}]`` ordered
        as the path is walked. Empty if there is no path."""
        starts, goals = self.start_nodes(owned), self.goal_nodes(targets)
        base = self._bfs(starts, {g for g in goals}, set())
        if not base:
            return []
        starts = {s for s in starts if s not in goals}
        out = []
        for e in base:
            cut = {e.dst}  # removing the node that this edge grants control of
            remains = bool(self._bfs(starts, goals, cut))
            out.append({
                "from": self.display.get(e.src, e.src),
                "to": self.display.get(e.dst, e.dst),
                "type": e.type,
                "breaks_path": not remains,
                "alternative_remains": remains,
            })
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
