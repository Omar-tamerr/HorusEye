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
  Reaches             vantage   -> web app         (reachability, NOT control)
  ExecutesAs          web app   -> account         (act with the account's privileges)
  AllowedToAct        principal -> computer        (RBCD already configured — INFERRED)
  HasSIDHistory       principal -> principal       (carries the other's SID and rights)
  ReadLAPSPassword    principal -> computer        (read the local admin password)
  ReadGMSAPassword    principal -> gMSA account    (read the managed password)
  GPLink              GPO       -> user/computer   (the GPO applies to it — INFERRED:
                                                    security filtering isn't in the data)
  ADCS                principal -> <domain>        (Certipy ESC1/2/3/4/6/7/8/11/15)

The last two come from a web app import (``parsers/webapps.py``). ``Reaches``
is the only edge that is not a control relationship: reaching an app gives
the tester no control of it, so it is never proposed as a fix.

Trust tiers
-----------
``validated``    — demonstrated in this engagement, with evidence.
``observed``     — a relationship read directly from the directory data.
``inferred``     — needs an additional abuse step (coercion, S4U) that the data
                   makes *possible* but does not prove.
``assumed``      — an analyst assumption (with a rationale), not evidence.
``not_assessed`` — never assessed; used only for "what if" routes.

Normal routes never cross an ``assumed`` or ``not_assessed`` step; routes that
need one are reported separately as conditional.

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
    "addallowedtoact", "writeaccountrestrictions",        # configure RBCD on a computer
}
_RIGHT_NAMES = {
    "genericall": "GenericAll", "genericwrite": "GenericWrite", "writedacl": "WriteDacl",
    "writeowner": "WriteOwner", "owns": "Owns", "allextendedrights": "AllExtendedRights",
    "addkeycredentiallink": "AddKeyCredentialLink", "writespn": "WriteSPN",
    "addallowedtoact": "AddAllowedToAct", "writeaccountrestrictions": "WriteAccountRestrictions",
}
_RBCD_RIGHTS = {"addallowedtoact", "writeaccountrestrictions"}

# Certipy findings that become a route to domain control: ESC -> (trust, what it
# lets the principal do). Others (ESC5, ESC9, ESC10, ESC12-14, ESC16) stay
# findings only: their abuse depends on data HorusEye doesn't import.
_ADCS_ESC = {
    "ESC1": ("observed", "enroll with a subject of their choice and authenticate as any user"),
    "ESC2": ("inferred", "enroll in an any-purpose template and use it as an enrollment agent"),
    "ESC3": ("inferred", "enroll as an enrollment agent and request certificates for other users"),
    "ESC4": ("observed", "rewrite the template to allow a chosen subject, then authenticate as any user"),
    "ESC6": ("inferred", "supply a subject alternative name on any client-auth template"),
    "ESC7": ("inferred", "manage the CA and issue a certificate for any user"),
    "ESC8": ("inferred", "coerce a domain controller and relay it to HTTP web enrollment"),
    "ESC11": ("inferred", "coerce a domain controller and relay it to the CA's RPC interface"),
    "ESC15": ("inferred", "add an application policy to a schema v1 template (EKUwu)"),
}
_ADCS_RELAY = {"ESC8", "ESC11"}           # any domain user can coerce + relay
_ADCS_ENROLL = {"ESC1", "ESC2", "ESC3", "ESC15"}
_ADCS_CONTROL = {"ESC4", "ESC7"}

# Relationship kinds that are not a change to propose: reaching an app, and a
# GPO applying to what is linked below it (the fix is who can edit the GPO).
_NOT_A_FIX = {"reachability", "policy", "implicit"}

_INFERRED_TYPES = {"Unconstrained", "ConstrainedDeleg", "AllowedToAct"}
_CONDITIONAL_TRUST = {"assumed", "not_assessed"}       # never on a normal route
_TRUST_RANK = {"validated": 0, "observed": 1, "inferred": 2, "assumed": 3, "not_assessed": 4}

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
# What the exposure number counts, said in the report so it isn't over-read.
EXPOSURE_MODELED = [
    "group membership", "ACL takeover (GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, "
    "AllExtendedRights, AddKeyCredentialLink, WriteSPN)", "password reset", "add member",
    "local admin", "sessions", "DCSync", "unconstrained, constrained and resource-based delegation",
    "SID history", "LAPS and gMSA password readers", "GPOs applied through OU links",
    "ADCS ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC11, ESC15 (Certipy)",
]
EXPOSURE_NOT_MODELED = [
    "Kerberoastable and AS-REP roastable accounts (they need a crackable password)",
    "ADCS ESC5, ESC9, ESC10, ESC12, ESC13, ESC14, ESC16",
    "domain and forest trusts",
    "GPO security filtering and WMI filters",
    "credentials outside Active Directory (scripts, shares, vaults)",
    "sessions not seen at collection time",
]

_SOURCE, _SINK = ("<source>",), ("<sink>",)    # flow-network terminals; never a node name


class Edge:
    __slots__ = ("src", "dst", "type", "detail", "trust", "kind", "evidence", "note")

    def __init__(self, src: str, dst: str, etype: str, detail: str = "",
                 trust: str = "observed", kind: str = "control",
                 evidence: tuple = (), note: str = ""):
        self.src, self.dst, self.type, self.detail, self.trust = src, dst, etype, detail, trust
        self.kind, self.evidence, self.note = kind, tuple(evidence), note


class AttackGraph:
    def __init__(self, domain_data: Dict):
        self.data = domain_data or {}
        self.idx = PrincipalIndex(self.data)
        self.domain_node = norm(self.data.get("domain", "") or "DOMAIN")
        self.adj: Dict[str, List[Edge]] = {}
        self.display: Dict[str, str] = {}      # node -> best display name
        self.is_computer: Set[str] = set()
        self._members_of: Optional[Dict[str, Set[str]]] = None   # group -> direct members, lazily
        self.vantages: Set[str] = set()        # assessment vantages from a web app import
        self.meta: Dict[tuple, Dict] = {}      # edge_key -> extra facts (ADCS template, CA)
        self._radj: Optional[Dict[str, List[Edge]]] = None   # reverse adjacency, lazily
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
              src_is_computer: bool = False, dst_is_computer: bool = False,
              trust: Optional[str] = None, **extra):
        s = self._node(src, src_is_computer)
        d = self._node(dst, dst_is_computer)
        if s and d and s != d:
            trust = trust or ("inferred" if etype in _INFERRED_TYPES else "observed")
            self.adj.setdefault(s, []).append(Edge(s, d, etype, detail, trust, **extra))

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
            elif right == "readlapspassword":
                self._edge(principal, target, "ReadLAPSPassword",
                           "read the local administrator password (LAPS)", dst_is_computer=True)
            elif right == "readgmsapassword":
                self._edge(principal, target, "ReadGMSAPassword", "read the gMSA password")
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
        for r in self._dicts(d.get("rbcd")):
            self._edge(r.get("principal", ""), r.get("computer", ""), "AllowedToAct",
                       "resource-based delegation (S4U impersonation)", dst_is_computer=True)
        for h in self._dicts(d.get("sid_history")):
            self._edge(h.get("principal", ""), h.get("target", ""), "HasSIDHistory",
                       "SID history")
        self._gpo_links()
        self._adcs()
        for app in self._dicts(d.get("webapps")):
            self._webapp(app)
        # Search observed relationships before inferred ones, so between two
        # routes of the same length the better-evidenced one is found first.
        for edges in self.adj.values():
            edges.sort(key=lambda e: _TRUST_RANK.get(e.trust, 9))

    def _gpo_links(self):
        """A GPO applies to every user and computer below the OU (or domain) it
        is linked to, except under an OU that blocks inheritance — unless the
        link is enforced. Controlling the GPO runs code on all of them."""
        conts = {}
        for c in self._dicts(self.data.get("containers")):
            if c.get("name"):
                conts[norm(c["name"])] = c
        for c in conts.values():
            for link in c.get("links") or []:
                gpo = (link or {}).get("gpo") if isinstance(link, dict) else None
                if not gpo:
                    continue
                enforced = bool(link.get("enforced"))
                where = short(c.get("name", ""))
                seen, stack = {norm(c["name"])}, [c]
                while stack:
                    for child in stack.pop().get("children") or []:
                        if not isinstance(child, dict) or not child.get("name"):
                            continue
                        key = norm(child["name"])
                        if key in seen:
                            continue
                        seen.add(key)
                        sub = conts.get(key)
                        ctype = str(child.get("type") or "").lower()
                        if sub is not None or ctype in ("ou", "container", "domain"):
                            if sub is not None and not (sub.get("blocks_inheritance") and not enforced):
                                stack.append(sub)
                            continue
                        if ctype and ctype not in ("user", "computer"):
                            continue
                        self._edge(gpo, child["name"], "GPLink",
                                   f"GPO linked to {where} applies to it",
                                   dst_is_computer=(ctype == "computer"),
                                   trust="inferred", kind="policy",
                                   note="Security filtering and WMI filters aren't in the data.")

    @staticmethod
    def _cert_principal(raw: str) -> str:
        """Certipy names principals ``DOMAIN\\Name``; the graph uses ``NAME@DOMAIN``."""
        raw = (raw or "").strip()
        if "\\" in raw:
            dom, _, name = raw.partition("\\")
            return f"{name.upper()}@{dom.upper()}" if name else dom.upper()
        return raw.upper()

    def _adcs(self):
        """Certipy findings that let a principal become any user: a route to
        domain control. The principal is whoever Certipy names in the finding,
        else the template's enrollment or control rights; relay findings (ESC8,
        ESC11) need only a coercible DC, so any domain user qualifies."""
        adcs = self.data.get("adcs") or {}
        if not isinstance(adcs, dict):
            return
        for v in self._dicts(adcs.get("vulnerabilities")):
            esc = str(v.get("esc") or "").upper()
            spec = _ADCS_ESC.get(esc)
            if not spec or v.get("enabled") is False:
                continue
            trust, what = spec
            principals = list(v.get("principals") or [])
            if not principals:
                if esc in _ADCS_RELAY:
                    principals = [f"DOMAIN USERS@{self.data.get('domain') or 'DOMAIN'}"]
                elif esc in _ADCS_ENROLL:
                    principals = list(v.get("enrollment_rights") or [])
                elif esc in _ADCS_CONTROL:
                    principals = list(v.get("control_rights") or [])
            where = v.get("template") or v.get("ca") or ""
            detail = f"{esc} {where}: {what}".replace(" :", ":")
            for raw in principals:
                name = self._cert_principal(str(raw))
                if self.idx.classify(name) in ("noise", "tier0"):
                    continue                  # already domain-admin-equivalent, or not a principal
                before = len(self.adj.get(norm(name), []))
                self._edge(name, self.domain_node, "ADCS", detail, trust=trust)
                edges = self.adj.get(norm(name), [])
                if len(edges) > before:
                    self.meta[self.edge_key(edges[-1])] = {
                        "esc": esc, "template": v.get("template") or "",
                        "ca": v.get("ca") or (v.get("cas") or [""])[0]}

    def _webapp(self, app: Dict):
        """Turn an imported app's claims into edges. Claims are never changed
        and the account is never marked owned: the trust says what was proven."""
        claims = app.get("claims") or {}
        node = f"APP:{app.get('id', '')}"
        reach = claims.get("reachable_from_vantage") or {}
        vantage = (app.get("vantage") or {}).get("id")
        if vantage and reach.get("status") in ("confirmed", "assumed"):
            vnode = f"VANTAGE:{vantage}"
            self.vantages.add(self._node(vnode))
            self._edge(vnode, node, "Reaches", f"reachable from {vantage}",
                       trust="validated" if reach["status"] == "confirmed" else "assumed",
                       kind="reachability", evidence=reach.get("evidence", ()),
                       note=reach.get("rationale", ""))
        if not app.get("bound"):
            return                           # the account mapping didn't bind by SID
        uses = (claims.get("uses_account") or {}).get("status")
        priv = claims.get("privileges_obtainable") or {}
        if priv.get("status") == "confirmed":
            trust = "validated"
        elif priv.get("status") == "assumed":
            trust = "assumed"
        elif uses in ("confirmed", "assumed"):
            trust = "not_assessed"           # what-if only; the claim stays not_assessed
        else:
            return
        account = app["account"]["name"]
        self._edge(node, account, "ExecutesAs",
                   f"act with {short(account)}'s privileges through the app", trust=trust,
                   evidence=priv.get("evidence", ()), note=priv.get("rationale", ""))

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
        """``owned`` if given; otherwise broad groups (any domain user) plus
        any imported assessment vantages. An imported account is never a start."""
        if owned:
            starts = {norm(o) for o in owned if o}
            self._implicit_broad(starts)
            return starts
        nodes = self._all_nodes()
        return {n for n in nodes if norm(self.display.get(n, n)) in BROAD_NAMES} | self.vantages

    def _implicit_broad(self, starts: Set[str]):
        """An owned account also holds what Domain Users / Authenticated Users /
        Everyone can do, even though exports rarely list it as a member (it's
        the primary group). Add that membership as an explicit step, so routes
        open to every user are found from the foothold too. It is a fact, not
        a fix: never proposed for removal."""
        broad = sorted(b for b in self._broad_nodes() if self.adj.get(b))
        added = False
        for s in sorted(starts):
            if s in broad:
                continue
            have = {e.dst for e in self.adj.get(s, [])}
            for b in broad:
                if b not in have:
                    self.adj.setdefault(s, []).insert(0, Edge(
                        s, b, "MemberOf", "every domain user is a member", "observed", kind="implicit"))
                    self.display.setdefault(s, s)
                    added = True
        if added:
            self._radj = None

    # ── Pathfinding ────────────────────────────────────────────────────────────
    def shortest_paths(self, owned: Optional[List[str]] = None,
                       max_paths: int = 5,
                       targets: Optional[List[str]] = None,
                       conditional: bool = False) -> List[List[Edge]]:
        """Up to ``max_paths`` short, node-diverse paths from the start set to the
        nearest goal. ``targets`` overrides the default Tier-0 goals. Steps that
        are only assumed or not assessed are crossed only if ``conditional``."""
        starts, goals = self.start_nodes(owned), self.goal_nodes(targets)
        if not starts or not goals:
            return []
        starts = {s for s in starts if s not in goals}
        paths, banned = [], set()
        for _ in range(max_paths):
            path = self._bfs(starts, goals, banned, conditional=conditional)
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

    def conditional_paths(self, owned: Optional[List[str]] = None,
                          max_paths: int = 5,
                          targets: Optional[List[str]] = None) -> List[List[Edge]]:
        """Routes that need at least one assumed or not-assessed step ("what if
        this account is compromised"). Reported separately from normal routes."""
        return [p for p in self.shortest_paths(owned=owned, max_paths=max_paths,
                                               targets=targets, conditional=True)
                if any(e.trust in _CONDITIONAL_TRUST for e in p)]

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

    @staticmethod
    def rel_id(e: Edge) -> str:
        """Stable, readable relationship id (e.g. ``AdminTo:WEB-SVC->WEB01.ACME.LAB``),
        so later evidence can name exactly which relationship it validates."""
        right = ""
        if e.type == "ACL":
            right = f":{(e.detail or '').split(' ')[0]}"
        elif e.type == "ADCS":                 # ESC and template/CA: ADCS:ESC1/USERTPL:...
            right = ":" + (e.detail or "").split(":")[0].strip().replace(" ", "/")
        return f"{e.type}{right}:{e.src}->{e.dst}"

    def _bfs(self, starts: Set[str], goals: Set[str], banned: Set[str],
             banned_edges: Optional[Set[tuple]] = None,
             conditional: bool = False) -> List[Edge]:
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
                if not conditional and e.trust in _CONDITIONAL_TRUST:
                    continue              # unproven: only on "what if" routes
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
                if key in done or e.kind in _NOT_A_FIX:
                    continue                  # reaching an app / a GPO link is not a fix to make
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

        def is_kept(e):                       # kept access, and what is not a fix
            return (e.src, e.dst) in kept or e.kind in _NOT_A_FIX

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
                if e.trust in _CONDITIONAL_TRUST:
                    continue                   # unproven steps aren't routes to cut
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

    # ── Domain exposure ────────────────────────────────────────────────────────
    def _reverse(self) -> Dict[str, List[Edge]]:
        """dst -> edges into it, without unproven (assumed / not assessed) steps."""
        if self._radj is None:
            radj: Dict[str, List[Edge]] = {}
            for u in sorted(self.adj):
                for e in self.adj[u]:
                    if e.trust not in _CONDITIONAL_TRUST:
                        radj.setdefault(e.dst, []).append(e)
            self._radj = radj
        return self._radj

    def _can_reach(self, goals: Set[str], banned_edges=None,
                   parent: Optional[Dict[str, Edge]] = None,
                   order: Optional[List[str]] = None) -> Set[str]:
        """Every node with a route to a goal (one reverse search from the goals).
        ``parent`` records each node's first step toward a goal, ``order`` the
        discovery order — together, a shortest-route tree."""
        radj = self._reverse()
        seen, q = set(goals), deque(sorted(goals))
        while q:
            n = q.popleft()
            for e in radj.get(n, ()):
                if e.src in seen or (banned_edges and self.edge_key(e) in banned_edges):
                    continue
                seen.add(e.src)
                if parent is not None:
                    parent[e.src] = e
                if order is not None:
                    order.append(e.src)
                q.append(e.src)
        return seen

    def _population(self, goals: Set[str], targets) -> List[str]:
        """Enabled users who are not already targets (Tier-0 accounts are what
        the routes lead to, not who is exposed)."""
        out = set()
        for u in self._dicts(self.data.get("users")):
            if u.get("enabled") is False:
                continue
            name = u.get("name", "")
            n = norm(name)
            if not n or n in goals or (not targets and self.idx.is_tier0_target(name)):
                continue
            out.add(n)
            if "@" in name or n not in self.display:
                self.display.setdefault(n, name)     # users with no relationship keep their name
        return sorted(out)

    def _broad_nodes(self) -> Set[str]:
        return {n for n in self._all_nodes() if norm(self.display.get(n, n)) in BROAD_NAMES}

    def exposure(self, targets: Optional[List[str]] = None,
                 keep: Optional[List[str]] = None,
                 max_changes: int = 50, top: int = 5) -> Dict:
        """How many users can reach the targets (Tier-0 by default), and the
        fewest changes that bring that to zero.

        A user is exposed if a route leads from the user — or from a group
        every user belongs to (Domain Users, Authenticated Users, ...) — to a
        target. The plan is a minimum cut over every exposed user at once, the
        cut closest to the targets among the smallest ones; its changes are
        ordered so each one removes as many users as possible, with the count
        left after each. ``top_fixes`` are the single changes that cut off the
        most users on their own. ``keep`` relationships are never proposed.
        Unproven (assumed / not assessed) steps are not routes here."""
        goals = self.goal_nodes(targets)
        pop = self._population(goals, targets)
        n_total = len(pop)
        out = {
            "computed": bool(n_total), "users_total": n_total, "users_exposed": 0,
            "percent": 0.0, "via_broad_groups": [], "exposed_users": [],
            "plan": None, "plan_note": "", "top_fixes": [],
            "targets": sorted(self.display.get(g, g) for g in goals) if targets else ["Tier-0"],
            "modeled": EXPOSURE_MODELED, "not_modeled": EXPOSURE_NOT_MODELED,
        }
        if not n_total:
            out["plan_note"] = "No user list in the data, so exposure can't be measured."
            return out
        broad = self._broad_nodes()
        pop_set = set(pop)

        def exposed_after(banned) -> Set[str]:
            reach = self._can_reach(goals, banned_edges=banned)
            if any(b in reach for b in broad):
                return pop_set
            return pop_set & reach

        parent: Dict[str, Edge] = {}
        order: List[str] = []
        reach = self._can_reach(goals, parent=parent, order=order)
        broad_hit = sorted(b for b in broad if b in reach)
        exposed = pop_set if broad_hit else pop_set & reach
        out.update(users_exposed=len(exposed),
                   percent=round(100.0 * len(exposed) / n_total, 1),
                   via_broad_groups=[self.display.get(b, b) for b in broad_hit],
                   exposed_users=sorted(self.display.get(u, u) for u in exposed))
        if not exposed:
            return out

        kept = self.parse_keep(keep)

        def protected(e):
            return (e.src, e.dst) in kept or e.kind in _NOT_A_FIX

        # Fewest changes that leave no user a route.
        starts = (pop_set & reach) | set(broad_hit)
        cut = self._min_cut(starts, goals, protected, "sink", max_changes)
        if cut is None:
            free = self._min_cut(starts, goals, lambda e: e.kind in _NOT_A_FIX, "sink", max_changes)
            out["plan_note"] = (
                f"No plan of at most {max_changes} changes avoids the access marked with --keep."
                if (kept and free is not None) else
                f"Reaching zero takes more than {max_changes} changes; start with the biggest fixes below.")
        elif exposed_after(frozenset(self.edge_key(e) for e in cut)):
            cut = None                         # min-cut over a broad group can't cover everyone
            out["plan_note"] = "No single plan cuts off every user; start with the biggest fixes below."
        if cut:
            depth = self._depths(starts)
            remaining = sorted(cut, key=lambda e: (depth.get(e.src, 1 << 30), self.edge_key(e)))
            applied: Set[tuple] = set()
            before, steps = len(exposed), []
            while remaining:
                if len(steps) < 12:             # greedy: the change that cuts off the most users next
                    best = min(remaining, key=lambda e: len(exposed_after(applied | {self.edge_key(e)})))
                else:
                    best = remaining[0]
                remaining.remove(best)
                applied.add(self.edge_key(best))
                after = len(exposed_after(applied))
                steps.append(dict(self._change(best), users_cut_off=before - after,
                                  users_after=after, id=self.rel_id(best)))
                before = after
            out["plan"] = {"changes": steps, "users_after": before,
                           "memberships_removed": sum(1 for c in steps if c["kind"] == "membership"),
                           "breaks_every_route": before == 0}

        # Biggest single changes. Removing one relationship cuts a user off only
        # if it is on every route of theirs, so on their shortest-route-tree path
        # too: tree subtree sizes bound the gain, and the best bounds are checked.
        weight = {u: 1 for u in exposed if u in reach}
        for b in broad_hit:
            weight[b] = weight.get(b, 0) + len(exposed)
        acc = dict(weight)
        for node in reversed(order):
            e = parent.get(node)
            if e is not None:
                acc[e.dst] = acc.get(e.dst, 0) + acc.get(node, 0)
        cands = sorted((e for n, e in parent.items() if acc.get(n, 0) and not protected(e)),
                       key=lambda e: (-acc.get(e.src, 0), self.edge_key(e)))
        best: List[tuple] = []
        for e in cands[:60]:
            bound = acc.get(e.src, 0)
            if len(best) >= top and bound <= best[-1][0]:
                break
            gain = len(exposed) - len(exposed_after({self.edge_key(e)}))
            if gain > 0:
                best.append((gain, e))
                best.sort(key=lambda t: (-t[0], self.edge_key(t[1])))
                best = best[:top]
        out["top_fixes"] = [dict(self._change(e), users_cut_off=g,
                                 users_after=len(exposed) - g, id=self.rel_id(e))
                            for g, e in best]
        return out

    def whatif_view(self, targets: Optional[List[str]] = None) -> Dict:
        """The part of the graph that matters for exposure, compact enough to
        embed in the explorer: every node with a route to a target, the
        relationships between them, the targets, the broad groups and the users
        counted. Cutting relationships and re-running the reverse search in the
        browser gives the same number ``exposure()`` would. ``keys`` (not
        embedded) maps each relationship back to ``edge_key``."""
        goals = self.goal_nodes(targets)
        pop = self._population(goals, targets)
        reach = self._can_reach(goals)
        nodes = sorted(reach)
        idx = {n: i for i, n in enumerate(nodes)}
        edges, keys = [], []
        for u in sorted(self.adj):
            if u not in reach or u in goals:
                continue                       # nothing past a target matters
            seen = set()
            for e in self.adj[u]:
                k = self.edge_key(e)
                if e.trust in _CONDITIONAL_TRUST or e.dst not in reach or k in seen:
                    continue
                seen.add(k)
                edges.append([idx[u], idx[e.dst], 0 if e.kind in _NOT_A_FIX else 1])
                keys.append(k)
        return {"nodes": [self.display.get(n, n) for n in nodes],
                "goals": sorted(idx[g] for g in goals if g in idx),
                "broad": sorted(idx[b] for b in self._broad_nodes() if b in idx),
                "pop": [idx[u] for u in pop if u in idx],
                "total": len(pop), "edges": edges, "keys": keys}

    def _depths(self, starts: Set[str]) -> Dict[str, int]:
        depth, q = {s: 0 for s in starts}, deque(sorted(starts))
        while q:
            n = q.popleft()
            for e in self.adj.get(n, []):
                if e.dst not in depth and e.trust not in _CONDITIONAL_TRUST:
                    depth[e.dst] = depth[n] + 1
                    q.append(e.dst)
        return depth

    def _members(self, group: str) -> List[str]:
        """Everyone who holds a group's rights: direct and nested members."""
        if self._members_of is None:
            self._members_of = {}
            for edges in self.adj.values():
                for e in edges:
                    if e.type == "MemberOf" and e.kind != "implicit":
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
            "Reaches": f"reach {b}",
            "ExecutesAs": f"act as {b}",
            "AllowedToAct": f"delegate to {b} (RBCD)",
            "HasSIDHistory": f"{b}'s rights through SID history",
            "ReadLAPSPassword": f"read {b}'s LAPS password",
            "ReadGMSAPassword": f"read {b}'s gMSA password",
            "GPLink": f"apply {short(self.display.get(e.src, e.src))} to {b}",
            "ADCS": self._adcs_right(e),
        }.get(e.type, f"{e.type} on {b}")

    def _adcs_right(self, e: Edge) -> str:
        m = self.meta.get(self.edge_key(e), {})
        esc = m.get("esc") or (e.detail or "ADCS").split(" ")[0]
        if m.get("template"):
            return f"enroll in {m['template']} ({esc})"
        if m.get("ca"):
            return f"{esc} on CA {m['ca']}"
        return f"certificate abuse ({esc})"

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
            "Reaches": f"Restrict which networks can reach {a.split(':', 1)[-1]}.",
            "ExecutesAs": f"Fix the vulnerable endpoint in {a.split(':', 1)[-1]}, and run it "
                          f"under an account with only the rights it needs.",
            "AllowedToAct": f"Clear msDS-AllowedToActOnBehalfOfOtherIdentity on {b} "
                            f"(remove {a} from its resource-based delegation).",
            "HasSIDHistory": f"Clear the SID history on {a} (it carries {b}'s SID).",
            "ReadLAPSPassword": f"Remove {a}'s right to read the LAPS password of {b}.",
            "ReadGMSAPassword": f"Remove {a} from the principals allowed to retrieve {b}'s "
                                f"password (msDS-GroupMSAMembership).",
            "GPLink": f"Restrict who can edit {a}, or unlink it from {b}'s OU.",
            "ADCS": self._adcs_fix(e, a),
        }.get(e.type, "Remove this relationship.")

    def _adcs_fix(self, e: Edge, a: str) -> str:
        m = self.meta.get(self.edge_key(e), {})
        esc, tpl, ca = m.get("esc", ""), m.get("template", ""), m.get("ca", "") or "the CA"
        if esc in ("ESC1", "ESC2", "ESC3", "ESC15") and tpl:
            return (f"Remove the enrollment right {a} holds on template {tpl}, or turn off "
                    f"'Supply in the request' / require manager approval on it.")
        if esc == "ESC4" and tpl:
            return f"Remove the write permissions {a} holds on template {tpl}."
        if esc == "ESC6":
            return f"Turn off EDITF_ATTRIBUTESUBJECTALTNAME2 on {ca} and enforce strong certificate mapping."
        if esc == "ESC7":
            return f"Remove the ManageCA / ManageCertificates rights {a} holds on {ca}."
        if esc == "ESC8":
            return f"Turn off HTTP web enrollment on {ca}, or require HTTPS with EPA."
        if esc == "ESC11":
            return f"Enforce encryption for RPC requests on {ca} (IF_ENFORCEENCRYPTICERTREQUEST)."
        return f"Fix the {esc or 'ADCS'} misconfiguration Certipy reported."

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
        elif e.type == "ADCS" and self.meta.get(self.edge_key(e), {}).get("esc") in ("ESC6", "ESC8", "ESC11"):
            out.update(kind="configuration", affects=[], loses=[],
                       effect="No account loses access: the change is on the certificate authority.",
                       note="Check which applications request certificates over this interface first.")
        elif e.type == "HasSIDHistory":
            out.update(kind="configuration", affects=[src], loses=[self._right_text(e)],
                       effect=f"{a} stops carrying {b}'s SID.",
                       note="Confirm the migration that set it is finished before clearing it.")
        elif e.type == "ExecutesAs":
            out.update(kind="application", affects=[], loses=[],
                       effect="No one loses access: the fix is in the application.",
                       note=f"Reducing {b}'s own rights is a separate, additional change.")
        else:
            right = self._right_text(e)
            members = self._members(e.src)
            if norm(self.display.get(e.src, e.src)) in BROAD_NAMES:
                out.update(kind="permission", affects=[src], loses=[right],
                           effect=f"Every domain user loses only this right ({a}): {right}.",
                           note="")
                return out
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
            steps.append({"id": self.rel_id(e), "from": src, "to": dst, "type": e.type,
                          "detail": e.detail, "trust": e.trust, "kind": e.kind,
                          "evidence": list(e.evidence), "fix": self.fix_text(e)})
            commands.append(self._command(e, src, dst))
        inferred = sum(1 for e in path if e.trust == "inferred")
        start = self.display.get(path[0].src, path[0].src) if path else ""
        end = self.display.get(path[-1].dst, path[-1].dst) if path else ""
        validated = sum(1 for e in path if e.trust == "validated")
        unproven = sum(1 for e in path if e.trust in _CONDITIONAL_TRUST)
        if validated or unproven:
            derived = len(path) - validated - unproven
            parts = [f"{validated} validated in this engagement" if validated else "",
                     f"{derived} derived from the imported data"
                     + (f" ({inferred} inferred)" if inferred else "") if derived else "",
                     f"{unproven} not proven (assumed or not assessed)" if unproven else ""]
            rationale = f"{len(path)} hop(s): " + ", ".join(p for p in parts if p) + "."
        else:
            rationale = (f"{len(path)} hop(s)"
                         + (f", {inferred} requiring an inferred abuse step (coercion / S4U)"
                            if inferred else ", all steps are observed relationships")
                         + ". Shorter, fully-observed paths rank higher.")
        # Conditional routes say exactly what they take for granted.
        assumptions, labels = [], []
        for e in path:
            if e.trust not in _CONDITIONAL_TRUST:
                continue
            who = self.display.get(e.dst, e.dst)
            if e.trust == "assumed":
                assumptions.append(f"{who} is compromised through {self.display.get(e.src, e.src)} "
                                   f"(assumed: {e.note})")
                labels.append(f"Assumed: if {who} is compromised")
            else:
                assumptions.append(f"{who} is compromised through {self.display.get(e.src, e.src)} "
                                   f"(not assessed)")
                labels.append(f"Hypothetical: if {who} is compromised")
        return {"hops": len(path), "start": start, "goal": end,
                "inferred_steps": inferred, "validated_steps": validated,
                "rationale": rationale, "conditional": bool(assumptions),
                "assumptions": assumptions,
                "label": "; ".join(labels) if labels else f"{start} → {end}",
                "steps": steps, "commands": commands}

    def _command(self, e: Edge, src: str, dst: str) -> str:
        dom = self.data.get("domain", "DOMAIN")
        dc = self.data.get("dc_ip") or "DC_IP"
        short = dst.split("@")[0]
        return {
            "MemberOf": (f"# every domain user holds {dst}'s rights" if e.kind == "implicit"
                         else f"# already inherit {dst}'s rights via group membership"),
            "ForceChangePassword": f"net rpc password \"{short}\" -U {dom}/USER%PASS -S {dc}",
            "AddMember": f"net rpc group addmem \"{short}\" USER -U {dom}/USER%PASS -S {dc}",
            "ACL": self._acl_command(e, src, dst, dom, dc) if e.type == "ACL" else "",
            "AdminTo": f"nxc smb {short} -u USER -p PASS --sam  # local admin on {dst}",
            "HasSession": f"# dump LSASS on {src} to recover {dst}'s credentials\n"
                          f"nxc smb {src.split('@')[0]} -u USER -p PASS --lsa",
            "DCSync": f"impacket-secretsdump {dom}/USER@{dc} -just-dc",
            "Unconstrained": f"# coerce a DC to auth to {src}, capture the TGT (printerbug/PetitPotam)",
            "ConstrainedDeleg": f"impacket-getST -spn SERVICE/{short} -impersonate Administrator "
                                f"{dom}/USER:PASS -dc-ip {dc}",
            "Reaches": f"# {dst} answered requests from {src} "
                       f"(evidence: {', '.join(e.evidence) or 'none'})",
            "ExecutesAs": f"# {src} ran code as {dst} "
                          f"(evidence: {', '.join(e.evidence) or 'not assessed'})",
            "AllowedToAct": f"impacket-getST -spn cifs/{short} -impersonate Administrator "
                            f"{dom}/USER:PASS -dc-ip {dc}  # RBCD already trusts {src.split('@')[0]}",
            "HasSIDHistory": f"# {src} already holds {dst}'s rights through SID history",
            "ReadLAPSPassword": f"nxc ldap {dc} -u USER -p PASS -M laps  # read {short}'s local admin password",
            "ReadGMSAPassword": f"nxc ldap {dc} -u USER -p PASS --gmsa  # read {short}'s password",
            "GPLink": f"# edit {src.split('@')[0]} to run a command on {short} "
                      f"(e.g. an immediate scheduled task with pyGPOAbuse)",
            "ADCS": self._adcs_command(e, dom, dc),
        }.get(e.type, f"# advance from {src} to {dst} ({e.type})")

    def _acl_command(self, e: Edge, src: str, dst: str, dom: str, dc: str) -> str:
        """The usual way to use control of the target, by what the target is."""
        short = dst.split("@")[0]
        right = (e.detail or "").split(" ")[0]
        if right in _RBCD_RIGHTS or (e.dst in self.is_computer and right not in
                                     ("addkeycredentiallink", "writespn")):
            return (f"# configure RBCD on {dst} for a computer account you control\n"
                    f"impacket-rbcd -delegate-from YOURPC$ -delegate-to {short}$ -action write "
                    f"{dom}/USER:PASS -dc-ip {dc}\n"
                    f"impacket-getST -spn cifs/{short} -impersonate Administrator "
                    f"{dom}/YOURPC$:PASS -dc-ip {dc}")
        if self._is_group(e.dst) and right != "writespn":
            return f"net rpc group addmem \"{short}\" USER -U {dom}/USER%PASS -S {dc}"
        if self._is_gpo(e.dst):
            return (f"# edit the GPO {short} to run a command where it applies\n"
                    f"pygpoabuse {dom}/USER:PASS -gpo-id GPO_GUID -dc-ip {dc}")
        if right == "writespn":
            return f"targetedKerberoast.py -d {dom} -u USER -p PASS --request-user {short}"
        return (f"# take over {dst} (shadow creds / targeted kerberoast)\n"
                f"certipy shadow auto -u USER@{dom} -account {short}")

    def _is_group(self, node: str) -> bool:
        if self._members_of is None:
            self._members(node)                # builds the membership index
        return node in (self._members_of or {}) or any(
            norm(g.get("name", "")) == node for g in self._dicts(self.data.get("groups")))

    def _is_gpo(self, node: str) -> bool:
        return any(e.type == "GPLink" for e in self.adj.get(node, [])) or any(
            norm(g.get("name", "")) == node for g in self._dicts(self.data.get("gpos")))

    def _adcs_command(self, e: Edge, dom: str, dc: str) -> str:
        m = self.meta.get(self.edge_key(e), {})
        esc, tpl, ca = m.get("esc", ""), m.get("template") or "TEMPLATE", m.get("ca") or "CA_NAME"
        auth = f"certipy auth -pfx administrator.pfx -dc-ip {dc}"
        if esc in ("ESC1", "ESC15"):
            return (f"certipy req -u USER@{dom} -p PASS -ca {ca} -template {tpl} "
                    f"-upn administrator@{dom}\n{auth}")
        if esc in ("ESC2", "ESC3"):
            return (f"certipy req -u USER@{dom} -p PASS -ca {ca} -template {tpl}\n"
                    f"certipy req -u USER@{dom} -p PASS -ca {ca} -template User "
                    f"-on-behalf-of '{dom.split('.')[0]}\\Administrator' -pfx user.pfx\n{auth}")
        if esc == "ESC4":
            return (f"certipy template -u USER@{dom} -p PASS -template {tpl} -save-old\n"
                    f"certipy req -u USER@{dom} -p PASS -ca {ca} -template {tpl} "
                    f"-upn administrator@{dom}\n{auth}")
        if esc == "ESC8":
            return (f"certipy relay -target http://CA_HOST/certsrv/certfnsh.asp -template DomainController\n"
                    f"# then coerce a DC to authenticate to you (PetitPotam / printerbug)")
        if esc == "ESC11":
            return (f"certipy relay -target rpc://CA_HOST -ca {ca} -template DomainController\n"
                    f"# then coerce a DC to authenticate to you (PetitPotam / printerbug)")
        return f"certipy find -u USER@{dom} -p PASS -dc-ip {dc} -vulnerable  # confirm {esc}"
