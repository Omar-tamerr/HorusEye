"""
HorusEye — Finding knowledge base.

Maps every finding type the detector emits to:

* ``mitre``       — MITRE ATT&CK technique(s) the finding enables
* ``remediation`` — concrete steps to close the path
* ``detection``   — telemetry a defender can alert on (Windows event IDs etc.)

This is what lets one report serve both sides of an engagement: the red team
gets the validation command, the blue team gets the fix and the alert logic.
``enrich()`` attaches the entry to each finding in place.
"""
from __future__ import annotations

from typing import Dict, List

# Replication extended-right GUIDs, used in DCSync detection guidance.
_REPL_GUIDS = (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes), "
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All), "
    "89e95b76-444d-4c62-991a-0facbeda640c (DS-Replication-Get-Changes-In-Filtered-Set)"
)

KNOWLEDGE: Dict[str, Dict[str, List]] = {
    "KERBEROASTING": {
        "mitre": [("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting")],
        "remediation": [
            "Move services to group Managed Service Accounts (gMSA) so passwords are 120+ random characters and rotate automatically.",
            "Give any remaining service accounts a random password of 25+ characters.",
            "Enforce AES-only Kerberos encryption (msDS-SupportedEncryptionTypes) and disable RC4 so tickets are far harder to crack.",
            "Remove service accounts from privileged groups; never put an SPN on a Tier-0 account.",
        ],
        "detection": [
            "Event 4769 (Kerberos service ticket requested) with Ticket Encryption Type 0x17 (RC4) for a service account.",
            "A single account requesting TGS tickets for many SPNs in a short window.",
            "Deploy a honeypot account with an SPN and alert on any 4769 for it.",
        ],
    },
    "ASREP_ROASTING": {
        "mitre": [("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting")],
        "remediation": [
            "Enable Kerberos pre-authentication: clear 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) on the account.",
            "If the flag is required for a legacy app, enforce a long random password and restrict the account's privileges.",
        ],
        "detection": [
            "Event 4768 (TGT requested) with Pre-Authentication Type 0.",
            "AS-REQ for preauth-disabled accounts from hosts that do not normally use them.",
        ],
    },
    "DCSYNC": {
        "mitre": [("T1003.006", "OS Credential Dumping: DCSync")],
        "remediation": [
            "Remove replication rights (Get-Changes / Get-Changes-All / Get-Changes-In-Filtered-Set) from every principal that is not a Domain Controller or a deliberately Tier-0 group.",
            "Review the domain root ACL and AdminSDHolder for unexpected grants.",
            "If abuse is suspected, reset the krbtgt password twice (with replication time between resets).",
        ],
        "detection": [
            f"Event 4662 on the domain object with an access GUID of {_REPL_GUIDS} from a non-DC account.",
            "DRSUAPI (DRSGetNCChanges) replication traffic originating from a host that is not a Domain Controller.",
        ],
    },
    "ACL_ABUSE": {
        "mitre": [("T1098", "Account Manipulation"),
                  ("T1078.002", "Valid Accounts: Domain Accounts")],
        "remediation": [
            "Remove the excessive ACE from the principal and apply least privilege on the target object.",
            "Treat any write/owner/control right over Tier-0 objects as Tier-0 itself — restrict it to Tier-0 admins.",
            "Never grant control rights to broad groups (Everyone, Authenticated Users, Domain Users).",
            "Audit delegated permissions on OUs and AdminSDHolder on a schedule.",
        ],
        "detection": [
            "Event 5136 (directory object modified) on nTSecurityDescriptor, member, servicePrincipalName or msDS-KeyCredentialLink.",
            "Event 4724 (password reset by another account) and 4738 (user account changed).",
            "Events 4728 / 4732 / 4756 (member added to a security-enabled group).",
        ],
    },
    "GPO_ABUSE": {
        "mitre": [("T1484.001", "Domain or Tenant Policy Modification: Group Policy Modification")],
        "remediation": [
            "Restrict GPO edit/owner rights to Tier-0 administrators.",
            "Review delegated permissions on every GPO linked to servers, DCs or admin workstations.",
            "Version-control and alert on GPO changes.",
        ],
        "detection": [
            "Event 5136 on groupPolicyContainer objects (gPCFileSysPath, versionNumber).",
            "Event 5145 / file auditing for writes under SYSVOL\\Policies (e.g. ScheduledTasks.xml).",
        ],
    },
    "UNCONSTRAINED_DELEGATION": {
        "mitre": [("T1558", "Steal or Forge Kerberos Tickets"),
                  ("T1187", "Forced Authentication")],
        "remediation": [
            "Replace unconstrained delegation with constrained delegation or resource-based constrained delegation (RBCD).",
            "Mark privileged accounts 'Account is sensitive and cannot be delegated' and add them to Protected Users.",
            "Disable the Print Spooler service on Domain Controllers and mitigate coercion vectors (e.g. EFSRPC/PetitPotam RPC filters).",
        ],
        "detection": [
            "Event 4624 network logons from Domain Controller machine accounts to non-DC hosts.",
            "Spooler (MS-RPRN) or EFSRPC calls targeting Domain Controllers from member hosts.",
        ],
    },
    "CONSTRAINED_DELEGATION": {
        "mitre": [("T1558", "Steal or Forge Kerberos Tickets")],
        "remediation": [
            "Disable protocol transition (TrustedToAuthForDelegation) unless a service genuinely requires it.",
            "Limit msDS-AllowedToDelegateTo to the minimum set of service SPNs.",
            "Protect privileged accounts from delegation (sensitive flag / Protected Users).",
        ],
        "detection": [
            "Event 4769 with S4U2Self / S4U2Proxy activity (Transited Services field populated) for sensitive targets.",
        ],
    },
    "PASS_THE_HASH": {
        "mitre": [("T1550.002", "Use Alternate Authentication Material: Pass the Hash")],
        "remediation": [
            "Deploy Windows LAPS so every machine has a unique, rotated local administrator password.",
            "Remove standing local-admin rights; use just-in-time elevation.",
            "Restrict or disable NTLM where possible and enable Credential Guard.",
        ],
        "detection": [
            "Event 4624 Logon Type 3 using NTLM from an unexpected source.",
            "One account authenticating to many hosts within minutes (lateral-movement fan-out).",
        ],
    },
    "ADCS_ESC": {
        "mitre": [("T1649", "Steal or Forge Authentication Certificates")],
        "remediation": [
            "ESC1/ESC2/ESC3: remove 'Supply in the request' (ENROLLEE_SUPPLIES_SUBJECT) or require manager approval; restrict enrollment rights to the intended principals.",
            "ESC4: remove write rights on the certificate template from non-Tier-0 principals.",
            "ESC6: clear EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA.",
            "ESC8: disable HTTP web enrollment or enforce HTTPS with Extended Protection for Authentication.",
            "Enable strong certificate mapping (KB5014754) on Domain Controllers.",
        ],
        "detection": [
            "Event 4886 / 4887 (certificate requested / issued) where the SAN differs from the requester.",
            "Event 4768 with certificate (PKINIT) authentication for privileged accounts.",
        ],
    },
    "DOMAIN_TRUST": {
        "mitre": [("T1482", "Domain Trust Discovery"),
                  ("T1134.005", "Access Token Manipulation: SID-History Injection")],
        "remediation": [
            "Enable SID filtering (quarantine) on external and forest trusts.",
            "Use Selective Authentication on forest trusts.",
            "Remove trusts that are no longer required and review trust direction.",
        ],
        "detection": [
            "Event 4675 (SIDs were filtered) and cross-realm 4769 requests from unusual principals.",
        ],
    },
    "PRIVILEGED_SESSION": {
        "mitre": [("T1003.001", "OS Credential Dumping: LSASS Memory"),
                  ("T1078.002", "Valid Accounts: Domain Accounts")],
        "remediation": [
            "Enforce a tiered admin model: Tier-0 accounts only log on to Tier-0 systems (use Privileged Access Workstations).",
            "Add administrators to Protected Users and enable LSA protection (RunAsPPL) and Credential Guard.",
            "Log off stale admin sessions on member servers and workstations.",
        ],
        "detection": [
            "Event 4624 logons by Tier-0 accounts on non-Tier-0 hosts.",
            "Process access to lsass.exe (Sysmon Event 10) on hosts where admins are logged on.",
        ],
    },
    "WEAK_PASSWORD_POLICY": {
        "mitre": [("T1110.003", "Brute Force: Password Spraying"),
                  ("T1201", "Password Policy Discovery")],
        "remediation": [
            "Set a minimum length of 14+ characters (or move to passphrases).",
            "Enable account lockout with a sensible threshold and observation window.",
            "Deploy a banned-password list and apply stricter fine-grained policies to privileged accounts.",
        ],
        "detection": [
            "Many Event 4625 / 4771 failures across different accounts from one source (spray pattern).",
            "Event 4740 (account locked out) bursts.",
        ],
    },
    "STALE_ADMIN": {
        "mitre": [("T1078.002", "Valid Accounts: Domain Accounts")],
        "remediation": [
            "Disable or delete privileged accounts that are no longer used.",
            "After removing an account from protected groups, clear adminCount and restore ACL inheritance.",
            "Remove 'password never expires' from administrative accounts and run periodic access reviews.",
        ],
        "detection": [
            "Event 4722 (account enabled) for a dormant privileged account.",
            "Logons by privileged accounts that have been inactive for a long period.",
        ],
    },
}


def enrich(findings: List[Dict]) -> List[Dict]:
    """Attach ATT&CK, remediation and detection guidance to each finding in
    place. Unknown types are left untouched. Returns the same list."""
    for f in findings or []:
        kb = KNOWLEDGE.get(f.get("type", ""))
        if not kb:
            continue
        f.setdefault("mitre", [{"id": tid, "name": name} for tid, name in kb["mitre"]])
        f.setdefault("remediation", list(kb["remediation"]))
        f.setdefault("detection", list(kb["detection"]))
    return findings


def mitre_coverage(findings: List[Dict]) -> List[Dict]:
    """Aggregate findings per ATT&CK technique for report summaries.

    Returns ``[{"id", "name", "count", "max_severity"}]`` sorted by technique.
    """
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    agg: Dict[str, Dict] = {}
    for f in findings or []:
        sev = (f.get("severity") or "INFO").upper()
        for t in f.get("mitre", []) or []:
            row = agg.setdefault(t["id"], {"id": t["id"], "name": t["name"],
                                           "count": 0, "max_severity": "INFO"})
            row["count"] += 1
            if order.get(sev, 0) > order.get(row["max_severity"], 0):
                row["max_severity"] = sev
    return sorted(agg.values(), key=lambda r: r["id"])
