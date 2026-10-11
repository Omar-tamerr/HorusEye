"""
LDAP / CME / Certipy / Manual Parsers - HorusEye v2
Author: Omar Tamer 🇪🇬

LDAPParser            -> parses ldapdomaindump JSON output directory
CMEParser             -> parses classic CrackMapExec text output
CertipyParser         -> parses `certipy find -json` output
ManualInputCollector  -> interactive fallback when no tool output is available
"""
import json
import os
import re
from typing import Dict, List


# ════════════════════════════════════════════════════════════════════════════
# LDAPParser — ldapdomaindump
# ════════════════════════════════════════════════════════════════════════════
class LDAPParser:
    """
    Parses ldapdomaindump JSON output.

    Generate with:
        ldapdomaindump -u 'corp\\user' -p pass ldap://10.10.10.5 -o ./ldap_out/

    Expects (any subset present is fine):
        domain_users.json
        domain_computers.json
        domain_groups.json
        domain_policy.json
        domain_trusts.json
    """

    _FILE_MAP = {
        "users":     ["domain_users.json"],
        "computers": ["domain_computers.json"],
        "groups":    ["domain_groups.json"],
        "policy":    ["domain_policy.json"],
        "trusts":    ["domain_trusts.json"],
    }

    def __init__(self, directory: str):
        self.directory = directory

    def parse(self) -> Dict:
        result = {
            "users":            [],
            "groups":           [],
            "computers":        [],
            "gpos":             [],
            "trusts":           [],
            "spns":             [],
            "asrep_users":      [],
            "password_policy":  {},
        }

        if not self.directory or not os.path.isdir(self.directory):
            return result

        users     = self._load_any(self._FILE_MAP["users"])
        computers = self._load_any(self._FILE_MAP["computers"])
        groups    = self._load_any(self._FILE_MAP["groups"])
        policy    = self._load_any(self._FILE_MAP["policy"])
        trusts    = self._load_any(self._FILE_MAP["trusts"])

        for u in users or []:
            attrs = u.get("attributes", u)
            name  = self._first(attrs.get("sAMAccountName") or attrs.get("cn") or "")
            uac   = self._first(attrs.get("userAccountControl"))
            spns  = attrs.get("servicePrincipalName") or []
            if isinstance(spns, str):
                spns = [spns]

            uac_int = int(uac) if str(uac).isdigit() else 0
            dont_req_preauth = bool(uac_int & 0x400000)   # DONT_REQ_PREAUTH
            disabled         = bool(uac_int & 0x000002)   # ACCOUNTDISABLE

            entry = {
                "name":           name,
                "domain":         "",
                "enabled":        not disabled,
                "hasspn":         bool(spns),
                "dontreqpreauth": dont_req_preauth,
                "source":         "ldapdomaindump",
            }
            if name:
                result["users"].append(entry)

            if spns:
                result["spns"].append({"user": name, "spns": spns})
            if dont_req_preauth:
                result["asrep_users"].append(name)

        for c in computers or []:
            attrs = c.get("attributes", c)
            name = self._first(attrs.get("dNSHostName") or attrs.get("cn") or "")
            if name:
                result["computers"].append({
                    "name":            name,
                    "operatingsystem": self._first(attrs.get("operatingSystem") or ""),
                    "enabled":         True,
                })

        for g in groups or []:
            attrs = g.get("attributes", g)
            name = self._first(attrs.get("cn") or attrs.get("name") or "")
            members = attrs.get("member") or []
            if isinstance(members, str):
                members = [members]
            if name:
                result["groups"].append({
                    "name":    name,
                    "members": members,
                })

        if isinstance(policy, dict):
            result["password_policy"] = {
                "min_length":         policy.get("minPwdLength", ""),
                "lockout_threshold":  policy.get("lockoutThreshold", ""),
                "max_pwd_age":        policy.get("maxPwdAge", ""),
            }

        for t in trusts or []:
            result["trusts"].append({
                "target_domain": t.get("attributes", t).get("cn", ""),
                "direction":     t.get("attributes", t).get("trustDirection", ""),
                "type":          t.get("attributes", t).get("trustType", ""),
            })

        return result

    def _load_any(self, filenames: List[str]):
        for fname in filenames:
            fpath = os.path.join(self.directory, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        return json.load(f)
                except json.JSONDecodeError:
                    return None
        return None

    def _first(self, value):
        """ldapdomaindump often wraps single values in a list."""
        if isinstance(value, list):
            return value[0] if value else ""
        return value


# ════════════════════════════════════════════════════════════════════════════
# CMEParser — classic CrackMapExec text output
# ════════════════════════════════════════════════════════════════════════════
class CMEParser:
    """
    Parses classic CrackMapExec output (pre-NetExec fork).

    Save output with:
        cme smb 10.10.10.0/24 -u user -p pass --shares 2>&1 | tee cme_out.txt

    Output format is nearly identical to NetExec's, just with a "CME"-style
    protocol prefix (SMB/LDAP/WINRM/MSSQL) and no NXC-specific banner.
    """

    _RE_HOST = re.compile(
        r"(?:SMB|LDAP|WINRM|MSSQL|RDP)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<port>\d+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"\[\*\]\s+(?P<info>.+)"
    )
    _RE_AUTH = re.compile(
        r"(?:SMB|LDAP|WINRM|MSSQL|RDP)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"\d+\s+\S+\s+"
        r"(?P<status>\[.\])\s+"
        r"(?P<domain>[^\\]+)\\(?P<user>\S+?):(?P<secret>\S+)"
        r"(?P<pwned>\s+\(Pwn3d!\))?"
    )
    _RE_SHARE = re.compile(
        r"(?:SMB|LDAP)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"\d+\s+\S+\s+"
        r"(?P<share>\S+)\s+"
        r"(?P<perms>READ(?:,WRITE)?|WRITE|NO ACCESS)"
    )

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> Dict:
        data = {
            "hosts":       [],
            "admin_hosts": [],
            "valid_creds": [],
            "shares":      [],
        }

        try:
            with open(self.filepath, "r", errors="ignore") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return data

        seen_hosts = set()
        seen_creds = set()

        for raw in lines:
            line = raw.strip()
            if not line:
                continue

            m = self._RE_HOST.search(line)
            if m and m.group("ip") not in seen_hosts:
                seen_hosts.add(m.group("ip"))
                data["hosts"].append({
                    "ip":       m.group("ip"),
                    "hostname": m.group("hostname"),
                    "os":       m.group("info")[:60],
                })

            m = self._RE_AUTH.search(line)
            if m and m.group("status") == "[+]":
                key = f"{m.group('domain')}\\{m.group('user')}:{m.group('secret')}"
                if key not in seen_creds:
                    seen_creds.add(key)
                    data["valid_creds"].append({
                        "ip":       m.group("ip"),
                        "domain":   m.group("domain"),
                        "username": m.group("user"),
                        "secret":   m.group("secret"),
                        "is_admin": bool(m.group("pwned")),
                    })
                if m.group("pwned"):
                    data["admin_hosts"].append({
                        "ip":       m.group("ip"),
                        "domain":   m.group("domain"),
                        "username": m.group("user"),
                    })

            m = self._RE_SHARE.search(line)
            if m and m.group("perms") != "NO ACCESS":
                data["shares"].append({
                    "ip":          m.group("ip"),
                    "share":       m.group("share").upper(),
                    "permissions": m.group("perms"),
                })

        return data


# ════════════════════════════════════════════════════════════════════════════
# CertipyParser — certipy find -json
# ════════════════════════════════════════════════════════════════════════════
class CertipyParser:
    """
    Parses `certipy find -u user@corp.local -p pass -dc-ip 10.10.10.5 -json`
    output (the file ending in _Certipy.json).
    """

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> Dict:
        result = {
            "cas":             [],
            "templates":       [],
            "vulnerabilities": [],
        }

        try:
            with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return result

        cas = raw.get("Certificate Authorities", {}) or {}
        for _, ca in cas.items():
            result["cas"].append({
                "name":    ca.get("CA Name", ""),
                "dns":     ca.get("DNS Name", ""),
                "web_enrollment": bool(ca.get("Web Enrollment")),
            })

        templates = raw.get("Certificate Templates", {}) or {}
        for _, tpl in templates.items():
            name  = tpl.get("Template Name", tpl.get("Display Name", ""))
            vulns = tpl.get("Vulnerabilities", {}) or {}

            result["templates"].append({
                "name":                    name,
                "enabled":                 bool(tpl.get("Enabled")),
                "client_authentication":   bool(tpl.get("Client Authentication")),
                "enrollee_supplies_subject": bool(tpl.get("Enrollee Supplies Subject")),
                "enrollment_rights":       tpl.get("Enrollment Rights", []),
                "vulnerable":              bool(vulns),
            })

            for esc, description in vulns.items():
                result["vulnerabilities"].append({
                    "esc":         esc,
                    "template":    name,
                    "description": description,
                    "severity":    "CRITICAL" if esc.upper() in
                                   ("ESC1", "ESC3", "ESC4", "ESC6", "ESC8") else "HIGH",
                })

        return result


# ════════════════════════════════════════════════════════════════════════════
# ManualInputCollector — interactive fallback
# ════════════════════════════════════════════════════════════════════════════
class ManualInputCollector:
    """Prompts the operator for AD facts when no tool output is available."""

    def __init__(self, console=None):
        self.console = console

    def _p(self, msg: str):
        if self.console:
            self.console.print(msg)
        else:
            print(msg)

    def _ask(self, prompt: str) -> str:
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return ""

    def collect(self) -> Dict:
        self._p("[bold cyan]𓂀 Manual input mode — no tool output detected[/bold cyan]")

        result = {
            "users":       [],
            "spns":        [],
            "asrep_users": [],
        }

        users_raw = self._ask("Known usernames (comma-separated, blank to skip): ")
        for name in [u.strip() for u in users_raw.split(",") if u.strip()]:
            result["users"].append({"name": name, "source": "manual"})

        kerb_raw = self._ask("Kerberoastable usernames, if known (comma-separated): ")
        for name in [u.strip() for u in kerb_raw.split(",") if u.strip()]:
            result["spns"].append({"user": name, "spns": []})

        asrep_raw = self._ask("AS-REP roastable usernames, if known (comma-separated): ")
        result["asrep_users"] = [u.strip() for u in asrep_raw.split(",") if u.strip()]

        return result
