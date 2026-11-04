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

    Reads the layout Certipy actually writes (``[!] Vulnerabilities``, nested
    ``Permissions``, ``"Enabled"``/``"Disabled"`` strings, v5's per-protocol web
    enrollment) and the flat layout older HorusEye fixtures used. Each
    vulnerability keeps who can abuse it, so the attack-path graph can turn it
    into a route: ``principals`` are the accounts Certipy names in the finding,
    ``enrollment_rights`` / ``control_rights`` the template's permissions.
    """

    CRITICAL = ("ESC1", "ESC3", "ESC4", "ESC6", "ESC8")

    def __init__(self, filepath: str):
        self.filepath = filepath

    # ── helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _enabled(value) -> bool:
        """True / "Enabled" / {"http": {"enabled": true}} → True; "Disabled" → False."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("enabled", "true", "yes", "1")
        if isinstance(value, dict):
            return any(CertipyParser._enabled(v) for v in value.values())
        if isinstance(value, (list, tuple)):
            return any(CertipyParser._enabled(v) for v in value)
        return bool(value)

    @staticmethod
    def _vulns(obj: Dict) -> Dict:
        for k, v in obj.items():
            if "vulnerabilit" in str(k).lower() and isinstance(v, dict):
                return v
        return {}

    @staticmethod
    def _names(value) -> List[str]:
        if isinstance(value, str):
            return [value] if value.strip() else []
        if isinstance(value, (list, tuple)):
            return [str(x) for x in value if isinstance(x, str) and x.strip()]
        return []

    @classmethod
    def _enrollment_rights(cls, tpl: Dict) -> List[str]:
        if tpl.get("Enrollment Rights"):
            return cls._names(tpl["Enrollment Rights"])
        perms = tpl.get("Permissions") or {}
        ep = perms.get("Enrollment Permissions") or {}
        return cls._names(ep.get("Enrollment Rights"))

    @classmethod
    def _control_rights(cls, obj: Dict) -> List[str]:
        """Principals that can rewrite the object (template or CA)."""
        perms = obj.get("Permissions") or {}
        out: List[str] = []
        ocp = perms.get("Object Control Permissions") or {}
        for k, v in ocp.items():
            if str(k).lower() != "owner":
                out += cls._names(v)
        ar = perms.get("Access Rights") or {}
        for k, v in ar.items():
            if str(k).replace(" ", "").lower() in ("manageca", "managecertificates"):
                out += cls._names(v)
        return sorted(set(out))

    @staticmethod
    def _quoted(text: str) -> List[str]:
        """Certipy names who can abuse a finding in quotes:
        ``'CORP.LOCAL\\Domain Users' can enroll, ...``"""
        return sorted({m.replace("\\\\", "\\") for m in re.findall(r"'([^']+)'", text or "")})

    def _sev(self, esc: str) -> str:
        return "CRITICAL" if esc.upper() in self.CRITICAL else "HIGH"

    # ── entry point ───────────────────────────────────────────────────────
    def parse(self) -> Dict:
        result = {
            "cas":             [],
            "templates":       [],
            "vulnerabilities": [],
        }

        try:
            with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return result
        if not isinstance(raw, dict):
            return result

        def rows(block):
            if isinstance(block, dict):
                return [v for v in block.values() if isinstance(v, dict)]
            if isinstance(block, list):
                return [v for v in block if isinstance(v, dict)]
            return []

        for ca in rows(raw.get("Certificate Authorities")):
            name = ca.get("CA Name", "")
            result["cas"].append({
                "name":    name,
                "dns":     ca.get("DNS Name", ""),
                "web_enrollment": self._enabled(ca.get("Web Enrollment")),
                "user_specified_san": self._enabled(ca.get("User Specified SAN")),
                "control_rights": self._control_rights(ca),
            })
            for esc, description in self._vulns(ca).items():
                desc = str(description or "")
                result["vulnerabilities"].append({
                    "esc":         str(esc).upper(),
                    "template":    "",
                    "ca":          name,
                    "cas":         [name] if name else [],
                    "description": desc,
                    "severity":    self._sev(str(esc)),
                    "principals":  self._quoted(desc),
                    "enrollment_rights": [],
                    "control_rights": self._control_rights(ca),
                })

        for tpl in rows(raw.get("Certificate Templates")):
            name  = tpl.get("Template Name", tpl.get("Display Name", ""))
            vulns = self._vulns(tpl)
            enabled = self._enabled(tpl.get("Enabled", True))
            enroll = self._enrollment_rights(tpl)
            control = self._control_rights(tpl)
            cas = self._names(tpl.get("Certificate Authorities"))

            result["templates"].append({
                "name":                    name,
                "enabled":                 enabled,
                "client_authentication":   self._enabled(tpl.get("Client Authentication")),
                "enrollee_supplies_subject": self._enabled(tpl.get("Enrollee Supplies Subject")),
                "enrollment_rights":       enroll,
                "control_rights":          control,
                "cas":                     cas,
                "vulnerable":              bool(vulns),
            })

            for esc, description in vulns.items():
                desc = str(description or "")
                result["vulnerabilities"].append({
                    "esc":         str(esc).upper(),
                    "template":    name,
                    "ca":          cas[0] if cas else "",
                    "cas":         cas,
                    "enabled":     enabled,
                    "description": desc,
                    "severity":    self._sev(str(esc)),
                    "principals":  self._quoted(desc),
                    "enrollment_rights": enroll,
                    "control_rights": control,
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
