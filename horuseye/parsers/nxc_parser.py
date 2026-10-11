"""
NetExec (NXC) Parser - HorusEye v2
Handles all common nxc output formats: smb, ldap, winrm, mssql, rdp
Author: Omar Tamer 🇪🇬
"""
import re
from typing import Dict, List


class NXCParser:
    """
    Parses NetExec (nxc) output files.

    Supports output from:
        nxc smb   10.10.10.0/24 -u user -p pass
        nxc smb   10.10.10.0/24 -u user -p pass --shares
        nxc smb   10.10.10.0/24 -u user -p pass --sessions
        nxc smb   10.10.10.0/24 -u user -p pass --pass-pol
        nxc ldap  10.10.10.5    -u user -p pass --active-users
        nxc winrm 10.10.10.0/24 -u user -p pass
        nxc smb   10.10.10.0/24 -u user -H <hash>   (PTH)

    Save output with:
        nxc smb 10.10.10.0/24 -u user -p pass --shares 2>&1 | tee nxc_out.txt
    """

    # ── Compiled patterns ──────────────────────────────────────────────────────
    # SMB host line:
    # SMB  10.10.10.5  445  DC01  [*] Windows 10.0 Build 17763 (name:DC01) (domain:corp.local)
    _RE_HOST = re.compile(
        r"(?:SMB|LDAP|WINRM|MSSQL|RDP)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<port>\d+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"\[\*\]\s+(?P<info>.+)"
    )

    # Auth result:
    # SMB  10.10.10.5  445  DC01  [+] corp.local\svc-sql:ServicePass2024! (Pwn3d!)
    # SMB  10.10.10.5  445  DC01  [-] corp.local\jsmith:wrongpass
    _RE_AUTH = re.compile(
        r"(?:SMB|LDAP|WINRM|MSSQL|RDP)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"\d+\s+\S+\s+"
        r"(?P<status>\[.\])\s+"
        r"(?P<domain>[^\\]+)\\(?P<user>\S+?):(?P<secret>\S+)"
        r"(?P<pwned>\s+\(Pwn3d!\))?"
    )

    # Share line:
    # SMB  10.10.10.5  445  DC01  SYSVOL  READ,WRITE
    _RE_SHARE = re.compile(
        r"(?:SMB|LDAP)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"\d+\s+\S+\s+"
        r"(?P<share>\S+)\s+"
        r"(?P<perms>READ(?:,WRITE)?|WRITE|NO ACCESS)"
    )

    # Session line:
    # SMB  10.10.10.5  445  DC01  jsmith
    _RE_SESSION = re.compile(
        r"(?:SMB)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"\d+\s+\S+\s+"
        r"(?P<user>[a-zA-Z0-9._-]+)\s*$"
    )

    # Password policy lines
    _RE_POL_MIN   = re.compile(r"Minimum password length:\s*(\d+)")
    _RE_POL_HIST  = re.compile(r"Password history length:\s*(\d+)")
    _RE_POL_LOCK  = re.compile(r"Account lockout threshold:\s*(\S+)")
    _RE_POL_COMP  = re.compile(r"Password Complexity Flags:\s*(.+)")

    # Local admin line (from --local-auth or Pwn3d!)
    _RE_ADMIN = re.compile(
        r"(?:SMB|WINRM)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"\d+\s+"
        r"(?P<hostname>\S+)\s+"
        r"\[.\]\s+.+\(Pwn3d!\)"
    )

    # Interesting share names
    INTERESTING_SHARES = {
        "SYSVOL", "NETLOGON", "C$", "ADMIN$", "IPC$",
        "BACKUP", "DATA", "SCRIPTS", "SHARE", "FILES",
        "TRANSFER", "IT", "FINANCE", "HR", "DOCS"
    }

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> Dict:
        data = {
            "hosts":            [],   # all discovered hosts
            "admin_hosts":      [],   # hosts where we have admin (Pwn3d!)
            "valid_creds":      [],   # valid credentials found
            "shares":           [],   # share enumeration results
            "sessions":         [],   # active user sessions on hosts
            "password_policy":  {},   # domain password policy
            "protocols":        {},   # per-host protocol support
            "raw_lines":        0,
        }

        try:
            with open(self.filepath, "r", errors="ignore") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return data

        data["raw_lines"] = len(lines)
        seen_hosts = set()
        seen_creds = set()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # ── Host discovery ─────────────────────────────────────────────
            m = self._RE_HOST.search(line)
            if m:
                ip = m.group("ip")
                hostname = m.group("hostname")
                info = m.group("info")

                # Parse Windows version from info string
                win_ver = ""
                vm = re.search(r"Windows\s+[\d.]+\s+Build\s+(\d+)", info)
                if vm:
                    win_ver = self._build_to_version(vm.group(1))

                # Detect protocol from line start
                proto = line.split()[0].upper()

                if ip not in seen_hosts:
                    seen_hosts.add(ip)
                    data["hosts"].append({
                        "ip":       ip,
                        "hostname": hostname,
                        "os":       win_ver or info[:60],
                        "domain":   self._extract_domain(info),
                        "signing":  "signing:True" in info or "signing: True" in info,
                    })

                # Track protocol support per host
                if ip not in data["protocols"]:
                    data["protocols"][ip] = []
                if proto not in data["protocols"][ip]:
                    data["protocols"][ip].append(proto)

            # ── Auth results ────────────────────────────────────────────────
            m = self._RE_AUTH.search(line)
            if m and m.group("status") == "[+]":
                ip     = m.group("ip")
                user   = m.group("user")
                secret = m.group("secret")
                domain = m.group("domain")
                pwned  = bool(m.group("pwned"))

                cred_key = f"{domain}\\{user}:{secret}"
                if cred_key not in seen_creds:
                    seen_creds.add(cred_key)
                    data["valid_creds"].append({
                        "ip":       ip,
                        "domain":   domain,
                        "username": user,
                        "secret":   secret,
                        "is_hash":  len(secret) == 32 and all(
                                        c in "0123456789abcdefABCDEF"
                                        for c in secret),
                        "is_admin": pwned,
                    })

                if pwned and ip not in [h["ip"] for h in data["admin_hosts"]]:
                    # Find hostname
                    hostname = next(
                        (h["hostname"] for h in data["hosts"] if h["ip"] == ip),
                        ip
                    )
                    data["admin_hosts"].append({
                        "ip":       ip,
                        "hostname": hostname,
                        "domain":   domain,
                        "username": user,
                        "secret":   secret,
                    })

            # ── Share enumeration ───────────────────────────────────────────
            m = self._RE_SHARE.search(line)
            if m:
                share  = m.group("share").upper()
                perms  = m.group("perms")
                ip     = m.group("ip")

                if perms != "NO ACCESS":
                    data["shares"].append({
                        "ip":          ip,
                        "share":       share,
                        "permissions": perms,
                        "interesting": share in self.INTERESTING_SHARES,
                        "writable":    "WRITE" in perms,
                    })

            # ── Active sessions ─────────────────────────────────────────────
            if "--sessions" in self.filepath.lower() or "session" in line.lower():
                m = self._RE_SESSION.search(line)
                if m:
                    data["sessions"].append({
                        "ip":   m.group("ip"),
                        "user": m.group("user"),
                    })

            # ── Admin hosts (Pwn3d! in any line) ───────────────────────────
            m = self._RE_ADMIN.search(line)
            if m:
                ip       = m.group("ip")
                hostname = m.group("hostname")
                if ip not in [h["ip"] for h in data["admin_hosts"]]:
                    data["admin_hosts"].append({
                        "ip":       ip,
                        "hostname": hostname,
                        "domain":   "",
                        "username": "",
                        "secret":   "",
                    })

            # ── Password policy ─────────────────────────────────────────────
            for pattern, key in [
                (self._RE_POL_MIN,  "min_length"),
                (self._RE_POL_HIST, "history"),
                (self._RE_POL_LOCK, "lockout_threshold"),
                (self._RE_POL_COMP, "complexity"),
            ]:
                m = pattern.search(line)
                if m:
                    data["password_policy"][key] = m.group(1).strip()

        return data

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _extract_domain(self, info: str) -> str:
        m = re.search(r"domain[:\s]+([a-zA-Z0-9._-]+)", info, re.IGNORECASE)
        return m.group(1) if m else ""

    def _build_to_version(self, build: str) -> str:
        builds = {
            "17763": "Windows Server 2019 / Win10 1809",
            "19041": "Windows 10 2004",
            "19042": "Windows 10 20H2",
            "19043": "Windows 10 21H1",
            "19044": "Windows 10 21H2",
            "20348": "Windows Server 2022",
            "22000": "Windows 11 21H2",
            "22621": "Windows 11 22H2",
            "14393": "Windows Server 2016 / Win10 1607",
            "10586": "Windows 10 1511",
            "9600":  "Windows Server 2012 R2",
            "9200":  "Windows Server 2012",
            "7601":  "Windows Server 2008 R2",
        }
        return builds.get(build, f"Build {build}")

    def summary(self, data: Dict) -> str:
        """Return a one-line summary of parse results."""
        return (
            f"{len(data['hosts'])} hosts  |  "
            f"{len(data['admin_hosts'])} admin  |  "
            f"{len(data['valid_creds'])} valid creds  |  "
            f"{len(data['shares'])} shares  |  "
            f"{len(data['sessions'])} sessions"
        )
