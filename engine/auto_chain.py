"""Auto exploit chain engine."""
class AutoChainEngine:
    def __init__(self, console=None, claude_key: str = ""):
        self.console   = console
        self.claude_key = claude_key

    def run(self, findings: list, domain_data: dict, args) -> list:
        _p = (lambda m: self.console.print(m)) if self.console else print
        _p("[bold yellow]⚡ Auto-chain: Kerberoast → crack → validate → pivot[/bold yellow]")
        _p("[dim]  (Connect to a real DC to execute — stub mode)[/dim]")
        return []
