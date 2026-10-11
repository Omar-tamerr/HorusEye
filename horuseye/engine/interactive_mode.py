"""Interactive AI-guided mode stub."""
class InteractiveMode:
    def __init__(self, console=None, claude_key="", creds_mgr=None, team=None):
        self.console    = console
        self.claude_key = claude_key

    def run(self, findings: list, domain_data: dict, args):
        _p = (lambda m: self.console.print(m)) if self.console else print
        _p("[bold cyan]𓂀 Interactive Mode[/bold cyan]")
        for i, f in enumerate(findings[:5], 1):
            _p(f"  [{i}] {f.get('severity','')} — {f.get('title','')}")
        _p("  [dim](Full interactive mode requires DC connection)[/dim]")
