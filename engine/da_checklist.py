"""Domain Takeover Checklist."""
class DomainTakeoverChecklist:
    def __init__(self, console=None):
        self.console = console

    def run(self, findings: list, domain_data: dict, args):
        _p = (lambda m: self.console.print(m)) if self.console else print
        _p("[bold cyan]𓂀 Domain Takeover Checklist[/bold cyan]")
        items = [
            ("DTC-01","Initial foothold"), ("DTC-02","BloodHound recon"),
            ("DTC-03","AS-REP check"),    ("DTC-04","Kerberoast check"),
            ("DTC-05","ACL abuse check"), ("DTC-06","ADCS check"),
            ("DTC-07","Delegation check"),("DTC-08","GPO check"),
            ("DTC-09","Password spray"),  ("DTC-10","Hash cracking"),
            ("DTC-11","Lateral movement"),("DTC-12","LSASS dump"),
            ("DTC-13","DCSync"),          ("DTC-14","Golden Ticket"),
        ]
        auto_done = {f.get("type","") for f in findings}
        for item_id, name in items:
            done = any(t in item_id for t in ["01","02"])
            icon = "✅" if done else "⬜"
            _p(f"  {icon} {item_id}  {name}")
