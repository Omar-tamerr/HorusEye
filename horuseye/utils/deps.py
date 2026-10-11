"""
External-tool preflight.

HorusEye orchestrates a toolchain it shells out to rather than reimplements.
``--check-deps`` reports which of those tools are on PATH so the operator finds
out before an engagement, not mid-run. Grouped by the HorusEye feature that
needs each one; nothing here is required to parse data and detect paths.
"""
from __future__ import annotations

import shutil

# feature → [(command, purpose)]
_TOOLCHAIN = {
    "Hash cracking": [
        ("hashcat", "GPU/CPU hash cracking (Kerberoast, AS-REP, NTLM)"),
        ("john", "John the Ripper fallback cracker"),
    ],
    "Enumeration / lateral": [
        ("nxc", "NetExec — SMB/LDAP/WinRM enumeration and execution"),
        ("netexec", "NetExec (alternate command name)"),
        ("crackmapexec", "CrackMapExec (legacy NetExec)"),
        ("evil-winrm", "WinRM shell"),
    ],
    "Impacket suite": [
        ("impacket-GetUserSPNs", "Kerberoast TGS request"),
        ("impacket-GetNPUsers", "AS-REP roast"),
        ("impacket-secretsdump", "DCSync / secret extraction"),
        ("impacket-psexec", "remote execution"),
    ],
    "ADCS": [
        ("certipy", "ADCS enumeration and ESC abuse"),
    ],
    "Collection": [
        ("bloodhound-python", "remote BloodHound collector"),
    ],
    "Credential dumping": [
        ("pypykatz", "offline LSASS parsing"),
    ],
}


def check_dependencies(console=None) -> dict:
    """Print a presence table for the external toolchain. Returns a
    {command: bool} map so callers/tests can assert on it."""
    results = {}
    try:
        from rich.table import Table
        from rich import box
        use_rich = console is not None
    except ImportError:
        use_rich = False

    if use_rich:
        table = Table(title="[bold red]𓂀 External Toolchain[/bold red]",
                      box=box.SIMPLE_HEAVY, border_style="red")
        table.add_column("Tool", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Used for", style="dim")
        for group, tools in _TOOLCHAIN.items():
            table.add_row(f"[bold yellow]{group}[/bold yellow]", "", "")
            for cmd, purpose in tools:
                present = shutil.which(cmd) is not None
                results[cmd] = present
                status = "[green]✓ found[/green]" if present else "[red]✗ missing[/red]"
                table.add_row(f"  {cmd}", status, purpose)
        console.print()
        console.print(table)
    else:
        print("\n== HorusEye external toolchain ==")
        for group, tools in _TOOLCHAIN.items():
            print(f"\n[{group}]")
            for cmd, purpose in tools:
                present = shutil.which(cmd) is not None
                results[cmd] = present
                mark = "found  " if present else "MISSING"
                print(f"  [{mark}] {cmd:28} {purpose}")

    missing = [c for c, ok in results.items() if not ok]
    found = len(results) - len(missing)
    msg = f"\n  {found}/{len(results)} tools present."
    if missing:
        msg += (" Core detection works without them; install the missing ones "
                "to enable the matching offense features.")
    if use_rich:
        console.print(f"[dim]{msg}[/dim]\n")
    else:
        print(msg + "\n")
    return results
