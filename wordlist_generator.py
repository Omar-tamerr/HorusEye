"""
HorusEye — Username Wordlist Generator
Generates every common AD username format from a list of names
Author: Omar Tamer 🇪🇬
"""

import os
import re
from typing import List, Dict, Set
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box


# All common enterprise username formats
USERNAME_FORMATS = {
    "jsmith":        lambda f, l: f"{f[0].lower()}{l.lower()}",
    "jsmith1":       lambda f, l: f"{f[0].lower()}{l.lower()}1",
    "john.smith":    lambda f, l: f"{f.lower()}.{l.lower()}",
    "john_smith":    lambda f, l: f"{f.lower()}_{l.lower()}",
    "smithj":        lambda f, l: f"{l.lower()}{f[0].lower()}",
    "smith.j":       lambda f, l: f"{l.lower()}.{f[0].lower()}",
    "smith_j":       lambda f, l: f"{l.lower()}_{f[0].lower()}",
    "johnsmith":     lambda f, l: f"{f.lower()}{l.lower()}",
    "john":          lambda f, l: f.lower(),
    "smith":         lambda f, l: l.lower(),
    "j.smith":       lambda f, l: f"{f[0].lower()}.{l.lower()}",
    "j_smith":       lambda f, l: f"{f[0].lower()}_{l.lower()}",
    "johns":         lambda f, l: f"{f.lower()}{l[0].lower()}",
    "JSMITH":        lambda f, l: f"{f[0].upper()}{l.upper()}",
    "John.Smith":    lambda f, l: f"{f.capitalize()}.{l.capitalize()}",
    "sjohn":         lambda f, l: f"{l[0].lower()}{f.lower()}",
    "john.s":        lambda f, l: f"{f.lower()}.{l[0].lower()}",
    "adm_jsmith":    lambda f, l: f"adm_{f[0].lower()}{l.lower()}",
    "svc_jsmith":    lambda f, l: f"svc_{f[0].lower()}{l.lower()}",
}


class WordlistGenerator:
    def __init__(self, console: Console):
        self.console = console

    def run_standalone(self, args):
        """Run wordlist generation without AD data."""
        self.console.print(Rule("[bold red][ 𓂀 USERNAME WORDLIST GENERATOR ][/bold red]"))
        self.console.print()

        names = []

        # Single name input
        if args.firstname and args.lastname:
            names.append((args.firstname, args.lastname))

        # File input
        if args.users_file:
            parsed = self._parse_names_file(args.users_file)
            names.extend(parsed)
            self.console.print(f"  [dim]📂 Loaded {len(parsed)} names from {args.users_file}[/dim]")

        if not names:
            self.console.print("[bold red]❌ Provide --firstname/--lastname or --users-file[/bold red]")
            return

        self._generate_and_save(names, args.output, args.formats)

    def generate_from_users(self, users: List[Dict], output_file: str, formats: str = "all"):
        """Generate wordlist from parsed AD users."""
        self.console.print(Rule("[bold red][ 𓂀 USERNAME WORDLIST GENERATOR ][/bold red]"))
        self.console.print()

        names = []
        raw_usernames = []

        for user in users:
            name = user.get("name", user.get("sAMAccountName", ""))
            if not name:
                continue

            # If it's already a username format (e.g. jsmith), add directly
            if "@" in name:
                raw_usernames.append(name.split("@")[0])
                parts = self._try_split_username(name.split("@")[0])
                if parts:
                    names.append(parts)
            elif " " in name:
                # "John Smith" format
                parts = name.strip().split()
                if len(parts) >= 2:
                    names.append((parts[0], parts[-1]))
                    raw_usernames.append(name)
            else:
                raw_usernames.append(name)
                parts = self._try_split_username(name)
                if parts:
                    names.append(parts)

        self.console.print(f"  [dim]👥 {len(users)} AD users → {len(names)} parseable names[/dim]\n")
        self._generate_and_save(names, output_file, formats, raw_usernames)

    def _generate_and_save(self, names: List[tuple], output_file: str,
                            formats: str = "all", extras: List[str] = None):
        """Generate all username variants and save to file."""
        all_usernames: Set[str] = set()

        # Add raw extras (already-formatted usernames from AD)
        if extras:
            all_usernames.update(extras)

        # Determine which formats to use
        if formats == "all":
            selected_formats = USERNAME_FORMATS
        else:
            format_list = [f.strip() for f in formats.split(",")]
            selected_formats = {k: v for k, v in USERNAME_FORMATS.items() if k in format_list}

        # Generate all variants
        format_counts = {}
        for firstname, lastname in names:
            firstname = self._clean_name(firstname)
            lastname = self._clean_name(lastname)
            if not firstname or not lastname:
                continue

            for fmt_name, fmt_func in selected_formats.items():
                try:
                    username = fmt_func(firstname, lastname)
                    if username and len(username) >= 2:
                        all_usernames.add(username)
                        format_counts[fmt_name] = format_counts.get(fmt_name, 0) + 1
                except Exception:
                    pass

        # Save to file
        sorted_usernames = sorted(all_usernames)
        with open(output_file, "w") as f:
            f.write("\n".join(sorted_usernames))
            f.write("\n")

        # Print summary table
        self.console.print(Panel(
            f"[bold green]✅ Wordlist generated successfully![/bold green]\n\n"
            f"[bold white]📊 Names processed:[/bold white]  [cyan]{len(names)}[/cyan]\n"
            f"[bold white]🔤 Formats applied:[/bold white]  [cyan]{len(selected_formats)}[/cyan]\n"
            f"[bold white]📝 Unique usernames:[/bold white] [bold green]{len(all_usernames)}[/bold green]\n"
            f"[bold white]💾 Saved to:[/bold white]         [cyan]{output_file}[/cyan]",
            title="[bold red][ 𓂀 WORDLIST COMPLETE ][/bold red]",
            border_style="green",
            padding=(1, 4)
        ))
        self.console.print()

        # Show format breakdown
        t = Table(title="Username Format Breakdown", box=box.SIMPLE, show_header=True)
        t.add_column("Format", style="cyan")
        t.add_column("Example", style="dim")
        t.add_column("Count", style="green", justify="right")

        example_first, example_last = ("John", "Smith") if not names else (names[0][0], names[0][1])
        for fmt_name, fmt_func in selected_formats.items():
            try:
                ex = fmt_func(example_first, example_last)
                count = format_counts.get(fmt_name, 0)
                t.add_row(fmt_name, ex, str(count))
            except Exception:
                pass

        self.console.print(t)
        self.console.print()
        self.console.print(f"[bold yellow]💡 Tip:[/bold yellow] Use with spray mode:[/bold yellow] [cyan]horuseye --spray --users-file {output_file} --password 'Password123' --domain DOMAIN --dc DC_IP[/cyan]\n")

    def _parse_names_file(self, filepath: str) -> List[tuple]:
        """Parse names file — handles 'John Smith', 'jsmith', or 'john,smith' formats."""
        names = []
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # "John Smith" format
                    if " " in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            names.append((parts[0], parts[-1]))
                    # "John,Smith" format
                    elif "," in line:
                        parts = line.split(",", 1)
                        names.append((parts[0].strip(), parts[1].strip()))
                    # Already a username — try to split
                    else:
                        parts = self._try_split_username(line)
                        if parts:
                            names.append(parts)
        except FileNotFoundError:
            self.console.print(f"[bold red]❌ File not found: {filepath}[/bold red]")
        return names

    def _try_split_username(self, username: str) -> tuple:
        """Try to split a username like 'jsmith' or 'john.smith' into (first, last)."""
        # john.smith or john_smith
        for sep in [".", "_", "-"]:
            if sep in username:
                parts = username.split(sep, 1)
                if len(parts[0]) > 1 and len(parts[1]) > 1:
                    return (parts[0], parts[1])

        # jsmith — first char is initial
        if len(username) >= 3:
            return (username[0], username[1:])

        return None

    def _clean_name(self, name: str) -> str:
        """Clean name — remove special chars, accents."""
        name = re.sub(r'[^a-zA-Z\s-]', '', name)
        return name.strip()
