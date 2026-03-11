"""
HorusEye v2 — Hash Cracking Engine
Built-in hashcat wrapper with wordlist & rules manager
Author: Omar Tamer 🇪🇬
"""

import os
import subprocess
import shutil
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# ── Try importing Rich (graceful fallback if not installed) ──────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None


# ── Hash type definitions ────────────────────────────────────────────────────

HASH_MODES: Dict[str, Dict] = {
    "ntlm":       {"mode": "1000",  "name": "NTLM",               "ext": ".ntlm"},
    "ntlmv2":     {"mode": "5600",  "name": "NetNTLMv2",          "ext": ".ntlmv2"},
    "kerberoast": {"mode": "13100", "name": "Kerberoast (TGS-RC4)","ext": ".kerb"},
    "asrep":      {"mode": "18200", "name": "AS-REP Roast",        "ext": ".asrep"},
    "mscache2":   {"mode": "2100",  "name": "MS-Cache v2 (DCC2)", "ext": ".dcc2"},
    "md5":        {"mode": "0",     "name": "MD5",                 "ext": ".md5"},
    "sha1":       {"mode": "100",   "name": "SHA-1",               "ext": ".sha1"},
    "sha256":     {"mode": "1400",  "name": "SHA-256",             "ext": ".sha256"},
}

# ── Built-in wordlist locations (Kali Linux standard paths) ──────────────────

BUILTIN_WORDLISTS: Dict[str, str] = {
    "rockyou":      "/usr/share/wordlists/rockyou.txt",
    "fasttrack":    "/usr/share/wordlists/fasttrack.txt",
    "darkweb2017":  "/usr/share/wordlists/darkweb2017-top10000.txt",
    "seclists-top": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "seclists-ad":  "/usr/share/seclists/Passwords/darkweb2017-top100.txt",
}

# ── Built-in hashcat rule sets (Kali Linux standard paths) ───────────────────

BUILTIN_RULES: Dict[str, str] = {
    "best64":       "/usr/share/hashcat/rules/best64.rule",
    "dive":         "/usr/share/hashcat/rules/dive.rule",
    "d3ad0ne":      "/usr/share/hashcat/rules/d3ad0ne.rule",
    "toggles1":     "/usr/share/hashcat/rules/toggles1.rule",
    "rockyou-30000":"/usr/share/hashcat/rules/rockyou-30000.rule",
}

# ── AD-specific password base patterns ──────────────────────────────────────

_AD_BASE_PATTERNS = [
    "Password",   "Welcome",    "Summer",    "Winter",
    "Spring",     "Fall",       "Admin",     "Change",
    "P@ssword",   "P@ssw0rd",   "Qwerty",    "Letmein",
]

_AD_SUFFIXES = ["1", "12", "123", "1234", "!", "@", "#", "1!", "123!"]


def _generate_ad_patterns(domain: str = "", year: Optional[int] = None) -> List[str]:
    """Generate AD-specific password candidates including company name and year combos."""
    if year is None:
        year = datetime.now().year

    patterns: List[str] = []
    company = domain.split(".")[0].capitalize() if domain else "Company"

    # Base patterns + suffixes
    for base in _AD_BASE_PATTERNS:
        for suffix in _AD_SUFFIXES:
            patterns.append(f"{base}{suffix}")

    # Year combos
    for y in [year - 1, year, year + 1]:
        for suffix in ["", "!", "@", "#"]:
            patterns += [
                f"Password{y}{suffix}",
                f"Welcome{y}{suffix}",
                f"Summer{y}{suffix}",
                f"Winter{y}{suffix}",
                f"{company}{y}{suffix}",
                f"{company.lower()}{y}{suffix}",
                f"{company.upper()}{y}{suffix}",
            ]

    # Season + year
    seasons = ["Summer", "Winter", "Spring", "Fall", "Autumn"]
    for season in seasons:
        for y in [year - 1, year]:
            patterns += [f"{season}{y}!", f"{season}{y}@", f"{season}{y}1"]

    # Company name variations
    for suffix in _AD_SUFFIXES:
        patterns += [
            f"{company}{suffix}",
            f"{company.lower()}{suffix}",
        ]

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


# ── Hash type auto-detection ─────────────────────────────────────────────────

def detect_hash_type(sample: str) -> str:
    """Detect hash type from a sample hash string."""
    s = sample.strip()
    if s.startswith("$krb5tgs$23$") or s.startswith("$krb5tgs$18$"):
        return "kerberoast"
    if s.startswith("$krb5asrep$23$") or s.startswith("$krb5asrep$18$"):
        return "asrep"
    if s.startswith("$DCC2$"):
        return "mscache2"
    # NetNTLMv2: username::domain:challenge:response:...
    if "::" in s and s.count(":") >= 5:
        return "ntlmv2"
    # Check pure hex lengths (longest first to avoid misclassification)
    pure_hex = all(c in "0123456789abcdefABCDEF" for c in s)
    if len(s) == 64 and pure_hex:
        return "sha256"
    if len(s) == 40 and pure_hex:
        return "sha1"
    # NTLM: 32 hex chars
    if len(s) == 32 and pure_hex:
        return "ntlm"
    return "ntlm"


# ── Potfile parser ───────────────────────────────────────────────────────────

def parse_potfile(potfile_path: str) -> Dict[str, str]:
    """
    Parse a hashcat potfile.
    Returns {hash_value: plaintext_password}
    Handles NTLM format (hash:plain) and full hash formats ($krb5...:plain).
    """
    results: Dict[str, str] = {}
    path = Path(potfile_path)
    if not path.exists():
        return results

    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line or line.startswith("#"):
                continue
            # Find the last colon that separates hash from plaintext.
            # For complex hashes like $krb5tgs$..., we split on the LAST colon.
            idx = line.rfind(":")
            if idx == -1:
                continue
            hash_val  = line[:idx]
            plaintext = line[idx + 1:]
            if hash_val and plaintext is not None:
                results[hash_val] = plaintext

    return results


# ── Main engine ──────────────────────────────────────────────────────────────

class HashCrackingEngine:
    """
    Multi-round hashcat wrapper.

    Round 1 — AD-specific pattern list (fast, high hit rate on corporate domains)
    Round 2 — Wordlist + rules (rockyou + best64 by default)
    Round 3 — Hybrid mask: wordlist word + year/number suffix (optional, for small sets)

    All cracked credentials are appended to valid_credentials.txt automatically.
    """

    def __init__(self, console=None, output_dir: str = "./horuseye_output"):
        self.console = console
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cracked: Dict[str, str] = {}   # hash -> plaintext (cumulative)
        self._lock = threading.Lock()

    # ── Public API ───────────────────────────────────────────────────────

    def crack(
        self,
        hashes: List[str],
        hash_type: str = "auto",
        wordlist: str = "rockyou",
        rules: str = "best64",
        domain: str = "",
        hybrid: bool = True,
        timeout: int = 300,
    ) -> Dict[str, str]:
        """
        Crack a list of hashes.

        Args:
            hashes:    List of raw hash strings.
            hash_type: One of HASH_MODES keys, or "auto" to detect automatically.
            wordlist:  Key from BUILTIN_WORDLISTS or a direct file path.
            rules:     Key from BUILTIN_RULES or a direct file path.
            domain:    Target domain name — used to generate company-specific patterns.
            hybrid:    Run hybrid mask attack as round 3 (word + year mask).
            timeout:   Max seconds per hashcat invocation.

        Returns:
            Dict mapping cracked hash → plaintext password.
        """
        if not hashes:
            self._print("⚠️  No hashes provided.")
            return {}

        # Auto-detect type
        if hash_type == "auto":
            hash_type = detect_hash_type(hashes[0])

        mode_info = HASH_MODES.get(hash_type, HASH_MODES["ntlm"])
        mode      = mode_info["mode"]

        self._print_header(hash_type, mode_info, hashes, wordlist, rules, domain)

        if not shutil.which("hashcat"):
            self._print("❌  hashcat not found — install with: apt install hashcat")
            return {}

        # Write hashes to temp file
        ts = int(time.time())
        hash_file = self.output_dir / f"hashes_{hash_type}_{ts}.txt"
        potfile   = self.output_dir / f"crack_{hash_type}_{ts}.pot"
        hash_file.write_text("\n".join(hashes) + "\n")

        session_results: Dict[str, str] = {}

        # ── Round 1: AD patterns ─────────────────────────────────────────
        self._print("\n⚡ Round 1 — AD-specific password patterns...")
        patterns     = _generate_ad_patterns(domain)
        pattern_file = self.output_dir / f"ad_patterns_{ts}.txt"
        pattern_file.write_text("\n".join(patterns) + "\n")

        self._run_hashcat(
            hash_file, str(pattern_file), mode, potfile,
            rules_file=None, label="AD Patterns", timeout=timeout
        )
        round1 = parse_potfile(str(potfile))
        new = {k: v for k, v in round1.items() if k not in session_results}
        session_results.update(new)
        self._print(f"   Round 1: {len(new)} new crack(s)")

        # ── Round 2: Wordlist + rules ────────────────────────────────────
        remaining = [h for h in hashes if h not in session_results]
        if remaining:
            self._print(f"\n⚡ Round 2 — Wordlist attack ({wordlist} + {rules} rules)...")
            wl_path = self._resolve_wordlist(wordlist)
            if wl_path:
                # Update hash file to remaining only
                hash_file.write_text("\n".join(remaining) + "\n")
                rules_path = self._resolve_rules(rules)
                self._run_hashcat(
                    hash_file, wl_path, mode, potfile,
                    rules_file=rules_path, label="Wordlist+Rules", timeout=timeout
                )
                round2 = parse_potfile(str(potfile))
                new2 = {k: v for k, v in round2.items() if k not in session_results}
                session_results.update(new2)
                self._print(f"   Round 2: {len(new2)} new crack(s)")
            else:
                self._print(f"   ⚠️  Wordlist '{wordlist}' not found — skipping Round 2")
                self._print("   Hint: apt install wordlists  |  gunzip /usr/share/wordlists/rockyou.txt.gz")

        # ── Round 3: Hybrid mask (optional, only for small sets) ─────────
        remaining2 = [h for h in hashes if h not in session_results]
        if hybrid and remaining2 and len(remaining2) <= 50:
            self._print(f"\n⚡ Round 3 — Hybrid mask attack ({len(remaining2)} hashes)...")
            hash_file.write_text("\n".join(remaining2) + "\n")
            round3 = self._run_hybrid_masks(hash_file, mode, potfile, timeout)
            new3 = {k: v for k, v in round3.items() if k not in session_results}
            session_results.update(new3)
            self._print(f"   Round 3: {len(new3)} new crack(s)")

        # ── Finalise ─────────────────────────────────────────────────────
        with self._lock:
            self.cracked.update(session_results)

        self._print_results(hashes, session_results, hash_type)

        if session_results:
            self._save_cracked(session_results, domain)

        # Cleanup temp files
        for f in [hash_file, pattern_file]:
            try:
                f.unlink()
            except Exception:
                pass

        return session_results

    def crack_file(
        self,
        hash_file_path: str,
        hash_type: str = "auto",
        wordlist: str = "rockyou",
        rules: str = "best64",
        domain: str = "",
    ) -> Dict[str, str]:
        """Convenience wrapper — reads hashes from a file then calls crack()."""
        path = Path(hash_file_path)
        if not path.exists():
            self._print(f"❌  Hash file not found: {hash_file_path}")
            return {}
        hashes = [line.strip() for line in path.read_text().splitlines() if line.strip()]
        if not hashes:
            self._print("❌  Hash file is empty.")
            return {}
        return self.crack(hashes, hash_type, wordlist, rules, domain)

    def show_wordlists(self):
        """Print available wordlists and whether they exist on disk."""
        rows = []
        for name, path in BUILTIN_WORDLISTS.items():
            exists = Path(path).exists()
            size = ""
            if exists:
                sz = Path(path).stat().st_size
                size = f"{sz // 1_048_576} MB" if sz > 1_048_576 else f"{sz // 1024} KB"
            rows.append((name, path, exists, size))
        self._print_table(
            ["Name", "Path", "Exists", "Size"],
            rows,
            title="Available Wordlists"
        )

    def show_rules(self):
        """Print available rule sets and whether they exist on disk."""
        rows = [(name, path, Path(path).exists()) for name, path in BUILTIN_RULES.items()]
        self._print_table(
            ["Name", "Path", "Exists"],
            rows,
            title="Available Rule Sets"
        )

    # ── Private helpers ──────────────────────────────────────────────────

    def _run_hashcat(
        self,
        hash_file: Path,
        wordlist: str,
        mode: str,
        potfile: Path,
        rules_file: Optional[str],
        label: str,
        timeout: int,
    ) -> bool:
        """Run a single hashcat wordlist attack. Returns True on success."""
        cmd = [
            "hashcat",
            "-m", mode,
            "-a", "0",                      # straight attack
            str(hash_file),
            wordlist,
            "--potfile-path", str(potfile),
            "--quiet",
            "--force",                       # ignore GPU warnings (VM/container)
            "--status-timer", "10",
        ]
        if rules_file and Path(rules_file).exists():
            cmd += ["-r", rules_file]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return True
        except subprocess.TimeoutExpired:
            self._print(f"   ⏰  Timeout after {timeout}s ({label})")
            return False
        except FileNotFoundError:
            self._print("   ❌  hashcat binary not found")
            return False
        except Exception as e:
            self._print(f"   ❌  hashcat error: {e}")
            return False

    def _run_hybrid_masks(
        self,
        hash_file: Path,
        mode: str,
        potfile: Path,
        timeout: int,
    ) -> Dict[str, str]:
        """
        Round 3 — hybrid attack: wordlist + numeric/special mask.
        Tries patterns like Password2024!, Admin@2025, etc.
        """
        results: Dict[str, str] = {}
        wl = self._resolve_wordlist("rockyou")
        if not wl:
            return results

        # Common suffix masks
        masks = [
            "?d?d?d?d",     # 4 digits  (year / PIN)
            "?d?d?d?d?d",   # 5 digits
            "!?d?d?d?d",    # !year
            "@?d?d?d?d",    # @year
            "?d?d?d?d!",    # year!
        ]

        for mask in masks:
            cmd = [
                "hashcat",
                "-m", mode,
                "-a", "6",              # hybrid: wordlist + mask
                str(hash_file),
                wl, mask,
                "--potfile-path", str(potfile),
                "--quiet", "--force",
            ]
            try:
                subprocess.run(cmd, capture_output=True, timeout=min(timeout, 60))
                results.update(parse_potfile(str(potfile)))
            except (subprocess.TimeoutExpired, Exception):
                pass

        return results

    def _resolve_wordlist(self, name: str) -> Optional[str]:
        """Resolve wordlist name to an absolute path, or return None."""
        if Path(name).exists():
            return name
        builtin = BUILTIN_WORDLISTS.get(name)
        if builtin and Path(builtin).exists():
            return builtin
        # Try bare filename in common dirs
        for d in ["/usr/share/wordlists", "/usr/share/seclists/Passwords"]:
            for candidate in [f"{d}/{name}", f"{d}/{name}.txt"]:
                if Path(candidate).exists():
                    return candidate
        return None

    def _resolve_rules(self, name: str) -> Optional[str]:
        """Resolve rules name to an absolute path, or return None."""
        if Path(name).exists():
            return name
        builtin = BUILTIN_RULES.get(name)
        if builtin and Path(builtin).exists():
            return builtin
        return None

    def _save_cracked(self, results: Dict[str, str], domain: str):
        """Append cracked hashes to valid_credentials.txt."""
        out = self.output_dir / "valid_credentials.txt"
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(out, "a") as f:
            f.write(f"\n# === Cracked hashes — {ts} — domain: {domain or 'N/A'} ===\n")
            for h, pwd in results.items():
                f.write(f"{h}:{pwd}\n")
        self._print(f"\n💾  Cracked creds saved → {out}")

    # ── Display helpers ──────────────────────────────────────────────────

    def _print(self, msg: str):
        """Print with Rich if available, else plain print."""
        if self.console and RICH_AVAILABLE:
            self.console.print(msg)
        else:
            # Strip Rich markup for plain output
            import re
            clean = re.sub(r"\[/?[^\]]*\]", "", msg)
            print(clean)

    def _print_header(self, hash_type, mode_info, hashes, wordlist, rules, domain):
        header = (
            f"\n{'='*55}\n"
            f"  𓂀  HorusEye v2 — Hash Cracking Engine  🇪🇬\n"
            f"{'='*55}\n"
            f"  Hash type : {mode_info['name']} (mode {mode_info['mode']})\n"
            f"  Hashes    : {len(hashes)}\n"
            f"  Wordlist  : {wordlist}\n"
            f"  Rules     : {rules}\n"
            f"  Domain    : {domain or 'N/A'}\n"
            f"  Output    : {self.output_dir}\n"
            f"{'='*55}"
        )
        if self.console and RICH_AVAILABLE:
            self.console.print(
                Panel(
                    f"[bold white]Hash Type:[/bold white]  [cyan]{mode_info['name']}[/cyan] (mode {mode_info['mode']})\n"
                    f"[bold white]Hashes:  [/bold white]  [cyan]{len(hashes)}[/cyan]\n"
                    f"[bold white]Wordlist:[/bold white]  [cyan]{wordlist}[/cyan]\n"
                    f"[bold white]Rules:   [/bold white]  [cyan]{rules}[/cyan]\n"
                    f"[bold white]Domain:  [/bold white]  [cyan]{domain or 'N/A'}[/cyan]",
                    title="[bold red][ 𓂀 HASH CRACKING ENGINE ][/bold red]",
                    border_style="red",
                    padding=(0, 3),
                )
            )
        else:
            print(header)

    def _print_results(self, hashes: List[str], results: Dict[str, str], hash_type: str):
        total   = len(hashes)
        cracked = len(results)
        pct     = int(cracked / total * 100) if total else 0

        if self.console and RICH_AVAILABLE:
            color = "green" if cracked > 0 else "yellow"
            self.console.print(
                Panel(
                    f"[bold white]Total   :[/bold white] [cyan]{total}[/cyan]\n"
                    f"[bold green]Cracked :[/bold green] [bold green]{cracked}[/bold green] ({pct}%)\n"
                    f"[bold red]Remaining:[/bold red] [red]{total - cracked}[/red]",
                    title="[bold red][ RESULTS ][/bold red]",
                    border_style=color,
                    padding=(0, 3),
                )
            )
            if results:
                t = Table(box=box.SIMPLE, title="🔓 Cracked")
                t.add_column("Hash (truncated)", style="dim")
                t.add_column("Password", style="bold green")
                for h, p in list(results.items())[:30]:
                    display_h = (h[:45] + "...") if len(h) > 48 else h
                    t.add_row(display_h, p)
                self.console.print(t)
        else:
            print(f"\n{'='*55}")
            print(f"  Results: {cracked}/{total} cracked ({pct}%)")
            if results:
                print(f"\n  {'Hash (truncated)':<48}  Password")
                print(f"  {'-'*48}  {'-'*20}")
                for h, p in list(results.items())[:30]:
                    display_h = (h[:45] + "...") if len(h) > 48 else h
                    print(f"  {display_h:<48}  {p}")
            print(f"{'='*55}\n")

    def _print_table(self, headers: List[str], rows: list, title: str = ""):
        if self.console and RICH_AVAILABLE:
            t = Table(box=box.SIMPLE, title=title, show_header=True)
            for h in headers:
                t.add_column(h)
            for row in rows:
                str_row = []
                for cell in row:
                    if isinstance(cell, bool):
                        str_row.append("[green]✓[/green]" if cell else "[red]✗[/red]")
                    else:
                        str_row.append(str(cell))
                t.add_row(*str_row)
            self.console.print(t)
        else:
            print(f"\n{title}")
            print("  " + "  ".join(headers))
            for row in rows:
                print("  " + "  ".join(str(c) for c in row))
