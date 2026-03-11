"""Re-export from wordlist_generator.py for backward compat."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
try:
    from wordlist_generator import WordlistGenerator
except ImportError:
    class WordlistGenerator:
        def __init__(self, console=None): self.console = console
        def generate_from_users(self, users, output):
            _p = (lambda m: self.console.print(m)) if self.console else print
            _p(f"[dim]Generating wordlist for {len(users)} users → {output}[/dim]")
