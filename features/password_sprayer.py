"""Re-export from password_sprayer.py for backward compat."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
try:
    from password_sprayer import PasswordSprayer
except ImportError:
    class PasswordSprayer:
        def __init__(self, console=None): self.console = console
        def run(self, args): return []
