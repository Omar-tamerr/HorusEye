"""Re-export HashCrackingEngine from hash_cracker.py for backward compat."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from hash_cracker import HashCrackingEngine
