"""Pytest bootstrap: put the repo root on sys.path so `import horuseye.*`
resolves when the tests run from a clone without an editable install."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
