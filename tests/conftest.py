"""Pytest bootstrap: put the repo root on sys.path so the flat-layout
packages (core, parsers, ...) import when tests run from anywhere."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
