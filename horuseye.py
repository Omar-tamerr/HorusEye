#!/usr/bin/env python3
"""Convenience launcher so `python horuseye.py ...` keeps working from a clone.
The CLI implementation lives in the package at horuseye/cli.py; installed users
get the `horuseye` command (see pyproject.toml) or can run `python -m horuseye`.
"""
from horuseye.cli import main

if __name__ == "__main__":
    main()
