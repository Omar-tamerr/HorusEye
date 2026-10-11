# Changelog

All notable changes to HorusEye are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-10-11

The detection engine is now real. v2.0 advertised 13 attack-path types but
only implemented two; v2.1 implements all of them, fixes the Windows crash,
and restructures the project into a proper installable package.

### Added
- **11 new attack-path detections** consuming data the parsers already
  extracted: DCSync, ACL abuse (GenericAll, GenericWrite, WriteDacl,
  WriteOwner, ForceChangePassword, AddMember, AddKeyCredentialLink, WriteSPN),
  GPO abuse, unconstrained delegation, constrained delegation, ADCS ESC1–ESC8,
  domain trusts, privileged sessions, weak password policy, stale admin
  accounts, and reusable admin access (pass-the-hash).
- **Tier-0 privilege model** (built from `adminCount` and well-known group
  membership) that promotes any path leading directly to Domain Admin to
  CRITICAL.
- **Exploitability-aware scoring** — findings are scored 0–100 by combining
  severity with an ease factor, so the shortest path to DA ranks first.
- `--check-deps` preflight that reports which external tools are on PATH,
  grouped by the feature that needs them.
- `pyproject.toml` with a `horuseye` console-script entry point; the tool can
  now be installed with `pip install -e .` and run as `horuseye` or
  `python -m horuseye`.
- `pytest` test suite (parsers, scorer, detection engine) and a GitHub Actions
  CI workflow running on Linux and Windows.
- Finding metadata: each finding now carries a description and a reference link
  in addition to its validation command(s).

### Changed
- **Project restructured into a single `horuseye/` package.** The seven
  top-level packages and the loose root modules now live under `horuseye/`,
  eliminating the `sys.path` shim modules and giving the repository a clean,
  professional root.
- `path_scorer` reworked so CRITICAL is reachable and ordering reflects impact
  × ease rather than a flat severity value.
- `--da-checklist` now auto-ticks its 20 items from the live detection results
  of the current run instead of showing a hardcoded placeholder.
- Version strings, banner and reports bumped to v2.1.
- README rewritten: accurate detection-coverage table, honest scope notes on
  the still-stubbed offense engines, corrected install instructions, and new
  Project Structure, Testing and Roadmap sections.

### Fixed
- **Windows crash:** the banner/finding glyphs (box drawing, `𓂀`, emoji) raised
  `UnicodeEncodeError` on a cp1252 console on every run. stdout/stderr are now
  reconfigured to UTF-8 at startup, and all report/credential/config writes use
  explicit UTF-8 encoding.
- `--team-connect` connected a non-blocking client and then exited immediately,
  and passed the whole `host:port` string as the host. It now stays attached as
  a watcher when no input is given, or streams findings through the broadcaster
  when it is, and parses `host:port` correctly.
- Team-collaboration port unified on `COLLAB_PORT` (31337); the CLI default and
  the broadcaster parser previously disagreed (9999).

### Notes
- The offensive execution engines (`--auto-exploit`, `--auto-chain`,
  `--lsass-dump`) remain stubs that print the method/commands rather than
  executing them. Wiring them to live execution is tracked on the Roadmap as a
  deliberate, opt-in change.

## [2.0.0] - 2025

- Initial public release: multi-source parsing (BloodHound, ldapdomaindump,
  CrackMapExec, NetExec, Certipy), Kerberoasting and AS-REP roasting detection,
  hash-cracking engine, password sprayer, wordlist generator, lateral-movement
  mapper, attack timeline, team collaboration, and HTML/JSON reporting.

[2.1.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.1.0
[2.0.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.0.0
