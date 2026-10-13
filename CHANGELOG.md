# Changelog

All notable changes to HorusEye are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-10-13

A trust-and-evidence release: findings, graph and reports now stand behind
their claims, and the output is automation-grade. Driven by a full repository
audit against the "professional AD platform" brief.

### Added
- **Finding evidence & confidence schema** (`core/finding.py`): every finding
  carries `rule_id` (more specific than `type`, e.g. `ACL_ABUSE.genericall`),
  `confidence` + rationale, and structured `evidence` (the actual ACEs/objects),
  so any finding is reproducible from source data. Evidence is retained in full
  even when the presentation is aggregated.
- **Parser provenance**: ACEs are tagged with their `source_file`, carried into
  DCSync/ACL/GPO evidence — a finding traces to its exact source file+object. A
  `parse_report` (counts, sources, compatibility warnings) distinguishes a clean
  domain from a thin import, printed and included in the JSON.
- **Graph trust**: `--target` paths to arbitrary critical assets (not just
  Tier-0); edges are labelled observed vs inferred; paths rank by hops then
  fewer inferred steps with a stated rationale; `remediation_impact()` reports
  the choke points — the single fixes that break the path with no alternative.
- **Deterministic output**: report timestamps are injectable and honour
  `SOURCE_DATE_EPOCH`, so HTML/Markdown/JSON are byte-identical for the same
  input + config.
- **Exit-code taxonomy** (`core/exit_codes.py`): 0 OK, 1 ERROR, 2 FINDINGS
  (`--fail-on`), 3 INCOMPLETE (a source parsed nothing usable — a clean result
  there is not trusted).
- **Redaction hardening** (`ai/redaction.py`): masks emails, IPv4, and
  domain/host/account names before transmission; restored locally.
- `SECURITY.md` with intended use, operational impact, data-egress policy,
  vulnerability reporting, and a supported-environment matrix.

### Changed
- AI output is validated before use and can only populate `ai_narrative`; it can
  never overwrite a verified field (severity, evidence, remediation, commands).
- Reports show confidence and an evidence list per finding; JSON stays
  `horuseye.report/3` (additive) and now includes `parse_report`.

### Fixed
- The no-input help documented a phase-based CLI (`horuseye recon|enum|...`) that
  never existed and errored when used; it now describes the real flat-flag CLI.
- `engine/auto_exploit.py` is clearly flagged as an unwired reference (nothing
  imports it; the active flags run the stubs).

## [2.2.0] - 2026-10-12

Turns HorusEye from a finding list into a path-aware analyzer that serves
both red and blue teams, and makes it trustworthy on real SharpHound exports.

### Added
- **Attack-path graph engine** (`--graph`): builds a directed control graph
  from group membership, abusable ACL edges, local-admin rights, sessions,
  DCSync rights and delegation, then BFS-finds the shortest route from a
  foothold to Domain Admin and prints the ordered steps with the command for
  each. `--owned USER@DOMAIN` sets the foothold (default: any domain user);
  `--max-paths` bounds how many node-diverse routes are shown.
- **Knowledge base**: every finding now carries MITRE ATT&CK technique(s),
  concrete remediation steps and detection guidance (event IDs / telemetry),
  so one report is actionable for defenders too.
- **Markdown report** (`--markdown`) with Mermaid attack-path diagrams;
  **professional HTML** rework (severity tiles, ATT&CK coverage table,
  per-finding remediation/detection); **JSON** gains a versioned schema
  (`horuseye.report/2`) with a summary block and the computed attack paths.
- **Retest diff** (`--diff OLD.json`): New / Fixed / Unchanged against a
  previous JSON report, by stable finding id.
- **CI gate** (`--fail-on LEVEL`): non-zero exit when a finding at/above a
  severity exists.
- Richer BloodHound parsing: local-admin edges (legacy + CE formats),
  constrained-delegation targets, and merged session sources.
- AI layer: `--ai-redact` masks domain/principal names before they leave the
  machine; `--ai-model` selects the model.

### Changed
- **Noise reduction** for real exports: DCSync requires genuine replication
  capability and skips expected replicators; ACL/GPO findings drop noise and
  already-Tier-0 principals, dedupe, and aggregate mass grants; broad-group
  grants are flagged. A shared principal model (`core/principals.py`) backs
  this and the graph.
- Every finding gets a stable id; findings are enriched with ATT&CK /
  remediation / detection in the pipeline.
- AI layer rewritten on the official `anthropic` SDK (optional dependency
  `horuseye[ai]`), current model `claude-opus-5-5`, per-finding narratives,
  and surfaced errors.

### Fixed
- AI narratives were keyed by finding type, so same-type findings shared one
  narrative — now keyed by finding id.
- The AI layer no longer swallows all errors silently.

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

[2.3.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.3.0
[2.2.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.2.0
[2.1.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.1.0
[2.0.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.0.0
