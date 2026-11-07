# Changelog

All notable changes to HorusEye are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.5.0] - 2026-11-07

A remediation release: the report now answers "what is most critical that is
an easy fix, and what are my options?", and tracks the work until a retest
verifies it.

### Added
- **Fix effort** (`core/effort.py`, `docs/effort.md`): Low, Medium or High on
  every finding and every proposed change (remediation options, the exposure
  plan, the biggest fixes, the `--keep` alternative), with a plain reason and
  a rule id. Effort is time to apply plus blast radius: an ACE on a non-Tier-0
  object is Low; a group membership, a privileged session or a certificate
  template is Medium; delegation, trusts, domain-wide policy, a GPO linked to
  many objects or a directory sync account's replication rights are High;
  taking access away from a service account is at least Medium. Deterministic,
  documented, tested, no AI. Effort never changes severity (tested).
- **Quick Wins**: Critical or High findings that are a Low-effort fix, first
  in the CLI, HTML and Markdown reports and on the explorer's Overview, with a
  Quick Wins filter in Findings and `"quick_win": true` / `quick_win_rank` in
  the JSON (plus a top-level `quick_wins` list). Ranked by users cut off from
  Tier-0, then users with a route through the finding, then score.
- **Finding cards** in the explorer, HTML and Markdown with labelled parts:
  why it is critical (users cut off, users with a route through it, or for an
  account finding, where that account leads if compromised), why it is an easy
  or hard fix, what to do (each fix with its own effort, and the fewest changes
  that still cut every user off if the access must stay, `--keep`), how to
  verify, and the source (file, collector, object, SID, confidence). Findings
  are now linked to the attack-graph relationships their evidence names
  (`rel_ids`, `impact` in the JSON).
- **Status tracker**: Open, In progress, Fixed, Accepted risk, False positive,
  with notes and a last-changed date. The explorer saves it in the browser
  (every storage access is guarded; the page works if storage is blocked) and
  exports or imports `horuseye-status.json` (schema `horuseye.status/1`: ids,
  status, notes, dates; anything else is dropped). `--status FILE` merges it
  into every output, with counts per status. With `--diff`, a finding marked
  Fixed that is still present is flagged "marked fixed but still found", and a
  finding gone since the baseline is "verified fixed".
- **`--csv FILE`**: one row per finding for spreadsheets (id, title, affected,
  severity, effort and reason, Quick Win, why critical, first fix, validation
  command, source, status, notes), Quick Wins first. Cells that start like a
  formula get a leading apostrophe, since AD names come from the directory.
- `api.triage()`; `api.analyze()` returns `quick_wins`.
- Explorer deep links: `#findings/<id>` opens one finding, `#quickwins` lists
  the Quick Wins.
- CI tests Python 3.13, and the smoke run writes a CSV.

### Changed
- The live demos show Quick Wins, effort and the tracker, with synthetic status
  entries. In the explorer, the findings table shows effort and status instead
  of confidence and rule (both remain in each card).

### Fixed
- Tier-0 checks for effort use the privilege model, so a Tier-0 object that is
  on no route is still treated as Tier-0.

## [2.4.0] - 2026-11-04

An exposure release: HorusEye now measures how many users can reach Tier-0,
finds the fewest changes that take that to zero, lets you try fixes live in
the explorer, and fails CI when a change reopens a route. The graph gains the
routes real domains use most: ADCS, RBCD, SID history, LAPS/gMSA readers and
GPOs.

### Added
- **Domain exposure** (`AttackGraph.exposure()`, `api.exposure()`, JSON
  `exposure`, CLI, HTML and Markdown): enabled users with a route to Tier-0
  (or `--target`), counting routes open to every user through broad groups;
  the **fewest changes to reach 0%** (a minimum cut over every exposed user at
  once, closest to the targets, ordered greedily with the users left after
  each change, `--keep` respected); and the **biggest single fixes** (exact,
  found through shortest-route-tree bounds). Every report states what the
  number does and doesn't model. Checked against brute force on random domains.
- **Live what-if in the explorer.** The Overview opens on the exposure card;
  ✂ Apply a change, or ✂ Cut any relationship from the attack-path inspector,
  and the page re-runs the reverse reachability search in the browser. Cut
  relationships show on the graph. The embedded graph is only what can reach a
  target, and tests check the page's numbers against the engine's.
- **Route and exposure drift.** `--diff` now compares attack routes (by their
  steps, so v2.3 reports still compare; different footholds aren't compared)
  and exposure (who gained a route, who lost one). `--fail-on` is repeatable
  and adds `new-route` and `exposure-up`, which exit **4 (DRIFT)**; both need
  `--diff`. The JSON gains a `retest` block.
- **New attack-path relationships:**
  - **ADCS** from Certipy: ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC11 and
    ESC15 become routes to domain control, from the principals Certipy names
    (else the template's enrollment or control rights; any domain user for the
    relay findings ESC8/ESC11). Tier-0 enrollees and disabled templates are
    skipped. Each step has the certipy commands and the fix for that ESC.
  - **Resource-based delegation**: configured (`AllowedToAct`, inferred), and
    writable through `AddAllowedToAct` / `WriteAccountRestrictions`.
  - **SID history** (`HasSIDHistory`), **LAPS** (`ReadLAPSPassword`) and
    **gMSA** (`ReadGMSAPassword`) password readers.
  - **GPOs applied through OU links** (`GPLink`, inferred): a GPO reaches every
    user and computer below the OU or domain it's linked to, except under an OU
    that blocks inheritance, unless the link is enforced. GPO links are never
    proposed as the fix; who can edit the GPO is.
- `examples/karnak-lab`: a synthetic 1,245-user domain (SharpHound + Certipy)
  where every user can reach Domain Admin and four changes take it to zero;
  rebuilt deterministically by `scripts/make_karnak_lab.py`. A second live
  demo, `docs/exposure-demo.html`; `scripts/build_demo.py` builds both.
- Explorer: icons, labels, explanations and fixes for the new relationship
  types; fix text now comes from the engine.
- Validation commands by target type for ACL takeover: RBCD for computers,
  `net rpc group addmem` for groups, pyGPOAbuse for GPOs, targeted Kerberoast
  for `WriteSPN`.

### Changed
- **A foothold holds what every user can do.** With `--owned`, routes open to
  Domain Users / Authenticated Users / Everyone are followed too, through an
  explicit membership step that is never proposed as a fix. Before, a plan
  could claim to break every route while such a route remained.
- Route search tries observed relationships before inferred ones, so between
  two routes of the same length the better-evidenced one is shown first.
- JSON schema `horuseye.report/4` (adds `exposure`, `retest`; steps gain
  `fix`). `diff.load_previous` still reads v1–v3.
- With `--json`, `--report`, `--markdown` or `--diff`, attack routes are
  computed even without `--graph`, so reports and retests always have them.

### Fixed
- **Real Certipy exports produced no ADCS findings.** The parser read
  `Vulnerabilities` and top-level `Enrollment Rights`; Certipy writes
  `[!] Vulnerabilities` and nests rights under `Permissions`. It also treated
  `"Web Enrollment": "Disabled"` as enabled and ignored CA-level findings
  (ESC6/7/8/11). All fixed, and the older flat layout still parses.

### Changed (from the previous `main`)
- **Redesigned attack-path view in the explorer** (`--explorer`): a route picker,
  node-type icons and FOOTHOLD/TARGET markers, readable relationship labels,
  animated highlighting of the selected route, a step-by-step walkthrough with
  copyable validation commands, an inspector for any node or relationship
  (meaning, validation, remediation impact, fix, related findings), and a
  "Fix this first" panel. The graph lays out left-to-right when it fits and
  top-to-bottom otherwise, so it works on phones. Tabs are linkable
  (`#overview`, `#paths`, `#findings`), and the logo is an inline SVG that
  renders on every device.
- Remediation impact now covers every edge on every displayed route, not only
  the shortest one.
- The CLI summary line and findings table now say "findings" instead of
  "paths"/"Attack Path(s)" — they count findings, not attack paths.

### Fixed (from the previous `main`)
- **Full analysis crashed on Python 3.8–3.11** with "f-string expression part
  cannot include a backslash" (`features/creds_manager.py`): syntax only Python
  3.12 accepts, in a module the tests never imported. New guards: every module is
  compiled and imported on each CI Python, a test flags 3.12-only f-strings when
  run on 3.12+, and CI now smoke-tests a full analysis of the bundled lab.
- **Remediation impact could overstate choke points.** It removed the whole
  node an edge pointed to instead of the edge itself, so a second route into
  the same object was missed and an edge could be wrongly reported as the
  single fix. It now removes exactly one relationship (parallel rights on the
  same object stay distinct), with regression tests.

### Added (from the previous `main`)
- **Remediation options that account for the business.** After the attack
  paths, HorusEye compares alternative fixes: *Fewest changes*, *Keep group
  memberships* (narrow the groups' permissions instead of removing anyone) and
  *Fix nearest the targets*. Each is a minimum set of changes (max-flow /
  min-cut) that breaks **every route in the imported graph** — including
  routes not displayed — and is re-checked by search. Every change says who is affected and what they
  lose: a removed membership lists all the rights the user loses with it; a
  narrowed group permission lists every member who loses that one right.
  Shown in the CLI, the explorer (pick an option and the ✂ marks move on the
  graph), the HTML and Markdown reports, and JSON (`remediation_plans`).
- **`--keep 'SRC->DST'`** marks access people need for their job; no
  remediation option removes it, and a choke point that is kept is labelled as
  such. A `--keep` that matches nothing in the data is flagged as a likely typo.
- `api.remediation_plans()`; `api.analyze(..., keep=)` includes the options.
- **Web app → AD service account import, milestone 1** (`--webapps FILE`,
  draft format `horuseye.webapps/1-draft`, designed with Adrian Korwel).
  Three separate, evidence-backed claims per app: *reachable from vantage*,
  *uses account*, *privileges obtainable*. Claims cite evidence by id; one
  request-linked execution record can support both of the last two.
  - Importing never marks the account as owned. Without a confirmed third
    claim, routes through the account are reported separately as
    **conditional** ("Hypothetical: if WEB-SVC is compromised"), and the claim
    keeps its `not_assessed` status. An explicit `assumed` claim needs a
    rationale.
  - New trust levels `validated` (demonstrated, with evidence) and `assumed`.
    Even on a validated route, AD steps keep their own label.
  - A distinct `Reaches` step for vantage → app: reachability, not control,
    and never proposed as a fix.
  - Strict validation with explicit errors: unique evidence ids, references
    resolved within the app, `triggered_by` must be a request, execution SID
    and host must match the mapping, no credential-like fields or raw
    response bodies (a safeguard only: evidence must be sanitized). A mapping
    binds to the directory by SID, never by name; config/execution conflicts
    are surfaced, not resolved.
  - Every relationship now has a stable id (e.g. `AdminTo:WEB-SVC->WEB01.ACME.LAB`).
  - Two lab fixtures (`examples/acme-lab-webapp/`) with and without execution
    evidence. `acme-lab` gains `WEB-SVC` (local admin on `WEB01`); the demo's
    findings, routes and fix options are unchanged.
  - BloodHound user records now keep their SID.
- `scripts/build_demo.py` rebuilds the website's live demo; demo-only extras
  (back-to-home bar, "synthetic data" label, link-preview tags, Attack Paths as
  the landing view) are opt-in and never appear in normal reports.
- Website: link-preview image (`scripts/make_og_image.py`) and Open Graph /
  Twitter tags, live release and CI badges, an SVG logo, and a comparison table
  rewritten from SpecterOps' public documentation.
- The `acme-lab` example now has two independent routes to domain control and a
  single choke point.

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
- **Performance harness** (`scripts/benchmark.py`) + a deterministic synthetic
  domain generator (`horuseye/synthetic.py`) with labeled ground truth. At 5000
  users: detect ~2ms, graph ~18ms, ~2MB peak. Stress tests cover large graphs,
  duplicate relationships, disconnected graphs, malformed input, and measure
  100% recall on planted findings.
- **Stable public Python API** (`horuseye.api`): `detect`, `analyze`,
  `attack_paths`, `remediation_impact`, `parse_sources`.
- **Example dataset** (`examples/acme-lab/`, synthetic) with a reproducible demo,
  plus `docs/ARCHITECTURE.md` and `docs/RELEASING.md`.
- **Interactive offline explorer** (`--explorer FILE`): one self-contained HTML
  file — Overview dashboard, clickable attack-path graph (nodes/edges → evidence,
  choke points highlighted), and a filterable Findings explorer. No server, no
  external requests; safe to hand to a client.

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

[2.5.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.5.0
[2.4.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.4.0
[2.3.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.3.0
[2.2.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.2.0
[2.1.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.1.0
[2.0.0]: https://github.com/Omar-tamerr/HorusEye/releases/tag/v2.0.0
