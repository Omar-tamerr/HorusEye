# HorusEye Architecture

HorusEye is a CLI-first, pure-Python package (one runtime dependency: `rich`).
The pipeline is linear and deterministic up to the optional AI step, so the same
input and configuration always produce the same findings, paths and report bytes.

## Pipeline

```
 parsers/            core/                                   reports/
 ┌─────────┐   domain_data   ┌──────────────┐ findings  ┌──────────────┐
 │ ingest  ├───────dict──────▶│ attack_      ├──────────▶│ CLI / HTML / │
 │ sources │                 │ detector     │           │ Markdown /   │
 └─────────┘                 └──────┬───────┘           │ JSON         │
  BloodHound, LDAP,                 │ scored            └──────────────┘
  CME, NetExec, Certipy    path_scorer → knowledge.enrich
                                      │
                             core/graph (--graph)      ai/ (optional, --no-ai to skip)
                             shortest path + remediation core/diff (--diff / --fail-on)
```

## Modules

| Area | Module | Responsibility |
|---|---|---|
| Ingest | `parsers/` | Parse each source into one normalized `domain_data` dict; tag provenance (`source_file`); build a `parse_report` with compatibility warnings |
| Model | `core/principals.py` | Classify every principal: `noise` / `tier0` / `broad` / `normal` (by name, well-known SID, domain RID) |
| Detect | `core/attack_detector.py` | The 13 detection rules → findings (see schema below) |
| Schema | `core/finding.py` | The finding contract: `rule_id`, `confidence`, `evidence`; `attach_schema()` |
| Rank | `core/path_scorer.py` | Severity × exploitability-ease → 0–100 score |
| Enrich | `core/knowledge.py` | ATT&CK technique(s), remediation, detection guidance per finding |
| Graph | `core/graph.py` | Directed control graph; BFS shortest path; observed/inferred edges; remediation impact |
| Retest | `core/diff.py` | New/Fixed/Unchanged by stable id; CI fail-gate |
| Exit | `core/exit_codes.py` | Automation exit-code taxonomy (0/1/2/3) |
| Report | `reports/report_generator.py` | CLI tables, self-contained HTML, Markdown (Mermaid), versioned JSON |
| AI | `ai/claude_analyzer.py`, `ai/redaction.py` | Optional narratives; local redaction; strict output validation |
| Orchestrate | `cli.py` | Argument parsing, stage wiring, rendering |
| Public API | `api.py` | Stable programmatic surface (`detect`, `analyze`, `attack_paths`, `parse_sources`) |

## Finding schema

Produced by the detector + `attach_schema` + scorer + knowledge:

```
id, type, rule_id, title, affected, severity,
confidence, confidence_reason, evidence[{source, object, detail, file}],
score, ease, description, commands[], references[],
mitre[{id,name}], remediation[], detection[], targets[]   # last two where applicable
```

Design rules:
- **Detection is separate from presentation and enrichment.** The rule decides
  *what/where* + evidence; knowledge adds remediation/ATT&CK; AI only ever adds
  `ai_narrative` and can never overwrite a verified field.
- **Evidence is never discarded** to shorten a report — aggregated findings keep
  every affected object.
- **Pathfinding is deterministic** and never consults an LLM.
- **Trust tiers** on findings (`confidence`) and graph edges (`observed` vs
  `inferred`) keep the tool honest about what the data proves.

## Data model (`domain_data`)

A dict of lists: `users`, `groups`, `computers`, `acls`, `sessions`, `gpos`,
`trusts`, `spns`, `asrep_users`, `local_admins`, `delegation_targets`, plus
`adcs`, `cme_data`, `nxc_data`, `password_policy`, `raw_sources`, `parse_report`.
Parsers populate it; detector, graph and reports consume it. Adding a source
means producing this shape; adding a detection means reading it.

## Extending

- **New detection:** add a `_detect_*` to `attack_detector.py`, register it in
  `detect_all()`, emit the schema (with `evidence`), give it an ease weight in
  `path_scorer.py` and an entry in `knowledge.py`, and add a test.
- **New source:** add a parser that returns the `domain_data` shape and merge it
  in `parsers/all_parsers.py`; tag `source_file` for provenance.
- **New graph edge:** add it in `graph.py._build` with a trust tier and a command
  in `_command`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [RELEASING.md](RELEASING.md).
