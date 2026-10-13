# Security Policy

## Intended use

HorusEye is for **authorized** security assessments, lab environments, CTF
practice, and defensive analysis. It analyses data you have already collected
(BloodHound/SharpHound, Certipy, NetExec, ldapdomaindump) and produces findings,
attack paths, remediation and detection guidance. Only use it against systems
you own or have explicit written permission to test.

## Operational impact

- **Detection, scoring, graphing and reporting are passive** — they read
  collected files and never touch the target. They require no external tools
  and make no network connections (the only network call is the optional AI
  narrative; see below).
- **The offensive-execution flags are stubs** in this release
  (`--auto-exploit`, `--auto-chain`, `--lsass-dump`): they print the method and
  commands rather than running them.
- **Active helpers** that do reach the network — `--winrm`, `--pivot`,
  `--spray`, `--team-server`/`--team-connect` — are opt-in and only run when you
  pass those flags with credentials. Password spraying honours `--safe`,
  `--delay`, `--jitter` and lockout thresholds; run it only with authorization.

## Data sent to third parties

HorusEye sends data off the machine **only** when the AI layer is enabled (an
API key configured and `--no-ai` not set). One request per run contains a
compact finding list (id, severity, type, affected principal) — never
credentials, hashes or file contents. `--ai-redact` masks domain, host, account
names, emails and IPs before the request leaves the machine. Run with `--no-ai`
for fully offline operation.

## Reporting a vulnerability

If you find a security issue **in HorusEye itself** (not in a target you are
assessing), please report it privately rather than opening a public issue:

- Use GitHub's **Report a vulnerability** (Security → Advisories) on
  https://github.com/Omar-tamerr/HorusEye, or
- Contact the author via the links in the README.

Please include a description, affected version (`horuseye --help` shows it),
reproduction steps, and impact. We aim to acknowledge reports promptly and will
credit reporters who wish to be named.

## Supported versions

The latest released minor version receives fixes. HorusEye follows semantic
versioning; see [CHANGELOG.md](CHANGELOG.md).

| Version | Supported |
|---------|-----------|
| 2.3.x   | ✅        |
| < 2.3   | ❌ (upgrade) |

## Supported environments

- Python 3.8+ on Linux and Windows (CI runs both).
- Only runtime dependency: `rich`. AI narratives need the optional
  `anthropic` SDK (`pip install horuseye[ai]`).
- Offensive helpers shell out to external tools (hashcat, nxc, impacket,
  certipy, …); `horuseye --check-deps` reports which are present.
