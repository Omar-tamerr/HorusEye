# Release checklist

HorusEye follows [semantic versioning](https://semver.org): MAJOR for breaking
changes, MINOR for backward-compatible features, PATCH for fixes.

1. **Green suite** — `pytest -q` passes on Linux and Windows (CI covers both).
2. **Smoke** — `horuseye --help`, `horuseye --check-deps`, and the example run
   in `examples/README.md` all work.
3. **Version bump** — update the version in `pyproject.toml` and
   `horuseye/__init__.py` (`__version__`), and the banner/report strings. Leave
   the collaboration `PROTOCOL_VERSION` unless the wire protocol changed.
4. **CHANGELOG** — add a dated section under the new version; move items out of
   "Unreleased"; add the release link at the bottom.
5. **README** — update "What's New", the test count, and any new flags.
6. **JSON schema** — if the report JSON changed shape, bump `schema`
   (`horuseye.report/N`) and confirm `diff.load_previous` still reads the old
   version (back-compat test).
7. **Determinism** — confirm `SOURCE_DATE_EPOCH=… horuseye … --json a.json` twice
   produces identical bytes.
8. **Commit & tag** — commit the release docs, then
   `git tag -a vX.Y.Z -m "…"` and push the tag.
9. **GitHub release** — paste the CHANGELOG section as the release notes.
10. **Website** — the landing site lives in `docs/` (`index.html`, `assets/`,
    `demo.html`). Enable it once under **Settings → Pages → Source: `main` /
    `/docs`**; it publishes to `https://omar-tamerr.github.io/HorusEye/`. Regenerate
    the live demo when the explorer changes:
    `SOURCE_DATE_EPOCH=1760000000 horuseye --bloodhound examples/acme-lab --domain ACME.LAB --dc 10.10.0.5 --no-ai --owned 'JDOE@ACME.LAB' --explorer docs/demo.html`.

## Supported environments

| | |
|---|---|
| Python | 3.8 – 3.12 |
| OS | Linux, Windows (CI), macOS (expected) |
| Runtime deps | `rich` (always); `anthropic` only for `--ai` (`horuseye[ai]`) |
| External tools | optional, for offensive helpers — `horuseye --check-deps` |
