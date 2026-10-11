# Contributing to HorusEye

Thanks for your interest in improving HorusEye. This guide covers the basics.

## Development setup

```bash
git clone https://github.com/Omar-tamerr/HorusEye
cd HorusEye
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running the tests

```bash
pytest -q
```

The suite lives in `tests/` and covers the parsers, the scorer and the
detection engine. CI runs the same suite on Linux and Windows via
`.github/workflows/ci.yml`; please make sure `pytest` is green before opening a
pull request.

## Project layout

See [Project Structure](README.md#project-structure) in the README. In short:
`parsers/` ingest, `core/` detect and score, `engine/` and `features/` act,
`reports/` present, `ai/` narrate, `utils/` support, and `cli.py` wires it all
together.

## Adding a detection

1. Add a `_detect_*` method to `horuseye/core/attack_detector.py` and register
   it in `detect_all()`.
2. Emit findings with the standard shape: `type`, `title`, `affected`,
   `severity`, `description`, `commands`, and optionally `references`.
3. Give it an ease weight in `horuseye/core/path_scorer.py`.
4. Add a case to `tests/test_detector.py` so the behaviour is locked in.

## Guidelines

- Detections should report *where* a misconfiguration exists and the standard,
  publicly documented command to validate it.
- Keep external tools optional — core detection must work with only `rich`
  installed.
- Match the existing style; keep commits focused with descriptive messages.

## Responsible use

HorusEye is for authorized penetration testing, CTF competitions and security
research only. Do not contribute features whose primary purpose is to evade
defenses or to target systems without authorization. See the Legal Notice in
the README.
