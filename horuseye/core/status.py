"""
HorusEye: remediation status tracker.

A team records, per finding: a status, free-text notes and the date it last
changed, in a small ``horuseye-status.json`` they can share. The explorer
exports and imports the same file, and ``--status FILE`` merges it into every
output.

The file holds stable finding ids, status, notes and dates, nothing else.
Anything else in an imported file is dropped, so a status file can't carry
findings, evidence or secrets around by accident. Notes are the user's own
text and are length-capped.

    {"schema": "horuseye.status/1",
     "findings": {"<finding id>": {"status": "fixed", "notes": "...", "changed": "2026-11-07"}}}
"""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

SCHEMA = "horuseye.status/1"
STATUSES = ("open", "in_progress", "fixed", "accepted_risk", "false_positive")
LABELS = {"open": "Open", "in_progress": "In progress", "fixed": "Fixed",
          "accepted_risk": "Accepted risk", "false_positive": "False positive"}
MAX_NOTES = 2000
_ID = re.compile(r"^[0-9a-f]{12}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ][0-9:.+Z-]{0,20})?$")


class StatusFileError(ValueError):
    """The status file is not a horuseye.status/1 document."""


def clean(doc) -> Dict[str, Dict]:
    """Validate a status document; keep only well-formed entries."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise StatusFileError(f"expected a {SCHEMA} document")
    out: Dict[str, Dict] = {}
    for fid, e in (doc.get("findings") or {}).items():
        if not (isinstance(fid, str) and _ID.match(fid) and isinstance(e, dict)):
            continue
        st = e.get("status")
        if st not in STATUSES:
            continue
        notes = e.get("notes") if isinstance(e.get("notes"), str) else ""
        changed = e.get("changed") if isinstance(e.get("changed"), str) and _DATE.match(e.get("changed")) else ""
        out[fid] = {"status": st, "notes": notes[:MAX_NOTES], "changed": changed}
    return out


def load(path: str) -> Dict[str, Dict]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise StatusFileError(f"{path}: cannot read status file ({e})") from e
    return clean(doc)


def export(entries: Dict[str, Dict]) -> Dict:
    """A status document with only ids, status, notes and dates (sorted, so it
    diffs cleanly in version control)."""
    return {"schema": SCHEMA, "findings": {fid: {"status": e["status"], "notes": e.get("notes", ""),
                                                  "changed": e.get("changed", "")}
                                            for fid, e in sorted(clean({"schema": SCHEMA,
                                                                        "findings": entries}).items())}}


def save(path: str, entries: Dict[str, Dict]) -> None:
    Path(path).write_text(json.dumps(export(entries), indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")


def merge(findings: List[Dict], entries: Dict[str, Dict], retest: Optional[Dict] = None) -> Dict:
    """Attach ``status`` / ``notes`` / ``status_changed`` to each finding
    (default Open) and check recorded fixes against this run. With a retest
    (``--diff``): a finding marked Fixed that is still found is flagged, and a
    finding that is gone since the baseline is "verified fixed". Returns a
    summary: counts per status, and the two checks."""
    current = {f.get("id") for f in findings}
    for f in findings:
        e = entries.get(f.get("id")) or {}
        f["status"] = e.get("status", "open")
        f["notes"] = e.get("notes", "")
        f["status_changed"] = e.get("changed", "")
        f.pop("status_check", None)
        if f["status"] == "fixed":
            f["status_check"] = "marked_fixed_still_found"
    counts = {s: 0 for s in STATUSES}
    for f in findings:
        counts[f["status"]] += 1
    still = [f["id"] for f in findings if f.get("status_check") == "marked_fixed_still_found"]
    verified: List[Dict] = []
    if retest and not retest.get("error"):
        for g in (retest.get("findings") or {}).get("fixed") or []:
            gid = g.get("id")
            if gid and gid not in current:
                e = entries.get(gid) or {}
                verified.append({"id": gid, "title": g.get("title", ""), "severity": g.get("severity", ""),
                                 "marked": e.get("status", "open"), "notes": e.get("notes", "")})
    unknown = sorted(fid for fid in entries if fid not in current
                     and fid not in {v["id"] for v in verified})
    return {"counts": counts, "marked_fixed_still_found": still, "verified_fixed": verified,
            "not_in_this_run": unknown, "tracked": len(entries)}


def today() -> str:
    return date.today().isoformat()
