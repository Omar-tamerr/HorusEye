"""
HorusEye — web app → AD service account import (``horuseye.webapps/1-draft``).

Links a web application to the AD account it runs as, through three separate,
evidence-backed claims:

  reachable_from_vantage  the app answers requests from a named assessment vantage
  uses_account            the app runs as the mapped account
  privileges_obtainable   an attacker who reaches the app can act with that
                          account's privileges (a request-linked execution record)

Each claim is ``confirmed`` (cites evidence), ``assumed`` (an analyst assumption
that must give a rationale) or ``not_assessed``. The importer never changes a
claim's status and never marks an account as owned: the attack graph turns the
claims into a reachability edge and a control edge whose trust says how much
was proven, and reports routes that need an unproven step separately.

Evidence must be sanitized before import. Credential-like key names (password,
hash, token, ...) and raw response bodies are rejected, but that is only a
safeguard: it cannot see a secret pasted into a free-text field or a URL.

    from horuseye.parsers.webapps import load_webapps
    load_webapps("portal.json", domain_data)      # raises WebappImportError
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

from horuseye.core.principals import norm

SCHEMA = "horuseye.webapps/1-draft"
CLAIMS = ("reachable_from_vantage", "uses_account", "privileges_obtainable")
STATUSES = ("confirmed", "assumed", "not_assessed")

_CREDENTIAL_KEY = re.compile(
    r"pass(word|wd|phrase)?|secret|token|cookie|hash|ticket|api_?key|private_?key|^ntlm?$|^lm$",
    re.I)
_RAW_BODY_KEY = re.compile(r"^(body|raw|raw_?response|response_?body|content)$", re.I)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_FIELDS = {
    "http_request": ("vantage", "method", "url", "timestamp", "response"),
    "service_config": ("source", "identity", "detail"),
    "execution_identity": ("triggered_by", "timestamp", "effective_identity",
                           "effective_sid", "host"),
}


class WebappImportError(ValueError):
    """The import file is malformed, unsafe, or makes an invalid confirmed claim."""


def load_webapps(path: str, domain_data: Dict) -> Dict:
    """Validate ``path`` and attach its apps to ``domain_data["webapps"]``.
    Problems that make a claim unusable but not invalid (e.g. the account is
    missing from the directory data) are recorded as parse-report warnings."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise WebappImportError(f"{path}: cannot read web app import ({e})") from e
    apps, warnings = parse_webapps(doc, domain_data, source=str(path))
    domain_data.setdefault("webapps", []).extend(apps)
    report = domain_data.setdefault("parse_report", {})
    report.setdefault("warnings", []).extend(warnings)
    sources = report.setdefault("sources", [])
    if "webapps" not in sources:
        sources.append("webapps")
    return domain_data


def parse_webapps(doc, domain_data: Dict, source: str = "webapps"):
    """Validate a parsed document. Returns ``(apps, warnings)``."""
    def fail(msg):
        raise WebappImportError(f"{source}: {msg}")

    if not isinstance(doc, dict):
        fail("expected a JSON object")
    if doc.get("schema") != SCHEMA:
        fail(f"schema must be {SCHEMA!r}, got {doc.get('schema')!r}")
    _reject_unsafe_keys(doc, fail)

    warnings: List[str] = []
    dom = str(domain_data.get("domain") or "").upper()
    if doc.get("domain") and dom and str(doc["domain"]).upper() != dom:
        warnings.append(f"{source}: file is for {doc['domain']}, data is for {dom}")

    vantages = {}
    for v in _list(doc.get("vantages"), "vantages", fail):
        vid = _text(v, "id", "vantage", fail)
        if vid in vantages:
            fail(f"duplicate vantage id {vid!r}")
        _text(v, "description", f"vantage {vid!r}", fail)
        _text(v, "network", f"vantage {vid!r}", fail)
        vantages[vid] = {"id": vid, "description": v["description"], "network": v["network"]}

    sids = _directory_sids(domain_data)
    apps, app_ids = [], set()
    for raw in _list(doc.get("apps"), "apps", fail):
        app = _parse_app(raw, vantages, sids, warnings, fail)
        if app["id"] in app_ids:
            fail(f"duplicate app id {app['id']!r}")
        app_ids.add(app["id"])
        app["source_file"] = source
        apps.append(app)
    if not apps:
        fail("no apps to import")
    return apps, warnings


def _parse_app(raw, vantages, sids, warnings, fail) -> Dict:
    if not isinstance(raw, dict):
        fail("each app must be an object")
    aid = _text(raw, "id", "app", fail)
    where = f"app {aid!r}"
    host = _text(raw, "host", where, fail)
    acct = raw.get("account")
    if not isinstance(acct, dict):
        fail(f"{where}: needs an explicit account mapping {{name, sid}}")
    name = _text(acct, "name", f"{where} account", fail)
    sid = _text(acct, "sid", f"{where} account", fail)

    # Evidence: unique ids, required fields per type, references within this app.
    evidence = {}
    for ev in _list(raw.get("evidence", []), f"{where} evidence", fail, allow_empty=True):
        eid = _text(ev, "id", f"{where} evidence", fail)
        if eid in evidence:
            fail(f"{where}: duplicate evidence id {eid!r}")
        etype = ev.get("type")
        if etype not in _EVIDENCE_FIELDS:
            fail(f"{where}: evidence {eid!r} has unknown type {etype!r}")
        for field in _EVIDENCE_FIELDS[etype]:
            if ev.get(field) in (None, "", {}):
                fail(f"{where}: {etype} evidence {eid!r} needs {field!r}")
        if ev.get("artifact_sha256") is not None and not _SHA256.match(str(ev["artifact_sha256"])):
            fail(f"{where}: evidence {eid!r} artifact_sha256 must be 64 lowercase hex characters")
        evidence[eid] = ev
    for eid, ev in evidence.items():
        if ev["type"] == "http_request":
            resp = ev["response"]
            if not isinstance(resp, dict) or not isinstance(resp.get("status"), int) \
                    or not str(resp.get("summary") or "").strip():
                fail(f"{where}: http_request {eid!r} response needs an integer status and a summary")
            if ev["vantage"] not in vantages:
                fail(f"{where}: http_request {eid!r} names unknown vantage {ev['vantage']!r}")
        if ev["type"] == "execution_identity":
            ref = evidence.get(ev["triggered_by"])
            if ref is None:
                fail(f"{where}: execution_identity {eid!r} is triggered_by {ev['triggered_by']!r}, "
                     f"which is not evidence in this app")
            if ref["type"] != "http_request":
                fail(f"{where}: execution_identity {eid!r} must be triggered_by an http_request, "
                     f"not {ref['type']}")

    # Claims: known names, valid status, references resolve, status rules.
    claims_raw = raw.get("claims") or {}
    if not isinstance(claims_raw, dict):
        fail(f"{where}: claims must be an object")
    unknown = set(claims_raw) - set(CLAIMS)
    if unknown:
        fail(f"{where}: unknown claim(s) {sorted(unknown)}; expected {list(CLAIMS)}")
    claims = {}
    for cname in CLAIMS:
        c = claims_raw.get(cname) or {"status": "not_assessed", "evidence": []}
        status = c.get("status")
        if status not in STATUSES:
            fail(f"{where}: {cname} status must be one of {list(STATUSES)}, got {status!r}")
        refs = c.get("evidence") or []
        if not isinstance(refs, list):
            fail(f"{where}: {cname} evidence must be a list of evidence ids")
        for r in refs:
            if r not in evidence:
                fail(f"{where}: {cname} cites {r!r}, which is not evidence in this app")
        claim = {"status": status, "evidence": list(refs)}
        if status == "confirmed" and not refs:
            fail(f"{where}: confirmed {cname} must cite evidence")
        if status == "assumed":
            rationale = str(c.get("rationale") or "").strip()
            if not rationale:
                fail(f"{where}: assumed {cname} needs a rationale")
            claim["rationale"] = rationale
        if status == "not_assessed" and (refs or c.get("rationale")):
            fail(f"{where}: {cname} is not_assessed, so it can't cite evidence or a rationale")
        claims[cname] = claim

    cited = {cname: [evidence[r] for r in claims[cname]["evidence"]] for cname in CLAIMS}

    reach = claims["reachable_from_vantage"]
    vantage = None
    if reach["status"] != "not_assessed":
        vid = (claims_raw.get("reachable_from_vantage") or {}).get("vantage")
        if vid not in vantages:
            fail(f"{where}: reachable_from_vantage needs a known vantage, got {vid!r}")
        vantage, reach["vantage"] = vantages[vid], vid
        if reach["status"] == "confirmed" and not any(
                e["type"] == "http_request" and e["vantage"] == vid for e in cited["reachable_from_vantage"]):
            fail(f"{where}: confirmed reachable_from_vantage needs an http_request from {vid!r}")

    def executions(cname):
        return [e for e in cited[cname] if e["type"] == "execution_identity"]

    uses = claims["uses_account"]
    if uses["status"] == "confirmed":
        kinds = {e["type"] for e in cited["uses_account"]}
        if not kinds & {"service_config", "execution_identity"}:
            fail(f"{where}: confirmed uses_account needs service_config or execution_identity evidence")
        for e in executions("uses_account"):
            if e["effective_sid"] != sid:
                fail(f"{where}: execution evidence {e['id']!r} ran as {e['effective_sid']}, "
                     f"not the mapped account {sid}")

    priv = claims["privileges_obtainable"]
    if priv["status"] == "confirmed":
        runs = executions("privileges_obtainable")
        if not runs:
            fail(f"{where}: invalid confirmed privileges_obtainable: needs execution_identity evidence")
        for e in runs:                         # triggered_by was resolved above
            if e["effective_sid"] != sid:
                fail(f"{where}: invalid confirmed privileges_obtainable: {e['id']!r} ran as "
                     f"{e['effective_sid']}, not the mapped account {sid}")
            if norm(e["host"]) != norm(host):
                fail(f"{where}: invalid confirmed privileges_obtainable: {e['id']!r} ran on "
                     f"{e['host']}, not the app host {host}")

    # Binding the mapping to the directory data: by SID, never silently by name.
    bound, dir_sid = False, sids.get(norm(name))
    if dir_sid is None:
        msg = f"{where}: account {name} is not in the directory data"
    elif dir_sid != sid:
        msg = f"{where}: account {name} has SID {dir_sid} in the directory data, not {sid}"
    else:
        msg, bound = None, True
    if msg:
        if priv["status"] == "confirmed":
            fail(f"invalid confirmed privileges_obtainable: {msg}")
        warnings.append(f"{msg}; the mapping is not used")

    # Conflicts between configuration and execution evidence are surfaced, not resolved.
    conflicts = []
    for e in evidence.values():
        if e["type"] != "service_config":
            continue
        cfg_sid, cfg_name = e.get("sid"), _sam(e["identity"])
        if (cfg_sid and cfg_sid != sid) or cfg_name != _sam(name):
            conflicts.append(f"{where}: config evidence {e['id']!r} names {e['identity']}"
                             f"{f' ({cfg_sid})' if cfg_sid else ''}, but the mapped account is "
                             f"{name} ({sid})")
    warnings.extend(conflicts)

    return {"id": aid, "name": raw.get("name") or aid, "host": host, "url": raw.get("url", ""),
            "account": {"name": name, "sid": sid}, "bound": bound, "vantage": vantage,
            "claims": claims, "evidence": list(evidence.values()), "conflicts": conflicts}


# ── helpers ──────────────────────────────────────────────────────────────────
def _reject_unsafe_keys(node, fail, path="$"):
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{path}.{k}"
            if _CREDENTIAL_KEY.search(str(k)):
                fail(f"{here}: credential-like field names are not accepted; import "
                     f"sanitized evidence only")
            if _RAW_BODY_KEY.match(str(k)):
                fail(f"{here}: raw response bodies are not accepted in v1; give a summary "
                     f"and an optional artifact_sha256 of a sanitized artifact")
            _reject_unsafe_keys(v, fail, here)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _reject_unsafe_keys(v, fail, f"{path}[{i}]")


def _list(value, what, fail, allow_empty=False):
    if not isinstance(value, list) or (not value and not allow_empty):
        fail(f"{what} must be a {'' if allow_empty else 'non-empty '}list")
    return value


def _text(obj, key, what, fail) -> str:
    val = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(val, str) or not val.strip():
        fail(f"{what} needs a non-empty {key!r}")
    return val.strip()


def _sam(identity: str) -> str:
    """``ACME\\WEB-SVC`` / ``WEB-SVC@ACME.LAB`` / ``web-svc`` → ``WEB-SVC``."""
    return norm(str(identity).split("\\")[-1])


def _directory_sids(domain_data: Dict) -> Dict[str, str]:
    out = {}
    for kind in ("users", "computers"):
        for obj in domain_data.get(kind) or []:
            if isinstance(obj, dict) and obj.get("sid") and obj.get("name"):
                out[norm(obj["name"])] = str(obj["sid"])
    return out
