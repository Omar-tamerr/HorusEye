"""
HorusEye — local redaction for the AI layer.

When ``--ai-redact`` is on, every sensitive identifier is replaced with a stable
placeholder *before* any outbound request, and restored in the model's reply.
Covered classes: email addresses, IPv4 addresses, and caller-supplied terms
(domain, hostnames, principal/account names). Placeholders are deterministic
(``EMAIL1``, ``IP1``, ``ENTITY1`` …) so the same identifier always maps the same
way within one run, and the reverse map restores the real values locally.

The redactor is pure and offline — it never makes a network call. The analyzer
runs it on the prompt text and asserts (in tests) that the real identifiers are
gone before transmission.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


class Redactor:
    def __init__(self, terms: Optional[List[str]] = None):
        self._map: Dict[str, str] = {}      # real -> placeholder
        self._counts: Dict[str, int] = {}
        # Longest first so 'CORP.LOCAL' masks before 'CORP', and 'WS01.CORP'
        # before 'WS01'.
        self._terms = sorted({t.strip() for t in (terms or []) if t and len(t.strip()) > 2},
                             key=len, reverse=True)

    # ── placeholders ──────────────────────────────────────────────────────────
    def _placeholder(self, real: str, kind: str) -> str:
        if real in self._map:
            return self._map[real]
        self._counts[kind] = self._counts.get(kind, 0) + 1
        ph = f"{kind}{self._counts[kind]}"
        self._map[real] = ph
        return ph

    def _mask_regex(self, text: str, pattern: re.Pattern, kind: str) -> str:
        return pattern.sub(lambda m: self._placeholder(m.group(0), kind), text)

    def _mask_term(self, text: str, term: str) -> str:
        ph = self._placeholder(term, "ENTITY")
        return re.sub(re.escape(term), ph, text, flags=re.IGNORECASE)

    # ── public API ──────────────────────────────────────────────────────────
    def redact(self, text: str) -> str:
        if not text:
            return text
        # Emails and IPs first (an email contains '@', which also appears in
        # UPN-style terms — masking the whole address avoids partial leaks).
        text = self._mask_regex(text, _EMAIL, "EMAIL")
        text = self._mask_regex(text, _IPV4, "IP")
        for term in self._terms:
            text = self._mask_term(text, term)
        return text

    def restore(self, text: str) -> str:
        if not text:
            return text
        # Longest placeholders first is unnecessary (they don't overlap), but
        # restore every mapping deterministically.
        for real, ph in self._map.items():
            text = text.replace(ph, real)
        return text

    @property
    def mapping(self) -> Dict[str, str]:
        return dict(self._map)


def terms_from(domain_data: Dict, findings: List[Dict]) -> List[str]:
    """Collect the identifiers worth masking: the domain, every principal /
    computer / group name, and each finding's affected/evidence objects."""
    terms = set()
    d = domain_data or {}
    if d.get("domain"):
        terms.add(d["domain"])
        terms.add(str(d["domain"]).split(".")[0])
    for coll in ("users", "computers", "groups"):
        for o in d.get(coll, []) or []:
            if o.get("name"):
                terms.add(o["name"])
    for f in findings or []:
        if f.get("affected"):
            # Split composite "A → B" affected strings into their parts.
            for part in re.split(r"→|,", f["affected"]):
                p = part.strip()
                if p:
                    terms.add(p)
        for e in f.get("evidence", []) or []:
            if e.get("object"):
                terms.add(e["object"])
    return [t for t in terms if t]
