"""
Claude AI analyzer — optional narrative layer.

Generates a one-line attack narrative for each finding via the Anthropic API.
It is entirely optional: every detection, score and report works without it.

Design notes:
* Uses the official ``anthropic`` SDK (optional dependency: ``pip install
  horuseye[ai]``) and the current default model, ``claude-opus-5-5``.
* Narratives are keyed by each finding's stable ``id`` — the previous version
  keyed by ``type``, so every DCSync/ACL finding shared one narrative.
* ``--ai-redact`` replaces the domain and affected principal names with
  placeholders before anything leaves the machine, then restores them in the
  returned text, so client identifiers are never sent to the API.
* Failures are surfaced with a clear reason instead of being swallowed.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Tuple

DEFAULT_MODEL = "claude-opus-5-5"


class ClaudeAnalyzer:
    def __init__(self, api_key: str, deep: bool = False,
                 model: str = DEFAULT_MODEL, redact: bool = False, console=None):
        self.api_key = api_key
        self.deep = deep
        self.model = model or DEFAULT_MODEL
        self.redact = redact
        self.console = console

    # ── Public entry point ────────────────────────────────────────────────────
    def analyze(self, findings: List[Dict], domain_data: Dict) -> List[Dict]:
        if not findings or not self.api_key:
            return findings
        try:
            import anthropic
        except ImportError:
            self._warn("AI analysis needs the anthropic package — "
                       "install it with [cyan]pip install horuseye\\[ai][/cyan]. "
                       "Continuing in rules-only mode.")
            return findings

        subset = findings[:20 if self.deep else 10]
        from horuseye.ai.redaction import Redactor, terms_from
        redactor = Redactor(terms_from(domain_data, subset)) if self.redact else None

        def mask(text):
            return redactor.redact(text) if redactor else text

        lines = []
        for f in subset:
            lines.append(f'- id={f.get("id","")} [{f.get("severity","")}] '
                         f'{f.get("type","")} on {mask(f.get("affected", ""))}')
        domain = mask(domain_data.get("domain", ""))
        prompt = (
            f"You are a senior red-team operator analysing Active Directory attack "
            f"paths for domain {domain}. For each finding below, write one concise "
            f"sentence explaining how it is abused and why it matters.\n\n"
            + "\n".join(lines) +
            '\n\nReply with ONLY a JSON array, no prose, no code fences: '
            '[{"id":"<id>","narrative":"<one sentence>"}]'
        )

        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            resp = client.messages.create(
                model=self.model,
                max_tokens=2000,
                output_config={"effort": "high" if self.deep else "low"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.AuthenticationError:
            self._warn("Claude API key rejected — check --claude-key / --config. "
                       "Continuing in rules-only mode.")
            return findings
        except anthropic.RateLimitError:
            self._warn("Claude API rate limited. Continuing in rules-only mode.")
            return findings
        except Exception as e:  # network, API error — report, don't crash the run
            self._warn(f"AI analysis unavailable ({type(e).__name__}). "
                       "Continuing in rules-only mode.")
            return findings

        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        narratives = self._parse(text)
        if not narratives:
            self._warn("AI response could not be parsed as JSON; no narratives added.")
            return findings

        # Validate structured output before using any of it. The AI may only
        # ever populate `ai_narrative` — it can never overwrite verified facts
        # (severity, evidence, remediation, commands).
        valid_ids = {f.get("id") for f in findings}
        by_id = {}
        for n in narratives:
            if not isinstance(n, dict):
                continue
            fid, narr = n.get("id"), n.get("narrative")
            if fid in valid_ids and isinstance(narr, str) and narr.strip():
                by_id[fid] = narr.strip()[:500]
        for f in findings:
            narr = by_id.get(f.get("id"))
            if narr:
                f["ai_narrative"] = redactor.restore(narr) if redactor else narr
        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────
    @staticmethod
    def _parse(text: str):
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else []
        except (ValueError, TypeError):
            return []

    def _warn(self, msg: str):
        if self.console:
            self.console.print(f"[yellow]⚠️  {msg}[/yellow]")
        else:
            print(re.sub(r"\[/?[^\]]*\]", "", msg))
