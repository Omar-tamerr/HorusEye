"""AI analyzer: redaction, id-keying, and graceful degradation — no network.

The Anthropic client is replaced with a fake so these tests never make a real
API call. They lock in the behaviour that matters: narratives key by finding
id (not type), redaction round-trips, and failures never crash the run.
"""
import sys
import types

import pytest

from horuseye.ai.claude_analyzer import ClaudeAnalyzer


def _findings():
    return [
        {"id": "aaa", "type": "DCSYNC", "severity": "CRITICAL", "affected": "HELPDESK@CORP.LOCAL"},
        {"id": "bbb", "type": "DCSYNC", "severity": "CRITICAL", "affected": "BACKUP@CORP.LOCAL"},
    ]


def _fake_anthropic(monkeypatch, capture, reply):
    """Install a fake `anthropic` module whose client returns `reply` text and
    records the outbound prompt into `capture`."""
    mod = types.ModuleType("anthropic")

    class _Block:
        type = "text"
        def __init__(self, text): self.text = text

    class _Resp:
        def __init__(self, text): self.content = [_Block(text)]

    class _Messages:
        def create(self, **kw):
            capture["prompt"] = kw["messages"][0]["content"]
            capture["model"] = kw["model"]
            return _Resp(reply)

    class _Client:
        def __init__(self, **kw): self.messages = _Messages()

    mod.Anthropic = _Client
    mod.AuthenticationError = type("AuthenticationError", (Exception,), {})
    mod.RateLimitError = type("RateLimitError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    return capture


def test_no_key_returns_unchanged():
    f = _findings()
    assert ClaudeAnalyzer("", False).analyze(f, {"domain": "CORP.LOCAL"}) is f


def test_narratives_keyed_by_id_not_type(monkeypatch):
    cap = _fake_anthropic(monkeypatch, {},
                          '[{"id":"aaa","narrative":"first"},{"id":"bbb","narrative":"second"}]')
    out = ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    # Two same-type findings must get DIFFERENT narratives (the old bug gave them one).
    assert out[0]["ai_narrative"] == "first"
    assert out[1]["ai_narrative"] == "second"


def test_model_default_is_opus_5_5(monkeypatch):
    cap = _fake_anthropic(monkeypatch, {}, "[]")
    ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert cap["model"] == "claude-opus-5-5"


def test_redaction_hides_names_and_restores(monkeypatch):
    cap = {}
    _fake_anthropic(monkeypatch, cap,
                    '[{"id":"aaa","narrative":"ENTITY_PLACEHOLDER controls the domain"}]')
    # Reply references a placeholder; analyzer must restore the real name.
    analyzer = ClaudeAnalyzer("k", redact=True)
    out = analyzer.analyze(_findings(), {"domain": "CORP.LOCAL"})
    # The outbound prompt must not contain the real domain or principal.
    assert "CORP.LOCAL" not in cap["prompt"]
    assert "HELPDESK" not in cap["prompt"]
    assert "ENTITY" in cap["prompt"]


def test_redaction_off_by_default(monkeypatch):
    cap = {}
    _fake_anthropic(monkeypatch, cap, "[]")
    ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert "CORP.LOCAL" in cap["prompt"]        # not redacted unless asked


def test_fenced_json_is_parsed(monkeypatch):
    _fake_anthropic(monkeypatch, {}, '```json\n[{"id":"aaa","narrative":"x"}]\n```')
    out = ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert out[0].get("ai_narrative") == "x"


def test_bad_json_does_not_crash(monkeypatch):
    _fake_anthropic(monkeypatch, {}, "not json at all")
    out = ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert "ai_narrative" not in out[0]


def test_auth_error_degrades_gracefully(monkeypatch):
    mod = types.ModuleType("anthropic")
    mod.AuthenticationError = type("AuthenticationError", (Exception,), {})
    mod.RateLimitError = type("RateLimitError", (Exception,), {})

    class _Client:
        def __init__(self, **kw):
            class M:
                def create(self, **k): raise mod.AuthenticationError("bad key")
            self.messages = M()
    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    f = _findings()
    out = ClaudeAnalyzer("k").analyze(f, {"domain": "CORP.LOCAL"})
    assert all("ai_narrative" not in x for x in out)      # no crash, no narratives
