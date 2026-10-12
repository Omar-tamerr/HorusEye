"""Stage E: redaction masks every sensitive identifier class before transmission,
and AI output is validated and can never overwrite verified evidence."""
import sys
import types

from horuseye.ai.claude_analyzer import ClaudeAnalyzer
from horuseye.ai.redaction import Redactor, terms_from


# ── Redactor, per identifier class ───────────────────────────────────────────
def test_email_is_masked_and_restored():
    r = Redactor()
    red = r.redact("contact admin@corp.local for access")
    assert "admin@corp.local" not in red and "EMAIL1" in red
    assert r.restore(red) == "contact admin@corp.local for access"


def test_ipv4_is_masked():
    r = Redactor()
    red = r.redact("DC is 10.0.0.5 and host 192.168.1.20")
    assert "10.0.0.5" not in red and "192.168.1.20" not in red
    assert red.count("IP") == 2


def test_hostname_and_username_terms_masked_longest_first():
    r = Redactor(["CORP.LOCAL", "CORP", "WS01.CORP.LOCAL", "HELPDESK"])
    red = r.redact("HELPDESK on WS01.CORP.LOCAL in CORP.LOCAL")
    for secret in ("HELPDESK", "WS01.CORP.LOCAL", "CORP.LOCAL"):
        assert secret not in red
    assert r.restore(red) == "HELPDESK on WS01.CORP.LOCAL in CORP.LOCAL"


def test_same_identifier_maps_consistently():
    r = Redactor(["CORP.LOCAL"])
    red = r.redact("CORP.LOCAL and again CORP.LOCAL")
    # one placeholder, used twice
    assert red.count("ENTITY1") == 2


def test_terms_from_collects_principals_and_evidence():
    data = {"domain": "CORP.LOCAL", "users": [{"name": "BOB@CORP.LOCAL"}],
            "computers": [{"name": "WS01@CORP.LOCAL"}]}
    findings = [{"affected": "HELPDESK@CORP.LOCAL → ADMIN@CORP.LOCAL",
                 "evidence": [{"object": "SVC@CORP.LOCAL"}]}]
    terms = terms_from(data, findings)
    for t in ("CORP.LOCAL", "BOB@CORP.LOCAL", "WS01@CORP.LOCAL",
              "HELPDESK@CORP.LOCAL", "ADMIN@CORP.LOCAL", "SVC@CORP.LOCAL"):
        assert t in terms


# ── AI output validation (fake SDK, no network) ──────────────────────────────
def _fake(monkeypatch, reply, capture=None):
    mod = types.ModuleType("anthropic")

    class _B:
        type = "text"
        def __init__(self, t): self.text = t

    class _R:
        def __init__(self, t): self.content = [_B(t)]

    class _M:
        def create(self, **kw):
            if capture is not None:
                capture["prompt"] = kw["messages"][0]["content"]
            return _R(reply)

    class _C:
        def __init__(self, **kw): self.messages = _M()
    mod.Anthropic = _C
    mod.AuthenticationError = type("AuthenticationError", (Exception,), {})
    mod.RateLimitError = type("RateLimitError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "anthropic", mod)


def _findings():
    return [{"id": "aaa", "type": "DCSYNC", "severity": "CRITICAL",
             "affected": "HELPDESK@CORP.LOCAL", "evidence": [{"object": "x"}],
             "remediation": ["verified fix"]}]


def test_redaction_removes_identifiers_from_prompt(monkeypatch):
    cap = {}
    _fake(monkeypatch, "[]", cap)
    ClaudeAnalyzer("k", redact=True).analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert "HELPDESK" not in cap["prompt"] and "CORP.LOCAL" not in cap["prompt"]


def test_ai_cannot_overwrite_verified_fields(monkeypatch):
    # Model tries to return severity/remediation — they must be ignored.
    _fake(monkeypatch, '[{"id":"aaa","narrative":"abc","severity":"LOW",'
                       '"remediation":["bad"],"evidence":[]}]')
    out = ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert out[0]["ai_narrative"] == "abc"
    assert out[0]["severity"] == "CRITICAL"          # untouched
    assert out[0]["remediation"] == ["verified fix"]  # untouched


def test_non_string_narrative_rejected(monkeypatch):
    _fake(monkeypatch, '[{"id":"aaa","narrative":{"nested":"obj"}}]')
    out = ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert "ai_narrative" not in out[0]


def test_unknown_id_rejected(monkeypatch):
    _fake(monkeypatch, '[{"id":"not-a-real-id","narrative":"x"}]')
    out = ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert "ai_narrative" not in out[0]


def test_narrative_length_capped(monkeypatch):
    _fake(monkeypatch, '[{"id":"aaa","narrative":"' + "A" * 999 + '"}]')
    out = ClaudeAnalyzer("k").analyze(_findings(), {"domain": "CORP.LOCAL"})
    assert len(out[0]["ai_narrative"]) <= 500
