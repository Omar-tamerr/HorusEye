"""Knowledge base: every finding type the detector can emit must carry ATT&CK,
remediation and detection guidance, so reports are useful to defenders."""
import re

from horuseye.core.knowledge import KNOWLEDGE, enrich, mitre_coverage

DETECTOR_TYPES = {
    "KERBEROASTING", "ASREP_ROASTING", "DCSYNC", "ACL_ABUSE", "GPO_ABUSE",
    "UNCONSTRAINED_DELEGATION", "CONSTRAINED_DELEGATION", "PASS_THE_HASH",
    "ADCS_ESC", "DOMAIN_TRUST", "PRIVILEGED_SESSION", "WEAK_PASSWORD_POLICY",
    "STALE_ADMIN",
}


def test_every_detector_type_has_guidance():
    assert DETECTOR_TYPES <= set(KNOWLEDGE), DETECTOR_TYPES - set(KNOWLEDGE)
    for ftype, kb in KNOWLEDGE.items():
        assert kb["mitre"], ftype
        assert kb["remediation"], ftype
        assert kb["detection"], ftype


def test_mitre_ids_are_well_formed():
    for kb in KNOWLEDGE.values():
        for tid, name in kb["mitre"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), tid
            assert name


def test_enrich_attaches_guidance_without_overwriting():
    findings = [{"type": "DCSYNC", "severity": "CRITICAL"},
                {"type": "KERBEROASTING", "severity": "HIGH", "remediation": ["custom"]},
                {"type": "UNKNOWN"}]
    enrich(findings)
    assert findings[0]["mitre"][0]["id"] == "T1003.006"
    assert findings[0]["detection"]
    assert findings[1]["remediation"] == ["custom"]    # existing value kept
    assert "mitre" not in findings[2]                  # unknown types untouched


def test_mitre_coverage_aggregates_by_technique():
    findings = enrich([{"type": "ACL_ABUSE", "severity": "HIGH"},
                       {"type": "ACL_ABUSE", "severity": "CRITICAL"},
                       {"type": "STALE_ADMIN", "severity": "LOW"}])
    cov = {row["id"]: row for row in mitre_coverage(findings)}
    assert cov["T1098"]["count"] == 2
    assert cov["T1098"]["max_severity"] == "CRITICAL"
    # ACL_ABUSE and STALE_ADMIN both map to T1078.002
    assert cov["T1078.002"]["count"] == 3
