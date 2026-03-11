"""Stub path scorer — scores and ranks findings."""

SEVERITY_SCORES = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 0}

class PathScorer:
    def score(self, findings: list) -> list:
        for f in findings:
            base = SEVERITY_SCORES.get(f.get("severity", "LOW"), 25)
            f["score"] = base
        return sorted(findings, key=lambda x: -x.get("score", 0))
