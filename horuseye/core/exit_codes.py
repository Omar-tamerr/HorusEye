"""
HorusEye — process exit codes for automation.

CI and schedulers key off these. They are stable and documented so a pipeline
can tell the difference between "clean", "findings over threshold", and "the
run could not be trusted".

    0  OK          analysis completed; no --fail-on threshold met
    1  ERROR       an unhandled error aborted the run
    2  FINDINGS    --fail-on set and a finding at/above the threshold exists
    3  INCOMPLETE  --fail-on set but the assessment was too thin to trust
                   (a source was given yet no usable objects were parsed) —
                   a clean result here would be a false negative
    4  DRIFT       --fail-on new-route / exposure-up set and, against the
                   --diff baseline, a new attack route appeared or more users
                   can reach Tier-0 (a fix didn't hold, or a change reopened one)

Exit codes are only emitted in automation-relevant paths; an ordinary
interactive run with no --fail-on returns 0.
"""
OK = 0
ERROR = 1
FINDINGS = 2
INCOMPLETE = 3
DRIFT = 4


def assessment_is_incomplete(domain_data: dict) -> bool:
    """True when input was provided but the parse produced no usable graph/ACL
    data, so 'no findings' cannot be trusted."""
    counts = (domain_data or {}).get("parse_report", {}).get("counts", {})
    if not counts:
        return False
    return (counts.get("users", 0) == 0
            and counts.get("acls", 0) == 0
            and counts.get("computers", 0) == 0)
