# Web app → AD service account import (milestone 1)

> **Status: draft format (`horuseye.webapps/1-draft`), milestone 1.** HorusEye
> imports these two fixtures and checks the resulting paths, labels and errors
> (`tests/test_webapp_fixtures.py`). No scanning or exploit execution is
> involved. The format may still change while it is reviewed on GitHub.

```bash
horuseye --bloodhound examples/acme-lab --domain ACME.LAB --dc 10.10.0.5 --graph \
    --webapps examples/acme-lab-webapp/portal-confirmed.json
```

## Scenario (synthetic lab)

An intentionally vulnerable intranet portal runs on `WEB01.ACME.LAB` under
`ACME\WEB-SVC` (`S-1-5-21-ACME-1106`). In the synthetic
[`acme-lab`](../acme-lab) directory data, `WEB-SVC` is a local administrator on
`WEB01`, where the Domain Admin `ADMINISTRATOR` has a session:

```
WEB-SVC ─AdminTo→ WEB01 ─HasSession→ ADMINISTRATOR   (observed in the directory data)
```

The import answers whether an attacker who can reach the app actually gets to
stand on that path.

## Three separate claims

| Claim | Meaning | Evidence it cites |
|---|---|---|
| `reachable_from_vantage` | The app answers requests from a named assessment vantage | `http_request` from that vantage |
| `uses_account` | The app runs as the mapped account | `service_config` or `execution_identity` |
| `privileges_obtainable` | An attacker who reaches the app can act with the account's privileges | `execution_identity` linked to its triggering `http_request` |

Each claim is `confirmed` (cites evidence), `assumed` (an analyst assumption;
needs a `rationale`) or `not_assessed`. Reaching the app, or an SSRF, does not
establish the third claim.

## Format

- `vantages`: where the tester stood, each with a stable `id`, a `description`
  and its `network` context. "Reachable" means reachable from that vantage,
  not internet-facing.
- `apps[].account`: the explicit account mapping, `{name, sid}`.
- `apps[].evidence`: evidence items with unique ids. Claims cite them by id, so
  one execution record can support both `uses_account` and
  `privileges_obtainable`.

| Evidence type | Required fields |
|---|---|
| `http_request` | `vantage`, `method`, `url` (sanitized), `timestamp`, `response.status`, `response.summary` |
| `service_config` | `source`, `identity`, `detail` (optional `sid`) |
| `execution_identity` | `triggered_by`, `timestamp`, `host`, `effective_identity`, `effective_sid` |

Any item may carry `artifact_sha256`, the SHA-256 of a sanitized saved
artifact, for provenance. Raw response bodies are not accepted.

## Validation

The import fails with an explicit error when:

- an evidence id is duplicated, or a claim cites evidence that isn't in its app
- `triggered_by` doesn't resolve to an `http_request` in the same app
- a confirmed `privileges_obtainable` has no execution record, or the
  execution ran as a different SID or on a different host than the mapping
- a confirmed claim cites no evidence, an `assumed` claim has no rationale, or
  a `not_assessed` claim cites evidence
- a field name looks like a credential (`password`, `hash`, `token`,
  `secret`, `cookie`, `ticket`, ...) or holds a raw response body

It warns, and does not use the mapping, when the account is missing from the
directory data or its SID differs: a mapping never binds by name alone. A
`service_config` that names a different identity than the mapping is reported
as a conflict, not silently resolved.

> **The credential check is a safeguard, not a guarantee.** It looks at field
> names, so it cannot see a secret pasted into `detail`, a URL or a response
> summary. Sanitize evidence before importing it.

## How it maps onto the graph

| Claim status | Graph step | Trust |
|---|---|---|
| `reachable_from_vantage` confirmed | vantage `Reaches` app | `validated` (reachability, **not** control) |
| `privileges_obtainable` confirmed | app `ExecutesAs` account | `validated` |
| `privileges_obtainable` assumed | app `ExecutesAs` account | `assumed` |
| `privileges_obtainable` not assessed, `uses_account` confirmed | app `ExecutesAs` account | `not_assessed` (what-if only) |

Normal routes never cross an `assumed` or `not_assessed` step. Routes that need
one are reported separately as conditional, and the claim keeps its original
status. The import never marks the account as owned, and AD steps after it keep
their own label (`observed` or `inferred`). A reachability step is never
proposed as a fix. Every relationship has a stable id (for example
`AdminTo:WEB-SVC->WEB01.ACME.LAB`) so later evidence can validate a specific
step; that import is deferred.

## Expected results

| | `portal-unconfirmed.json` | `portal-confirmed.json` |
|---|---|---|
| `privileges_obtainable` | `not_assessed` (stays so) | `confirmed` (`req-2` → `exec-1`) |
| `WEB-SVC` owned | No | No |
| Normal routes | None | `lab-tester-1` → `acme-portal` → `WEB-SVC` → `WEB01` → `ADMINISTRATOR` |
| Conditional routes | "Hypothetical: if `WEB-SVC@ACME.LAB` is compromised" | None |
| Step trust | `validated` · `not_assessed` · `observed` · `observed` | `validated` · `validated` · `observed` · `observed` |
| Fix options | None (nothing proven yet) | Fix the endpoint, or remove `WEB-SVC`'s local admin on `WEB01` |
