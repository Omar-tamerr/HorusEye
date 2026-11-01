# Web app → AD service account: draft fixtures

> **Status: proposal.** HorusEye does not import these files yet. The format is
> being agreed in a GitHub issue first; these fixtures and the tests in
> `tests/test_webapp_fixtures.py` pin down the behaviour the importer must have.

## Scenario (synthetic lab)

An intentionally vulnerable intranet portal runs on `WEB01.ACME.LAB` under the
service account `ACME\WEB-SVC` (`S-1-5-21-ACME-1106`). In the synthetic
[`acme-lab`](../acme-lab) directory data, `WEB-SVC` is a local administrator on
`WEB01`, where the Domain Admin `ADMINISTRATOR` has a session. So the directory
data alone already holds a known path:

```
WEB-SVC ─AdminTo→ WEB01 ─HasSession→ ADMINISTRATOR   (both steps observed in the data)
```

The question the import answers is whether an attacker who can reach the web
app actually gets to stand on that path.

## Three separate claims

| Claim | Meaning | Evidence |
|---|---|---|
| `exposed` | The tester can reach the app | Request from the test machine: URL, timestamp, response |
| `uses_account` | The app runs as `WEB-SVC` | Sanitized deployment or service config, matched to the account's AD SID |
| `privileges_obtainable` | An attacker can act with `WEB-SVC`'s privileges | Controlled exploit of a lab endpoint: effective identity and SID, linked to the triggering request |

No credential values ever: no passwords, hashes, tokens, cookies or tickets.
Reaching the app (or an SSRF) does not establish the third claim on its own.

## The two fixtures

They describe the same app and the same account mapping. Only
`privileges_obtainable` differs.

| | `portal-unconfirmed.json` | `portal-confirmed.json` |
|---|---|---|
| `privileges_obtainable` | `not_assessed` | `confirmed` (`req-2` → `exec-1`, effective SID matches) |
| `WEB-SVC` marked as owned | **No** | **No** |
| Normal attack routes from the tester | None | tester → portal → `WEB-SVC` → `WEB01` → `ADMINISTRATOR` |
| Conditional routes | The same route, labelled "if `WEB-SVC@ACME.LAB` is compromised" | Not needed |
| Step labels | reach the portal: `validated` · act as `WEB-SVC`: `assumed` · AD steps: `observed` | reach the portal, act as `WEB-SVC`: `validated` · AD steps: `observed` |

In both, the AD steps stay graph-derived (`observed`): the exploit proves the
web-to-account step, not the directory relationships after it.
