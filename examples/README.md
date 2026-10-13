# Example dataset — `acme-lab`

A small, **synthetic** BloodHound/SharpHound export (domain `ACME.LAB`) for a
reproducible demonstration. It contains no real or client data — every object
is invented. Use it to see HorusEye end-to-end without collecting anything.

## What it contains

A handful of deliberately planted weaknesses:

| Object | Weakness |
|---|---|
| `SVC-SQL@ACME.LAB` | Kerberoastable (has an SPN) |
| `SVC-BACKUP@ACME.LAB` | AS-REP roastable (no pre-auth) |
| `HELPDESK-SVC@ACME.LAB` | DCSync rights on the domain |
| `WEB01.ACME.LAB` | Unconstrained delegation |
| `OLD-ADMIN@ACME.LAB` | Disabled but still admin-flagged |
| `ACME.LAB ↔ PARTNER.LAB` | Bidirectional forest trust |
| `HELPDESK` group | Local admin on `WEB01`, where a DA has a session |

## Run it

```bash
# Findings + reports
horuseye --bloodhound examples/acme-lab --domain ACME.LAB --dc 10.10.0.5 \
    --report acme.html --markdown acme.md --json acme.json

# Shortest attack path from an ordinary user to Domain Admin
horuseye --bloodhound examples/acme-lab --domain ACME.LAB --dc 10.10.0.5 \
    --graph --owned 'JDOE@ACME.LAB'
```

## Expected result

- **7 findings, 2 CRITICAL** (DCSync, unconstrained delegation) and several HIGH.
- An attack path:

  ```
  JDOE@ACME.LAB
    │ MemberOf   → HELPDESK@ACME.LAB
    │ AdminTo    → WEB01.ACME.LAB
    │ HasSession → ADMINISTRATOR@ACME.LAB   (Domain Admin)
  ```

- **Remediation impact** names each edge as a choke point (removing any one
  breaks the path), so the fix is obvious: get the Domain Admin off `WEB01`,
  or remove `HELPDESK`'s local-admin rights there.

> Generate larger synthetic domains for benchmarking with
> `python scripts/benchmark.py`, which uses `horuseye.synthetic`.
