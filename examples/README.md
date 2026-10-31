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
| `HELPDESK` group | Can reset `HELPDESK-SVC`'s password (ForceChangePassword) |

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

- **8 findings: 2 CRITICAL** (DCSync, unconstrained delegation), **5 HIGH**, 1 LOW.
- **Two attack routes** from `JDOE` to domain control:

  ```
  Route 1   JDOE ─MemberOf→ HELPDESK ─ForceChangePassword→ HELPDESK-SVC ─DCSync→ ACME.LAB
  Route 2   JDOE ─MemberOf→ HELPDESK ─AdminTo→ WEB01 ─HasSession→ ADMINISTRATOR
  ```

- **Remediation impact** finds **one choke point**: removing `JDOE` from
  `HELPDESK` breaks both routes. Every other fix (the reset right, the DCSync
  grant, the local-admin rights, the admin session) closes one route but leaves
  the other open — which is exactly why the choke point is the fix to make first.

The same report runs on the website as the
[live demo](https://omar-tamerr.github.io/HorusEye/demo.html), rebuilt with
`python scripts/build_demo.py`.

> Generate larger synthetic domains for benchmarking with
> `python scripts/benchmark.py`, which uses `horuseye.synthetic`.
