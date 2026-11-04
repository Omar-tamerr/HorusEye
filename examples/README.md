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
| `WEB-SVC@ACME.LAB` | Intranet portal's app pool identity; local admin on `WEB01` |

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
- **Remediation options** compare three ways to break every route:
  1. *Fewest changes*: remove `JDOE` from `HELPDESK` (JDOE also loses the
     password-reset right and local admin on `WEB01`).
  2. *Keep group memberships*: remove `HELPDESK`'s reset right on
     `HELPDESK-SVC` and its local admin on `WEB01`; JDOE stays in the group.
  3. *Fix nearest the targets*: remove `HELPDESK`'s local admin on `WEB01` and
     `HELPDESK-SVC`'s DCSync rights. It cuts admin on `WEB01` rather than the
     Administrator's session, because `WEB01` also has unconstrained
     delegation: a third, inferred route to the domain that isn't drawn.

  If JDOE needs the membership for their job, add
  `--keep 'JDOE@ACME.LAB->HELPDESK@ACME.LAB'`; option 1 then becomes the
  two-change fix and the membership is never proposed.

The same report runs on the website as the
[live demo](https://omar-tamerr.github.io/HorusEye/demo.html), rebuilt with
`python scripts/build_demo.py`.

> [`acme-lab-webapp/`](acme-lab-webapp) holds the web app → AD service account
> import fixtures (`--webapps`), built on `WEB-SVC`.

> Generate larger synthetic domains for benchmarking with
> `python scripts/benchmark.py`, which uses `horuseye.synthetic`.

---

# Example dataset — `karnak-lab` (domain exposure)

A **synthetic** 1,245-user domain (`KARNAK.LAB`) in SharpHound JSON, plus a
Certipy export in `adcs/`. Every name, SID and host is invented. It exists to
show **domain exposure**: how many users can reach Tier-0, and the fewest
changes that take that to zero.

```bash
horuseye --bloodhound examples/karnak-lab --certipy examples/karnak-lab/adcs/karnak_Certipy.json \
    --domain KARNAK.LAB --dc 10.20.0.10 --explorer karnak.html

# Routes from one helpdesk user, with the remediation options
horuseye --bloodhound examples/karnak-lab --certipy examples/karnak-lab/adcs/karnak_Certipy.json \
    --domain KARNAK.LAB --dc 10.20.0.10 --graph --owned 'K.EID@KARNAK.LAB'
```

| Planted weakness | Who it exposes |
|---|---|
| Template `KarnakUser`: ESC1, enrollable by Domain Users | every user |
| `IT-SUPPORT` is local admin on all 300 workstations; `ADM-RAMSES` (Domain Admin) is signed in to `WS-0142` | 120 IT-Support members |
| `HELPDESK` can reset `SVC-BACKUP`'s password; `SVC-BACKUP` can DCSync | 40 helpdesk members, and SVC-BACKUP |
| `GPO-EDITORS` can edit `DC SECURITY BASELINE`, linked to the Domain Controllers OU | 8 GPO editors |

Expected exposure: **1,211 of 1,211 users (100%)**, and four changes take it to
zero (165 → 49 → 8 → 0 users left). Open `karnak.html`, press ✂ Apply on each
change, and watch the number fall.

Rebuild it (deterministic, same files every run): `python scripts/make_karnak_lab.py`.
