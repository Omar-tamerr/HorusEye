#!/usr/bin/env python3
"""
Build examples/karnak-lab: a synthetic ~1,250-user domain for the domain
exposure demo, in SharpHound JSON plus a Certipy export.

Everything is invented (names, SIDs, hosts). The weaknesses are planted so the
exposure story is easy to follow:

  * ESC1 on the KarnakUser template, open to Domain Users  -> every user
  * HELPDESK can reset SVC-BACKUP's password; SVC-BACKUP can DCSync
  * IT-SUPPORT is local admin on every workstation; a Domain Admin is signed
    in to one of them
  * GPO-EDITORS can edit a GPO linked to the Domain Controllers OU

    python scripts/make_karnak_lab.py          # deterministic: same files every run
"""
import json
import random
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "examples" / "karnak-lab"
DOMAIN = "KARNAK.LAB"
DSID = "S-1-5-21-4242424242-1717171717-2626262626"

FIRST = "ABCDEFGHIKLMNORSTWYZ"
LAST = ["AHMED", "ALI", "ADEL", "AMIN", "ASHRAF", "BAKR", "DIAB", "EID", "FAHMY", "FARID",
        "FAWZY", "GABER", "GAMAL", "HAFEZ", "HAMDY", "HASSAN", "HEGAZY", "HELMY", "HOSNY",
        "IBRAHIM", "ISMAIL", "KAMAL", "KHALIL", "LOTFY", "MAHER", "MAHMOUD", "MANSOUR",
        "MORSY", "MOSTAFA", "NABIL", "NAGUIB", "NASSER", "OSMAN", "RAGAB", "RAMADAN",
        "RASHAD", "SABRY", "SALAH", "SALEM", "SAMIR", "SAYED", "SHAWKY", "SHERIF", "SOLIMAN",
        "TAHA", "TAWFIK", "WAHBA", "YOUSSEF", "ZAKI", "ZAKARIA"]


def main() -> None:
    rng = random.Random(4242)
    guid = lambda: str(uuid.UUID(int=rng.getrandbits(128))).upper()  # noqa: E731
    rid = iter(range(1100, 100000))

    def sid(r=None):
        return f"{DSID}-{r if r is not None else next(rid)}"

    def ace(principal_sid, right):
        return {"PrincipalSID": principal_sid, "PrincipalType": "Group", "RightName": right,
                "IsInherited": False}

    users, groups, computers, ous, gpos = [], [], [], [], []

    def user(name, enabled=True, admincount=False, **props):
        u = {"ObjectIdentifier": sid(), "Properties": dict(
            name=f"{name}@{DOMAIN}", domain=DOMAIN, enabled=enabled, admincount=admincount, **props),
            "Aces": []}
        users.append(u)
        return u

    # Tier-0 accounts
    administrator = user("ADMINISTRATOR", admincount=True)
    administrator["ObjectIdentifier"] = sid(500)
    ramses = user("ADM-RAMSES", admincount=True)
    nefertari = user("ADM-NEFERTARI", admincount=True)

    # Service accounts
    svc_backup = user("SVC-BACKUP", description="Backup service")
    svc_sql = user("SVC-SQL", hasspn=True, serviceprincipalnames=["MSSQLSvc/srv-sql01.karnak.lab:1433"])

    # Staff: ~1,240 people, some accounts disabled
    seen, staff = set(), []
    while len(staff) < 1240:
        base = f"{rng.choice(FIRST)}.{rng.choice(LAST)}"
        name, k = base, 2
        while name in seen:
            name, k = f"{base}{k}", k + 1
        seen.add(name)
        staff.append(user(name, enabled=rng.random() > 0.025))

    def group(name, members, admincount=False, r=None):
        g = {"ObjectIdentifier": sid(r), "Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN,
                                                        "admincount": admincount},
             "Members": [{"ObjectIdentifier": m["ObjectIdentifier"],
                          "ObjectType": "Computer" if m in computers else "User"} for m in members],
             "Aces": []}
        groups.append(g)
        return g

    pool = list(staff)
    rng.shuffle(pool)
    helpdesk_m, it_m, gpo_m = pool[:40], pool[40:160], pool[160:168]
    others = pool[168:]

    # Computers
    def computer(name, **props):
        c = {"ObjectIdentifier": sid(), "Properties": dict(name=f"{name}.{DOMAIN}", domain=DOMAIN,
                                                            enabled=True, **props),
             "LocalAdmins": {"Results": []}, "Sessions": {"Results": []}, "Aces": []}
        computers.append(c)
        return c

    dc01 = computer("DC01", operatingsystem="Windows Server 2022")
    workstations = [computer(f"WS-{i:04d}", operatingsystem="Windows 11 Enterprise") for i in range(1, 301)]
    servers = [computer(n, operatingsystem="Windows Server 2022") for n in
               ("SRV-FILE01", "SRV-SQL01", "SRV-WEB01", "SRV-APP01", "SRV-PRINT01")]

    da = group("DOMAIN ADMINS", [administrator, ramses, nefertari], admincount=True, r=512)
    group("DOMAIN USERS", [], r=513)
    group("DOMAIN CONTROLLERS", [dc01], admincount=True, r=516)
    helpdesk = group("HELPDESK", helpdesk_m)
    it_support = group("IT-SUPPORT", it_m)
    gpo_editors = group("GPO-EDITORS", gpo_m)
    for dept, n in (("FINANCE", 180), ("HR", 60), ("SALES", 320), ("ENGINEERING", 240), ("MARKETING", 90)):
        group(dept, rng.sample(others, n))

    # IT-SUPPORT administers every workstation (classic, and fine on its own)…
    for ws in workstations:
        ws["LocalAdmins"]["Results"].append({"ObjectIdentifier": it_support["ObjectIdentifier"],
                                             "ObjectType": "Group"})
        # ordinary sign-ins (noise)
        for u in rng.sample(others, 2):
            ws["Sessions"]["Results"].append({"UserSID": u["ObjectIdentifier"],
                                              "ComputerSID": ws["ObjectIdentifier"]})
    # …but a Domain Admin signed in to one of them.
    ws142 = workstations[141]
    ws142["Sessions"]["Results"].append({"UserSID": ramses["ObjectIdentifier"],
                                         "ComputerSID": ws142["ObjectIdentifier"]})
    for srv in servers:
        srv["LocalAdmins"]["Results"].append({"ObjectIdentifier": da["ObjectIdentifier"], "ObjectType": "Group"})

    # HELPDESK can reset SVC-BACKUP's password; SVC-BACKUP can DCSync.
    svc_backup["Aces"].append(ace(helpdesk["ObjectIdentifier"], "ForceChangePassword"))

    # GPOs
    def gpo(name, editors=()):
        g = {"ObjectIdentifier": guid(), "Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN},
             "Aces": [ace(da["ObjectIdentifier"], "GenericAll")]
                     + [ace(e["ObjectIdentifier"], "GenericWrite") for e in editors]}
        gpos.append(g)
        return g

    ddp = gpo("DEFAULT DOMAIN POLICY")
    dcp = gpo("DEFAULT DOMAIN CONTROLLERS POLICY")
    dc_baseline = gpo("DC SECURITY BASELINE", editors=[gpo_editors])
    ws_baseline = gpo("WORKSTATION BASELINE", editors=[it_support])

    def ou(name, children, links=(), blocks=False):
        o = {"ObjectIdentifier": guid(),
             "Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "blocksinheritance": blocks},
             "Links": [{"GUID": g["ObjectIdentifier"], "IsEnforced": False} for g in links],
             "ChildObjects": [{"ObjectIdentifier": c["ObjectIdentifier"],
                               "ObjectType": "Computer" if c in computers else ("OU" if c in ous else "User")}
                              for c in children],
             "Aces": []}
        ous.append(o)
        return o

    ou_dc = ou("DOMAIN CONTROLLERS", [dc01], links=[dcp, dc_baseline])
    ou_ws = ou("WORKSTATIONS", workstations, links=[ws_baseline])
    ou_srv = ou("SERVERS", servers)
    ou_staff = ou("STAFF", staff + [svc_backup, svc_sql])
    ou_admins = ou("ADMIN ACCOUNTS", [administrator, ramses, nefertari], blocks=True)

    domain = {"ObjectIdentifier": DSID, "Properties": {"name": DOMAIN, "domain": DOMAIN,
                                                      "functionallevel": "2016"},
              "Links": [{"GUID": ddp["ObjectIdentifier"], "IsEnforced": False}],
              "ChildObjects": [{"ObjectIdentifier": o["ObjectIdentifier"], "ObjectType": "OU"}
                               for o in (ou_dc, ou_ws, ou_srv, ou_staff, ou_admins)],
              "Aces": [ace(svc_backup["ObjectIdentifier"], "GetChanges"),
                       ace(svc_backup["ObjectIdentifier"], "GetChangesAll")],
              "Trusts": []}

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "adcs").mkdir(exist_ok=True)
    for kind, rows in (("users", users), ("groups", groups), ("computers", computers),
                       ("ous", ous), ("gpos", gpos), ("domains", [domain])):
        (OUT / f"karnak_{kind}.json").write_text(
            json.dumps({"meta": {"type": kind, "count": len(rows), "version": 5}, "data": rows},
                       separators=(",", ":")), encoding="utf-8")

    certipy = {
        "Certificate Authorities": {"0": {
            "CA Name": "KARNAK-CA", "DNS Name": "srv-app01.karnak.lab",
            "Certificate Subject": "CN=KARNAK-CA, DC=KARNAK, DC=LAB",
            "Web Enrollment": "Disabled", "User Specified SAN": "Disabled",
            "Request Disposition": "Issue",
            "Permissions": {"Owner": "KARNAK.LAB\\Administrators",
                            "Access Rights": {"ManageCa": ["KARNAK.LAB\\Domain Admins"],
                                              "ManageCertificates": ["KARNAK.LAB\\Domain Admins"],
                                              "Enroll": ["KARNAK.LAB\\Authenticated Users"]}}}},
        "Certificate Templates": {
            "0": {"Template Name": "KarnakUser", "Display Name": "Karnak User",
                  "Certificate Authorities": ["KARNAK-CA"], "Enabled": True,
                  "Client Authentication": True, "Enrollee Supplies Subject": True,
                  "Requires Manager Approval": False, "Extended Key Usage": ["Client Authentication"],
                  "Permissions": {
                      "Enrollment Permissions": {"Enrollment Rights": [
                          "KARNAK.LAB\\Domain Admins", "KARNAK.LAB\\Domain Users"]},
                      "Object Control Permissions": {"Owner": "KARNAK.LAB\\Administrator",
                                                     "Write Property Principals": ["KARNAK.LAB\\Domain Admins"]}},
                  "[!] Vulnerabilities": {
                      "ESC1": "'KARNAK.LAB\\\\Domain Users' can enroll, enrollee supplies subject "
                              "and template allows client authentication"}},
            "1": {"Template Name": "User", "Display Name": "User",
                  "Certificate Authorities": ["KARNAK-CA"], "Enabled": True,
                  "Client Authentication": True, "Enrollee Supplies Subject": False,
                  "Permissions": {"Enrollment Permissions": {"Enrollment Rights": [
                      "KARNAK.LAB\\Domain Users"]}}},
        },
    }
    (OUT / "adcs" / "karnak_Certipy.json").write_text(json.dumps(certipy, indent=2), encoding="utf-8")
    enabled = sum(1 for u in users if u["Properties"]["enabled"])
    print(f"wrote {OUT.relative_to(ROOT)}: {len(users):,} users ({enabled:,} enabled), "
          f"{len(groups)} groups, {len(computers)} computers, {len(gpos)} GPOs, {len(ous)} OUs")


if __name__ == "__main__":
    main()
