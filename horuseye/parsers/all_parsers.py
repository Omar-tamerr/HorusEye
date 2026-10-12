"""
HorusEye - All Parsers
Handles BloodHound, ldapdomaindump, CrackMapExec, NetExec, Certipy, Manual
Author: Omar Tamer 🇪🇬
"""
from horuseye.parsers.bloodhound_parser import BloodHoundParser
from horuseye.parsers.ldap_parser import LDAPParser, CMEParser, CertipyParser, ManualInputCollector
from horuseye.parsers.nxc_parser import NXCParser


def parse_all_sources(args, console, animated_task):
    domain_data = {
        "domain":       args.domain,
        "dc":           getattr(args, "dc", None),
        "dc_ip":        getattr(args, "dc", None),
        "users":        [],
        "groups":       [],
        "computers":    [],
        "gpos":         [],
        "acls":         [],
        "sessions":     [],
        "trusts":       [],
        "adcs":         {},
        "cme_data":     {},
        "nxc_data":     {},
        "spns":         [],   # kerberoastable users
        "asrep_users":  [],   # AS-REP roastable users
        "local_admins": [],   # {principal, computer}
        "delegation_targets": [],  # {principal, target}
        "raw_sources":  [],
    }

    console.print()

    # ── BloodHound ─────────────────────────────────────────────────────────────
    if getattr(args, "bloodhound", None):
        animated_task("Parsing BloodHound", ["Users", "Groups", "ACLs", "Sessions", "Graph"], "cyan")
        d = BloodHoundParser(args.bloodhound).parse()
        for k in ["users", "groups", "computers", "acls", "sessions", "gpos", "trusts",
                  "local_admins", "delegation_targets"]:
            domain_data[k].extend(d.get(k, []))
        domain_data["spns"].extend(d.get("spns", []))
        domain_data["asrep_users"].extend(d.get("asrep_users", []))
        domain_data["raw_sources"].append("bloodhound")
        console.print(
            f"  [dim]└─ {len(d.get('users', []))} users, "
            f"{len(d.get('acls', []))} ACL edges[/dim]\n"
        )

    # ── ldapdomaindump ─────────────────────────────────────────────────────────
    if getattr(args, "ldap", None):
        animated_task("Parsing ldapdomaindump", ["Users", "Groups", "GPOs", "Trusts"], "cyan")
        d = LDAPParser(args.ldap).parse()
        domain_data["users"].extend(d.get("users", []))
        domain_data["groups"].extend(d.get("groups", []))
        domain_data["gpos"].extend(d.get("gpos", []))
        domain_data["trusts"].extend(d.get("trusts", []))
        domain_data["spns"].extend(d.get("spns", []))
        domain_data["asrep_users"].extend(d.get("asrep_users", []))
        if d.get("password_policy") and not domain_data.get("password_policy"):
            domain_data["password_policy"] = d["password_policy"]
        domain_data["raw_sources"].append("ldapdomaindump")
        console.print(
            f"  [dim]└─ {len(d.get('users', []))} users, "
            f"{len(d.get('groups', []))} groups[/dim]\n"
        )

    # ── CrackMapExec ───────────────────────────────────────────────────────────
    if getattr(args, "cme", None):
        animated_task("Parsing CrackMapExec", ["Admin hosts", "Shares", "Policy"], "cyan")
        domain_data["cme_data"] = CMEParser(args.cme).parse()
        domain_data["raw_sources"].append("crackmapexec")
        console.print(
            f"  [dim]└─ {len(domain_data['cme_data'].get('admin_hosts', []))} admin hosts[/dim]\n"
        )

    # ── NetExec (NXC) ──────────────────────────────────────────────────────────
    if getattr(args, "nxc", None):
        animated_task(
            "Parsing NetExec",
            ["Hosts", "Admin access", "Shares", "Sessions", "Policy"],
            "cyan"
        )
        parser = NXCParser(args.nxc)
        nxc    = parser.parse()
        domain_data["nxc_data"] = nxc
        domain_data["raw_sources"].append("netexec")

        # Merge NXC sessions into main sessions list
        for session in nxc.get("sessions", []):
            domain_data["sessions"].append({
                "UserName":    session["user"],
                "ComputerName": session["ip"],
                "source":      "nxc",
            })

        # Merge NXC computers into main computers list
        for host in nxc.get("hosts", []):
            existing = [c.get("name", "") for c in domain_data["computers"]]
            if host["hostname"] not in existing:
                domain_data["computers"].append({
                    "name":       host["hostname"],
                    "ip":         host["ip"],
                    "os":         host["os"],
                    "domain":     host["domain"],
                    "signing":    host["signing"],
                    "source":     "nxc",
                })

        # Merge password policy if not already set from BloodHound/LDAP
        if nxc.get("password_policy") and not domain_data.get("password_policy"):
            domain_data["password_policy"] = nxc["password_policy"]

        console.print(
            f"  [dim]└─ {parser.summary(nxc)}[/dim]\n"
        )

    # ── Certipy ────────────────────────────────────────────────────────────────
    if getattr(args, "certipy", None):
        animated_task(
            "Parsing Certipy",
            ["Templates", "ESC1-ESC8", "CA", "Enrollment"],
            "magenta"
        )
        domain_data["adcs"] = CertipyParser(args.certipy).parse()
        domain_data["raw_sources"].append("certipy")
        console.print(
            f"  [dim]└─ {len(domain_data['adcs'].get('vulnerabilities', []))} "
            f"ADCS vulns[/dim]\n"
        )

    # ── Manual input ───────────────────────────────────────────────────────────
    if getattr(args, "manual", False):
        d = ManualInputCollector(console).collect()
        domain_data["users"].extend(d.get("users", []))
        domain_data["spns"].extend(d.get("spns", []))
        domain_data["asrep_users"].extend(d.get("asrep_users", []))
        domain_data["raw_sources"].append("manual")

    # ── Deduplicate users ──────────────────────────────────────────────────────
    seen, unique = [], []
    for u in domain_data["users"]:
        n = u.get("name", "")
        if n and n not in seen:
            seen.append(n)
            unique.append(u)
    dropped = len(domain_data["users"]) - len(unique)
    domain_data["users"] = unique

    # ── Parse report: counts, provenance, compatibility warnings ────────────────
    report = build_parse_report(args, domain_data, dropped)
    domain_data["parse_report"] = report
    _print_parse_report(console, report)

    return domain_data


# ── Parse diagnostics ────────────────────────────────────────────────────────
def build_parse_report(args, domain_data: dict, dropped_dupes: int = 0) -> dict:
    """Summarize what was parsed and flag compatibility problems, so the operator
    knows whether a clean result means a clean domain or a thin import."""
    counts = {k: len(domain_data.get(k, []))
              for k in ("users", "groups", "computers", "acls", "sessions",
                        "gpos", "trusts", "spns", "asrep_users",
                        "local_admins", "delegation_targets")}
    warnings = []

    if getattr(args, "bloodhound", None) and counts["acls"] == 0 and counts["users"] == 0:
        warnings.append("BloodHound source given but no objects parsed — check the "
                        "directory/zip path and that it contains SharpHound JSON.")
    if getattr(args, "bloodhound", None) and counts["acls"] == 0 and counts["users"] > 0:
        warnings.append("Users parsed but zero ACL edges — ACL/DCSync/GPO detection "
                        "will be blind. Collect with SharpHound -c All (or DCOnly+ACL).")
    if counts["sessions"] == 0 and counts["local_admins"] == 0 and getattr(args, "bloodhound", None):
        warnings.append("No session or local-admin data — attack-path graph will be "
                        "limited. Collect with SharpHound -c All.")
    if counts["users"] > 0 and counts["computers"] == 0:
        warnings.append("Users but no computers — session/delegation/LSASS analysis "
                        "will be limited.")

    return {
        "sources": list(domain_data.get("raw_sources", [])),
        "counts": counts,
        "duplicate_users_dropped": dropped_dupes,
        "warnings": warnings,
    }


def _print_parse_report(console, report: dict):
    if not report["sources"]:
        return
    console.print(f"  [dim]Sources: {', '.join(report['sources'])} · "
                  f"{report['counts']['users']} users, {report['counts']['acls']} ACLs, "
                  f"{report['counts']['local_admins']} admin edges, "
                  f"{report['counts']['sessions']} sessions[/dim]")
    for w in report["warnings"]:
        console.print(f"  [yellow]⚠️  {w}[/yellow]")
    if report["warnings"]:
        console.print()
