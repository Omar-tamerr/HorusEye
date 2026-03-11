"""Stub parser — replace with real BloodHound/LDAP/Certipy parsers."""

def parse_all_sources(args, console=None, animated_task=None) -> dict:
    """Parse all input sources and return normalised domain_data dict."""
    domain_data = {
        "domain":   getattr(args, "domain", "") or "",
        "dc_ip":    getattr(args, "dc", "")     or "",
        "users":    [],
        "groups":   [],
        "computers":[],
        "sessions": [],
        "acls":     [],
        "gpos":     [],
        "trusts":   [],
        "certs":    [],
        "spns":     [],
        "asrep_users": [],
        "unconstrained": [],
        "constrained":   [],
        "password_policy": {},
    }

    _p = (lambda m: console.print(m)) if console else print

    if getattr(args, "manual", False):
        domain_data = _manual_input(domain_data, _p)

    if getattr(args, "bloodhound", None):
        _p(f"[dim]📂 BloodHound: {args.bloodhound} (stub — add real parser)[/dim]")

    if getattr(args, "certipy", None):
        _p(f"[dim]📂 Certipy: {args.certipy} (stub)[/dim]")

    if getattr(args, "ldap", None):
        _p(f"[dim]📂 LDAP: {args.ldap} (stub)[/dim]")

    return domain_data


def _manual_input(domain_data: dict, _p) -> dict:
    _p("\n[bold cyan]Manual Input Mode — enter what you know (press Enter to skip)[/bold cyan]\n")
    try:
        u = input("  Known usernames (comma-separated): ").strip()
        if u:
            domain_data["users"] = [x.strip() for x in u.split(",") if x.strip()]

        spns = input("  Kerberoastable SPNs (comma-separated): ").strip()
        if spns:
            domain_data["spns"] = [{"user": x.strip(), "spn": x.strip()} for x in spns.split(",") if x.strip()]

        asrep = input("  AS-REP roastable users (comma-separated): ").strip()
        if asrep:
            domain_data["asrep_users"] = [x.strip() for x in asrep.split(",") if x.strip()]

        da = input("  Known Domain Admins (comma-separated): ").strip()
        if da:
            domain_data["domain_admins"] = [x.strip() for x in da.split(",") if x.strip()]

        dc = input(f"  DC IP [{domain_data['dc_ip']}]: ").strip()
        if dc:
            domain_data["dc_ip"] = dc

    except (KeyboardInterrupt, EOFError):
        pass
    return domain_data
