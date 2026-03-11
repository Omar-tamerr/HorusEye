def print_quick_help(console=None):
    msg = """
  𓂀 HorusEye v2.0 — Quick Help
  ─────────────────────────────────────────────────
  --bloodhound DIR    BloodHound JSON folder
  --certipy FILE      Certipy output JSON
  --ldap DIR          ldapdomaindump output folder
  --manual            Interactive manual input mode
  --domain DOMAIN     Target domain (e.g. corp.local)
  --dc IP             Domain Controller IP
  --no-ai             Skip Claude AI analysis
  --report FILE       Export HTML report
  --make-wordlist     Generate username wordlist
  --spray             Password spraying
  --crack FILE        Crack hashes from file
  --timeline          Show attack timeline
  --da-checklist      Domain takeover checklist
  --team-server       Start collaboration server
  --config            Configure Claude API key
  ─────────────────────────────────────────────────
"""
    if console:
        console.print(msg)
    else:
        print(msg)
