"""Stub attack detector — detects attack paths from domain_data."""

class AttackDetector:
    def __init__(self, domain_data: dict):
        self.data = domain_data

    def detect_all(self) -> list:
        findings = []

        for spn in self.data.get("spns", []):
            findings.append({
                "type": "KERBEROASTING",
                "title": f"Kerberoastable SPN: {spn.get('user','')}",
                "affected": spn.get("user",""),
                "severity": "HIGH",
                "commands": [
                    f"impacket-GetUserSPNs {self.data.get('domain','')}/user:pass -dc-ip {self.data.get('dc_ip','')} -request"
                ]
            })

        for user in self.data.get("asrep_users", []):
            findings.append({
                "type": "ASREP_ROASTING",
                "title": f"AS-REP Roastable: {user}",
                "affected": user,
                "severity": "HIGH",
                "commands": [
                    f"impacket-GetNPUsers {self.data.get('domain','')}/{user} -no-pass -dc-ip {self.data.get('dc_ip','')}"
                ]
            })

        return findings
