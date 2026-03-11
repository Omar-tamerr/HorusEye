"""Claude AI analyzer — calls Claude API for narrative analysis."""
import json, urllib.request

class ClaudeAnalyzer:
    def __init__(self, api_key: str, deep: bool = False):
        self.api_key = api_key
        self.deep    = deep

    def analyze(self, findings: list, domain_data: dict) -> list:
        if not findings:
            return findings
        try:
            summary = "\n".join(
                f"- [{f.get('severity','')}] {f.get('type','')} on {f.get('affected','')}"
                for f in findings[:10]
            )
            prompt = (
                f"You are a senior red team operator. Analyze these AD attack paths for {domain_data.get('domain','')}:\n"
                f"{summary}\n\nFor each finding give a 1-sentence attack narrative. "
                f"Respond ONLY with valid JSON array: [{{"type":"...","ai_narrative":"..."}}]"
            )
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=json.dumps({
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                }).encode(),
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                text = data["content"][0]["text"]
                narratives = json.loads(text)
                narrative_map = {n["type"]: n.get("ai_narrative","") for n in narratives}
                for f in findings:
                    if f.get("type") in narrative_map:
                        f["ai_narrative"] = narrative_map[f["type"]]
        except Exception as e:
            pass  # graceful fallback — no AI narratives
        return findings
