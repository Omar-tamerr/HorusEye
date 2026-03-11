"""Re-export from team_collab.py for backward compat."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from team_collab import CollabServer as TeamServer, CollabClient as TeamClient

class TeamBroadcaster:
    """Lightweight broadcaster used by the main analysis loop."""
    def __init__(self, console=None, connect_str: str = None):
        self.console     = console
        self.connect_str = connect_str
        self._client     = None
        if connect_str:
            self._client = TeamClient(console)
            self._client.connect(*self._parse(connect_str))

    def broadcast(self, data: dict):
        if self._client:
            try:
                if data.get("event") == "creds_found":
                    self._client.send_cred(data.get("creds", {}))
                elif data.get("event") == "findings":
                    pass  # bulk findings sent via sync on join
            except Exception:
                pass

    @staticmethod
    def _parse(s: str):
        parts = s.split(":")
        return parts[0], int(parts[1]) if len(parts) > 1 else 9999
