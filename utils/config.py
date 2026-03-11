import json, os
from pathlib import Path

CONFIG_PATH = Path.home() / ".horuseye" / "config.json"

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            pass
    return {}

def save_config(**kwargs):
    CONFIG_PATH.parent.mkdir(exist_ok=True)
    existing = load_config()
    existing.update({k: v for k, v in kwargs.items() if v is not None})
    CONFIG_PATH.write_text(json.dumps(existing, indent=2))
    print(f"✓ Config saved → {CONFIG_PATH}")
