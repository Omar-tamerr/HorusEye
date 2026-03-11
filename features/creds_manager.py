"""Re-export from creds_manager.py for backward compat."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from creds_manager import CredsManager
