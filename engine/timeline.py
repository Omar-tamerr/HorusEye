"""Re-export AttackTimeline from attack_timeline.py for backward compat."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from attack_timeline import AttackTimeline
