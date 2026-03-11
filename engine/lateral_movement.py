"""Re-export LateralMovementEngine for backward compat."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from lateral_movement import LateralMovementEngine
