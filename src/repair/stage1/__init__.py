"""
Stage 1: Rule-Based Automated Repair
Deterministic, template-driven fixes for well-known vulnerability classes
Based on CMU/SEI-2025-TR-007
"""

from .classifier import classify_vulnerability, is_stage1_repairable
from .repair_engine import Stage1RepairEngine
from .null_pointer import NullPointerRepair
from .uninitialized_var import UninitializedVarRepair
from .dead_code import DeadCodeRepair
from .integer_overflow import IntegerOverflowRepair

__all__ = [
    'classify_vulnerability',
    'is_stage1_repairable',
    'Stage1RepairEngine',
    'NullPointerRepair',
    'UninitializedVarRepair',
    'DeadCodeRepair',
    'IntegerOverflowRepair'
]
