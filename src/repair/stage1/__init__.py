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
from .integer_overflow import IntegerOverflowFixer
from .buffer_overflow import BufferOverflowFixer
from .temporal_safety_cets import CETSFixer
from .memory_leak import MemoryLeakFixer
from .format_string_vulnerability import PHPTaintFixer
from .race_condition import RaceConditionFixer
from .file_handling import FileHandlingFixer

__all__ = [
    'classify_vulnerability',
    'is_stage1_repairable',
    'Stage1RepairEngine',
    'NullPointerRepair',
    'UninitializedVarRepair',
    'DeadCodeRepair',
    'IntegerOverflowFixer',
    'BufferOverflowFixer',
    'CETSFixer',
    'MemoryLeakFixer',
    'PHPTaintFixer',
    'RaceConditionFixer',
    'FileHandlingFixer'
]
