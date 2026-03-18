"""
Automated Vulnerability Repair Module
Multi-agent system using LangGraph + Local LLMs
"""

# Core components - wrapped in try/except as some submodules may be missing
try:
    from .state import RepairState, create_initial_state
except Exception:
    pass

try:
    from .llm_client import MultiProviderLLMClient, GroqClient, GeminiClient, get_client
except Exception:
    pass

try:
    from .validators import ResponseValidator
except Exception:
    pass

try:
    from .metrics import RepairMetrics
except Exception:
    pass

try:
    from .orchestrator import RepairOrchestrator, repair_vulnerability
except Exception:
    pass

# Tools - may not exist
try:
    from .tools.code_reader import CodeReader
    from .tools.patch_applier import PatchApplier
except Exception:
    pass

# Agents - may not exist
try:
    from .agents.base import BaseAgent
    from .agents.analyzer import AnalyzerAgent
    from .agents.generator import GeneratorAgent
    from .agents.validator import ValidatorAgent
except Exception:
    pass

# Stage 1 rule-based repair is always available
from .stage1 import Stage1RepairEngine
