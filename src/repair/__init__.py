"""
Automated Vulnerability Repair Module
Multi-agent system using LangGraph + Local LLMs
"""

# Core components
from .state import RepairState, create_initial_state
from .llm_client import MultiProviderLLMClient, GroqClient, GeminiClient, get_client
from .validators import ResponseValidator
from .metrics import RepairMetrics
from .orchestrator import RepairOrchestrator, repair_vulnerability

# Tools
from .tools.code_reader import CodeReader
from .tools.patch_applier import PatchApplier

# Agents
from .agents.base import BaseAgent
from .agents.analyzer import AnalyzerAgent
from .agents.generator import GeneratorAgent
from .agents.validator import ValidatorAgent

__all__ = [
    # State
    'RepairState',
    'create_initial_state',
    
    # LLM
    'MultiProviderLLMClient',
    'GroqClient',
    'GeminiClient',
    'get_client',
    
    # Validation
    'ResponseValidator',
    
    # Metrics
    'RepairMetrics',
    
    # Orchestrator
    'RepairOrchestrator',
    'repair_vulnerability',
    
    # Tools
    'CodeReader',
    'PatchApplier',
    
    # Agents
    'BaseAgent',
    'AnalyzerAgent',
    'GeneratorAgent',
    'ValidatorAgent',
]
