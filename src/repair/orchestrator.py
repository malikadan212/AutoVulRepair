"""
Repair Orchestrator
LangGraph workflow that coordinates all repair agents
"""
import logging
from typing import Dict, Any, Optional
from langgraph.graph import StateGraph, END

from .state import (
    RepairState,
    create_initial_state,
    update_status,
    add_message,
    is_terminal_state,
    should_retry,
    increment_retry
)
from .llm_client import BaseLLMClient, get_client
from .agents.analyzer import AnalyzerAgent
from .agents.generator import GeneratorAgent
from .agents.validator import ValidatorAgent
from .agents.base import BaseAgent
from .metrics import RepairMetrics
from .tools.code_reader import CodeReader
from .tools.patch_applier import PatchApplier

logger = logging.getLogger(__name__)


class RepairOrchestrator:
    """Orchestrates the multi-agent repair workflow using LangGraph"""
    
    def __init__(
        self,
        llm_client: BaseLLMClient = None,
        build_orchestrator=None,
        fuzz_executor=None,
        enable_optimizer: bool = False
    ):
        """
        Initialize repair orchestrator
        
        Args:
            llm_client: LLM client (uses default multi-provider if None)
            build_orchestrator: BuildOrchestrator instance (optional)
            fuzz_executor: FuzzExecutor instance (optional)
            enable_optimizer: Whether to enable optimizer agent
        """
        self.llm = llm_client or get_client()
        self.metrics = None  # Will be created per repair
        self.enable_optimizer = enable_optimizer
        
        # Initialize agents (without metrics for now)
        self.analyzer = AnalyzerAgent(self.llm)
        self.generator = GeneratorAgent(self.llm)
        self.validator = ValidatorAgent(
            self.llm,
            build_orchestrator=build_orchestrator,
            fuzz_executor=fuzz_executor
        )
        
        # Build workflow graph
        self.workflow = self._build_workflow()
        
        logger.info("RepairOrchestrator initialized")
    
    def _build_workflow(self) -> StateGraph:
        """
        Build LangGraph workflow
        
        Returns:
            Compiled StateGraph
        """
        # Create graph
        workflow = StateGraph(RepairState)
        
        # Add nodes (agents)
        workflow.add_node("analyzer", self._run_analyzer)
        workflow.add_node("generator", self._run_generator)
        workflow.add_node("validator", self._run_validator)
        
        if self.enable_optimizer:
            workflow.add_node("optimizer", self._run_optimizer)
        
        # Add edges (workflow flow)
        workflow.set_entry_point("analyzer")
        
        # Analyzer -> Generator (or retry/fail)
        workflow.add_conditional_edges(
            "analyzer",
            self._should_continue_after_analyzer,
            {
                "continue": "generator",
                "retry": "analyzer",
                "fail": END
            }
        )
        
        # Generator -> Validator (or retry/fail)
        workflow.add_conditional_edges(
            "generator",
            self._should_continue_after_generator,
            {
                "continue": "validator",
                "retry": "generator",
                "fail": END
            }
        )
        
        # Validator -> Optimizer or END
        if self.enable_optimizer:
            workflow.add_conditional_edges(
                "validator",
                self._should_optimize,
                {
                    "optimize": "optimizer",
                    "complete": END,
                    "fail": END
                }
            )
            workflow.add_edge("optimizer", END)
        else:
            workflow.add_edge("validator", END)
        
        # Compile graph
        return workflow.compile()
    
    def repair(
        self,
        vulnerability: Dict[str, Any],
        scan_id: str,
        crash_id: str,
        max_retries: int = 3
    ) -> RepairState:
        """
        Run repair workflow on a vulnerability
        
        Args:
            vulnerability: Vulnerability data from triage
            scan_id: Scan ID
            crash_id: Crash ID
            max_retries: Maximum retry attempts
            
        Returns:
            Final RepairState with results
        """
        logger.info(f"Starting repair for {crash_id}")
        
        # Create metrics for this repair
        self.metrics = RepairMetrics(scan_id)
        
        # Update agents with metrics and scan_id
        self.analyzer.metrics = self.metrics
        self.analyzer.scan_id = scan_id
        self.analyzer.code_reader = CodeReader(scan_id=scan_id)
        
        self.generator.metrics = self.metrics
        self.generator.scan_id = scan_id
        self.generator.code_reader = CodeReader(scan_id=scan_id)
        
        self.validator.metrics = self.metrics
        self.validator.scan_id = scan_id
        self.validator.patch_applier = PatchApplier(scan_id=scan_id)
        
        # Create initial state
        state = create_initial_state(
            vulnerability=vulnerability,
            scan_id=scan_id,
            crash_id=crash_id,
            max_retries=max_retries
        )
        
        # Start metrics tracking
        self.metrics.start_repair(crash_id)
        
        try:
            # Run workflow
            final_state = self.workflow.invoke(state)
            
            # Mark as completed if not failed
            if final_state['status'] != 'failed':
                final_state = update_status(final_state, 'completed')
            
            # Record metrics
            self.metrics.end_repair(
                crash_id=crash_id,
                success=(final_state['status'] == 'completed'),
                patches_generated=len(final_state.get('patches', [])),
                best_score=final_state.get('validation_results', {}).get('best_score', 0.0)
            )
            
            logger.info(f"Repair completed: {final_state['status']}")
            return final_state
            
        except Exception as e:
            logger.error(f"Repair workflow failed: {e}", exc_info=True)
            state['error'] = str(e)
            state = update_status(state, 'failed')
            
            self.metrics.end_repair(
                crash_id=crash_id,
                success=False,
                patches_generated=0,
                best_score=0.0
            )
            
            return state
    
    # ========================================================================
    # Agent Runner Functions
    # ========================================================================
    
    def _run_analyzer(self, state: RepairState) -> RepairState:
        """Run analyzer agent"""
        logger.info("Running Analyzer...")
        return self.analyzer.run(state)
    
    def _run_generator(self, state: RepairState) -> RepairState:
        """Run generator agent"""
        logger.info("Running Generator...")
        return self.generator.run(state)
    
    def _run_validator(self, state: RepairState) -> RepairState:
        """Run validator agent"""
        logger.info("Running Validator...")
        return self.validator.run(state)
    
    def _run_optimizer(self, state: RepairState) -> RepairState:
        """Run optimizer agent (placeholder)"""
        logger.info("Running Optimizer...")
        # TODO: Implement optimizer agent
        state = add_message(state, "Optimizer not yet implemented")
        return state
    
    # ========================================================================
    # Conditional Edge Functions
    # ========================================================================
    
    def _should_continue_after_analyzer(self, state: RepairState) -> str:
        """
        Decide what to do after analyzer
        
        Returns:
            'continue', 'retry', or 'fail'
        """
        if state['status'] == 'failed':
            if should_retry(state):
                state = increment_retry(state)
                return "retry"
            return "fail"
        
        if state.get('analysis'):
            return "continue"
        
        return "fail"
    
    def _should_continue_after_generator(self, state: RepairState) -> str:
        """
        Decide what to do after generator
        
        Returns:
            'continue', 'retry', or 'fail'
        """
        if state['status'] == 'failed':
            if should_retry(state):
                state = increment_retry(state)
                return "retry"
            return "fail"
        
        if state.get('patches') and len(state['patches']) > 0:
            return "continue"
        
        return "fail"
    
    def _should_optimize(self, state: RepairState) -> str:
        """
        Decide whether to optimize best patch
        
        Returns:
            'optimize', 'complete', or 'fail'
        """
        if state['status'] == 'failed':
            return "fail"
        
        if state.get('best_patch') and self.enable_optimizer:
            return "optimize"
        
        return "complete"
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get repair metrics
        
        Returns:
            Metrics dict
        """
        return self.metrics.get_summary()
    
    def check_health(self) -> bool:
        """
        Check if orchestrator is healthy
        
        Returns:
            True if healthy, False otherwise
        """
        return self.llm.check_health()
    
    def visualize_workflow(self, output_path: str = "repair_workflow.png"):
        """
        Visualize workflow graph (requires graphviz)
        
        Args:
            output_path: Path to save visualization
        """
        try:
            from langgraph.graph import Graph
            
            # Get mermaid representation
            mermaid = self.workflow.get_graph().draw_mermaid()
            
            logger.info(f"Workflow visualization:\n{mermaid}")
            
            # Try to save as image if graphviz available
            try:
                self.workflow.get_graph().draw_png(output_path)
                logger.info(f"Workflow saved to {output_path}")
            except:
                logger.warning("Could not save PNG (graphviz not installed)")
                
        except Exception as e:
            logger.error(f"Failed to visualize workflow: {e}")


# ============================================================================
# Convenience Functions
# ============================================================================

def repair_vulnerability(
    vulnerability: Dict[str, Any],
    scan_id: str,
    crash_id: str,
    orchestrator: RepairOrchestrator = None
) -> RepairState:
    """
    Convenience function to repair a single vulnerability
    
    Args:
        vulnerability: Vulnerability data
        scan_id: Scan ID
        crash_id: Crash ID
        orchestrator: RepairOrchestrator (creates default if None)
        
    Returns:
        Final RepairState
    """
    if orchestrator is None:
        orchestrator = RepairOrchestrator()
    
    return orchestrator.repair(vulnerability, scan_id, crash_id)
