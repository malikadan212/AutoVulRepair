"""
Base Agent Class
Shared functionality for all repair agents
"""
import time
import logging
from datetime import datetime
from typing import Dict, Optional
from abc import ABC, abstractmethod

from ..state import RepairState, add_message, update_status
from ..llm_client import BaseLLMClient
from ..metrics import RepairMetrics

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class for all repair agents"""
    
    def __init__(self, llm_client: BaseLLMClient, metrics: Optional[RepairMetrics] = None):
        """
        Initialize base agent
        
        Args:
            llm_client: Ollama client for LLM calls
            metrics: Metrics tracker (optional)
        """
        self.llm = llm_client
        self.metrics = metrics
        self.logger = logging.getLogger(self.__class__.__name__)
        self.agent_name = self.__class__.__name__
    
    def run(self, state: RepairState) -> RepairState:
        """
        Run agent with logging, timing, and error handling
        
        Args:
            state: Current repair state
            
        Returns:
            Updated repair state
        """
        start_time = time.time()
        
        self.logger.info(f"[{self.agent_name}] Starting...")
        state = add_message(state, f"{self.agent_name} started")
        
        try:
            # Run agent-specific logic
            state = self._execute(state)
            
            # Calculate elapsed time
            elapsed = time.time() - start_time
            
            # Log success
            self.logger.info(f"[{self.agent_name}] Completed in {elapsed:.2f}s")
            state = add_message(state, f"{self.agent_name} completed ({elapsed:.2f}s)")
            
            # Track metrics
            if self.metrics:
                self.metrics.track_agent(
                    agent_name=self.agent_name,
                    duration=elapsed,
                    success=True
                )
            
            return state
            
        except Exception as e:
            # Calculate elapsed time
            elapsed = time.time() - start_time
            
            # Log error
            self.logger.error(f"[{self.agent_name}] Failed after {elapsed:.2f}s: {e}", exc_info=True)
            state = add_message(state, f"{self.agent_name} failed: {str(e)}")
            
            # Update state
            state['error'] = f"{self.agent_name}: {str(e)}"
            state['status'] = 'failed'
            
            # Track metrics
            if self.metrics:
                self.metrics.track_agent(
                    agent_name=self.agent_name,
                    duration=elapsed,
                    success=False,
                    details={'error': str(e)}
                )
            
            return state
    
    @abstractmethod
    def _execute(self, state: RepairState) -> RepairState:
        """
        Execute agent-specific logic
        
        This method must be implemented by subclasses
        
        Args:
            state: Current repair state
            
        Returns:
            Updated repair state
        """
        raise NotImplementedError(f"{self.agent_name} must implement _execute()")
    
    def log(self, message: str, level: str = 'info'):
        """
        Log message with agent name prefix
        
        Args:
            message: Message to log
            level: Log level ('info', 'warning', 'error', 'debug')
        """
        log_func = getattr(self.logger, level, self.logger.info)
        log_func(f"[{self.agent_name}] {message}")
    
    def validate_state(self, state: RepairState, required_fields: list) -> bool:
        """
        Validate that state has required fields
        
        Args:
            state: State to validate
            required_fields: List of required field names
            
        Returns:
            True if valid, False otherwise
        """
        for field in required_fields:
            if field not in state or state[field] is None:
                self.log(f"Missing required field: {field}", level='error')
                return False
        return True
    
    def should_retry(self, state: RepairState) -> bool:
        """
        Check if agent should retry
        
        Args:
            state: Current state
            
        Returns:
            True if should retry, False otherwise
        """
        return state['retry_count'] < state['max_retries']
    
    def increment_retry(self, state: RepairState) -> RepairState:
        """
        Increment retry counter
        
        Args:
            state: Current state
            
        Returns:
            Updated state
        """
        state['retry_count'] += 1
        self.log(f"Retry {state['retry_count']}/{state['max_retries']}")
        return state
