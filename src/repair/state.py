"""
Repair State Management
TypedDict for LangGraph state and helper functions
"""
from typing import TypedDict, List, Dict, Optional, Any
from datetime import datetime


class RepairState(TypedDict):
    """State passed between agents in the repair workflow"""
    
    # Input data
    vulnerability: Dict[str, Any]  # Vulnerability from triage
    scan_id: str  # Scan ID
    crash_id: str  # Crash ID
    
    # Analysis results
    analysis: Optional[Dict[str, Any]]  # From Analyzer
    
    # Generated patches
    patches: List[Dict[str, Any]]  # List of patch candidates
    
    # Validation results
    validation_results: Dict[str, Any]  # From Validator
    best_patch: Optional[Dict[str, Any]]  # Best validated patch
    
    # Optimization
    optimized_patch: Optional[Dict[str, Any]]  # From Optimizer
    
    # Workflow control
    status: str  # 'pending', 'analyzing', 'generating', 'validating', 'optimizing', 'completed', 'failed'
    current_agent: str  # Current agent name
    retry_count: int  # Number of retries
    max_retries: int  # Maximum retries allowed
    
    # Logging and debugging
    messages: List[str]  # Log messages
    error: Optional[str]  # Error message if failed
    
    # Timestamps
    started_at: str  # ISO timestamp
    completed_at: Optional[str]  # ISO timestamp
    
    # Metadata
    metadata: Dict[str, Any]  # Additional metadata


def create_initial_state(
    vulnerability: Dict[str, Any],
    scan_id: str,
    crash_id: str,
    max_retries: int = 3
) -> RepairState:
    """
    Create initial repair state
    
    Args:
        vulnerability: Vulnerability data from triage
        scan_id: Scan ID
        crash_id: Crash ID
        max_retries: Maximum retry attempts
        
    Returns:
        Initial RepairState
    """
    return RepairState(
        # Input
        vulnerability=vulnerability,
        scan_id=scan_id,
        crash_id=crash_id,
        
        # Results (empty initially)
        analysis=None,
        patches=[],
        validation_results={},
        best_patch=None,
        optimized_patch=None,
        
        # Control
        status='pending',
        current_agent='',
        retry_count=0,
        max_retries=max_retries,
        
        # Logging
        messages=[],
        error=None,
        
        # Timestamps
        started_at=datetime.utcnow().isoformat(),
        completed_at=None,
        
        # Metadata
        metadata={}
    )


def update_status(state: RepairState, status: str, agent: str = '') -> RepairState:
    """
    Update workflow status
    
    Args:
        state: Current state
        status: New status
        agent: Current agent name
        
    Returns:
        Updated state
    """
    state['status'] = status
    if agent:
        state['current_agent'] = agent
    
    if status in ['completed', 'failed']:
        state['completed_at'] = datetime.utcnow().isoformat()
    
    return state


def add_message(state: RepairState, message: str) -> RepairState:
    """
    Add log message to state
    
    Args:
        state: Current state
        message: Message to add
        
    Returns:
        Updated state
    """
    timestamp = datetime.utcnow().strftime('%H:%M:%S')
    state['messages'].append(f"[{timestamp}] {message}")
    return state


def add_patch(state: RepairState, patch: Dict[str, Any]) -> RepairState:
    """
    Add patch candidate to state
    
    Args:
        state: Current state
        patch: Patch data
        
    Returns:
        Updated state
    """
    state['patches'].append(patch)
    return state


def set_best_patch(state: RepairState, patch: Dict[str, Any]) -> RepairState:
    """
    Set the best validated patch
    
    Args:
        state: Current state
        patch: Best patch
        
    Returns:
        Updated state
    """
    state['best_patch'] = patch
    return state


def get_vulnerability_summary(state: RepairState) -> str:
    """
    Get human-readable vulnerability summary
    
    Args:
        state: Current state
        
    Returns:
        Summary string
    """
    vuln = state['vulnerability']
    return (
        f"{vuln.get('crash_type', 'Unknown')} in "
        f"{vuln.get('file', 'unknown')}:{vuln.get('line', 0)} "
        f"({vuln.get('function', 'unknown')})"
    )


def get_patch_summary(patch: Dict[str, Any]) -> str:
    """
    Get human-readable patch summary
    
    Args:
        patch: Patch data
        
    Returns:
        Summary string
    """
    return (
        f"{patch.get('type', 'unknown')} patch for {patch.get('file', 'unknown')} "
        f"({patch.get('lines_added', 0)}+ / {patch.get('lines_removed', 0)}-)"
    )


def is_terminal_state(state: RepairState) -> bool:
    """
    Check if state is terminal (completed or failed)
    
    Args:
        state: Current state
        
    Returns:
        True if terminal, False otherwise
    """
    return state['status'] in ['completed', 'failed']


def should_retry(state: RepairState) -> bool:
    """
    Check if workflow should retry
    
    Args:
        state: Current state
        
    Returns:
        True if should retry, False otherwise
    """
    return (
        state['status'] == 'failed' and
        state['retry_count'] < state['max_retries']
    )


def increment_retry(state: RepairState) -> RepairState:
    """
    Increment retry counter
    
    Args:
        state: Current state
        
    Returns:
        Updated state
    """
    state['retry_count'] += 1
    state = add_message(state, f"Retry {state['retry_count']}/{state['max_retries']}")
    return state
