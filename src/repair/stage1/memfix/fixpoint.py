"""
Fixed-Point Iteration for MemFix Typestate Analysis
Computes least fixed point of F over the CFG
"""
import logging
from typing import Dict, Set, List
from collections import defaultdict
from .cfg_builder import CFG, CFGNode, CommandType
from .object_state import ObjectState, create_initial_state
from .transfer_functions import TransferFunctions
from .points_to import PointsToAnalysis

logger = logging.getLogger(__name__)


class FixedPointAnalysis:
    """
    Computes fixed point of typestate analysis
    Uses worklist algorithm for efficiency
    """
    
    def __init__(self, cfg: CFG, points_to: PointsToAnalysis):
        self.cfg = cfg
        self.points_to = points_to
        self.transfer = TransferFunctions(points_to)
        
        # D: NodeID -> Set[ObjectState]
        self.D: Dict[int, Set[ObjectState]] = defaultdict(set)
    
    def analyze(self) -> Dict[int, Set[ObjectState]]:
        """
        Run fixed-point iteration
        
        Returns:
            D mapping node IDs to sets of ObjectStates
        """
        logger.info("Starting fixed-point iteration...")
        
        # Initialize worklist with all nodes
        worklist = list(self.cfg.nodes.keys())
        
        # Initialize entry node with empty set
        if self.cfg.entry_node is not None:
            self.D[self.cfg.entry_node] = set()
        
        iterations = 0
        max_iterations = 1000
        
        while worklist and iterations < max_iterations:
            iterations += 1
            node_id = worklist.pop(0)
            
            # Compute new state for this node
            old_state = self.D[node_id].copy()
            new_state = self._compute_node_state(node_id)
            
            # Check if changed
            if new_state != old_state:
                self.D[node_id] = new_state
                
                # Add successors to worklist
                node = self.cfg.get_node(node_id)
                if node:
                    for succ_id in node.successors:
                        if succ_id not in worklist:
                            worklist.append(succ_id)
        
        if iterations >= max_iterations:
            logger.warning(f"Fixed-point iteration did not converge after {max_iterations} iterations")
        else:
            logger.info(f"Fixed-point converged in {iterations} iterations")
        
        return dict(self.D)
    
    def _compute_node_state(self, node_id: int) -> Set[ObjectState]:
        """
        Compute state at a node using F
        
        Args:
            node_id: CFG node ID
            
        Returns:
            Set of ObjectStates at this node
        """
        node = self.cfg.get_node(node_id)
        if not node:
            return set()
        
        # JOIN: union of all predecessor states
        joined_states = set()
        for pred_id in node.predecessors:
            joined_states.update(self.D[pred_id])
        
        # Apply transfer function f_node
        return self._apply_transfer(node, joined_states)
    
    def _apply_transfer(
        self,
        node: CFGNode,
        states: Set[ObjectState]
    ) -> Set[ObjectState]:
        """
        Apply transfer function for node command type
        
        Args:
            node: CFG node
            states: Input states
            
        Returns:
            Output states
        """
        if node.command_type == CommandType.ALLOC:
            return self._transfer_alloc(node, states)
        elif node.command_type == CommandType.FREE:
            return self._transfer_free(node, states)
        elif node.command_type == CommandType.SET:
            return self._transfer_set(node, states)
        elif node.command_type == CommandType.USE:
            return self._transfer_use(node, states)
        else:  # NOP
            return self._transfer_nop(node, states)
    
    def _transfer_alloc(
        self,
        node: CFGNode,
        states: Set[ObjectState]
    ) -> Set[ObjectState]:
        """
        Transfer function for alloc(x)
        
        Args:
            node: Allocation node
            states: Input states
            
        Returns:
            Output states
        """
        # Determine allocation type from original code
        alloc_type = 'malloc'
        if node.original_code:
            if 'new ' in node.original_code:
                if '[' in node.original_code:
                    alloc_type = 'new[]'
                else:
                    alloc_type = 'new'
            elif 'fopen' in node.original_code:
                alloc_type = 'fopen'
        
        # Create new ObjectState for this allocation
        new_state = create_initial_state(node.node_id, node.ptr, alloc_type)
        
        # Update existing states via φ then τ
        updated_states = set()
        for state in states:
            # Apply φ (points-to update)
            state_phi = self.transfer.phi(state, node)
            # Apply τ (patch update)
            state_tau = self.transfer.tau(state_phi, node)
            updated_states.add(state_tau)
        
        # Add new state
        updated_states.add(new_state)
        
        return updated_states
    
    def _transfer_free(
        self,
        node: CFGNode,
        states: Set[ObjectState]
    ) -> Set[ObjectState]:
        """
        Transfer function for free(ptr)
        
        CRITICAL: Ignores all existing free() statements
        Treats them as NOP
        
        Args:
            node: Free node
            states: Input states
            
        Returns:
            Output states (unchanged)
        """
        # Pass through unchanged - ignore existing frees
        return states
    
    def _transfer_set(
        self,
        node: CFGNode,
        states: Set[ObjectState]
    ) -> Set[ObjectState]:
        """
        Transfer function for set(lvalue, rvalue)
        
        Args:
            node: Assignment node
            states: Input states
            
        Returns:
            Output states
        """
        updated_states = set()
        for state in states:
            # Apply φ then τ
            state_phi = self.transfer.phi(state, node)
            state_tau = self.transfer.tau(state_phi, node)
            updated_states.add(state_tau)
        
        return updated_states
    
    def _transfer_use(
        self,
        node: CFGNode,
        states: Set[ObjectState]
    ) -> Set[ObjectState]:
        """
        Transfer function for use(ptr)
        
        Args:
            node: Use node
            states: Input states
            
        Returns:
            Output states
        """
        updated_states = set()
        for state in states:
            # Apply φ then τ
            state_phi = self.transfer.phi(state, node)
            state_tau = self.transfer.tau(state_phi, node)
            updated_states.add(state_tau)
        
        return updated_states
    
    def _transfer_nop(
        self,
        node: CFGNode,
        states: Set[ObjectState]
    ) -> Set[ObjectState]:
        """
        Transfer function for nop
        
        Args:
            node: NOP node
            states: Input states
            
        Returns:
            Output states
        """
        updated_states = set()
        for state in states:
            # Apply φ then τ
            state_phi = self.transfer.phi(state, node)
            state_tau = self.transfer.tau(state_phi, node)
            updated_states.add(state_tau)
        
        return updated_states
