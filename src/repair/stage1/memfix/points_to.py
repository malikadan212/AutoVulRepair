"""
Points-To and Alias Analysis for MemFix
Implements may-points-to, may-alias, and must-alias analyses
"""
import logging
from typing import Dict, Set, List, Tuple
from .cfg_builder import CFG, CFGNode, CommandType
from .object_state import AccessPath

logger = logging.getLogger(__name__)


class PointsToAnalysis:
    """
    Flow-sensitive, context-insensitive may-points-to analysis
    Andersen-style algorithm
    """
    
    def __init__(self, cfg: CFG):
        self.cfg = cfg
        # Maps (node_id, access_path) -> Set[alloc_site]
        self.may_points_to: Dict[Tuple[int, str], Set[int]] = {}
        # Maps (node_id, access_path) -> Set[access_path]
        self.may_alias: Dict[Tuple[int, str], Set[str]] = {}
        self.must_alias: Dict[Tuple[int, str], Set[str]] = {}
    
    def analyze(self):
        """Run points-to analysis"""
        logger.info("Running points-to analysis...")
        
        # Initialize
        for node_id, node in self.cfg.nodes.items():
            if node.command_type == CommandType.ALLOC:
                # ptr points to allocation site
                key = (node_id, node.ptr)
                self.may_points_to[key] = {node_id}
                self.may_alias[key] = {node.ptr}
                self.must_alias[key] = {node.ptr}
        
        # Forward dataflow iteration
        changed = True
        iterations = 0
        max_iterations = 100
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for node_id in self.cfg.nodes:
                if self._propagate_node(node_id):
                    changed = True
        
        logger.info(f"Points-to analysis converged in {iterations} iterations")
    
    def _propagate_node(self, node_id: int) -> bool:
        """
        Propagate points-to information through a node
        
        Returns:
            True if information changed
        """
        node = self.cfg.get_node(node_id)
        if not node:
            return False
        
        changed = False
        
        # Propagate from predecessors
        for pred_id in node.predecessors:
            # Copy predecessor's points-to info
            for key, alloc_sites in list(self.may_points_to.items()):
                if key[0] == pred_id:
                    var = key[1]
                    new_key = (node_id, var)
                    
                    if new_key not in self.may_points_to:
                        self.may_points_to[new_key] = set()
                    
                    old_size = len(self.may_points_to[new_key])
                    self.may_points_to[new_key].update(alloc_sites)
                    
                    if len(self.may_points_to[new_key]) > old_size:
                        changed = True
        
        # Apply transfer function
        if node.command_type == CommandType.SET:
            # Assignment: lvalue = rvalue
            if node.rvalue in ['NULL', 'nullptr', '0']:
                # Points to nothing
                key = (node_id, node.lvalue)
                if key in self.may_points_to:
                    del self.may_points_to[key]
                    changed = True
            else:
                # Copy points-to from rvalue to lvalue
                rval_key = (node_id, node.rvalue)
                if rval_key in self.may_points_to:
                    lval_key = (node_id, node.lvalue)
                    if lval_key not in self.may_points_to:
                        self.may_points_to[lval_key] = set()
                    
                    old_size = len(self.may_points_to[lval_key])
                    self.may_points_to[lval_key].update(self.may_points_to[rval_key])
                    
                    if len(self.may_points_to[lval_key]) > old_size:
                        changed = True
        
        return changed
    
    def get_may_points_to(self, node_id: int, access_path: str) -> Set[int]:
        """
        Get allocation sites that access_path may point to at node
        
        Args:
            node_id: CFG node ID
            access_path: Access path string
            
        Returns:
            Set of allocation site IDs
        """
        key = (node_id, access_path)
        return self.may_points_to.get(key, set())
    
    def get_may_alias(self, node_id: int, access_path: str) -> Set[str]:
        """
        Get access paths that may alias with access_path at node
        
        Args:
            node_id: CFG node ID
            access_path: Access path string
            
        Returns:
            Set of access path strings
        """
        # Simple implementation: all vars pointing to same allocation sites
        alloc_sites = self.get_may_points_to(node_id, access_path)
        if not alloc_sites:
            return {access_path}
        
        aliases = {access_path}
        for key, sites in self.may_points_to.items():
            if key[0] == node_id and sites.intersection(alloc_sites):
                aliases.add(key[1])
        
        return aliases
    
    def get_must_alias(self, node_id: int, access_path: str) -> Set[str]:
        """
        Get access paths that must alias with access_path at node
        
        Args:
            node_id: CFG node ID
            access_path: Access path string
            
        Returns:
            Set of access path strings
        """
        # Simplified: only exact same variable must-aliases
        # Full implementation would use flow-sensitive must-alias analysis
        return {access_path}
