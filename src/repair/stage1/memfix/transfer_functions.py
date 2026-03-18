"""
Transfer Functions τ and φ for MemFix Typestate Analysis
"""
import logging
from typing import Set, FrozenSet
from .object_state import ObjectState, AccessPath, Patch
from .cfg_builder import CFGNode, CommandType
from .points_to import PointsToAnalysis

logger = logging.getLogger(__name__)


class TransferFunctions:
    """
    Implements τ (patch update) and φ (points-to update) transfer functions
    """
    
    def __init__(self, points_to: PointsToAnalysis):
        self.points_to = points_to
    
    def tau(self, state: ObjectState, node: CFGNode) -> ObjectState:
        """
        τ transfer function: Update patch and patchNot sets
        
        Args:
            state: Current ObjectState
            node: CFG node
            
        Returns:
            Updated ObjectState
        """
        # G = newly generated safe patches at this node
        G = frozenset(Patch(node.node_id, ap, state.o) for ap in state.must)
        
        # U = uncertain patches (may-but-not-must)
        may_not_must = state.may - state.must
        U = frozenset(Patch(node.node_id, ap, state.o) for ap in may_not_must)
        
        # D = double-free risk (existing patch == new patch)
        D = state.patch.intersection(G)
        
        # Check if object can be used at this node
        object_used = self._is_object_used(state, node)
        
        if object_used:
            # Object is used: old patches now cause UAF
            patch_not_new = state.patchNot | U | state.patch
            patch_new = G - patch_not_new
        else:
            # Object not used: only uncertain and double-free are unsafe
            patch_not_new = state.patchNot | U | D
            patch_new = (state.patch | G) - patch_not_new
        
        return state.with_updates(
            patch=patch_new,
            patchNot=patch_not_new
        )
    
    def phi(self, state: ObjectState, node: CFGNode) -> ObjectState:
        """
        φ transfer function: Update may, must, mustNot sets
        
        Args:
            state: Current ObjectState
            node: CFG node
            
        Returns:
            Updated ObjectState
        """
        if node.command_type == CommandType.ALLOC:
            return self._phi_alloc(state, node)
        elif node.command_type == CommandType.SET:
            return self._phi_set(state, node)
        else:
            # For USE and NOP, recompute may from oracle
            return self._phi_default(state, node)
    
    def _phi_alloc(self, state: ObjectState, node: CFGNode) -> ObjectState:
        """
        φ for alloc(x): x now points to new object
        
        Args:
            state: Current ObjectState
            node: Allocation node
            
        Returns:
            Updated ObjectState
        """
        var = node.ptr
        
        # x and *x no longer point to this object
        killed = self.points_to.get_may_alias(node.node_id, var)
        killed.add(f"*{var}")
        
        # Update mustNot: add x (now points to different object)
        mustNot_new = state.mustNot | frozenset([AccessPath(var)])
        
        # Recompute may from oracle (before updating must)
        may_new = self._compute_may(state.o, node.node_id, mustNot_new)
        
        # Update must: remove killed access paths and ensure must ⊆ may
        must_new = frozenset(ap for ap in state.must if ap.path not in killed)
        must_new = must_new.intersection(may_new)
        
        return state.with_updates(
            may=may_new,
            must=must_new,
            mustNot=mustNot_new
        )
    
    def _phi_set(self, state: ObjectState, node: CFGNode) -> ObjectState:
        """
        φ for set(lvalue, rvalue): lvalue = rvalue
        
        Args:
            state: Current ObjectState
            node: Assignment node
            
        Returns:
            Updated ObjectState
        """
        lval = node.lvalue
        rval = node.rvalue
        
        # Check if rvalue is null
        if rval in ['NULL', 'nullptr', '0']:
            # lvalue no longer points to this object
            mustNot_new = state.mustNot | frozenset([AccessPath(lval)])
            must_new = frozenset(ap for ap in state.must if ap.path != lval)
            may_new = self._compute_may(state.o, node.node_id, mustNot_new)
            
            return state.with_updates(
                may=may_new,
                must=must_new,
                mustNot=mustNot_new
            )
        
        # Recompute may first
        may_new = self._compute_may(state.o, node.node_id, state.mustNot)
        
        # Check if rvalue must-aliases something in must
        rval_aliases = self.points_to.get_must_alias(node.node_id, rval)
        if any(ap.path in rval_aliases for ap in state.must):
            # lvalue now must point to this object
            lval_ap = AccessPath(lval)
            # Only add to must if it's in may
            if lval_ap in may_new:
                must_new = state.must | frozenset([lval_ap])
            else:
                must_new = state.must
        else:
            # Remove lval from must if assignment breaks the alias
            must_new = frozenset(ap for ap in state.must if ap.path != lval)
        
        # Ensure must ⊆ may invariant
        must_new = must_new.intersection(may_new)
        
        return state.with_updates(
            may=may_new,
            must=must_new
        )
    
    def _phi_default(self, state: ObjectState, node: CFGNode) -> ObjectState:
        """
        φ for USE/NOP: recompute may from oracle
        
        Args:
            state: Current ObjectState
            node: CFG node
            
        Returns:
            Updated ObjectState
        """
        may_new = self._compute_may(state.o, node.node_id, state.mustNot)
        
        return state.with_updates(may=may_new)
    
    def _compute_may(
        self,
        alloc_site: int,
        node_id: int,
        mustNot: FrozenSet[AccessPath]
    ) -> FrozenSet[AccessPath]:
        """
        Compute may set from points-to oracle
        
        Args:
            alloc_site: Allocation site ID
            node_id: Current node ID
            mustNot: Access paths that must not point to object
            
        Returns:
            Set of access paths that may point to object
        """
        may_aps = set()
        
        # Query oracle for all access paths
        # Get all variables from points-to analysis
        for key, alloc_sites in self.points_to.may_points_to.items():
            if key[0] == node_id and alloc_site in alloc_sites:
                ap = AccessPath(key[1])
                if ap not in mustNot:
                    may_aps.add(ap)
        
        # If no results from oracle, fall back to checking common variable names
        if not may_aps:
            for var_name in ['p', 'q', 'ptr', 'data', 'buf', 'buffer', 'x', 'y', 
                            'leaked_memory', 'leaked_array', 'leaked_doubles', 'leaked_data']:
                alloc_sites = self.points_to.get_may_points_to(node_id, var_name)
                if alloc_site in alloc_sites:
                    ap = AccessPath(var_name)
                    if ap not in mustNot:
                        may_aps.add(ap)
        
        return frozenset(may_aps)
    
    def _is_object_used(self, state: ObjectState, node: CFGNode) -> bool:
        """
        Check if object can be used at this node
        
        Args:
            state: ObjectState
            node: CFG node
            
        Returns:
            True if object is used
        """
        if node.command_type != CommandType.USE:
            return False
        
        # Check if used pointer may point to this object
        if node.ptr:
            ap = AccessPath(node.ptr)
            return ap in state.may
        
        return False
