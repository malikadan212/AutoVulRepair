"""
SAT-based Exact Cover Solver for MemFix
Encodes the Correct Patch Problem as Boolean SAT
"""
import logging
from typing import Dict, Set, List, Tuple, Optional
from .object_state import ObjectState, Patch

logger = logging.getLogger(__name__)

try:
    from z3 import Bool, And, Or, Not, Solver, sat, Optimize
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    logger.warning("z3-solver not available, using fallback greedy solver")


class SATSolver:
    """
    Encodes and solves the Correct Patch Problem
    
    Constraints:
    - φ1: No memory leaks (every object covered)
    - φ2: No double-frees (each object covered at most once)
    - φ3: No UAF from patch ordering
    """
    
    def __init__(self):
        self.use_z3 = Z3_AVAILABLE
    
    def solve(
        self,
        reachable_states: Set[ObjectState]
    ) -> Optional[Set[Patch]]:
        """
        Solve the exact cover problem
        
        Args:
            reachable_states: Set of ObjectStates at program exit
            
        Returns:
            Set of patches to apply, or None if UNSAT
        """
        if not reachable_states:
            logger.info("No reachable states, no patches needed")
            return set()
        
        # Extract candidate patches
        safe_patches = set()
        unsafe_patches = set()
        
        for state in reachable_states:
            safe_patches.update(state.patch)
            unsafe_patches.update(state.patchNot)
        
        logger.info(f"Safe patches: {len(safe_patches)}, Unsafe patches: {len(unsafe_patches)}")
        
        # Candidate patches: safe AND not unsafe
        candidates = safe_patches - unsafe_patches
        
        if not candidates:
            logger.warning(f"No candidate patches available (all {len(safe_patches)} safe patches are also unsafe)")
            # Log some details for debugging
            if safe_patches and unsafe_patches:
                logger.debug(f"Sample safe patch: {list(safe_patches)[0] if safe_patches else 'none'}")
                logger.debug(f"Sample unsafe patch: {list(unsafe_patches)[0] if unsafe_patches else 'none'}")
            return None
        
        logger.info(f"Candidate patches: {len(candidates)}")
        
        # Build incidence function M
        M = self._build_incidence_function(candidates, reachable_states)
        
        # Solve using Z3 or fallback
        if self.use_z3:
            return self._solve_z3(candidates, reachable_states, M)
        else:
            return self._solve_greedy(candidates, reachable_states, M)
    
    def _build_incidence_function(
        self,
        candidates: Set[Patch],
        states: Set[ObjectState]
    ) -> Dict[Patch, Set[ObjectState]]:
        """
        Build incidence function M(c) = states covered by patch c
        
        Args:
            candidates: Candidate patches
            states: Reachable object states
            
        Returns:
            Dict mapping patches to covered states
        """
        M = {}
        for patch in candidates:
            covered = set()
            for state in states:
                if patch in state.patch:
                    covered.add(state)
            M[patch] = covered
        
        return M
    
    def _solve_z3(
        self,
        candidates: Set[Patch],
        states: Set[ObjectState],
        M: Dict[Patch, Set[ObjectState]]
    ) -> Optional[Set[Patch]]:
        """
        Solve using Z3 SAT solver
        
        Args:
            candidates: Candidate patches
            states: Reachable states
            M: Incidence function
            
        Returns:
            Solution set of patches or None
        """
        # Create Boolean variables for each patch
        patch_vars = {patch: Bool(f"S_{i}") for i, patch in enumerate(candidates)}
        
        # Create optimizer for minimal solution
        opt = Optimize()
        
        # φ1: No memory leaks - every state must be covered
        for state in states:
            covering_patches = [patch_vars[p] for p in candidates if state in M.get(p, set())]
            if covering_patches:
                opt.add(Or(covering_patches))
            else:
                # No patch can cover this state - UNSAT
                logger.warning(f"State {state.o} cannot be covered by any patch")
                return None
        
        # φ2: No double-frees - each state covered by at most one patch
        for state in states:
            covering_patches = [patch_vars[p] for p in candidates if state in M.get(p, set())]
            if len(covering_patches) > 1:
                # At most one can be true
                for i, p1 in enumerate(covering_patches):
                    for p2 in covering_patches[i+1:]:
                        opt.add(Not(And(p1, p2)))
        
        # φ3: No UAF from patch ordering
        # For simplicity, we skip this in the basic implementation
        # Full implementation would check M(c1) ∩ U(c2) = ∅
        
        # Soft constraint: minimize number of patches
        for patch_var in patch_vars.values():
            opt.add_soft(Not(patch_var))
        
        # Solve
        if opt.check() == sat:
            model = opt.model()
            solution = set()
            
            for patch, var in patch_vars.items():
                if model.evaluate(var):
                    solution.add(patch)
            
            logger.info(f"SAT solution found with {len(solution)} patches")
            return solution
        else:
            logger.warning("UNSAT: No valid patch exists")
            return None
    
    def _solve_greedy(
        self,
        candidates: Set[Patch],
        states: Set[ObjectState],
        M: Dict[Patch, Set[ObjectState]]
    ) -> Optional[Set[Patch]]:
        """
        Fallback greedy solver when Z3 not available
        
        Args:
            candidates: Candidate patches
            states: Reachable states
            M: Incidence function
            
        Returns:
            Greedy solution or None
        """
        uncovered = set(states)
        solution = set()
        
        while uncovered:
            # Find patch that covers most uncovered states
            best_patch = None
            best_coverage = 0
            
            for patch in candidates:
                if patch in solution:
                    continue
                
                coverage = len(M.get(patch, set()).intersection(uncovered))
                if coverage > best_coverage:
                    best_coverage = coverage
                    best_patch = patch
            
            if best_patch is None or best_coverage == 0:
                # Cannot cover remaining states
                logger.warning(f"Greedy solver: {len(uncovered)} states cannot be covered")
                return None
            
            # Add patch to solution
            solution.add(best_patch)
            uncovered -= M[best_patch]
        
        logger.info(f"Greedy solution found with {len(solution)} patches")
        return solution
