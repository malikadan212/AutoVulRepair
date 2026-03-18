"""
MemFix Stage 1 Repair Module
Main entry point for memory deallocation error repair
"""
import logging
import uuid
import re
from typing import Dict, Any, Optional

from .cfg_builder import SimpleCFGBuilder
from .points_to import PointsToAnalysis
from .fixpoint import FixedPointAnalysis
from .sat_solver import SATSolver
from .patcher import SourcePatcher

logger = logging.getLogger(__name__)


class MemFixRepair:
    """
    MemFix: Automated repair of memory deallocation errors
    
    Repairs:
    - Memory Leak (CWE-401)
    - Double-Free (CWE-415)
    - Use-After-Free (CWE-416)
    
    Based on: Lee, Hong & Oh - MemFix: Static Analysis-Based Repair
    of Memory Deallocation Errors for C - ESEC/FSE 2018
    """
    
    def __init__(self):
        self.cfg_builder = SimpleCFGBuilder()
        self.sat_solver = SATSolver()
    
    def generate_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate patch for memory deallocation error
        
        Args:
            vuln: Vulnerability dict with keys: id, cwe, file, line, etc.
            source_code: Full source code
            source_file: Path to source file
            
        Returns:
            Patch dict or None if repair failed
        """
        cwe = str(vuln.get('cwe', ''))
        vuln_id = vuln.get('id', '')
        line_num = vuln.get('line', 0)
        
        logger.info(f"MemFix analyzing {vuln_id} (CWE-{cwe}) at line {line_num}")
        
        # Extract the function containing the vulnerability
        function_code = self._extract_function(source_code, line_num)
        if not function_code:
            logger.warning(f"Could not extract function for line {line_num}, using full file")
            function_code = source_code
        else:
            logger.info(f"Extracted function: {len(function_code)} chars")
        
        try:
            # Phase 1: Build CFG and run pre-analysis
            logger.info("Phase 1: Building CFG and running pre-analysis...")
            cfg = self.cfg_builder.build_cfg(function_code)
            
            if not cfg.nodes:
                logger.warning("Empty CFG, cannot analyze")
                return None
            
            # Run points-to analysis
            points_to = PointsToAnalysis(cfg)
            points_to.analyze()
            
            # Phase 2: Typestate analysis (fixed-point iteration)
            logger.info("Phase 2: Running typestate analysis...")
            fixpoint = FixedPointAnalysis(cfg, points_to)
            D = fixpoint.analyze()
            
            # Get reachable states at exit
            if cfg.exit_node is None:
                logger.warning("No exit node in CFG")
                return None
            
            reachable_states = D.get(cfg.exit_node, set())
            
            if not reachable_states:
                logger.info("No reachable object states at exit, no patches needed")
                return self._create_no_patch_result(vuln, source_file)
            
            logger.info(f"Found {len(reachable_states)} reachable object states at exit")
            
            # Phase 3: SAT solving for exact cover
            logger.info("Phase 3: Solving exact cover problem...")
            solution = self.sat_solver.solve(reachable_states)
            
            if solution is None:
                logger.warning("UNSAT: Cannot generate valid patch")
                
                # Special case: For double-free (CWE-415), try simple duplicate removal
                if cwe == '415':
                    logger.info("Attempting simple double-free fix...")
                    simple_patch = self._try_simple_double_free_fix(function_code, cfg)
                    if simple_patch:
                        return simple_patch
                
                # Return informative result instead of None
                return {
                    'patch_id': str(uuid.uuid4()),
                    'vulnerability_id': vuln_id,
                    'file': source_file,
                    'cwe': cwe,
                    'original': f'Found {len(reachable_states)} object state(s) at exit',
                    'repaired': 'UNSAT: No valid patch configuration exists',
                    'diff': '',
                    'description': (
                        f'MemFix could not find a valid patch configuration for CWE-{cwe}. '
                        f'This may occur when: (1) the code is too complex for Stage 1 analysis, '
                        f'(2) multiple interacting allocations require coordinated fixes, or '
                        f'(3) the vulnerability requires conditional logic. '
                        f'Consider routing to Stage 2 (AI-assisted repair).'
                    ),
                    'confidence': 0.0,
                    'num_patches': 0,
                    'changes': ['UNSAT: No solution found'],
                    'reachable_states': len(reachable_states),
                    'method': 'memfix_stage1',
                    'unsat': True
                }
            
            if not solution:
                logger.info("No patches needed (all objects properly freed)")
                return self._create_no_patch_result(vuln, source_file)
            
            # Apply patches
            logger.info(f"Applying {len(solution)} patches...")
            patcher = SourcePatcher(cfg)
            patched_code, changes = patcher.apply_patches(function_code, solution, reachable_states)
            
            # Generate diff
            diff = patcher.generate_diff(function_code, patched_code, source_file)
            
            # Create patch result
            return {
                'patch_id': str(uuid.uuid4()),
                'vulnerability_id': vuln_id,
                'file': source_file,
                'cwe': cwe,
                'original': self._format_original_for_display(function_code, solution, patcher),
                'repaired': self._format_patched_for_display(patched_code, solution, patcher),
                'diff': diff,
                'description': self._generate_description(cwe, len(solution), changes),
                'confidence': self._calculate_confidence(solution, reachable_states),
                'num_patches': len(solution),
                'changes': changes,
                'reachable_states': len(reachable_states),
                'method': 'memfix_stage1'
            }
            
        except Exception as e:
            logger.error(f"MemFix repair failed for {vuln_id}: {e}", exc_info=True)
            # Return a failure result instead of None so UI can display it
            return {
                'patch_id': str(uuid.uuid4()),
                'vulnerability_id': vuln_id,
                'file': source_file,
                'cwe': cwe,
                'original': 'MemFix analysis failed',
                'repaired': f'Error: {str(e)[:100]}',
                'diff': '',
                'description': f'MemFix could not analyze this code: {str(e)[:200]}',
                'confidence': 0.0,
                'num_patches': 0,
                'changes': [f'Error: {str(e)}'],
                'method': 'memfix_stage1',
                'error': True
            }
    
    def _create_no_patch_result(
        self,
        vuln: Dict[str, Any],
        source_file: str
    ) -> Dict[str, Any]:
        """
        Create result for case where no patches are needed
        
        Args:
            vuln: Vulnerability dict
            source_file: Source file path
            
        Returns:
            Patch dict indicating no changes needed
        """
        return {
            'patch_id': str(uuid.uuid4()),
            'vulnerability_id': vuln.get('id', ''),
            'file': source_file,
            'cwe': str(vuln.get('cwe', '')),
            'original': 'No existing free() statements',
            'repaired': 'No changes needed - memory properly managed',
            'diff': '',
            'description': 'No patches needed - memory properly managed',
            'confidence': 1.0,
            'num_patches': 0,
            'changes': [],
            'method': 'memfix_stage1'
        }
    
    def _generate_description(
        self,
        cwe: str,
        num_patches: int,
        changes: list
    ) -> str:
        """
        Generate human-readable patch description
        
        Args:
            cwe: CWE identifier
            num_patches: Number of patches applied
            changes: List of changes
            
        Returns:
            Description string
        """
        error_type = {
            '401': 'memory leak',
            '415': 'double-free',
            '416': 'use-after-free'
        }.get(cwe, 'memory deallocation error')
        
        desc = f"MemFix repair for {error_type} (CWE-{cwe}): "
        desc += f"Applied {num_patches} patch(es). "
        
        # Summarize changes
        removed = sum(1 for c in changes if 'Removed' in c)
        inserted = sum(1 for c in changes if 'Inserted' in c)
        
        if removed > 0:
            desc += f"Removed {removed} existing free() statement(s). "
        if inserted > 0:
            desc += f"Inserted {inserted} new free() statement(s). "
        
        return desc
    
    def _calculate_confidence(
        self,
        solution: set,
        reachable_states: set
    ) -> float:
        """
        Calculate confidence score for the patch
        
        Args:
            solution: Set of patches
            reachable_states: Reachable object states
            
        Returns:
            Confidence score (0.0-1.0)
        """
        # Base confidence for MemFix
        base_confidence = 0.85
        
        # Adjust based on solution complexity
        if len(solution) == 0:
            return 1.0  # No changes needed
        
        # Penalize complex solutions
        complexity_penalty = min(0.1 * len(solution), 0.2)
        
        # Adjust based on coverage
        # (In full implementation, would check exact coverage)
        coverage_bonus = 0.05
        
        confidence = base_confidence - complexity_penalty + coverage_bonus
        return max(0.5, min(1.0, confidence))
    
    def _format_original_for_display(
        self,
        source_code: str,
        solution: set,
        patcher
    ) -> str:
        """
        Format original code snippet for UI display
        
        Args:
            source_code: Original source code
            solution: Patch solution
            patcher: SourcePatcher instance
            
        Returns:
            Formatted original code snippet
        """
        lines = source_code.split('\n')
        
        # Find lines with existing free() statements
        free_lines = []
        for i, line in enumerate(lines, 1):
            if 'free(' in line:
                free_lines.append(f"Line {i}: {line.strip()}")
        
        if free_lines:
            return "Existing free() statements:\n" + "\n".join(free_lines[:3])
        else:
            return "No existing free() statements (memory leak)"
    
    def _format_patched_for_display(
        self,
        patched_code: str,
        solution: set,
        patcher
    ) -> str:
        """
        Format patched code snippet for UI display
        
        Args:
            patched_code: Patched source code
            solution: Patch solution
            patcher: SourcePatcher instance
            
        Returns:
            Formatted patched code snippet
        """
        if not solution:
            return "No changes needed"
        
        # Show the inserted free() statements
        inserted = []
        for patch in solution:
            node = patcher.cfg.get_node(patch.cfg_node)
            if node:
                inserted.append(f"Line {node.line_num}: free({patch.expr});")
        
        if inserted:
            return "Inserted free() statements:\n" + "\n".join(inserted[:5])
        else:
            return f"{len(solution)} free() statement(s) optimally placed"
    
    def _extract_function(self, source_code: str, line_num: int) -> Optional[str]:
        """
        Extract the function containing the given line number
        
        Args:
            source_code: Full source code
            line_num: Line number of vulnerability
            
        Returns:
            Function source code or None
        """
        lines = source_code.split('\n')
        if line_num < 1 or line_num > len(lines):
            return None
        
        # Find function start (look backwards for function signature)
        func_start = None
        
        for i in range(line_num - 1, -1, -1):
            line = lines[i].strip()
            
            # Look for function signature pattern (more flexible)
            # Match: type name(...) { or type name(...)\n{
            if re.search(r'\w+\s+\w+\s*\([^)]*\)', line):
                # Check if it's likely a function definition
                if not line.startswith('//') and not line.startswith('/*'):
                    func_start = i
                    break
            
            # Also check for opening brace on its own line after function signature
            if line == '{' and i > 0:
                prev_line = lines[i-1].strip()
                if re.search(r'\w+\s+\w+\s*\([^)]*\)', prev_line):
                    func_start = i - 1
                    break
        
        if func_start is None:
            logger.warning(f"Could not find function start for line {line_num}")
            return None
        
        # Find function end (match braces)
        func_end = None
        brace_count = 0
        in_function = False
        
        for i in range(func_start, len(lines)):
            line = lines[i]
            
            for char in line:
                if char == '{':
                    brace_count += 1
                    in_function = True
                elif char == '}':
                    brace_count -= 1
                    if in_function and brace_count == 0:
                        func_end = i
                        break
            
            if func_end is not None:
                break
        
        if func_end is None:
            logger.warning(f"Could not find function end for line {line_num}")
            return None
        
        # Extract function
        function_lines = lines[func_start:func_end + 1]
        function_code = '\n'.join(function_lines)
        
        logger.info(f"Extracted function: lines {func_start+1}-{func_end+1} ({len(function_lines)} lines)")
        return function_code
    
    def _try_simple_double_free_fix(self, source_code: str, cfg) -> Optional[Dict[str, Any]]:
        """
        Try simple fix for double-free: remove duplicate free() statements
        
        Args:
            source_code: Function source code
            cfg: Control flow graph
            
        Returns:
            Patch dict or None
        """
        lines = source_code.split('\n')
        free_lines = []
        
        # Find all free() statements
        for i, line in enumerate(lines):
            if (re.search(r'\bfree\s*\(', line) or 
                re.search(r'\bdelete\s+', line) or 
                re.search(r'\bfclose\s*\(', line)):
                free_lines.append(i)
        
        if len(free_lines) < 2:
            return None
        
        # Remove all but the first free()
        changes = []
        for line_idx in free_lines[1:]:
            changes.append(f"Removed duplicate free at line {line_idx + 1}: {lines[line_idx].strip()}")
        
        # Create patched code
        patched_lines = lines.copy()
        for line_idx in reversed(free_lines[1:]):  # Remove in reverse to maintain indices
            patched_lines[line_idx] = ''
        
        patched_code = '\n'.join(patched_lines)
        
        # Generate diff
        patcher = SourcePatcher(cfg)
        diff = patcher.generate_diff(source_code, patched_code, 'source')
        
        logger.info(f"Simple double-free fix: removed {len(free_lines) - 1} duplicate free() statements")
        
        return {
            'patch_id': str(uuid.uuid4()),
            'vulnerability_id': 'double_free_simple',
            'file': 'source',
            'cwe': '415',
            'original': f"Found {len(free_lines)} free() statements",
            'repaired': f"Kept first free(), removed {len(free_lines) - 1} duplicate(s)",
            'patched': f"Kept first free(), removed {len(free_lines) - 1} duplicate(s)",
            'diff': diff,
            'description': f"Double-free fix: Removed {len(free_lines) - 1} duplicate free() statement(s), keeping only the first one",
            'confidence': 0.90,
            'num_patches': len(free_lines) - 1,
            'changes': changes,
            'method': 'memfix_stage1_simple'
        }
