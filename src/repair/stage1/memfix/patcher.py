"""
Source Code Patcher for MemFix
Applies patches by removing old free() and inserting new ones
"""
import logging
import re
from typing import Set, List, Tuple
from .object_state import Patch
from .cfg_builder import CFG

logger = logging.getLogger(__name__)


class SourcePatcher:
    """
    Applies MemFix patches to source code
    
    Steps:
    1. Remove all existing free() statements
    2. Insert new free() statements per solution
    3. Preserve formatting and comments
    """
    
    def __init__(self, cfg: CFG):
        self.cfg = cfg
        self.alloc_type_map = {}  # Maps allocation site to alloc_type
    
    def apply_patches(
        self,
        source_code: str,
        patches: Set[Patch],
        object_states: Set = None
    ) -> Tuple[str, List[str]]:
        """
        Apply patches to source code
        
        Args:
            source_code: Original source code
            patches: Set of patches to apply
            object_states: Set of ObjectStates (to determine alloc_type)
            
        Returns:
            Tuple of (patched_code, list of changes)
        """
        lines = source_code.split('\n')
        changes = []
        
        # Build map of allocation site to alloc_type
        self.alloc_type_map = {}
        if object_states:
            for state in object_states:
                self.alloc_type_map[state.o] = state.alloc_type
        
        # Step 1: Remove all existing free() statements
        lines, removed = self._remove_existing_frees(lines)
        changes.extend(removed)
        
        # Step 2: Insert new free() statements
        lines, inserted = self._insert_new_frees(lines, patches)
        changes.extend(inserted)
        
        patched_code = '\n'.join(lines)
        
        logger.info(f"Applied {len(patches)} patches: {len(removed)} removed, {len(inserted)} inserted")
        
        return patched_code, changes
    
    def _remove_existing_frees(
        self,
        lines: List[str]
    ) -> Tuple[List[str], List[str]]:
        """
        Remove all existing free(), delete, and fclose statements
        
        Args:
            lines: Source lines
            
        Returns:
            Tuple of (modified lines, list of changes)
        """
        new_lines = []
        changes = []
        
        for line_num, line in enumerate(lines, 1):
            # Check if line contains free(), delete, or fclose
            if (re.search(r'\bfree\s*\(', line) or 
                re.search(r'\bdelete\s+', line) or 
                re.search(r'\bfclose\s*\(', line)):
                # Remove this line
                changes.append(f"Removed line {line_num}: {line.strip()}")
                # Keep empty line to preserve line numbers
                new_lines.append('')
            else:
                new_lines.append(line)
        
        return new_lines, changes
    
    def _insert_new_frees(
        self,
        lines: List[str],
        patches: Set[Patch]
    ) -> Tuple[List[str], List[str]]:
        """
        Insert new free()/delete statements
        
        Args:
            lines: Source lines
            patches: Patches to insert
            
        Returns:
            Tuple of (modified lines, list of changes)
        """
        # Group patches by line number
        patches_by_line = {}
        for patch in patches:
            node = self.cfg.get_node(patch.cfg_node)
            if node:
                line_num = node.line_num
                if line_num not in patches_by_line:
                    patches_by_line[line_num] = []
                patches_by_line[line_num].append(patch)
        
        # Insert patches (process in reverse to maintain line numbers)
        new_lines = lines.copy()
        changes = []
        
        for line_num in sorted(patches_by_line.keys(), reverse=True):
            if line_num < 1 or line_num > len(new_lines):
                continue
            
            # Get indentation from the line
            original_line = new_lines[line_num - 1]
            indent = self._get_indentation(original_line)
            
            # Insert free()/delete/fclose statements after this line
            for patch in patches_by_line[line_num]:
                # Get allocation type from map using the alloc_site from patch
                alloc_site = patch.alloc_site
                alloc_type = self.alloc_type_map.get(alloc_site, 'malloc')
                
                # Use appropriate deallocation
                if alloc_type == 'new[]':
                    free_stmt = f"{indent}delete[] {patch.expr};"
                elif alloc_type == 'new':
                    free_stmt = f"{indent}delete {patch.expr};"
                elif alloc_type == 'fopen':
                    free_stmt = f"{indent}fclose({patch.expr});"
                else:
                    free_stmt = f"{indent}free({patch.expr});"
                
                new_lines.insert(line_num, free_stmt)
                changes.append(f"Inserted after line {line_num}: {free_stmt.strip()}")
        
        return new_lines, changes
    
    def _get_indentation(self, line: str) -> str:
        """
        Extract indentation from a line
        
        Args:
            line: Source line
            
        Returns:
            Indentation string (spaces/tabs)
        """
        match = re.match(r'^(\s*)', line)
        return match.group(1) if match else ''
    
    def generate_diff(
        self,
        original: str,
        patched: str,
        filename: str
    ) -> str:
        """
        Generate unified diff
        
        Args:
            original: Original source code
            patched: Patched source code
            filename: Source filename
            
        Returns:
            Unified diff string
        """
        import difflib
        
        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"{filename} (original)",
            tofile=f"{filename} (patched)",
            lineterm=''
        )
        
        return ''.join(diff)
