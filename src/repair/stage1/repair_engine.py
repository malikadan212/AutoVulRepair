"""
Stage 1 Repair Engine
Coordinates rule-based repairs for auto-repairable vulnerabilities
"""
import logging
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from .classifier import classify_vulnerability, is_stage1_repairable
from .null_pointer import NullPointerRepair
from .uninitialized_var import UninitializedVarRepair
from .dead_code import DeadCodeRepair
from .integer_overflow import IntegerOverflowFixer
from .memfix.memfix_repair import MemFixRepair
from .buffer_overflow import BufferOverflowFixer
from .format_string import FormatStringRepair
from .use_after_free_cets import UseAfterFreeRepair
from .dangerous_api import DangerousAPIRepair

logger = logging.getLogger(__name__)


class Stage1RepairEngine:
    """
    Stage 1 rule-based repair engine
    Generates deterministic patches for well-known vulnerability classes
    """
    
    def __init__(self, enable_dead_code: bool = False):
        """
        Initialize Stage 1 repair engine
        
        Args:
            enable_dead_code: Enable MSC12-C dead code repairs (disabled by default)
        """
        self.enable_dead_code = enable_dead_code
        
        # Initialize repair modules
        self.null_pointer_repair = NullPointerRepair()
        self.uninitialized_var_repair = UninitializedVarRepair()
        self.dead_code_repair = DeadCodeRepair()
        self.integer_overflow_repair = IntegerOverflowFixer()
        self.memfix_repair = MemFixRepair()
        self.buffer_overflow_repair = BufferOverflowFixer(mode="API-REP")  # Use API replacement mode
        self.format_string_repair = FormatStringRepair()
        self.use_after_free_repair = UseAfterFreeRepair()
        self.dangerous_api_repair = DangerousAPIRepair()
        
        logger.info(f"Stage1RepairEngine initialized (dead_code={enable_dead_code})")
    
    def can_repair(self, vuln: Dict[str, Any]) -> bool:
        """
        Check if vulnerability can be repaired by Stage 1
        
        Args:
            vuln: Vulnerability dict
            
        Returns:
            True if Stage 1 can repair, False otherwise
        """
        return is_stage1_repairable(vuln, enable_dead_code=self.enable_dead_code)
    
    def generate_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a patch for a Stage 1 repairable vulnerability
        
        Args:
            vuln: Vulnerability dict with keys: id, cwe, file, line, column, etc.
            source_code: Full source code of the file
            source_file: Path to source file
            
        Returns:
            Patch dict with:
            - patch_id: str
            - vulnerability_id: str
            - category: str
            - diff: str (unified diff format)
            - description: str
            - confidence: float (0.0-1.0)
            - stage: int (1)
            Or None if repair failed
        """
        # Classify vulnerability
        classification = classify_vulnerability(vuln)
        
        if classification['stage'] != 1:
            logger.warning(f"Vulnerability {vuln.get('id')} is not Stage 1 repairable")
            return None
        
        if not classification['enabled']:
            if classification['category'] == 'dead_code' and not self.enable_dead_code:
                logger.info(f"Dead code repair disabled for {vuln.get('id')}")
                return None
            logger.warning(f"Repair category {classification['category']} is disabled")
            return None
        
        # Route to appropriate repair module
        category = classification['category']
        
        try:
            if category == 'null_pointer':
                patch = self.null_pointer_repair.generate_patch(vuln, source_code, source_file)
            elif category == 'uninitialized_var':
                patch = self.uninitialized_var_repair.generate_patch(vuln, source_code, source_file)
            elif category == 'dead_code':
                patch = self.dead_code_repair.generate_patch(vuln, source_code, source_file)
            elif category == 'integer_overflow':
                patch = self.integer_overflow_repair.generate_patch(vuln, source_code, source_file)
            elif category == 'memory_dealloc':
                patch = self.memfix_repair.generate_patch(vuln, source_code, source_file)
            elif category == 'buffer_overflow':
                patch = self._generate_buffer_overflow_patch(vuln, source_code, source_file)
            elif category == 'format_string':
                patch = self.format_string_repair.generate_patch(vuln, source_code, source_file)
            elif category == 'use_after_free':
                patch = self.use_after_free_repair.generate_patch(vuln, source_code, source_file)
            elif category == 'dangerous_api':
                patch = self.dangerous_api_repair.generate_patch(vuln, source_code, source_file)
            else:
                logger.error(f"Unknown Stage 1 category: {category}")
                return None
            
            if patch:
                # Add metadata
                patch['stage'] = 1
                patch['category'] = category
                patch['priority'] = classification['priority']
                patch['expected_success_rate'] = classification['success_rate']
                
                logger.info(f"Generated Stage 1 patch for {vuln.get('id')} ({category})")
                return patch
            else:
                logger.warning(f"Failed to generate patch for {vuln.get('id')}")
                return None
                
        except Exception as e:
            logger.error(f"Error generating patch for {vuln.get('id')}: {e}", exc_info=True)
            return None
    
    def _generate_buffer_overflow_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Adapter for buffer overflow repair module.
        Cppcheck sometimes reports the function signature or a comment line rather
        than the actual unsafe API call.  We scan forward from the reported line
        (up to 20 lines, staying within the function) to find the real call.
        """
        import uuid
        from .buffer_overflow import BufferOverflowScanner

        line_num = vuln.get('line', 0)
        lines = source_code.split('\n')

        if line_num < 1 or line_num > len(lines):
            logger.error(f"Invalid line number {line_num} for buffer overflow")
            return None

        scanner = BufferOverflowScanner()

        # Try the reported line first, then scan forward if it's a comment/signature
        target_line_num = None
        scanned_vuln = None

        for offset in range(0, 21):
            candidate_num = line_num + offset
            if candidate_num > len(lines):
                break
            candidate = lines[candidate_num - 1]

            # Stop at closing brace (end of function)
            if offset > 0 and re.match(r'^\s*\}\s*$', candidate):
                break

            result = scanner.scan_line(candidate, candidate_num)
            if result and result.get('status') != 'false_positive':
                target_line_num = candidate_num
                scanned_vuln = result
                if offset > 0:
                    logger.info(
                        f"Buffer overflow: Cppcheck reported line {line_num} "
                        f"(comment/signature); actual call found at line {candidate_num}"
                    )
                break

        if not scanned_vuln:
            logger.warning(f"Buffer overflow scanner did not detect vulnerability at line {line_num} or nearby")
            return None

        # Generate patch using the fixer
        patch_data = self.buffer_overflow_repair.generate_patch(scanned_vuln)
        if not patch_data:
            return None

        import difflib
        original = patch_data.get('original', lines[target_line_num - 1])
        repaired = patch_data.get('repaired', lines[target_line_num - 1])

        original_lines = original.split('\n')
        repaired_lines = repaired.split('\n')

        diff = '\n'.join(difflib.unified_diff(
            original_lines,
            repaired_lines,
            fromfile=source_file,
            tofile=source_file,
            lineterm=''
        ))

        return {
            'patch_id': str(uuid.uuid4()),
            'vulnerability_id': vuln.get('finding_id') or vuln.get('id', ''),
            'file': source_file,
            'line': target_line_num,
            'original': original,
            'repaired': repaired,
            'diff': diff,
            'description': f"Buffer overflow fix at line {target_line_num} using {self.buffer_overflow_repair.mode} mode",
            'confidence': 0.80,
            'api': scanned_vuln.get('api', 'unknown'),
            'needs_my_vsnprintf': patch_data.get('needs_my_vsnprintf', False)
        }
    
    def batch_repair(
        self,
        vulnerabilities: List[Dict[str, Any]],
        source_files: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Generate patches for multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dicts
            source_files: Dict mapping file paths to source code
            
        Returns:
            Results dict with:
            - patches: List of generated patches
            - stats: Statistics about repairs
        """
        patches = []
        stats = {
            'total': len(vulnerabilities),
            'stage1_repairable': 0,
            'stage2_only': 0,
            'patches_generated': 0,
            'patches_failed': 0,
            'by_category': {}
        }
        
        for vuln in vulnerabilities:
            classification = classify_vulnerability(vuln)
            
            # Update stats
            if classification['stage'] == 1:
                stats['stage1_repairable'] += 1
                category = classification['category']
                stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            else:
                stats['stage2_only'] += 1
                continue
            
            # Skip if not enabled
            if not self.can_repair(vuln):
                continue
            
            # Get source code
            file_path = vuln.get('file', '')
            logger.info(f"Looking for source code: '{file_path}' (available keys: {list(source_files.keys())[:3]}...)")
            source_code = source_files.get(file_path)
            
            if not source_code:
                logger.warning(f"Source code not found for {file_path}")
                stats['patches_failed'] += 1
                continue
            
            # Generate patch
            patch = self.generate_patch(vuln, source_code, file_path)
            
            if patch:
                patches.append(patch)
                stats['patches_generated'] += 1
            else:
                stats['patches_failed'] += 1
        
        logger.info(f"Batch repair complete: {stats['patches_generated']}/{stats['stage1_repairable']} patches generated")
        
        return {
            'patches': patches,
            'stats': stats
        }
