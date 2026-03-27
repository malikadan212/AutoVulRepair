"""
Stage 1 Repair Engine
Coordinates rule-based repairs for auto-repairable vulnerabilities
"""
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from .classifier import classify_vulnerability, is_stage1_repairable
from .null_pointer import NullPointerRepair
from .uninitialized_var import UninitializedVarRepair
from .dead_code import DeadCodeRepair
from .integer_overflow import IntegerOverflowFixer
from .buffer_overflow import BufferOverflowFixer
from .temporal_safety_cets import CETSFixer
from .memory_leak import MemoryLeakFixer
from .format_string_vulnerability import PHPTaintFixer
from .race_condition import RaceConditionFixer
from .file_handling import FileHandlingFixer
from .memfix import MemFixRepair
import uuid
import difflib

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
        self.buffer_overflow_repair = BufferOverflowFixer()
        self.cets_repair = CETSFixer()
        self.memory_leak_repair = MemoryLeakFixer()
        self.php_taint_repair = PHPTaintFixer()
        self.race_condition_repair = RaceConditionFixer()
        self.file_handling_repair = FileHandlingFixer()
        self.memfix_repair = MemFixRepair()
        
        logger.info(f"Stage1RepairEngine initialized (dead_code={enable_dead_code})")
        
    def _wrap_batch_to_patch(self, vuln: Dict[str, Any], source_code: str, source_file: str, category: str, obj: Any) -> Optional[Dict[str, Any]]:
        try:
            repaired_code, vulns, repaired_lines_map = obj.batch_repair(source_code)
            if not repaired_lines_map:
                return None
            
            diff = ''.join(difflib.unified_diff(
                source_code.splitlines(True),
                repaired_code.splitlines(True),
                fromfile=source_file + "\t(original)",
                tofile=source_file + "\t(repaired)"
            ))
            
            line_num = vuln.get('line', 0)
            target_repaired = repaired_lines_map.get(line_num, "Batch fixed file")
            
            original_lines = source_code.split('\n')
            original_line = original_lines[line_num - 1] if 0 < line_num <= len(original_lines) else ""
            
            return {
                'patch_id': str(uuid.uuid4()),
                'vulnerability_id': vuln.get('id', ''),
                'file': source_file,
                'line': line_num,
                'original': original_line,
                'repaired': target_repaired,
                'diff': diff,
                'description': f"Automated {category} repair applied",
                'confidence': 0.90
            }
        except Exception as e:
            logger.error(f"Wrapper error for {category}: {e}")
            return None
    
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
                patch = self._wrap_batch_to_patch(vuln, source_code, source_file, category, self.integer_overflow_repair)
            elif category == 'buffer_overflow':
                patch = self._wrap_batch_to_patch(vuln, source_code, source_file, category, self.buffer_overflow_repair)
            elif category == 'cets':
                patch = self._wrap_batch_to_patch(vuln, source_code, source_file, category, self.cets_repair)
            elif category == 'memory_leak':
                patch = self._wrap_batch_to_patch(vuln, source_code, source_file, category, self.memory_leak_repair)
            elif category == 'format_string':
                patch = self._wrap_batch_to_patch(vuln, source_code, source_file, category, self.php_taint_repair)
            elif category == 'race_condition':
                patch = self._wrap_batch_to_patch(vuln, source_code, source_file, category, self.race_condition_repair)
            elif category == 'file_handling':
                patch = self._wrap_batch_to_patch(vuln, source_code, source_file, category, self.file_handling_repair)
            elif category == 'memory_dealloc':
                patch = self.memfix_repair.generate_patch(vuln, source_code, source_file)
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
