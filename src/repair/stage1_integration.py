"""
Stage 1 Integration with Main Orchestrator
Routes vulnerabilities between Stage 1 (rule-based) and Stage 2 (AI-assisted)
Based on CMU/SEI-2025-TR-007
"""
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

from .stage1.classifier import classify_vulnerability, is_stage1_repairable
from .stage1.repair_engine import Stage1RepairEngine
from .tools.code_reader import read_source_code

logger = logging.getLogger(__name__)


class Stage1Integration:
    """
    Integrates Stage 1 rule-based repairs with the main repair orchestrator
    """
    
    def __init__(self, enable_dead_code: bool = False):
        """
        Initialize Stage 1 integration
        
        Args:
            enable_dead_code: Enable MSC12-C dead code repairs (disabled by default)
        """
        self.stage1_engine = Stage1RepairEngine(enable_dead_code=enable_dead_code)
        self.enable_dead_code = enable_dead_code
        
        logger.info(f"Stage1Integration initialized (dead_code={enable_dead_code})")
    
    def should_use_stage1(self, vulnerability: Dict[str, Any]) -> bool:
        """
        Determine if vulnerability should be handled by Stage 1
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            True if Stage 1 should handle, False if route to Stage 2
        """
        return self.stage1_engine.can_repair(vulnerability)
    
    def attempt_stage1_repair(
        self,
        vulnerability: Dict[str, Any],
        scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt Stage 1 repair for a vulnerability
        
        Args:
            vulnerability: Vulnerability dict
            scan_id: Scan ID
            
        Returns:
            Patch dict if successful, None if failed (route to Stage 2)
        """
        # Classify vulnerability
        classification = classify_vulnerability(vulnerability)
        
        logger.info(
            f"Vulnerability {vulnerability.get('finding_id')}: "
            f"category={classification['category']}, "
            f"stage={classification['stage']}, "
            f"enabled={classification['enabled']}"
        )
        
        # Check if Stage 1 can handle
        if classification['stage'] != 1:
            logger.info(f"Routing to Stage 2: {classification['reason']}")
            return None
        
        if not classification['enabled']:
            if classification['category'] == 'dead_code' and not self.enable_dead_code:
                logger.info("Dead code repair disabled, routing to Stage 2")
            else:
                logger.info(f"Category {classification['category']} disabled, routing to Stage 2")
            return None
        
        # Get source code
        source_file = vulnerability.get('file', '')
        if not source_file:
            logger.error("No source file in vulnerability data")
            return None
        
        try:
            source_code = read_source_code(scan_id, source_file)
            if not source_code:
                logger.error(f"Could not read source file: {source_file}")
                return None
        except Exception as e:
            logger.error(f"Failed to read source file {source_file}: {e}")
            return None
        
        # Generate patch
        try:
            patch = self.stage1_engine.generate_patch(
                vulnerability,
                source_code,
                source_file
            )
            
            if patch:
                logger.info(
                    f"Stage 1 patch generated: {patch['patch_id']} "
                    f"(confidence={patch['confidence']:.2f})"
                )
                return patch
            else:
                logger.warning("Stage 1 patch generation failed, routing to Stage 2")
                return None
                
        except Exception as e:
            logger.error(f"Stage 1 repair error: {e}", exc_info=True)
            return None
    
    def batch_attempt_stage1(
        self,
        vulnerabilities: List[Dict[str, Any]],
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Attempt Stage 1 repairs for multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dicts
            scan_id: Scan ID
            
        Returns:
            Results dict with:
            - stage1_patches: List of successful Stage 1 patches
            - stage2_vulns: List of vulnerabilities to route to Stage 2
            - stats: Statistics
        """
        stage1_patches = []
        stage2_vulns = []
        
        stats = {
            'total': len(vulnerabilities),
            'stage1_attempted': 0,
            'stage1_success': 0,
            'stage1_failed': 0,
            'stage2_routed': 0,
            'by_category': {}
        }
        
        for vuln in vulnerabilities:
            classification = classify_vulnerability(vuln)
            category = classification['category']
            
            # Track by category
            if category not in stats['by_category']:
                stats['by_category'][category] = {
                    'total': 0,
                    'stage1_success': 0,
                    'stage2_routed': 0
                }
            stats['by_category'][category]['total'] += 1
            
            # Check if Stage 1 can handle
            if not self.should_use_stage1(vuln):
                stage2_vulns.append(vuln)
                stats['stage2_routed'] += 1
                stats['by_category'][category]['stage2_routed'] += 1
                continue
            
            # Attempt Stage 1 repair
            stats['stage1_attempted'] += 1
            patch = self.attempt_stage1_repair(vuln, scan_id)
            
            if patch:
                stage1_patches.append(patch)
                stats['stage1_success'] += 1
                stats['by_category'][category]['stage1_success'] += 1
            else:
                # Failed Stage 1, route to Stage 2
                stage2_vulns.append(vuln)
                stats['stage1_failed'] += 1
                stats['stage2_routed'] += 1
                stats['by_category'][category]['stage2_routed'] += 1
        
        logger.info(
            f"Stage 1 batch complete: "
            f"{stats['stage1_success']}/{stats['stage1_attempted']} successful, "
            f"{stats['stage2_routed']} routed to Stage 2"
        )
        
        return {
            'stage1_patches': stage1_patches,
            'stage2_vulns': stage2_vulns,
            'stats': stats
        }
    
    def get_classification_stats(self) -> Dict[str, Any]:
        """
        Get statistics about vulnerability classification
        
        Returns:
            Classification statistics
        """
        from .stage1.classifier import get_repair_statistics
        return get_repair_statistics()


def create_stage1_integration(enable_dead_code: bool = False) -> Stage1Integration:
    """
    Create Stage 1 integration instance
    
    Args:
        enable_dead_code: Enable MSC12-C dead code repairs
        
    Returns:
        Stage1Integration instance
    """
    return Stage1Integration(enable_dead_code=enable_dead_code)
