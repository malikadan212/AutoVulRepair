"""
Vulnerability Classifier for Stage 1 Repairs
Determines if a vulnerability meets the automatic repairability criteria
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Stage 1 repairable vulnerability mappings
STAGE1_CATEGORIES = {
    # Category 1: Null Pointer Dereference (EXP34-C / CWE-476)
    'null_pointer': {
        'cwes': ['476'],
        'cppcheck_ids': ['nullPointer'],
        'priority': 18,
        'enabled': True,
        'success_rate': 0.935
    },
    
    # Category 2: Uninitialized Value Read (EXP33-C / CWE-457, CWE-908)
    'uninitialized_var': {
        'cwes': ['457', '908'],
        'cppcheck_ids': ['uninitvar', 'uninitdata'],
        'priority': 12,
        'enabled': True,
        'success_rate': 0.945
    },
    
    # Category 3: Dead/Ineffective Code (MSC12-C / CWE-561, CWE-1164)
    # DISABLED by default - only 20-40% satisfaction rate
    'dead_code': {
        'cwes': ['561', '1164', '398'],
        'cppcheck_ids': ['unusedFunction', 'unusedVariable', 'unreadVariable', 'variableScope'],
        'priority': 2,
        'enabled': False,  # Disabled by default
        'success_rate': 0.30
    },
    
    # Category 4: Integer Overflow (CWE-190 / CWE-191)
    # Based on IntRepair paper - deterministic pattern-based repairs
    'integer_overflow': {
        'cwes': ['190', '191'],
        'cppcheck_ids': ['integerOverflow'],
        'priority': 15,
        'enabled': True,
        'success_rate': 0.90
    },
    
    # Category 5: Memory Deallocation Errors (MemFix)
    # CWE-401 (Memory Leak), CWE-415 (Double-Free), CWE-416 (Use-After-Free)
    # Based on MemFix paper - static analysis + SAT solving
    'memory_dealloc': {
        'cwes': ['401', '415', '416'],
        'cppcheck_ids': ['memleak', 'resourceLeak', 'doubleFree', 'deallocuse'],
        'priority': 16,
        'enabled': True,
        'success_rate': 0.85
    }
}

# Vulnerabilities that should NOT be auto-repaired (route to Stage 2 AI)
STAGE2_ONLY = {
    'buffer_overflow': {
        'cwes': ['121', '122', '788'],
        'cppcheck_ids': ['bufferAccessOutOfBounds', 'arrayIndexOutOfBounds'],
        'reason': 'Non-local repair required'
    },
    'format_string': {
        'cwes': ['134'],
        'cppcheck_ids': ['invalidPrintfArgType_sint', 'invalidPrintfArgType_uint'],
        'reason': 'Requires understanding calling convention'
    },
    'race_condition': {
        'cwes': ['362'],
        'cppcheck_ids': ['raceAfterInterlockedDecrement'],
        'reason': 'Multi-threading complexity'
    }
}


def classify_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify a vulnerability for repair routing
    
    Args:
        vuln: Vulnerability dict with keys: id, cwe, severity, file, line, etc.
        
    Returns:
        Classification dict with:
        - category: 'null_pointer', 'uninitialized_var', 'dead_code', or 'stage2_only'
        - stage: 1 or 2
        - enabled: bool
        - reason: str (why it's classified this way)
        - priority: int
    """
    # Extract CWE - might be in 'cwe' field or embedded in description
    cwe = str(vuln.get('cwe', ''))
    if not cwe and 'description' in vuln:
        # Try to extract CWE from description like "CWE-476"
        import re
        match = re.search(r'CWE-(\d+)', vuln['description'])
        if match:
            cwe = match.group(1)
    
    cppcheck_id = vuln.get('rule_id', vuln.get('id', ''))
    
    # Check Stage 1 categories
    for category, config in STAGE1_CATEGORIES.items():
        if cwe in config['cwes'] or cppcheck_id in config['cppcheck_ids']:
            return {
                'category': category,
                'stage': 1,
                'enabled': config['enabled'],
                'reason': f"Stage 1 auto-repairable ({config['priority']} priority)",
                'priority': config['priority'],
                'success_rate': config['success_rate']
            }
    
    # Check Stage 2 only categories
    for category, config in STAGE2_ONLY.items():
        if cwe in config['cwes'] or cppcheck_id in config['cppcheck_ids']:
            return {
                'category': category,
                'stage': 2,
                'enabled': True,
                'reason': config['reason'],
                'priority': 0,
                'success_rate': 0.0
            }
    
    # Unknown category - route to Stage 2
    return {
        'category': 'unknown',
        'stage': 2,
        'enabled': True,
        'reason': 'Unknown vulnerability type, requires AI analysis',
        'priority': 0,
        'success_rate': 0.0
    }


def is_stage1_repairable(vuln: Dict[str, Any], enable_dead_code: bool = False) -> bool:
    """
    Check if vulnerability is Stage 1 repairable
    
    Args:
        vuln: Vulnerability dict
        enable_dead_code: Whether to enable MSC12-C dead code repairs
        
    Returns:
        True if Stage 1 repairable, False otherwise
    """
    classification = classify_vulnerability(vuln)
    
    if classification['stage'] != 1:
        return False
    
    # Check if category is enabled
    if not classification['enabled']:
        # Special case: dead_code can be enabled via flag
        if classification['category'] == 'dead_code' and enable_dead_code:
            return True
        return False
    
    return True


def get_repair_statistics() -> Dict[str, Any]:
    """
    Get statistics about Stage 1 repair categories
    
    Returns:
        Statistics dict
    """
    stats = {
        'stage1_categories': {},
        'stage2_categories': {},
        'total_stage1': 0,
        'total_stage2': 0
    }
    
    for category, config in STAGE1_CATEGORIES.items():
        stats['stage1_categories'][category] = {
            'priority': config['priority'],
            'enabled': config['enabled'],
            'success_rate': config['success_rate'],
            'cwes': config['cwes']
        }
        if config['enabled']:
            stats['total_stage1'] += 1
    
    for category, config in STAGE2_ONLY.items():
        stats['stage2_categories'][category] = {
            'reason': config['reason'],
            'cwes': config['cwes']
        }
        stats['total_stage2'] += 1
    
    return stats
