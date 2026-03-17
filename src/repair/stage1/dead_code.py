"""
Dead/Ineffective Code Repair (MSC12-C / CWE-561, CWE-1164)
Priority: 2 (CERT Recommendation, NOT a Rule)
Success Rate: 20-40% (DISABLED by default)
"""
import logging
import re
import uuid
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class DeadCodeRepair:
    """
    Repairs dead/ineffective code vulnerabilities
    DISABLED by default due to low satisfaction rate (20-40%)
    """
    
    def generate_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate dead code patch
        
        Args:
            vuln: Vulnerability dict
            source_code: Full source code
            source_file: Path to source file
            
        Returns:
            Patch dict or None
        """
        line_num = vuln.get('line', 0)
        symbol = vuln.get('symbol', '')
        vuln_id = vuln.get('id', '')
        
        if not line_num:
            logger.warning(f"Missing line number for dead code vuln")
            return None
        
        # Get the source line
        lines = source_code.split('\n')
        if line_num < 1 or line_num > len(lines):
            logger.error(f"Line number {line_num} out of range")
            return None
        
        original_line = lines[line_num - 1]
        
        # Determine dead code type and repair strategy
        if 'unusedFunction' in vuln_id:
            # Skip unused functions - often intentional (e.g., yacc/bison generated)
            logger.info(f"Skipping unused function repair (often intentional)")
            return None
        
        elif 'unusedVariable' in vuln_id or 'unreadVariable' in vuln_id:
            # Remove dead assignment, preserve side effects
            repaired_line = self._remove_dead_assignment(original_line, symbol)
        
        elif 'variableScope' in vuln_id:
            # Variable scope reduction - skip (requires code restructuring)
            logger.info(f"Skipping variable scope reduction (requires restructuring)")
            return None
        
        else:
            logger.warning(f"Unknown dead code type: {vuln_id}")
            return None
        
        if not repaired_line or repaired_line == original_line:
            logger.warning(f"Could not generate repair for line {line_num}")
            return None
        
        # Generate unified diff
        diff = self._generate_diff(
            source_file,
            line_num,
            original_line,
            repaired_line
        )
        
        return {
            'patch_id': str(uuid.uuid4()),
            'vulnerability_id': vuln.get('id', ''),
            'file': source_file,
            'line': line_num,
            'symbol': symbol,
            'original': original_line.strip(),
            'repaired': repaired_line.strip(),
            'diff': diff,
            'description': f"Remove dead code at line {line_num}",
            'confidence': 0.40,  # Low confidence - only 20-40% satisfaction
            'requires_acr_header': False,
            'warning': 'Dead code repairs have low satisfaction rate. Review carefully.'
        }
    
    def _remove_dead_assignment(self, line: str, symbol: str) -> str:
        """
        Remove dead assignment, preserve side effects
        
        Args:
            line: Original line
            symbol: Variable name
            
        Returns:
            Modified line with assignment removed
        """
        # Pattern: variable = expression;
        # Replace with: (void)expression;
        
        # Find the assignment
        pattern = rf'{re.escape(symbol)}\s*=\s*([^;]+);'
        match = re.search(pattern, line)
        
        if not match:
            return line
        
        expression = match.group(1).strip()
        
        # Check if expression has side effects (function call)
        if '(' in expression and ')' in expression:
            # Preserve side effects by casting to void
            replacement = f'(void){expression};'
        else:
            # No side effects - remove entire statement
            replacement = '// Removed dead assignment'
        
        # Replace the assignment
        repaired = re.sub(pattern, replacement, line)
        
        return repaired
    
    def _generate_diff(
        self,
        filename: str,
        line_num: int,
        original: str,
        repaired: str
    ) -> str:
        """
        Generate unified diff format
        
        Args:
            filename: Source file name
            line_num: Line number
            original: Original line
            repaired: Repaired line
            
        Returns:
            Unified diff string
        """
        diff = f"""--- {filename}	(original)
+++ {filename}	(repaired)
@@ -{line_num},1 +{line_num},1 @@
-{original}
+{repaired}
"""
        return diff
