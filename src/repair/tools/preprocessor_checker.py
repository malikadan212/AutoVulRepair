"""
Preprocessor Safety Checker
Classifies expressions as INDEPENDENT, EMBEDDED, or MIXED
Based on CMU/SEI-2025-TR-007 Section 4
"""
import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class PreprocessorCase(Enum):
    """Preprocessor directive classification"""
    INDEPENDENT = "independent"  # No directives in expression - SAFE
    EMBEDDED = "embedded"        # Self-contained directives - USUALLY SAFE
    MIXED = "mixed"              # Overlapping directives - DO NOT REPAIR


class PreprocessorChecker:
    """
    Checks preprocessor directive safety for repairs
    """
    
    # Preprocessor directive patterns
    DIRECTIVE_PATTERN = re.compile(r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)', re.MULTILINE)
    IF_PATTERN = re.compile(r'^\s*#\s*(if|ifdef|ifndef)', re.MULTILINE)
    ENDIF_PATTERN = re.compile(r'^\s*#\s*endif', re.MULTILINE)
    
    def check_expression_safety(
        self,
        source_code: str,
        start_line: int,
        end_line: int = None
    ) -> Dict[str, Any]:
        """
        Check if expression is safe to repair given preprocessor directives
        
        Args:
            source_code: Full source code
            start_line: Start line of expression (1-indexed)
            end_line: End line of expression (defaults to start_line)
            
        Returns:
            Dict with:
            - case: PreprocessorCase enum
            - safe: bool (True if safe to repair)
            - reason: str (explanation)
            - directives: List of directive info
        """
        if end_line is None:
            end_line = start_line
        
        lines = source_code.split('\n')
        
        # Extract expression byte range
        if start_line < 1 or end_line > len(lines):
            return {
                'case': PreprocessorCase.INDEPENDENT,
                'safe': False,
                'reason': 'Invalid line range',
                'directives': []
            }
        
        # Get expression text (0-indexed)
        expr_lines = lines[start_line - 1:end_line]
        expr_text = '\n'.join(expr_lines)
        
        # Find all directives in expression
        directives = self._find_directives(expr_text, start_line)
        
        if not directives:
            # No directives - INDEPENDENT case
            return {
                'case': PreprocessorCase.INDEPENDENT,
                'safe': True,
                'reason': 'No preprocessor directives in expression',
                'directives': []
            }
        
        # Check if directives are self-contained (EMBEDDED)
        is_embedded, reason = self._check_embedded(directives, expr_text)
        
        if is_embedded:
            # Check for pathological EMBEDDED cases
            is_pathological = self._check_pathological(expr_text, directives)
            
            if is_pathological:
                return {
                    'case': PreprocessorCase.MIXED,
                    'safe': False,
                    'reason': 'Pathological embedded directives detected',
                    'directives': directives
                }
            
            return {
                'case': PreprocessorCase.EMBEDDED,
                'safe': True,  # Usually safe, but verify
                'reason': 'Self-contained preprocessor directives',
                'directives': directives,
                'warning': 'Verify no pathological cases'
            }
        
        # MIXED case - not safe
        return {
            'case': PreprocessorCase.MIXED,
            'safe': False,
            'reason': reason,
            'directives': directives
        }
    
    def _find_directives(self, text: str, base_line: int) -> List[Dict[str, Any]]:
        """
        Find all preprocessor directives in text
        
        Args:
            text: Source text
            base_line: Base line number for offset
            
        Returns:
            List of directive dicts
        """
        directives = []
        
        for match in self.DIRECTIVE_PATTERN.finditer(text):
            line_num = text[:match.start()].count('\n')
            directive_type = match.group(1)
            
            directives.append({
                'type': directive_type,
                'line': base_line + line_num,
                'text': match.group(0).strip()
            })
        
        return directives
    
    def _check_embedded(
        self,
        directives: List[Dict[str, Any]],
        expr_text: str
    ) -> Tuple[bool, str]:
        """
        Check if directives are self-contained (EMBEDDED)
        
        Args:
            directives: List of directive dicts
            expr_text: Expression text
            
        Returns:
            Tuple of (is_embedded, reason)
        """
        # Count opening and closing directives
        opening = sum(1 for d in directives if d['type'] in ['if', 'ifdef', 'ifndef'])
        closing = sum(1 for d in directives if d['type'] == 'endif')
        
        if opening != closing:
            return False, f"Unmatched directives: {opening} opening, {closing} closing"
        
        # Check nesting is valid
        stack = []
        for d in directives:
            if d['type'] in ['if', 'ifdef', 'ifndef']:
                stack.append(d)
            elif d['type'] == 'endif':
                if not stack:
                    return False, "endif without matching if"
                stack.pop()
            elif d['type'] in ['elif', 'else']:
                if not stack:
                    return False, f"{d['type']} without matching if"
        
        if stack:
            return False, "Unclosed if directives"
        
        return True, "Self-contained directives"
    
    def _check_pathological(
        self,
        expr_text: str,
        directives: List[Dict[str, Any]]
    ) -> bool:
        """
        Check for pathological EMBEDDED cases
        
        Example from paper:
        y = (
        #if FOO
        32);
        z = (a
        #else
        * e
        #endif
        ) + c;
        
        Args:
            expr_text: Expression text
            directives: List of directives
            
        Returns:
            True if pathological
        """
        # Check if directives split statements
        # This is a heuristic - look for directives between statement parts
        
        lines = expr_text.split('\n')
        
        for i, d in enumerate(directives):
            if d['type'] in ['if', 'ifdef', 'ifndef', 'else', 'elif']:
                # Check if previous line has unclosed parentheses/brackets
                line_idx = d['line'] - 1
                if line_idx > 0:
                    prev_line = lines[line_idx - 1] if line_idx - 1 < len(lines) else ""
                    
                    # Count unmatched parens/brackets
                    open_parens = prev_line.count('(') - prev_line.count(')')
                    open_brackets = prev_line.count('[') - prev_line.count(']')
                    open_braces = prev_line.count('{') - prev_line.count('}')
                    
                    if open_parens > 0 or open_brackets > 0 or open_braces > 0:
                        logger.warning(f"Pathological case detected: directive splits expression")
                        return True
        
        return False
    
    def should_skip_repair(
        self,
        source_code: str,
        line_num: int,
        context_lines: int = 5
    ) -> Tuple[bool, str]:
        """
        Determine if repair should be skipped due to preprocessor directives
        
        Args:
            source_code: Full source code
            line_num: Line number to repair
            context_lines: Lines of context to check
            
        Returns:
            Tuple of (should_skip, reason)
        """
        # Check expression and surrounding context
        start_line = max(1, line_num - context_lines)
        end_line = line_num + context_lines
        
        result = self.check_expression_safety(source_code, start_line, end_line)
        
        if result['case'] == PreprocessorCase.MIXED:
            return True, result['reason']
        
        if result['case'] == PreprocessorCase.EMBEDDED and result.get('warning'):
            # Be conservative with EMBEDDED cases
            logger.warning(f"EMBEDDED directives at line {line_num}: {result['reason']}")
            # Could make this configurable - for now, allow EMBEDDED
            return False, "EMBEDDED case - proceeding with caution"
        
        return False, "Safe to repair"


def check_preprocessor_safety(
    source_code: str,
    line_num: int,
    context_lines: int = 5
) -> Dict[str, Any]:
    """
    Convenience function to check preprocessor safety
    
    Args:
        source_code: Full source code
        line_num: Line number
        context_lines: Context lines to check
        
    Returns:
        Safety check result dict
    """
    checker = PreprocessorChecker()
    should_skip, reason = checker.should_skip_repair(source_code, line_num, context_lines)
    
    return {
        'should_skip': should_skip,
        'reason': reason,
        'safe': not should_skip
    }
