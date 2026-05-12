"""
False Positive Detector for Static Analysis Results
Filters out common false positives from Cppcheck and other tools
"""
import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class FalsePositiveDetector:
    """
    Detects false positives in static analysis results
    """
    
    # Patterns that indicate false positives
    COMMENT_PATTERNS = [
        r'^\s*//',           # Single-line comment
        r'^\s*/\*',          # Multi-line comment start
        r'^\s*\*',           # Multi-line comment continuation
        r'^\s*\*/',          # Multi-line comment end
    ]
    
    FUNCTION_DECLARATION_PATTERNS = [
        r'^\s*void\s+\w+\s*\([^)]*\)\s*\{?\s*$',      # void function()
        r'^\s*int\s+\w+\s*\([^)]*\)\s*\{?\s*$',       # int function()
        r'^\s*char\*?\s+\w+\s*\([^)]*\)\s*\{?\s*$',   # char* function()
        r'^\s*\w+\s+\w+\s*\([^)]*\)\s*\{?\s*$',       # type function()
    ]
    
    SAFE_FUNCTIONS = [
        'printf',      # printf is safe for output
        'fprintf',     # fprintf is safe for output
        'puts',        # puts is safe
        'putchar',     # putchar is safe
    ]
    
    def __init__(self):
        self.comment_regex = [re.compile(pattern) for pattern in self.COMMENT_PATTERNS]
        self.function_decl_regex = [re.compile(pattern) for pattern in self.FUNCTION_DECLARATION_PATTERNS]
    
    def is_false_positive(
        self,
        line_content: str,
        rule_id: str,
        cwe: str,
        source_code: str = None,
        line_number: int = None,
        file_path: str = None,
        message: str = None
    ) -> Dict[str, Any]:
        """
        Check if a vulnerability is a false positive
        
        Args:
            line_content: The actual line of code
            rule_id: Cppcheck rule ID
            cwe: CWE number
            source_code: Full source code (optional, for context)
            line_number: Line number (optional, for context)
            file_path: File path (optional, for context)
            message: The vulnerability message (optional, for context)
            
        Returns:
            Dict with:
            - is_false_positive: bool
            - reason: str (why it's a false positive)
            - confidence: float (0.0-1.0)
        """
        line_stripped = line_content.strip()
        message_lower = message.lower() if message else ''
        
        # Check if it's a comment
        for regex in self.comment_regex:
            if regex.match(line_stripped):
                return {
                    'is_false_positive': True,
                    'reason': 'Code is in a comment, not executable',
                    'confidence': 1.0,
                    'category': 'comment'
                }
        
        # Check for test functions marked as unused
        # Cppcheck reports unused functions with messages like "The function 'X' is never used"
        # CWE-561 is "Dead Code" which includes unused functions
        if file_path and (cwe == 'CWE-561' or 'never used' in message_lower or 'unusedFunction' in rule_id.lower()):
            # Test files often have unused test functions
            if any(pattern in file_path.lower() for pattern in ['test', 'spec', 'mock', 'fixture', 'example']):
                # Check if the message or line content suggests it's a test function
                combined_text = f"{line_stripped} {message_lower}".lower()
                if any(pattern in combined_text for pattern in ['test_', 'test', 'example', 'demo', 'never used']):
                    return {
                        'is_false_positive': True,
                        'reason': 'Test function in test file - unused functions are expected',
                        'confidence': 0.9,
                        'category': 'test_code'
                    }
        
        # Check if it's a function declaration (not the actual vulnerable call)
        if rule_id in ['bufferAccessOutOfBounds', 'nullPointer']:
            for regex in self.function_decl_regex:
                if regex.match(line_stripped):
                    return {
                        'is_false_positive': True,
                        'reason': 'Function declaration, not the actual vulnerable code',
                        'confidence': 0.95,
                        'category': 'function_declaration'
                    }
        
        # Check if it's inside a commented-out block
        if source_code and line_number:
            if self._is_in_comment_block(source_code, line_number):
                return {
                    'is_false_positive': True,
                    'reason': 'Code is commented out (inside /* */ block)',
                    'confidence': 1.0,
                    'category': 'commented_code'
                }
        
        # Check for safe functions flagged as buffer overflow
        if rule_id == 'bufferAccessOutOfBounds':
            for safe_func in self.SAFE_FUNCTIONS:
                if f'{safe_func}(' in line_stripped:
                    # Check if it's just a safe output function
                    if not any(unsafe in line_stripped for unsafe in ['strcpy', 'strcat', 'sprintf', 'gets']):
                        return {
                            'is_false_positive': True,
                            'reason': f'{safe_func}() is a safe output function, not a buffer overflow',
                            'confidence': 0.90,
                            'category': 'safe_function'
                        }
        
        # Not a false positive
        return {
            'is_false_positive': False,
            'reason': None,
            'confidence': 0.0,
            'category': None
        }
    
    def _is_in_comment_block(self, source_code: str, line_number: int) -> bool:
        """
        Check if a line is inside a /* */ comment block
        """
        lines = source_code.split('\n')
        if line_number < 1 or line_number > len(lines):
            return False
        
        in_comment = False
        for i, line in enumerate(lines[:line_number], 1):
            # Check for comment start
            if '/*' in line:
                in_comment = True
            # Check for comment end
            if '*/' in line:
                in_comment = False
        
        return in_comment
    
    def analyze_findings(self, findings: list, source_files: dict) -> Dict[str, Any]:
        """
        Analyze a list of findings and mark false positives
        
        Args:
            findings: List of finding dicts
            source_files: Dict mapping file paths to source code
            
        Returns:
            Dict with:
            - findings: Updated findings with false_positive flag
            - stats: Statistics about false positives
        """
        stats = {
            'total': len(findings),
            'false_positives': 0,
            'real_vulnerabilities': 0,
            'by_category': {}
        }
        
        updated_findings = []
        
        for finding in findings:
            file_path = finding.get('file_path', finding.get('file', ''))
            line_number = finding.get('line_number', finding.get('line', 0))
            rule_id = finding.get('rule_id', '')
            cwe = finding.get('cwe', '')
            message = finding.get('message', '')
            
            # Get source code
            source_code = source_files.get(file_path, '')
            
            # Get the actual line content
            if source_code and line_number > 0:
                lines = source_code.split('\n')
                if line_number <= len(lines):
                    line_content = lines[line_number - 1]
                else:
                    line_content = message  # Fallback to message
            else:
                line_content = message
            
            # Check if it's a false positive
            fp_result = self.is_false_positive(
                line_content=line_content,
                rule_id=rule_id,
                cwe=cwe,
                source_code=source_code,
                line_number=line_number
            )
            
            # Add false positive info to finding
            finding['is_false_positive'] = fp_result['is_false_positive']
            finding['false_positive_reason'] = fp_result['reason']
            finding['false_positive_confidence'] = fp_result['confidence']
            finding['false_positive_category'] = fp_result['category']
            
            # Update stats
            if fp_result['is_false_positive']:
                stats['false_positives'] += 1
                category = fp_result['category']
                stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
                logger.info(f"False positive detected: {file_path}:{line_number} - {fp_result['reason']}")
            else:
                stats['real_vulnerabilities'] += 1
            
            updated_findings.append(finding)
        
        logger.info(f"False positive analysis: {stats['false_positives']}/{stats['total']} false positives detected")
        
        return {
            'findings': updated_findings,
            'stats': stats
        }
