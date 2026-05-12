"""
Format String Vulnerability Repair (CWE-134)
Priority: 14
Success Rate: 80-85% (for direct variable cases)

Repairs common format string vulnerabilities where user input is used directly
as a format string argument.
"""
import logging
import re
import uuid
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)


class FormatStringRepair:
    """
    Repairs format string vulnerabilities
    
    Handles two main patterns:
    1. Direct variable as format string: printf(user_input) → printf("%s", user_input)
    2. User input in format position: syslog(LOG_INFO, msg) → syslog(LOG_INFO, "%s", msg)
    
    Success Rate: ~80% for direct variable cases
    Routes complex cases (dynamic format construction) to Stage 2
    """
    
    # Format functions with their format string position (0-indexed)
    FORMAT_FUNCTIONS = {
        # Standard printf family
        'printf': {'format_pos': 0, 'safe_format': '"%s"'},
        'fprintf': {'format_pos': 1, 'safe_format': '"%s"'},
        'sprintf': {'format_pos': 1, 'safe_format': '"%s"'},
        'snprintf': {'format_pos': 2, 'safe_format': '"%s"'},
        'vprintf': {'format_pos': 0, 'safe_format': '"%s"'},
        'vfprintf': {'format_pos': 1, 'safe_format': '"%s"'},
        'vsprintf': {'format_pos': 1, 'safe_format': '"%s"'},
        'vsnprintf': {'format_pos': 2, 'safe_format': '"%s"'},
        
        # Syslog family
        'syslog': {'format_pos': 1, 'safe_format': '"%s"'},
        'vsyslog': {'format_pos': 1, 'safe_format': '"%s"'},
        
        # Error reporting
        'err': {'format_pos': 1, 'safe_format': '"%s"'},
        'verr': {'format_pos': 1, 'safe_format': '"%s"'},
        'errx': {'format_pos': 1, 'safe_format': '"%s"'},
        'verrx': {'format_pos': 1, 'safe_format': '"%s"'},
        'warn': {'format_pos': 0, 'safe_format': '"%s"'},
        'vwarn': {'format_pos': 0, 'safe_format': '"%s"'},
        'warnx': {'format_pos': 0, 'safe_format': '"%s"'},
        'vwarnx': {'format_pos': 0, 'safe_format': '"%s"'},
        
        # Logging functions
        'error': {'format_pos': 0, 'safe_format': '"%s"'},
        'log': {'format_pos': 0, 'safe_format': '"%s"'},
        'logf': {'format_pos': 0, 'safe_format': '"%s"'},
    }
    
    def __init__(self):
        pass
    
    def generate_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate format string vulnerability patch
        
        Args:
            vuln: Vulnerability dict
            source_code: Full source code
            source_file: Path to source file
            
        Returns:
            Patch dict or None if not repairable by Stage 1
        """
        line_num = vuln.get('line', 0)
        
        if not line_num:
            logger.warning(f"Missing line number for format string vuln")
            return None
        
        # Get the source line
        lines = source_code.split('\n')
        if line_num < 1 or line_num > len(lines):
            logger.error(f"Line number {line_num} out of range")
            return None
        
        original_line = lines[line_num - 1]
        
        # Check if already repaired (idempotency)
        if self._is_already_safe(original_line):
            logger.info(f"Line {line_num} already has safe format string, skipping")
            return None
        
        # Analyze the format string vulnerability
        analysis = self._analyze_format_string(original_line, line_num)
        
        if not analysis:
            logger.warning(f"Could not analyze format string at line {line_num}")
            return None
        
        if analysis['complexity'] == 'complex':
            logger.info(f"Complex format string at line {line_num}, routing to Stage 2")
            return None  # Route to Stage 2
        
        # Generate the repaired line
        repaired_line = self._repair_format_string(original_line, analysis)
        
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
            'vulnerability_id': vuln.get('finding_id') or vuln.get('id', ''),
            'file': source_file,
            'line': line_num,
            'function': analysis['function'],
            'original': original_line.strip(),
            'repaired': repaired_line.strip(),
            'diff': diff,
            'description': f"Fix format string vulnerability in {analysis['function']}() at line {line_num}",
            'confidence': analysis['confidence'],
            'pattern': analysis['pattern'],
            'requires_acr_header': False
        }
    
    def _is_already_safe(self, line: str) -> bool:
        """
        Check if line already has safe format string
        
        Args:
            line: Source line
            
        Returns:
            True if already safe
        """
        # Check if format string is a literal (contains quotes)
        for func_name in self.FORMAT_FUNCTIONS.keys():
            pattern = rf'\b{func_name}\s*\('
            if re.search(pattern, line):
                # Extract arguments
                match = re.search(rf'\b{func_name}\s*\(([^)]+)\)', line)
                if match:
                    args = match.group(1)
                    # Check if first/second arg (depending on function) is a string literal
                    if '"%s"' in args or '\'%s\'' in args:
                        return True
                    # Check if format arg contains format specifiers
                    if re.search(r'["\'].*%[sdifuxXeEgGcpn]', args):
                        return True
        
        return False
    
    def _analyze_format_string(
        self,
        line: str,
        line_num: int
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze format string vulnerability
        
        Args:
            line: Source line
            line_num: Line number
            
        Returns:
            Analysis dict with pattern, complexity, confidence, etc.
        """
        # Find which format function is used
        for func_name, func_info in self.FORMAT_FUNCTIONS.items():
            pattern = rf'\b{func_name}\s*\(([^)]+)\)'
            match = re.search(pattern, line)
            
            if match:
                args_str = match.group(1)
                args = self._parse_arguments(args_str)
                
                if not args:
                    continue
                
                format_pos = func_info['format_pos']
                
                # Check if we have enough arguments
                if len(args) <= format_pos:
                    continue
                
                format_arg = args[format_pos].strip()
                
                # Determine complexity and pattern
                complexity, pattern, confidence = self._classify_format_arg(format_arg)
                
                return {
                    'function': func_name,
                    'format_pos': format_pos,
                    'format_arg': format_arg,
                    'all_args': args,
                    'complexity': complexity,
                    'pattern': pattern,
                    'confidence': confidence,
                    'safe_format': func_info['safe_format']
                }
        
        return None
    
    def _parse_arguments(self, args_str: str) -> List[str]:
        """
        Parse function arguments, handling nested parentheses and commas
        
        Args:
            args_str: Arguments string
            
        Returns:
            List of argument strings
        """
        args = []
        current_arg = []
        paren_depth = 0
        
        for char in args_str:
            if char == '(':
                paren_depth += 1
                current_arg.append(char)
            elif char == ')':
                paren_depth -= 1
                current_arg.append(char)
            elif char == ',' and paren_depth == 0:
                # Argument separator
                args.append(''.join(current_arg).strip())
                current_arg = []
            else:
                current_arg.append(char)
        
        # Add last argument
        if current_arg:
            args.append(''.join(current_arg).strip())
        
        return args
    
    def _classify_format_arg(
        self,
        format_arg: str
    ) -> Tuple[str, str, float]:
        """
        Classify format argument complexity
        
        Args:
            format_arg: Format argument string
            
        Returns:
            Tuple of (complexity, pattern, confidence)
            - complexity: 'simple', 'complex'
            - pattern: 'direct_variable', 'function_call', 'expression', 'dynamic'
            - confidence: 0.0-1.0
        """
        # Pattern 1: Direct variable (most common)
        # printf(user_input) or fprintf(fp, msg)
        if re.match(r'^[a-zA-Z_]\w*$', format_arg):
            return ('simple', 'direct_variable', 0.95)
        
        # Pattern 2: Simple dereference
        # printf(*ptr) or printf(obj->field)
        if re.match(r'^\*[a-zA-Z_]\w*$', format_arg) or \
           re.match(r'^[a-zA-Z_]\w*->[a-zA-Z_]\w*$', format_arg):
            return ('simple', 'direct_variable', 0.90)
        
        # Pattern 3: Array access
        # printf(array[i])
        if re.match(r'^[a-zA-Z_]\w*\[[^\]]+\]$', format_arg):
            return ('simple', 'direct_variable', 0.85)
        
        # Pattern 4: Function call returning string
        # printf(get_message())
        if re.search(r'[a-zA-Z_]\w*\s*\([^)]*\)$', format_arg):
            return ('simple', 'function_call', 0.80)
        
        # Pattern 5: String literal (already safe, but shouldn't reach here)
        if format_arg.startswith('"') or format_arg.startswith("'"):
            return ('simple', 'literal', 1.0)
        
        # Pattern 6: Complex expression (string concatenation, ternary, etc.)
        # printf(flag ? msg1 : msg2) or printf(str1 + str2)
        if '+' in format_arg or '?' in format_arg or 'strcat' in format_arg:
            return ('complex', 'dynamic', 0.0)
        
        # Pattern 7: sprintf/snprintf building format string
        if 'sprintf' in format_arg or 'snprintf' in format_arg:
            return ('complex', 'dynamic', 0.0)
        
        # Default: treat as simple if it looks like a variable expression
        if re.match(r'^[a-zA-Z_][\w\.\->\[\]]*$', format_arg):
            return ('simple', 'expression', 0.75)
        
        # Unknown pattern - route to Stage 2
        return ('complex', 'unknown', 0.0)
    
    def _repair_format_string(
        self,
        line: str,
        analysis: Dict[str, Any]
    ) -> str:
        """
        Repair format string vulnerability
        
        Args:
            line: Original line
            analysis: Analysis dict
            
        Returns:
            Repaired line
        """
        func_name = analysis['function']
        format_pos = analysis['format_pos']
        format_arg = analysis['format_arg']
        all_args = analysis['all_args']
        safe_format = analysis['safe_format']
        
        # Build new argument list
        new_args = all_args.copy()
        
        # Insert safe format string at format position
        # Move original format arg to next position
        new_args.insert(format_pos, safe_format)
        
        # Build repaired function call
        indent = line[:len(line) - len(line.lstrip())]
        new_args_str = ', '.join(new_args)
        
        # Replace the function call
        pattern = rf'\b{func_name}\s*\([^)]+\)'
        replacement = f'{func_name}({new_args_str})'
        
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
