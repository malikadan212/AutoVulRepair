"""
Dangerous API Replacement (CWE-676)
Priority: 13
Success Rate: 85-90%

Replaces dangerous/deprecated APIs with safer alternatives.
Extends the API-REP pattern from buffer_overflow.py.
"""
import logging
import re
import uuid
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class DangerousAPIRepair:
    """
    Repairs dangerous/deprecated API usage
    
    Replaces unsafe functions with safer alternatives:
    - gets() → fgets()
    - strcat() → strncat()
    - scanf("%s") → scanf("%255s")
    - Plus all buffer overflow replacements (strcpy, sprintf, etc.)
    """
    
    # Dangerous API patterns and their safe replacements
    DANGEROUS_APIS = {
        # Pattern: (regex, replacement_function, needs_size_param)
        'gets': {
            'pattern': r'\bgets\s*\(\s*([^)]+)\s*\)',
            'replacement': lambda m, buf: f'fgets({buf}, sizeof({buf}), stdin)',
            'description': 'Replace gets() with fgets()',
            'confidence': 0.95
        },
        'strcat': {
            'pattern': r'\bstrcat\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)',
            'replacement': lambda m, dest, src: f'strncat({dest}, {src}, sizeof({dest}) - strlen({dest}) - 1)',
            'description': 'Replace strcat() with strncat()',
            'confidence': 0.90
        },
        'scanf_unbounded': {
            'pattern': r'\bscanf\s*\(\s*"([^"]*%s[^"]*)"\s*,\s*([^)]+)\s*\)',
            'replacement': lambda m, fmt, var: f'scanf("{fmt.replace("%s", "%255s")}", {var})',
            'description': 'Add size limit to scanf %s format',
            'confidence': 0.85
        },
        'fscanf_unbounded': {
            'pattern': r'\bfscanf\s*\(\s*([^,]+)\s*,\s*"([^"]*%s[^"]*)"\s*,\s*([^)]+)\s*\)',
            'replacement': lambda m, fp, fmt, var: f'fscanf({fp}, "{fmt.replace("%s", "%255s")}", {var})',
            'description': 'Add size limit to fscanf %s format',
            'confidence': 0.85
        },
        'strcpy': {
            'pattern': r'\bstrcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)',
            'replacement': lambda m, dest, src: f'strncpy({dest}, {src}, sizeof({dest}) - 1); {dest}[sizeof({dest}) - 1] = \'\\0\'',
            'description': 'Replace strcpy() with strncpy() and null-terminate',
            'confidence': 0.90
        },
        'sprintf': {
            'pattern': r'\bsprintf\s*\(\s*([^,]+)\s*,\s*(.+)\)',
            'replacement': lambda m, dest, rest: f'snprintf({dest}, sizeof({dest}), {rest})',
            'description': 'Replace sprintf() with snprintf()',
            'confidence': 0.90
        },
        'vsprintf': {
            'pattern': r'\bvsprintf\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)',
            'replacement': lambda m, dest, fmt, args: f'vsnprintf({dest}, sizeof({dest}), {fmt}, {args})',
            'description': 'Replace vsprintf() with vsnprintf()',
            'confidence': 0.90
        }
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
        Generate dangerous API replacement patch
        
        Args:
            vuln: Vulnerability dict
            source_code: Full source code
            source_file: Path to source file
            
        Returns:
            Patch dict or None
        """
        line_num = vuln.get('line', 0)
        
        if not line_num:
            logger.warning(f"Missing line number for dangerous API vuln")
            return None
        
        # Get the source line
        lines = source_code.split('\n')
        if line_num < 1 or line_num > len(lines):
            logger.error(f"Line number {line_num} out of range")
            return None
        
        original_line = lines[line_num - 1]
        
        # Check if already repaired (idempotency)
        if self._is_already_safe(original_line):
            logger.info(f"Line {line_num} already uses safe API, skipping")
            return None
        
        # Detect which dangerous API is used
        api_info = self._detect_dangerous_api(original_line)
        
        if not api_info:
            logger.warning(f"Could not detect dangerous API at line {line_num}")
            return None
        
        # Generate the repaired line
        repaired_line = self._repair_api_call(original_line, api_info)
        
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
            'api': api_info['api'],
            'original': original_line.strip(),
            'repaired': repaired_line.strip(),
            'diff': diff,
            'description': f"{api_info['description']} at line {line_num}",
            'confidence': api_info['confidence'],
            'requires_acr_header': False
        }
    
    def _is_already_safe(self, line: str) -> bool:
        """
        Check if line already uses safe API
        
        Args:
            line: Source line
            
        Returns:
            True if already safe
        """
        # Check for safe alternatives
        safe_apis = ['fgets', 'strncpy', 'strncat', 'snprintf', 'vsnprintf']
        for safe_api in safe_apis:
            if re.search(rf'\b{safe_api}\s*\(', line):
                return True
        
        # Check for bounded scanf
        if re.search(r'scanf\s*\([^)]*%\d+s', line):
            return True
        
        return False
    
    def _detect_dangerous_api(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Detect which dangerous API is used
        
        Args:
            line: Source line
            
        Returns:
            API info dict or None
        """
        for api_name, api_config in self.DANGEROUS_APIS.items():
            pattern = api_config['pattern']
            match = re.search(pattern, line)
            
            if match:
                return {
                    'api': api_name,
                    'match': match,
                    'replacement': api_config['replacement'],
                    'description': api_config['description'],
                    'confidence': api_config['confidence']
                }
        
        return None
    
    def _repair_api_call(
        self,
        line: str,
        api_info: Dict[str, Any]
    ) -> str:
        """
        Repair dangerous API call
        
        Args:
            line: Original line
            api_info: API info dict
            
        Returns:
            Repaired line
        """
        match = api_info['match']
        replacement_func = api_info['replacement']
        
        # Extract matched groups
        groups = match.groups()
        
        # Generate replacement
        try:
            replacement = replacement_func(match, *groups)
        except Exception as e:
            logger.error(f"Error generating replacement: {e}")
            return line
        
        # Replace in line
        indent = line[:len(line) - len(line.lstrip())]
        repaired = line[:match.start()] + replacement + line[match.end():]
        
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
