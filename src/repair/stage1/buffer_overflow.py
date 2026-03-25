import re
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class BufferOverflowScanner:
    """
    Scanner for Buffer Overflow vulnerabilities.
    Detects specific API calls and evaluates their overflow constraint.
    """
    
    API_PATTERNS = {
        'strcpy': r'\bstrcpy\s*\(([^,]+),\s*([^)]+)\)',
        'strncpy': r'\bstrncpy\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
        'memcpy': r'\bmemcpy\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
        'memmove': r'\bmemmove\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
        'memset': r'\bmemset\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
        'snprintf': r'\bsnprintf\s*\(([^,]+),\s*([^,]+)(.+)\)',
        'vsnprintf': r'\bvsnprintf\s*\(([^,]+),\s*([^,]+)(.+)\)',
        'strcat': r'\bstrcat\s*\(([^,]+),\s*([^)]+)\)',
        'strncat': r'\bstrncat\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
        'sprintf': r'\bsprintf\s*\(([^,]+),\s*([^,]+)([^)]*)\)',
        'fgets': r'\bfgets\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
        'fread': r'\bfread\s*\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)',
        'read': r'\bread\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
    }
    
    # Simple regex for array access or pointer arithmetic. 
    # e.g. buf[i] or *(buf + i), ensuring index is a variable (starts with letter/underscore)
    ARRAY_ACCESS_PATTERN = r'(\w+)\s*\[\s*([a-zA-Z_]\w*)\s*\]'
    POINTER_ARITHMETIC_PATTERN = r'\*\s*\(\s*(\w+)\s*\+\s*([a-zA-Z_]\w*)\s*\)'

    def __init__(self, time_threshold: int = 10):
        self.time_threshold = time_threshold

    def is_reachable(self, line_num: int, icfg: Any) -> bool:
        """
        Check if the warning point is reachable from program entry.
        Unreachable warning points are classified as false positives.
        """
        if icfg is None:
            return True # Fallback to true if no ICFG is provided
        return icfg.is_reachable(line_num)

    def resolve_constraint(self, constraint: str, time_limit: int) -> str:
        """
        Simulate constraint solving. 
        Returns 'true', 'false', or 'undecidable'.
        """
        # In a real implementation, this would invoke an SMT solver (e.g., Z3).
        # We simulate the threshold logic here.
        # If the solver cannot resolve the warning within the time threshold, it is marked 'undecidable'.
        pass 

    def scan_line(self, line: str, line_num: int, icfg: Any = None) -> Optional[Dict[str, Any]]:
        """
        Scan a single line for APIs and evaluate overflow constraint.
        """
        if not self.is_reachable(line_num, icfg):
            logger.info(f"Line {line_num} is unreachable by backward ICFG constraint. False positive.")
            return {
                'line': line_num,
                'status': 'false_positive',
                'reason': 'unreachable'
            }

        vulnerabilities = []
        
        # 1. Check API calls
        for api, pattern in self.API_PATTERNS.items():
            match = re.search(pattern, line)
            if match:
                vuln = self._extract_api_constraint(api, match, line_num, line)
                if vuln:
                    vulnerabilities.append(vuln)
                    
        # 2. Check Direct Array / Pointer Access
        match_array = re.search(self.ARRAY_ACCESS_PATTERN, line)
        if match_array:
            buf = match_array.group(1).strip()
            idx = match_array.group(2).strip()
            # If idx is variable block, constraint: i * sizeof(buf[0]) >= sizeof(buf)
            constraint = f"{idx}*sizeof({buf}[0]) >= sizeof({buf})"
            vulnerabilities.append({
                'api': 'array_access',
                'line': line_num,
                'dest': buf,
                'idx': idx,
                'constraint': constraint,
                'status': 'vulnerable',
                'original': line
            })

        match_ptr = re.search(self.POINTER_ARITHMETIC_PATTERN, line)
        if match_ptr:
            buf = match_ptr.group(1).strip()
            idx = match_ptr.group(2).strip()
            constraint = f"{idx}*sizeof({buf}[0]) >= sizeof({buf})"
            vulnerabilities.append({
                'api': 'pointer_access',
                'line': line_num,
                'dest': buf,
                'idx': idx,
                'constraint': constraint,
                'status': 'vulnerable',
                'original': line
            })

        if vulnerabilities:
            # Note: For multiple vulns on a line, return the first for simplicity
            return vulnerabilities[0]
            
        return None

    def _extract_api_constraint(self, api: str, match: re.Match, line_num: int, line: str) -> Optional[Dict[str, Any]]:
        """
        Evaluates the specific overflow constraint for the detected API.
        """
        constraint = ""
        dest = ""
        
        if api == 'strcpy':
            dest = match.group(1).strip()
            src = match.group(2).strip()
            constraint = f"strlen({src}) >= sizeof({dest})"
            
        elif api in ['strncpy', 'memcpy', 'memmove', 'memset', 'snprintf', 'vsnprintf']:
            dest = match.group(1).strip()
            if api in ['strncpy', 'snprintf', 'vsnprintf']:
                n = match.group(3).strip() if api == 'strncpy' else match.group(2).strip() # simplified param mapping
            else:
                n = match.group(3).strip() # memcpy(dest, src, n)
            constraint = f"{n} > sizeof({dest})"
            
        elif api == 'strcat':
            dest = match.group(1).strip()
            src = match.group(2).strip()
            constraint = f"strlen({src}) + strlen({dest}) >= sizeof({dest})"
            
        elif api == 'strncat':
            dest = match.group(1).strip()
            src = match.group(2).strip()
            n = match.group(3).strip()
            # strncat min-length constraint
            constraint = f"min(strlen({src}), {n}) + strlen({dest}) >= sizeof({dest})"
            
        elif api == 'sprintf':
            dest = match.group(1).strip()
            format_str = match.group(2).strip()
            args = match.group(3).strip()
            # sprintf format length computation using MY_vsnprintf
            constraint = f"MY_vsnprintf({format_str}{args}) >= sizeof({dest})"
            
        elif api == 'fgets':
            dest = match.group(1).strip()
            num = match.group(2).strip()
            constraint = f"{num} > sizeof({dest})"
            
        elif api == 'fread':
            dest = match.group(1).strip()
            size = match.group(2).strip()
            count = match.group(3).strip()
            constraint = f"{size}*{count} > sizeof({dest})"
            
        elif api == 'read':
            fd = match.group(1).strip()
            buf = match.group(2).strip()
            count = match.group(3).strip()
            dest = buf
            constraint = f"{count} > sizeof({buf})"

        return {
            'api': api,
            'line': line_num,
            'dest': dest,
            'constraint': constraint,
            'status': 'vulnerable', # If simulation fails or times out, mark 'undecidable'
            'original': line,
            'match': match.groups()
        }


class BufferOverflowFixer:
    """
    Fixer for Buffer Overflow vulnerabilities.
    Modes: "default", "API-REP", "extend"
    """
    def __init__(self, mode: str = "default"):
        if mode not in ["default", "API-REP", "extend"]:
            raise ValueError("Invalid mode. Must be 'default', 'API-REP', or 'extend'.")
        self.mode = mode

    def generate_patch(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Generate a patch based on the fixer mode.
        """
        status = vuln.get('status')
        if status == 'false_positive':
            return None # Skip repair
        elif status == 'undecidable':
            # Neither fixed nor dismissed
            logger.warning(f"Warning at line {vuln.get('line')} is undecidable.")
            return None 

        api = vuln.get('api')
        dest = vuln.get('dest')
        original = vuln.get('original', '')
        constraint = vuln.get('constraint')
        match = vuln.get('match', [])

        repaired_lines = []
        needs_my_vsnprintf = False

        if self.mode == "extend":
            # Buffer extension strategy
            # Flag for manual buffer size configuration at the declaration site
            target_line = vuln.get('decl_line', vuln.get('line'))
            return {
                'line': target_line,
                'is_extend_mode': True,
                'dest': dest
            }
        elif self.mode == "API-REP":
            # Replace with safer API or fallback to boundary check
            safe_api_replacement = self._get_safe_api_replacement(api, dest, original, match)
            if safe_api_replacement:
                repaired_lines = [safe_api_replacement]
            else:
                # Fallback to boundary check (default mode behaviour)
                chk_lines, needs_my_vsnprintf = self._get_boundary_check(api, dest, original, constraint, match)
                repaired_lines = chk_lines
        elif self.mode == "default":
            # Insert boundary check before the vulnerable line
            chk_lines, needs_my_vsnprintf = self._get_boundary_check(api, dest, original, constraint, match)
            repaired_lines = chk_lines

        return {
            'line': vuln['line'],
            'original': original,
            'repaired': '\n'.join(repaired_lines),
            'needs_my_vsnprintf': needs_my_vsnprintf
        }

    def _get_safe_api_replacement(self, api: str, dest: str, original: str, match: tuple) -> Optional[str]:
        """
        Return replacement safe API string, or None if no direct safe API exists.
        Only strcpy, strcat, and sprintf have a direct safe API replacement options.
        """
        indent = original[:len(original) - len(original.lstrip())]
        
        if api == 'strcpy':
            src = match[1].strip()
            return f"{indent}strncpy({dest}, {src}, sizeof({dest}));"
        elif api == 'strcat':
            src = match[1].strip()
            return f"{indent}snprintf({dest} + strlen({dest}), sizeof({dest}) - strlen({dest}), \"%s\", {src});"
        elif api == 'sprintf':
            format_str = match[1].strip()
            args = match[2].strip() if len(match) > 2 else ""
            return f"{indent}snprintf({dest}, sizeof({dest}), {format_str}{args});"
        
        # APIs without Safer API Option: fallback to boundary check
        return None

    def _get_boundary_check(self, api: str, dest: str, original: str, constraint: str, match: tuple) -> Tuple[List[str], bool]:
        """
        Generate boundary check insertion code.
        Returns the lines and a boolean indicating if MY_vsnprintf.h is needed.
        """
        indent = original[:len(original) - len(original.lstrip())]
        needs_my_vsnprintf = False
        
        if api == 'sprintf':
            format_str = match[1].strip()
            args = match[2].strip() if len(match) > 2 else ""
            # Insert MY_vsnprintf logic before original line
            needs_my_vsnprintf = True
            return [
                f"{indent}if (MY_vsnprintf({format_str}{args}) >= sizeof({dest})) {{ /* terminate */ return; }}",
                original.strip()
            ], needs_my_vsnprintf
            
        boundary_logic = f"{indent}if ({constraint}) {{ /* terminate */ return; }}"
        return [boundary_logic, original.strip()], needs_my_vsnprintf

    def batch_repair(self, vulnerabilities: List[Dict[str, Any]], source_code: str) -> str:
        """
        Line number shifting during batch repair:
        Extract positions, sort descending by line number (bottom to top),
        and apply repairs so earlier insertions don't shift later positions.
        """
        # Sort vulnerabilities in descending order by line number depending on the action
        # For extend mode, we use decl_line. So we resolve the precise line we will alter.
        patches = []
        for vuln in vulnerabilities:
            patch = self.generate_patch(vuln)
            if patch:
                patches.append(patch)
                
        # Sort descending by the target line to avoid shifting issues
        sorted_patches = sorted(patches, key=lambda p: p.get('line', 0), reverse=True)
        
        lines = source_code.split('\n')
        include_my_vsnprintf = False
        
        for patch in sorted_patches:
            line_idx = patch['line'] - 1
            if 0 <= line_idx < len(lines):
                if patch.get('is_extend_mode'):
                    # Insert comment above the declaration/definition
                    dest = patch.get('dest', 'buffer')
                    lines[line_idx] = f"/* TODO(BufferExtend): Manual buffer size configuration required for '{dest}' to prevent overflow */\n{lines[line_idx]}"
                else:
                    # Replace the original line with the repaired block
                    lines[line_idx] = patch['repaired']
                
                if patch.get('needs_my_vsnprintf'):
                    include_my_vsnprintf = True
                    
        repaired_code = '\n'.join(lines)
        if include_my_vsnprintf:
            repaired_code = '#include "MY_vsnprintf.h"\n' + repaired_code
            
        return repaired_code


def run_buffer_overflow_repair(source_code: str, mode: str = "default", icfg: Any = None) -> str:
    """
    Convenience function to scan and fix source code.
    """
    scanner = BufferOverflowScanner()
    
    lines = source_code.split('\n')
    vulns = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        vuln = scanner.scan_line(line, line_num, icfg)
        if vuln:
            vulns.append(vuln)
            
    fixer = BufferOverflowFixer(mode=mode)
    repaired_code = fixer.batch_repair(vulns, source_code)
    
    return repaired_code
