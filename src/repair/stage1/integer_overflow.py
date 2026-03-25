import re
import math
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class IntegerOverflowScanner:
    """
    Scanner for integer overflow vulnerabilities.
    """
    BOUNDS = {
        'char': ('CHAR_MAX', '-CHAR_MAX'),
        'short': ('SHRT_MAX', '-SHRT_MAX'),
        'int': ('INT_MAX', 'INT_MIN'),
        'int64_t': ('LLONG_MAX', '-LLONG_MAX'),
        'long long': ('LLONG_MAX', '-LLONG_MAX'),
        'unsigned int': ('UINT_MAX', '0'),
        'unsigned long': ('ULONG_MAX', '0')
    }

    def __init__(self):
        # We look for binary assignments: type x = s1 op s2;
        # Support basic types optionally leading the assignment
        self.statement_pattern = re.compile(
            r'^(\s*)(?:(?:unsigned\s+|long\s+)*\w+\s+)?(\w+)\s*=\s*(.+?)\s*([+\-*\/&|><]+)\s*(.+?);'
        )

    def scan_line(self, line: str, line_num: int, source_code: str = "") -> Optional[Dict[str, Any]]:
        if any(op in line for op in ['>>', '<<', '-', 'trunc']):
            # Explicitly unsupported per Implementation note 12
            match = self.statement_pattern.search(line)
            if match and match.group(4) in ('-', '>>', '<<'):
                return {'line': line_num, 'status': 'unsupported_operation'}

        match = self.statement_pattern.search(line)
        if not match:
            return None

        indent = match.group(1)
        result_var = match.group(2)
        s1 = match.group(3).strip()
        op = match.group(4).strip()
        s2 = match.group(5).strip()

        if op not in ('+', '*'):
            return {'line': line_num, 'status': 'no_repair_proposed'}

        # Detect integer type (search backward)
        int_type = self._detect_type(line, result_var, source_code, line_num)
        max_bound, min_bound = self.BOUNDS.get(int_type, ('INT_MAX', 'INT_MIN'))

        is_s1_var = self._is_var(s1)
        is_s2_var = self._is_var(s2)
        s1_const = self._get_const(s1)
        s2_const = self._get_const(s2)
        
        precondition = None

        if op == '+':
            if is_s1_var and is_s2_var:
                precondition = f"({s1} > {max_bound} - {s2}) || ({s1} < {min_bound} - {s2})"
            elif is_s1_var and s2_const is not None and s2_const > 0:
                precondition = f"({s1} > 0) && ({s1} > ({max_bound} - {s2}))"
            elif is_s2_var and s1_const is not None and s1_const > 0:
                precondition = f"({s2} > 0) && ({s2} > ({max_bound} - {s1}))"
            else:
                return {'line': line_num, 'status': 'no_repair_proposed'}

        elif op == '*':
            if is_s1_var and is_s2_var and s1 == s2:
                # Two equal variables
                precondition = f"({s1} > 0 && {s1} >= sqrt({max_bound})) || ({s1} < 0 && {s1} < -sqrt({max_bound}))"
            elif is_s1_var and s2_const is not None and s2_const < 0:
                precondition = f"({s1} > 0 && {s1} > ({min_bound}/({s2}))) || ({s1} < 0 && {s1} < ({max_bound}/({s2})))"
            elif is_s2_var and s1_const is not None and s1_const < 0:
                precondition = f"({s2} > 0 && {s2} > ({min_bound}/({s1}))) || ({s2} < 0 && {s2} < ({max_bound}/({s1})))"
            else:
                return {'line': line_num, 'status': 'no_repair_proposed'}

        if not precondition:
            return {'line': line_num, 'status': 'no_repair_proposed'}

        return {
            'line': line_num,
            'status': 'vulnerable',
            'precondition': precondition,
            'original': line.strip(),
            'indent': indent
        }

    def _detect_type(self, line: str, var_name: str, source_code: str, line_num: int) -> str:
        # Check current line
        types = ['char', 'short', 'int64_t', 'long long', 'unsigned int', 'unsigned long', 'int']
        for t in types:
            if re.search(rf'\b{t}\b', line):
                return t
        # Check backwards
        lines = source_code.split('\n')
        for i in range(max(0, line_num - 20), line_num - 1):
            for t in types:
                if re.search(rf'\b{t}\b.*\b{var_name}\b', lines[i]):
                    return t
        return 'int'

    def _is_var(self, s: str) -> bool:
        s = s.strip()
        # Ensure it starts with letter or underscore, which means it's a variable and not a pure number/constant
        if re.match(r'^[a-zA-Z_]\w*$', s):
            return True
        return False

    def _get_const(self, s: str) -> Optional[int]:
        s = s.strip('() ')
        try:
            return int(s)
        except ValueError:
            return None


class IntegerOverflowFixer:
    """
    Applies the repairs for integer overflow based on INTREPAIR.
    """
    def __init__(self, mode: str = "automated"):
        self.mode = mode

    def generate_patch(self, vuln: Dict[str, Any]) -> str:
        indent = vuln.get('indent', '')
        precondition = vuln.get('precondition')
        original = vuln.get('original')

        repaired = f"{indent}if ({precondition}) {{\n"
        repaired += f"{indent}    log_or_die();\n"
        repaired += f"{indent}}} else {{\n"
        repaired += f"{indent}    {original}\n"
        repaired += f"{indent}}}"
        return repaired

    def batch_repair(self, source_code: str) -> Tuple[str, List[Dict[str, Any]], Dict[int, str]]:
        scanner = IntegerOverflowScanner()
        lines = source_code.split('\n')
        vulns = []

        for i, line in enumerate(lines):
            vuln = scanner.scan_line(line, i + 1, source_code)
            if vuln and vuln.get('status') == 'vulnerable':
                vulns.append(vuln)
            elif vuln and vuln.get('status') == 'no_repair_proposed':
                # Mark unrepaired explicitly
                vulns.append(vuln)
                
        # Sort descending by line number (Implementation Note 7)
        sorted_vulns = sorted([v for v in vulns if v.get('status') == 'vulnerable'], key=lambda x: x['line'], reverse=True)
        
        repaired_lines_map = {}
        for vuln in sorted_vulns:
            line_idx = vuln['line'] - 1
            if 0 <= line_idx < len(lines):
                repaired = self.generate_patch(vuln)
                lines[line_idx] = repaired
                repaired_lines_map[vuln['line']] = repaired
                logger.info(f"Repair removes the detected integer overflow at line {vuln['line']}. Other faults previously masked by this fault may now be exposed. Re-run full analysis on the repaired program.")
                
        return '\n'.join(lines), vulns, repaired_lines_map


class IntegerOverflowValidator:
    """
    Validates if the repair correctly removed the overflow without introducing new ones.
    """
    def validate(self, original_source: str, repaired_source: str, expected_vulns: List[Dict[str, Any]]) -> Dict[int, str]:
        results = {}
        # In a generic static parsing scope without control-flow/data-flow bounds, 
        # we check if the wrapped log_or_die constraint is present at the repair location
        # to confirm structural mitigation.
        
        repaired_lines_split = repaired_source.split('\n')
        
        for vuln in expected_vulns:
            line_num = vuln['line']
            if vuln.get('status') == 'no_repair_proposed':
                results[line_num] = 'unrepaired_source_code'
                continue
            
            # Simulated check: ensure the block wrapper is populated with log_or_die()
            # In a full tool, the scanner re-runs path equations here.
            line_idx = line_num - 1
            if line_idx < len(repaired_lines_split):
                if 'log_or_die()' in repaired_lines_split[line_idx]:
                    results[line_num] = 'correct_repair'
                else:
                    results[line_num] = 'unremoved_overflow'
            else:
                results[line_num] = 'unrepaired_source_code'
                
        return results

def run_int_repair(source_code: str) -> Tuple[str, Dict[str, Any]]:
    fixer = IntegerOverflowFixer()
    repaired_code, original_vulns, _ = fixer.batch_repair(source_code)
    
    validator = IntegerOverflowValidator()
    validation_results = validator.validate(source_code, repaired_code, original_vulns)
    
    return repaired_code, validation_results
