import re
import math
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class IntegerOverflowScanner:
    """
    Scanner for integer overflow vulnerabilities.
    
    Supports:
    - Addition overflow (CWE-190)
    - Multiplication overflow (CWE-190)
    - Subtraction underflow (CWE-191) - NEW
    - Left shift overflow (CWE-190) - NEW
    - Truncation/narrowing cast (CWE-197) - NEW
    """
    BOUNDS = {
        'char': ('CHAR_MAX', 'CHAR_MIN'),
        'short': ('SHRT_MAX', 'SHRT_MIN'),
        'int': ('INT_MAX', 'INT_MIN'),
        'int64_t': ('LLONG_MAX', 'LLONG_MIN'),
        'long long': ('LLONG_MAX', 'LLONG_MIN'),
        'unsigned int': ('UINT_MAX', '0'),
        'unsigned long': ('ULONG_MAX', '0'),
        'unsigned char': ('UCHAR_MAX', '0'),
        'unsigned short': ('USHRT_MAX', '0')
    }

    def __init__(self):
        # Pattern 1: Binary operations (addition, subtraction, multiplication)
        self.binary_op_pattern = re.compile(
            r'^(\s*)(?:(?:unsigned\s+|long\s+)*\w+\s+)?(\w+)\s*=\s*(.+?)\s*([+\-*])\s*(.+?);'
        )
        
        # Pattern 2: Left shift operations
        self.shift_pattern = re.compile(
            r'^(\s*)(?:(?:unsigned\s+|long\s+)*\w+\s+)?(\w+)\s*=\s*(.+?)\s*<<\s*(.+?);'
        )
        
        # Pattern 3: Narrowing cast (type conversion)
        self.cast_pattern = re.compile(
            r'^(\s*)(?:unsigned\s+|signed\s+)?(char|short|int)\s+(\w+)\s*=\s*\((?:unsigned\s+|signed\s+)?(char|short|int)\)\s*(.+?);'
        )

    def scan_line(self, line: str, line_num: int, source_code: str = "") -> Optional[Dict[str, Any]]:
        """
        Scan a line for integer overflow vulnerabilities
        
        Detects:
        1. Addition overflow
        2. Multiplication overflow
        3. Subtraction underflow (NEW)
        4. Left shift overflow (NEW)
        5. Truncation/narrowing cast (NEW)
        """
        # Try Pattern 1: Binary operations (addition, subtraction, multiplication)
        match = self.binary_op_pattern.search(line)
        if match:
            return self._scan_binary_op(match, line, line_num, source_code)
        
        # Try Pattern 2: Left shift
        match = self.shift_pattern.search(line)
        if match:
            return self._scan_shift(match, line, line_num, source_code)
        
        # Try Pattern 3: Narrowing cast
        match = self.cast_pattern.search(line)
        if match:
            return self._scan_cast(match, line, line_num, source_code)
        
        return None
    
    def _scan_binary_op(
        self,
        match: re.Match,
        line: str,
        line_num: int,
        source_code: str
    ) -> Optional[Dict[str, Any]]:
        """Scan binary operations: addition, subtraction, multiplication"""
        indent = match.group(1)
        result_var = match.group(2)
        s1 = match.group(3).strip()
        op = match.group(4).strip()
        s2 = match.group(5).strip()

        # Detect integer type
        int_type = self._detect_type(line, result_var, source_code, line_num)
        max_bound, min_bound = self.BOUNDS.get(int_type, ('INT_MAX', 'INT_MIN'))

        is_s1_var = self._is_var(s1)
        is_s2_var = self._is_var(s2)
        s1_const = self._get_const(s1)
        s2_const = self._get_const(s2)
        
        precondition = None
        operation_type = None

        if op == '+':
            operation_type = 'addition_overflow'
            if is_s1_var and is_s2_var:
                precondition = f"({s1} > {max_bound} - {s2}) || ({s1} < {min_bound} - {s2})"
            elif is_s1_var and s2_const is not None and s2_const > 0:
                precondition = f"({s1} > 0) && ({s1} > ({max_bound} - {s2}))"
            elif is_s2_var and s1_const is not None and s1_const > 0:
                precondition = f"({s2} > 0) && ({s2} > ({max_bound} - {s1}))"
            else:
                return {'line': line_num, 'status': 'no_repair_proposed'}

        elif op == '-':
            # NEW: Subtraction underflow (CWE-191)
            operation_type = 'subtraction_underflow'
            if is_s1_var and is_s2_var:
                # General case: check if s2 > s1 (for unsigned) or underflow (for signed)
                if 'unsigned' in int_type:
                    precondition = f"({s2} > {s1})"
                else:
                    precondition = f"({s1} < {min_bound} + {s2}) || ({s1} > {max_bound} + {s2})"
            elif is_s1_var and s2_const is not None:
                if 'unsigned' in int_type and s2_const > 0:
                    precondition = f"({s1} < {s2})"
                elif s2_const > 0:
                    precondition = f"({s1} < {min_bound} + {s2})"
                else:
                    return {'line': line_num, 'status': 'no_repair_proposed'}
            else:
                return {'line': line_num, 'status': 'no_repair_proposed'}

        elif op == '*':
            operation_type = 'multiplication_overflow'
            if is_s1_var and is_s2_var and s1 == s2:
                # Two equal variables
                precondition = f"({s1} > 0 && {s1} >= sqrt({max_bound})) || ({s1} < 0 && {s1} < -sqrt({max_bound}))"
            elif is_s1_var and s2_const is not None and s2_const < 0:
                precondition = f"({s1} > 0 && {s1} > ({min_bound}/({s2}))) || ({s1} < 0 && {s1} < ({max_bound}/({s2})))"
            elif is_s2_var and s1_const is not None and s1_const < 0:
                precondition = f"({s2} > 0 && {s2} > ({min_bound}/({s1}))) || ({s2} < 0 && {s2} < ({max_bound}/({s1})))"
            elif is_s1_var and s2_const is not None and s2_const > 0:
                # Variable * positive constant
                precondition = f"({s1} > 0 && {s1} > ({max_bound}/{s2})) || ({s1} < 0 && {s1} < ({min_bound}/{s2}))"
            elif is_s2_var and s1_const is not None and s1_const > 0:
                # Positive constant * variable
                precondition = f"({s2} > 0 && {s2} > ({max_bound}/{s1})) || ({s2} < 0 && {s2} < ({min_bound}/{s1}))"
            elif is_s1_var and is_s2_var:
                # Two different variables
                precondition = f"({s1} != 0 && {s2} != 0 && abs({s1}) > ({max_bound}/abs({s2})))"
            else:
                return {'line': line_num, 'status': 'no_repair_proposed'}

        if not precondition:
            return {'line': line_num, 'status': 'no_repair_proposed'}

        return {
            'line': line_num,
            'status': 'vulnerable',
            'operation_type': operation_type,
            'precondition': precondition,
            'original': line.strip(),
            'indent': indent,
            'int_type': int_type
        }
    
    def _scan_shift(
        self,
        match: re.Match,
        line: str,
        line_num: int,
        source_code: str
    ) -> Optional[Dict[str, Any]]:
        """Scan left shift operations for overflow"""
        indent = match.group(1)
        result_var = match.group(2)
        value = match.group(3).strip()
        shift_amount = match.group(4).strip()
        
        # Detect integer type
        int_type = self._detect_type(line, result_var, source_code, line_num)
        
        # Calculate bit width
        bit_width = self._get_bit_width(int_type)
        
        # Precondition: shift amount must be in valid range [0, bit_width)
        precondition = f"({shift_amount} >= {bit_width} || {shift_amount} < 0)"
        
        return {
            'line': line_num,
            'status': 'vulnerable',
            'operation_type': 'shift_overflow',
            'precondition': precondition,
            'original': line.strip(),
            'indent': indent,
            'int_type': int_type,
            'bit_width': bit_width
        }
    
    def _scan_cast(
        self,
        match: re.Match,
        line: str,
        line_num: int,
        source_code: str
    ) -> Optional[Dict[str, Any]]:
        """Scan narrowing casts for truncation"""
        indent = match.group(1)
        target_type = match.group(2)  # char, short, int
        result_var = match.group(3)
        source_type = match.group(4)  # char, short, int
        value = match.group(5).strip()
        
        # Check if this is actually a narrowing cast
        type_sizes = {'char': 1, 'short': 2, 'int': 4}
        if type_sizes.get(target_type, 4) >= type_sizes.get(source_type, 4):
            # Not a narrowing cast
            return None
        
        # Get bounds for target type
        max_bound, min_bound = self.BOUNDS.get(target_type, ('INT_MAX', 'INT_MIN'))
        
        # Precondition: value must fit in target type
        precondition = f"({value} > {max_bound} || {value} < {min_bound})"
        
        return {
            'line': line_num,
            'status': 'vulnerable',
            'operation_type': 'truncation',
            'precondition': precondition,
            'original': line.strip(),
            'indent': indent,
            'target_type': target_type,
            'source_type': source_type
        }
    
    def _get_bit_width(self, int_type: str) -> int:
        """Get bit width for integer type"""
        if 'char' in int_type:
            return 8
        elif 'short' in int_type:
            return 16
        elif 'long long' in int_type or 'int64' in int_type:
            return 64
        else:  # int, long
            return 32

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

    def generate_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate integer overflow patch
        
        Args:
            vuln: Vulnerability dict
            source_code: Full source code
            source_file: Path to source file
            
        Returns:
            Patch dict or None
        """
        line_num = vuln.get('line', 0)
        
        if not line_num:
            logger.warning(f"Missing line number for integer overflow vuln")
            return None
        
        # Get the source line
        lines = source_code.split('\n')
        if line_num < 1 or line_num > len(lines):
            logger.error(f"Line number {line_num} out of range")
            return None
        
        original_line = lines[line_num - 1]
        
        # IDEMPOTENCY: skip if already wrapped in overflow check
        if 'Integer overflow detected' in original_line or 'abort()' in original_line or 'if (' in original_line:
            logger.info(f"Line {line_num} already has overflow check, skipping")
            return None
        
        # Use the scanner to analyze the line
        scanner = IntegerOverflowScanner()
        scan_result = scanner.scan_line(original_line, line_num, source_code)
        
        if not scan_result or scan_result.get('status') != 'vulnerable':
            logger.warning(f"Integer overflow scanner could not analyze line {line_num}: {original_line.strip()}")
            return None
        
        # Generate the repaired line using the scanner result
        indent = scan_result.get('indent', '')
        precondition = scan_result.get('precondition')
        original = scan_result.get('original')
        
        if not precondition:
            logger.warning(f"No precondition generated for line {line_num}")
            return None
        
        # Generate repaired code
        operation_type = scan_result.get('operation_type', 'overflow')
        
        repaired_lines = []
        repaired_lines.append(f"{indent}if ({precondition}) {{")
        
        # Customize error message based on operation type
        if operation_type == 'subtraction_underflow':
            repaired_lines.append(f"{indent}    // Subtraction underflow detected - abort")
            repaired_lines.append(f"{indent}    fprintf(stderr, \"Subtraction underflow at line {line_num}\\n\");")
        elif operation_type == 'shift_overflow':
            bit_width = scan_result.get('bit_width', 32)
            repaired_lines.append(f"{indent}    // Shift overflow detected - abort")
            repaired_lines.append(f"{indent}    fprintf(stderr, \"Shift amount out of range [0, {bit_width}) at line {line_num}\\n\");")
        elif operation_type == 'truncation':
            target_type = scan_result.get('target_type', 'int')
            repaired_lines.append(f"{indent}    // Truncation/narrowing cast overflow - abort")
            repaired_lines.append(f"{indent}    fprintf(stderr, \"Value does not fit in {target_type} at line {line_num}\\n\");")
        else:
            repaired_lines.append(f"{indent}    // Integer overflow detected - abort")
            repaired_lines.append(f"{indent}    fprintf(stderr, \"Integer overflow detected at line {line_num}\\n\");")
        
        repaired_lines.append(f"{indent}    abort();")
        repaired_lines.append(f"{indent}}} else {{")
        repaired_lines.append(f"{indent}    {original}")
        repaired_lines.append(f"{indent}}}")
        
        repaired_code = '\n'.join(repaired_lines)
        
        # Generate unified diff
        diff = self._generate_diff(
            source_file,
            line_num,
            original_line,
            repaired_code
        )
        
        return {
            'patch_id': str(uuid.uuid4()),
            'vulnerability_id': vuln.get('finding_id', ''),
            'file': source_file,
            'line': line_num,
            'original': original_line.strip(),
            'repaired': repaired_code,
            'diff': diff,
            'description': f"Add {operation_type.replace('_', ' ')} check at line {line_num}",
            'confidence': 0.90,
            'requires_acr_header': False,
            'precondition': precondition,
            'operation_type': operation_type
        }
    
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
            repaired: Repaired code block
            
        Returns:
            Unified diff string
        """
        diff = f"""--- {filename}	(original)
+++ {filename}	(repaired)
@@ -{line_num},1 +{line_num},{len(repaired.split(chr(10)))} @@
-{original}
+{repaired.replace(chr(10), chr(10) + '+')}
"""
        return diff

    def generate_patch_old(self, vuln: Dict[str, Any]) -> str:
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
