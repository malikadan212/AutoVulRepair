"""
Integer Overflow Repair Module (Stage 1)
Based on: IntRepair - Informed Repairing of Integer Overflows
(Muntean, Monperrus, Sun, Grossklags, Eckert - IEEE TSE 2019)

Implements the 8-step repair generation algorithm for CWE-190/CWE-191
"""
import logging
import re
import uuid
import math
from typing import Dict, Any, Optional, Tuple, List
from enum import Enum

logger = logging.getLogger(__name__)


class OperatorType(Enum):
    """Arithmetic operator types"""
    ADDITION = "+"
    MULTIPLICATION = "*"
    UNKNOWN = "unknown"


class OperandType(Enum):
    """Operand classification for decision tree"""
    CONSTANT = "constant"
    VARIABLE = "variable"
    VARIABLE_WITH_SIDE_EFFECTS = "variable_with_side_effects"
    UNKNOWN = "unknown"


class IntegerType(Enum):
    """Supported integer precisions"""
    CHAR = ("char", 127, -128, "CHAR_MAX", "CHAR_MIN")
    SHORT = ("short", 32767, -32768, "SHRT_MAX", "SHRT_MIN")
    INT = ("int", 2147483647, -2147483648, "INT_MAX", "INT_MIN")
    LONG_LONG = ("long long", 9223372036854775807, -9223372036854775808, "LLONG_MAX", "LLONG_MIN")
    INT64_T = ("int64_t", 9223372036854775807, -9223372036854775808, "LLONG_MAX", "LLONG_MIN")
    UNSIGNED_INT = ("unsigned int", 4294967295, 0, "UINT_MAX", "0")
    UNSIGNED_LONG = ("unsigned long", 4294967295, 0, "ULONG_MAX", "0")
    
    def __init__(self, type_name: str, max_val: int, min_val: int, max_const: str, min_const: str):
        self.type_name = type_name
        self.max_val = max_val
        self.min_val = min_val
        self.max_const = max_const
        self.min_const = min_const


class IntegerOverflowRepair:
    """
    Stage 1 repair module for integer overflow vulnerabilities (CWE-190/CWE-191)
    
    Implements the IntRepair 8-step algorithm:
    1. Determine integer upper bound
    2. Generate SMT constraint system (simplified for Stage 1)
    3. Select constraint values
    4. Recompute bound-checking constraints
    5. Determine fault type
    6. Select repair pattern (decision tree)
    7. Determine new SMT constraint system
    8. Generate code repair
    """
    
    def __init__(self):
        """Initialize the integer overflow repair module"""
        self.logger = logging.getLogger(__name__)
    
    def generate_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate integer overflow repair patch
        
        Args:
            vuln: Vulnerability dict with keys: id, cwe, message, file, line, etc.
            source_code: Full source code
            source_file: Path to source file
            
        Returns:
            Patch dict or None if repair cannot be generated
        """
        try:
            line_num = vuln.get('line', 0)
            if line_num == 0:
                self.logger.warning("No line number in vulnerability")
                return None
            
            # Extract the vulnerable line
            lines = source_code.split('\n')
            if line_num > len(lines):
                self.logger.warning(f"Line {line_num} exceeds file length {len(lines)}")
                return None
            
            original_line = lines[line_num - 1]
            
            # STEP 1: Determine integer upper bound (multi-precision detection)
            integer_type = self._detect_integer_type(original_line, vuln, source_code, line_num)
            if not integer_type:
                self.logger.warning(f"Could not detect integer type for line {line_num}")
                return None
            
            self.logger.info(f"Detected integer type: {integer_type.type_name} "
                           f"(MAX={integer_type.max_const}, MIN={integer_type.min_const})")
            
            # STEP 2-3: Parse the vulnerable statement and extract operands
            parsed = self._parse_overflow_statement(original_line, vuln)
            if not parsed:
                self.logger.warning(f"Could not parse overflow statement: {original_line}")
                return None
            
            # STEP 4-5: Determine fault type and validate repairability
            operator = parsed['operator']
            lhs_operand = parsed['lhs_operand']
            rhs_operand = parsed['rhs_operand']
            result_var = parsed['result_var']
            
            # Classify operands for decision tree
            lhs_type = self._classify_operand(lhs_operand)
            rhs_type = self._classify_operand(rhs_operand)
            
            self.logger.info(f"Operator: {operator.value}, LHS: {lhs_type.value}, RHS: {rhs_type.value}")
            
            # STEP 6: Select repair pattern using decision tree
            repair_pattern = self._select_repair_pattern(
                operator, lhs_operand, rhs_operand, lhs_type, rhs_type, integer_type
            )
            
            if not repair_pattern:
                self.logger.warning("No suitable repair pattern found")
                return None
            
            # STEP 7-8: Generate the repaired code
            repaired_line = self._generate_repair_code(
                original_line, repair_pattern, integer_type, result_var,
                lhs_operand, rhs_operand, operator
            )
            
            if not repaired_line:
                self.logger.warning("Failed to generate repair code")
                return None
            
            # Generate unified diff
            diff = self._generate_diff(source_file, line_num, original_line, repaired_line)
            
            # Create patch dict
            patch = {
                'patch_id': str(uuid.uuid4()),
                'vulnerability_id': vuln.get('id', ''),
                'file': source_file,
                'line': line_num,
                'original': original_line,
                'repaired': repaired_line,
                'diff': diff,
                'description': f"Insert overflow check for {operator.value} operation at line {line_num}",
                'confidence': 0.90,
                'integer_type': integer_type.type_name,
                'operator': operator.value,
                'pattern': repair_pattern['name'],
                'requires_limits_h': True
            }
            
            self.logger.info(f"Generated integer overflow patch for line {line_num}")
            return patch
            
        except Exception as e:
            self.logger.error(f"Error generating integer overflow patch: {e}", exc_info=True)
            return None

    
    def _detect_integer_type(
        self,
        line: str,
        vuln: Dict[str, Any],
        source_code: str,
        line_num: int
    ) -> Optional[IntegerType]:
        """STEP 1: Determine the integer upper bound value (multi-precision detection)"""
        type_patterns = [
            (r'\bint64_t\b', IntegerType.INT64_T),
            (r'\blong\s+long\b', IntegerType.LONG_LONG),
            (r'\bunsigned\s+int\b', IntegerType.UNSIGNED_INT),
            (r'\bunsigned\s+long\b', IntegerType.UNSIGNED_LONG),
            (r'\bshort\b', IntegerType.SHORT),
            (r'\bchar\b', IntegerType.CHAR),
            (r'\bint\b', IntegerType.INT),
        ]
        
        for pattern, int_type in type_patterns:
            if re.search(pattern, line):
                return int_type
        
        var_match = re.search(r'(\w+)\s*=', line)
        if var_match:
            var_name = var_match.group(1)
            lines = source_code.split('\n')
            for i in range(line_num - 2, max(0, line_num - 50), -1):
                decl_line = lines[i]
                for pattern, int_type in type_patterns:
                    if re.search(pattern, decl_line) and re.search(rf'\b{re.escape(var_name)}\b', decl_line):
                        return int_type
        
        return IntegerType.INT
    
    def _parse_overflow_statement(
        self,
        line: str,
        vuln: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """STEP 2-3: Parse the vulnerable statement into AST components"""
        line = re.sub(r'//.*$', '', line).strip()
        line = re.sub(r'/\*.*?\*/', '', line).strip()
        
        patterns = [
            r'(?:\w+\s+)?(\w+)\s*=\s*([^+*]+)\s*([+*])\s*([^;]+)',
            r'(\w+)\s*=\s*([^+*]+)\s*([+*])\s*([^;]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                result_var = match.group(1).strip()
                lhs_operand = match.group(2).strip()
                operator_str = match.group(3).strip()
                rhs_operand = match.group(4).strip().rstrip(';').strip()
                
                operator = OperatorType.ADDITION if operator_str == '+' else OperatorType.MULTIPLICATION
                
                return {
                    'result_var': result_var,
                    'lhs_operand': lhs_operand,
                    'rhs_operand': rhs_operand,
                    'operator': operator
                }
        
        return None
    
    def _classify_operand(self, operand: str) -> OperandType:
        """STEP 3: Classify operand for decision tree"""
        operand = operand.strip()
        
        if re.match(r'^-?\d+[ULul]*$', operand):
            return OperandType.CONSTANT
        
        side_effect_patterns = [r'\+\+', r'--', r'\(', r'\[', r'\*']
        
        for pattern in side_effect_patterns:
            if re.search(pattern, operand):
                return OperandType.VARIABLE_WITH_SIDE_EFFECTS
        
        if re.match(r'^\w+$', operand):
            return OperandType.VARIABLE
        
        return OperandType.UNKNOWN
    
    def _select_repair_pattern(
        self,
        operator: OperatorType,
        lhs_operand: str,
        rhs_operand: str,
        lhs_type: OperandType,
        rhs_type: OperandType,
        integer_type: IntegerType
    ) -> Optional[Dict[str, Any]]:
        """STEP 6: Select repair pattern using decision tree"""
        if (operator == OperatorType.MULTIPLICATION and
            lhs_operand == rhs_operand and
            lhs_type == OperandType.VARIABLE):
            return {
                'name': 'self_multiplication',
                'criteria': 'C15_C19',
                'template': 'sqrt_check'
            }
        
        if operator == OperatorType.MULTIPLICATION:
            if lhs_type == OperandType.VARIABLE and rhs_type == OperandType.CONSTANT:
                return {
                    'name': 'multiply_var_const',
                    'criteria': 'C15_C17',
                    'template': 'division_check',
                    'var': lhs_operand,
                    'const': rhs_operand
                }
            elif lhs_type == OperandType.CONSTANT and rhs_type == OperandType.VARIABLE:
                return {
                    'name': 'multiply_const_var',
                    'criteria': 'C15_C17',
                    'template': 'division_check',
                    'var': rhs_operand,
                    'const': lhs_operand
                }
        
        if operator == OperatorType.ADDITION:
            if lhs_type == OperandType.VARIABLE and rhs_type == OperandType.CONSTANT:
                return {
                    'name': 'add_var_const',
                    'criteria': 'C3_C11',
                    'template': 'subtraction_check',
                    'var': lhs_operand,
                    'const': rhs_operand
                }
            elif lhs_type == OperandType.CONSTANT and rhs_type == OperandType.VARIABLE:
                return {
                    'name': 'add_const_var',
                    'criteria': 'C3_C11',
                    'template': 'subtraction_check',
                    'var': rhs_operand,
                    'const': lhs_operand
                }
            elif lhs_type == OperandType.VARIABLE and rhs_type == OperandType.VARIABLE:
                return {
                    'name': 'add_var_var',
                    'criteria': 'C3_C7',
                    'template': 'subtraction_check_vars',
                    'var1': lhs_operand,
                    'var2': rhs_operand
                }
        
        return None
    
    def _generate_repair_code(
        self,
        original_line: str,
        pattern: Dict[str, Any],
        integer_type: IntegerType,
        result_var: str,
        lhs_operand: str,
        rhs_operand: str,
        operator: OperatorType
    ) -> Optional[str]:
        """STEP 8: Generate the repaired code"""
        indent = self._get_indentation(original_line)
        max_const = integer_type.max_const
        min_const = integer_type.min_const
        
        error_handler = f'fprintf(stderr, "Integer overflow detected at {result_var}\\n"); abort();'
        
        template_name = pattern['template']
        
        if template_name == 'sqrt_check':
            var = lhs_operand
            sqrt_max = int(math.sqrt(integer_type.max_val))
            guard = (f"if (({var} > 0 && {var} >= {sqrt_max}) || "
                    f"({var} < 0 && {var} <= -{sqrt_max}))")
            
        elif template_name == 'division_check':
            var = pattern['var']
            const = pattern['const']
            const_val = int(const) if const.lstrip('-').isdigit() else None
            if const_val and const_val < 0:
                guard = (f"if (({var} > 0 && {var} > {min_const} / ({const})) || "
                        f"({var} < 0 && {var} < {max_const} / ({const})))")
            else:
                guard = f"if ({var} > {max_const} / ({const}) || {var} < {min_const} / ({const}))"
        
        elif template_name == 'subtraction_check':
            var = pattern['var']
            const = pattern['const']
            guard = f"if ({var} > {max_const} - ({const}) || {var} < {min_const} - ({const}))"
        
        elif template_name == 'subtraction_check_vars':
            var1 = pattern['var1']
            var2 = pattern['var2']
            guard = f"if ({var1} > {max_const} - {var2} || {var1} < {min_const} - {var2})"
        
        else:
            return None
        
        repaired = f"{indent}{guard} {{\n"
        repaired += f"{indent}    {error_handler}\n"
        repaired += f"{indent}}} else {{\n"
        repaired += f"{indent}    {original_line.strip()}\n"
        repaired += f"{indent}}}"
        
        return repaired
    
    def _get_indentation(self, line: str) -> str:
        """Extract leading whitespace from line"""
        match = re.match(r'^(\s*)', line)
        return match.group(1) if match else ''
    
    def _generate_diff(
        self,
        filename: str,
        line_num: int,
        original: str,
        repaired: str
    ) -> str:
        """Generate unified diff"""
        diff = f"""--- {filename}	(original)
+++ {filename}	(repaired)
@@ -{line_num},1 +{line_num},5 @@
-{original}
+{repaired}
"""
        return diff
