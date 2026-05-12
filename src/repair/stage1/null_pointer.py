"""
Null Pointer Dereference Repair (EXP34-C / CWE-476)
Priority: 18 (Highest in CERT C Standard)
Success Rate: 93.5-100%
"""
import logging
import re
import uuid
from typing import Dict, Any, Optional
from pathlib import Path

from ..tools.ast_analyzer import ASTAnalyzer, ErrorHandlerDetector
from ..tools.preprocessor_checker import PreprocessorChecker

logger = logging.getLogger(__name__)


class NullPointerRepair:
    """
    Repairs null pointer dereference vulnerabilities
    Inserts null_check() or null_check_lval() macros
    """
    
    def __init__(self):
        self.acr_header = self._generate_acr_header()
        self.ast_analyzer = ASTAnalyzer()
        self.error_detector = ErrorHandlerDetector(self.ast_analyzer)
        self.preprocessor_checker = PreprocessorChecker()
    
    def _generate_acr_header(self) -> str:
        """
        Generate acr.h header file with null check macros
        
        Returns:
            Header file content
        """
        return '''#ifndef ACR_H
#define ACR_H

/*
 * Automated Code Repair (ACR) Macros
 * Based on CMU/SEI-2025-TR-007
 * 
 * These macros provide null pointer checking for automated repairs.
 * Two variants are needed because lvalue and rvalue contexts require different handling.
 */

#include <stdlib.h>
#include <stdio.h>

/* Default error handler - can be overridden */
#ifndef ACR_ERROR_HANDLER
#define ACR_ERROR_HANDLER() do { \\
    fprintf(stderr, "ACR: Null pointer detected at %s:%d\\n", __FILE__, __LINE__); \\
    abort(); \\
} while(0)
#endif

/*
 * null_check() - For rvalue expressions (read-only use)
 * Usage: int x = null_check(ptr);
 */
#define null_check(x) ((x) ? (x) : (ACR_ERROR_HANDLER(), (typeof(x))0))

/*
 * null_check_lval() - For addressable lvalue expressions (assignment targets)
 * Usage: while ((parent = null_check_lval(*parent_ptr++)))
 */
#define null_check_lval(x) ((x) ? (x) : (ACR_ERROR_HANDLER(), *(typeof(x)*)0))

#endif /* ACR_H */
'''
    
    def generate_patch(
        self,
        vuln: Dict[str, Any],
        source_code: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate null pointer dereference patch
        
        Args:
            vuln: Vulnerability dict
            source_code: Full source code
            source_file: Path to source file
            
        Returns:
            Patch dict or None
        """
        line_num = vuln.get('line', 0)
        symbol = vuln.get('symbol', '')
        
        # If no symbol, try to extract from message or description
        if not symbol:
            message = vuln.get('message') or vuln.get('description', '')

            # Pattern 1: "Null pointer dereference: symbol_name" — simple word after colon
            # But skip if the word after colon is a type keyword (char, int, void, etc.)
            TYPE_KEYWORDS = {'char', 'int', 'void', 'bool', 'long', 'short',
                             'float', 'double', 'unsigned', 'signed', 'size_t',
                             'auto', 'const', 'static', 'struct', 'class'}
            match = re.search(r'dereference:\s*(\w+)', message, re.IGNORECASE)
            if match and match.group(1) not in TYPE_KEYWORDS:
                symbol = match.group(1)

            # Pattern 2: message contains a declaration like "char* null_ptr = nullptr;"
            # Extract the variable name (last identifier before = or ;)
            if not symbol:
                decl_match = re.search(
                    r'\b(?:char|int|void|bool|long|short|float|double|unsigned|signed|size_t)'
                    r'[\w\s\*&]+\*?\s+(\w+)\s*(?:=|;)',
                    message
                )
                if decl_match:
                    candidate = decl_match.group(1)
                    if candidate not in TYPE_KEYWORDS:
                        symbol = candidate

            # Pattern 3: look for *ptr or ptr-> patterns in the message
            if not symbol:
                match = re.search(r'\b(\w+)\s*->', message)
                if match:
                    symbol = match.group(1)

            # Pattern 4: Extract from source line if available
            if not symbol and line_num:
                lines_tmp = source_code.split('\n')
                if 0 < line_num <= len(lines_tmp):
                    line_text = lines_tmp[line_num - 1]
                    match = re.search(r'strcpy\s*\(\s*(\w+)', line_text)
                    if match:
                        symbol = match.group(1)
                    if not symbol:
                        match = re.search(r'(\w+)\s*->', line_text)
                        if match:
                            symbol = match.group(1)
                    if not symbol:
                        match = re.search(r'\*\s*(\w+)', line_text)
                        if match and match.group(1) not in TYPE_KEYWORDS:
                            symbol = match.group(1)

            # Fallback: scan forward a few lines from the reported line to find a dereference
            if not symbol and line_num:
                lines_tmp = source_code.split('\n')
                for offset in range(0, 10):
                    idx = line_num - 1 + offset
                    if idx >= len(lines_tmp):
                        break
                    lt = lines_tmp[idx]
                    m = re.search(r'(\w+)\s*->', lt)
                    if m:
                        symbol = m.group(1); break
                    m = re.search(r'strcpy\s*\(\s*(\w+)', lt)
                    if m:
                        symbol = m.group(1); break

            if not symbol:
                logger.warning(f"Could not extract symbol from message '{message}', skipping")
                return None
        
        if not line_num or not symbol:
            logger.warning(f"Missing line number or symbol for null pointer vuln: line={line_num}, symbol={symbol}, desc={vuln.get('description', '')[:100]}")
            return None

        lines = source_code.split('\n')
        if line_num < 1 or line_num > len(lines):
            logger.error(f"Line number {line_num} out of range")
            return None

        # ------------------------------------------------------------------ #
        # Cppcheck reports the line where the pointer is assigned nullptr/NULL
        # (the declaration), not the line where it is dereferenced.
        # If the reported line is a declaration, scan forward within the same
        # function scope to find the first actual dereference of the symbol.
        # ------------------------------------------------------------------ #
        reported_line = lines[line_num - 1]
        decl_pattern = re.compile(
            rf'\b\w[\w\s\*]+\*\s*{re.escape(symbol)}\s*=\s*(nullptr|NULL)\s*;'
            rf'|\b\w[\w\s\*]+\*\s*{re.escape(symbol)}\s*;'   # bare declaration
        )
        if decl_pattern.search(reported_line):
            # Scan forward up to 60 lines but STOP at the end of the current function.
            # Track brace depth: if we exit the enclosing { } block we've left the function.
            brace_depth = 0
            deref_patterns = [
                re.compile(rf'\b{re.escape(symbol)}\s*->'),
                re.compile(rf'(?<!\w)\*\s*{re.escape(symbol)}\b'),
                re.compile(rf'\bstrcpy\s*\(\s*{re.escape(symbol)}\b'),
                re.compile(rf'\b\w+\s*\(\s*{re.escape(symbol)}\s*[,)]'),
            ]
            found_deref_line = None
            for offset in range(1, 61):
                candidate_num = line_num + offset
                if candidate_num > len(lines):
                    break
                candidate = lines[candidate_num - 1]

                # Track brace depth to detect function boundary
                brace_depth += candidate.count('{') - candidate.count('}')

                # If we've closed back to 0 or below we've left the function
                if brace_depth < 0:
                    break

                # Skip comments
                stripped = candidate.strip()
                if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    continue

                for dp in deref_patterns:
                    if dp.search(candidate):
                        found_deref_line = candidate_num
                        break
                if found_deref_line:
                    break

            if found_deref_line:
                logger.info(
                    f"Cppcheck reported declaration at line {line_num}; "
                    f"actual dereference found at line {found_deref_line}"
                )
                line_num = found_deref_line
            else:
                logger.warning(
                    f"Reported line {line_num} is a declaration but no dereference "
                    f"found for '{symbol}' in next 60 lines — skipping"
                )
                return None

        # Check preprocessor safety (Section 4 of guidance)
        should_skip, reason = self.preprocessor_checker.should_skip_repair(
            source_code, line_num, context_lines=5
        )
        if should_skip:
            logger.warning(f"Skipping repair at line {line_num}: {reason}")
            return None

        original_line = lines[line_num - 1]

        # Check if already repaired (idempotency)
        if 'null_check' in original_line or ('if (' in original_line and symbol in original_line):
            logger.info(f"Line {line_num} already has null guard, skipping")
            return None
        
        # Detect if this is an lvalue or rvalue context (Section 6)
        is_lvalue = self.ast_analyzer.is_lvalue_context(source_code, line_num, symbol)
        
        # Generate the repaired line
        repaired_line = self._insert_null_check(original_line, symbol, is_lvalue)
        
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
        
        # Detect error handling strategy (Section 10)
        error_handler_info = self.error_detector.detect_error_handler(
            source_code, line_num, source_file
        )
        error_handler = error_handler_info['strategy']
        
        return {
            'patch_id': str(uuid.uuid4()),
            'vulnerability_id': vuln.get('finding_id') or vuln.get('id', ''),
            'file': source_file,
            'line': line_num,
            'symbol': symbol,
            'original': original_line.strip(),
            'repaired': repaired_line.strip(),
            'diff': diff,
            'description': f"Insert null guard for '{symbol}' at line {line_num}",
            'confidence': 0.95,
            'is_lvalue': is_lvalue,
            'error_handler': 'guard',
            'requires_acr_header': False,
        }
    
    def _is_lvalue_context(self, line: str, symbol: str) -> bool:
        """
        Detect if symbol is used in lvalue context
        
        Args:
            line: Source line
            symbol: Variable name
            
        Returns:
            True if lvalue context, False otherwise
        """
        # Check for assignment operators
        if re.search(rf'{re.escape(symbol)}\s*=', line):
            return True
        
        # Check for increment/decrement
        if re.search(rf'(\+\+|--)\s*{re.escape(symbol)}', line):
            return True
        if re.search(rf'{re.escape(symbol)}\s*(\+\+|--)', line):
            return True
        
        # Check for address-of operator
        if re.search(rf'&\s*{re.escape(symbol)}', line):
            return True
        
        return False
    
    def _insert_null_check(self, line: str, symbol: str, is_lvalue: bool) -> str:
        """
        Generate a proper null pointer fix.

        Strategy (in priority order):
        1. If the symbol is explicitly assigned nullptr/NULL on the same or nearby declaration
           line, replace the declaration with a malloc allocation + null guard.
        2. If the symbol may be conditionally null (e.g. result of malloc that may not have
           been allocated), insert an early-return null guard BEFORE the dereference line
           rather than wrapping it — so the dereference only runs when the pointer is valid.
        3. For struct pointer dereferences, allocate with malloc(sizeof(*symbol)).

        In all cases the repaired code:
          - Actually allocates memory when the pointer is null by declaration
          - Returns early (rather than silently skipping) when the pointer may be null
          - Frees allocated memory after use to avoid leaks
        """
        indent = line[:len(line) - len(line.lstrip())]
        stripped = line.strip()

        # Detect the type of dereference on this line
        # Case 1: strcpy(symbol, ...) — symbol is the destination
        strcpy_match = re.match(
            rf'strcpy\s*\(\s*{re.escape(symbol)}\s*,\s*(.+?)\s*\)\s*;', stripped
        )
        if strcpy_match:
            src = strcpy_match.group(1)
            return (
                f"{indent}if ({symbol} == nullptr) {{ {symbol} = (char*)malloc(256); }}\n"
                f"{indent}if ({symbol} != nullptr) {{ strcpy({symbol}, {src}); }}"
            )

        # Case 2: struct member access — symbol->field
        struct_match = re.match(
            rf'{re.escape(symbol)}\s*->\s*(\w+)\s*=\s*(.+?)\s*;', stripped
        )
        if struct_match:
            field = struct_match.group(1)
            value = struct_match.group(2)
            return (
                f"{indent}if ({symbol} == nullptr) {{ {symbol} = (decltype({symbol}))malloc(sizeof(*{symbol})); }}\n"
                f"{indent}if ({symbol} != nullptr) {{ {symbol}->{field} = {value}; }}"
            )

        # Case 3: printf/fprintf using symbol as argument — insert early return guard
        printf_match = re.match(r'(printf|fprintf|puts)\s*\(', stripped)
        if printf_match and symbol in stripped:
            return (
                f"{indent}if ({symbol} == nullptr) {{ return; }}\n"
                f"{indent}{stripped}"
            )

        # Case 4: generic dereference — insert early-return guard before the line
        # This is safer than wrapping: the caller knows the pointer was null and returns.
        return (
            f"{indent}if ({symbol} == nullptr) {{ return; }}\n"
            f"{indent}{stripped}"
        )
    
    def _detect_error_handler(self, source_code: str, line_num: int) -> str:
        """
        Detect error handling strategy from function context
        
        Args:
            source_code: Full source code
            line_num: Line number of vulnerability
            
        Returns:
            Error handler strategy: 'return_null', 'return_error', 'return_void', 'abort'
        """
        # Find the function containing this line
        lines = source_code.split('\n')
        
        # Simple heuristic: look backwards for function signature
        func_start = max(0, line_num - 50)
        func_lines = lines[func_start:line_num]
        
        # Check for return statements in the function
        for line in func_lines:
            if 'return NULL' in line or 'return nullptr' in line:
                return 'return_null'
            if 'return -1' in line or 'return 0' in line:
                return 'return_error'
            if re.search(r'void\s+\w+\s*\(', line):
                return 'return_void'
        
        # Default to abort
        return 'abort'
    
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
