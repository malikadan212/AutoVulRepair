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
            # Pattern: "Null pointer dereference: symbol_name" or "... : symbol_name"
            import re
            match = re.search(r':\s*(\w+)', message)
            if match:
                symbol = match.group(1)
        
        # If still no symbol, try to extract from source code at the line
        if not symbol and line_num:
            lines = source_code.split('\n')
            if 0 < line_num <= len(lines):
                line_text = lines[line_num - 1]
                # Look for pointer dereferences: *ptr, ptr->, ptr[
                match = re.search(r'[\*\->]\s*(\w+)|(\w+)\s*->', line_text)
                if match:
                    symbol = match.group(1) or match.group(2)
                    logger.info(f"Extracted symbol '{symbol}' from source line: {line_text.strip()}")
        
        if not line_num or not symbol:
            logger.warning(f"Missing line number or symbol for null pointer vuln: line={line_num}, symbol={symbol}, desc={vuln.get('description', '')[:100]}")
            return None
        
        # Check preprocessor safety (Section 4 of guidance)
        should_skip, reason = self.preprocessor_checker.should_skip_repair(
            source_code, line_num, context_lines=5
        )
        if should_skip:
            logger.warning(f"Skipping repair at line {line_num}: {reason}")
            return None
        
        # Get the source line
        lines = source_code.split('\n')
        if line_num < 1 or line_num > len(lines):
            logger.error(f"Line number {line_num} out of range")
            return None
        
        original_line = lines[line_num - 1]
        
        # Check if already repaired (idempotency - Section 7)
        if 'null_check' in original_line:
            logger.info(f"Line {line_num} already has null_check, skipping")
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
            'vulnerability_id': vuln.get('id', ''),
            'file': source_file,
            'line': line_num,
            'symbol': symbol,
            'original': original_line,
            'repaired': repaired_line,
            'diff': diff,
            'description': f"Insert null check for '{symbol}' at line {line_num}",
            'confidence': 0.95,
            'is_lvalue': is_lvalue,
            'error_handler': error_handler,
            'error_handler_code': error_handler_info['code'],
            'error_handler_confidence': error_handler_info['confidence'],
            'requires_acr_header': True,
            'acr_header_content': self.acr_header
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
        Insert null_check macro into line
        
        Args:
            line: Original line
            symbol: Variable to check
            is_lvalue: Whether this is lvalue context
            
        Returns:
            Modified line with null_check
        """
        macro = 'null_check_lval' if is_lvalue else 'null_check'
        
        # Simple pattern: wrap the symbol with the macro
        # This is a simplified version - production would use AST
        pattern = rf'\b{re.escape(symbol)}\b'
        replacement = f'{macro}({symbol})'
        
        # Only replace the first occurrence to be safe
        repaired = re.sub(pattern, replacement, line, count=1)
        
        return repaired
    
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
