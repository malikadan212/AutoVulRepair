"""
AST-Based Code Analysis Tools
Uses clang Python bindings for proper C/C++ AST manipulation
Based on CMU/SEI-2025-TR-007 Section 9
"""
import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import clang bindings
try:
    import clang.cindex as clang
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False
    logger.warning("clang Python bindings not available. Install with: pip install libclang")


class ASTAnalyzer:
    """
    AST-based code analyzer for C/C++
    Provides semantic analysis for repair operations
    """
    
    def __init__(self):
        self.clang_available = CLANG_AVAILABLE
        if CLANG_AVAILABLE:
            self.index = clang.Index.create()
    
    def parse_file(self, file_path: str, args: List[str] = None) -> Optional[Any]:
        """
        Parse C/C++ file into AST
        
        Args:
            file_path: Path to source file
            args: Compiler arguments (e.g., ['-std=c++11'])
            
        Returns:
            TranslationUnit or None
        """
        if not self.clang_available:
            logger.warning("Clang not available, cannot parse AST")
            return None
        
        try:
            args = args or []
            tu = self.index.parse(file_path, args=args)
            
            if tu.diagnostics:
                for diag in tu.diagnostics:
                    if diag.severity >= clang.Diagnostic.Error:
                        logger.error(f"Parse error: {diag.spelling}")
            
            return tu
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return None
    
    def find_function_at_line(self, tu: Any, line: int) -> Optional[Any]:
        """
        Find function node containing the given line
        
        Args:
            tu: TranslationUnit
            line: Line number
            
        Returns:
            Function cursor or None
        """
        if not self.clang_available or not tu:
            return None
        
        def visit_node(node):
            if node.kind == clang.CursorKind.FUNCTION_DECL:
                if node.extent.start.line <= line <= node.extent.end.line:
                    return node
            
            for child in node.get_children():
                result = visit_node(child)
                if result:
                    return result
            return None
        
        return visit_node(tu.cursor)
    
    def get_function_return_type(self, func_cursor: Any) -> Optional[str]:
        """
        Get return type of function
        
        Args:
            func_cursor: Function cursor
            
        Returns:
            Return type string or None
        """
        if not self.clang_available or not func_cursor:
            return None
        
        try:
            return func_cursor.result_type.spelling
        except:
            return None
    
    def find_return_statements(self, func_cursor: Any) -> List[str]:
        """
        Find all return statements in function
        
        Args:
            func_cursor: Function cursor
            
        Returns:
            List of return statement strings
        """
        if not self.clang_available or not func_cursor:
            return []
        
        returns = []
        
        def visit_node(node):
            if node.kind == clang.CursorKind.RETURN_STMT:
                # Get the return value
                tokens = list(node.get_tokens())
                if len(tokens) > 1:  # More than just 'return'
                    return_value = ' '.join(t.spelling for t in tokens[1:])
                    returns.append(return_value.rstrip(';'))
            
            for child in node.get_children():
                visit_node(child)
        
        visit_node(func_cursor)
        return returns
    
    def is_lvalue_context(self, source_code: str, line: int, symbol: str) -> bool:
        """
        Detect if symbol is used in lvalue context
        Fallback to regex if AST not available
        
        Args:
            source_code: Full source code
            line: Line number
            symbol: Variable name
            
        Returns:
            True if lvalue context
        """
        lines = source_code.split('\n')
        if line < 1 or line > len(lines):
            return False
        
        line_text = lines[line - 1]
        
        # Check for assignment operators
        if re.search(rf'{re.escape(symbol)}\s*[+\-*/&|^%]?=', line_text):
            return True
        
        # Check for increment/decrement
        if re.search(rf'(\+\+|--)\s*{re.escape(symbol)}', line_text):
            return True
        if re.search(rf'{re.escape(symbol)}\s*(\+\+|--)', line_text):
            return True
        
        # Check for address-of operator
        if re.search(rf'&\s*{re.escape(symbol)}', line_text):
            return True
        
        return False


class ErrorHandlerDetector:
    """
    Detects error handling strategy from function context
    Based on CMU/SEI-2025-TR-007 Section 10
    """
    
    def __init__(self, ast_analyzer: ASTAnalyzer = None):
        self.ast = ast_analyzer or ASTAnalyzer()
    
    def detect_error_handler(
        self,
        source_code: str,
        line_num: int,
        file_path: str = None
    ) -> Dict[str, Any]:
        """
        Detect error handling strategy for function containing line_num
        
        Args:
            source_code: Full source code
            line_num: Line number of vulnerability
            file_path: Path to source file (for AST parsing)
            
        Returns:
            Dict with:
            - strategy: 'return_null', 'return_error', 'return_void', 'abort', 'custom'
            - code: Error handler code to insert
            - confidence: float (0.0-1.0)
        """
        # Try AST-based detection first
        if file_path and self.ast.clang_available:
            result = self._detect_with_ast(file_path, line_num)
            if result:
                return result
        
        # Fallback to heuristic detection
        return self._detect_with_heuristics(source_code, line_num)
    
    def _detect_with_ast(self, file_path: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        Detect error handler using AST
        
        Args:
            file_path: Path to source file
            line_num: Line number
            
        Returns:
            Error handler dict or None
        """
        tu = self.ast.parse_file(file_path)
        if not tu:
            return None
        
        func = self.ast.find_function_at_line(tu, line_num)
        if not func:
            return None
        
        return_type = self.ast.get_function_return_type(func)
        return_stmts = self.ast.find_return_statements(func)
        
        return self._analyze_return_pattern(return_type, return_stmts)
    
    def _detect_with_heuristics(self, source_code: str, line_num: int) -> Dict[str, Any]:
        """
        Detect error handler using heuristics
        
        Args:
            source_code: Full source code
            line_num: Line number
            
        Returns:
            Error handler dict
        """
        lines = source_code.split('\n')
        
        # Find function boundaries (simple heuristic)
        func_start = max(0, line_num - 100)
        func_end = min(len(lines), line_num + 50)
        func_lines = lines[func_start:func_end]
        
        # Look for function signature
        return_type = None
        for i, line in enumerate(func_lines):
            if '{' in line and '(' in line:
                # Try to extract return type
                match = re.search(r'^\s*([\w\s\*]+)\s+\w+\s*\(', line)
                if match:
                    return_type = match.group(1).strip()
                    break
        
        # Collect return statements
        return_stmts = []
        for line in func_lines:
            if 'return' in line:
                match = re.search(r'return\s+([^;]+);', line)
                if match:
                    return_stmts.append(match.group(1).strip())
        
        return self._analyze_return_pattern(return_type, return_stmts)
    
    def _analyze_return_pattern(
        self,
        return_type: Optional[str],
        return_stmts: List[str]
    ) -> Dict[str, Any]:
        """
        Analyze return type and statements to determine error handler
        
        Args:
            return_type: Function return type
            return_stmts: List of return statement values
            
        Returns:
            Error handler dict
        """
        # Check for void return
        if return_type and 'void' in return_type:
            return {
                'strategy': 'return_void',
                'code': 'return;',
                'confidence': 0.95
            }
        
        # Check for pointer return
        if return_type and '*' in return_type:
            if any('NULL' in stmt or 'nullptr' in stmt for stmt in return_stmts):
                return {
                    'strategy': 'return_null',
                    'code': 'return NULL;',
                    'confidence': 0.90
                }
        
        # Check for integer error returns
        if return_type and any(t in return_type for t in ['int', 'long', 'short', 'ssize_t']):
            # Look for negative error values
            for stmt in return_stmts:
                if '-1' in stmt or stmt.startswith('-'):
                    return {
                        'strategy': 'return_error',
                        'code': f'return {stmt};',
                        'confidence': 0.85
                    }
        
        # Check for custom error functions
        for stmt in return_stmts:
            if any(func in stmt for func in ['die(', 'error(', 'fatal(', 'err(', 'panic(']):
                return {
                    'strategy': 'custom',
                    'code': stmt + ';',
                    'confidence': 0.80
                }
        
        # Default to abort
        return {
            'strategy': 'abort',
            'code': 'abort();',
            'confidence': 0.50
        }


# Convenience function
def create_ast_analyzer() -> ASTAnalyzer:
    """Create AST analyzer instance"""
    return ASTAnalyzer()


def create_error_detector() -> ErrorHandlerDetector:
    """Create error handler detector instance"""
    return ErrorHandlerDetector()
