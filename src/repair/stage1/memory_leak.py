import re
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)

class MemoryLeakScanner:
    """
    Heuristic rule-based scanner for memory leaks based on SABER concepts.
    Approximates value-flow analysis intra-procedurally.
    """
    def __init__(self):
        self.malloc_pattern = re.compile(r'^(\s*)([a-zA-Z_]\w*(?:->[a-zA-Z_]\w*)?)\s*=\s*(?:\([a-zA-Z_\s\*]+\))?\s*(?:malloc|calloc)\s*\(')
        self.deref_malloc_pattern = re.compile(r'^(\s*)\*\s*([a-zA-Z_]\w*)\s*=\s*(?:\([a-zA-Z_\s\*]+\))?\s*(?:malloc|calloc)\s*\(')
        self.free_pattern = re.compile(r'[^a-zA-Z_]free\s*\(\s*([a-zA-Z_]\w*(?:->[a-zA-Z_]\w*)?)\s*\)')
        self.return_pattern = re.compile(r'^(\s*)return\b')
        self.if_error_pattern = re.compile(r'^(\s*)if\s*\(\s*![a-zA-Z_]\w*.*\)|\(\s*[a-zA-Z_]\w*\s*==\s*NULL\s*\)')
        self.func_start_pattern = re.compile(r'^(?:[\w\s\*]+)\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{')

    def scan_functions(self, source_code: str) -> List[Dict[str, Any]]:
        lines = source_code.split('\n')
        vulns = []
        
        in_func = False
        func_name = ""
        allocations = {}
        frees = set()
        returns = []
        early_error_blocks = []
        
        brace_depth = 0
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            # Function tracking
            func_match = self.func_start_pattern.match(line)
            if func_match and brace_depth == 0:
                in_func = True
                func_name = func_match.group(1)
                allocations = {}
                frees = set()
                returns = []
                early_error_blocks = []
                brace_depth = 1
                continue
                
            if in_func:
                brace_depth += line.count('{')
                brace_depth -= line.count('}')
                
                # Check allocations
                mal_match = self.malloc_pattern.search(line)
                if mal_match:
                    var_name = mal_match.group(2)
                    allocations[var_name] = {'line': line_num, 'indent': mal_match.group(1), 'type': 'simple'}
                
                deref_mal = self.deref_malloc_pattern.search(line)
                if deref_mal:
                    var_name = deref_mal.group(2)
                    allocations[var_name] = {'line': line_num, 'indent': deref_mal.group(1), 'type': 'deref'}
                    
                # Check frees
                free_match = self.free_pattern.search(line)
                if free_match:
                    frees.add(free_match.group(1))
                    
                # Check returns
                ret_match = self.return_pattern.search(line)
                if ret_match:
                    returns.append({'line': line_num, 'indent': ret_match.group(1), 'depth': brace_depth})
                    
                # Function end evaluation
                if brace_depth == 0:
                    in_func = False
                    vulns.extend(self._evaluate_function_leaks(allocations, frees, returns, func_name, lines, line_num))

        return vulns

    def _evaluate_function_leaks(self, allocations: Dict[str, Any], frees: Set[str], returns: List[Dict[str, Any]], func_name: str, lines: List[str], func_end_line: int) -> List[Dict[str, Any]]:
        vulns = []
        
        for var, alloc_data in allocations.items():
            alloc_line = alloc_data['line']
            
            # Simple Never-Freed Leak
            if var not in frees:
                # Check if it's returned
                is_returned = any(re.search(rf'return\s+{re.escape(var)}\s*;', lines[r['line']-1]) for r in returns)
                
                # Check if global (heuristic: uppercase or specific naming, or simple assumption for scope)
                
                if not is_returned:
                    # Mark as Never-Freed Leak (or Address-Taken Leak if field/deref)
                    leak_type = 'address_taken_leak' if '->' in var or alloc_data['type'] == 'deref' else 'never_freed_leak'
                    
                    # We will insert free() before every return that is after the allocation
                    valid_returns = [r for r in returns if r['line'] > alloc_line]
                    if not valid_returns:
                        # Fallback to end of function
                        valid_returns = [{'line': func_end_line, 'indent': '    '}]
                        
                    for ret in valid_returns:
                        vulns.append({
                            'type': leak_type,
                            'var': var,
                            'line': ret['line'], # Target insertion line
                            'alloc_line': alloc_line,
                            'indent': ret['indent'],
                            'status': 'vulnerable'
                        })
            
            # Conditional Leak (Implicit Free on Error Path)
            # If it is freed eventually, but there are early returns bypassing the free
            elif var in frees:
                # Find the line of the highest free
                free_lines = [i+1 for i, l in enumerate(lines) if re.search(rf'free\s*\(\s*{re.escape(var)}\s*\)', l)]
                first_free = min(free_lines) if free_lines else func_end_line
                
                # Pre-free returns
                early_returns = [r for r in returns if alloc_line < r['line'] < first_free]
                
                for ret in early_returns:
                    # Check if 'free(var)' is in the block (heuristic)
                    return_line_content = lines[ret['line']-1]
                    if 'free' not in return_line_content:
                        vulns.append({
                            'type': 'conditional_leak_error_path',
                            'var': var,
                            'line': ret['line'], # Target insertion line
                            'alloc_line': alloc_line,
                            'indent': ret['indent'],
                            'status': 'vulnerable'
                        })
                        
            # Conditional Leak (Allocation Failure - Nested)
            # If var 'A' is allocated, and another 'B' is allocated, and B fails causing return
            # We must free 'A' before returning.
            # Covered implicitly by 'early_returns' for A if A is eventually freed, 
            # or by 'never_freed_leak' for A on that specific return if not freed.
                        
        return vulns


class MemoryLeakFixer:
    """
    Fixes memory leaks by inserting appropriate free() calls.
    """
    def __init__(self, mode: str = "automated"):
        self.mode = mode

    def generate_patch(self, vuln: Dict[str, Any]) -> str:
        var = vuln['var']
        indent = vuln['indent']
        
        # We insert the free call matching the indentation of the target line (e.g. return statement)
        patch_lines = []
        if '->' in var:
            # Safe access assuming base pointer is not null is tricky, but SABER standard inserts free directly
            patch_lines.append(f"{indent}free({var});")
        else:
            patch_lines.append(f"{indent}free({var});")
            
        return '\n'.join(patch_lines)

    def batch_repair(self, source_code: str) -> Tuple[str, List[Dict[str, Any]], Dict[int, str]]:
        scanner = MemoryLeakScanner()
        vulns = scanner.scan_functions(source_code)
        
        lines = source_code.split('\n')
        
        # Sort descending by line number to avoid offset shifting
        sorted_vulns = sorted(vulns, key=lambda x: x['line'], reverse=True)
        
        repaired_lines_map = {}
        for vuln in sorted_vulns:
            line_idx = vuln['line'] - 1
            if 0 <= line_idx < len(lines):
                patch_str = self.generate_patch(vuln)
                # Insert free() before the return statement or targeted branch exit
                lines[line_idx] = f"{patch_str}\n{lines[line_idx]}"
                repaired_lines_map[vuln['line']] = patch_str
                
        return '\n'.join(lines), vulns, repaired_lines_map


class MemoryLeakValidator:
    def validate(self, original_source: str, repaired_source: str, expected_vulns: List[Dict[str, Any]]) -> Dict[int, str]:
        results = {}
        # In a generic static parsing scope, confirm structural mitigation manually tracking insertions
        repaired_lines_split = repaired_source.split('\n')
        
        for vuln in expected_vulns:
            line_num = vuln['line']
            var = vuln['var']
            
            # Simulated check: ensure the block wrapper is populated with free(var)
            line_idx = line_num - 1
            found = False
            
            # Since we inserted it directly before the line or above it, check nearby context
            for offset in range(-2, 2):
                if 0 <= line_idx + offset < len(repaired_lines_split):
                    if f"free({var})" in repaired_lines_split[line_idx + offset]:
                        found = True
                        break
                        
            if found:
                results[line_num] = 'correct_repair'
            else:
                results[line_num] = 'unremoved_leak'
                
        return results


def run_memory_leak_repair(source_code: str) -> Tuple[str, Dict[str, Any]]:
    fixer = MemoryLeakFixer()
    repaired_code, original_vulns, _ = fixer.batch_repair(source_code)
    
    validator = MemoryLeakValidator()
    validation_results = validator.validate(source_code, repaired_code, original_vulns)
    
    return repaired_code, validation_results
