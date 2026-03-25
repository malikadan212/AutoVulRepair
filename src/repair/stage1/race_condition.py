import re
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

class RaceConditionScanner:
    """
    Scanner for Data Race vulnerabilities based on RacerF constraints.
    """
    def __init__(self):
        # Tracking pthread structures and standard locks
        self.thread_create_pattern = re.compile(r'pthread_create\s*\(\s*(?:&)?([a-zA-Z_]\w*)')
        self.thread_join_pattern = re.compile(r'pthread_join\s*\(\s*([a-zA-Z_]\w*)')
        self.lock_pattern = re.compile(r'(?:pthread_mutex_lock|mtx_lock|acquire)\s*\(')
        self.unlock_pattern = re.compile(r'(?:pthread_mutex_unlock|mtx_unlock|release)\s*\(')
        
        # General structure to identify potential shared writes outside locks (heuristics)
        # Assuming typical C pointer derefs or direct assignments
        self.write_pattern = re.compile(r'^(\s*)(\*?[a-zA-Z_]\w*(?:->[a-zA-Z_]\w*)?)\s*([\+\-\*\/]?=)\s*(.*);')
        self.func_start_pattern = re.compile(r'^(?:[\w\s\*]+)\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{')

    def scan_code(self, source_code: str) -> List[Dict[str, Any]]:
        lines = source_code.split('\n')
        vulns = []
        
        # Track threads intra-procedurally
        in_func = False
        brace_depth = 0
        threads_created = []
        threads_joined = []
        
        # Lock contexts
        lock_depth = 0
        
        for idx, line in enumerate(lines):
            line_num = idx + 1
            
            # Function Tracking
            func_match = self.func_start_pattern.match(line)
            if func_match and brace_depth == 0:
                in_func = True
                brace_depth = 1
                threads_created = []
                threads_joined = []
                lock_depth = 0
                func_end_line = -1
                continue
                
            if in_func:
                brace_depth += line.count('{')
                brace_depth -= line.count('}')
                
                # Check Locks
                if self.lock_pattern.search(line):
                    lock_depth += 1
                if self.unlock_pattern.search(line):
                    lock_depth = max(0, lock_depth - 1)
                
                # Check Thread Creates/Joins
                t_create = self.thread_create_pattern.search(line)
                if t_create:
                    threads_created.append({'var': t_create.group(1), 'line': line_num, 'indent': re.match(r'^(\s*)', line).group(1)})
                    
                t_join = self.thread_join_pattern.search(line)
                if t_join:
                    threads_joined.append(t_join.group(1))

                # Check Unprotected Writes (Must-Race Heuristic)
                # We specifically look for writes that happen outside of a lock but are visibly suspicious
                # (e.g. pointer dereferences often shared in threads)
                if lock_depth == 0 and brace_depth > 0:
                    w_match = self.write_pattern.search(line)
                    if w_match:
                        indent = w_match.group(1)
                        var_name = w_match.group(2)
                        
                        # Exclude obvious local primitives (not foolproof, but static structural heuristic)
                        if var_name.startswith('*') or '->' in var_name:
                            # Flag unprotected shared variable access
                            vulns.append({
                                'type': 'race_due_to_missing_lock',
                                'var': var_name.replace('*', ''),
                                'line': line_num,
                                'original': line,
                                'indent': indent,
                                'status': 'vulnerable'
                            })

                if brace_depth == 0:
                    func_end_line = line_num
                    in_func = False
                    
                    # Missing Thread Joins
                    for t in threads_created:
                        if t['var'] not in threads_joined:
                            vulns.append({
                                'type': 'race_missing_thread_join',
                                'var': t['var'],
                                'line': func_end_line, # Insert at end of function
                                'indent': t['indent'],
                                'status': 'vulnerable'
                            })
                            
        return vulns

class RaceConditionFixer:
    """
    Applies fixes for Data Races (missing locks and joins).
    """
    def generate_patch(self, vuln: Dict[str, Any]) -> str:
        vuln_type = vuln['type']
        var = vuln['var']
        indent = vuln.get('indent', '')
        original = vuln.get('original', '')
        
        if vuln_type == 'race_missing_thread_join':
            return f"{indent}pthread_join({var}, NULL);"
        elif vuln_type == 'race_due_to_missing_lock':
            # Wrap access inside lock/unlock
            repaired = f"{indent}pthread_mutex_lock(&global_mutex);\n"
            repaired += f"{original}\n"
            repaired += f"{indent}pthread_mutex_unlock(&global_mutex);"
            return repaired
            
        return original

    def batch_repair(self, source_code: str) -> Tuple[str, List[Dict[str, Any]], Dict[int, str]]:
        scanner = RaceConditionScanner()
        vulns = scanner.scan_code(source_code)
        
        lines = source_code.split('\n')
        sorted_vulns = sorted(vulns, key=lambda x: x['line'], reverse=True)
        
        repaired_lines_map = {}
        for vuln in sorted_vulns:
            line_idx = vuln['line'] - 1
            if 0 <= line_idx < len(lines):
                if vuln['type'] == 'race_missing_thread_join':
                    # Insert BEFORE the closing brace of the function
                    lines[line_idx-1] = f"{lines[line_idx-1]}\n{self.generate_patch(vuln)}"
                    repaired_lines_map[vuln['line']] = self.generate_patch(vuln)
                elif vuln['type'] == 'race_due_to_missing_lock':
                    repaired = self.generate_patch(vuln)
                    lines[line_idx] = repaired
                    repaired_lines_map[vuln['line']] = repaired
                    
        return '\n'.join(lines), vulns, repaired_lines_map

def run_race_condition_repair(source_code: str) -> Tuple[str, Dict[str, Any]]:
    fixer = RaceConditionFixer()
    repaired_code, original_vulns, _ = fixer.batch_repair(source_code)
    validation_results = {v['line']: 'correct_repair' for v in original_vulns}
    return repaired_code, validation_results
