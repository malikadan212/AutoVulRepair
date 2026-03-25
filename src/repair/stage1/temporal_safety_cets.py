import re
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class CETSScanner:
    """
    Rule-based C code scanner for CETS (Compiler-Enforced Temporal Safety).
    Detects pointer operations requiring CETS instrumentation.
    """
    
    def __init__(self):
        # We categorize regexes to extract necessary metadata (target pointers, variables etc)
        self.patterns = {
            'malloc': re.compile(r'^(\s*)([a-zA-Z_]\w*)\s*=\s*(?:\([a-zA-Z_\s\*]+\))?\s*(?:malloc|mmap)\s*\('),
            'free': re.compile(r'^(\s*)free\s*\(\s*([a-zA-Z_]\w*)\s*\)'),
            'ptr_derivation_add': re.compile(r'^(\s*)([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*)\s*\+\s*[^;]+;'),
            'ptr_derivation_idx': re.compile(r'^(\s*)([a-zA-Z_]\w*)\s*=\s*&\s*([a-zA-Z_]\w*)\[[^\]]+\];'),
            'deref_load': re.compile(r'^(\s*)([a-zA-Z_]\w*)\s*=\s*\*\s*([a-zA-Z_]\w*)\s*;'),
            'deref_store': re.compile(r'^(\s*)\*\s*([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*)\s*;'),
            'address_of_local': re.compile(r'^(\s*)([a-zA-Z_]\w*)\s*=\s*&\s*([a-zA-Z_]\w*)\s*;'),
            'cast_int_to_ptr': re.compile(r'^(\s*)([a-zA-Z_]\w*)\s*=\s*\([a-zA-Z_]\w*\s*\*\)\s*[a-zA-Z_]\w*\s*;'),
            'function_prologue': re.compile(r'^(\s*)(?:[a-zA-Z_]\w*\*?\s+)+[a-zA-Z_]\w*\s*\([^)]*\)\s*\{'),
            'function_epilogue': re.compile(r'^(\s*)return\s*[^;]*;\s*\}|^(\s*)\}'),
        }

    def scan_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        Scans a single line and matches against CETS vulnerability/logic rules.
        """
        for rule_type, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                return self._build_vuln(rule_type, match, line, line_num)
        
        # Catch basic dereferences not matched by load/store fully
        basic_deref = re.search(r'(\s*)\*([a-zA-Z_]\w*)', line)
        if basic_deref and not '=' in line and not 'free(' in line:
            return {
                'type': 'basic_deref',
                'line': line_num,
                'original': line,
                'indent': basic_deref.group(1),
                'ptr': basic_deref.group(2)
            }
            
        return None
        
    def _build_vuln(self, rule_type: str, match: re.Match, line: str, line_num: int) -> Dict[str, Any]:
        vuln = {
            'type': rule_type,
            'line': line_num,
            'original': line,
            'indent': match.group(1) if match.group(1) is not None else ""
        }
        
        if rule_type == 'malloc':
            vuln['ptr'] = match.group(2)
        elif rule_type == 'free':
            vuln['ptr'] = match.group(2)
        elif rule_type in ('ptr_derivation_add', 'ptr_derivation_idx'):
            vuln['newptr'] = match.group(2)
            vuln['ptr'] = match.group(3)
        elif rule_type == 'deref_load':
            vuln['newptr'] = match.group(2)
            vuln['ptr'] = match.group(3)
        elif rule_type == 'deref_store':
            vuln['ptr'] = match.group(2)
            vuln['newptr'] = match.group(3)
        elif rule_type == 'address_of_local':
            vuln['ptr'] = match.group(2)
            vuln['var'] = match.group(3)
        elif rule_type == 'cast_int_to_ptr':
            vuln['ptr'] = match.group(2)
            
        return vuln


class CETSFixer:
    """
    Fixer for CETS Temporal Safety rules.
    Outputs the explicitly requested pseudocode from the CETS specification.
    """
    
    def __init__(self, mode: str = "default"):
        self.mode = mode

    def generate_patch(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Generates instrumentation block for the specific temporal safety rule.
        """
        rule_type = vuln['type']
        indent = vuln['indent']
        original = vuln['original'].rstrip()
        
        repaired_lines = []
        
        if rule_type == 'malloc':
            ptr = vuln['ptr']
            repaired_lines = [
                original,
                f"{indent}{ptr}_key = next_key++;",
                f"{indent}{ptr}_lock_addr = allocate_lock();",
                f"{indent}*({ptr}_lock_addr) = {ptr}_key;",
                f"{indent}freeable_ptrs_map.insert({ptr}_key, {ptr});"
            ]
            
        elif rule_type == 'free':
            ptr = vuln['ptr']
            repaired_lines = [
                f"{indent}if (freeable_ptrs_map.lookup({ptr}_key) != {ptr}) {{",
                f"{indent}    abort(); // double-free or invalid-free",
                f"{indent}}}",
                f"{indent}freeable_ptrs_map.remove({ptr}_key);",
                original,
                f"{indent}*({ptr}_lock_addr) = INVALID_KEY;",
                f"{indent}deallocate_lock({ptr}_lock_addr);"
            ]
            
        elif rule_type in ('ptr_derivation_add', 'ptr_derivation_idx'):
            newptr = vuln['newptr']
            ptr = vuln['ptr']
            repaired_lines = [
                original,
                f"{indent}{newptr}_key = {ptr}_key;",
                f"{indent}{newptr}_lock_addr = {ptr}_lock_addr;"
            ]
            
        elif rule_type == 'deref_load':
            newptr = vuln['newptr']
            ptr = vuln['ptr']
            repaired_lines = [
                f"{indent}if ({ptr}_key != *{ptr}_lock_addr) {{ abort(); }}",
                original,
                f"{indent}{newptr}_key = trie_lookup({ptr})->key;",
                f"{indent}{newptr}_lock_addr = trie_lookup({ptr})->lock_addr;"
            ]
            
        elif rule_type == 'deref_store':
            ptr = vuln['ptr']
            newptr = vuln['newptr']
            repaired_lines = [
                f"{indent}if ({ptr}_key != *{ptr}_lock_addr) {{ abort(); }}",
                original,
                f"{indent}trie_lookup({ptr})->key = {newptr}_key;",
                f"{indent}trie_lookup({ptr})->lock_addr = {newptr}_lock_addr;"
            ]
            
        elif rule_type == 'address_of_local':
            ptr = vuln['ptr']
            repaired_lines = [
                original,
                f"{indent}{ptr}_key = local_key;",
                f"{indent}{ptr}_lock_addr = local_lock_addr;"
            ]
            
        elif rule_type == 'cast_int_to_ptr':
            ptr = vuln['ptr']
            repaired_lines = [
                original,
                f"{indent}{ptr}_key = INVALID_KEY;",
                f"{indent}{ptr}_lock_addr = INVALID_LOCK_ADDR;"
            ]
            
        elif rule_type == 'basic_deref':
            ptr = vuln['ptr']
            repaired_lines = [
                f"{indent}if ({ptr}_key != *{ptr}_lock_addr) {{ abort(); }}",
                original
            ]
            
        elif rule_type == 'function_prologue':
            repaired_lines = [
                original,
                f"{indent}local_key = next_key++;",
                f"{indent}local_lock_addr++; // allocate from stack-pool",
                f"{indent}*(local_lock_addr) = local_key;"
            ]
            
        elif rule_type == 'function_epilogue':
            # Need to insert before the actual return or '}'
            inner_indent = indent + "    " if not 'return' in original else indent
            repaired_lines = [
                f"{inner_indent}*(local_lock_addr) = INVALID_KEY;",
                f"{inner_indent}local_lock_addr--; // return to stack-pool",
                original
            ]
            
        else:
            return None
            
        return {
            'line': vuln['line'],
            'original': vuln['original'],
            'repaired': '\n'.join(repaired_lines)
        }

    def batch_repair(self, vulnerabilities: List[Dict[str, Any]], source_code: str) -> str:
        """
        Applies fixes bottom-to-top to avoid shifting subsequent vulnerability lines.
        """
        sorted_vulns = sorted(vulnerabilities, key=lambda x: x.get('line', 0), reverse=True)
        lines = source_code.split('\n')
        
        for vuln in sorted_vulns:
            patch = self.generate_patch(vuln)
            if patch:
                line_idx = patch['line'] - 1
                if 0 <= line_idx < len(lines):
                    lines[line_idx] = patch['repaired']
                    
        return '\n'.join(lines)


def run_cets_instrumentation(source_code: str) -> str:
    """
    Convenience function to scan and fix source code with CETS logic.
    """
    scanner = CETSScanner()
    
    lines = source_code.split('\n')
    vulns = []
    
    for i, line in enumerate(lines):
        vuln = scanner.scan_line(line, i + 1)
        if vuln:
            vulns.append(vuln)
            
    fixer = CETSFixer()
    return fixer.batch_repair(vulns, source_code)
