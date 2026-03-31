#!/usr/bin/env python3
"""
Race Condition Target Detection Module
Identifies functions and code patterns susceptible to race conditions
"""

import os
import re
import ast
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class SharedResource:
    """Represents a shared resource that could cause race conditions"""
    resource_type: str  # 'file', 'memory', 'database', 'network', 'global_var'
    resource_name: str
    access_pattern: str  # 'read', 'write', 'read_write'
    file_path: str
    line_number: int
    function_context: str


@dataclass
class ConcurrentTarget:
    """Represents a function that could have race conditions"""
    function_name: str
    file_path: str
    line_number: int
    shared_resources: List[SharedResource]
    concurrency_indicators: List[str]
    risk_score: float
    vulnerability_types: List[str]
    thread_safety_analysis: Dict[str, any]


class RaceConditionDetector:
    """Detects potential race condition targets in source code"""
    
    # Patterns that indicate concurrency/threading
    CONCURRENCY_PATTERNS = [
        # Threading patterns
        r'pthread_create|std::thread|CreateThread',
        r'std::mutex|pthread_mutex|CRITICAL_SECTION',
        r'std::atomic|atomic_|InterlockedIncrement',
        r'std::lock_guard|std::unique_lock|pthread_mutex_lock',
        
        # Async patterns
        r'async|await|Promise|Future',
        r'std::async|std::future|std::promise',
        
        # Synchronization primitives
        r'std::condition_variable|pthread_cond',
        r'std::shared_mutex|std::recursive_mutex',
        r'std::barrier|std::latch|std::counting_semaphore',
        
        # Process/IPC patterns
        r'fork\(\)|exec|CreateProcess',
        r'shared_memory|mmap|shmget',
        r'pipe\(\)|socket\(\)|connect\(',
        
        # Signal handling
        r'signal\(\)|sigaction|SetConsoleCtrlHandler',
    ]
    
    # Patterns for shared resource access
    SHARED_RESOURCE_PATTERNS = {
        'file': [
            r'fopen|fclose|fread|fwrite|fprintf|fscanf',
            r'open\(\)|close\(\)|read\(\)|write\(\)',
            r'std::ifstream|std::ofstream|std::fstream',
            r'CreateFile|ReadFile|WriteFile|CloseHandle',
        ],
        'memory': [
            r'malloc|calloc|realloc|free',
            r'new\s+|delete\s+|delete\[\]',
            r'std::shared_ptr|std::unique_ptr|std::weak_ptr',
            r'HeapAlloc|HeapFree|VirtualAlloc',
        ],
        'database': [
            r'sqlite3_|mysql_|pg_|ODBC',
            r'SELECT|INSERT|UPDATE|DELETE|CREATE|DROP',
            r'BEGIN|COMMIT|ROLLBACK|TRANSACTION',
            r'ExecuteQuery|ExecuteNonQuery|ExecuteScalar',
        ],
        'network': [
            r'socket\(\)|bind\(\)|listen\(\)|accept\(\)',
            r'send\(\)|recv\(\)|sendto\(\)|recvfrom\(',
            r'connect\(\)|gethostbyname|getaddrinfo',
            r'WSAStartup|WSASocket|WSASend|WSARecv',
        ],
        'global_var': [
            r'static\s+\w+|extern\s+\w+',
            r'global\s+\w+|__global__',
            r'singleton|getInstance',
        ]
    }
    
    # Vulnerability patterns that indicate race condition risks
    VULNERABILITY_PATTERNS = {
        'toctou': [  # Time-of-check to time-of-use
            r'access\(\).*fopen|access\(\).*open\(',
            r'stat\(\).*fopen|stat\(\).*open\(',
            r'GetFileAttributes.*CreateFile',
            r'PathFileExists.*CreateFile',
            r'if.*access.*fopen|if.*stat.*fopen',
        ],
        'double_free': [
            r'free\(\)|delete\s+',
            r'HeapFree|LocalFree|GlobalFree',
        ],
        'use_after_free': [
            r'free\(\).*\w+|delete\s+.*\w+',
            r'close\(\).*\w+',
        ],
        'resource_leak': [
            r'malloc|new\s+|fopen|socket\(',
            r'CreateFile|CreateThread|CreateMutex',
        ],
        'state_corruption': [
            r'static\s+\w+\s*=|global\s+\w+\s*=',
            r'shared_ptr|singleton',
        ]
    }
    
    def __init__(self, source_dir: str):
        """Initialize detector with source directory"""
        self.source_dir = source_dir
        self.source_files = []
        self.functions = {}  # file_path -> List[function_info]
        self.shared_resources = []
        self.concurrent_targets = []
        
    def discover_source_files(self) -> List[str]:
        """Discover source files for analysis"""
        source_extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.py', '.js', '.ts'}
        source_files = []
        
        for root, dirs, files in os.walk(self.source_dir):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'build', 'dist']]
            
            for file in files:
                if any(file.endswith(ext) for ext in source_extensions):
                    file_path = os.path.join(root, file)
                    source_files.append(file_path)
        
        logger.info(f"Found {len(source_files)} source files for race condition analysis")
        self.source_files = source_files
        return source_files
    
    def _analyze_cpp_file(self, file_path: str) -> List[Dict]:
        """Analyze C/C++ file for race condition patterns"""
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find function definitions
            function_pattern = r'(?:^|\n)\s*(?:static\s+)?(?:inline\s+)?(?:\w+\s+)*(\w+)\s*\(\s*([^)]*)\s*\)\s*\{'
            
            for match in re.finditer(function_pattern, content, re.MULTILINE):
                func_name = match.group(1)
                params_str = match.group(2)
                line_number = content[:match.start()].count('\n') + 1
                
                # Skip common non-function matches
                if func_name in ['if', 'for', 'while', 'switch', 'return']:
                    continue
                
                # Extract function body
                func_start = match.end()
                brace_count = 1
                func_end = func_start
                
                for i, char in enumerate(content[func_start:], func_start):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            func_end = i
                            break
                
                func_body = content[func_start:func_end]
                
                # Analyze function for race condition patterns
                concurrency_indicators = self._find_concurrency_patterns(func_body)
                shared_resources = self._find_shared_resources(func_body, file_path, line_number, func_name)
                vulnerability_types = self._find_vulnerability_patterns(func_body)
                
                # Only include functions with potential race conditions
                if concurrency_indicators or shared_resources or vulnerability_types:
                    functions.append({
                        'name': func_name,
                        'file_path': file_path,
                        'line_number': line_number,
                        'body': func_body,
                        'concurrency_indicators': concurrency_indicators,
                        'shared_resources': shared_resources,
                        'vulnerability_types': vulnerability_types
                    })
                    
        except Exception as e:
            logger.warning(f"Failed to analyze C/C++ file {file_path}: {e}")
        
        return functions
    
    def _analyze_python_file(self, file_path: str) -> List[Dict]:
        """Analyze Python file for race condition patterns"""
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    line_number = node.lineno
                    
                    # Get function body as string
                    func_body = ast.unparse(node)
                    
                    # Analyze for race condition patterns
                    concurrency_indicators = self._find_concurrency_patterns(func_body)
                    shared_resources = self._find_shared_resources(func_body, file_path, line_number, func_name)
                    vulnerability_types = self._find_vulnerability_patterns(func_body)
                    
                    # Check for Python-specific concurrency patterns
                    python_concurrency = self._find_python_concurrency_patterns(func_body)
                    concurrency_indicators.extend(python_concurrency)
                    
                    if concurrency_indicators or shared_resources or vulnerability_types:
                        functions.append({
                            'name': func_name,
                            'file_path': file_path,
                            'line_number': line_number,
                            'body': func_body,
                            'concurrency_indicators': concurrency_indicators,
                            'shared_resources': shared_resources,
                            'vulnerability_types': vulnerability_types
                        })
                        
        except Exception as e:
            logger.warning(f"Failed to analyze Python file {file_path}: {e}")
        
        return functions
    
    def _find_concurrency_patterns(self, code: str) -> List[str]:
        """Find concurrency indicators in code"""
        indicators = []
        
        for pattern in self.CONCURRENCY_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                indicators.append(pattern)
        
        return indicators
    
    def _find_python_concurrency_patterns(self, code: str) -> List[str]:
        """Find Python-specific concurrency patterns"""
        python_patterns = [
            r'threading\.|multiprocessing\.|asyncio\.',
            r'Thread\(|Process\(|Pool\(',
            r'Lock\(\)|RLock\(\)|Semaphore\(',
            r'Queue\(\)|Event\(\)|Condition\(',
            r'async\s+def|await\s+',
            r'concurrent\.futures',
        ]
        
        indicators = []
        for pattern in python_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                indicators.append(pattern)
        
        return indicators
    
    def _find_shared_resources(self, code: str, file_path: str, line_number: int, func_name: str) -> List[SharedResource]:
        """Find shared resource access patterns"""
        resources = []
        
        for resource_type, patterns in self.SHARED_RESOURCE_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    # Determine access pattern (read/write/both)
                    access_pattern = self._determine_access_pattern(match.group(), resource_type)
                    
                    resource = SharedResource(
                        resource_type=resource_type,
                        resource_name=match.group(),
                        access_pattern=access_pattern,
                        file_path=file_path,
                        line_number=line_number + code[:match.start()].count('\n'),
                        function_context=func_name
                    )
                    resources.append(resource)
        
        return resources
    
    def _determine_access_pattern(self, match_text: str, resource_type: str) -> str:
        """Determine if resource access is read, write, or both"""
        read_patterns = ['read', 'get', 'select', 'recv', 'fread', 'scanf']
        write_patterns = ['write', 'set', 'insert', 'update', 'delete', 'send', 'fwrite', 'printf']
        
        match_lower = match_text.lower()
        
        is_read = any(pattern in match_lower for pattern in read_patterns)
        is_write = any(pattern in match_lower for pattern in write_patterns)
        
        if is_read and is_write:
            return 'read_write'
        elif is_write:
            return 'write'
        elif is_read:
            return 'read'
        else:
            return 'unknown'
    
    def _find_vulnerability_patterns(self, code: str) -> List[str]:
        """Find vulnerability patterns that could lead to race conditions"""
        vulnerabilities = []
        
        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    vulnerabilities.append(vuln_type)
                    break  # Only add each vulnerability type once
        
        return vulnerabilities
    
    def _calculate_risk_score(self, func_info: Dict) -> float:
        """Calculate risk score for potential race condition"""
        base_score = 1.0
        
        # Boost for concurrency indicators
        concurrency_boost = len(func_info['concurrency_indicators']) * 2.0
        
        # Boost for shared resources
        resource_boost = len(func_info['shared_resources']) * 1.5
        
        # Boost for vulnerability patterns
        vuln_boost = len(func_info['vulnerability_types']) * 3.0
        
        # Boost for specific high-risk patterns
        high_risk_patterns = ['toctou', 'double_free', 'use_after_free']
        high_risk_boost = sum(2.0 for vuln in func_info['vulnerability_types'] if vuln in high_risk_patterns)
        
        # Boost for write access to shared resources
        write_boost = sum(1.0 for resource in func_info['shared_resources'] 
                         if 'write' in resource.access_pattern)
        
        total_score = base_score + concurrency_boost + resource_boost + vuln_boost + high_risk_boost + write_boost
        
        return min(total_score, 10.0)  # Cap at 10.0
    
    def _analyze_thread_safety(self, func_info: Dict) -> Dict[str, any]:
        """Analyze thread safety characteristics"""
        analysis = {
            'has_synchronization': False,
            'uses_atomic_operations': False,
            'accesses_global_state': False,
            'potential_deadlock': False,
            'resource_contention': False
        }
        
        code = func_info['body']
        
        # Check for synchronization primitives
        sync_patterns = ['mutex', 'lock', 'atomic', 'synchronized', 'critical_section']
        analysis['has_synchronization'] = any(re.search(pattern, code, re.IGNORECASE) for pattern in sync_patterns)
        
        # Check for atomic operations
        atomic_patterns = ['atomic_', 'InterlockedIncrement', 'std::atomic', '__sync_']
        analysis['uses_atomic_operations'] = any(re.search(pattern, code, re.IGNORECASE) for pattern in atomic_patterns)
        
        # Check for global state access
        global_patterns = ['static', 'extern', 'global', 'singleton']
        analysis['accesses_global_state'] = any(re.search(pattern, code, re.IGNORECASE) for pattern in global_patterns)
        
        # Check for potential deadlock (multiple locks)
        lock_count = len(re.findall(r'lock|mutex', code, re.IGNORECASE))
        analysis['potential_deadlock'] = lock_count > 1
        
        # Check for resource contention
        analysis['resource_contention'] = len(func_info['shared_resources']) > 1
        
        return analysis
    
    def analyze_functions(self) -> Dict[str, List[Dict]]:
        """Analyze all source files for race condition targets"""
        logger.info("Analyzing functions for race condition patterns...")
        
        for file_path in self.source_files:
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext == '.py':
                functions = self._analyze_python_file(file_path)
            elif file_ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']:
                functions = self._analyze_cpp_file(file_path)
            else:
                continue
            
            if functions:
                self.functions[file_path] = functions
                logger.debug(f"Found {len(functions)} potential race condition targets in {file_path}")
        
        total_functions = sum(len(funcs) for funcs in self.functions.values())
        logger.info(f"Analyzed {total_functions} functions with potential race conditions")
        
        return self.functions
    
    def generate_concurrent_targets(self) -> List[ConcurrentTarget]:
        """Generate concurrent targets from analyzed functions"""
        logger.info("Generating concurrent targets...")
        
        targets = []
        
        for file_funcs in self.functions.values():
            for func_info in file_funcs:
                # Calculate risk score
                risk_score = self._calculate_risk_score(func_info)
                
                # Analyze thread safety
                thread_safety = self._analyze_thread_safety(func_info)
                
                # Create concurrent target
                target = ConcurrentTarget(
                    function_name=func_info['name'],
                    file_path=func_info['file_path'],
                    line_number=func_info['line_number'],
                    shared_resources=func_info['shared_resources'],
                    concurrency_indicators=func_info['concurrency_indicators'],
                    risk_score=risk_score,
                    vulnerability_types=func_info['vulnerability_types'],
                    thread_safety_analysis=thread_safety
                )
                
                targets.append(target)
        
        # Sort by risk score (highest first)
        targets.sort(key=lambda t: t.risk_score, reverse=True)
        
        logger.info(f"Generated {len(targets)} concurrent targets")
        self.concurrent_targets = targets
        
        return targets
    
    def export_targets_to_json(self, targets: List[ConcurrentTarget], output_path: str) -> None:
        """Export concurrent targets to JSON file"""
        targets_data = []
        
        for target in targets:
            target_data = {
                'function_name': target.function_name,
                'file_path': target.file_path,
                'line_number': target.line_number,
                'risk_score': target.risk_score,
                'vulnerability_types': target.vulnerability_types,
                'concurrency_indicators': target.concurrency_indicators,
                'thread_safety_analysis': target.thread_safety_analysis,
                'shared_resources': [
                    {
                        'resource_type': res.resource_type,
                        'resource_name': res.resource_name,
                        'access_pattern': res.access_pattern,
                        'line_number': res.line_number
                    }
                    for res in target.shared_resources
                ]
            }
            targets_data.append(target_data)
        
        output_data = {
            'generated_at': json.dumps(None, default=str),
            'source_dir': self.source_dir,
            'total_targets': len(targets),
            'targets': targets_data
        }
        
        # Replace datetime placeholder
        import datetime
        output_data['generated_at'] = datetime.datetime.now().isoformat()
        
        # Create directory if needed
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Exported {len(targets)} concurrent targets to {output_path}")
    
    def generate_summary_report(self, targets: List[ConcurrentTarget]) -> Dict:
        """Generate summary report of race condition analysis"""
        if not targets:
            return {
                'total_targets': 0,
                'vulnerability_types': {},
                'resource_types': {},
                'risk_distribution': {},
                'top_risk_targets': []
            }
        
        # Count vulnerability types
        vuln_counts = defaultdict(int)
        for target in targets:
            for vuln in target.vulnerability_types:
                vuln_counts[vuln] += 1
        
        # Count resource types
        resource_counts = defaultdict(int)
        for target in targets:
            for resource in target.shared_resources:
                resource_counts[resource.resource_type] += 1
        
        # Risk distribution
        risk_ranges = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for target in targets:
            if target.risk_score < 3.0:
                risk_ranges['low'] += 1
            elif target.risk_score < 6.0:
                risk_ranges['medium'] += 1
            elif target.risk_score < 8.0:
                risk_ranges['high'] += 1
            else:
                risk_ranges['critical'] += 1
        
        # Top risk targets
        top_targets = targets[:10]  # Top 10 by risk score
        
        return {
            'total_targets': len(targets),
            'vulnerability_types': dict(vuln_counts),
            'resource_types': dict(resource_counts),
            'risk_distribution': risk_ranges,
            'average_risk_score': sum(t.risk_score for t in targets) / len(targets),
            'top_risk_targets': [
                {
                    'function_name': target.function_name,
                    'file_path': target.file_path,
                    'risk_score': target.risk_score,
                    'vulnerability_types': target.vulnerability_types,
                    'shared_resources_count': len(target.shared_resources)
                }
                for target in top_targets
            ]
        }


def main():
    """CLI interface for race condition detection"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Detect race condition targets')
    parser.add_argument('source_dir', help='Directory to scan for source files')
    parser.add_argument('--output', '-o', default='race_condition_targets.json',
                       help='Output file for detected targets')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')
    
    # Run detection
    detector = RaceConditionDetector(args.source_dir)
    detector.discover_source_files()
    detector.analyze_functions()
    targets = detector.generate_concurrent_targets()
    
    # Export results
    detector.export_targets_to_json(targets, args.output)
    
    # Print summary
    summary = detector.generate_summary_report(targets)
    print(f"\nRace Condition Analysis Summary:")
    print(f"Total targets: {summary['total_targets']}")
    print(f"Vulnerability types: {summary['vulnerability_types']}")
    print(f"Resource types: {summary['resource_types']}")
    print(f"Risk distribution: {summary['risk_distribution']}")
    
    if summary['top_risk_targets']:
        print(f"\nTop Risk Targets:")
        for target in summary['top_risk_targets'][:5]:
            print(f"  {target['function_name']}: {target['risk_score']:.1f} (vulnerabilities: {target['vulnerability_types']})")


if __name__ == '__main__':
    main()