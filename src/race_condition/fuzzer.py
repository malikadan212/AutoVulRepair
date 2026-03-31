#!/usr/bin/env python3
"""
Race Condition Fuzzer Module
Executes multi-threaded fuzzing to detect race conditions
"""

import os
import time
import json
import random
import threading
import multiprocessing
import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from queue import Queue, Empty
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class RaceConditionResult:
    """Result of race condition fuzzing"""
    target_name: str
    race_detected: bool
    execution_count: int
    crash_count: int
    race_evidence: List[Dict]
    timing_analysis: Dict[str, float]
    resource_conflicts: List[str]
    thread_safety_violations: List[str]
    execution_time: float


@dataclass
class ConcurrentExecution:
    """Configuration for concurrent execution"""
    thread_count: int
    execution_count: int
    timing_variation: float  # Seconds to vary timing
    resource_contention_level: str  # 'low', 'medium', 'high'
    synchronization_delay: float  # Delay between thread starts


class RaceConditionFuzzer:
    """Fuzzes targets for race conditions using concurrent execution"""
    
    def __init__(self, build_dir: str, timeout: int = 30):
        """Initialize race condition fuzzer"""
        self.build_dir = build_dir
        self.timeout = timeout
        self.results = []
        self.temp_dir = tempfile.mkdtemp(prefix='race_fuzzing_')
        
        # Race detection configuration
        self.detection_config = {
            'min_threads': 2,
            'max_threads': 16,
            'executions_per_thread': 100,
            'timing_precision': 0.001,  # 1ms precision
            'race_threshold': 0.05,     # 5% different outcomes = race condition
        }
        
    def __del__(self):
        """Cleanup temporary directory"""
        import shutil
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def fuzz_race_conditions(self, target_name: str, target_binary: str, 
                           concurrent_config: ConcurrentExecution) -> RaceConditionResult:
        """Fuzz a target for race conditions"""
        logger.info(f"Starting race condition fuzzing for {target_name}")
        
        start_time = time.time()
        
        # Generate test inputs for concurrent execution
        test_inputs = self._generate_race_test_inputs(target_name)
        
        # Execute concurrent fuzzing
        race_evidence = []
        execution_count = 0
        crash_count = 0
        
        for test_round in range(5):  # Multiple rounds with different configurations
            logger.debug(f"Race fuzzing round {test_round + 1} for {target_name}")
            
            # Vary thread count and timing for each round
            thread_count = min(concurrent_config.thread_count + test_round * 2, 16)
            timing_variation = concurrent_config.timing_variation * (1 + test_round * 0.2)
            
            round_config = ConcurrentExecution(
                thread_count=thread_count,
                execution_count=concurrent_config.execution_count,
                timing_variation=timing_variation,
                resource_contention_level=concurrent_config.resource_contention_level,
                synchronization_delay=concurrent_config.synchronization_delay
            )
            
            # Execute concurrent test
            round_results = self._execute_concurrent_test(
                target_binary, test_inputs, round_config
            )
            
            execution_count += round_results['execution_count']
            crash_count += round_results['crash_count']
            race_evidence.extend(round_results['race_evidence'])
        
        # Analyze results for race conditions
        race_detected = len(race_evidence) > 0
        timing_analysis = self._analyze_timing_patterns(race_evidence)
        resource_conflicts = self._detect_resource_conflicts(race_evidence)
        thread_safety_violations = self._detect_thread_safety_violations(race_evidence)
        
        execution_time = time.time() - start_time
        
        result = RaceConditionResult(
            target_name=target_name,
            race_detected=race_detected,
            execution_count=execution_count,
            crash_count=crash_count,
            race_evidence=race_evidence,
            timing_analysis=timing_analysis,
            resource_conflicts=resource_conflicts,
            thread_safety_violations=thread_safety_violations,
            execution_time=execution_time
        )
        
        logger.info(f"Race condition fuzzing completed for {target_name}: "
                   f"{'RACE DETECTED' if race_detected else 'NO RACE'} "
                   f"({execution_count} executions, {crash_count} crashes)")
        
        return result
    
    def _generate_race_test_inputs(self, target_name: str) -> List[bytes]:
        """Generate test inputs designed to trigger race conditions"""
        inputs = []
        
        # Basic inputs
        basic_inputs = [
            b'',  # Empty input
            b'A' * 100,  # Simple buffer
            b'0' * 50,  # Numeric input
            b'\x00' * 32,  # Null bytes
        ]
        inputs.extend(basic_inputs)
        
        # Race-specific inputs (designed to cause timing issues)
        race_inputs = [
            # Inputs that might cause different processing times
            b'A' * 1000,  # Large input
            b'A' * 10000,  # Very large input
            
            # Inputs with special characters that might affect parsing
            b'\n' * 100,  # Many newlines
            b'\x01\x02\x03\x04' * 25,  # Control characters
            
            # Inputs that might trigger different code paths
            b'admin\x00user',  # Null-terminated strings
            b'../../../etc/passwd',  # Path traversal
            b'SELECT * FROM users',  # SQL-like input
            
            # Inputs with timing-sensitive patterns
            b'sleep(1)',  # Command injection attempt
            b'<script>alert(1)</script>',  # XSS attempt
        ]
        inputs.extend(race_inputs)
        
        # Generate random inputs of various sizes
        for size in [1, 10, 100, 1000]:
            for _ in range(5):
                random_input = bytes([random.randint(0, 255) for _ in range(size)])
                inputs.append(random_input)
        
        logger.debug(f"Generated {len(inputs)} test inputs for race condition testing")
        return inputs
    
    def _execute_concurrent_test(self, target_binary: str, test_inputs: List[bytes],
                                config: ConcurrentExecution) -> Dict[str, Any]:
        """Execute concurrent test with multiple threads"""
        results = {
            'execution_count': 0,
            'crash_count': 0,
            'race_evidence': []
        }
        
        # Shared state for race detection
        execution_results = Queue()
        crash_queue = Queue()
        
        # Create worker function
        def worker_thread(thread_id: int, inputs: List[bytes]):
            thread_results = []
            thread_crashes = 0
            
            for i, test_input in enumerate(inputs):
                try:
                    # Add timing variation to increase race condition likelihood
                    if config.timing_variation > 0:
                        delay = random.uniform(0, config.timing_variation)
                        time.sleep(delay)
                    
                    # Execute target with input
                    start_time = time.time()
                    result = self._execute_target_with_input(target_binary, test_input, thread_id)
                    end_time = time.time()
                    
                    execution_result = {
                        'thread_id': thread_id,
                        'input_index': i,
                        'input_hash': hashlib.md5(test_input).hexdigest(),
                        'start_time': start_time,
                        'end_time': end_time,
                        'duration': end_time - start_time,
                        'return_code': result.get('return_code', 0),
                        'stdout': result.get('stdout', ''),
                        'stderr': result.get('stderr', ''),
                        'crashed': result.get('crashed', False),
                        'output_hash': hashlib.md5(result.get('stdout', '').encode()).hexdigest()
                    }
                    
                    thread_results.append(execution_result)
                    
                    if result.get('crashed', False):
                        thread_crashes += 1
                        crash_queue.put(execution_result)
                    
                except Exception as e:
                    logger.warning(f"Thread {thread_id} execution failed: {e}")
            
            execution_results.put({
                'thread_id': thread_id,
                'results': thread_results,
                'crashes': thread_crashes
            })
        
        # Start concurrent threads
        threads = []
        inputs_per_thread = len(test_inputs) // config.thread_count
        
        for thread_id in range(config.thread_count):
            start_idx = thread_id * inputs_per_thread
            end_idx = start_idx + inputs_per_thread if thread_id < config.thread_count - 1 else len(test_inputs)
            thread_inputs = test_inputs[start_idx:end_idx]
            
            thread = threading.Thread(
                target=worker_thread,
                args=(thread_id, thread_inputs),
                name=f"RaceFuzzer-{thread_id}"
            )
            threads.append(thread)
        
        # Start threads with synchronization delay
        for i, thread in enumerate(threads):
            if i > 0 and config.synchronization_delay > 0:
                time.sleep(config.synchronization_delay)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=self.timeout)
            if thread.is_alive():
                logger.warning(f"Thread {thread.name} timed out")
        
        # Collect results
        all_executions = []
        while not execution_results.empty():
            try:
                thread_result = execution_results.get_nowait()
                all_executions.extend(thread_result['results'])
                results['execution_count'] += len(thread_result['results'])
                results['crash_count'] += thread_result['crashes']
            except Empty:
                break
        
        # Analyze for race conditions
        race_evidence = self._analyze_concurrent_executions(all_executions)
        results['race_evidence'] = race_evidence
        
        return results
    
    def _execute_target_with_input(self, target_binary: str, test_input: bytes, 
                                  thread_id: int) -> Dict[str, Any]:
        """Execute target binary with given input"""
        try:
            # Create temporary input file
            input_file = os.path.join(self.temp_dir, f'input_{thread_id}_{time.time()}.bin')
            with open(input_file, 'wb') as f:
                f.write(test_input)
            
            # Execute target
            cmd = [target_binary, input_file]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout
            )
            
            stdout, stderr = process.communicate()
            return_code = process.returncode
            
            # Clean up input file
            try:
                os.unlink(input_file)
            except:
                pass
            
            return {
                'return_code': return_code,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'crashed': return_code != 0 and return_code < 0  # Negative return codes often indicate crashes
            }
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Target execution timed out for thread {thread_id}")
            return {
                'return_code': -1,
                'stdout': '',
                'stderr': 'Execution timed out',
                'crashed': True
            }
        except Exception as e:
            logger.error(f"Failed to execute target for thread {thread_id}: {e}")
            return {
                'return_code': -1,
                'stdout': '',
                'stderr': str(e),
                'crashed': True
            }
    
    def _analyze_concurrent_executions(self, executions: List[Dict]) -> List[Dict]:
        """Analyze concurrent executions for race condition evidence"""
        race_evidence = []
        
        if len(executions) < 2:
            return race_evidence
        
        # Group executions by input
        input_groups = {}
        for execution in executions:
            input_hash = execution['input_hash']
            if input_hash not in input_groups:
                input_groups[input_hash] = []
            input_groups[input_hash].append(execution)
        
        # Analyze each input group for race conditions
        for input_hash, group_executions in input_groups.items():
            if len(group_executions) < 2:
                continue
            
            # Check for different outcomes with same input
            outcomes = {}
            for execution in group_executions:
                outcome_key = (execution['return_code'], execution['output_hash'])
                if outcome_key not in outcomes:
                    outcomes[outcome_key] = []
                outcomes[outcome_key].append(execution)
            
            # Race condition detected if same input produces different outcomes
            if len(outcomes) > 1:
                evidence = {
                    'type': 'different_outcomes',
                    'input_hash': input_hash,
                    'outcomes': len(outcomes),
                    'executions': group_executions,
                    'confidence': self._calculate_race_confidence(outcomes)
                }
                race_evidence.append(evidence)
            
            # Check for timing-based race conditions
            timing_evidence = self._analyze_timing_races(group_executions)
            if timing_evidence:
                race_evidence.extend(timing_evidence)
        
        # Check for resource contention patterns
        resource_evidence = self._analyze_resource_contention(executions)
        race_evidence.extend(resource_evidence)
        
        return race_evidence
    
    def _calculate_race_confidence(self, outcomes: Dict) -> float:
        """Calculate confidence level for race condition detection"""
        total_executions = sum(len(executions) for executions in outcomes.values())
        
        if total_executions < 2:
            return 0.0
        
        # Calculate outcome distribution
        outcome_counts = [len(executions) for executions in outcomes.values()]
        outcome_counts.sort(reverse=True)
        
        # Higher confidence if outcomes are more evenly distributed
        if len(outcome_counts) == 2:
            minority_ratio = outcome_counts[1] / total_executions
            # Confidence increases as minority outcome becomes more frequent
            confidence = min(minority_ratio * 4, 1.0)  # Scale to 0-1
        else:
            # Multiple outcomes - high confidence
            confidence = 0.8
        
        return confidence
    
    def _analyze_timing_races(self, executions: List[Dict]) -> List[Dict]:
        """Analyze timing patterns for race conditions"""
        timing_evidence = []
        
        if len(executions) < 3:
            return timing_evidence
        
        # Sort by start time
        executions.sort(key=lambda x: x['start_time'])
        
        # Look for overlapping executions with different outcomes
        for i in range(len(executions) - 1):
            for j in range(i + 1, len(executions)):
                exec1 = executions[i]
                exec2 = executions[j]
                
                # Check if executions overlapped in time
                overlap = (exec1['start_time'] < exec2['end_time'] and 
                          exec2['start_time'] < exec1['end_time'])
                
                if overlap:
                    # Check if outcomes were different
                    different_outcome = (exec1['return_code'] != exec2['return_code'] or
                                       exec1['output_hash'] != exec2['output_hash'])
                    
                    if different_outcome:
                        evidence = {
                            'type': 'timing_race',
                            'execution1': exec1,
                            'execution2': exec2,
                            'overlap_duration': min(exec1['end_time'], exec2['end_time']) - 
                                              max(exec1['start_time'], exec2['start_time']),
                            'confidence': 0.7
                        }
                        timing_evidence.append(evidence)
        
        return timing_evidence
    
    def _analyze_resource_contention(self, executions: List[Dict]) -> List[Dict]:
        """Analyze for resource contention patterns"""
        contention_evidence = []
        
        # Look for patterns in stderr that indicate resource contention
        contention_patterns = [
            'resource busy',
            'file locked',
            'permission denied',
            'access denied',
            'device busy',
            'address already in use',
            'connection refused',
            'timeout',
            'deadlock'
        ]
        
        contention_executions = []
        for execution in executions:
            stderr_lower = execution['stderr'].lower()
            for pattern in contention_patterns:
                if pattern in stderr_lower:
                    contention_executions.append({
                        'execution': execution,
                        'pattern': pattern
                    })
                    break
        
        if len(contention_executions) > 1:
            evidence = {
                'type': 'resource_contention',
                'affected_executions': contention_executions,
                'confidence': 0.6
            }
            contention_evidence.append(evidence)
        
        return contention_evidence
    
    def _analyze_timing_patterns(self, race_evidence: List[Dict]) -> Dict[str, float]:
        """Analyze timing patterns in race evidence"""
        if not race_evidence:
            return {}
        
        timing_analysis = {
            'avg_execution_time': 0.0,
            'timing_variance': 0.0,
            'overlap_frequency': 0.0,
            'race_window': 0.0
        }
        
        # Collect timing data
        execution_times = []
        overlaps = []
        
        for evidence in race_evidence:
            if evidence['type'] == 'timing_race':
                exec1 = evidence['execution1']
                exec2 = evidence['execution2']
                execution_times.extend([exec1['duration'], exec2['duration']])
                overlaps.append(evidence['overlap_duration'])
        
        if execution_times:
            timing_analysis['avg_execution_time'] = sum(execution_times) / len(execution_times)
            
            # Calculate variance
            avg_time = timing_analysis['avg_execution_time']
            variance = sum((t - avg_time) ** 2 for t in execution_times) / len(execution_times)
            timing_analysis['timing_variance'] = variance ** 0.5
        
        if overlaps:
            timing_analysis['overlap_frequency'] = len(overlaps) / len(race_evidence)
            timing_analysis['race_window'] = sum(overlaps) / len(overlaps)
        
        return timing_analysis
    
    def _detect_resource_conflicts(self, race_evidence: List[Dict]) -> List[str]:
        """Detect resource conflicts from race evidence"""
        conflicts = []
        
        for evidence in race_evidence:
            if evidence['type'] == 'resource_contention':
                patterns = [exec_info['pattern'] for exec_info in evidence['affected_executions']]
                conflicts.extend(patterns)
        
        return list(set(conflicts))  # Remove duplicates
    
    def _detect_thread_safety_violations(self, race_evidence: List[Dict]) -> List[str]:
        """Detect thread safety violations from race evidence"""
        violations = []
        
        for evidence in race_evidence:
            if evidence['type'] == 'different_outcomes':
                if evidence['confidence'] > 0.5:
                    violations.append('non_deterministic_behavior')
            
            elif evidence['type'] == 'timing_race':
                violations.append('timing_dependent_behavior')
            
            elif evidence['type'] == 'resource_contention':
                violations.append('resource_access_conflict')
        
        return list(set(violations))  # Remove duplicates
    
    def generate_race_report(self, results: List[RaceConditionResult], output_path: str) -> None:
        """Generate comprehensive race condition report"""
        report_data = {
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_targets': len(results),
            'races_detected': sum(1 for r in results if r.race_detected),
            'total_executions': sum(r.execution_count for r in results),
            'total_crashes': sum(r.crash_count for r in results),
            'results': []
        }
        
        for result in results:
            result_data = {
                'target_name': result.target_name,
                'race_detected': result.race_detected,
                'execution_count': result.execution_count,
                'crash_count': result.crash_count,
                'execution_time': result.execution_time,
                'timing_analysis': result.timing_analysis,
                'resource_conflicts': result.resource_conflicts,
                'thread_safety_violations': result.thread_safety_violations,
                'race_evidence_count': len(result.race_evidence),
                'race_evidence': result.race_evidence  # Include detailed evidence
            }
            report_data['results'].append(result_data)
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Generated race condition report: {output_path}")


def main():
    """CLI interface for race condition fuzzing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Fuzz targets for race conditions')
    parser.add_argument('build_dir', help='Directory containing built fuzz targets')
    parser.add_argument('--output', '-o', default='race_condition_results.json',
                       help='Output file for results')
    parser.add_argument('--threads', '-t', type=int, default=4,
                       help='Number of concurrent threads')
    parser.add_argument('--executions', '-e', type=int, default=100,
                       help='Number of executions per thread')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout per execution in seconds')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')
    
    # Find fuzz targets
    fuzz_targets = []
    for file in os.listdir(args.build_dir):
        if file.startswith('fuzz_') and os.access(os.path.join(args.build_dir, file), os.X_OK):
            fuzz_targets.append(os.path.join(args.build_dir, file))
    
    if not fuzz_targets:
        print(f"No fuzz targets found in {args.build_dir}")
        return 1
    
    print(f"Found {len(fuzz_targets)} fuzz targets")
    
    # Initialize fuzzer
    fuzzer = RaceConditionFuzzer(args.build_dir, timeout=args.timeout)
    
    # Configure concurrent execution
    config = ConcurrentExecution(
        thread_count=args.threads,
        execution_count=args.executions,
        timing_variation=0.01,  # 10ms variation
        resource_contention_level='medium',
        synchronization_delay=0.001  # 1ms delay between thread starts
    )
    
    # Fuzz each target
    results = []
    for target_path in fuzz_targets:
        target_name = os.path.basename(target_path)
        print(f"Fuzzing {target_name} for race conditions...")
        
        result = fuzzer.fuzz_race_conditions(target_name, target_path, config)
        results.append(result)
        
        status = "RACE DETECTED" if result.race_detected else "NO RACE"
        print(f"  {status} ({result.execution_count} executions, {result.crash_count} crashes)")
    
    # Generate report
    fuzzer.generate_race_report(results, args.output)
    
    # Summary
    races_found = sum(1 for r in results if r.race_detected)
    print(f"\nRace Condition Fuzzing Summary:")
    print(f"  Targets tested: {len(results)}")
    print(f"  Race conditions found: {races_found}")
    print(f"  Total executions: {sum(r.execution_count for r in results)}")
    print(f"  Total crashes: {sum(r.crash_count for r in results)}")
    
    return 0


if __name__ == '__main__':
    exit(main())