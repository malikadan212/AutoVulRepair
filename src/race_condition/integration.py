#!/usr/bin/env python3
"""
Race Condition Integration Module
Integrates race condition fuzzing with the existing fuzz plan generator
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .detector import RaceConditionDetector, ConcurrentTarget
from .fuzzer import RaceConditionFuzzer, ConcurrentExecution, RaceConditionResult

logger = logging.getLogger(__name__)


@dataclass
class RaceConditionFuzzTarget:
    """Race condition fuzz target for integration with fuzz plan"""
    target_id: str
    function_name: str
    file_path: str
    line_number: int
    risk_score: float
    vulnerability_types: List[str]
    shared_resources: List[Dict]
    concurrency_indicators: List[str]
    thread_safety_analysis: Dict[str, Any]
    
    # Fuzzing configuration
    thread_count: int
    execution_count: int
    timing_variation: float
    
    # Results (populated after fuzzing)
    race_detected: Optional[bool] = None
    execution_results: Optional[Dict] = None


class RaceConditionIntegration:
    """Integrates race condition fuzzing with existing fuzz plan system"""
    
    def __init__(self, source_dir: Optional[str] = None):
        """Initialize race condition integration"""
        self.source_dir = source_dir
        self.detector = None
        self.fuzzer = None
        self.race_targets = []
        
    def discover_race_targets(self) -> List[RaceConditionFuzzTarget]:
        """Discover race condition targets from source code"""
        if not self.source_dir:
            logger.warning("No source directory provided for race condition detection")
            return []
        
        logger.info("Discovering race condition targets...")
        
        # Initialize detector
        self.detector = RaceConditionDetector(self.source_dir)
        
        # Discover and analyze source files
        self.detector.discover_source_files()
        self.detector.analyze_functions()
        concurrent_targets = self.detector.generate_concurrent_targets()
        
        # Convert to race condition fuzz targets
        race_targets = []
        for target in concurrent_targets:
            # Configure fuzzing parameters based on risk score
            thread_count, execution_count, timing_variation = self._configure_fuzzing_params(target)
            
            race_target = RaceConditionFuzzTarget(
                target_id=f"race_{target.function_name}_{hash(target.file_path) % 10000}",
                function_name=target.function_name,
                file_path=target.file_path,
                line_number=target.line_number,
                risk_score=target.risk_score,
                vulnerability_types=target.vulnerability_types,
                shared_resources=[
                    {
                        'type': res.resource_type,
                        'name': res.resource_name,
                        'access_pattern': res.access_pattern,
                        'line_number': res.line_number
                    }
                    for res in target.shared_resources
                ],
                concurrency_indicators=target.concurrency_indicators,
                thread_safety_analysis=target.thread_safety_analysis,
                thread_count=thread_count,
                execution_count=execution_count,
                timing_variation=timing_variation
            )
            
            race_targets.append(race_target)
        
        # Sort by risk score (highest first)
        race_targets.sort(key=lambda t: t.risk_score, reverse=True)
        
        logger.info(f"Discovered {len(race_targets)} race condition targets")
        self.race_targets = race_targets
        
        return race_targets
    
    def _configure_fuzzing_params(self, target: ConcurrentTarget) -> tuple:
        """Configure fuzzing parameters based on target characteristics"""
        # Base configuration
        base_threads = 4
        base_executions = 100
        base_timing = 0.01  # 10ms
        
        # Adjust based on risk score
        risk_multiplier = min(target.risk_score / 5.0, 2.0)  # Cap at 2x
        
        # More threads for higher risk targets
        thread_count = int(base_threads * risk_multiplier)
        thread_count = max(2, min(thread_count, 16))  # Clamp between 2-16
        
        # More executions for higher risk targets
        execution_count = int(base_executions * risk_multiplier)
        execution_count = max(50, min(execution_count, 500))  # Clamp between 50-500
        
        # Vary timing based on vulnerability types
        timing_variation = base_timing
        if 'toctou' in target.vulnerability_types:
            timing_variation *= 2.0  # TOCTOU needs more timing variation
        if 'state_corruption' in target.vulnerability_types:
            timing_variation *= 1.5  # State corruption benefits from timing variation
        
        return thread_count, execution_count, timing_variation
    
    def generate_race_fuzz_plan_targets(self) -> List[Dict[str, Any]]:
        """Generate race condition targets for fuzz plan integration"""
        if not self.race_targets:
            return []
        
        fuzz_plan_targets = []
        
        for race_target in self.race_targets:
            # Create fuzz plan target compatible with existing system
            target = {
                'target_id': race_target.target_id,
                'type': 'race_condition',  # Mark as race condition target
                'source_file': race_target.file_path,
                'file_stem': Path(race_target.file_path).stem,
                'function_name': race_target.function_name,
                'bug_class': 'Race-Condition',
                'rule_id': 'race_condition_fuzzing',
                'severity': self._map_risk_to_severity(race_target.risk_score),
                'confidence': 'high' if race_target.risk_score > 7.0 else 'medium',
                'line_number': race_target.line_number,
                'column_number': 0,
                'message': self._generate_race_message(race_target),
                'cwe': self._map_vulnerability_to_cwe(race_target.vulnerability_types),
                'sanitizers': ['thread', 'address'],  # Thread sanitizer + AddressSanitizer
                'seed_directories': ['fuzz/seeds/race_condition/', 'fuzz/seeds/concurrent/'],
                'dictionaries': ['fuzz/race_condition.dict', 'fuzz/threading.dict'],
                'priority': race_target.risk_score,
                'harness_type': 'race_condition',
                'harness_template': 'race_condition',
                
                # Race condition specific metadata
                'race_condition_config': {
                    'thread_count': race_target.thread_count,
                    'execution_count': race_target.execution_count,
                    'timing_variation': race_target.timing_variation,
                    'vulnerability_types': race_target.vulnerability_types,
                    'shared_resources': race_target.shared_resources,
                    'concurrency_indicators': race_target.concurrency_indicators,
                    'thread_safety_analysis': race_target.thread_safety_analysis
                }
            }
            
            fuzz_plan_targets.append(target)
        
        logger.info(f"Generated {len(fuzz_plan_targets)} race condition fuzz plan targets")
        return fuzz_plan_targets
    
    def _map_risk_to_severity(self, risk_score: float) -> str:
        """Map risk score to severity level"""
        if risk_score >= 8.0:
            return 'error'
        elif risk_score >= 6.0:
            return 'warning'
        elif risk_score >= 4.0:
            return 'information'
        else:
            return 'style'
    
    def _generate_race_message(self, race_target: RaceConditionFuzzTarget) -> str:
        """Generate descriptive message for race condition target"""
        base_msg = f"Potential race condition in {race_target.function_name}"
        
        # Add vulnerability details
        if race_target.vulnerability_types:
            vuln_desc = ', '.join(race_target.vulnerability_types).replace('_', ' ')
            base_msg += f" (vulnerabilities: {vuln_desc})"
        
        # Add shared resource info
        if race_target.shared_resources:
            resource_types = list(set(res['type'] for res in race_target.shared_resources))
            resource_desc = ', '.join(resource_types)
            base_msg += f" accessing shared resources: {resource_desc}"
        
        return base_msg
    
    def _map_vulnerability_to_cwe(self, vulnerability_types: List[str]) -> str:
        """Map vulnerability types to CWE numbers"""
        cwe_mapping = {
            'toctou': '367',      # Time-of-check Time-of-use Race Condition
            'double_free': '415', # Double Free
            'use_after_free': '416', # Use After Free
            'resource_leak': '401',  # Missing Release of Memory after Effective Lifetime
            'state_corruption': '362', # Concurrent Execution using Shared Resource with Improper Synchronization
        }
        
        # Return CWE for first matching vulnerability type
        for vuln_type in vulnerability_types:
            if vuln_type in cwe_mapping:
                return cwe_mapping[vuln_type]
        
        # Default to general race condition CWE
        return '362'  # Concurrent Execution using Shared Resource with Improper Synchronization
    
    def execute_race_condition_fuzzing(self, build_dir: str, targets: List[str] = None) -> List[RaceConditionResult]:
        """Execute race condition fuzzing on built targets"""
        if not self.race_targets:
            logger.warning("No race condition targets available for fuzzing")
            return []
        
        logger.info("Starting race condition fuzzing execution...")
        
        # Initialize fuzzer
        self.fuzzer = RaceConditionFuzzer(build_dir)
        
        # Filter targets if specified
        targets_to_fuzz = self.race_targets
        if targets:
            targets_to_fuzz = [t for t in self.race_targets if t.target_id in targets]
        
        results = []
        
        for race_target in targets_to_fuzz:
            logger.info(f"Fuzzing race condition target: {race_target.function_name}")
            
            # Find corresponding binary
            target_binary = self._find_target_binary(build_dir, race_target)
            if not target_binary:
                logger.warning(f"No binary found for race target {race_target.function_name}")
                continue
            
            # Configure concurrent execution
            config = ConcurrentExecution(
                thread_count=race_target.thread_count,
                execution_count=race_target.execution_count,
                timing_variation=race_target.timing_variation,
                resource_contention_level='medium',
                synchronization_delay=0.001
            )
            
            # Execute race condition fuzzing
            try:
                result = self.fuzzer.fuzz_race_conditions(
                    race_target.target_id, target_binary, config
                )
                results.append(result)
                
                # Update race target with results
                race_target.race_detected = result.race_detected
                race_target.execution_results = {
                    'execution_count': result.execution_count,
                    'crash_count': result.crash_count,
                    'race_evidence_count': len(result.race_evidence),
                    'timing_analysis': result.timing_analysis,
                    'resource_conflicts': result.resource_conflicts,
                    'thread_safety_violations': result.thread_safety_violations
                }
                
            except Exception as e:
                logger.error(f"Race condition fuzzing failed for {race_target.function_name}: {e}")
        
        logger.info(f"Race condition fuzzing completed: {len(results)} targets tested")
        return results
    
    def _find_target_binary(self, build_dir: str, race_target: RaceConditionFuzzTarget) -> Optional[str]:
        """Find the binary corresponding to a race condition target"""
        # Look for binaries that might correspond to this target
        possible_names = [
            f"fuzz_{race_target.function_name}",
            f"race_{race_target.function_name}",
            f"{Path(race_target.file_path).stem}_{race_target.function_name}",
            race_target.target_id
        ]
        
        for name in possible_names:
            binary_path = os.path.join(build_dir, name)
            if os.path.exists(binary_path) and os.access(binary_path, os.X_OK):
                return binary_path
        
        # Fallback: look for any executable that might be related
        for file in os.listdir(build_dir):
            if (race_target.function_name in file and 
                os.access(os.path.join(build_dir, file), os.X_OK)):
                return os.path.join(build_dir, file)
        
        return None
    
    def generate_race_condition_report(self, results: List[RaceConditionResult], 
                                     output_path: str) -> None:
        """Generate comprehensive race condition report"""
        if not self.fuzzer:
            logger.error("No fuzzer instance available for report generation")
            return
        
        self.fuzzer.generate_race_report(results, output_path)
        logger.info(f"Race condition report generated: {output_path}")
    
    def get_race_condition_summary(self) -> Dict[str, Any]:
        """Get summary of race condition analysis and fuzzing"""
        if not self.race_targets:
            return {
                'total_targets': 0,
                'races_detected': 0,
                'vulnerability_distribution': {},
                'risk_distribution': {}
            }
        
        # Count races detected
        races_detected = sum(1 for t in self.race_targets 
                           if t.race_detected is True)
        
        # Vulnerability type distribution
        vuln_counts = {}
        for target in self.race_targets:
            for vuln_type in target.vulnerability_types:
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        # Risk distribution
        risk_ranges = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for target in self.race_targets:
            if target.risk_score < 3.0:
                risk_ranges['low'] += 1
            elif target.risk_score < 6.0:
                risk_ranges['medium'] += 1
            elif target.risk_score < 8.0:
                risk_ranges['high'] += 1
            else:
                risk_ranges['critical'] += 1
        
        return {
            'total_targets': len(self.race_targets),
            'races_detected': races_detected,
            'vulnerability_distribution': vuln_counts,
            'risk_distribution': risk_ranges,
            'average_risk_score': sum(t.risk_score for t in self.race_targets) / len(self.race_targets),
            'top_risk_targets': [
                {
                    'target_id': t.target_id,
                    'function_name': t.function_name,
                    'risk_score': t.risk_score,
                    'race_detected': t.race_detected
                }
                for t in sorted(self.race_targets, key=lambda x: x.risk_score, reverse=True)[:5]
            ]
        }


def main():
    """CLI interface for race condition integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Race condition fuzzing integration')
    parser.add_argument('source_dir', help='Source code directory')
    parser.add_argument('--build-dir', help='Build directory for fuzzing')
    parser.add_argument('--output', '-o', default='race_condition_integration.json',
                       help='Output file for integration results')
    parser.add_argument('--fuzz-plan', help='Generate fuzz plan targets only')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')
    
    # Initialize integration
    integration = RaceConditionIntegration(args.source_dir)
    
    # Discover race condition targets
    race_targets = integration.discover_race_targets()
    
    if args.fuzz_plan:
        # Generate fuzz plan targets
        fuzz_plan_targets = integration.generate_race_fuzz_plan_targets()
        
        with open(args.output, 'w') as f:
            json.dump({
                'race_condition_targets': fuzz_plan_targets,
                'summary': integration.get_race_condition_summary()
            }, f, indent=2)
        
        print(f"Generated {len(fuzz_plan_targets)} race condition fuzz plan targets")
    
    elif args.build_dir:
        # Execute race condition fuzzing
        results = integration.execute_race_condition_fuzzing(args.build_dir)
        
        # Generate report
        report_path = args.output.replace('.json', '_report.json')
        integration.generate_race_condition_report(results, report_path)
        
        # Save summary
        summary = integration.get_race_condition_summary()
        with open(args.output, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"Race condition fuzzing completed:")
        print(f"  Targets tested: {summary['total_targets']}")
        print(f"  Races detected: {summary['races_detected']}")
    
    else:
        # Just discovery
        summary = integration.get_race_condition_summary()
        with open(args.output, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"Race condition target discovery completed:")
        print(f"  Targets found: {summary['total_targets']}")
        print(f"  Risk distribution: {summary['risk_distribution']}")


if __name__ == '__main__':
    main()