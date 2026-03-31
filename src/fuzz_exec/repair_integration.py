"""
Fuzzing Integration with Repair System
Uses fuzzing crashes to validate that patches actually fix vulnerabilities
"""

import os
import json
import subprocess
import base64
from typing import Dict, List, Optional

class FuzzingRepairIntegration:
    """
    Integrates fuzzing with the repair system to:
    1. Validate patches using crash inputs
    2. Ensure fixes don't break functionality
    3. Prevent regression of fixed vulnerabilities
    """
    
    def __init__(self, scan_dir: str):
        self.scan_dir = scan_dir
        self.crashes_dir = os.path.join(scan_dir, 'fuzz', 'crashes')
        self.build_dir = os.path.join(scan_dir, 'build')
    
    def validate_patch(self, vulnerability_id: str, patched_code_path: str) -> Dict:
        """
        Validate that a patch fixes vulnerabilities using fuzzing crash inputs
        
        Args:
            vulnerability_id: ID of the vulnerability being patched
            patched_code_path: Path to the patched source code
            
        Returns:
            Validation results with pass/fail status
        """
        
        # Find crash inputs related to this vulnerability
        related_crashes = self._find_related_crashes(vulnerability_id)
        
        if not related_crashes:
            return {
                'status': 'no_crashes',
                'message': 'No fuzzing crashes found for this vulnerability',
                'validation_possible': False
            }
        
        # Rebuild the patched code
        rebuild_result = self._rebuild_with_patch(patched_code_path)
        
        if not rebuild_result['success']:
            return {
                'status': 'build_failed',
                'message': f'Failed to build patched code: {rebuild_result["error"]}',
                'validation_possible': False
            }
        
        # Test each crash input against the patched code
        validation_results = []
        
        for crash_info in related_crashes:
            test_result = self._test_crash_input(crash_info, rebuild_result['binary_path'])
            validation_results.append(test_result)
        
        # Analyze overall validation results
        passed_tests = sum(1 for r in validation_results if r['status'] == 'fixed')
        total_tests = len(validation_results)
        
        return {
            'status': 'completed',
            'validation_possible': True,
            'total_crash_inputs': total_tests,
            'inputs_fixed': passed_tests,
            'inputs_still_crashing': total_tests - passed_tests,
            'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            'detailed_results': validation_results,
            'overall_result': 'PATCH_SUCCESSFUL' if passed_tests == total_tests else 'PATCH_INCOMPLETE',
            'recommendation': self._get_patch_recommendation(passed_tests, total_tests)
        }
    
    def _find_related_crashes(self, vulnerability_id: str) -> List[Dict]:
        """Find crash inputs related to a specific vulnerability"""
        related_crashes = []
        
        if not os.path.exists(self.crashes_dir):
            return related_crashes
        
        # Map vulnerability types to crash directories
        vuln_to_crash_mapping = {
            'buffer_overflow': ['fuzz_test_array_bounds_overflow', 'fuzz_test_sprintf_overflow'],
            'double_free': ['fuzz_test_double_free'],
            'null_pointer': ['fuzz_test_null_pointer_dereference'],
            'memory_leak': ['fuzz_test_malloc_memory_leak'],
            'use_after_free': ['fuzz_test_use_after_free']
        }
        
        # Extract vulnerability type from ID
        vuln_type = self._extract_vulnerability_type(vulnerability_id)
        crash_dirs = vuln_to_crash_mapping.get(vuln_type, [])
        
        for crash_dir_name in crash_dirs:
            crash_dir_path = os.path.join(self.crashes_dir, crash_dir_name)
            
            if os.path.exists(crash_dir_path):
                for crash_file in os.listdir(crash_dir_path):
                    if crash_file.startswith('crash-') or crash_file.startswith('leak-'):
                        crash_file_path = os.path.join(crash_dir_path, crash_file)
                        
                        related_crashes.append({
                            'crash_file': crash_file,
                            'crash_path': crash_file_path,
                            'target': crash_dir_name,
                            'vulnerability_type': vuln_type
                        })
        
        return related_crashes
    
    def _extract_vulnerability_type(self, vulnerability_id: str) -> str:
        """Extract vulnerability type from vulnerability ID"""
        vuln_id_lower = vulnerability_id.lower()
        
        if 'buffer' in vuln_id_lower or 'overflow' in vuln_id_lower:
            return 'buffer_overflow'
        elif 'double' in vuln_id_lower and 'free' in vuln_id_lower:
            return 'double_free'
        elif 'null' in vuln_id_lower or 'pointer' in vuln_id_lower:
            return 'null_pointer'
        elif 'leak' in vuln_id_lower:
            return 'memory_leak'
        elif 'use' in vuln_id_lower and 'after' in vuln_id_lower:
            return 'use_after_free'
        else:
            return 'unknown'
    
    def _rebuild_with_patch(self, patched_code_path: str) -> Dict:
        """Rebuild the code with the applied patch"""
        
        # This would integrate with your existing build system
        # For now, return a mock result
        return {
            'success': True,
            'binary_path': os.path.join(self.build_dir, 'patched_binary'),
            'build_time': 5.2
        }
    
    def _test_crash_input(self, crash_info: Dict, binary_path: str) -> Dict:
        """Test a specific crash input against the patched binary"""
        
        crash_file_path = crash_info['crash_path']
        
        try:
            # Read the crash input
            with open(crash_file_path, 'rb') as f:
                crash_input = f.read()
            
            # Run the patched binary with the crash input
            # This is a simplified version - real implementation would depend on your binary interface
            result = subprocess.run(
                [binary_path],
                input=crash_input,
                capture_output=True,
                timeout=10
            )
            
            # Analyze the result
            if result.returncode == 0:
                # Binary didn't crash - patch likely successful
                return {
                    'crash_file': crash_info['crash_file'],
                    'status': 'fixed',
                    'message': 'Crash input no longer causes crash - vulnerability appears fixed',
                    'exit_code': result.returncode
                }
            else:
                # Binary still crashes - patch may be incomplete
                return {
                    'crash_file': crash_info['crash_file'],
                    'status': 'still_crashing',
                    'message': 'Crash input still causes crash - patch may be incomplete',
                    'exit_code': result.returncode,
                    'stderr': result.stderr.decode('utf-8', errors='ignore')[:500]
                }
                
        except subprocess.TimeoutExpired:
            return {
                'crash_file': crash_info['crash_file'],
                'status': 'timeout',
                'message': 'Test timed out - possible infinite loop or hang'
            }
        except Exception as e:
            return {
                'crash_file': crash_info['crash_file'],
                'status': 'error',
                'message': f'Error testing crash input: {str(e)}'
            }
    
    def _get_patch_recommendation(self, passed_tests: int, total_tests: int) -> str:
        """Get recommendation based on patch validation results"""
        
        if total_tests == 0:
            return "No crash inputs available for validation. Consider additional testing."
        
        success_rate = (passed_tests / total_tests) * 100
        
        if success_rate == 100:
            return "✅ Excellent! All crash inputs are now handled safely. Patch appears complete."
        elif success_rate >= 80:
            return "⚠️ Good progress! Most crash inputs are fixed, but some still cause issues. Review remaining failures."
        elif success_rate >= 50:
            return "🔄 Partial fix. About half the crash inputs are resolved. Patch needs more work."
        else:
            return "❌ Patch appears ineffective. Most crash inputs still cause crashes. Significant rework needed."
    
    def generate_regression_test_suite(self, vulnerability_id: str) -> Dict:
        """Generate a regression test suite from crash inputs"""
        
        related_crashes = self._find_related_crashes(vulnerability_id)
        
        if not related_crashes:
            return {
                'success': False,
                'message': 'No crash inputs found for regression test generation'
            }
        
        test_suite = {
            'vulnerability_id': vulnerability_id,
            'test_count': len(related_crashes),
            'tests': []
        }
        
        for crash_info in related_crashes:
            # Read crash input
            with open(crash_info['crash_path'], 'rb') as f:
                crash_input = f.read()
            
            # Create test case
            test_case = {
                'test_name': f"regression_test_{crash_info['crash_file']}",
                'input_data': base64.b64encode(crash_input).decode('ascii'),
                'expected_behavior': 'should_not_crash',
                'vulnerability_type': crash_info['vulnerability_type'],
                'description': f"Regression test to ensure {crash_info['vulnerability_type']} vulnerability stays fixed"
            }
            
            test_suite['tests'].append(test_case)
        
        # Save test suite
        test_suite_path = os.path.join(self.scan_dir, f'regression_tests_{vulnerability_id}.json')
        with open(test_suite_path, 'w') as f:
            json.dump(test_suite, f, indent=2)
        
        return {
            'success': True,
            'test_suite_path': test_suite_path,
            'test_count': len(related_crashes),
            'message': f'Generated regression test suite with {len(related_crashes)} tests'
        }