#!/usr/bin/env python3
"""
AutoVulRepair Test Runner
Runs all test suites and generates a comprehensive test report
"""

import unittest
import sys
import time
import os
from io import StringIO


class TestResult:
    """Custom test result class to capture detailed results"""
    
    def __init__(self):
        self.tests_run = 0
        self.failures = []
        self.errors = []
        self.successes = []
        self.start_time = None
        self.end_time = None
    
    def start_test(self, test):
        self.start_time = time.time()
    
    def stop_test(self, test):
        self.end_time = time.time()
        self.tests_run += 1
    
    def add_success(self, test):
        self.successes.append(test)
    
    def add_error(self, test, error):
        self.errors.append((test, error))
    
    def add_failure(self, test, failure):
        self.failures.append((test, failure))
    
    @property
    def success_count(self):
        return len(self.successes)
    
    @property
    def failure_count(self):
        return len(self.failures)
    
    @property
    def error_count(self):
        return len(self.errors)
    
    @property
    def total_time(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0


def run_test_suite(test_module_name, verbose=True):
    """Run a specific test suite and return results"""
    print(f"\n{'='*60}")
    print(f"Running {test_module_name}")
    print(f"{'='*60}")
    
    # Import the test module
    try:
        test_module = __import__(f'tests.{test_module_name}', fromlist=[test_module_name])
    except ImportError as e:
        print(f"❌ Failed to import {test_module_name}: {e}")
        return None
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_module)
    
    # Run tests with custom result collector
    stream = StringIO()
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=2 if verbose else 1,
        buffer=True
    )
    
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    # Print results
    output = stream.getvalue()
    print(output)
    
    # Summary
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    successes = total_tests - failures - errors
    execution_time = end_time - start_time
    
    print(f"\n📊 {test_module_name} Results:")
    print(f"   ✅ Passed: {successes}/{total_tests}")
    print(f"   ❌ Failed: {failures}")
    print(f"   🚨 Errors: {errors}")
    print(f"   ⏱️  Time: {execution_time:.2f}s")
    
    if failures > 0:
        print(f"\n❌ Failures in {test_module_name}:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if errors > 0:
        print(f"\n🚨 Errors in {test_module_name}:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    return {
        'module': test_module_name,
        'total': total_tests,
        'passed': successes,
        'failed': failures,
        'errors': errors,
        'time': execution_time,
        'success_rate': (successes / total_tests * 100) if total_tests > 0 else 0
    }


def main():
    """Main test runner"""
    print("🧪 AutoVulRepair Test Suite")
    print("=" * 60)
    
    # Test modules to run
    test_modules = [
        'test_fuzz_plan_generator',
        'test_harness_generator', 
        'test_triage_analyzer',
        'test_integration',
        'test_performance',
        'test_web_app',
        'test_analysis_tools'
    ]
    
    # Run all test suites
    all_results = []
    total_start_time = time.time()
    
    for module in test_modules:
        result = run_test_suite(module, verbose=True)
        if result:
            all_results.append(result)
    
    total_end_time = time.time()
    total_execution_time = total_end_time - total_start_time
    
    # Generate comprehensive report
    print(f"\n{'='*60}")
    print("📋 COMPREHENSIVE TEST REPORT")
    print(f"{'='*60}")
    
    total_tests = sum(r['total'] for r in all_results)
    total_passed = sum(r['passed'] for r in all_results)
    total_failed = sum(r['failed'] for r in all_results)
    total_errors = sum(r['errors'] for r in all_results)
    overall_success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n📊 Overall Statistics:")
    print(f"   Total Tests: {total_tests}")
    print(f"   ✅ Passed: {total_passed} ({overall_success_rate:.1f}%)")
    print(f"   ❌ Failed: {total_failed}")
    print(f"   🚨 Errors: {total_errors}")
    print(f"   ⏱️  Total Time: {total_execution_time:.2f}s")
    
    print(f"\n📈 Module Breakdown:")
    print(f"{'Module':<25} {'Tests':<8} {'Passed':<8} {'Failed':<8} {'Success Rate':<12} {'Time':<8}")
    print("-" * 80)
    
    for result in all_results:
        print(f"{result['module']:<25} {result['total']:<8} {result['passed']:<8} "
              f"{result['failed']:<8} {result['success_rate']:<11.1f}% {result['time']:<7.2f}s")
    
    # Test coverage analysis
    print(f"\n🎯 Test Coverage Analysis:")
    
    coverage_areas = {
        'Fuzz Plan Generation': 'test_fuzz_plan_generator',
        'Harness Generation': 'test_harness_generator',
        'Crash Triage': 'test_triage_analyzer', 
        'Component Integration': 'test_integration',
        'Performance & Scalability': 'test_performance',
        'Web Application': 'test_web_app',
        'Analysis Tools': 'test_analysis_tools'
    }
    
    for area, module in coverage_areas.items():
        result = next((r for r in all_results if r['module'] == module), None)
        if result:
            status = "✅ COVERED" if result['success_rate'] >= 80 else "⚠️  PARTIAL" if result['success_rate'] >= 50 else "❌ POOR"
            print(f"   {area:<25}: {status} ({result['success_rate']:.1f}%)")
    
    # Quality assessment
    print(f"\n🏆 Quality Assessment:")
    
    if overall_success_rate >= 95:
        quality = "🥇 EXCELLENT"
    elif overall_success_rate >= 85:
        quality = "🥈 GOOD"
    elif overall_success_rate >= 70:
        quality = "🥉 ACCEPTABLE"
    else:
        quality = "❌ NEEDS IMPROVEMENT"
    
    print(f"   Overall Quality: {quality}")
    print(f"   Test Completeness: {'✅ COMPREHENSIVE' if total_tests >= 50 else '⚠️  BASIC'}")
    print(f"   Performance Testing: {'✅ INCLUDED' if any('performance' in r['module'] for r in all_results) else '❌ MISSING'}")
    print(f"   Integration Testing: {'✅ INCLUDED' if any('integration' in r['module'] for r in all_results) else '❌ MISSING'}")
    
    # Recommendations
    print(f"\n💡 Recommendations:")
    
    if total_failed > 0 or total_errors > 0:
        print("   - Fix failing tests before production deployment")
    
    if overall_success_rate < 90:
        print("   - Improve test coverage for critical components")
    
    if total_execution_time > 60:
        print("   - Consider optimizing slow tests for CI/CD pipeline")
    
    print("   - Add more edge case testing")
    print("   - Consider adding load testing for production scenarios")
    print("   - Implement continuous testing in CI/CD pipeline")
    
    # Exit code
    exit_code = 0 if (total_failed == 0 and total_errors == 0) else 1
    
    print(f"\n{'='*60}")
    if exit_code == 0:
        print("🎉 ALL TESTS PASSED! System is ready for deployment.")
    else:
        print("⚠️  SOME TESTS FAILED! Review and fix issues before deployment.")
    print(f"{'='*60}")
    
    return exit_code


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)