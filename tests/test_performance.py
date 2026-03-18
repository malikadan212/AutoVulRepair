"""
Performance Tests for AutoVulRepair
Tests system performance and scalability
"""

import unittest
import json
import tempfile
import os
import time
import shutil
from src.fuzz_plan.generator import FuzzPlanGenerator
from src.harness.generator import HarnessGenerator


class TestPerformance(unittest.TestCase):
    """Test performance characteristics of the system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def create_large_findings_dataset(self, num_findings: int) -> str:
        """Create a large dataset of findings for performance testing"""
        findings = {
            "total_findings": num_findings,
            "findings": []
        }
        
        bug_types = [
            "Buffer Overflow", "Use After Free", "Integer Overflow", 
            "Null Pointer Dereference", "Memory Leak", "Double Free"
        ]
        severities = ["critical", "high", "medium", "low"]
        
        rule_ids = ["bufferOverflow", "useAfterFree", "integerOverflow", "nullPointer", "memleak", "doubleFree"]
        confidences = ["high", "medium", "low"]
        
        for i in range(num_findings):
            file_name = f"file_{i % 100}.cpp"
            finding = {
                "rule_id": rule_ids[i % len(rule_ids)],
                "type": bug_types[i % len(bug_types)],
                "severity": severities[i % len(severities)],
                "confidence": confidences[i % len(confidences)],
                "file": file_name,
                "file_stem": file_name.replace('.cpp', ''),
                "line": (i % 1000) + 1,  # Lines 1-1000
                "message": f"Vulnerability {i} detected",
                "function": f"function_{i}"
            }
            findings["findings"].append(finding)
        
        findings_file = os.path.join(self.temp_dir, f'large_findings_{num_findings}.json')
        with open(findings_file, 'w') as f:
            json.dump(findings, f)
        
        return findings_file
    
    def test_fuzz_plan_generation_performance_small(self):
        """Test fuzz plan generation performance with small dataset (10 findings)"""
        findings_file = self.create_large_findings_dataset(10)
        
        start_time = time.time()
        
        generator = FuzzPlanGenerator(findings_file)
        fuzz_plan = generator.generate_fuzz_plan()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete quickly for small dataset
        self.assertLess(execution_time, 1.0)  # Less than 1 second
        self.assertEqual(len(fuzz_plan['targets']), 10)
        
        print(f"Small dataset (10 findings): {execution_time:.3f}s")
    
    def test_fuzz_plan_generation_performance_medium(self):
        """Test fuzz plan generation performance with medium dataset (100 findings)"""
        findings_file = self.create_large_findings_dataset(100)
        
        start_time = time.time()
        
        generator = FuzzPlanGenerator(findings_file)
        fuzz_plan = generator.generate_fuzz_plan()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should still be reasonably fast
        self.assertLess(execution_time, 5.0)  # Less than 5 seconds
        
        # Check deduplication worked (should be less than 100 due to same functions)
        self.assertLessEqual(len(fuzz_plan['targets']), 100)
        
        print(f"Medium dataset (100 findings): {execution_time:.3f}s")
    
    def test_fuzz_plan_generation_performance_large(self):
        """Test fuzz plan generation performance with large dataset (1000 findings)"""
        findings_file = self.create_large_findings_dataset(1000)
        
        start_time = time.time()
        
        generator = FuzzPlanGenerator(findings_file)
        fuzz_plan = generator.generate_fuzz_plan()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should handle large datasets reasonably
        self.assertLess(execution_time, 30.0)  # Less than 30 seconds
        
        # Check deduplication worked significantly
        self.assertLess(len(fuzz_plan['targets']), 1000)
        
        print(f"Large dataset (1000 findings): {execution_time:.3f}s, "
              f"Targets: {len(fuzz_plan['targets'])}")
    
    def test_harness_generation_performance_small(self):
        """Test harness generation performance with small dataset"""
        findings_file = self.create_large_findings_dataset(10)
        
        # Generate fuzz plan
        fuzz_plan_generator = FuzzPlanGenerator(findings_file)
        fuzz_plan_file = os.path.join(self.temp_dir, 'perf_small_fuzzplan.json')
        fuzz_plan_generator.save_fuzz_plan(fuzz_plan_file)
        
        # Time harness generation
        start_time = time.time()
        
        harness_generator = HarnessGenerator(fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(
            os.path.join(self.temp_dir, 'perf_small_harnesses')
        )
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should be very fast for small dataset
        self.assertLess(execution_time, 2.0)  # Less than 2 seconds
        self.assertEqual(len(harnesses), 10)
        
        print(f"Small harness generation (10 targets): {execution_time:.3f}s")
    
    def test_harness_generation_performance_medium(self):
        """Test harness generation performance with medium dataset"""
        findings_file = self.create_large_findings_dataset(50)
        
        # Generate fuzz plan
        fuzz_plan_generator = FuzzPlanGenerator(findings_file)
        fuzz_plan_file = os.path.join(self.temp_dir, 'perf_medium_fuzzplan.json')
        fuzz_plan_generator.save_fuzz_plan(fuzz_plan_file)
        
        # Time harness generation
        start_time = time.time()
        
        harness_generator = HarnessGenerator(fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(
            os.path.join(self.temp_dir, 'perf_medium_harnesses')
        )
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should handle medium datasets well
        self.assertLess(execution_time, 10.0)  # Less than 10 seconds
        
        print(f"Medium harness generation ({len(harnesses)} targets): {execution_time:.3f}s")
    
    def test_memory_usage_large_dataset(self):
        """Test memory usage with large datasets"""
        import psutil
        import os as os_module
        
        # Get initial memory usage
        process = psutil.Process(os_module.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Process large dataset
        findings_file = self.create_large_findings_dataset(500)
        
        generator = FuzzPlanGenerator(findings_file)
        fuzz_plan = generator.generate_fuzz_plan()
        
        # Get peak memory usage
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = peak_memory - initial_memory
        
        # Memory usage should be reasonable (less than 100MB increase)
        self.assertLess(memory_increase, 100.0)
        
        print(f"Memory usage increase for 500 findings: {memory_increase:.1f}MB")
    
    def test_file_io_performance(self):
        """Test file I/O performance for large outputs"""
        findings_file = self.create_large_findings_dataset(100)
        
        # Time complete pipeline with file I/O
        start_time = time.time()
        
        # Generate fuzz plan
        fuzz_plan_generator = FuzzPlanGenerator(findings_file)
        fuzz_plan_file = os.path.join(self.temp_dir, 'io_perf_fuzzplan.json')
        fuzz_plan_generator.save_fuzz_plan(fuzz_plan_file)
        
        # Generate harnesses
        harness_generator = HarnessGenerator(fuzz_plan_file)
        harness_dir = os.path.join(self.temp_dir, 'io_perf_harnesses')
        harnesses = harness_generator.generate_all_harnesses(harness_dir)
        
        # Generate build artifacts
        harness_generator.generate_build_script(harness_dir, harnesses)
        harness_generator.generate_readme(harness_dir, harnesses)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Complete pipeline should be reasonably fast
        self.assertLess(total_time, 15.0)  # Less than 15 seconds
        
        # Count generated files
        total_files = 0
        for root, dirs, files in os.walk(harness_dir):
            total_files += len(files)
        
        print(f"Complete pipeline (100 findings): {total_time:.3f}s, "
              f"Generated {total_files} files")
    
    def test_deduplication_performance(self):
        """Test performance of deduplication with many similar findings"""
        # Create dataset with many duplicates
        findings = {
            "total_findings": 110,
            "findings": []
        }
        
        # Create 100 findings for the same function (should deduplicate to 1)
        for i in range(100):
            finding = {
                "rule_id": "bufferOverflow",
                "type": "Buffer Overflow",
                "severity": "high",
                "confidence": "high",
                "file": "duplicate.cpp",
                "file_stem": "duplicate",
                "line": i + 1,  # Different lines
                "message": f"Buffer overflow at line {i + 1}",
                "function": "same_vulnerable_function"  # Same function
            }
            findings["findings"].append(finding)
        
        # Add some unique findings
        for i in range(10):
            finding = {
                "rule_id": "useAfterFree",
                "type": "Use After Free",
                "severity": "critical",
                "confidence": "high",
                "file": f"unique_{i}.cpp",
                "file_stem": f"unique_{i}",
                "line": 42,
                "message": "Use after free",
                "function": f"unique_function_{i}"
            }
            findings["findings"].append(finding)
        
        findings_file = os.path.join(self.temp_dir, 'dedup_test_findings.json')
        with open(findings_file, 'w') as f:
            json.dump(findings, f)
        
        start_time = time.time()
        
        generator = FuzzPlanGenerator(findings_file)
        fuzz_plan = generator.generate_fuzz_plan()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should deduplicate efficiently
        self.assertLess(execution_time, 5.0)  # Less than 5 seconds
        
        # Should have 11 targets (1 deduplicated + 10 unique)
        self.assertEqual(len(fuzz_plan['targets']), 11)
        
        print(f"Deduplication test (110 findings → 11 targets): {execution_time:.3f}s")


class TestScalability(unittest.TestCase):
    """Test system scalability characteristics"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_linear_scaling_fuzz_plan(self):
        """Test that fuzz plan generation scales linearly with input size"""
        sizes = [10, 50, 100]
        times = []
        
        for size in sizes:
            # Create findings dataset
            findings = {
                "total_findings": size,
                "findings": [
                    {
                        "rule_id": "bufferOverflow",
                        "type": "Buffer Overflow",
                        "severity": "high",
                        "confidence": "high",
                        "file": f"file_{i}.cpp",
                        "file_stem": f"file_{i}",
                        "line": i + 1,
                        "message": f"Buffer overflow in function_{i}",
                        "function": f"function_{i}"
                    }
                    for i in range(size)
                ]
            }
            
            findings_file = os.path.join(self.temp_dir, f'scaling_{size}.json')
            with open(findings_file, 'w') as f:
                json.dump(findings, f)
            
            # Time execution
            start_time = time.time()
            generator = FuzzPlanGenerator(findings_file)
            fuzz_plan = generator.generate_fuzz_plan()
            end_time = time.time()
            
            execution_time = end_time - start_time
            times.append(execution_time)
            
            print(f"Size {size}: {execution_time:.3f}s")
        
        # Check that scaling is reasonable (not exponential)
        # Time for 100 should be less than 10x time for 10
        if len(times) >= 3:
            ratio = times[2] / times[0]  # 100 vs 10
            self.assertLess(ratio, 20.0)  # Should be less than 20x slower
    
    def test_concurrent_processing_simulation(self):
        """Test behavior under simulated concurrent load"""
        import threading
        import queue
        
        # Create multiple findings files
        findings_files = []
        for i in range(5):
            findings = {
                "total_findings": 20,
                "findings": [
                    {
                        "rule_id": "bufferOverflow",
                        "type": "Buffer Overflow",
                        "severity": "high",
                        "confidence": "high",
                        "file": f"concurrent_{i}_{j}.cpp",
                        "file_stem": f"concurrent_{i}_{j}",
                        "line": j + 1,
                        "message": f"Buffer overflow in function_{i}_{j}",
                        "function": f"function_{i}_{j}"
                    }
                    for j in range(20)
                ]
            }
            
            findings_file = os.path.join(self.temp_dir, f'concurrent_{i}.json')
            with open(findings_file, 'w') as f:
                json.dump(findings, f)
            findings_files.append(findings_file)
        
        # Process files concurrently
        results_queue = queue.Queue()
        
        def process_file(findings_file):
            try:
                start_time = time.time()
                generator = FuzzPlanGenerator(findings_file)
                fuzz_plan = generator.generate_fuzz_plan()
                end_time = time.time()
                
                results_queue.put({
                    'file': findings_file,
                    'time': end_time - start_time,
                    'targets': len(fuzz_plan['targets']),
                    'success': True
                })
            except Exception as e:
                results_queue.put({
                    'file': findings_file,
                    'error': str(e),
                    'success': False
                })
        
        # Start threads
        threads = []
        start_time = time.time()
        
        for findings_file in findings_files:
            thread = threading.Thread(target=process_file, args=(findings_file,))
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Collect results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())
        
        # All should succeed
        successful_results = [r for r in results if r['success']]
        self.assertEqual(len(successful_results), 5)
        
        # Total time should be reasonable (concurrent processing benefit)
        self.assertLess(total_time, 10.0)  # Should complete in reasonable time
        
        print(f"Concurrent processing (5 files): {total_time:.3f}s")
        for result in successful_results:
            print(f"  {os.path.basename(result['file'])}: {result['time']:.3f}s, "
                  f"{result['targets']} targets")


if __name__ == '__main__':
    # Run with verbose output to see performance metrics
    unittest.main(verbosity=2)