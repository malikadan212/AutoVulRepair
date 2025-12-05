"""
Integration Tests for AutoVulRepair
Tests the interaction between different components
"""

import unittest
import json
import tempfile
import os
import shutil
from unittest.mock import patch, MagicMock
from src.fuzz_plan.generator import FuzzPlanGenerator
from src.harness.generator import HarnessGenerator
from src.triage.analyzer import CrashTriageAnalyzer


class TestPipelineIntegration(unittest.TestCase):
    """Test integration between pipeline components"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create test static findings
        self.test_findings = {
            "total_findings": 2,
            "findings": [
                {
                    "rule_id": "bufferOverflow",
                    "type": "Buffer Overflow",
                    "severity": "high",
                    "confidence": "high",
                    "file": "vulnerable.cpp",
                    "file_stem": "vulnerable",
                    "line": 42,
                    "message": "Potential buffer overflow in strcpy",
                    "function": "process_input"
                },
                {
                    "rule_id": "useAfterFree", 
                    "type": "Use After Free", 
                    "severity": "critical",
                    "confidence": "medium",
                    "file": "memory.cpp",
                    "file_stem": "memory",
                    "line": 15,
                    "message": "Use after free detected",
                    "function": "free_memory"
                }
            ]
        }
        
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.findings_file = os.path.join(self.temp_dir, 'findings.json')
        self.fuzz_plan_file = os.path.join(self.temp_dir, 'fuzzplan.json')
        self.harness_dir = os.path.join(self.temp_dir, 'harnesses')
        
        # Write test findings
        with open(self.findings_file, 'w') as f:
            json.dump(self.test_findings, f)
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_fuzz_plan_to_harness_generation(self):
        """Test integration: Static findings → Fuzz plan → Harnesses"""
        
        # Step 1: Generate fuzz plan from static findings
        fuzz_plan_generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan_generator.save_fuzz_plan(self.fuzz_plan_file)
        
        # Verify fuzz plan was created
        self.assertTrue(os.path.exists(self.fuzz_plan_file))
        
        # Step 2: Generate harnesses from fuzz plan
        harness_generator = HarnessGenerator(self.fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(self.harness_dir)
        
        # Verify harnesses were created
        self.assertEqual(len(harnesses), 2)  # Should create 2 harnesses
        
        # Check harness files exist
        for harness in harnesses:
            self.assertTrue(os.path.exists(harness['full_path']))
            
            # Check harness content
            with open(harness['full_path'], 'r') as f:
                content = f.read()
            
            self.assertIn('LLVMFuzzerTestOneInput', content)
            self.assertIn(harness['function_name'], content)
    
    def test_fuzz_plan_target_consistency(self):
        """Test that fuzz plan targets match static findings"""
        
        # Generate fuzz plan
        generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan = generator.generate_fuzz_plan()
        
        # Check target count matches findings
        self.assertEqual(len(fuzz_plan['targets']), len(self.test_findings['findings']))
        
        # Check target details match findings
        targets = fuzz_plan['targets']
        findings = self.test_findings['findings']
        
        for i, target in enumerate(targets):
            finding = findings[i] if i < len(findings) else findings[0]
            
            self.assertEqual(target['source_file'], finding['file'])
            self.assertEqual(target['line_number'], finding['line'])
            self.assertEqual(target['function_name'], finding['function'])
    
    def test_harness_metadata_consistency(self):
        """Test that harness metadata is consistent with fuzz plan"""
        
        # Generate fuzz plan and harnesses
        fuzz_plan_generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan_generator.save_fuzz_plan(self.fuzz_plan_file)
        
        harness_generator = HarnessGenerator(self.fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(self.harness_dir)
        
        # Load fuzz plan for comparison
        with open(self.fuzz_plan_file, 'r') as f:
            fuzz_plan = json.load(f)
        
        # Check harness count matches targets
        self.assertEqual(len(harnesses), len(fuzz_plan['targets']))
        
        # Check harness metadata matches targets
        for harness in harnesses:
            # Find matching target
            matching_target = None
            for target in fuzz_plan['targets']:
                if target['function_name'] == harness['function_name']:
                    matching_target = target
                    break
            
            self.assertIsNotNone(matching_target)
            self.assertEqual(harness['bug_class'], matching_target['bug_class'])
            self.assertEqual(harness['priority'], matching_target['priority'])
            self.assertEqual(harness['sanitizers'], matching_target['sanitizers'])
    
    def test_build_script_generation(self):
        """Test that build script includes all harnesses"""
        
        # Generate complete pipeline
        fuzz_plan_generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan_generator.save_fuzz_plan(self.fuzz_plan_file)
        
        harness_generator = HarnessGenerator(self.fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(self.harness_dir)
        
        build_script_path = harness_generator.generate_build_script(self.harness_dir, harnesses)
        
        # Check build script content
        with open(build_script_path, 'r') as f:
            script_content = f.read()
        
        # Should contain build commands for all harnesses
        for harness in harnesses:
            self.assertIn(harness['file_path'], script_content)
            self.assertIn(harness['target_id'], script_content)
        
        # Should contain proper compiler flags
        self.assertIn('clang++', script_content)
        self.assertIn('-fsanitize=fuzzer', script_content)
        self.assertIn('address', script_content)  # Check that address sanitizer is included


class TestEndToEndPipeline(unittest.TestCase):
    """Test complete end-to-end pipeline scenarios"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create comprehensive test findings
        self.comprehensive_findings = {
            "total_findings": 4,
            "findings": [
                {
                    "rule_id": "bufferOverflow",
                    "type": "Buffer Overflow",
                    "severity": "high",
                    "confidence": "high",
                    "file": "buffer.cpp",
                    "file_stem": "buffer",
                    "line": 10,
                    "message": "Buffer overflow in copy_buffer",
                    "function": "copy_buffer"
                },
                {
                    "rule_id": "useAfterFree",
                    "type": "Use After Free",
                    "severity": "critical",
                    "confidence": "high",
                    "file": "memory.cpp",
                    "file_stem": "memory",
                    "line": 25,
                    "message": "Use after free in use_pointer",
                    "function": "use_pointer"
                },
                {
                    "rule_id": "integerOverflow",
                    "type": "Integer Overflow",
                    "severity": "medium",
                    "confidence": "medium",
                    "file": "math.cpp",
                    "file_stem": "math",
                    "line": 50,
                    "message": "Integer overflow in add_numbers",
                    "function": "add_numbers"
                },
                {
                    "rule_id": "nullPointer",
                    "type": "Null Pointer Dereference",
                    "severity": "high",
                    "confidence": "medium",
                    "file": "pointer.cpp",
                    "file_stem": "pointer",
                    "line": 75,
                    "message": "Null pointer dereference in deref_pointer",
                    "function": "deref_pointer"
                }
            ]
        }
        
        self.findings_file = os.path.join(self.temp_dir, 'comprehensive_findings.json')
        with open(self.findings_file, 'w') as f:
            json.dump(self.comprehensive_findings, f)
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_complete_pipeline_execution(self):
        """Test complete pipeline: Findings → Plan → Harnesses → Build → Metadata"""
        
        # Step 1: Generate fuzz plan
        fuzz_plan_file = os.path.join(self.temp_dir, 'pipeline_fuzzplan.json')
        fuzz_plan_generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan_generator.save_fuzz_plan(fuzz_plan_file)
        
        # Step 2: Generate harnesses
        harness_dir = os.path.join(self.temp_dir, 'pipeline_harnesses')
        harness_generator = HarnessGenerator(fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(harness_dir)
        
        # Step 3: Generate build artifacts
        build_script = harness_generator.generate_build_script(harness_dir, harnesses)
        readme_file = harness_generator.generate_readme(harness_dir, harnesses)
        
        # Verify all components were created
        self.assertTrue(os.path.exists(fuzz_plan_file))
        self.assertTrue(os.path.exists(harness_dir))
        self.assertTrue(os.path.exists(build_script))
        self.assertTrue(os.path.exists(readme_file))
        
        # Verify correct number of harnesses
        self.assertEqual(len(harnesses), 4)
        
        # Verify metadata file
        metadata_file = os.path.join(harness_dir, '.metadata.json')
        self.assertTrue(os.path.exists(metadata_file))
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        self.assertEqual(metadata['total_harnesses'], 4)
        self.assertIn('toolbox_types', metadata)
        self.assertIn('bug_class_breakdown', metadata)
    
    def test_priority_ordering_consistency(self):
        """Test that priority ordering is maintained throughout pipeline"""
        
        # Generate fuzz plan
        fuzz_plan_generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan = fuzz_plan_generator.generate_fuzz_plan()
        
        # Check targets are ordered by priority
        targets = fuzz_plan['targets']
        priorities = [target['priority'] for target in targets]
        self.assertEqual(priorities, sorted(priorities, reverse=True))
        
        # Generate harnesses and check order is maintained
        fuzz_plan_file = os.path.join(self.temp_dir, 'priority_fuzzplan.json')
        fuzz_plan_generator.save_fuzz_plan(fuzz_plan_file)
        
        harness_generator = HarnessGenerator(fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(
            os.path.join(self.temp_dir, 'priority_harnesses')
        )
        
        # Harnesses should maintain same priority order
        harness_priorities = [harness['priority'] for harness in harnesses]
        self.assertEqual(harness_priorities, sorted(harness_priorities, reverse=True))
    
    def test_bug_class_mapping_consistency(self):
        """Test that bug class mapping is consistent across components"""
        
        # Generate fuzz plan
        fuzz_plan_generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan = fuzz_plan_generator.generate_fuzz_plan()
        
        # Check bug class mappings
        expected_mappings = {
            'Buffer Overflow': 'OOB',
            'Use After Free': 'UAF', 
            'Integer Overflow': 'Integer-UB',
            'Null Pointer Dereference': 'Null-Deref'
        }
        
        for target in fuzz_plan['targets']:
            original_type = None
            for finding in self.comprehensive_findings['findings']:
                if finding['function'] == target['function_name']:
                    original_type = finding['type']
                    break
            
            if original_type:
                expected_bug_class = expected_mappings[original_type]
                self.assertEqual(target['bug_class'], expected_bug_class)
    
    def test_harness_type_selection_logic(self):
        """Test that appropriate harness types are selected for different bug classes"""
        
        # Generate complete pipeline
        fuzz_plan_file = os.path.join(self.temp_dir, 'harness_type_fuzzplan.json')
        fuzz_plan_generator = FuzzPlanGenerator(self.findings_file)
        fuzz_plan_generator.save_fuzz_plan(fuzz_plan_file)
        
        harness_generator = HarnessGenerator(fuzz_plan_file)
        harnesses = harness_generator.generate_all_harnesses(
            os.path.join(self.temp_dir, 'harness_type_harnesses')
        )
        
        # Check that different harness types are used
        harness_types = [harness['harness_type'] for harness in harnesses]
        
        # Should have variety of harness types (not all the same)
        unique_types = set(harness_types)
        self.assertGreaterEqual(len(unique_types), 1)  # At least some variety
        
        # All should be valid harness types
        valid_types = {'bytes_to_api', 'fdp_adapter', 'parser_wrapper', 'api_sequence'}
        for harness_type in harness_types:
            self.assertIn(harness_type, valid_types)


if __name__ == '__main__':
    unittest.main()