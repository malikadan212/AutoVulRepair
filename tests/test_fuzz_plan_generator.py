"""
Unit Tests for Fuzz Plan Generator
Tests the core logic of fuzz plan generation from static analysis findings
"""

import unittest
import json
import tempfile
import os
from unittest.mock import patch, mock_open
from src.fuzz_plan.generator import FuzzPlanGenerator


class TestFuzzPlanGenerator(unittest.TestCase):
    """Test cases for FuzzPlanGenerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_findings = {
            "total_findings": 3,
            "findings": [
                {
                    "rule_id": "bufferOverflow",
                    "type": "Buffer Overflow",
                    "severity": "high",
                    "confidence": "high",
                    "file": "test.cpp",
                    "file_stem": "test",
                    "line": 42,
                    "message": "Potential buffer overflow in strcpy",
                    "function": "vulnerable_function"
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
                    "function": "memory_handler"
                },
                {
                    "rule_id": "integerOverflow",
                    "type": "Integer Overflow",
                    "severity": "medium",
                    "confidence": "low",
                    "file": "calc.cpp",
                    "file_stem": "calc",
                    "line": 88,
                    "message": "Integer overflow in addition",
                    "function": "calculate_sum"
                }
            ]
        }
        
        # Create temporary findings file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.test_findings, self.temp_file)
        self.temp_file.close()
        
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_load_static_findings_success(self):
        """Test successful loading of static findings"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        generator.load_findings()
        self.assertEqual(len(generator.findings_data['findings']), 3)
        self.assertEqual(generator.findings_data['findings'][0]['type'], 'Buffer Overflow')
    
    def test_load_static_findings_file_not_found(self):
        """Test handling of missing findings file"""
        generator = FuzzPlanGenerator('nonexistent_file.json')
        with self.assertRaises(FileNotFoundError):
            generator.load_findings()
    
    def test_map_bug_class_buffer_overflow(self):
        """Test bug class mapping for buffer overflow"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        bug_class = generator.infer_bug_class('bufferOverflow')
        self.assertEqual(bug_class, 'OOB')
    
    def test_map_bug_class_use_after_free(self):
        """Test bug class mapping for use after free"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        bug_class = generator.infer_bug_class('useAfterFree')
        self.assertEqual(bug_class, 'UAF')
    
    def test_map_bug_class_unknown(self):
        """Test bug class mapping for unknown types"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        bug_class = generator.infer_bug_class('unknownVulnerability')
        self.assertEqual(bug_class, 'Unknown')
    
    def test_calculate_priority_critical(self):
        """Test priority calculation for critical severity"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        finding = {"severity": "error", "confidence": "high", "rule_id": "useAfterFree", "line": 50}
        priority = generator.calculate_priority(finding)
        self.assertGreater(priority, 10.0)  # Critical UAF should be highest priority
    
    def test_calculate_priority_high(self):
        """Test priority calculation for high severity"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        finding = {"severity": "warning", "confidence": "high", "rule_id": "bufferOverflow", "line": 50}
        priority = generator.calculate_priority(finding)
        self.assertGreater(priority, 6.0)  # High buffer overflow
    
    def test_calculate_priority_medium(self):
        """Test priority calculation for medium severity"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        finding = {"severity": "style", "confidence": "medium", "rule_id": "integerOverflow", "line": 50}
        priority = generator.calculate_priority(finding)
        self.assertGreater(priority, 3.0)  # Medium integer issue
    
    def test_generate_target_id(self):
        """Test target ID generation"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        finding = self.test_findings['findings'][0]
        target = generator.generate_target_metadata(finding)
        self.assertIn('vulnerable_function', target['target_id'])
    
    def test_generate_fuzz_plan_structure(self):
        """Test fuzz plan generation structure"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        fuzz_plan = generator.generate_fuzz_plan()
        
        # Check required fields
        self.assertIn('metadata', fuzz_plan)
        self.assertIn('targets', fuzz_plan)
        self.assertIn('version', fuzz_plan)
        self.assertIn('generated_at', fuzz_plan)
        
        # Check metadata
        metadata = fuzz_plan['metadata']
        self.assertIn('total_findings', metadata)
        self.assertIn('deduplicated_targets', metadata)
        self.assertIn('bug_class_breakdown', metadata)
    
    def test_generate_fuzz_plan_target_count(self):
        """Test correct number of targets generated"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        fuzz_plan = generator.generate_fuzz_plan()
        
        # Should generate targets for all findings
        self.assertEqual(len(fuzz_plan['targets']), 3)
    
    def test_generate_fuzz_plan_target_fields(self):
        """Test target fields are correctly populated"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        fuzz_plan = generator.generate_fuzz_plan()
        
        target = fuzz_plan['targets'][0]
        required_fields = [
            'target_id', 'function_name', 'source_file', 'line_number',
            'bug_class', 'severity', 'priority', 'harness_type', 'sanitizers'
        ]
        
        for field in required_fields:
            self.assertIn(field, target)
    
    def test_generate_fuzz_plan_priority_ordering(self):
        """Test targets are ordered by priority"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        fuzz_plan = generator.generate_fuzz_plan()
        
        targets = fuzz_plan['targets']
        priorities = [target['priority'] for target in targets]
        
        # Should be in descending order (highest priority first)
        self.assertEqual(priorities, sorted(priorities, reverse=True))
    
    def test_save_fuzz_plan(self):
        """Test saving fuzz plan to file"""
        generator = FuzzPlanGenerator(self.temp_file.name)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as output_file:
            output_path = output_file.name
        
        try:
            generator.save_fuzz_plan(output_path)
            
            # Verify file was created and contains valid JSON
            self.assertTrue(os.path.exists(output_path))
            
            with open(output_path, 'r') as f:
                saved_plan = json.load(f)
            
            self.assertIn('targets', saved_plan)
            self.assertIn('metadata', saved_plan)
            
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def test_deduplication(self):
        """Test deduplication of similar findings"""
        # Create findings with duplicates
        duplicate_findings = {
            "total_findings": 2,
            "findings": [
                {
                    "rule_id": "bufferOverflow",
                    "type": "Buffer Overflow",
                    "severity": "high",
                    "confidence": "high",
                    "file": "test.cpp",
                    "file_stem": "test",
                    "line": 42,
                    "message": "Buffer overflow detected",
                    "function": "same_function"
                },
                {
                    "rule_id": "bufferOverflow",
                    "type": "Buffer Overflow",
                    "severity": "high",
                    "confidence": "high",
                    "file": "test.cpp",
                    "file_stem": "test",
                    "line": 43,  # Different line, same function
                    "message": "Buffer overflow detected",
                    "function": "same_function"
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as temp_dup:
            json.dump(duplicate_findings, temp_dup)
            temp_dup_path = temp_dup.name
        
        try:
            generator = FuzzPlanGenerator(temp_dup_path)
            fuzz_plan = generator.generate_fuzz_plan()
            
            # Should deduplicate to 1 target
            self.assertEqual(len(fuzz_plan['targets']), 1)
            
        finally:
            os.unlink(temp_dup_path)


if __name__ == '__main__':
    unittest.main()