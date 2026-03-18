"""
Unit Tests for Harness Generator
Tests the harness generation logic and toolbox approach
"""

import unittest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock
from src.harness.generator import HarnessGenerator
from src.harness.toolbox import HarnessToolbox


class TestHarnessGenerator(unittest.TestCase):
    """Test cases for HarnessGenerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_fuzz_plan = {
            "metadata": {
                "total_findings": 2,
                "generation_timestamp": "2024-01-01T00:00:00"
            },
            "targets": [
                {
                    "target_id": "fuzz_test_buffer_overflow",
                    "function_name": "process_buffer",
                    "source_file": "test.cpp",
                    "line_number": 42,
                    "bug_class": "Buffer-Overflow",
                    "severity": "high",
                    "priority": 8,
                    "harness_type": "bytes_to_api",
                    "sanitizers": ["ASan", "UBSan"]
                },
                {
                    "target_id": "fuzz_test_api_call",
                    "function_name": "api_handler",
                    "source_file": "api.cpp",
                    "line_number": 15,
                    "bug_class": "Integer-UB",
                    "severity": "medium",
                    "priority": 5,
                    "harness_type": "fdp_adapter",
                    "sanitizers": ["ASan", "UBSan"]
                }
            ]
        }
        
        # Create temporary fuzz plan file
        self.temp_plan_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.test_fuzz_plan, self.temp_plan_file)
        self.temp_plan_file.close()
        
        # Create temporary output directory
        self.temp_output_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_plan_file.name):
            os.unlink(self.temp_plan_file.name)
        
        # Clean up output directory
        import shutil
        if os.path.exists(self.temp_output_dir):
            shutil.rmtree(self.temp_output_dir)
    
    def test_load_fuzz_plan_success(self):
        """Test successful loading of fuzz plan"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        self.assertEqual(len(generator.fuzz_plan['targets']), 2)
        self.assertEqual(generator.fuzz_plan['targets'][0]['function_name'], 'process_buffer')
    
    def test_load_fuzz_plan_file_not_found(self):
        """Test handling of missing fuzz plan file"""
        with self.assertRaises(Exception):
            HarnessGenerator('nonexistent_plan.json')
    
    def test_sanitize_function_name(self):
        """Test function name sanitization"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        
        # Test normal name
        self.assertEqual(generator._sanitize_function_name('normal_function'), 'normal_function')
        
        # Test name with special characters
        self.assertEqual(generator._sanitize_function_name('func::with->special<chars>'), 'func_with_special_chars')
        
        # Test name with consecutive underscores
        self.assertEqual(generator._sanitize_function_name('func___name'), 'func_name')
    
    def test_format_sanitizers(self):
        """Test sanitizer formatting for compilation"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        
        # Test standard sanitizers
        formatted = generator._format_sanitizers(['ASan', 'UBSan'])
        self.assertEqual(formatted, 'address,undefined')
        
        # Test unknown sanitizer
        formatted = generator._format_sanitizers(['UnknownSan'])
        self.assertEqual(formatted, 'address,undefined')  # Default fallback
        
        # Test empty list
        formatted = generator._format_sanitizers([])
        self.assertEqual(formatted, 'address,undefined')  # Default fallback
    
    def test_extract_file_stem(self):
        """Test file stem extraction"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        
        target = {'source_file': '/path/to/test.cpp'}
        stem = generator._extract_file_stem(target)
        self.assertEqual(stem, 'test')
        
        # Test with no source file
        target = {}
        stem = generator._extract_file_stem(target)
        self.assertEqual(stem, 'unknown')
    
    def test_generate_harness_bytes_to_api(self):
        """Test generation of bytes_to_api harness"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        target = self.test_fuzz_plan['targets'][0]
        
        harness_meta = generator.generate_harness(target, self.temp_output_dir)
        
        # Check metadata
        self.assertEqual(harness_meta['function_name'], 'process_buffer')
        self.assertEqual(harness_meta['harness_type'], 'bytes_to_api')
        self.assertTrue(harness_meta['name'].endswith('.cc'))
        
        # Check file was created
        self.assertTrue(os.path.exists(harness_meta['full_path']))
        
        # Check file content
        with open(harness_meta['full_path'], 'r') as f:
            content = f.read()
        
        self.assertIn('LLVMFuzzerTestOneInput', content)
        self.assertIn('process_buffer', content)
        self.assertIn('#include <stdint.h>', content)
    
    def test_generate_harness_fdp_adapter(self):
        """Test generation of fdp_adapter harness"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        target = self.test_fuzz_plan['targets'][1]
        
        harness_meta = generator.generate_harness(target, self.temp_output_dir)
        
        # Check metadata
        self.assertEqual(harness_meta['harness_type'], 'fdp_adapter')
        
        # Check file content
        with open(harness_meta['full_path'], 'r') as f:
            content = f.read()
        
        self.assertIn('FuzzedDataProvider', content)
        self.assertIn('api_handler', content)
        self.assertIn('#include <fuzzer/FuzzedDataProvider.h>', content)
    
    def test_generate_all_harnesses(self):
        """Test generation of all harnesses from fuzz plan"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        harnesses = generator.generate_all_harnesses(self.temp_output_dir)
        
        # Should generate 2 harnesses
        self.assertEqual(len(harnesses), 2)
        
        # Check all files were created
        for harness in harnesses:
            self.assertTrue(os.path.exists(harness['full_path']))
        
        # Check metadata file was created
        metadata_path = os.path.join(self.temp_output_dir, '.metadata.json')
        self.assertTrue(os.path.exists(metadata_path))
    
    def test_generate_build_script(self):
        """Test build script generation"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        harnesses = generator.generate_all_harnesses(self.temp_output_dir)
        
        build_script_path = generator.generate_build_script(self.temp_output_dir, harnesses)
        
        # Check script was created
        self.assertTrue(os.path.exists(build_script_path))
        
        # Check script content
        with open(build_script_path, 'r') as f:
            content = f.read()
        
        self.assertIn('#!/bin/bash', content)
        self.assertIn('clang++', content)
        self.assertIn('-fsanitize=fuzzer', content)
        self.assertIn('process_buffer', content)
    
    def test_generate_readme(self):
        """Test README generation"""
        generator = HarnessGenerator(self.temp_plan_file.name)
        harnesses = generator.generate_all_harnesses(self.temp_output_dir)
        
        readme_path = generator.generate_readme(self.temp_output_dir, harnesses)
        
        # Check README was created
        self.assertTrue(os.path.exists(readme_path))
        
        # Check README content
        with open(readme_path, 'r') as f:
            content = f.read()
        
        self.assertIn('# Fuzzing Harnesses', content)
        self.assertIn('Total Harnesses: 2', content)
        self.assertIn('process_buffer', content)
        self.assertIn('api_handler', content)


class TestHarnessToolbox(unittest.TestCase):
    """Test cases for HarnessToolbox class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.toolbox = HarnessToolbox()
    
    def test_select_harness_type_explicit(self):
        """Test explicit harness type selection"""
        target = {'harness_type': 'fdp_adapter'}
        harness_type = self.toolbox.select_harness_type(target)
        self.assertEqual(harness_type, 'fdp_adapter')
    
    def test_select_harness_type_parser(self):
        """Test parser harness type selection"""
        target = {
            'function_name': 'parse_json',
            'bug_class': 'OOB'
        }
        harness_type = self.toolbox.select_harness_type(target)
        self.assertEqual(harness_type, 'parser_wrapper')
    
    def test_select_harness_type_stateful_api(self):
        """Test stateful API harness type selection"""
        target = {'function_name': 'session_init'}
        harness_type = self.toolbox.select_harness_type(target)
        self.assertEqual(harness_type, 'api_sequence')
    
    def test_select_harness_type_buffer_processing(self):
        """Test buffer processing harness type selection"""
        target = {'function_name': 'process_buffer'}
        harness_type = self.toolbox.select_harness_type(target)
        self.assertEqual(harness_type, 'bytes_to_api')
    
    def test_select_harness_type_default(self):
        """Test default harness type selection"""
        target = {'function_name': 'unknown_function'}
        harness_type = self.toolbox.select_harness_type(target)
        self.assertEqual(harness_type, 'bytes_to_api')  # Default
    
    def test_generate_bytes_to_api_harness(self):
        """Test bytes_to_api harness generation"""
        target = {
            'function_name': 'test_function',
            'bug_class': 'Buffer-Overflow',
            'source_file': 'test.cpp'
        }
        
        harness_code = self.toolbox._generate_bytes_to_api(target)
        
        self.assertIn('LLVMFuzzerTestOneInput', harness_code)
        self.assertIn('test_function', harness_code)
        self.assertIn('bytes_to_api', harness_code)
        self.assertIn('#include <stdint.h>', harness_code)
    
    def test_generate_fdp_adapter_harness(self):
        """Test fdp_adapter harness generation"""
        target = {
            'function_name': 'api_call',
            'bug_class': 'Integer-UB',
            'source_file': 'api.cpp'
        }
        
        harness_code = self.toolbox._generate_fdp_adapter(target)
        
        self.assertIn('FuzzedDataProvider', harness_code)
        self.assertIn('api_call', harness_code)
        self.assertIn('fdp_adapter', harness_code)
        self.assertIn('#include <fuzzer/FuzzedDataProvider.h>', harness_code)
    
    def test_generate_parser_wrapper_harness(self):
        """Test parser_wrapper harness generation"""
        target = {
            'function_name': 'parse_input',
            'bug_class': 'OOB',
            'source_file': 'parser.cpp'
        }
        
        harness_code = self.toolbox._generate_parser_wrapper(target)
        
        self.assertIn('parse_input', harness_code)
        self.assertIn('parser_wrapper', harness_code)
        self.assertIn('malloc', harness_code)
        self.assertIn('null-terminated', harness_code.lower())
    
    def test_generate_api_sequence_harness(self):
        """Test api_sequence harness generation"""
        target = {
            'function_name': 'session_command',
            'bug_class': 'UAF',
            'source_file': 'session.cpp'
        }
        
        harness_code = self.toolbox._generate_api_sequence(target)
        
        self.assertIn('session_command', harness_code)
        self.assertIn('api_sequence', harness_code)
        self.assertIn('num_calls', harness_code)
        self.assertIn('for (int i = 0', harness_code)


if __name__ == '__main__':
    unittest.main()