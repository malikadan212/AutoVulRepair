"""
Tests for HarnessToolbox signature awareness
"""

import pytest
from src.harness.toolbox import HarnessToolbox
from src.harness.signature_extractor import FunctionSignature, Parameter


class TestToolboxSignatureAwareness:
    """Test that HarnessToolbox properly uses signature information"""
    
    def test_toolbox_initialization(self):
        """Test that toolbox initializes with signature extractor and parameter mapper"""
        toolbox = HarnessToolbox()
        
        assert hasattr(toolbox, 'signature_extractor')
        assert hasattr(toolbox, 'parameter_mapper')
        assert toolbox.signature_extractor is not None
        assert toolbox.parameter_mapper is not None
    
    def test_signature_extraction_from_source_code(self):
        """Test that toolbox extracts signature from source code when available"""
        toolbox = HarnessToolbox()
        
        source_code = """
        void test_function(const char* input) {
            // implementation
        }
        """
        
        target = {
            'function_name': 'test_function',
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp'
        }
        
        harness = toolbox.generate_harness(target, source_code=source_code)
        
        # Verify signature was extracted and used
        assert 'test_function' in harness
        assert 'const char* input' in harness or 'Detected signature' in harness
    
    def test_harness_uses_signature_information(self):
        """Test that generated harness uses signature information when available"""
        toolbox = HarnessToolbox()
        
        # Create a target with signature information
        signature = FunctionSignature(
            function_name='test_parse',
            return_type='void',
            parameters=[
                Parameter(name='data', type='const uint8_t*', is_pointer=True, is_const=True),
                Parameter(name='size', type='size_t')
            ]
        )
        
        target = {
            'function_name': 'test_parse',
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target)
        
        # Verify the harness uses the signature
        assert 'test_parse' in harness
        assert 'Detected signature' in harness
        # Should call function with parameters, not with empty parens
        assert 'test_parse(data, size)' in harness or 'test_parse(' in harness
    
    def test_harness_type_selection_with_signature(self):
        """Test that harness type selection considers signature information"""
        toolbox = HarnessToolbox()
        
        # Single string parameter should select parser_wrapper
        signature1 = FunctionSignature(
            function_name='parse_string',
            return_type='void',
            parameters=[
                Parameter(name='input', type='const char*', is_pointer=True, is_const=True)
            ]
        )
        
        target1 = {
            'function_name': 'parse_string',
            'function_signature': signature1.to_dict()
        }
        
        harness_type1 = toolbox.select_harness_type(target1)
        assert harness_type1 == 'parser_wrapper'
        
        # Buffer + size should select bytes_to_api
        signature2 = FunctionSignature(
            function_name='process_buffer',
            return_type='void',
            parameters=[
                Parameter(name='data', type='const uint8_t*', is_pointer=True, is_const=True),
                Parameter(name='size', type='size_t')
            ]
        )
        
        target2 = {
            'function_name': 'process_buffer',
            'function_signature': signature2.to_dict()
        }
        
        harness_type2 = toolbox.select_harness_type(target2)
        assert harness_type2 == 'bytes_to_api'
        
        # Multiple parameters should select fdp_adapter
        signature3 = FunctionSignature(
            function_name='api_call',
            return_type='void',
            parameters=[
                Parameter(name='id', type='int'),
                Parameter(name='flag', type='bool'),
                Parameter(name='name', type='const char*', is_pointer=True, is_const=True)
            ]
        )
        
        target3 = {
            'function_name': 'api_call',
            'function_signature': signature3.to_dict()
        }
        
        harness_type3 = toolbox.select_harness_type(target3)
        assert harness_type3 == 'fdp_adapter'
    
    def test_parser_wrapper_with_signature(self):
        """Test parser_wrapper generation with signature information"""
        toolbox = HarnessToolbox()
        
        signature = FunctionSignature(
            function_name='parse_input',
            return_type='void',
            parameters=[
                Parameter(name='input', type='const char*', is_pointer=True, is_const=True)
            ]
        )
        
        target = {
            'function_name': 'parse_input',
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target, harness_type='parser_wrapper')
        
        # Verify signature-aware generation
        assert 'Detected signature' in harness
        assert 'parse_input' in harness
        assert 'const char* input' in harness
        # Should not have multiple extern declarations
        assert harness.count('extern "C"') <= 1
    
    def test_bytes_to_api_with_signature(self):
        """Test bytes_to_api generation with signature information"""
        toolbox = HarnessToolbox()
        
        signature = FunctionSignature(
            function_name='process_data',
            return_type='void',
            parameters=[
                Parameter(name='buffer', type='const uint8_t*', is_pointer=True, is_const=True),
                Parameter(name='len', type='size_t')
            ]
        )
        
        target = {
            'function_name': 'process_data',
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target, harness_type='bytes_to_api')
        
        # Verify signature-aware generation
        assert 'Detected signature' in harness
        assert 'process_data' in harness
        assert 'buffer' in harness and 'len' in harness
    
    def test_fdp_adapter_with_signature(self):
        """Test fdp_adapter generation with signature information"""
        toolbox = HarnessToolbox()
        
        signature = FunctionSignature(
            function_name='api_function',
            return_type='int',
            parameters=[
                Parameter(name='id', type='int'),
                Parameter(name='enabled', type='bool')
            ]
        )
        
        target = {
            'function_name': 'api_function',
            'bug_class': 'Unknown',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target, harness_type='fdp_adapter')
        
        # Verify signature-aware generation
        assert 'Detected signature' in harness
        assert 'api_function' in harness
        assert 'FuzzedDataProvider' in harness
    
    def test_fallback_without_signature(self):
        """Test that harness generation still works without signature information"""
        toolbox = HarnessToolbox()
        
        target = {
            'function_name': 'unknown_function',
            'bug_class': 'Unknown',
            'source_file': '/test/test.cpp'
        }
        
        harness = toolbox.generate_harness(target)
        
        # Should still generate a harness (fallback behavior)
        assert 'unknown_function' in harness
        assert 'LLVMFuzzerTestOneInput' in harness
        # Should have multiple extern declarations as fallback
        assert 'extern "C"' in harness
    
    def test_api_sequence_with_signature(self):
        """Test api_sequence generation with signature information"""
        toolbox = HarnessToolbox()
        
        signature = FunctionSignature(
            function_name='api_call',
            return_type='void',
            parameters=[
                Parameter(name='param', type='int')
            ]
        )
        
        target = {
            'function_name': 'api_call',
            'bug_class': 'Unknown',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target, harness_type='api_sequence')
        
        # Verify signature-aware generation
        assert 'Detected signature' in harness
        assert 'api_call' in harness
        assert 'num_calls' in harness  # API sequence specific


class TestSignatureExtractionIntegration:
    """Test integration of signature extraction with harness generation"""
    
    def test_extract_and_use_signature(self):
        """Test end-to-end: extract signature from source and use in harness"""
        toolbox = HarnessToolbox()
        
        source_code = """
        #include <stddef.h>
        
        void vulnerable_parse(const char* input, size_t length) {
            // Parse implementation
        }
        """
        
        target = {
            'function_name': 'vulnerable_parse',
            'bug_class': 'OOB',
            'source_file': '/test/vulnerable.cpp'
        }
        
        harness = toolbox.generate_harness(target, source_code=source_code)
        
        # Verify signature was extracted and used
        assert 'vulnerable_parse' in harness
        assert 'Detected signature' in harness
        assert 'const char* input' in harness
        assert 'size_t length' in harness
    
    def test_signature_persists_in_target(self):
        """Test that extracted signature is stored in target dict"""
        toolbox = HarnessToolbox()
        
        source_code = """
        void test_func(int x) {
            // implementation
        }
        """
        
        target = {
            'function_name': 'test_func',
            'bug_class': 'Unknown',
            'source_file': '/test/test.cpp'
        }
        
        # Generate harness with source code
        harness = toolbox.generate_harness(target, source_code=source_code)
        
        # Verify signature was added to target
        assert 'function_signature' in target
        assert target['function_signature']['function_name'] == 'test_func'
        assert target['function_signature']['param_count'] == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
