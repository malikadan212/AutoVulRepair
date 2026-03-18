"""
Property-Based Tests for Harness Generation
Tests properties 1, 2, and 6 from the design document
"""

import re
import pytest
from hypothesis import given, strategies as st, settings, HealthCheck, assume
from src.harness.toolbox import HarnessToolbox
from src.harness.signature_extractor import FunctionSignature, Parameter


# Strategy for generating function signatures
@st.composite
def function_signature_strategy(draw):
    """Generate random function signatures"""
    function_name = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll'), min_codepoint=65, max_codepoint=122),
        min_size=3,
        max_size=20
    ))
    
    return_types = ['void', 'int', 'bool', 'char*', 'const char*', 'uint8_t*', 'size_t']
    return_type = draw(st.sampled_from(return_types))
    
    # Generate 0-5 parameters
    num_params = draw(st.integers(min_value=0, max_value=5))
    parameters = []
    
    for i in range(num_params):
        param_types = [
            'int', 'bool', 'char*', 'const char*', 
            'uint8_t*', 'const uint8_t*', 'size_t',
            'float', 'double', 'void*', 'const void*'
        ]
        param_type = draw(st.sampled_from(param_types))
        param_name = f'param{i}'
        
        is_pointer = '*' in param_type
        is_const = 'const' in param_type
        
        parameters.append(Parameter(
            name=param_name,
            type=param_type,
            is_pointer=is_pointer,
            is_const=is_const
        ))
    
    return FunctionSignature(
        function_name=function_name,
        return_type=return_type,
        parameters=parameters
    )


class TestHarnessGenerationProperties:
    """Property-based tests for harness generation"""
    
    @given(function_signature_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_property_1_generated_harnesses_use_prepared_data(self, signature):
        """
        **Feature: harness-parameter-passing, Property 1: Generated harnesses use prepared data**
        
        Property: For any target function and generated harness, when the harness prepares 
        input data from fuzzer bytes, the generated function call should include that 
        prepared data as an argument.
        
        **Validates: Requirements 1.1, 1.2, 1.5**
        """
        # Skip if function name is not valid C identifier
        assume(signature.function_name.isidentifier())
        assume(len(signature.function_name) > 0)
        
        toolbox = HarnessToolbox()
        
        target = {
            'function_name': signature.function_name,
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        # Test with different harness types
        harness_types = ['parser_wrapper', 'bytes_to_api', 'fdp_adapter', 'api_sequence']
        
        for harness_type in harness_types:
            harness = toolbox.generate_harness(target, harness_type=harness_type)
            
            # If signature has parameters, verify they're used
            if signature.parameters:
                # Check that parameter names appear in the harness
                for param in signature.parameters:
                    # The parameter name should appear in the harness
                    # Either as a variable declaration or in the function call
                    assert param.name in harness, (
                        f"Parameter '{param.name}' not found in {harness_type} harness"
                    )
                
                # Check that the function is actually called with arguments
                # Look for function_name followed by parentheses with content
                function_call_pattern = rf'{re.escape(signature.function_name)}\s*\([^)]+\)'
                assert re.search(function_call_pattern, harness), (
                    f"Function '{signature.function_name}' not called with arguments in {harness_type} harness"
                )
            else:
                # No parameters - function should be called with empty parens
                function_call_pattern = rf'{re.escape(signature.function_name)}\s*\(\s*\)'
                assert re.search(function_call_pattern, harness), (
                    f"Function '{signature.function_name}' not called correctly in {harness_type} harness"
                )
    
    @given(function_signature_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_property_2_parameter_count_matches_signature(self, signature):
        """
        **Feature: harness-parameter-passing, Property 2: Parameter count matches signature**
        
        Property: For any function signature with N parameters, the generated harness 
        should call the function with exactly N arguments.
        
        **Validates: Requirements 1.3, 1.4**
        """
        # Skip if function name is not valid C identifier
        assume(signature.function_name.isidentifier())
        assume(len(signature.function_name) > 0)
        
        toolbox = HarnessToolbox()
        
        target = {
            'function_name': signature.function_name,
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        # Test with different harness types
        harness_types = ['parser_wrapper', 'bytes_to_api', 'fdp_adapter', 'api_sequence']
        
        for harness_type in harness_types:
            harness = toolbox.generate_harness(target, harness_type=harness_type)
            
            # Find the function call in the generated harness
            # Look for: function_name(arg1, arg2, ...)
            function_call_pattern = rf'{re.escape(signature.function_name)}\s*\(([^)]*)\)'
            matches = re.findall(function_call_pattern, harness)
            
            # Should find at least one function call
            assert len(matches) > 0, (
                f"No function call found for '{signature.function_name}' in {harness_type} harness"
            )
            
            # Check the first function call (main call, not in comments)
            # Find the actual call (not in comments)
            for match in matches:
                # Skip if this looks like it's in a comment
                call_context = harness[harness.find(f'{signature.function_name}({match})') - 10:
                                       harness.find(f'{signature.function_name}({match})')]
                if '//' in call_context:
                    continue
                
                # Count arguments in the function call
                args_str = match.strip()
                if not args_str:
                    # Empty arguments
                    arg_count = 0
                else:
                    # Count commas to determine argument count
                    # This is a simple heuristic - count top-level commas
                    arg_count = args_str.count(',') + 1
                
                expected_count = len(signature.parameters)
                
                # The argument count should match the parameter count
                assert arg_count == expected_count, (
                    f"Parameter count mismatch in {harness_type} harness: "
                    f"expected {expected_count}, got {arg_count} "
                    f"for function '{signature.function_name}'"
                )
                
                # Found a valid call, no need to check others
                break
    
    @given(function_signature_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_property_6_template_uses_signature_information(self, signature):
        """
        **Feature: harness-parameter-passing, Property 6: Template uses signature information**
        
        Property: For any harness template rendered with signature information, 
        the generated code should reference the parameters from that signature.
        
        **Validates: Requirements 4.2, 4.3, 4.5**
        """
        # Skip if function name is not valid C identifier
        assume(signature.function_name.isidentifier())
        assume(len(signature.function_name) > 0)
        
        toolbox = HarnessToolbox()
        
        target = {
            'function_name': signature.function_name,
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        # Test with different harness types
        harness_types = ['parser_wrapper', 'bytes_to_api', 'fdp_adapter', 'api_sequence']
        
        for harness_type in harness_types:
            harness = toolbox.generate_harness(target, harness_type=harness_type)
            
            # Verify signature comment is present
            assert 'Detected signature' in harness, (
                f"Signature comment not found in {harness_type} harness"
            )
            
            # Verify function name appears in signature comment
            assert signature.function_name in harness, (
                f"Function name '{signature.function_name}' not in {harness_type} harness"
            )
            
            # If there are parameters, verify they're referenced
            if signature.parameters:
                # At least one parameter should be mentioned in the harness
                param_found = False
                for param in signature.parameters:
                    if param.name in harness or param.type in harness:
                        param_found = True
                        break
                
                assert param_found, (
                    f"No parameters from signature found in {harness_type} harness"
                )
                
                # Verify that parameter preparation code exists
                # Look for common patterns like variable declarations
                has_preparation = any([
                    'std::string' in harness,
                    'FuzzedDataProvider' in harness,
                    'reinterpret_cast' in harness,
                    'static_cast' in harness,
                    'ConsumeIntegral' in harness,
                    'ConsumeBool' in harness,
                    'ConsumeRandomLengthString' in harness,
                ])
                
                assert has_preparation, (
                    f"No parameter preparation code found in {harness_type} harness"
                )


class TestHarnessGenerationEdgeCases:
    """Test edge cases for harness generation"""
    
    def test_empty_parameter_list(self):
        """Test harness generation with no parameters"""
        toolbox = HarnessToolbox()
        
        signature = FunctionSignature(
            function_name='no_params_func',
            return_type='void',
            parameters=[]
        )
        
        target = {
            'function_name': 'no_params_func',
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target, harness_type='parser_wrapper')
        
        # Should call function with empty parentheses
        assert 'no_params_func()' in harness
    
    def test_single_string_parameter(self):
        """Test harness generation with single string parameter"""
        toolbox = HarnessToolbox()
        
        signature = FunctionSignature(
            function_name='parse_string',
            return_type='void',
            parameters=[
                Parameter(name='input', type='const char*', is_pointer=True, is_const=True)
            ]
        )
        
        target = {
            'function_name': 'parse_string',
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target, harness_type='parser_wrapper')
        
        # Should prepare string and pass it
        assert 'input' in harness
        assert 'parse_string(input)' in harness
    
    def test_buffer_size_pattern(self):
        """Test harness generation with buffer + size pattern"""
        toolbox = HarnessToolbox()
        
        signature = FunctionSignature(
            function_name='process_buffer',
            return_type='void',
            parameters=[
                Parameter(name='buffer', type='const uint8_t*', is_pointer=True, is_const=True),
                Parameter(name='size', type='size_t')
            ]
        )
        
        target = {
            'function_name': 'process_buffer',
            'bug_class': 'OOB',
            'source_file': '/test/test.cpp',
            'function_signature': signature.to_dict()
        }
        
        harness = toolbox.generate_harness(target, harness_type='bytes_to_api')
        
        # Should pass buffer and size
        assert 'buffer' in harness
        assert 'size' in harness
        assert 'process_buffer(buffer, size)' in harness


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
