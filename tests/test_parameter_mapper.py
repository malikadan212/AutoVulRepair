"""
Property-based tests for parameter mapping module
Feature: harness-parameter-passing
"""

import pytest
import re
from hypothesis import given, strategies as st, settings, HealthCheck, assume
from src.harness.parameter_mapper import ParameterMapper, ParameterMapping
from src.harness.signature_extractor import (
    FunctionSignature,
    Parameter
)


# Strategy for generating valid C/C++ identifiers
@st.composite
def c_identifier(draw):
    """Generate valid C/C++ identifier"""
    first_char = draw(st.sampled_from('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'))
    rest = draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_',
        min_size=0,
        max_size=15
    ))
    return first_char + rest


# Strategy for generating parameters of specific types
@st.composite
def typed_parameter(draw, type_category):
    """Generate a parameter of a specific type category"""
    param_name = draw(c_identifier())
    
    if type_category == 'string':
        param_type = draw(st.sampled_from([
            'char*', 'const char*', 'std::string', 'const std::string&'
        ]))
        is_pointer = '*' in param_type
        is_const = 'const' in param_type
        is_reference = '&' in param_type
    
    elif type_category == 'buffer':
        param_type = draw(st.sampled_from([
            'uint8_t*', 'const uint8_t*', 'void*', 'const void*',
            'unsigned char*', 'const unsigned char*'
        ]))
        is_pointer = True
        is_const = 'const' in param_type
        is_reference = False
    
    elif type_category == 'size':
        param_type = draw(st.sampled_from([
            'size_t', 'int', 'unsigned int', 'uint32_t', 'unsigned', 'long'
        ]))
        is_pointer = False
        is_const = False
        is_reference = False
    
    elif type_category == 'integer':
        param_type = draw(st.sampled_from([
            'int', 'long', 'short', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
            'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'unsigned', 'signed'
        ]))
        is_pointer = False
        is_const = False
        is_reference = False
    
    elif type_category == 'boolean':
        param_type = draw(st.sampled_from(['bool', '_Bool']))
        is_pointer = False
        is_const = False
        is_reference = False
    
    elif type_category == 'float':
        param_type = draw(st.sampled_from(['float', 'double', 'long double']))
        is_pointer = False
        is_const = False
        is_reference = False
    
    else:
        # Generic type
        param_type = 'int'
        is_pointer = False
        is_const = False
        is_reference = False
    
    return Parameter(
        name=param_name,
        type=param_type,
        is_pointer=is_pointer,
        is_const=is_const,
        is_reference=is_reference
    )


# Strategy for generating function signatures with various parameter types
@st.composite
def function_signature_with_params(draw):
    """Generate a function signature with random parameters"""
    function_name = draw(c_identifier())
    return_type = draw(st.sampled_from(['void', 'int', 'bool', 'char*']))
    
    # Generate 0-5 parameters of various types
    param_count = draw(st.integers(min_value=0, max_value=5))
    parameters = []
    
    for _ in range(param_count):
        type_category = draw(st.sampled_from([
            'string', 'buffer', 'size', 'integer', 'boolean', 'float'
        ]))
        param = draw(typed_parameter(type_category))
        parameters.append(param)
    
    return FunctionSignature(
        function_name=function_name,
        return_type=return_type,
        parameters=parameters
    )


class TestParameterMapping:
    """Property-based tests for parameter mapping"""
    
    @given(function_signature_with_params())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_property_5_parameter_type_mapping_consistency(self, signature):
        """
        **Feature: harness-parameter-passing, Property 5: Parameter type mapping consistency**
        
        For any parameter type in a function signature, 
        the parameter mapper should generate preparation code that produces 
        a value compatible with that type.
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
        """
        mapper = ParameterMapper()
        
        # Generate mapping
        mapping = mapper.map_parameters(signature, harness_type='parser_wrapper')
        
        # Property 1: Mapping should be generated successfully
        assert mapping is not None, "Mapping should not be None"
        assert isinstance(mapping, ParameterMapping), "Should return ParameterMapping object"
        
        # Property 2: Preparation code should be non-empty for functions with parameters
        if len(signature.parameters) > 0:
            assert mapping.preparation_code, "Preparation code should not be empty for functions with parameters"
        
        # Property 3: Function call should include the function name
        assert signature.function_name in mapping.function_call, \
            f"Function call should include function name '{signature.function_name}'"
        
        # Property 4: Function call should have correct number of arguments
        # Extract arguments from function call
        call_match = re.search(rf'{re.escape(signature.function_name)}\((.*?)\)', mapping.function_call)
        if call_match:
            args_str = call_match.group(1).strip()
            if args_str:
                # Count arguments by splitting on commas (simple heuristic)
                arg_count = len([a.strip() for a in args_str.split(',') if a.strip()])
            else:
                arg_count = 0
            
            expected_count = len(signature.parameters)
            assert arg_count == expected_count, \
                f"Expected {expected_count} arguments, got {arg_count} in call: {mapping.function_call}"
        
        # Property 5: Each parameter should have corresponding preparation or usage
        for param in signature.parameters:
            param_name = param.name
            # Parameter name should appear in either preparation code or function call
            appears_in_prep = param_name in mapping.preparation_code
            appears_in_call = param_name in mapping.function_call
            
            assert appears_in_prep or appears_in_call, \
                f"Parameter '{param_name}' should appear in preparation code or function call"
        
        # Property 6: Type-specific validation
        for param in signature.parameters:
            self._validate_type_specific_mapping(param, mapping)
    
    def _validate_type_specific_mapping(self, param: Parameter, mapping: ParameterMapping):
        """Validate type-specific mapping properties"""
        mapper = ParameterMapper()
        
        # String types should have string handling
        if mapper._is_string_type(param):
            # Should have string-related code (c_str, string, or char*)
            has_string_handling = (
                'string' in mapping.preparation_code.lower() or
                'c_str' in mapping.preparation_code or
                'char*' in mapping.preparation_code
            )
            assert has_string_handling, \
                f"String parameter '{param.name}' should have string handling in preparation code"
        
        # Buffer types should have buffer/pointer handling
        elif mapper._is_buffer_type(param):
            # Should have pointer/buffer-related code
            has_buffer_handling = (
                'reinterpret_cast' in mapping.preparation_code or
                'data' in mapping.preparation_code.lower() or
                'buffer' in mapping.preparation_code.lower()
            )
            assert has_buffer_handling, \
                f"Buffer parameter '{param.name}' should have buffer handling in preparation code"
        
        # Integer types should have integer extraction
        elif mapper._is_integer_type(param):
            # Should have integer-related code
            has_integer_handling = (
                'ConsumeIntegral' in mapping.preparation_code or
                'reinterpret_cast' in mapping.preparation_code or
                param.type in mapping.preparation_code
            )
            assert has_integer_handling, \
                f"Integer parameter '{param.name}' should have integer handling in preparation code"
        
        # Boolean types should have boolean extraction
        elif mapper._is_boolean_type(param):
            # Should have boolean-related code
            has_boolean_handling = (
                'ConsumeBool' in mapping.preparation_code or
                'bool' in mapping.preparation_code
            )
            assert has_boolean_handling, \
                f"Boolean parameter '{param.name}' should have boolean handling in preparation code"
        
        # Float types should have float extraction
        elif mapper._is_float_type(param):
            # Should have float-related code
            has_float_handling = (
                'ConsumeFloatingPoint' in mapping.preparation_code or
                'float' in mapping.preparation_code.lower() or
                'double' in mapping.preparation_code.lower()
            )
            assert has_float_handling, \
                f"Float parameter '{param.name}' should have float handling in preparation code"


class TestParameterMappingPatterns:
    """Example-based tests for common parameter patterns"""
    
    def test_single_string_parameter(self):
        """Test mapping for single string parameter (Requirement 3.1)"""
        mapper = ParameterMapper()
        
        sig = FunctionSignature(
            function_name="test_func",
            return_type="void",
            parameters=[
                Parameter(name="input", type="const char*", is_pointer=True, is_const=True)
            ]
        )
        
        mapping = mapper.map_parameters(sig)
        
        assert mapping is not None
        assert "input" in mapping.function_call
        assert "string" in mapping.preparation_code.lower() or "char" in mapping.preparation_code
    
    def test_buffer_and_size_parameters(self):
        """Test mapping for buffer + size pattern (Requirement 3.3)"""
        mapper = ParameterMapper()
        
        sig = FunctionSignature(
            function_name="process_data",
            return_type="void",
            parameters=[
                Parameter(name="data", type="const uint8_t*", is_pointer=True, is_const=True),
                Parameter(name="size", type="size_t")
            ]
        )
        
        mapping = mapper.map_parameters(sig)
        
        assert mapping is not None
        assert "data" in mapping.function_call
        assert "size" in mapping.function_call
        # Both parameters should be in the call
        assert "data, size" in mapping.function_call or "data,size" in mapping.function_call.replace(' ', '')
    
    def test_integer_parameter(self):
        """Test mapping for integer parameter (Requirement 3.4)"""
        mapper = ParameterMapper()
        
        sig = FunctionSignature(
            function_name="test_func",
            return_type="void",
            parameters=[
                Parameter(name="value", type="int")
            ]
        )
        
        mapping = mapper.map_parameters(sig)
        
        assert mapping is not None
        assert "value" in mapping.function_call
    
    def test_multiple_parameters(self):
        """Test mapping for multiple parameters of different types"""
        mapper = ParameterMapper()
        
        sig = FunctionSignature(
            function_name="complex_func",
            return_type="int",
            parameters=[
                Parameter(name="flag", type="bool"),
                Parameter(name="count", type="int"),
                Parameter(name="message", type="const char*", is_pointer=True, is_const=True)
            ]
        )
        
        mapping = mapper.map_parameters(sig)
        
        assert mapping is not None
        # All parameters should appear in the function call
        assert "flag" in mapping.function_call
        assert "count" in mapping.function_call
        assert "message" in mapping.function_call
    
    def test_no_parameters(self):
        """Test mapping for function with no parameters"""
        mapper = ParameterMapper()
        
        sig = FunctionSignature(
            function_name="test_func",
            return_type="void",
            parameters=[]
        )
        
        mapping = mapper.map_parameters(sig)
        
        assert mapping is not None
        assert "test_func()" in mapping.function_call
    
    def test_pointer_parameter(self):
        """Test mapping for pointer parameter (Requirement 3.5)"""
        mapper = ParameterMapper()
        
        sig = FunctionSignature(
            function_name="test_func",
            return_type="void",
            parameters=[
                Parameter(name="ptr", type="void*", is_pointer=True)
            ]
        )
        
        mapping = mapper.map_parameters(sig)
        
        assert mapping is not None
        assert "ptr" in mapping.function_call


class TestParameterMappingDataClass:
    """Tests for ParameterMapping data class"""
    
    def test_parameter_mapping_to_dict(self):
        """Test ParameterMapping to_dict conversion"""
        param = Parameter(name="x", type="int")
        mapping = ParameterMapping(
            parameters=[param],
            preparation_code="int x = 42;",
            function_call="test(x)",
            includes=["<cstdint>"]
        )
        
        d = mapping.to_dict()
        assert d['preparation_code'] == "int x = 42;"
        assert d['function_call'] == "test(x)"
        assert len(d['includes']) == 1
        assert len(d['parameters']) == 1


class TestTypeClassification:
    """Tests for type classification methods"""
    
    def test_string_type_classification(self):
        """Test string type classification"""
        mapper = ParameterMapper()
        
        string_params = [
            Parameter(name="s1", type="char*", is_pointer=True),
            Parameter(name="s2", type="const char*", is_pointer=True, is_const=True),
            Parameter(name="s3", type="std::string"),
            Parameter(name="s4", type="const std::string&", is_reference=True, is_const=True),
        ]
        
        for param in string_params:
            assert mapper._is_string_type(param), f"Should classify {param.type} as string type"
    
    def test_buffer_type_classification(self):
        """Test buffer type classification"""
        mapper = ParameterMapper()
        
        buffer_params = [
            Parameter(name="b1", type="uint8_t*", is_pointer=True),
            Parameter(name="b2", type="const uint8_t*", is_pointer=True, is_const=True),
            Parameter(name="b3", type="void*", is_pointer=True),
            Parameter(name="b4", type="const void*", is_pointer=True, is_const=True),
        ]
        
        for param in buffer_params:
            assert mapper._is_buffer_type(param), f"Should classify {param.type} as buffer type"
    
    def test_integer_type_classification(self):
        """Test integer type classification"""
        mapper = ParameterMapper()
        
        integer_params = [
            Parameter(name="i1", type="int"),
            Parameter(name="i2", type="uint32_t"),
            Parameter(name="i3", type="int64_t"),
            Parameter(name="i4", type="short"),
        ]
        
        for param in integer_params:
            assert mapper._is_integer_type(param), f"Should classify {param.type} as integer type"
    
    def test_boolean_type_classification(self):
        """Test boolean type classification"""
        mapper = ParameterMapper()
        
        bool_params = [
            Parameter(name="b1", type="bool"),
            Parameter(name="b2", type="_Bool"),
        ]
        
        for param in bool_params:
            assert mapper._is_boolean_type(param), f"Should classify {param.type} as boolean type"
    
    def test_float_type_classification(self):
        """Test float type classification"""
        mapper = ParameterMapper()
        
        float_params = [
            Parameter(name="f1", type="float"),
            Parameter(name="f2", type="double"),
            Parameter(name="f3", type="long double"),
        ]
        
        for param in float_params:
            assert mapper._is_float_type(param), f"Should classify {param.type} as float type"
