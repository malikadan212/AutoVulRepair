"""
Property-based tests for signature extraction module
Feature: harness-parameter-passing
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from src.harness.signature_extractor import (
    SignatureExtractor,
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


# Strategy for generating C/C++ types
@st.composite
def c_type(draw):
    """Generate valid C/C++ type"""
    base_types = ['int', 'char', 'void', 'uint8_t', 'size_t', 'bool', 'float', 'double', 'uint32_t', 'long']
    base = draw(st.sampled_from(base_types))
    
    # Add const qualifier sometimes
    if draw(st.booleans()):
        base = 'const ' + base
    
    # Add pointer sometimes
    pointer_count = draw(st.integers(min_value=0, max_value=2))
    base = base + ('*' * pointer_count)
    
    return base


# Strategy for generating function parameters
@st.composite
def function_parameter(draw):
    """Generate a function parameter declaration"""
    param_type = draw(c_type())
    param_name = draw(c_identifier())
    return f"{param_type} {param_name}"


# Strategy for generating function declarations
@st.composite
def function_declaration(draw):
    """Generate a valid C/C++ function declaration"""
    return_type = draw(c_type())
    function_name = draw(c_identifier())
    
    # Generate 0-5 parameters
    param_count = draw(st.integers(min_value=0, max_value=5))
    
    if param_count == 0:
        params = 'void'
    else:
        params = ', '.join([draw(function_parameter()) for _ in range(param_count)])
    
    # Choose declaration style
    style = draw(st.sampled_from(['simple', 'with_modifier', 'with_semicolon', 'with_brace']))
    
    if style == 'simple':
        declaration = f"{return_type} {function_name}({params});"
    elif style == 'with_modifier':
        modifier = draw(st.sampled_from(['static', 'inline', 'const']))
        declaration = f"{modifier} {return_type} {function_name}({params});"
    elif style == 'with_semicolon':
        declaration = f"{return_type} {function_name}({params});"
    else:  # with_brace
        declaration = f"{return_type} {function_name}({params}) {{"
    
    return {
        'declaration': declaration,
        'function_name': function_name,
        'return_type': return_type,
        'param_count': param_count if param_count > 0 else 0
    }


class TestSignatureExtraction:
    """Property-based tests for signature extraction"""
    
    @given(function_declaration())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_property_4_signature_extraction_from_valid_declarations(self, func_decl):
        """
        **Feature: harness-parameter-passing, Property 4: Signature extraction from valid declarations**
        
        For any valid C/C++ function declaration in source code, 
        the signature extractor should successfully extract the function signature.
        
        **Validates: Requirements 2.1, 2.3, 7.2, 7.3**
        """
        extractor = SignatureExtractor()
        
        source_code = func_decl['declaration']
        function_name = func_decl['function_name']
        
        # Extract signature
        signature = extractor.extract_function_signature(source_code, function_name)
        
        # Property: extraction should succeed for valid declarations
        assert signature is not None, f"Failed to extract signature from: {source_code}"
        assert signature.function_name == function_name
        assert signature.return_type is not None and signature.return_type != ""
    
    @given(function_declaration())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_property_3_signature_extraction_completeness(self, func_decl):
        """
        **Feature: harness-parameter-passing, Property 3: Signature extraction completeness**
        
        For any successfully extracted function signature, 
        the signature object should contain non-empty function name, return type, and parameter list.
        
        **Validates: Requirements 2.2**
        """
        extractor = SignatureExtractor()
        
        source_code = func_decl['declaration']
        function_name = func_decl['function_name']
        
        # Extract signature
        signature = extractor.extract_function_signature(source_code, function_name)
        
        # If extraction succeeds, verify completeness
        if signature is not None:
            # Property: all components should be present
            assert signature.function_name != "", "Function name should not be empty"
            assert signature.return_type != "", "Return type should not be empty"
            assert signature.parameters is not None, "Parameters list should not be None"
            
            # Verify parameter count matches
            expected_count = func_decl['param_count']
            actual_count = len(signature.parameters)
            assert actual_count == expected_count, \
                f"Expected {expected_count} parameters, got {actual_count} from: {source_code}"


class TestSignatureExtractionExamples:
    """Example-based tests for common patterns"""
    
    def test_simple_void_function(self):
        """Test extraction of simple void function"""
        extractor = SignatureExtractor()
        source = "void test_function();"
        
        sig = extractor.extract_function_signature(source, "test_function")
        
        assert sig is not None
        assert sig.function_name == "test_function"
        assert sig.return_type == "void"
        assert len(sig.parameters) == 0
    
    def test_function_with_string_parameter(self):
        """Test extraction of function with const char* parameter"""
        extractor = SignatureExtractor()
        source = "void test_sprintf_overflow(const char* input);"
        
        sig = extractor.extract_function_signature(source, "test_sprintf_overflow")
        
        assert sig is not None
        assert sig.function_name == "test_sprintf_overflow"
        assert sig.return_type == "void"
        assert len(sig.parameters) == 1
        assert sig.parameters[0].is_const == True
        assert sig.parameters[0].is_pointer == True
    
    def test_function_with_buffer_and_size(self):
        """Test extraction of function with buffer and size parameters"""
        extractor = SignatureExtractor()
        source = "void process_data(const uint8_t* data, size_t size);"
        
        sig = extractor.extract_function_signature(source, "process_data")
        
        assert sig is not None
        assert sig.function_name == "process_data"
        assert len(sig.parameters) == 2
        assert sig.parameters[0].is_pointer == True
        assert sig.parameters[1].name == "size"
    
    def test_static_function(self):
        """Test extraction of static function"""
        extractor = SignatureExtractor()
        source = "static int helper_function(int x);"
        
        sig = extractor.extract_function_signature(source, "helper_function")
        
        assert sig is not None
        assert sig.is_static == True
        assert sig.return_type == "int"
    
    def test_function_with_multiple_parameters(self):
        """Test extraction of function with multiple parameters"""
        extractor = SignatureExtractor()
        source = "void complex_function(int a, bool b, const char* c);"
        
        sig = extractor.extract_function_signature(source, "complex_function")
        
        assert sig is not None
        assert len(sig.parameters) == 3
        assert sig.parameters[0].name == "a"
        assert sig.parameters[1].name == "b"
        assert sig.parameters[2].name == "c"


class TestParameterParsing:
    """Tests for parameter parsing"""
    
    def test_parse_empty_parameters(self):
        """Test parsing empty parameter list"""
        extractor = SignatureExtractor()
        params = extractor.parse_parameters("")
        assert len(params) == 0
    
    def test_parse_void_parameters(self):
        """Test parsing void parameter list"""
        extractor = SignatureExtractor()
        params = extractor.parse_parameters("void")
        assert len(params) == 0
    
    def test_parse_single_parameter(self):
        """Test parsing single parameter"""
        extractor = SignatureExtractor()
        params = extractor.parse_parameters("int x")
        assert len(params) == 1
        assert params[0].name == "x"
        assert params[0].type == "int"
    
    def test_parse_const_pointer_parameter(self):
        """Test parsing const pointer parameter"""
        extractor = SignatureExtractor()
        params = extractor.parse_parameters("const char* str")
        assert len(params) == 1
        assert params[0].is_const == True
        assert params[0].is_pointer == True
    
    def test_parse_multiple_parameters(self):
        """Test parsing multiple parameters"""
        extractor = SignatureExtractor()
        params = extractor.parse_parameters("int a, bool b, const char* c")
        assert len(params) == 3


class TestDataClassSerialization:
    """Tests for data class serialization"""
    
    def test_parameter_to_dict(self):
        """Test Parameter to_dict conversion"""
        param = Parameter(
            name="test",
            type="const char*",
            is_pointer=True,
            is_const=True
        )
        
        d = param.to_dict()
        assert d['name'] == "test"
        assert d['type'] == "const char*"
        assert d['is_pointer'] == True
        assert d['is_const'] == True
    
    def test_parameter_from_dict(self):
        """Test Parameter from_dict conversion"""
        d = {
            'name': 'test',
            'type': 'int',
            'is_pointer': False,
            'is_const': False,
            'is_reference': False,
            'array_size': None
        }
        
        param = Parameter.from_dict(d)
        assert param.name == "test"
        assert param.type == "int"
    
    def test_signature_to_dict(self):
        """Test FunctionSignature to_dict conversion"""
        sig = FunctionSignature(
            function_name="test_func",
            return_type="void",
            parameters=[
                Parameter(name="x", type="int")
            ]
        )
        
        d = sig.to_dict()
        assert d['function_name'] == "test_func"
        assert d['return_type'] == "void"
        assert d['param_count'] == 1
    
    def test_signature_from_dict(self):
        """Test FunctionSignature from_dict conversion"""
        d = {
            'function_name': 'test_func',
            'return_type': 'void',
            'parameters': [
                {'name': 'x', 'type': 'int', 'is_pointer': False, 'is_const': False, 'is_reference': False, 'array_size': None}
            ],
            'is_const': False,
            'is_static': False
        }
        
        sig = FunctionSignature.from_dict(d)
        assert sig.function_name == "test_func"
        assert len(sig.parameters) == 1
