"""
Property-based tests for fuzz plan generator
Tests signature persistence and serialization
"""

import json
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, settings, HealthCheck
from src.fuzz_plan.generator import FuzzPlanGenerator
from src.harness.signature_extractor import FunctionSignature, Parameter


# Strategy for generating valid parameter types
param_types = st.sampled_from([
    'int', 'char*', 'const char*', 'void*', 'const void*',
    'uint8_t*', 'const uint8_t*', 'size_t', 'bool',
    'float', 'double', 'uint32_t', 'int64_t'
])

# Strategy for generating parameter names
param_names = st.text(
    alphabet=st.characters(whitelist_categories=('Ll', 'Lu'), min_codepoint=97, max_codepoint=122),
    min_size=1,
    max_size=20
).filter(lambda x: x.isidentifier())

# Strategy for generating function names
function_names = st.text(
    alphabet=st.characters(whitelist_categories=('Ll', 'Lu'), min_codepoint=97, max_codepoint=122),
    min_size=3,
    max_size=30
).filter(lambda x: x.isidentifier() and not x.startswith('_'))

# Strategy for generating return types
return_types = st.sampled_from([
    'void', 'int', 'char*', 'bool', 'float', 'double',
    'uint32_t', 'size_t', 'void*'
])


@st.composite
def parameter_strategy(draw):
    """Generate a valid Parameter object"""
    name = draw(param_names)
    param_type = draw(param_types)
    
    is_pointer = '*' in param_type
    is_const = 'const' in param_type
    is_reference = draw(st.booleans()) if not is_pointer else False
    
    return Parameter(
        name=name,
        type=param_type,
        is_pointer=is_pointer,
        is_const=is_const,
        is_reference=is_reference,
        array_size=None
    )


@st.composite
def function_signature_strategy(draw):
    """Generate a valid FunctionSignature object"""
    func_name = draw(function_names)
    ret_type = draw(return_types)
    
    # Generate 0-5 parameters
    num_params = draw(st.integers(min_value=0, max_value=5))
    parameters = [draw(parameter_strategy()) for _ in range(num_params)]
    
    is_static = draw(st.booleans())
    is_const = draw(st.booleans())
    
    return FunctionSignature(
        function_name=func_name,
        return_type=ret_type,
        parameters=parameters,
        is_static=is_static,
        is_const=is_const
    )


@st.composite
def fuzz_plan_entry_strategy(draw):
    """Generate a valid fuzz plan entry with signature"""
    func_name = draw(function_names)
    file_stem = draw(st.text(min_size=1, max_size=20, alphabet=st.characters(
        whitelist_categories=('Ll', 'Lu'), min_codepoint=97, max_codepoint=122
    )))
    
    signature = draw(function_signature_strategy())
    # Ensure function names match
    signature.function_name = func_name
    
    entry = {
        'target_id': f"{file_stem}_{func_name}",
        'source_file': f"/source/{file_stem}.cpp",
        'file_stem': file_stem,
        'function_name': func_name,
        'bug_class': draw(st.sampled_from(['OOB', 'UAF', 'Integer-UB', 'Null-Deref'])),
        'rule_id': 'testRule',
        'severity': 'error',
        'confidence': 'high',
        'line_number': draw(st.integers(min_value=1, max_value=1000)),
        'column_number': draw(st.integers(min_value=1, max_value=100)),
        'message': 'Test message',
        'cwe': '119',
        'sanitizers': ['address'],
        'seed_directories': ['fuzz/seeds/generic/'],
        'dictionaries': [],
        'priority': draw(st.floats(min_value=1.0, max_value=20.0)),
        'harness_type': 'parser_wrapper',
        'harness_template': 'parser_wrapper',
        'function_signature': signature.to_dict()
    }
    
    return entry


# **Feature: harness-parameter-passing, Property 7: Fuzz plan signature persistence**
@given(fuzz_plan_entry_strategy())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_signature_persistence_in_fuzz_plan_entry(entry):
    """
    Property 7: Fuzz plan signature persistence
    
    For any fuzz plan entry with a function signature, saving and loading 
    the fuzz plan should preserve the signature information.
    
    **Validates: Requirements 6.1, 6.2, 6.3**
    """
    # Create a temporary fuzz plan with the entry
    fuzz_plan = {
        'version': '1.0',
        'generated_at': '2024-01-01T00:00:00',
        'source': 'test',
        'targets': [entry],
        'metadata': {
            'total_findings': 1,
            'deduplicated_targets': 1,
            'bug_class_breakdown': {entry['bug_class']: 1},
            'sanitizers_used': ['address']
        }
    }
    
    # Save to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(fuzz_plan, f, indent=2)
        temp_path = f.name
    
    try:
        # Load back from file
        with open(temp_path, 'r') as f:
            loaded_plan = json.load(f)
        
        # Extract original and loaded signatures
        original_sig = entry['function_signature']
        loaded_sig = loaded_plan['targets'][0]['function_signature']
        
        # Verify signature is preserved
        assert loaded_sig is not None, "Signature should not be None after loading"
        assert loaded_sig['function_name'] == original_sig['function_name'], \
            "Function name should be preserved"
        assert loaded_sig['return_type'] == original_sig['return_type'], \
            "Return type should be preserved"
        assert loaded_sig['param_count'] == original_sig['param_count'], \
            "Parameter count should be preserved"
        assert len(loaded_sig['parameters']) == len(original_sig['parameters']), \
            "Number of parameters should be preserved"
        
        # Verify each parameter is preserved
        for orig_param, loaded_param in zip(original_sig['parameters'], loaded_sig['parameters']):
            assert loaded_param['name'] == orig_param['name'], \
                f"Parameter name should be preserved: {orig_param['name']}"
            assert loaded_param['type'] == orig_param['type'], \
                f"Parameter type should be preserved: {orig_param['type']}"
            assert loaded_param['is_pointer'] == orig_param['is_pointer'], \
                "Parameter is_pointer flag should be preserved"
            assert loaded_param['is_const'] == orig_param['is_const'], \
                "Parameter is_const flag should be preserved"
            assert loaded_param['is_reference'] == orig_param['is_reference'], \
                "Parameter is_reference flag should be preserved"
        
        # Verify modifiers are preserved
        assert loaded_sig['is_static'] == original_sig['is_static'], \
            "is_static flag should be preserved"
        assert loaded_sig['is_const'] == original_sig['is_const'], \
            "is_const flag should be preserved"
        
    finally:
        # Clean up temporary file
        Path(temp_path).unlink(missing_ok=True)


@given(st.lists(fuzz_plan_entry_strategy(), min_size=1, max_size=10))
@settings(max_examples=100)
def test_multiple_signatures_persistence(entries):
    """
    Test that multiple signatures in a fuzz plan are all preserved correctly
    """
    fuzz_plan = {
        'version': '1.0',
        'generated_at': '2024-01-01T00:00:00',
        'source': 'test',
        'targets': entries,
        'metadata': {
            'total_findings': len(entries),
            'deduplicated_targets': len(entries),
            'bug_class_breakdown': {},
            'sanitizers_used': ['address']
        }
    }
    
    # Save to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(fuzz_plan, f, indent=2)
        temp_path = f.name
    
    try:
        # Load back from file
        with open(temp_path, 'r') as f:
            loaded_plan = json.load(f)
        
        # Verify all signatures are preserved
        assert len(loaded_plan['targets']) == len(entries), \
            "Number of targets should be preserved"
        
        for original_entry, loaded_entry in zip(entries, loaded_plan['targets']):
            if 'function_signature' in original_entry:
                assert 'function_signature' in loaded_entry, \
                    "Signature should be present in loaded entry"
                
                original_sig = original_entry['function_signature']
                loaded_sig = loaded_entry['function_signature']
                
                assert loaded_sig['function_name'] == original_sig['function_name'], \
                    "Function name should match"
                assert loaded_sig['param_count'] == original_sig['param_count'], \
                    "Parameter count should match"
    
    finally:
        # Clean up temporary file
        Path(temp_path).unlink(missing_ok=True)


@given(function_signature_strategy())
@settings(max_examples=100)
def test_signature_serialization_round_trip(signature):
    """
    Test that FunctionSignature can be serialized to dict and back without loss
    """
    # Convert to dict
    sig_dict = signature.to_dict()
    
    # Verify dict has required fields
    assert 'function_name' in sig_dict
    assert 'return_type' in sig_dict
    assert 'parameters' in sig_dict
    assert 'param_count' in sig_dict
    assert 'is_static' in sig_dict
    assert 'is_const' in sig_dict
    
    # Convert back to FunctionSignature
    restored_sig = FunctionSignature.from_dict(sig_dict)
    
    # Verify all fields match
    assert restored_sig.function_name == signature.function_name
    assert restored_sig.return_type == signature.return_type
    assert len(restored_sig.parameters) == len(signature.parameters)
    assert restored_sig.is_static == signature.is_static
    assert restored_sig.is_const == signature.is_const
    
    # Verify parameters match
    for orig_param, restored_param in zip(signature.parameters, restored_sig.parameters):
        assert restored_param.name == orig_param.name
        assert restored_param.type == orig_param.type
        assert restored_param.is_pointer == orig_param.is_pointer
        assert restored_param.is_const == orig_param.is_const
        assert restored_param.is_reference == orig_param.is_reference
