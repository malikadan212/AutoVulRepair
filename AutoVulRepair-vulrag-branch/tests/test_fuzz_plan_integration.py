"""
Integration tests for fuzz plan generator with signature extraction
"""

import json
import tempfile
from pathlib import Path
from src.fuzz_plan.generator import FuzzPlanGenerator


def test_fuzz_plan_generation_with_source_files():
    """
    Test that fuzz plan generator can extract signatures from source files
    """
    # Create temporary source file
    source_code = """
void test_function_no_params() {
    // Test function
}

int test_function_with_params(const char* input, size_t size) {
    // Test function
    return 0;
}

void test_sprintf_overflow(const char* input) {
    char buffer[10];
    sprintf(buffer, "%s", input);
}
"""
    
    # Create temporary directories
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        source_dir = temp_path / "source"
        source_dir.mkdir()
        
        # Write source file
        source_file = source_dir / "test.cpp"
        source_file.write_text(source_code)
        
        # Create static findings
        findings = {
            'total_findings': 3,
            'findings': [
                {
                    'rule_id': 'bufferAccessOutOfBounds',
                    'file': '/source/test.cpp',
                    'file_stem': 'test',
                    'function': 'test_sprintf_overflow',
                    'severity': 'error',
                    'confidence': 'high',
                    'line': 10,
                    'column': 5,
                    'message': 'Buffer overflow',
                    'cwe': '119'
                },
                {
                    'rule_id': 'bufferAccessOutOfBounds',
                    'file': '/source/test.cpp',
                    'file_stem': 'test',
                    'function': 'test_function_with_params',
                    'severity': 'error',
                    'confidence': 'high',
                    'line': 5,
                    'column': 5,
                    'message': 'Buffer overflow',
                    'cwe': '119'
                },
                {
                    'rule_id': 'bufferAccessOutOfBounds',
                    'file': '/source/test.cpp',
                    'file_stem': 'test',
                    'function': 'test_function_no_params',
                    'severity': 'error',
                    'confidence': 'high',
                    'line': 1,
                    'column': 5,
                    'message': 'Buffer overflow',
                    'cwe': '119'
                }
            ]
        }
        
        # Write findings file
        findings_file = temp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        
        # Generate fuzz plan with source directory
        generator = FuzzPlanGenerator(str(findings_file), source_dir=str(source_dir))
        fuzz_plan = generator.generate_fuzz_plan()
        
        # Verify fuzz plan was generated
        assert fuzz_plan is not None
        assert 'targets' in fuzz_plan
        assert len(fuzz_plan['targets']) == 3
        
        # Find the target with signature
        sprintf_target = None
        params_target = None
        no_params_target = None
        
        for target in fuzz_plan['targets']:
            if target['function_name'] == 'test_sprintf_overflow':
                sprintf_target = target
            elif target['function_name'] == 'test_function_with_params':
                params_target = target
            elif target['function_name'] == 'test_function_no_params':
                no_params_target = target
        
        # Verify sprintf target has signature
        assert sprintf_target is not None
        assert 'function_signature' in sprintf_target
        sig = sprintf_target['function_signature']
        assert sig['function_name'] == 'test_sprintf_overflow'
        assert sig['return_type'] == 'void'
        assert sig['param_count'] == 1
        assert len(sig['parameters']) == 1
        assert sig['parameters'][0]['type'] == 'const char*'
        
        # Verify params target has signature
        assert params_target is not None
        assert 'function_signature' in params_target
        sig = params_target['function_signature']
        assert sig['function_name'] == 'test_function_with_params'
        assert sig['return_type'] == 'int'
        assert sig['param_count'] == 2
        assert len(sig['parameters']) == 2
        assert sig['parameters'][0]['type'] == 'const char*'
        assert sig['parameters'][1]['type'] == 'size_t'
        
        # Verify no params target has signature
        assert no_params_target is not None
        assert 'function_signature' in no_params_target
        sig = no_params_target['function_signature']
        assert sig['function_name'] == 'test_function_no_params'
        assert sig['return_type'] == 'void'
        assert sig['param_count'] == 0
        assert len(sig['parameters']) == 0


def test_fuzz_plan_generation_without_source_files():
    """
    Test that fuzz plan generator works without source files (fallback)
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create static findings
        findings = {
            'total_findings': 1,
            'findings': [
                {
                    'rule_id': 'bufferAccessOutOfBounds',
                    'file': '/source/test.cpp',
                    'file_stem': 'test',
                    'function': 'test_function',
                    'severity': 'error',
                    'confidence': 'high',
                    'line': 10,
                    'column': 5,
                    'message': 'Buffer overflow',
                    'cwe': '119'
                }
            ]
        }
        
        # Write findings file
        findings_file = temp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        
        # Generate fuzz plan WITHOUT source directory
        generator = FuzzPlanGenerator(str(findings_file), source_dir=None)
        fuzz_plan = generator.generate_fuzz_plan()
        
        # Verify fuzz plan was generated
        assert fuzz_plan is not None
        assert 'targets' in fuzz_plan
        assert len(fuzz_plan['targets']) == 1
        
        # Verify target does NOT have signature (fallback behavior)
        target = fuzz_plan['targets'][0]
        assert 'function_signature' not in target or target.get('function_signature') is None


def test_fuzz_plan_save_and_load_with_signatures():
    """
    Test that signatures are preserved when saving and loading fuzz plan
    """
    source_code = """
void test_function(const char* input) {
    // Test
}
"""
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        source_dir = temp_path / "source"
        source_dir.mkdir()
        
        # Write source file
        source_file = source_dir / "test.cpp"
        source_file.write_text(source_code)
        
        # Create static findings
        findings = {
            'total_findings': 1,
            'findings': [
                {
                    'rule_id': 'bufferAccessOutOfBounds',
                    'file': '/source/test.cpp',
                    'file_stem': 'test',
                    'function': 'test_function',
                    'severity': 'error',
                    'confidence': 'high',
                    'line': 1,
                    'column': 5,
                    'message': 'Buffer overflow',
                    'cwe': '119'
                }
            ]
        }
        
        # Write findings file
        findings_file = temp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        
        # Generate and save fuzz plan
        output_file = temp_path / "fuzzplan.json"
        generator = FuzzPlanGenerator(str(findings_file), source_dir=str(source_dir))
        generator.save_fuzz_plan(str(output_file))
        
        # Load fuzz plan back
        with open(output_file, 'r') as f:
            loaded_plan = json.load(f)
        
        # Verify signature is preserved
        assert len(loaded_plan['targets']) == 1
        target = loaded_plan['targets'][0]
        assert 'function_signature' in target
        sig = target['function_signature']
        assert sig['function_name'] == 'test_function'
        assert sig['return_type'] == 'void'
        assert sig['param_count'] == 1
        assert len(sig['parameters']) == 1
        assert sig['parameters'][0]['type'] == 'const char*'
