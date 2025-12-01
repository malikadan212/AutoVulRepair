"""
Toolbox-Based Harness Generator
Implements intelligent harness selection and generation
"""

import re
from typing import Dict, List, Optional, Tuple
from src.harness.signature_extractor import SignatureExtractor, FunctionSignature
from src.harness.parameter_mapper import ParameterMapper


class HarnessToolbox:
    """Intelligent harness generation using toolbox approach"""
    
    def __init__(self):
        self.signature_extractor = SignatureExtractor()
        self.parameter_mapper = ParameterMapper()
        self.harness_types = {
            'bytes_to_api': self._generate_bytes_to_api,
            'fdp_adapter': self._generate_fdp_adapter,
            'parser_wrapper': self._generate_parser_wrapper,
            'api_sequence': self._generate_api_sequence
        }
    
    def select_harness_type(self, target: Dict) -> str:
        """
        Select appropriate harness type based on target characteristics
        
        Args:
            target: Target metadata from fuzz plan
            
        Returns:
            Harness type identifier
        """
        function_name = target.get('function_name', '').lower()
        bug_class = target.get('bug_class', '')
        
        # Check if explicit harness_type is specified
        if 'harness_type' in target:
            explicit_type = target['harness_type'].lower()
            if explicit_type == 'api':
                return 'fdp_adapter'
            elif explicit_type in self.harness_types:
                return explicit_type
        
        # Rule 0: Use signature information if available (highest priority)
        if 'function_signature' in target:
            sig_dict = target['function_signature']
            harness_type = self._infer_harness_from_signature(sig_dict)
            if harness_type:
                return harness_type
        
        # Rule 1: Parser functions with OOB bugs
        if bug_class == 'OOB' and any(kw in function_name for kw in ['parse', 'read', 'decode', 'deserialize', 'unmarshal']):
            return 'parser_wrapper'
        
        # Rule 2: Stateful APIs that need initialization/cleanup
        if any(kw in function_name for kw in ['init', 'create', 'open', 'connect', 'session', 'context']):
            # Check if there are corresponding cleanup functions
            return 'api_sequence'
        
        # Rule 3: Simple data processing functions (check before API)
        if any(kw in function_name for kw in ['buffer', 'data', 'input', 'stream', 'bytes']):
            return 'bytes_to_api'
        
        # Rule 4: API-like functions with structured parameters
        if any(kw in function_name for kw in ['api', 'handle', 'process', 'execute', 'request', 'response']):
            return 'fdp_adapter'
        
        # Default: bytes_to_api (most common pattern)
        return 'bytes_to_api'
    
    def _infer_harness_from_signature(self, sig_dict: Dict) -> Optional[str]:
        """
        Infer best harness type from function signature
        
        Args:
            sig_dict: Function signature dictionary
            
        Returns:
            Harness type identifier or None
        """
        param_count = sig_dict.get('param_count', 0)
        parameters = sig_dict.get('parameters', [])
        
        if param_count == 0:
            return 'bytes_to_api'
        
        # Check for common patterns in parameter types
        if param_count == 1:
            param = parameters[0]
            param_type = param.get('type', '').lower()
            
            # Single string parameter -> parser wrapper
            if 'char*' in param_type and 'const' in param_type:
                return 'parser_wrapper'
            # Single buffer -> bytes to api
            elif 'uint8_t*' in param_type or 'void*' in param_type:
                return 'bytes_to_api'
        
        elif param_count == 2:
            param0 = parameters[0]
            param1 = parameters[1]
            param0_type = param0.get('type', '').lower()
            param1_type = param1.get('type', '').lower()
            
            # Buffer + size pattern -> bytes to api
            if (('uint8_t*' in param0_type or 'void*' in param0_type or 'char*' in param0_type) and
                ('size' in param1_type or 'int' in param1_type)):
                return 'bytes_to_api'
        
        # Multiple parameters (3+) -> fdp adapter for typed parameters
        if param_count >= 3:
            return 'fdp_adapter'
        
        # Default for 1-3 parameters
        return 'fdp_adapter'
    
    def generate_harness(self, target: Dict, harness_type: Optional[str] = None, source_code: Optional[str] = None) -> str:
        """
        Generate harness code using selected type
        
        Args:
            target: Target metadata
            harness_type: Override harness type selection
            source_code: Optional source code for signature detection
            
        Returns:
            Generated harness code
        """
        # Extract signature from source code if available and not already present
        if source_code and 'function_signature' not in target:
            function_name = target.get('function_name', '')
            signature = self.signature_extractor.extract_function_signature(
                source_code,
                function_name
            )
            if signature:
                target['function_signature'] = signature.to_dict()
        
        # Select harness type if not specified
        if harness_type is None:
            harness_type = self.select_harness_type(target)
        
        # Generate harness using appropriate generator
        generator = self.harness_types.get(harness_type, self._generate_bytes_to_api)
        return generator(target)
    
    def _generate_bytes_to_api(self, target: Dict) -> str:
        """
        Generate bytes-to-API harness (simplest case)
        Works for functions that take (data, size) or similar
        """
        function_name = target.get('function_name', 'unknown')
        bug_class = target.get('bug_class', 'Unknown')
        source_file = target.get('source_file', '')
        
        # Generate include based on source file
        include_line = ""
        # Check if we have signature information
        signature_dict = target.get('function_signature')
        if signature_dict:
            # Use signature-aware generation
            signature = FunctionSignature.from_dict(signature_dict)
            mapping = self.parameter_mapper.map_parameters(signature, 'bytes_to_api')
            
            # Add any additional includes needed
            additional_includes = '\n'.join(f'#include {inc}' for inc in mapping.includes)
            
            signature_comment = f"// Detected signature: {signature.return_type} {signature.function_name}("
            signature_comment += ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            signature_comment += ")"
            
            # Generate function declaration instead of header include
            param_list = ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            function_declaration = f"extern {signature.return_type} {signature.function_name}({param_list});"
            
            return f"""// Auto-generated fuzzing harness
// Type: bytes_to_api
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}
{signature_comment}

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include <cstdlib>
{additional_includes}

// Function declaration (source file will be compiled with harness)
{function_declaration}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Input validation
    if (size < 1) return 0;
    if (size > 1024 * 1024) return 0;  // 1MB limit
    
{mapping.preparation_code}
    
    // Call target function with prepared parameters
    {mapping.function_call};
    
    return 0;
}}
"""
        
        # Fallback: No signature information available
        # Declare the function instead of including header
        function_declaration = f"extern void {function_name}();"
        
        return f"""// Auto-generated fuzzing harness
// Type: bytes_to_api
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include <cstdlib>

// Function declaration (source file will be compiled with harness)
{function_declaration}

// Declare target function with common signatures
extern "C" {{
    // Try multiple common signatures
    void {function_name}(const uint8_t* data, size_t size);
    void {function_name}(const char* data, size_t size);
    void {function_name}(void* data, size_t size);
    void {function_name}(const void* data, size_t size);
    void {function_name}();
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Input validation
    if (size < 1) return 0;
    if (size > 1024 * 1024) return 0;  // 1MB limit
    
    // Call target function with fuzzer data
    // Try the most common signature: (const uint8_t* data, size_t size)
    {function_name}(data, size);
    
    return 0;
}}
"""
    
    def _generate_fdp_adapter(self, target: Dict) -> str:
        """
        Generate FuzzedDataProvider adapter harness
        Works for functions with typed parameters (int, bool, string, etc.)
        """
        function_name = target.get('function_name', 'unknown')
        bug_class = target.get('bug_class', 'Unknown')
        source_file = target.get('source_file', '')
        
        # Check if we have signature information
        signature_dict = target.get('function_signature')
        if signature_dict:
            # Use signature-aware generation
            signature = FunctionSignature.from_dict(signature_dict)
            mapping = self.parameter_mapper.map_parameters(signature, 'fdp_adapter')
            
            # Add any additional includes needed
            additional_includes = '\n'.join(f'#include {inc}' for inc in mapping.includes)
            
            signature_comment = f"// Detected signature: {signature.return_type} {signature.function_name}("
            signature_comment += ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            signature_comment += ")"
            
            # Generate function declaration instead of header include
            param_list = ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            function_declaration = f"extern {signature.return_type} {signature.function_name}({param_list});"
            
            return f"""// Auto-generated fuzzing harness
// Type: fdp_adapter
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}
{signature_comment}

#include <stdint.h>
#include <stddef.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
{additional_includes}

// Function declaration (source file will be compiled with harness)
{function_declaration}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
{mapping.preparation_code}
    
    // Call target function with prepared parameters
    {mapping.function_call};
    
    return 0;
}}
"""
        
        # Fallback: No signature information available
        function_declaration = f"extern void {function_name}();"
        
        return f"""// Auto-generated fuzzing harness
// Type: fdp_adapter
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}

#include <stdint.h>
#include <stddef.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

// Function declaration (source file will be compiled with harness)
{function_declaration}

// Declare target function with common API signatures
extern "C" {{
    void {function_name}(int, bool, const char*);
    void {function_name}(int, int, int);
    void {function_name}(int, const char*);
    void {function_name}(const char*, int);
    void {function_name}(int);
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    FuzzedDataProvider fdp(data, size);
    
    // Generate typed parameters from fuzzer input
    int param1 = fdp.ConsumeIntegral<int>();
    bool param2 = fdp.ConsumeBool();
    std::string param3 = fdp.ConsumeRandomLengthString(256);
    
    // Call target function with fuzzer-generated parameters
    // Try most common signature: (int, bool, const char*)
    {function_name}(param1, param2, param3.c_str());
    
    return 0;
}}
"""
    
    def _generate_parser_wrapper(self, target: Dict) -> str:
        """
        Generate parser wrapper harness
        Works for parsing functions that process structured input
        """
        function_name = target.get('function_name', 'unknown')
        bug_class = target.get('bug_class', 'Unknown')
        source_file = target.get('source_file', '')
        
        # Check if we have signature information
        signature_dict = target.get('function_signature')
        if signature_dict:
            # Use signature-aware generation
            signature = FunctionSignature.from_dict(signature_dict)
            mapping = self.parameter_mapper.map_parameters(signature, 'parser_wrapper')
            
            # Add any additional includes needed
            additional_includes = '\n'.join(f'#include {inc}' for inc in mapping.includes)
            
            signature_comment = f"// Detected signature: {signature.return_type} {signature.function_name}("
            signature_comment += ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            signature_comment += ")"
            
            # Generate function declaration instead of header include
            param_list = ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            function_declaration = f"extern {signature.return_type} {signature.function_name}({param_list});"
            
            return f"""// Auto-generated fuzzing harness
// Type: parser_wrapper
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}
{signature_comment}

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include <cstdlib>
{additional_includes}

// Function declaration (source file will be compiled with harness)
{function_declaration}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Input validation for parser
    if (size < 4) return 0;  // Minimum size for meaningful parsing
    if (size > 10 * 1024 * 1024) return 0;  // 10MB limit for parsers
    
{mapping.preparation_code}
    
    // Call target function with prepared parameters
    {mapping.function_call};
    
    return 0;
}}
"""
        
        # Fallback: No signature information available
        function_declaration = f"extern void {function_name}();"
        
        return f"""// Auto-generated fuzzing harness
// Type: parser_wrapper
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}

#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include <cstdlib>

// Function declaration (source file will be compiled with harness)
{function_declaration}

// Declare target function with common parser signatures
extern "C" {{
    void {function_name}(const char* input, size_t size);
    void {function_name}(char* input, size_t size);
    void {function_name}(const char* input);
    void {function_name}(char* input);
    void {function_name}(const uint8_t* data, size_t size);
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Input validation for parser
    if (size < 4) return 0;  // Minimum size for meaningful parsing
    if (size > 10 * 1024 * 1024) return 0;  // 10MB limit for parsers
    
    // Create null-terminated copy for string parsers
    char* input = (char*)malloc(size + 1);
    if (!input) return 0;
    
    memcpy(input, data, size);
    input[size] = '\\0';
    
    // Call parser function with fuzzer-generated input
    // Try most common signature: (const char* input, size_t size)
    {function_name}(input, size);
    
    free(input);
    
    return 0;
}}
"""
    
    def _generate_api_sequence(self, target: Dict) -> str:
        """
        Generate API sequence harness
        Works for stateful APIs that require initialization/cleanup
        """
        function_name = target.get('function_name', 'unknown')
        bug_class = target.get('bug_class', 'Unknown')
        source_file = target.get('source_file', '')
        
        # Check if we have signature information
        signature_dict = target.get('function_signature')
        if signature_dict:
            # Use signature-aware generation
            signature = FunctionSignature.from_dict(signature_dict)
            mapping = self.parameter_mapper.map_parameters(signature, 'api_sequence')
            
            # Add any additional includes needed
            additional_includes = '\n'.join(f'#include {inc}' for inc in mapping.includes)
            
            signature_comment = f"// Detected signature: {signature.return_type} {signature.function_name}("
            signature_comment += ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            signature_comment += ")"
            
            # Generate function declaration instead of header include
            param_list = ', '.join(f"{p.type} {p.name}" for p in signature.parameters)
            function_declaration = f"extern {signature.return_type} {signature.function_name}({param_list});"
            
            return f"""// Auto-generated fuzzing harness
// Type: api_sequence
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}
{signature_comment}

#include <stdint.h>
#include <stddef.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
{additional_includes}

// Function declaration (source file will be compiled with harness)
{function_declaration}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    FuzzedDataProvider fdp(data, size);
    
    // Generate API call sequence with fuzzer-driven parameters
    int num_calls = fdp.ConsumeIntegralInRange<int>(1, 10);
    
    for (int i = 0; i < num_calls; i++) {{
{mapping.preparation_code}
        
        // Call target function with prepared parameters
        {mapping.function_call};
        
        // Check for early termination
        if (fdp.remaining_bytes() < 4) break;
    }}
    
    return 0;
}}
"""
        
        # Fallback: No signature information available
        function_declaration = f"extern void {function_name}();"
        
        return f"""// Auto-generated fuzzing harness
// Type: api_sequence
// Target: {function_name}
// Bug Class: {bug_class}
// Source: {source_file}

#include <stdint.h>
#include <stddef.h>
#include <fuzzer/FuzzedDataProvider.h>

// Function declaration (source file will be compiled with harness)
{function_declaration}

// Declare target function with common signatures
extern "C" {{
    void {function_name}(int param);
    void {function_name}(const char* param);
    void {function_name}(int, int);
    void {function_name}();
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    FuzzedDataProvider fdp(data, size);
    
    // Generate API call sequence with fuzzer-driven parameters
    int num_calls = fdp.ConsumeIntegralInRange<int>(1, 10);
    
    for (int i = 0; i < num_calls; i++) {{
        // Generate parameter for each call
        int param = fdp.ConsumeIntegral<int>();
        
        // Call target function with fuzzer-generated parameter
        {function_name}(param);
        
        // Check for early termination
        if (fdp.remaining_bytes() < 4) break;
    }}
    
    return 0;
}}
"""

