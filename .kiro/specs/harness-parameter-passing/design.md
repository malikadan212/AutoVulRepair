# Design Document

## Overview

This design addresses the critical issue where fuzzing harnesses prepare input data from the fuzzer but fail to pass it correctly to target functions. The solution involves implementing function signature extraction, intelligent parameter mapping, and enhanced template generation to ensure harnesses actually test the target functions with fuzzer-provided data.

The design takes a pragmatic, incremental approach:
1. Start with regex-based signature extraction (simple, works for most cases)
2. Store signature information in the fuzz plan
3. Enhance templates to use signature information
4. Generate correct function calls with properly mapped parameters

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Harness Generation Flow                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  1. Signature Extractor                                      │
│     - Parses source files for function declarations          │
│     - Extracts return type, parameters, types                │
│     - Stores in fuzz plan entry                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Parameter Mapper                                         │
│     - Analyzes parameter types                               │
│     - Determines data preparation strategy                   │
│     - Maps fuzzer data to typed parameters                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Template Generator                                       │
│     - Selects appropriate template                           │
│     - Injects signature information                          │
│     - Generates parameter preparation code                   │
│     - Generates correct function call                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Generated Harness                                        │
│     - Receives fuzzer data                                   │
│     - Prepares typed parameters                              │
│     - Calls target function with parameters                  │
└─────────────────────────────────────────────────────────────┘
```

### Integration Points

1. **Static Analysis → Signature Extraction**: When creating fuzz plan entries, extract signatures from source files
2. **Fuzz Plan → Harness Generator**: Pass signature information through fuzz plan JSON
3. **Harness Generator → Templates**: Provide signature data to template rendering
4. **Templates → Generated Code**: Use signature to generate correct function calls

## Components and Interfaces

### 1. Signature Extractor

**Purpose**: Extract function signatures from source code

**Module**: `src/harness/signature_extractor.py`

**Key Functions**:

```python
def extract_function_signature(
    source_code: str,
    function_name: str
) -> Optional[FunctionSignature]:
    """
    Extract function signature from source code
    
    Args:
        source_code: Source file content
        function_name: Target function name
        
    Returns:
        FunctionSignature object or None if not found
    """
    pass

def parse_parameters(param_string: str) -> List[Parameter]:
    """
    Parse parameter string into structured parameter list
    
    Args:
        param_string: Raw parameter string from function declaration
        
    Returns:
        List of Parameter objects
    """
    pass
```

**Extraction Strategy**:
- Use regex patterns to match common C/C++ function declarations
- Support multiple declaration styles (const, static, inline, etc.)
- Handle pointer types, const qualifiers, reference types
- Extract parameter names and types separately
- Fall back to manual specification if extraction fails

### 2. Parameter Mapper

**Purpose**: Map fuzzer data to function parameters based on types

**Module**: `src/harness/parameter_mapper.py`

**Key Functions**:

```python
def map_parameters(
    signature: FunctionSignature,
    harness_type: str
) -> ParameterMapping:
    """
    Create parameter mapping strategy for signature
    
    Args:
        signature: Function signature information
        harness_type: Type of harness being generated
        
    Returns:
        ParameterMapping with preparation and call code
    """
    pass

def generate_param_preparation(
    param: Parameter,
    param_index: int
) -> str:
    """
    Generate code to prepare a single parameter from fuzzer data
    
    Args:
        param: Parameter information
        param_index: Index in parameter list
        
    Returns:
        C++ code string for parameter preparation
    """
    pass
```

**Mapping Rules**:

| Parameter Type Pattern | Preparation Strategy |
|------------------------|---------------------|
| `const char*` | Null-terminated string from fuzzer data |
| `char*` | Mutable null-terminated string |
| `const uint8_t*, size_t` | Raw fuzzer buffer and size |
| `void*, size_t` | Cast fuzzer buffer and size |
| `int`, `uint32_t`, etc. | Extract integer from fuzzer data |
| `bool` | Extract boolean from fuzzer data |
| `const std::string&` | Construct std::string from fuzzer data |
| `float`, `double` | Extract floating point from fuzzer data |

### 3. Enhanced Harness Toolbox

**Purpose**: Generate harnesses with correct parameter passing

**Module**: `src/harness/toolbox.py` (enhanced)

**Key Changes**:

```python
class HarnessToolbox:
    def __init__(self):
        self.signature_extractor = SignatureExtractor()
        self.parameter_mapper = ParameterMapper()
        # ... existing code ...
    
    def generate_harness(
        self,
        target: Dict,
        harness_type: Optional[str] = None,
        source_code: Optional[str] = None
    ) -> str:
        """
        Generate harness with signature-aware parameter passing
        
        Enhanced to:
        1. Extract or use provided signature
        2. Map parameters appropriately
        3. Generate correct function call
        """
        # Extract signature if not in target
        if 'function_signature' not in target and source_code:
            signature = self.signature_extractor.extract_function_signature(
                source_code,
                target['function_name']
            )
            if signature:
                target['function_signature'] = signature.to_dict()
        
        # Generate with signature awareness
        # ... rest of implementation ...
```

### 4. Enhanced Templates

**Purpose**: Generate harnesses that use signature information

**Templates Updated**:
- `parser_wrapper.cc.template`
- `bytes_to_api.cc.template`
- `fdp_adapter.cc.template`
- `api_sequence.cc.template`

**Template Variables Added**:
- `{{function_call}}`: Complete function call with parameters
- `{{param_preparation}}`: Code to prepare parameters
- `{{param_declarations}}`: Variable declarations for parameters
- `{{signature_comment}}`: Comment showing detected signature

## Data Models

### FunctionSignature

```python
@dataclass
class FunctionSignature:
    """Function signature information"""
    function_name: str
    return_type: str
    parameters: List[Parameter]
    is_const: bool = False
    is_static: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'function_name': self.function_name,
            'return_type': self.return_type,
            'parameters': [p.to_dict() for p in self.parameters],
            'param_count': len(self.parameters),
            'is_const': self.is_const,
            'is_static': self.is_static
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'FunctionSignature':
        """Create from dictionary"""
        return cls(
            function_name=data['function_name'],
            return_type=data['return_type'],
            parameters=[Parameter.from_dict(p) for p in data['parameters']],
            is_const=data.get('is_const', False),
            is_static=data.get('is_static', False)
        )
```

### Parameter

```python
@dataclass
class Parameter:
    """Function parameter information"""
    name: str
    type: str
    is_pointer: bool = False
    is_const: bool = False
    is_reference: bool = False
    array_size: Optional[int] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'type': self.type,
            'is_pointer': self.is_pointer,
            'is_const': self.is_const,
            'is_reference': self.is_reference,
            'array_size': self.array_size
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Parameter':
        """Create from dictionary"""
        return cls(
            name=data['name'],
            type=data['type'],
            is_pointer=data.get('is_pointer', False),
            is_const=data.get('is_const', False),
            is_reference=data.get('is_reference', False),
            array_size=data.get('array_size')
        )
    
    def get_base_type(self) -> str:
        """Get base type without qualifiers"""
        base = self.type.replace('const', '').replace('*', '').replace('&', '').strip()
        return base
```

### ParameterMapping

```python
@dataclass
class ParameterMapping:
    """Parameter mapping strategy for harness generation"""
    parameters: List[Parameter]
    preparation_code: str
    function_call: str
    includes: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'parameters': [p.to_dict() for p in self.parameters],
            'preparation_code': self.preparation_code,
            'function_call': self.function_call,
            'includes': self.includes
        }
```

### Enhanced Fuzz Plan Entry

```json
{
  "target_id": "test_test_sprintf_overflow",
  "function_name": "test_sprintf_overflow",
  "source_file": "/source/test.cpp",
  "bug_class": "OOB",
  "function_signature": {
    "function_name": "test_sprintf_overflow",
    "return_type": "void",
    "parameters": [
      {
        "name": "input",
        "type": "const char*",
        "is_pointer": true,
        "is_const": true
      }
    ],
    "param_count": 1
  },
  "harness_type": "parser_wrapper"
}
```



## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Acceptance Criteria Testing Prework

1.1 WHEN a parser wrapper harness is generated for a target function THEN the harness SHALL pass the prepared input data to that function
  Thoughts: This is about ensuring that for any target function, the generated harness actually uses the prepared data. We can test this by generating harnesses for various functions and verifying the generated code contains a function call with the prepared data as an argument.
  Testable: yes - property

1.2 WHEN the harness prepares a null-terminated string from fuzzer data THEN the harness SHALL use that string as an argument to the target function
  Thoughts: This is specific to string preparation. We can verify that when a string variable is created and null-terminated, it appears in the function call.
  Testable: yes - property

1.3 WHEN a target function requires multiple parameters THEN the harness SHALL provide all required parameters from the fuzzer data
  Thoughts: This tests that the parameter count in the function call matches the signature. For any function with N parameters, the generated call should have N arguments.
  Testable: yes - property

1.4 WHEN a harness calls a target function THEN the function call SHALL match the target function's signature
  Thoughts: This is about type correctness. For any function signature, the generated call should have matching parameter types.
  Testable: yes - property

1.5 WHEN fuzzer data is allocated and prepared THEN the harness SHALL ensure that data is consumed by the target function before cleanup
  Thoughts: This is about the ordering of operations. Any allocated data should be used before being freed.
  Testable: yes - property

2.1 WHEN the harness generator processes a target function THEN the system SHALL extract the function signature from the source code
  Thoughts: For any source code containing a function declaration, the extractor should find and parse it.
  Testable: yes - property

2.2 WHEN a function signature is extracted THEN the system SHALL identify the function name, return type, and all parameter types
  Thoughts: For any successfully extracted signature, all components should be present.
  Testable: yes - property

2.3 WHEN source code contains function declarations THEN the system SHALL parse those declarations to obtain signature information
  Thoughts: This is similar to 2.1, testing the parsing capability across various declaration formats.
  Testable: yes - property

2.4 WHEN multiple overloads of a function exist THEN the system SHALL identify all available signatures
  Thoughts: For any set of overloaded functions, all signatures should be extracted.
  Testable: yes - property

2.5 WHEN signature extraction fails THEN the system SHALL provide a clear error message indicating what information is missing
  Thoughts: This is about error handling. For any extraction failure, there should be an error message.
  Testable: yes - example

3.1 WHEN a target function accepts a string parameter THEN the harness SHALL convert fuzzer data to a null-terminated string
  Thoughts: For any function with a string parameter, the generated code should include null-termination.
  Testable: yes - property

3.2 WHEN a target function accepts a size parameter THEN the harness SHALL provide the size of the fuzzer data
  Thoughts: For any function with a size_t parameter, the size should be passed.
  Testable: yes - property

3.3 WHEN a target function accepts a buffer and length THEN the harness SHALL pass both the data pointer and size
  Thoughts: For any function with (buffer, length) pattern, both should be in the call.
  Testable: yes - property

3.4 WHEN a target function accepts integer parameters THEN the harness SHALL extract integers from the fuzzer data
  Thoughts: For any function with int parameters, the harness should use FuzzedDataProvider or similar to extract integers.
  Testable: yes - property

3.5 WHEN a target function accepts pointer parameters THEN the harness SHALL allocate appropriate memory and pass valid pointers
  Thoughts: For any function with pointer parameters, memory should be allocated before the call.
  Testable: yes - property

4.1 WHEN a harness template is instantiated THEN the template SHALL accept function signature information as input
  Thoughts: For any template instantiation, signature data should be accepted as a parameter.
  Testable: yes - property

4.2 WHEN generating a function call THEN the template SHALL use the provided parameter list
  Thoughts: For any template with signature info, the generated call should use those parameters.
  Testable: yes - property

4.3 WHEN the template renders a harness THEN the harness SHALL include all necessary parameter preparation code
  Thoughts: For any rendered harness, all parameters should have preparation code.
  Testable: yes - property

4.4 WHEN parameter types vary THEN the template SHALL adapt the data preparation logic accordingly
  Thoughts: For any set of different parameter types, the preparation code should differ appropriately.
  Testable: yes - property

4.5 WHEN the fuzz plan specifies parameter details THEN the template SHALL use that information in code generation
  Thoughts: For any fuzz plan with signature info, that info should appear in the generated code.
  Testable: yes - property

5.1 WHEN a function accepts `(const char* str)` THEN the harness SHALL pass a null-terminated string
  Thoughts: This is a specific example of a common pattern.
  Testable: yes - example

5.2 WHEN a function accepts `(const uint8_t* data, size_t size)` THEN the harness SHALL pass the raw fuzzer buffer and its size
  Thoughts: This is a specific example of a common pattern.
  Testable: yes - example

5.3 WHEN a function accepts `(char* buffer, size_t len)` THEN the harness SHALL allocate a buffer and pass it with the size
  Thoughts: This is a specific example of a common pattern.
  Testable: yes - example

5.4 WHEN a function accepts `(const std::string& str)` THEN the harness SHALL construct a std::string from fuzzer data
  Thoughts: This is a specific example of a common pattern.
  Testable: yes - example

5.5 WHEN a function accepts `(void* data, int length)` THEN the harness SHALL cast the fuzzer data appropriately and pass the length
  Thoughts: This is a specific example of a common pattern.
  Testable: yes - example

6.1 WHEN a fuzz plan entry is created THEN the entry SHALL include the target function signature
  Thoughts: For any fuzz plan entry, signature should be present in the JSON.
  Testable: yes - property

6.2 WHEN the fuzz plan is stored THEN the function signature SHALL be persisted in the JSON format
  Thoughts: For any saved fuzz plan, signatures should be in the JSON file.
  Testable: yes - property

6.3 WHEN the harness generator reads a fuzz plan entry THEN the generator SHALL extract the function signature
  Thoughts: For any fuzz plan entry with signature, the generator should read it.
  Testable: yes - property

6.4 WHEN signature information is incomplete THEN the system SHALL use reasonable defaults or request user input
  Thoughts: For any incomplete signature, there should be fallback behavior.
  Testable: yes - property

6.5 WHEN the fuzz plan is displayed THEN the function signature SHALL be visible to the user
  Thoughts: For any displayed fuzz plan, signatures should be shown in the UI.
  Testable: yes - property

7.1 WHEN extracting function signatures THEN the system SHALL support regex-based extraction as a fallback
  Thoughts: For any extraction attempt, regex should be available as a method.
  Testable: yes - property

7.2 WHEN a function declaration matches a simple pattern THEN the system SHALL extract the signature using pattern matching
  Thoughts: For any simple function declaration, regex extraction should succeed.
  Testable: yes - property

7.3 WHEN regex extraction is used THEN the system SHALL handle common C/C++ function declaration formats
  Thoughts: For any common declaration format, extraction should work.
  Testable: yes - property

7.4 WHEN the simple extraction fails THEN the system SHALL provide guidance on manual signature specification
  Thoughts: For any extraction failure, guidance should be provided.
  Testable: yes - example

7.5 WHEN function signatures are provided manually THEN the system SHALL accept them in a standard format
  Thoughts: For any manually provided signature, the system should parse and use it.
  Testable: yes - property

### Property 1: Generated harnesses use prepared data

*For any* target function and generated harness, when the harness prepares input data from fuzzer bytes, the generated function call should include that prepared data as an argument.

**Validates: Requirements 1.1, 1.2, 1.5**

### Property 2: Parameter count matches signature

*For any* function signature with N parameters, the generated harness should call the function with exactly N arguments.

**Validates: Requirements 1.3, 1.4**

### Property 3: Signature extraction completeness

*For any* successfully extracted function signature, the signature object should contain non-empty function name, return type, and parameter list.

**Validates: Requirements 2.2**

### Property 4: Signature extraction from valid declarations

*For any* valid C/C++ function declaration in source code, the signature extractor should successfully extract the function signature.

**Validates: Requirements 2.1, 2.3, 7.2, 7.3**

### Property 5: Parameter type mapping consistency

*For any* parameter type in a function signature, the parameter mapper should generate preparation code that produces a value compatible with that type.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

### Property 6: Template uses signature information

*For any* harness template rendered with signature information, the generated code should reference the parameters from that signature.

**Validates: Requirements 4.2, 4.3, 4.5**

### Property 7: Fuzz plan signature persistence

*For any* fuzz plan entry with a function signature, saving and loading the fuzz plan should preserve the signature information.

**Validates: Requirements 6.1, 6.2, 6.3**

## Error Handling

### Signature Extraction Failures

**Scenario**: Function signature cannot be extracted from source code

**Handling**:
1. Log warning with function name and source file
2. Attempt fallback patterns (multiple regex variations)
3. If all patterns fail, use default signature based on harness type
4. Include TODO comment in generated harness indicating manual review needed
5. Store extraction failure in metadata for user visibility

**Example**:
```python
try:
    signature = extract_function_signature(source_code, function_name)
except SignatureExtractionError as e:
    logger.warning(f"Could not extract signature for {function_name}: {e}")
    signature = get_default_signature(harness_type)
    metadata['signature_extraction_failed'] = True
    metadata['extraction_error'] = str(e)
```

### Parameter Mapping Failures

**Scenario**: Parameter type cannot be mapped to fuzzer data preparation

**Handling**:
1. Log warning with parameter type
2. Use generic byte buffer as fallback
3. Add TODO comment in generated code
4. Include type information in comment for manual implementation

**Example**:
```cpp
// TODO: Unknown parameter type 'CustomStruct*'
// Manual implementation required
// Original type: CustomStruct* param_name
void* param_name = (void*)data;  // Fallback: raw bytes
```

### Missing Source Code

**Scenario**: Source file not available for signature extraction

**Handling**:
1. Check if signature is already in fuzz plan entry
2. If not, use harness type to infer likely signature
3. Generate harness with multiple extern declarations (current approach)
4. Mark harness as requiring manual verification

### Invalid Fuzz Plan Data

**Scenario**: Fuzz plan entry has malformed signature data

**Handling**:
1. Validate signature structure on load
2. If invalid, log error and skip signature
3. Fall back to signature-less generation
4. Continue harness generation with warnings

## Testing Strategy

### Unit Testing

**Signature Extraction Tests**:
- Test extraction from various function declaration formats
- Test handling of const, static, inline modifiers
- Test pointer and reference type extraction
- Test parameter name and type parsing
- Test extraction failure cases

**Parameter Mapping Tests**:
- Test mapping for common type patterns
- Test preparation code generation for each type
- Test function call generation with various signatures
- Test handling of unknown types

**Template Rendering Tests**:
- Test template rendering with signature data
- Test template rendering without signature data
- Test parameter preparation code injection
- Test function call code injection

### Property-Based Testing

The testing framework will use **Hypothesis** for Python property-based testing.

Each property-based test should run a minimum of 100 iterations to ensure thorough coverage of the random input space.

**Property Test 1: Generated harnesses use prepared data**
- **Feature: harness-parameter-passing, Property 1: Generated harnesses use prepared data**
- Generate random target metadata with various function names
- Generate harness code using the toolbox
- Parse the generated C++ code to find variable declarations and function calls
- Verify that any allocated/prepared variables appear as arguments in the function call
- **Validates: Requirements 1.1, 1.2, 1.5**

**Property Test 2: Parameter count matches signature**
- **Feature: harness-parameter-passing, Property 2: Parameter count matches signature**
- Generate random function signatures with varying parameter counts (0-10)
- Generate harness code with those signatures
- Parse the generated function call
- Verify the argument count matches the signature parameter count
- **Validates: Requirements 1.3, 1.4**

**Property Test 3: Signature extraction completeness**
- **Feature: harness-parameter-passing, Property 3: Signature extraction completeness**
- Generate random valid function declarations
- Extract signatures from those declarations
- Verify all extracted signatures have non-empty function_name, return_type, and parameters list
- **Validates: Requirements 2.2**

**Property Test 4: Signature extraction from valid declarations**
- **Feature: harness-parameter-passing, Property 4: Signature extraction from valid declarations**
- Generate random valid C/C++ function declarations with various formats
- Attempt signature extraction on each
- Verify extraction succeeds for all valid declarations
- **Validates: Requirements 2.1, 2.3, 7.2, 7.3**

**Property Test 5: Parameter type mapping consistency**
- **Feature: harness-parameter-passing, Property 5: Parameter type mapping consistency**
- Generate random parameter types from common C/C++ types
- Generate preparation code for each type
- Verify the preparation code produces a value that can be used with that type
- **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

**Property Test 6: Template uses signature information**
- **Feature: harness-parameter-passing, Property 6: Template uses signature information**
- Generate random function signatures
- Render templates with those signatures
- Verify the generated code contains references to the signature parameters
- **Validates: Requirements 4.2, 4.3, 4.5**

**Property Test 7: Fuzz plan signature persistence**
- **Feature: harness-parameter-passing, Property 7: Fuzz plan signature persistence**
- Generate random fuzz plan entries with signatures
- Serialize to JSON and deserialize
- Verify signatures are preserved exactly
- **Validates: Requirements 6.1, 6.2, 6.3**

### Integration Testing

**End-to-End Harness Generation**:
- Create test source files with known function signatures
- Run full harness generation pipeline
- Verify generated harnesses compile
- Verify generated harnesses can be linked with test functions
- Verify harnesses actually call functions with correct parameters

**Real-World Function Testing**:
- Test with actual vulnerable functions from test suite
- Verify harnesses can trigger known bugs
- Verify sanitizers detect the bugs when harnesses run

## Implementation Notes

### Regex Patterns for Signature Extraction

The signature extractor will use multiple regex patterns to handle various declaration styles:

```python
SIGNATURE_PATTERNS = [
    # Standard: return_type function_name(params)
    r'\b(\w+(?:\s*\*)?)\s+(\w+)\s*\((.*?)\)',
    
    # With modifiers: static/const/inline return_type function_name(params)
    r'\b(?:static|const|inline)\s+(\w+(?:\s*\*)?)\s+(\w+)\s*\((.*?)\)',
    
    # Pointer return: return_type* function_name(params)
    r'\b(\w+\s*\*+)\s*(\w+)\s*\((.*?)\)',
    
    # Template functions: template<...> return_type function_name(params)
    r'template\s*<[^>]+>\s*(\w+(?:\s*\*)?)\s+(\w+)\s*\((.*?)\)',
    
    # Extern "C": extern "C" return_type function_name(params)
    r'extern\s+"C"\s+(\w+(?:\s*\*)?)\s+(\w+)\s*\((.*?)\)',
]
```

### Parameter Type Classification

Parameters will be classified into categories for mapping:

1. **String types**: `char*`, `const char*`, `std::string`, `const std::string&`
2. **Buffer types**: `uint8_t*`, `void*`, `const uint8_t*`, `const void*`
3. **Size types**: `size_t`, `int`, `unsigned int`, `uint32_t`
4. **Integer types**: `int`, `long`, `short`, `uint32_t`, etc.
5. **Boolean types**: `bool`
6. **Floating point**: `float`, `double`
7. **Pointer types**: Any type with `*`
8. **Reference types**: Any type with `&`

### Fallback Strategy

When signature extraction fails:

1. **Parser wrapper**: Assume `(const char* input)` or `(const char* input, size_t size)`
2. **Bytes to API**: Assume `(const uint8_t* data, size_t size)`
3. **FDP adapter**: Assume `(int param1, bool param2, const char* param3)`
4. **API sequence**: Assume `(int param)` or `()`

### Future Enhancements

1. **AST-based extraction**: Use libclang for more robust signature extraction
2. **Type inference**: Infer parameter relationships (e.g., buffer + size pairs)
3. **Smart generators**: Generate fuzzer data that respects parameter constraints
4. **Signature database**: Cache extracted signatures for reuse
5. **Manual override**: UI for users to specify signatures when extraction fails
