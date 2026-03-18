# Requirements Document

## Introduction

The harness generation system currently creates fuzz harnesses that prepare input data from the fuzzer but fail to pass that data to the target functions under test. This spec addresses the critical issue where parser wrapper harnesses call target functions with no arguments instead of passing the prepared fuzzer input, rendering the fuzzing ineffective.

## Glossary

- **Harness Generator**: The system component that creates libFuzzer-compatible test harnesses from fuzz plan entries
- **Parser Wrapper Template**: A harness template designed for functions that parse string or byte input
- **Target Function**: The function under test that the harness is designed to fuzz
- **Fuzzer Data**: The raw byte array provided by libFuzzer to the harness
- **Function Signature**: The declaration of a function including its name, return type, and parameter types
- **AST**: Abstract Syntax Tree, a tree representation of source code structure
- **FuzzedDataProvider**: A libFuzzer utility class for consuming fuzzer data in typed chunks

## Requirements

### Requirement 1

**User Story:** As a security researcher, I want harnesses to actually pass fuzzer data to target functions, so that the fuzzing can discover vulnerabilities in those functions.

#### Acceptance Criteria

1. WHEN a parser wrapper harness is generated for a target function THEN the harness SHALL pass the prepared input data to that function
2. WHEN the harness prepares a null-terminated string from fuzzer data THEN the harness SHALL use that string as an argument to the target function
3. WHEN a target function requires multiple parameters THEN the harness SHALL provide all required parameters from the fuzzer data
4. WHEN a harness calls a target function THEN the function call SHALL match the target function's signature
5. WHEN fuzzer data is allocated and prepared THEN the harness SHALL ensure that data is consumed by the target function before cleanup

### Requirement 2

**User Story:** As a developer, I want the harness generator to extract function signatures from source code, so that harnesses can correctly call target functions with appropriate parameters.

#### Acceptance Criteria

1. WHEN the harness generator processes a target function THEN the system SHALL extract the function signature from the source code
2. WHEN a function signature is extracted THEN the system SHALL identify the function name, return type, and all parameter types
3. WHEN source code contains function declarations THEN the system SHALL parse those declarations to obtain signature information
4. WHEN multiple overloads of a function exist THEN the system SHALL identify all available signatures
5. WHEN signature extraction fails THEN the system SHALL provide a clear error message indicating what information is missing

### Requirement 3

**User Story:** As a developer, I want the harness generator to map fuzzer data to function parameters, so that target functions receive appropriate typed inputs.

#### Acceptance Criteria

1. WHEN a target function accepts a string parameter THEN the harness SHALL convert fuzzer data to a null-terminated string
2. WHEN a target function accepts a size parameter THEN the harness SHALL provide the size of the fuzzer data
3. WHEN a target function accepts a buffer and length THEN the harness SHALL pass both the data pointer and size
4. WHEN a target function accepts integer parameters THEN the harness SHALL extract integers from the fuzzer data
5. WHEN a target function accepts pointer parameters THEN the harness SHALL allocate appropriate memory and pass valid pointers

### Requirement 4

**User Story:** As a developer, I want harness templates to include parameter information, so that generated harnesses can be customized for different function signatures.

#### Acceptance Criteria

1. WHEN a harness template is instantiated THEN the template SHALL accept function signature information as input
2. WHEN generating a function call THEN the template SHALL use the provided parameter list
3. WHEN the template renders a harness THEN the harness SHALL include all necessary parameter preparation code
4. WHEN parameter types vary THEN the template SHALL adapt the data preparation logic accordingly
5. WHEN the fuzz plan specifies parameter details THEN the template SHALL use that information in code generation

### Requirement 5

**User Story:** As a security researcher, I want the system to handle common parameter patterns, so that harnesses work correctly for typical C/C++ function signatures.

#### Acceptance Criteria

1. WHEN a function accepts `(const char* str)` THEN the harness SHALL pass a null-terminated string
2. WHEN a function accepts `(const uint8_t* data, size_t size)` THEN the harness SHALL pass the raw fuzzer buffer and its size
3. WHEN a function accepts `(char* buffer, size_t len)` THEN the harness SHALL allocate a buffer and pass it with the size
4. WHEN a function accepts `(const std::string& str)` THEN the harness SHALL construct a std::string from fuzzer data
5. WHEN a function accepts `(void* data, int length)` THEN the harness SHALL cast the fuzzer data appropriately and pass the length

### Requirement 6

**User Story:** As a developer, I want the fuzz plan to include function signature information, so that the harness generator has the data it needs to create correct harnesses.

#### Acceptance Criteria

1. WHEN a fuzz plan entry is created THEN the entry SHALL include the target function signature
2. WHEN the fuzz plan is stored THEN the function signature SHALL be persisted in the JSON format
3. WHEN the harness generator reads a fuzz plan entry THEN the generator SHALL extract the function signature
4. WHEN signature information is incomplete THEN the system SHALL use reasonable defaults or request user input
5. WHEN the fuzz plan is displayed THEN the function signature SHALL be visible to the user

### Requirement 7

**User Story:** As a developer, I want a simple signature extraction mechanism, so that the system can work without complex AST parsing initially.

#### Acceptance Criteria

1. WHEN extracting function signatures THEN the system SHALL support regex-based extraction as a fallback
2. WHEN a function declaration matches a simple pattern THEN the system SHALL extract the signature using pattern matching
3. WHEN regex extraction is used THEN the system SHALL handle common C/C++ function declaration formats
4. WHEN the simple extraction fails THEN the system SHALL provide guidance on manual signature specification
5. WHEN function signatures are provided manually THEN the system SHALL accept them in a standard format
