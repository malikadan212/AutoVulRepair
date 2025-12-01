# Implementation Plan

- [x] 1. Create signature extraction module





  - Implement `SignatureExtractor` class with regex-based pattern matching
  - Create `FunctionSignature` and `Parameter` data classes
  - Implement signature parsing for common C/C++ declaration formats
  - Add support for const, static, inline modifiers
  - Handle pointer and reference types
  - _Requirements: 2.1, 2.2, 2.3, 7.1, 7.2, 7.3_

- [x] 1.1 Write property test for signature extraction


  - **Property 4: Signature extraction from valid declarations**
  - **Validates: Requirements 2.1, 2.3, 7.2, 7.3**

- [x] 1.2 Write property test for signature completeness


  - **Property 3: Signature extraction completeness**
  - **Validates: Requirements 2.2**

- [x] 2. Create parameter mapping module





  - Implement `ParameterMapper` class
  - Create `ParameterMapping` data class
  - Implement type classification logic (string, buffer, integer, etc.)
  - Generate parameter preparation code for each type category
  - Generate function call code with correct arguments
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 2.1 Write property test for parameter type mapping





  - **Property 5: Parameter type mapping consistency**
  - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

- [x] 3. Integrate signature extraction into fuzz plan generation






  - Modify fuzz plan creation to extract signatures from source files
  - Add signature information to fuzz plan JSON entries
  - Implement signature serialization/deserialization
  - Add fallback handling when source files are unavailable
  - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [x] 3.1 Write property test for signature persistence


  - **Property 7: Fuzz plan signature persistence**
  - **Validates: Requirements 6.1, 6.2, 6.3**

- [x] 4. Enhance HarnessToolbox with signature awareness












  - Update `HarnessToolbox.__init__()` to initialize signature extractor and parameter mapper
  - Modify `generate_harness()` to use signature information
  - Update harness type selection to consider signature information
  - Add signature extraction from source code when available
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [ ] 5. Update parser_wrapper template




  - Modify template to accept signature information
  - Add parameter preparation code generation
  - Generate correct function call with parameters
  - Remove multiple extern declarations in favor of single correct declaration
  - Add signature comment showing detected signature
  - _Requirements: 1.1, 1.2, 4.1, 4.2, 4.3, 4.5_

- [x] 6. Update bytes_to_api template


  - Modify template to use signature information
  - Generate parameter preparation for buffer/size patterns
  - Generate correct function call with data and size parameters
  - _Requirements: 1.1, 1.3, 1.4, 4.1, 4.2, 4.3_

- [x] 7. Update fdp_adapter template


  - Modify template to use signature information
  - Generate FuzzedDataProvider calls based on parameter types
  - Generate correct function call with typed parameters
  - _Requirements: 1.3, 1.4, 3.4, 4.1, 4.2, 4.3_

- [x] 8. Update api_sequence template




  - Modify template to use signature information
  - Generate parameter preparation for API calls
  - Generate correct function calls in sequence
  - _Requirements: 1.3, 1.4, 4.1, 4.2, 4.3_

- [x] 8.1 Write property test for generated harnesses using prepared data


  - **Property 1: Generated harnesses use prepared data**
  - **Validates: Requirements 1.1, 1.2, 1.5**

- [x] 8.2 Write property test for parameter count matching

  - **Property 2: Parameter count matches signature**
  - **Validates: Requirements 1.3, 1.4**

- [x] 8.3 Write property test for template signature usage

  - **Property 6: Template uses signature information**
  - **Validates: Requirements 4.2, 4.3, 4.5**

- [ ] 9. Add error handling and fallbacks
  - Implement error handling for signature extraction failures
  - Add fallback signatures based on harness type
  - Generate TODO comments when signature extraction fails
  - Add metadata tracking for extraction failures
  - _Requirements: 2.5, 6.4, 7.4_

- [x] 10. Update fuzz plan display to show signatures



  - Modify fuzz plan HTML template to display function signatures
  - Add signature information to fuzz plan markdown report
  - Show parameter details in the UI
  - _Requirements: 6.5_

- [ ] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Create integration tests
  - Test end-to-end harness generation with real source files
  - Verify generated harnesses compile successfully
  - Test with known vulnerable functions from test suite
  - Verify harnesses can trigger known bugs

- [ ] 13. Add unit tests for edge cases
  - Test signature extraction with complex declarations
  - Test parameter mapping with unusual types
  - Test template rendering with missing signature data
  - Test error handling paths
