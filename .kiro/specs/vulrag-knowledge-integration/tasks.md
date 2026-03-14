# Implementation Plan

- [x] 1. Extend database schema for VUL-RAG enrichment





  - Create migration script to add vulrag_enrichment table with all required fields
  - Add foreign key constraint linking to cves table
  - Create index on cve_id for fast lookups
  - Test database schema creation on fresh and existing databases
  - _Requirements: 1.3, 1.4_

- [ ]* 1.1 Write property test for database round-trip
  - **Property 3: Database storage round-trip**
  - **Validates: Requirements 1.3**

- [x] 2. Implement VUL-RAG data importer





  - Create VulRagImporter class with JSON parsing functionality
  - Implement validation for required fields (cve_id, description)
  - Add merge logic to handle duplicate CVE entries
  - Implement import statistics tracking (success count, error count)
  - Add error handling for invalid JSON and missing files
  - _Requirements: 1.1, 1.2, 1.4, 1.5_

- [ ]* 2.1 Write property test for required field validation
  - **Property 2: Required field validation**
  - **Validates: Requirements 1.2**

- [ ]* 2.2 Write property test for CVE uniqueness
  - **Property 4: CVE uniqueness preservation**
  - **Validates: Requirements 1.4**

- [ ]* 2.3 Write property test for import statistics
  - **Property 5: Import statistics accuracy**
  - **Validates: Requirements 1.5**

- [ ]* 2.4 Write unit tests for importer
  - Test JSON parsing with valid and malformed data
  - Test validation logic with various field combinations
  - Test duplicate handling scenarios
  - Test error reporting
  - _Requirements: 1.1, 1.2, 1.4, 1.5_

- [x] 3. Create enhanced embedding generator





  - Create EnhancedEmbeddingGenerator class
  - Implement embedding text formatting with labeled fields (CVE, Description, Root Cause, Fix Strategy, etc.)
  - Add logic to handle CVEs with partial or missing VUL-RAG data
  - Implement vector generation using sentence-transformers (all-MiniLM-L6-v2)
  - Add L2 normalization for all generated vectors
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [ ]* 3.1 Write property test for embedding text field inclusion
  - **Property 6: Embedding text field inclusion**
  - **Validates: Requirements 2.1**

- [ ]* 3.2 Write property test for graceful degradation
  - **Property 7: Graceful embedding degradation**
  - **Validates: Requirements 2.2**

- [ ]* 3.3 Write property test for vector normalization
  - **Property 9: Vector normalization**
  - **Validates: Requirements 2.5**

- [ ]* 3.4 Write unit tests for embedding generator
  - Test embedding text formatting with complete data
  - Test embedding text formatting with partial data
  - Test label inclusion in generated text
  - Test model consistency
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [x] 4. Build enhanced FAISS index creation tool





  - Create script to generate enhanced FAISS index from database
  - Load CVE data and VUL-RAG enrichment from database
  - Generate embeddings using EnhancedEmbeddingGenerator
  - Create FAISS index with normalized vectors
  - Save index file and metadata pickle with distinct name (cve-vulrag)
  - Add progress reporting during index creation
  - _Requirements: 2.1, 2.2, 2.5, 5.1, 5.2_

- [ ]* 4.1 Write property test for index file creation
  - **Property 19: Index file pair creation**
  - **Validates: Requirements 5.2**

- [ ]* 4.2 Write unit tests for index creation
  - Test index file generation
  - Test metadata file generation
  - Test progress reporting
  - _Requirements: 5.1, 5.2_

- [x] 5. Implement enhanced search functionality





  - Create EnhancedFAISSCVESearch class extending FAISSCVESearch
  - Implement search_with_enrichment method that retrieves VUL-RAG data
  - Add _load_vulrag_data method to fetch enrichment from database
  - Implement _merge_results_with_enrichment to combine search results with VUL-RAG fields
  - Ensure results include all standard CVE fields plus enrichment fields
  - Handle CVEs without enrichment by setting VUL-RAG fields to None
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 6.1, 6.2, 6.3, 6.4, 6.5_

- [ ]* 5.1 Write property test for enrichment field completeness
  - **Property 10: Enrichment field completeness**
  - **Validates: Requirements 3.1**

- [ ]* 5.2 Write property test for result schema consistency
  - **Property 11: Result schema consistency**
  - **Validates: Requirements 3.2, 3.3**

- [ ]* 5.3 Write property test for similarity score ordering
  - **Property 12: Similarity score ordering**
  - **Validates: Requirements 3.4, 6.4, 6.5**

- [ ]* 5.4 Write property test for JSON serializability
  - **Property 13: Result JSON serializability**
  - **Validates: Requirements 3.5**

- [ ]* 5.5 Write unit tests for enhanced search
  - Test search with enriched CVEs
  - Test search with non-enriched CVEs
  - Test result merging logic
  - Test filtering and ranking
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 6. Create fix context formatter




  - Create FixContextFormatter class
  - Implement format_single_cve method with structured sections
  - Implement format_multiple_cves with clear delimiters
  - Add logic to handle partial VUL-RAG data (include only available fields)
  - Implement fallback formatting for CVEs without enrichment
  - Add section headers optimized for LLM comprehension
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ]* 6.1 Write property test for fix context field inclusion
  - **Property 14: Fix context field inclusion**
  - **Validates: Requirements 4.1**

- [ ]* 6.2 Write property test for multi-CVE concatenation
  - **Property 15: Multi-CVE context concatenation**
  - **Validates: Requirements 4.2**

- [ ]* 6.3 Write property test for partial data handling
  - **Property 16: Partial data handling**
  - **Validates: Requirements 4.3**

- [ ]* 6.4 Write unit tests for fix context formatter
  - Test single CVE formatting
  - Test multiple CVE formatting
  - Test partial data scenarios
  - Test fallback formatting
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 7. Add fix context retrieval to enhanced search




  - Add get_fix_context method to EnhancedFAISSCVESearch
  - Add get_fix_context_single method for individual CVEs
  - Integrate FixContextFormatter for formatting
  - Handle lists of CVE IDs and single CVE IDs
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ]* 7.1 Write unit tests for fix context retrieval
  - Test single CVE context retrieval
  - Test multiple CVE context retrieval
  - Test error handling for non-existent CVEs
  - _Requirements: 4.1, 4.2_

- [x] 8. Implement index manager





  - Create IndexManager class
  - Implement list_indexes method to show all available indexes
  - Add get_index_info method to retrieve index metadata
  - Implement verify_index_schema to check for VUL-RAG fields
  - Add indicators showing which indexes contain enrichment
  - _Requirements: 5.3, 5.4, 5.5_

- [ ]* 8.1 Write property test for enhanced index validation
  - **Property 20: Enhanced index metadata validation**
  - **Validates: Requirements 5.3**

- [ ]* 8.2 Write property test for index listing
  - **Property 21: Index listing completeness**
  - **Validates: Requirements 5.4**

- [ ]* 8.3 Write unit tests for index manager
  - Test index listing
  - Test index info retrieval
  - Test schema verification
  - _Requirements: 5.3, 5.4, 5.5_

- [x] 9. Ensure backward compatibility





  - Verify EnhancedFAISSCVESearch accepts same parameters as FAISSCVESearch
  - Test that standard cve-full index still works with existing code
  - Ensure result format includes all standard fields
  - Add graceful fallback when enhanced index is unavailable
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ]* 9.1 Write property test for result schema extension
  - **Property 23: Result schema extension**
  - **Validates: Requirements 7.4, 7.5**

- [ ]* 9.2 Write unit tests for backward compatibility
  - Test standard index functionality
  - Test parameter compatibility
  - Test result format compatibility
  - Test fallback behavior
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 10. Implement CVE update functionality





  - Add update_vulrag_enrichment method to update existing CVE enrichment
  - Implement selective field updates (preserve standard CVE data)
  - Add embedding regeneration for updated CVEs
  - Implement FAISS index vector replacement at existing position
  - Ensure database and index remain synchronized
  - _Requirements: 8.1, 8.2, 8.3, 8.4_

- [ ]* 10.1 Write property test for selective field updates
  - **Property 24: Selective field updates**
  - **Validates: Requirements 8.1**

- [ ]* 10.2 Write property test for embedding update consistency
  - **Property 25: Embedding update consistency**
  - **Validates: Requirements 8.2**

- [ ]* 10.3 Write property test for index size preservation
  - **Property 26: Index size preservation**
  - **Validates: Requirements 8.3**

- [ ]* 10.4 Write property test for database-index synchronization
  - **Property 27: Database-index synchronization**
  - **Validates: Requirements 8.4**

- [x] 10.5 Write unit tests for update functionality



  - Test single CVE updates
  - Test bulk updates
  - Test error handling
  - Test synchronization
  - _Requirements: 8.1, 8.2, 8.3, 8.4_

- [x] 11. Create command-line tools





  - Create import_vulrag_data.py script for importing VUL-RAG JSON files
  - Create create_enhanced_index.py script for building enhanced FAISS indexes
  - Create search_enhanced_cve.py script for searching with enrichment
  - Add command-line arguments for all configurable options
  - Add help text and usage examples
  - _Requirements: 1.1, 1.2, 1.5, 5.1, 5.2, 6.1, 6.2, 6.3_

- [ ]* 11.1 Write unit tests for CLI tools
  - Test argument parsing
  - Test error handling
  - Test output formatting
  - _Requirements: 1.1, 1.5_

- [ ] 12. Integrate with existing LLM patching system
  - Update ai_patch_generator.py to use enhanced search
  - Modify patch generation to include fix context from VUL-RAG
  - Update autovulrepair_rag_integration.py to use enriched CVE data
  - Ensure fix strategies are passed to LLM prompts
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ]* 12.1 Write integration tests for LLM patching
  - Test end-to-end patch generation with enriched data
  - Test fix context formatting in LLM prompts
  - Test fallback behavior when enrichment is unavailable
  - _Requirements: 4.1, 4.2, 4.5_

- [ ] 13. Create documentation and examples
  - Write user guide for importing VUL-RAG data
  - Document enhanced search API with examples
  - Create example VUL-RAG JSON file for testing
  - Add troubleshooting section for common issues
  - Update existing documentation to mention VUL-RAG integration
  - _Requirements: 1.1, 3.1, 4.1, 5.1_

- [ ] 14. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
