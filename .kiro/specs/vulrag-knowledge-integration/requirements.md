# Requirements Document

## Introduction

This feature enhances the existing CVE search system by integrating VUL-RAG's enriched knowledge base, which includes additional vulnerability metadata such as root causes, fix strategies, code patterns, and attack conditions. The system will create enhanced embeddings that incorporate this additional context and return comprehensive vulnerability information during searches to provide better context for LLM-based vulnerability fixing.

## Glossary

- **VUL-RAG**: A vulnerability knowledge base system that provides enriched CVE data with fix strategies and root cause analysis
- **Knowledge Base**: The VUL-RAG database containing CVE entries with additional fields (root_cause, fix_strategy, code_pattern, attack_condition, vulnerability_type)
- **Enhanced Embedding**: Vector representation that includes both standard CVE data and VUL-RAG enriched fields
- **CVE Search System**: The existing FAISS-based semantic search system for CVE vulnerabilities
- **Fix Context**: The comprehensive vulnerability information (including fix strategies) returned with search results for LLM consumption
- **Embedding Text**: The concatenated text representation used to create vector embeddings

## Requirements

### Requirement 1

**User Story:** As a security researcher, I want to import VUL-RAG's knowledge base into my project, so that I can access enriched vulnerability data with fix strategies and root cause analysis.

#### Acceptance Criteria

1. WHEN the system imports VUL-RAG data THEN the System SHALL parse the knowledge base JSON format containing cve_id, cwe_id, vulnerability_type, root_cause, attack_condition, fix_strategy, code_pattern, and description fields
2. WHEN importing knowledge base entries THEN the System SHALL validate that each entry contains required fields (cve_id, description) before storage
3. WHEN a knowledge base entry is stored THEN the System SHALL persist all VUL-RAG fields to the local database for future retrieval
4. WHEN duplicate CVE entries are encountered during import THEN the System SHALL merge the VUL-RAG data with existing CVE data without creating duplicates
5. WHEN the import process completes THEN the System SHALL report the number of successfully imported entries and any validation errors

### Requirement 2

**User Story:** As a developer, I want the system to create enhanced embeddings that include VUL-RAG fields, so that semantic searches can match against fix strategies and root causes in addition to descriptions.

#### Acceptance Criteria

1. WHEN creating embeddings for a CVE with VUL-RAG data THEN the System SHALL concatenate CVE ID, description, root cause, fix strategy, CWE ID, vulnerability type, and attack condition into the embedding text
2. WHEN a CVE lacks VUL-RAG enrichment data THEN the System SHALL create embeddings using only the available standard CVE fields
3. WHEN generating the embedding text THEN the System SHALL format fields with clear labels (e.g., "Root Cause:", "Fix Strategy:") for semantic clarity
4. WHEN the embedding process runs THEN the System SHALL use the same sentence transformer model (all-MiniLM-L6-v2) as the existing CVE embeddings for consistency
5. WHEN embeddings are created THEN the System SHALL normalize vectors using L2 normalization before storage in FAISS

### Requirement 3

**User Story:** As a user performing CVE searches, I want search results to include VUL-RAG enrichment data, so that I receive comprehensive vulnerability information including suggested fixes.

#### Acceptance Criteria

1. WHEN a semantic search returns matching CVEs THEN the System SHALL retrieve all associated VUL-RAG fields (root_cause, fix_strategy, code_pattern, attack_condition, vulnerability_type) from the database
2. WHEN formatting search results THEN the System SHALL include VUL-RAG fields in the response dictionary alongside standard CVE metadata
3. WHEN a matched CVE has no VUL-RAG enrichment THEN the System SHALL return the standard CVE fields with null or empty values for VUL-RAG fields
4. WHEN returning top-k results THEN the System SHALL maintain the similarity score ranking while including all enrichment data
5. WHEN the search completes THEN the System SHALL return results in a structured format suitable for LLM context consumption

### Requirement 4

**User Story:** As a developer integrating with LLMs, I want a dedicated method to retrieve fix context for vulnerabilities, so that I can provide comprehensive information to the LLM for generating patches.

#### Acceptance Criteria

1. WHEN requesting fix context for a CVE ID THEN the System SHALL return a formatted text block containing the CVE description, root cause, fix strategy, code pattern, and attack condition
2. WHEN requesting fix context for multiple CVEs THEN the System SHALL concatenate individual fix contexts with clear delimiters
3. WHEN a CVE has incomplete VUL-RAG data THEN the System SHALL include only the available fields in the fix context
4. WHEN formatting fix context THEN the System SHALL structure the text with clear section headers optimized for LLM comprehension
5. WHEN no VUL-RAG data exists for a CVE THEN the System SHALL return the standard CVE description with a note indicating limited context availability

### Requirement 5

**User Story:** As a system administrator, I want to create and manage separate FAISS indexes for standard and enhanced CVE embeddings, so that I can choose the appropriate search strategy based on my needs.

#### Acceptance Criteria

1. WHEN creating a new enhanced index THEN the System SHALL generate a distinct index name (e.g., "cve-vulrag") to differentiate from standard indexes
2. WHEN storing enhanced embeddings THEN the System SHALL save both the FAISS index file and metadata pickle file with the enhanced index name
3. WHEN loading an enhanced index THEN the System SHALL verify that metadata contains VUL-RAG fields before allowing searches
4. WHEN listing available indexes THEN the System SHALL indicate which indexes contain VUL-RAG enrichment data
5. WHEN switching between indexes THEN the System SHALL load the appropriate metadata schema without requiring system restart

### Requirement 6

**User Story:** As a security analyst, I want to search for vulnerabilities using natural language queries about fix strategies, so that I can find CVEs based on how they should be remediated.

#### Acceptance Criteria

1. WHEN searching with a fix-strategy query (e.g., "input validation fixes") THEN the System SHALL match against the fix_strategy field in embeddings
2. WHEN searching with a root-cause query (e.g., "buffer overflow causes") THEN the System SHALL match against the root_cause field in embeddings
3. WHEN searching with a code-pattern query THEN the System SHALL match against the code_pattern field in embeddings
4. WHEN performing semantic search THEN the System SHALL rank results by cosine similarity across all embedded fields
5. WHEN multiple CVEs match a query THEN the System SHALL return results ordered by relevance score with the most similar CVEs first

### Requirement 7

**User Story:** As a developer, I want backward compatibility with existing CVE search functionality, so that current integrations continue to work while new features are available.

#### Acceptance Criteria

1. WHEN using the standard cve-full index THEN the System SHALL continue to function with existing search methods without modification
2. WHEN the enhanced index is unavailable THEN the System SHALL fall back to standard CVE search without errors
3. WHEN search methods are called THEN the System SHALL accept the same parameters as the existing FAISSCVESearch class
4. WHEN results are returned THEN the System SHALL include VUL-RAG fields as optional additions to the existing result schema
5. WHEN existing scripts call search functions THEN the System SHALL return results in a format compatible with current consumers

### Requirement 8

**User Story:** As a data engineer, I want to update VUL-RAG enrichment data for existing CVEs, so that I can keep fix strategies and root cause information current.

#### Acceptance Criteria

1. WHEN updating a CVE with new VUL-RAG data THEN the System SHALL replace existing enrichment fields while preserving standard CVE metadata
2. WHEN an update is triggered THEN the System SHALL regenerate embeddings for the affected CVE with the new enrichment data
3. WHEN updating the FAISS index THEN the System SHALL replace the vector at the existing index position without reindexing all CVEs
4. WHEN updates complete THEN the System SHALL synchronize both the database and FAISS index to maintain consistency
5. WHEN bulk updates are performed THEN the System SHALL process updates in batches to optimize performance
