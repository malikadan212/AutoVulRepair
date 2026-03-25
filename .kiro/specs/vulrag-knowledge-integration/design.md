# Design Document

## Overview

This design extends the existing CVE search system to integrate VUL-RAG's enriched knowledge base. The system will maintain backward compatibility with existing FAISS-based CVE search while adding enhanced embeddings that include fix strategies, root causes, code patterns, and attack conditions. The architecture follows a layered approach with data import, embedding generation, storage, and retrieval components.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│  (LLM Integration, Patch Generation, Web Interface)         │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│                  Search & Retrieval Layer                    │
│  ┌──────────────────┐      ┌──────────────────────┐        │
│  │ Enhanced Search  │      │  Fix Context         │        │
│  │ (VUL-RAG Index)  │      │  Formatter           │        │
│  └──────────────────┘      └──────────────────────┘        │
│  ┌──────────────────┐                                       │
│  │ Standard Search  │      (Backward Compatible)            │
│  │ (CVE-Full Index) │                                       │
│  └──────────────────┘                                       │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│                   Storage Layer                              │
│  ┌──────────────────┐      ┌──────────────────────┐        │
│  │ FAISS Indexes    │      │  SQLite Database     │        │
│  │ - cve-full       │      │  - cves table        │        │
│  │ - cve-vulrag     │      │  - vulrag_enrichment │        │
│  └──────────────────┘      └──────────────────────┘        │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│                  Data Import Layer                           │
│  ┌──────────────────┐      ┌──────────────────────┐        │
│  │ VUL-RAG Importer │      │  Embedding Generator │        │
│  │ (JSON Parser)    │      │  (SentenceTransform) │        │
│  └──────────────────┘      └──────────────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Backward Compatibility**: Existing CVE search functionality remains unchanged
2. **Separation of Concerns**: VUL-RAG enrichment is stored separately and joined during retrieval
3. **Extensibility**: New enrichment fields can be added without breaking existing functionality
4. **Performance**: FAISS vector search maintains sub-second query times even with enhanced embeddings
5. **Data Integrity**: Database constraints ensure CVE-enrichment relationships are maintained

## Components and Interfaces

### 1. VUL-RAG Data Importer

**Purpose**: Import and validate VUL-RAG knowledge base entries

**Class**: `VulRagImporter`

**Methods**:
- `import_from_json(file_path: str) -> ImportResult`: Import VUL-RAG data from JSON file
- `validate_entry(entry: dict) -> bool`: Validate required fields exist
- `merge_with_existing(cve_id: str, vulrag_data: dict) -> None`: Merge with existing CVE data
- `get_import_stats() -> dict`: Return statistics about the import process

**Input Format**:
```json
{
  "cve_id": "CVE-2023-12345",
  "cwe_id": "CWE-79",
  "vulnerability_type": "Cross-Site Scripting",
  "root_cause": "Insufficient input validation on user-supplied data",
  "attack_condition": "Attacker can inject malicious scripts through form inputs",
  "fix_strategy": "Implement input sanitization and output encoding",
  "code_pattern": "Unescaped user input in HTML context",
  "description": "XSS vulnerability in web application"
}
```

### 2. Database Schema Extension

**New Table**: `vulrag_enrichment`

```sql
CREATE TABLE IF NOT EXISTS vulrag_enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    cwe_id TEXT,
    vulnerability_type TEXT,
    root_cause TEXT,
    attack_condition TEXT,
    fix_strategy TEXT,
    code_pattern TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE INDEX idx_vulrag_cve_id ON vulrag_enrichment(cve_id);
```

### 3. Enhanced Embedding Generator

**Purpose**: Create embeddings that include VUL-RAG enrichment data

**Class**: `EnhancedEmbeddingGenerator`

**Methods**:
- `generate_embedding_text(cve_data: dict, vulrag_data: dict) -> str`: Format text for embedding
- `create_embeddings(cve_list: List[dict]) -> np.ndarray`: Generate vector embeddings
- `format_for_semantic_search(vulrag_data: dict) -> str`: Format VUL-RAG fields for embedding

**Embedding Text Format**:
```
CVE: {cve_id}
Description: {description}
Root Cause: {root_cause}
Fix Strategy: {fix_strategy}
CWE: {cwe_id}
Vulnerability Type: {vulnerability_type}
Attack Condition: {attack_condition}
Code Pattern: {code_pattern}
```

### 4. Enhanced FAISS Search

**Purpose**: Search CVEs with VUL-RAG enrichment data

**Class**: `EnhancedFAISSCVESearch` (extends `FAISSCVESearch`)

**Methods**:
- `search_with_enrichment(query: str, top_k: int) -> List[dict]`: Search and return enriched results
- `get_fix_context(cve_ids: List[str]) -> str`: Get formatted fix context for LLM
- `get_fix_context_single(cve_id: str) -> dict`: Get fix context for one CVE
- `_load_vulrag_data(cve_ids: List[str]) -> dict`: Load enrichment from database
- `_merge_results_with_enrichment(results: List[dict], enrichment: dict) -> List[dict]`: Combine search results with VUL-RAG data

**Enhanced Result Format**:
```python
{
    'cve_id': 'CVE-2023-12345',
    'score': 0.8542,
    'severity': 'HIGH',
    'cvss_score': 7.5,
    'description': '...',
    'cwe': 'CWE-79',
    # VUL-RAG enrichment fields
    'vulnerability_type': 'Cross-Site Scripting',
    'root_cause': 'Insufficient input validation...',
    'fix_strategy': 'Implement input sanitization...',
    'code_pattern': 'Unescaped user input...',
    'attack_condition': 'Attacker can inject...'
}
```

### 5. Fix Context Formatter

**Purpose**: Format vulnerability data for LLM consumption

**Class**: `FixContextFormatter`

**Methods**:
- `format_single_cve(cve_data: dict) -> str`: Format one CVE for LLM
- `format_multiple_cves(cve_list: List[dict]) -> str`: Format multiple CVEs with delimiters
- `format_for_patch_generation(cve_data: dict, code_snippet: str) -> str`: Create patch generation prompt

**Output Format**:
```
=== CVE-2023-12345 ===
Vulnerability Type: Cross-Site Scripting
Severity: HIGH (CVSS: 7.5)

Description:
XSS vulnerability in web application...

Root Cause:
Insufficient input validation on user-supplied data

Attack Condition:
Attacker can inject malicious scripts through form inputs

Fix Strategy:
Implement input sanitization and output encoding

Code Pattern:
Unescaped user input in HTML context

===================================
```

### 6. Index Manager

**Purpose**: Manage multiple FAISS indexes

**Class**: `IndexManager`

**Methods**:
- `list_indexes() -> List[dict]`: List all available indexes with metadata
- `get_index_info(index_name: str) -> dict`: Get information about specific index
- `create_enhanced_index(source_data: str, output_name: str) -> None`: Create new enhanced index
- `verify_index_schema(index_name: str) -> bool`: Verify index contains expected fields

## Data Models

### CVE Data Model (Existing)
```python
@dataclass
class CVE:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cwe: str
    published_date: str
    modified_date: str
```

### VUL-RAG Enrichment Model (New)
```python
@dataclass
class VulRagEnrichment:
    cve_id: str
    cwe_id: Optional[str]
    vulnerability_type: Optional[str]
    root_cause: Optional[str]
    attack_condition: Optional[str]
    fix_strategy: Optional[str]
    code_pattern: Optional[str]
    created_at: datetime
    updated_at: datetime
```

### Enhanced Search Result Model
```python
@dataclass
class EnhancedSearchResult:
    cve_id: str
    score: float
    severity: str
    cvss_score: Optional[float]
    description: str
    cwe: Optional[str]
    published_date: str
    # VUL-RAG fields
    vulnerability_type: Optional[str] = None
    root_cause: Optional[str] = None
    fix_strategy: Optional[str] = None
    code_pattern: Optional[str] = None
    attack_condition: Optional[str] = None
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*


### Data Import Properties

Property 1: JSON parsing completeness
*For any* valid VUL-RAG JSON entry containing all required fields, parsing should extract all fields (cve_id, cwe_id, vulnerability_type, root_cause, attack_condition, fix_strategy, code_pattern, description) into the corresponding data structure fields
**Validates: Requirements 1.1**

Property 2: Required field validation
*For any* knowledge base entry, if it lacks cve_id or description fields, the validation should reject it, and if it contains both required fields, the validation should accept it
**Validates: Requirements 1.2**

Property 3: Database storage round-trip
*For any* valid VUL-RAG entry, storing it to the database and then retrieving it by cve_id should return an entry with all the same field values
**Validates: Requirements 1.3**

Property 4: CVE uniqueness preservation
*For any* CVE ID, importing entries with that CVE ID multiple times should result in exactly one database record for that CVE ID
**Validates: Requirements 1.4**

Property 5: Import statistics accuracy
*For any* set of import entries (valid and invalid), the sum of successfully imported count and validation error count should equal the total number of entries attempted
**Validates: Requirements 1.5**

### Embedding Generation Properties

Property 6: Embedding text field inclusion
*For any* CVE with complete VUL-RAG data, the generated embedding text should contain all specified fields (CVE ID, description, root cause, fix strategy, CWE ID, vulnerability type, attack condition) as substrings
**Validates: Requirements 2.1**

Property 7: Graceful embedding degradation
*For any* CVE without VUL-RAG enrichment data, the embedding generation should succeed and produce a valid vector of the expected dimensionality
**Validates: Requirements 2.2**

Property 8: Embedding text label formatting
*For any* generated embedding text with VUL-RAG data, it should contain the label strings "Root Cause:", "Fix Strategy:", and "Attack Condition:"
**Validates: Requirements 2.3**

Property 9: Vector normalization
*For any* generated embedding vector, its L2 norm should equal 1.0 within floating point tolerance (±0.0001)
**Validates: Requirements 2.5**

### Search and Retrieval Properties

Property 10: Enrichment field completeness
*For any* search result where the CVE has VUL-RAG enrichment in the database, the result dictionary should contain all enrichment field keys (root_cause, fix_strategy, code_pattern, attack_condition, vulnerability_type)
**Validates: Requirements 3.1**

Property 11: Result schema consistency
*For any* search result, the response dictionary should contain both standard CVE keys (cve_id, description, severity) and VUL-RAG field keys (even if VUL-RAG values are None)
**Validates: Requirements 3.2, 3.3**

Property 12: Similarity score ordering
*For any* search returning multiple results, the results should be ordered by similarity score in descending order (highest scores first)
**Validates: Requirements 3.4, 6.4, 6.5**

Property 13: Result JSON serializability
*For any* search result, it should be serializable to JSON without errors
**Validates: Requirements 3.5**

### Fix Context Properties

Property 14: Fix context field inclusion
*For any* CVE with complete VUL-RAG enrichment, the fix context string should contain the description, root cause, fix strategy, code pattern, and attack condition as substrings
**Validates: Requirements 4.1**

Property 15: Multi-CVE context concatenation
*For any* list of N CVE IDs (N > 1), the combined fix context should contain N delimiter strings and N individual CVE contexts
**Validates: Requirements 4.2**

Property 16: Partial data handling
*For any* CVE with some but not all enrichment fields populated, the fix context should include only the non-null fields and should not contain placeholder text for missing fields
**Validates: Requirements 4.3**

Property 17: Fix context header formatting
*For any* generated fix context, it should contain section header strings like "Root Cause:", "Fix Strategy:", and "Attack Condition:"
**Validates: Requirements 4.4**

Property 18: Fallback context generation
*For any* CVE without VUL-RAG enrichment, the fix context should contain the CVE description and a note string indicating limited context availability
**Validates: Requirements 4.5**

### Index Management Properties

Property 19: Index file pair creation
*For any* enhanced index creation operation, both the .index file and .metadata file should exist on disk after completion
**Validates: Requirements 5.2**

Property 20: Enhanced index metadata validation
*For any* loaded enhanced index, the metadata should contain at least one VUL-RAG field key (root_cause, fix_strategy, or code_pattern) in at least one metadata entry
**Validates: Requirements 5.3**

Property 21: Index listing completeness
*For any* index list operation, each returned index should have an indicator (boolean or flag) showing whether it contains VUL-RAG enrichment
**Validates: Requirements 5.4**

Property 22: Index switching state consistency
*For any* sequence of loading index A, then loading index B, searches should use metadata from index B, not index A
**Validates: Requirements 5.5**

### Backward Compatibility Properties

Property 23: Result schema extension
*For any* search result from an enhanced index, it should contain all standard CVE fields that the base FAISSCVESearch class returns, plus optional VUL-RAG fields
**Validates: Requirements 7.4, 7.5**

### Update and Synchronization Properties

Property 24: Selective field updates
*For any* CVE update operation, the VUL-RAG enrichment fields should change to the new values while standard CVE fields (description, severity, cvss_score) remain unchanged
**Validates: Requirements 8.1**

Property 25: Embedding update consistency
*For any* CVE whose enrichment data is updated, searching for that CVE by its original description should return results reflecting the new enrichment data
**Validates: Requirements 8.2**

Property 26: Index size preservation
*For any* single CVE update operation, the total number of vectors in the FAISS index should remain the same before and after the update
**Validates: Requirements 8.3**

Property 27: Database-index synchronization
*For any* CVE after an update operation, the enrichment data retrieved from the database should match the enrichment data embedded in the FAISS index vector
**Validates: Requirements 8.4**

## Error Handling

### Import Errors

1. **Invalid JSON Format**: If the input file is not valid JSON, raise `JSONDecodeError` with a clear message
2. **Missing Required Fields**: If an entry lacks cve_id or description, log a warning and skip the entry
3. **Database Constraint Violations**: If a foreign key constraint fails (CVE doesn't exist), log an error and continue with remaining entries
4. **File Not Found**: If the import file doesn't exist, raise `FileNotFoundError` with the file path

### Search Errors

1. **Index Not Found**: If the specified FAISS index doesn't exist, raise `FileNotFoundError` with available index names
2. **Database Connection Failure**: If the database is unavailable, raise `DatabaseError` with connection details
3. **Empty Query**: If the search query is empty or whitespace-only, return an empty result list
4. **Invalid top_k Parameter**: If top_k is negative or zero, raise `ValueError` with valid range

### Embedding Errors

1. **Model Loading Failure**: If the sentence transformer model can't be loaded, raise `ModelLoadError` with model name
2. **Dimension Mismatch**: If generated embeddings don't match the expected dimension, raise `DimensionError`
3. **Memory Errors**: If embedding generation runs out of memory, process in smaller batches and log a warning

### Update Errors

1. **CVE Not Found**: If updating a non-existent CVE, raise `CVENotFoundError` with the CVE ID
2. **Index Update Failure**: If FAISS index update fails, rollback database changes and raise `IndexUpdateError`
3. **Concurrent Modification**: If a CVE is modified during an update, retry the operation up to 3 times

## Testing Strategy

### Unit Testing

The system will use pytest for unit testing with the following test categories:

1. **Data Import Tests**
   - Test JSON parsing with valid and invalid formats
   - Test validation logic for required fields
   - Test database insertion and duplicate handling
   - Test import statistics calculation

2. **Embedding Generation Tests**
   - Test embedding text formatting with complete and partial data
   - Test vector normalization
   - Test model consistency

3. **Search Tests**
   - Test result formatting and enrichment merging
   - Test filtering and ranking
   - Test error handling for missing indexes

4. **Fix Context Tests**
   - Test single and multi-CVE formatting
   - Test partial data handling
   - Test fallback behavior

5. **Index Management Tests**
   - Test index creation and file generation
   - Test index loading and validation
   - Test index switching

### Property-Based Testing

The system will use Hypothesis for property-based testing. Each property-based test will run a minimum of 100 iterations to ensure robust validation.

**Property-based testing library**: Hypothesis (Python)

**Test configuration**: Each test will use `@given` decorators with appropriate strategies and `@settings(max_examples=100)` to ensure sufficient coverage.

**Test tagging**: Each property-based test will include a comment with the format:
`# Feature: vulrag-knowledge-integration, Property {number}: {property_text}`

**Key property tests**:

1. **Property 3: Database storage round-trip** - Generate random VUL-RAG entries, store and retrieve them, verify data integrity
2. **Property 4: CVE uniqueness preservation** - Generate random CVE IDs, import duplicates, verify single database records
3. **Property 9: Vector normalization** - Generate random CVE data, create embeddings, verify L2 norm equals 1.0
4. **Property 12: Similarity score ordering** - Perform searches, verify results are sorted by descending score
5. **Property 26: Index size preservation** - Update random CVEs, verify index size remains constant

### Integration Testing

Integration tests will verify end-to-end workflows:

1. **Import-to-Search Flow**: Import VUL-RAG data, create enhanced index, perform searches, verify enriched results
2. **Update Flow**: Import data, update enrichment, verify search results reflect updates
3. **Backward Compatibility**: Run existing search scripts against new system, verify results match expected format
4. **LLM Integration**: Generate fix contexts, pass to mock LLM, verify format is consumable

### Test Data

- **Synthetic VUL-RAG Data**: Generate test JSON files with various field combinations
- **Real CVE Samples**: Use a small subset of real CVE data for integration tests
- **Edge Cases**: Empty strings, very long text, special characters, Unicode
- **Performance Data**: Large datasets (10k+ CVEs) for performance validation

## Performance Considerations

### Embedding Generation

- **Batch Processing**: Generate embeddings in batches of 100 to optimize GPU/CPU usage
- **Caching**: Cache the sentence transformer model to avoid reloading
- **Parallel Processing**: Use multiprocessing for large-scale embedding generation

### Search Performance

- **FAISS Optimization**: Use IVF (Inverted File) index for datasets > 100k CVEs
- **Database Indexing**: Create indexes on cve_id and frequently queried fields
- **Result Caching**: Cache frequent queries for 5 minutes to reduce database load

### Memory Management

- **Lazy Loading**: Load metadata only when needed, not all at once
- **Streaming**: Process large import files in streaming mode
- **Index Sharding**: Split very large indexes into multiple shards

### Expected Performance Metrics

- **Import Speed**: 1000 CVEs per second
- **Embedding Generation**: 500 CVEs per second
- **Search Latency**: < 100ms for top-10 results
- **Database Query**: < 50ms for enrichment data retrieval

## Security Considerations

1. **Input Validation**: Sanitize all user inputs to prevent SQL injection
2. **File Path Validation**: Validate file paths to prevent directory traversal attacks
3. **API Key Protection**: Store Gemini API keys in environment variables, never in code
4. **Data Privacy**: Ensure CVE data doesn't contain sensitive information before embedding
5. **Access Control**: Implement read-only access for search operations, write access only for import/update

## Deployment Considerations

1. **Database Migration**: Create migration script to add vulrag_enrichment table to existing databases
2. **Index Versioning**: Version FAISS indexes to handle schema changes
3. **Backward Compatibility**: Maintain support for existing cve-full index during transition
4. **Monitoring**: Log import statistics, search performance, and error rates
5. **Documentation**: Update user guides with VUL-RAG integration instructions

## Future Enhancements

1. **Incremental Updates**: Support streaming updates without full reindexing
2. **Multi-Language Support**: Extend VUL-RAG data to include multiple languages
3. **Custom Enrichment**: Allow users to add custom enrichment fields
4. **Advanced Filtering**: Add filters for vulnerability_type, attack_condition patterns
5. **Visualization**: Create dashboards showing enrichment coverage and search patterns
