# Enhanced CVE Search with VUL-RAG Enrichment

## Overview

The `EnhancedFAISSCVESearch` class extends the standard FAISS CVE search to include VUL-RAG enrichment data (root causes, fix strategies, code patterns, and attack conditions) in search results.

## Features

- **Backward Compatible**: Extends `FAISSCVESearch` without breaking existing functionality
- **Enrichment Integration**: Automatically fetches VUL-RAG data from the database
- **Graceful Degradation**: Returns None for enrichment fields when data is unavailable
- **Structured Output**: Results include both standard CVE fields and VUL-RAG enrichment

## Installation

No additional dependencies required beyond the existing project requirements.

## Usage

### Basic Search with Enrichment

```python
from enhanced_cve_search import EnhancedFAISSCVESearch

# Initialize searcher
searcher = EnhancedFAISSCVESearch('cve-vulrag-test')

# Search with enrichment
results = searcher.search_with_enrichment("SQL injection", top_k=5)

# Access enrichment data
for result in results:
    print(f"{result['cve_id']}: {result.get('fix_strategy', 'N/A')}")
```

### Command Line Usage

```bash
# Search with enrichment
python enhanced_cve_search.py --index-name cve-vulrag-test --query "SQL injection" --top-k 5

# Output as JSON
python enhanced_cve_search.py --index-name cve-vulrag-test --query "buffer overflow" --json

# With filters
python enhanced_cve_search.py --index-name cve-vulrag-test --query "XSS" --severity HIGH --min-cvss 7.0
```

### Standard Search (Backward Compatible)

```python
# Use standard search without enrichment
results = searcher.search("buffer overflow", top_k=10)
# Returns only standard CVE fields
```

## Result Format

### Enhanced Search Results

Each result includes:

**Standard CVE Fields:**
- `cve_id`: CVE identifier
- `score`: Similarity score (0-1)
- `severity`: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
- `cvss_score`: CVSS score (if available)
- `cwe`: CWE identifier
- `published_date`: Publication date
- `description`: CVE description

**VUL-RAG Enrichment Fields:**
- `vulnerability_type`: Type of vulnerability (e.g., "SQL Injection", "XSS")
- `root_cause`: Root cause analysis
- `fix_strategy`: Recommended fix strategy
- `code_pattern`: Common code patterns associated with the vulnerability
- `attack_condition`: Conditions required for exploitation

**Note:** Enrichment fields are set to `None` for CVEs without VUL-RAG data.

### Example Result

```json
{
  "cve_id": "CVE-2023-12345",
  "score": 0.8542,
  "severity": "HIGH",
  "cvss_score": 7.5,
  "cwe": "CWE-79",
  "published_date": "2023-01-15",
  "description": "XSS vulnerability in web application",
  "vulnerability_type": "Cross-Site Scripting",
  "root_cause": "Insufficient input validation on user-supplied data",
  "fix_strategy": "Implement input sanitization and output encoding",
  "code_pattern": "Unescaped user input in HTML context",
  "attack_condition": "Attacker can inject malicious scripts through form inputs"
}
```

## API Reference

### EnhancedFAISSCVESearch

#### Constructor

```python
EnhancedFAISSCVESearch(
    index_name: str,
    index_dir: str = 'faiss_indexes',
    db_path: str = 'cves.db'
)
```

**Parameters:**
- `index_name`: Name of the FAISS index to use
- `index_dir`: Directory containing FAISS indexes (default: 'faiss_indexes')
- `db_path`: Path to SQLite database with vulrag_enrichment table (default: 'cves.db')

#### Methods

##### search_with_enrichment()

```python
search_with_enrichment(
    query: str,
    top_k: int = 10,
    severity_filter: str = None,
    min_cvss: float = None
) -> List[Dict[str, Any]]
```

Search CVEs and return results with VUL-RAG enrichment data.

**Parameters:**
- `query`: Natural language search query
- `top_k`: Number of results to return (default: 10)
- `severity_filter`: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- `min_cvss`: Minimum CVSS score

**Returns:** List of CVE dictionaries with standard fields plus VUL-RAG enrichment

##### search() (inherited)

Standard search method from `FAISSCVESearch` - returns results without enrichment fields.

## Implementation Details

### Database Schema

The enrichment data is stored in the `vulrag_enrichment` table:

```sql
CREATE TABLE vulrag_enrichment (
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
```

### Internal Methods

#### _load_vulrag_data()

Loads VUL-RAG enrichment data from the database for given CVE IDs.

```python
_load_vulrag_data(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]
```

#### _merge_results_with_enrichment()

Merges VUL-RAG enrichment data with search results.

```python
_merge_results_with_enrichment(
    results: List[Dict[str, Any]],
    enrichment: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]
```

## Testing

Run the test suite:

```bash
python test_enhanced_search.py
```

Run the demonstration:

```bash
python demo_enhanced_search.py
```

## Requirements Validation

This implementation satisfies the following requirements:

- **Requirement 3.1**: Retrieves all VUL-RAG fields from database
- **Requirement 3.2**: Includes VUL-RAG fields in response dictionary
- **Requirement 3.3**: Returns None for CVEs without enrichment
- **Requirement 3.4**: Maintains similarity score ranking
- **Requirement 3.5**: Returns structured format suitable for LLM consumption
- **Requirement 6.1-6.5**: Supports natural language search across all fields
- **Requirement 7.1-7.5**: Maintains backward compatibility

## Next Steps

The following tasks build on this implementation:

1. **Task 6**: Create fix context formatter for LLM integration
2. **Task 7**: Add fix context retrieval methods
3. **Task 12**: Integrate with existing LLM patching system

## Troubleshooting

### Index Not Found

If you get a "Index not found" error, ensure you've created the enhanced index:

```bash
python create_enhanced_index.py --index-name cve-vulrag-test
```

### Database Connection Error

Ensure the `cves.db` database exists and has the `vulrag_enrichment` table:

```bash
python verify_vulrag_schema.py
```

### No Enrichment Data

If all results show "No VUL-RAG enrichment available", import enrichment data:

```bash
python vulrag_importer.py --input sample_vulrag_data.json
```

## Files Created

- `enhanced_cve_search.py`: Main implementation
- `test_enhanced_search.py`: Test suite
- `demo_enhanced_search.py`: Demonstration script
- `ENHANCED_SEARCH_README.md`: This documentation

## License

Same as the parent project.
