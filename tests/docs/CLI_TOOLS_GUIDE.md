# VUL-RAG Command-Line Tools Guide

This guide covers the three command-line tools for working with VUL-RAG enriched CVE data.

## Overview

The VUL-RAG integration provides three command-line tools:

1. **import_vulrag_data.py** - Import VUL-RAG knowledge base data
2. **create_enhanced_index.py** - Build FAISS indexes with enrichment
3. **search_enhanced_cve.py** - Search CVEs with enrichment data

## Prerequisites

- Python 3.7+
- Required packages: `pip install -r requirements.txt`
- CVE database with `vulrag_enrichment` table (run `migrate_vulrag_schema.py` first)

## Tool 1: import_vulrag_data.py

Import VUL-RAG knowledge base entries from JSON files into the CVE database.

### Basic Usage

```bash
# Import VUL-RAG data
python import_vulrag_data.py --file vulrag_data.json

# Import with custom database
python import_vulrag_data.py --file vulrag_data.json --db-path /path/to/cves.db

# Show import statistics
python import_vulrag_data.py --stats

# Verbose output with detailed errors
python import_vulrag_data.py --file vulrag_data.json --verbose
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--file FILE` | Path to VUL-RAG JSON file to import | Required |
| `--db-path PATH` | Path to CVE database | `cves.db` |
| `--stats` | Show import statistics instead of importing | - |
| `--verbose, -v` | Enable verbose output with detailed errors | - |

### VUL-RAG JSON Format

```json
{
  "cve_id": "CVE-2023-12345",
  "description": "Vulnerability description",
  "cwe_id": "CWE-79",
  "vulnerability_type": "Cross-Site Scripting",
  "root_cause": "Insufficient input validation",
  "attack_condition": "Attacker can inject scripts",
  "fix_strategy": "Implement input sanitization",
  "code_pattern": "Unescaped user input"
}
```

**Required Fields:**
- `cve_id` - CVE identifier (e.g., CVE-2023-12345)
- `description` - Vulnerability description

**Optional Fields:**
- `cwe_id` - CWE identifier
- `vulnerability_type` - Type of vulnerability
- `root_cause` - Root cause analysis
- `attack_condition` - Attack conditions
- `fix_strategy` - Recommended fix strategy
- `code_pattern` - Vulnerable code pattern

### Examples

**Import a single file:**
```bash
python import_vulrag_data.py --file sample_vulrag_data.json
```

**Check import statistics:**
```bash
python import_vulrag_data.py --stats
```

Output:
```
VUL-RAG Import Statistics
==================================================
Total enrichments: 11

Field Coverage:
CWE ID               ██████████░░░░░░░░░░      6 ( 54.5%)
Vulnerability Type   ██████████░░░░░░░░░░      6 ( 54.5%)
Root Cause           ██████████░░░░░░░░░░      6 ( 54.5%)
Attack Condition     ██████████░░░░░░░░░░      6 ( 54.5%)
Fix Strategy         ████████████░░░░░░░░      7 ( 63.6%)
Code Pattern         ██████████░░░░░░░░░░      6 ( 54.5%)
```

### Error Handling

The importer validates each entry and reports errors:
- Missing required fields (cve_id, description)
- Invalid CVE ID format
- Database integrity errors
- JSON parsing errors

Errors are displayed in the output and can be saved to a file with `--verbose`.

---

## Tool 2: create_enhanced_index.py

Build FAISS indexes with VUL-RAG enrichment data for semantic search.

### Basic Usage

```bash
# Create enhanced index with all CVEs
python create_enhanced_index.py

# Create with custom name
python create_enhanced_index.py --index-name cve-vulrag-v2

# Create test index with limited records
python create_enhanced_index.py --index-name cve-test --max-records 1000

# Test search after creation
python create_enhanced_index.py --test-search "SQL injection fix"
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--index-name NAME` | Name for the enhanced index | `cve-vulrag` |
| `--db-path PATH` | Path to CVE database | `cves.db` |
| `--batch-size N` | Batch size for processing | `100` |
| `--max-records N` | Maximum records to process (for testing) | All records |
| `--test-search QUERY` | Test search query after creation | - |
| `--skip-build` | Skip building, only run test search | - |

### Index Creation Process

1. **Validation** - Checks database schema and tables
2. **Statistics** - Shows enrichment coverage
3. **Embedding Generation** - Creates vectors with VUL-RAG data
4. **Index Building** - Builds FAISS index with progress bar
5. **Saving** - Saves index, metadata, and info files

### Output Files

The tool creates three files in `faiss_indexes/`:

- `{index-name}.index` - FAISS index file
- `{index-name}.metadata` - Metadata pickle file
- `{index-name}.info` - JSON info file with statistics

### Examples

**Create production index:**
```bash
python create_enhanced_index.py
```

Output:
```
Loading embedding model...
✓ Model loaded: all-MiniLM-L6-v2 (384 dimensions)

Enrichment Statistics:
  Total CVEs: 316,437
  Enriched CVEs: 11
  Enrichment coverage: 0.0%

Building enhanced index with 316,437 CVEs...
Processing CVEs: 100%|████████████| 316437/316437

✓ Enhanced index creation complete!
Total vectors: 316,437
Index dimension: 384
Index location: faiss_indexes/cve-vulrag.index
```

**Create test index:**
```bash
python create_enhanced_index.py --index-name cve-test --max-records 100
```

**Test search on existing index:**
```bash
python create_enhanced_index.py --test-search "buffer overflow" --skip-build
```

---

## Tool 3: search_enhanced_cve.py

Search CVEs with VUL-RAG enrichment data including root causes and fix strategies.

### Basic Usage

```bash
# Basic search
python search_enhanced_cve.py --query "SQL injection"

# Search with filters
python search_enhanced_cve.py --query "buffer overflow" --severity HIGH --min-cvss 7.0

# Get more results
python search_enhanced_cve.py --query "XSS" --top-k 20

# JSON output
python search_enhanced_cve.py --query "input validation" --json

# Get fix context for specific CVE
python search_enhanced_cve.py --fix-context CVE-2023-12345

# List available indexes
python search_enhanced_cve.py --list-indexes
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--query QUERY` | Search query (natural language) | Required* |
| `--fix-context CVE_ID` | Get fix context for CVE(s) | - |
| `--list-indexes` | List available FAISS indexes | - |
| `--top-k N` | Number of results to return | `10` |
| `--severity LEVEL` | Filter by severity (LOW/MEDIUM/HIGH/CRITICAL) | - |
| `--min-cvss SCORE` | Minimum CVSS score (0.0-10.0) | - |
| `--index-name NAME` | FAISS index to use | `cve-vulrag` |
| `--index-dir DIR` | Directory with FAISS indexes | `faiss_indexes` |
| `--db-path PATH` | Path to CVE database | `cves.db` |
| `--json` | Output results as JSON | - |
| `--full` | Show full text (no truncation) | - |
| `--verbose, -v` | Enable verbose output | - |

*One of `--query`, `--fix-context`, or `--list-indexes` is required.

### Search Features

**Natural Language Queries:**
- "SQL injection fixes"
- "buffer overflow causes"
- "XSS input sanitization"
- "memory corruption vulnerabilities"

**Search by Fix Strategy:**
- "input validation"
- "bounds checking"
- "output encoding"

**Search by Root Cause:**
- "insufficient validation"
- "memory corruption"
- "improper authentication"

### Examples

**Basic search:**
```bash
python search_enhanced_cve.py --query "SQL injection"
```

Output:
```
Enhanced CVE Search with VUL-RAG Enrichment
============================================

Query: 'SQL injection'
Results: Top 10

Found 10 results
============================================

1. CVE-2023-12345
----------------------------------------
Similarity Score: 0.8542
Severity: HIGH
CVSS Score: 7.5
CWE: CWE-89
Published: 2023-01-15

Description:
  SQL injection vulnerability in web application...

VUL-RAG Enrichment:
  Type: SQL Injection
  Root Cause: Insufficient input validation on user-supplied data
  Fix Strategy: Use parameterized queries and input sanitization
  Attack Condition: Attacker can inject SQL commands through form inputs
```

**Search with filters:**
```bash
python search_enhanced_cve.py --query "buffer overflow" --severity HIGH --min-cvss 7.0 --top-k 5
```

**Get fix context:**
```bash
python search_enhanced_cve.py --fix-context CVE-2023-12345
```

Output:
```
=== CVE-2023-12345 ===
Vulnerability Type: SQL Injection
Severity: HIGH (CVSS: 7.5)

Description:
SQL injection vulnerability in web application...

Root Cause:
Insufficient input validation on user-supplied data

Attack Condition:
Attacker can inject SQL commands through form inputs

Fix Strategy:
Use parameterized queries and input sanitization

Code Pattern:
Direct string concatenation in SQL queries

===================================
```

**Get fix context for multiple CVEs:**
```bash
python search_enhanced_cve.py --fix-context "CVE-2023-1,CVE-2023-2,CVE-2023-3"
```

**List available indexes:**
```bash
python search_enhanced_cve.py --list-indexes
```

Output:
```
Available FAISS Indexes:
============================================

• cve-full
  Vectors: 316,437
  Dimension: 384
  VUL-RAG Enrichment: No

• cve-vulrag
  Vectors: 316,437
  Dimension: 384
  VUL-RAG Enrichment: Yes
  Enrichment Coverage: 11 / 316,437 (0.0%)
```

**JSON output for programmatic use:**
```bash
python search_enhanced_cve.py --query "XSS" --json --top-k 3
```

Output:
```json
[
  {
    "cve_id": "CVE-2023-12345",
    "score": 0.8542,
    "severity": "HIGH",
    "cvss_score": 7.5,
    "description": "XSS vulnerability...",
    "cwe": "CWE-79",
    "published_date": "2023-01-15",
    "vulnerability_type": "Cross-Site Scripting",
    "root_cause": "Insufficient input validation",
    "fix_strategy": "Implement input sanitization",
    "code_pattern": "Unescaped user input",
    "attack_condition": "Attacker can inject scripts"
  }
]
```

---

## Workflow Example

Complete workflow from import to search:

```bash
# Step 1: Ensure database schema is ready
python migrate_vulrag_schema.py

# Step 2: Import VUL-RAG data
python import_vulrag_data.py --file vulrag_data.json

# Step 3: Check import statistics
python import_vulrag_data.py --stats

# Step 4: Create enhanced FAISS index
python create_enhanced_index.py

# Step 5: Search with enrichment
python search_enhanced_cve.py --query "SQL injection fixes"

# Step 6: Get fix context for specific CVE
python search_enhanced_cve.py --fix-context CVE-2023-12345
```

---

## Troubleshooting

### Import Issues

**Error: Database file not found**
```
Solution: Ensure cves.db exists or specify correct path with --db-path
```

**Error: vulrag_enrichment table does not exist**
```
Solution: Run migration script first: python migrate_vulrag_schema.py
```

**Error: Invalid JSON format**
```
Solution: Validate JSON file format, ensure proper syntax
```

### Index Creation Issues

**Error: Required packages not installed**
```
Solution: pip install faiss-cpu sentence-transformers
```

**Error: Out of memory**
```
Solution: Use --batch-size with smaller value (e.g., --batch-size 50)
```

### Search Issues

**Error: Index file not found**
```
Solution: Create index first with create_enhanced_index.py
         Or use --list-indexes to see available indexes
```

**Error: No results found**
```
Solution: Try different search terms, remove filters, or use broader queries
```

---

## Performance Tips

1. **Batch Size**: Adjust `--batch-size` based on available memory
   - Default: 100
   - Low memory: 50
   - High memory: 200+

2. **Test Indexes**: Use `--max-records` to create small test indexes
   ```bash
   python create_enhanced_index.py --index-name test --max-records 1000
   ```

3. **JSON Output**: Use `--json` for programmatic processing
   ```bash
   python search_enhanced_cve.py --query "XSS" --json > results.json
   ```

4. **Verbose Mode**: Use `--verbose` for debugging
   ```bash
   python import_vulrag_data.py --file data.json --verbose
   ```

---

## Integration with Other Tools

### Using with LLM Patching System

```bash
# Get fix context for CVEs found in code
python search_enhanced_cve.py --fix-context CVE-2023-12345 > fix_context.txt

# Use in patch generation
python ai_patch_generator.py --cve-context fix_context.txt
```

### Batch Processing

```bash
# Import multiple files
for file in vulrag_data/*.json; do
    python import_vulrag_data.py --file "$file"
done

# Search multiple queries
for query in "SQL injection" "XSS" "buffer overflow"; do
    python search_enhanced_cve.py --query "$query" --json >> all_results.json
done
```

### Automation Scripts

```bash
#!/bin/bash
# update_vulrag.sh - Update VUL-RAG data and rebuild index

echo "Importing new VUL-RAG data..."
python import_vulrag_data.py --file latest_vulrag.json

echo "Rebuilding enhanced index..."
python create_enhanced_index.py --index-name cve-vulrag-latest

echo "Testing search..."
python search_enhanced_cve.py --query "test" --index-name cve-vulrag-latest --top-k 1

echo "Done!"
```

---

## Requirements Mapping

These tools satisfy the following requirements:

- **Requirement 1.1**: JSON parsing and import functionality
- **Requirement 1.2**: Field validation during import
- **Requirement 1.5**: Import statistics reporting
- **Requirement 5.1**: Enhanced index creation
- **Requirement 5.2**: Index file management
- **Requirement 6.1**: Search by fix strategy
- **Requirement 6.2**: Search by root cause
- **Requirement 6.3**: Search by code pattern

---

## Additional Resources

- **VUL-RAG Importer Guide**: `VULRAG_IMPORTER_GUIDE.md`
- **Enhanced Index Guide**: `ENHANCED_INDEX_GUIDE.md`
- **Enhanced Search README**: `ENHANCED_SEARCH_README.md`
- **API Documentation**: See individual Python files for API usage

---

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the individual tool help: `python <tool>.py --help`
3. Check the verbose output: `python <tool>.py --verbose`
4. Review the requirements and design documents in `.kiro/specs/vulrag-knowledge-integration/`
