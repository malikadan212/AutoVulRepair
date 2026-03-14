# VUL-RAG Data Importer Guide

## Overview

The VUL-RAG Data Importer allows you to import enriched vulnerability knowledge base data into your CVE database. This enrichment includes fix strategies, root causes, code patterns, and attack conditions that enhance the standard CVE information.

## Prerequisites

1. Ensure you have the CVE database (`cves.db`) set up
2. Run the migration script to add the `vulrag_enrichment` table:
   ```bash
   python migrate_vulrag_schema.py
   ```

## Quick Start

### Import VUL-RAG Data

```bash
python vulrag_importer.py --file your_vulrag_data.json
```

### View Import Statistics

```bash
python vulrag_importer.py --stats
```

## JSON Data Format

Your VUL-RAG JSON file should contain an array of entries with the following structure:

```json
[
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
]
```

### Required Fields

- `cve_id`: CVE identifier (must start with "CVE-")
- `description`: Description of the vulnerability

### Optional Fields

- `cwe_id`: CWE identifier
- `vulnerability_type`: Type of vulnerability
- `root_cause`: Root cause analysis
- `attack_condition`: Conditions for exploitation
- `fix_strategy`: Recommended fix strategy
- `code_pattern`: Common code pattern associated with the vulnerability

## Features

### 1. JSON Parsing

The importer automatically parses JSON files and extracts all VUL-RAG fields.

```python
from vulrag_importer import VulRagImporter

importer = VulRagImporter(db_path='cves.db')
result = importer.import_from_json('vulrag_data.json')
print(f"Imported: {result.success_count}, Errors: {result.error_count}")
```

### 2. Field Validation

The importer validates that each entry contains required fields:
- CVE ID must be present and non-empty
- CVE ID must start with "CVE-"
- Description must be present and non-empty

Invalid entries are skipped and reported in the error log.

### 3. Duplicate Handling

When importing data for a CVE that already has enrichment:
- The existing enrichment is **updated** (not duplicated)
- All fields are replaced with new values
- The `updated_at` timestamp is automatically updated

This allows you to:
- Re-import the same file without creating duplicates
- Update enrichment data as it evolves
- Maintain a single source of truth

### 4. Import Statistics

The importer tracks detailed statistics:
- Total entries processed
- Successfully imported entries
- Errors encountered
- Error details (entry index, CVE ID, error message)

### 5. Error Handling

The importer handles various error conditions:
- **Missing file**: Clear error message with file path
- **Invalid JSON**: Detailed JSON parsing error
- **Missing required fields**: Validation error with field name
- **Invalid CVE format**: Format validation error
- **Database errors**: Integrity constraint violations

## Usage Examples

### Basic Import

```bash
python vulrag_importer.py --file sample_vulrag_data.json
```

Output:
```
Importing VUL-RAG data from: sample_vulrag_data.json
Database: cves.db

============================================================
Import Complete
============================================================
Total entries: 3
Successfully imported: 3
Errors: 0
```

### Import with Custom Database

```bash
python vulrag_importer.py --file vulrag_data.json --db-path /path/to/custom_cves.db
```

### View Statistics

```bash
python vulrag_importer.py --stats
```

Output:
```
============================================================
VUL-RAG Import Statistics
============================================================
Total enrichments: 3

cwe_id: 3 (100.0%)
vulnerability_type: 3 (100.0%)
root_cause: 3 (100.0%)
attack_condition: 3 (100.0%)
fix_strategy: 3 (100.0%)
code_pattern: 3 (100.0%)
```

### Programmatic Usage

```python
from vulrag_importer import VulRagImporter

# Initialize importer
importer = VulRagImporter(db_path='cves.db')

# Import data
result = importer.import_from_json('vulrag_data.json')

# Check results
print(f"Success: {result.success_count}")
print(f"Errors: {result.error_count}")

# Handle errors
if result.errors:
    for error in result.errors:
        print(f"Error in {error['cve_id']}: {error['error']}")

# Get statistics
stats = importer.get_import_stats()
print(f"Total enrichments: {stats['total_enrichments']}")
```

## Testing

### Run Comprehensive Tests

```bash
python test_vulrag_importer_comprehensive.py
```

This tests:
- JSON parsing functionality
- Required field validation
- Duplicate handling
- Import statistics tracking
- Error handling

### Run Workflow Demo

```bash
python test_vulrag_workflow.py
```

This demonstrates the complete import workflow with sample data.

## Troubleshooting

### Error: Database file not found

Make sure the CVE database exists:
```bash
ls -l cves.db
```

### Error: vulrag_enrichment table does not exist

Run the migration script:
```bash
python migrate_vulrag_schema.py
```

### Error: Invalid JSON format

Validate your JSON file:
```bash
python -m json.tool your_file.json
```

### Error: Missing required field

Check that all entries have `cve_id` and `description` fields:
```json
{
  "cve_id": "CVE-2023-12345",  // Required
  "description": "..."          // Required
}
```

## Sample Data

A sample VUL-RAG data file is provided: `sample_vulrag_data.json`

You can use this to test the importer:
```bash
python vulrag_importer.py --file sample_vulrag_data.json
```

## Next Steps

After importing VUL-RAG data:

1. **Create Enhanced Embeddings**: Generate embeddings that include VUL-RAG fields
2. **Build Enhanced Index**: Create a FAISS index with enriched embeddings
3. **Use Enhanced Search**: Search CVEs with fix strategy and root cause information

See the main VUL-RAG integration documentation for details on these steps.
