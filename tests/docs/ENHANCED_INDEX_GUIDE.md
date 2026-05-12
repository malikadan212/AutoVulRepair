# Enhanced FAISS Index Creation Guide

## Overview

The enhanced FAISS index creation tool (`create_enhanced_index.py`) builds vector indexes that include VUL-RAG enrichment data. These indexes enable semantic search across CVE descriptions, root causes, fix strategies, code patterns, and attack conditions.

## Features

- **VUL-RAG Integration**: Embeddings include root causes, fix strategies, code patterns, and attack conditions
- **Graceful Degradation**: Handles CVEs with and without enrichment data
- **Progress Reporting**: Real-time progress bars during index creation
- **Batch Processing**: Efficient batch processing for large datasets
- **Metadata Storage**: Comprehensive metadata including all VUL-RAG fields
- **Index Versioning**: Distinct naming (cve-vulrag) to differentiate from standard indexes

## Prerequisites

1. **Database Setup**: Ensure the CVE database exists with the vulrag_enrichment table
   ```bash
   python migrate_vulrag_schema.py
   ```

2. **VUL-RAG Data**: Import VUL-RAG enrichment data
   ```bash
   python vulrag_importer.py --file vulrag_data.json
   ```

3. **Dependencies**: Install required packages
   ```bash
   pip install faiss-cpu sentence-transformers tqdm
   ```

## Usage

### Basic Usage

Create an enhanced index with all CVEs:

```bash
python create_enhanced_index.py
```

This creates:
- `faiss_indexes/cve-vulrag.index` - FAISS vector index
- `faiss_indexes/cve-vulrag.metadata` - Metadata pickle file
- `faiss_indexes/cve-vulrag.info` - Index information JSON

### Custom Index Name

```bash
python create_enhanced_index.py --index-name cve-vulrag-v2
```

### Test with Limited Records

For testing, create an index with a subset of CVEs:

```bash
python create_enhanced_index.py --index-name cve-test --max-records 1000
```

### Custom Batch Size

Adjust batch size for memory optimization:

```bash
python create_enhanced_index.py --batch-size 50
```

### Test Search

Test search functionality after index creation:

```bash
python create_enhanced_index.py --test-search "SQL injection fix strategies"
```

Or test on existing index without rebuilding:

```bash
python create_enhanced_index.py --index-name cve-vulrag --test-search "buffer overflow" --skip-build
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--index-name` | Name for the enhanced index | `cve-vulrag` |
| `--db-path` | Path to CVE database | `cves.db` |
| `--batch-size` | Batch size for processing | `100` |
| `--max-records` | Maximum records to process (for testing) | None (all) |
| `--test-search` | Test search query after creation | None |
| `--skip-build` | Skip building, only run test search | False |

## Index Structure

### Index Files

1. **`.index` file**: FAISS vector index with normalized embeddings
2. **`.metadata` file**: Pickle file containing metadata for each CVE
3. **`.info` file**: JSON file with index statistics and configuration

### Metadata Format

Each CVE in the metadata includes:

```python
{
    'cve_id': 'CVE-2023-12345',
    'description': 'SQL injection vulnerability...',
    'published_date': '2023-01-15',
    'severity': 'HIGH',
    'cvss_score': 7.5,
    'cwe': 'CWE-89',
    # VUL-RAG enrichment fields
    'vulnerability_type': 'SQL Injection',
    'root_cause': 'Insufficient input validation...',
    'fix_strategy': 'Use parameterized queries...',
    'code_pattern': 'Direct string concatenation...',
    'attack_condition': 'Attacker can inject SQL...',
    'vulrag_cwe_id': 'CWE-89'
}
```

For CVEs without enrichment, VUL-RAG fields are set to `None`.

### Info File Format

```json
{
  "name": "cve-vulrag",
  "total_vectors": 316437,
  "dimension": 384,
  "model": "all-MiniLM-L6-v2",
  "enhanced": true,
  "vulrag_enrichment": true,
  "enrichment_stats": {
    "total_cves": 316437,
    "enriched_cves": 11,
    "enrichment_percentage": 0.003
  }
}
```

## Embedding Generation

### Embedding Text Format

For CVEs with VUL-RAG enrichment:

```
CVE: CVE-2023-12345
Description: SQL injection vulnerability in web application
Root Cause: Insufficient input validation on user-supplied data
Fix Strategy: Use parameterized queries and input sanitization
CWE: CWE-89
Vulnerability Type: SQL Injection
Attack Condition: Attacker can inject SQL commands through form inputs
Code Pattern: Direct string concatenation in SQL queries
```

For CVEs without enrichment:

```
CVE: CVE-1999-0001
Description: Buffer overflow in FTP server
```

### Normalization

All embeddings are L2-normalized for cosine similarity search using FAISS's `IndexFlatIP`.

## Performance

### Expected Performance

- **Index Creation**: ~1-2 hours for 316k CVEs (depends on hardware)
- **Batch Processing**: ~50-100 CVEs per second
- **Memory Usage**: ~2-3 GB during creation
- **Index Size**: ~500 MB for 316k CVEs

### Optimization Tips

1. **Batch Size**: Increase for faster processing (if memory allows)
   ```bash
   python create_enhanced_index.py --batch-size 200
   ```

2. **Test First**: Create a small test index to verify setup
   ```bash
   python create_enhanced_index.py --index-name test --max-records 100
   ```

3. **Monitor Progress**: The tool shows real-time progress with tqdm

## Troubleshooting

### Database Not Found

```
ERROR: Database file 'cves.db' not found
```

**Solution**: Ensure the CVE database exists in the current directory or specify path:
```bash
python create_enhanced_index.py --db-path /path/to/cves.db
```

### Missing vulrag_enrichment Table

```
ERROR: The 'vulrag_enrichment' table does not exist
```

**Solution**: Run the migration script:
```bash
python migrate_vulrag_schema.py
```

### Out of Memory

```
ERROR: MemoryError during embedding generation
```

**Solution**: Reduce batch size:
```bash
python create_enhanced_index.py --batch-size 50
```

### Model Download Issues

```
WARNING: You are sending unauthenticated requests to the HF Hub
```

**Solution**: Set HuggingFace token (optional):
```bash
export HF_TOKEN=your_token_here
python create_enhanced_index.py
```

## Comparison with Standard Index

| Feature | Standard Index (cve-full) | Enhanced Index (cve-vulrag) |
|---------|---------------------------|----------------------------|
| CVE Description | ✓ | ✓ |
| Severity/CVSS | ✓ | ✓ |
| CWE Information | ✓ | ✓ |
| Root Cause | ✗ | ✓ |
| Fix Strategy | ✗ | ✓ |
| Code Pattern | ✗ | ✓ |
| Attack Condition | ✗ | ✓ |
| Vulnerability Type | ✗ | ✓ |

## Next Steps

After creating the enhanced index:

1. **Test Search**: Verify the index works correctly
   ```bash
   python create_enhanced_index.py --test-search "your query" --skip-build
   ```

2. **Use in Application**: Integrate with enhanced search functionality
   ```python
   from search_enhanced_cve import EnhancedFAISSCVESearch
   
   searcher = EnhancedFAISSCVESearch('cve-vulrag')
   results = searcher.search_with_enrichment('SQL injection', top_k=5)
   ```

3. **Update Regularly**: Rebuild index when new VUL-RAG data is imported
   ```bash
   python vulrag_importer.py --file new_data.json
   python create_enhanced_index.py
   ```

## Examples

### Example 1: Create Full Production Index

```bash
# Import VUL-RAG data
python vulrag_importer.py --file vulrag_knowledge_base.json

# Create enhanced index
python create_enhanced_index.py --index-name cve-vulrag

# Test search
python create_enhanced_index.py --index-name cve-vulrag \
    --test-search "input validation vulnerabilities" \
    --skip-build
```

### Example 2: Create Test Index

```bash
# Create small test index
python create_enhanced_index.py \
    --index-name cve-test \
    --max-records 1000 \
    --batch-size 50

# Test search
python create_enhanced_index.py \
    --index-name cve-test \
    --test-search "XSS vulnerability" \
    --skip-build
```

### Example 3: Update Existing Index

```bash
# Import new VUL-RAG data
python vulrag_importer.py --file updated_vulrag_data.json

# Rebuild index with new data
python create_enhanced_index.py --index-name cve-vulrag-v2

# Verify enrichment coverage
python create_enhanced_index.py --index-name cve-vulrag-v2 --skip-build
```

## See Also

- [VUL-RAG Importer Guide](VULRAG_IMPORTER_GUIDE.md)
- [Enhanced Embedding Generator](enhanced_embedding_generator.py)
- [Database Migration Guide](VULRAG_MIGRATION_README.md)
