# Index Manager Guide

## Overview

The Index Manager provides a centralized way to manage and query information about FAISS CVE indexes. It helps you:

- List all available indexes
- Get detailed information about specific indexes
- Verify which indexes contain VUL-RAG enrichment
- View enrichment coverage statistics
- Switch between different indexes

## Installation

No additional installation required. The Index Manager uses standard Python libraries and the existing FAISS infrastructure.

## Quick Start

### Command Line Usage

```bash
# List all available indexes
python index_manager.py --list

# Get detailed information about a specific index
python index_manager.py --info cve-vulrag

# Verify if an index has VUL-RAG enrichment
python index_manager.py --verify cve-vulrag

# Print formatted summary of all indexes
python index_manager.py --summary
```

### Programmatic Usage

```python
from index_manager import IndexManager

# Initialize the manager
manager = IndexManager(index_dir='faiss_indexes')

# List all indexes
indexes = manager.list_indexes()
for idx in indexes:
    print(f"{idx['name']}: VUL-RAG={idx['has_vulrag_enrichment']}")

# Get detailed info about a specific index
info = manager.get_index_info('cve-vulrag')
print(f"Total vectors: {info['total_vectors']:,}")
print(f"Has enrichment: {info['has_vulrag_enrichment']}")

# Verify VUL-RAG enrichment
has_enrichment = manager.verify_index_schema('cve-vulrag')
if has_enrichment:
    print("✓ Index contains VUL-RAG enrichment")
    
    # Get coverage statistics
    coverage = manager.get_enrichment_coverage('cve-vulrag')
    if coverage:
        print(f"Coverage: {coverage['enrichment_percentage']:.2f}%")
```

## API Reference

### IndexManager Class

#### `__init__(index_dir='faiss_indexes')`

Initialize the index manager.

**Parameters:**
- `index_dir` (str): Directory containing FAISS indexes (default: 'faiss_indexes')

**Raises:**
- `FileNotFoundError`: If the index directory doesn't exist

#### `list_indexes() -> List[Dict[str, Any]]`

List all available FAISS indexes with metadata.

**Returns:**
- List of dictionaries, each containing:
  - `name`: Index name
  - `total_vectors`: Number of vectors in the index
  - `dimension`: Vector dimension
  - `model`: Embedding model used
  - `has_vulrag_enrichment`: Boolean indicating VUL-RAG data presence
  - `enrichment_stats`: Statistics about enrichment coverage (if available)
  - `index_file`: Path to .index file
  - `metadata_file`: Path to .metadata file
  - `info_file`: Path to .info file

**Example:**
```python
indexes = manager.list_indexes()
for idx in indexes:
    enrichment = "✓" if idx['has_vulrag_enrichment'] else "✗"
    print(f"{enrichment} {idx['name']} ({idx['total_vectors']:,} vectors)")
```

#### `get_index_info(index_name: str) -> Dict[str, Any]`

Get detailed information about a specific index.

**Parameters:**
- `index_name` (str): Name of the index (without file extension)

**Returns:**
- Dictionary containing index information (same structure as list_indexes items)

**Raises:**
- `FileNotFoundError`: If the index doesn't exist

**Example:**
```python
info = manager.get_index_info('cve-vulrag')
print(f"Index: {info['name']}")
print(f"Vectors: {info['total_vectors']:,}")
print(f"Model: {info['model']}")
print(f"VUL-RAG: {info['has_vulrag_enrichment']}")
```

#### `verify_index_schema(index_name: str) -> bool`

Verify if an index contains VUL-RAG enrichment fields.

**Parameters:**
- `index_name` (str): Name of the index to verify

**Returns:**
- `True` if the index contains VUL-RAG enrichment, `False` otherwise

**Example:**
```python
if manager.verify_index_schema('cve-vulrag'):
    print("Index has VUL-RAG enrichment")
else:
    print("Standard index (no enrichment)")
```

#### `get_enrichment_coverage(index_name: str) -> Optional[Dict[str, Any]]`

Get enrichment coverage statistics for an index.

**Parameters:**
- `index_name` (str): Name of the index

**Returns:**
- Dictionary with statistics or None if not available:
  - `total_cves`: Total number of CVEs in the index
  - `enriched_cves`: Number of CVEs with VUL-RAG enrichment
  - `enrichment_percentage`: Percentage of CVEs with enrichment

**Example:**
```python
coverage = manager.get_enrichment_coverage('cve-vulrag')
if coverage:
    print(f"Total CVEs: {coverage['total_cves']:,}")
    print(f"Enriched: {coverage['enriched_cves']:,}")
    print(f"Coverage: {coverage['enrichment_percentage']:.2f}%")
```

#### `print_index_summary()`

Print a formatted summary of all available indexes.

**Example:**
```python
manager.print_index_summary()
```

Output:
```
================================================================================
FAISS Index Summary
================================================================================
Index Directory: faiss_indexes
Total Indexes: 2

Index: cve-full
  Location: faiss_indexes/cve-full.index
  Total Vectors: 316,437
  Dimension: 384
  Model: all-MiniLM-L6-v2
  VUL-RAG Enrichment: ✗ NO (standard index)

Index: cve-vulrag
  Location: faiss_indexes/cve-vulrag.index
  Total Vectors: 316,437
  Dimension: 384
  Model: all-MiniLM-L6-v2
  VUL-RAG Enrichment: ✓ YES
    - Total CVEs: 316,437
    - Enriched CVEs: 11,234
    - Coverage: 3.55%
```

## Understanding Index Types

### Standard Indexes

Standard indexes (e.g., `cve-full`) contain:
- CVE ID
- Description
- Severity
- CVSS score
- CWE information
- Published date

These indexes are suitable for basic CVE searches based on descriptions and metadata.

### Enhanced Indexes (VUL-RAG)

Enhanced indexes (e.g., `cve-vulrag`) contain all standard fields plus:
- Root cause analysis
- Fix strategies
- Code patterns
- Attack conditions
- Vulnerability types

These indexes enable searches based on fix strategies, root causes, and other enriched information.

## Use Cases

### 1. Choosing the Right Index

```python
manager = IndexManager()
indexes = manager.list_indexes()

# Find the best index for your needs
for idx in indexes:
    if idx['has_vulrag_enrichment']:
        print(f"Use {idx['name']} for enriched searches")
    else:
        print(f"Use {idx['name']} for standard searches")
```

### 2. Verifying Index Quality

```python
manager = IndexManager()

# Check if an index has sufficient enrichment
info = manager.get_index_info('cve-vulrag')
if info['has_vulrag_enrichment']:
    coverage = info['enrichment_stats']
    if coverage['enrichment_percentage'] > 10:
        print("Good enrichment coverage")
    else:
        print("Limited enrichment coverage")
```

### 3. Monitoring Index Status

```python
manager = IndexManager()

# Monitor all indexes
for idx in manager.list_indexes():
    print(f"\nIndex: {idx['name']}")
    print(f"  Vectors: {idx['total_vectors']:,}")
    print(f"  Enriched: {idx['has_vulrag_enrichment']}")
    
    if idx['has_vulrag_enrichment'] and idx['enrichment_stats']:
        stats = idx['enrichment_stats']
        print(f"  Coverage: {stats['enrichment_percentage']:.2f}%")
```

### 4. Switching Between Indexes

```python
from enhanced_cve_search import EnhancedFAISSCVESearch
from index_manager import IndexManager

manager = IndexManager()

# List available indexes
indexes = manager.list_indexes()
print("Available indexes:")
for idx in indexes:
    marker = "✓" if idx['has_vulrag_enrichment'] else "✗"
    print(f"  {marker} {idx['name']}")

# Choose an enriched index
enriched_indexes = [idx for idx in indexes if idx['has_vulrag_enrichment']]
if enriched_indexes:
    index_name = enriched_indexes[0]['name']
    print(f"\nUsing enriched index: {index_name}")
    
    # Create searcher with the enriched index
    searcher = EnhancedFAISSCVESearch(index_name)
    results = searcher.search_with_enrichment("SQL injection fix", top_k=5)
```

## Integration with Other Components

### With Enhanced Search

```python
from enhanced_cve_search import EnhancedFAISSCVESearch
from index_manager import IndexManager

# Find the best enriched index
manager = IndexManager()
indexes = manager.list_indexes()

enriched = [idx for idx in indexes if idx['has_vulrag_enrichment']]
if enriched:
    # Use the enriched index with the most coverage
    best_index = max(enriched, 
                    key=lambda x: x.get('enrichment_stats', {}).get('enrichment_percentage', 0))
    
    print(f"Using index: {best_index['name']}")
    searcher = EnhancedFAISSCVESearch(best_index['name'])
```

### With Index Creation

```python
from create_enhanced_index import EnhancedIndexCreator
from index_manager import IndexManager

# Create a new enhanced index
creator = EnhancedIndexCreator(index_name='cve-vulrag-v2')
creator.build_index()

# Verify it was created successfully
manager = IndexManager()
info = manager.get_index_info('cve-vulrag-v2')
print(f"Created index with {info['total_vectors']:,} vectors")
print(f"VUL-RAG enrichment: {info['has_vulrag_enrichment']}")
```

## Troubleshooting

### Index Not Found

```python
try:
    info = manager.get_index_info('nonexistent-index')
except FileNotFoundError as e:
    print(f"Error: {e}")
    # List available indexes
    indexes = manager.list_indexes()
    print("Available indexes:", [idx['name'] for idx in indexes])
```

### Missing Enrichment Data

If an index shows `has_vulrag_enrichment: False` but you expect it to be enriched:

1. Check the .info file for `vulrag_enrichment` or `enhanced` flags
2. Verify the .metadata file contains VUL-RAG fields
3. Ensure the index was created with `create_enhanced_index.py`

### Corrupted Index Files

If an index appears in the list but has errors:

```python
indexes = manager.list_indexes()
for idx in indexes:
    if 'error' in idx:
        print(f"Index {idx['name']} has errors: {idx['error']}")
        # Recreate the index
```

## Best Practices

1. **Always verify enrichment** before using an index for enriched searches
2. **Check coverage statistics** to ensure sufficient enrichment
3. **Use standard indexes** for basic searches to save resources
4. **Monitor index quality** regularly with `print_index_summary()`
5. **Document index purposes** in your application

## Requirements Validation

This implementation satisfies the following requirements:

- **Requirement 5.3**: ✓ Verifies metadata contains VUL-RAG fields before allowing searches
- **Requirement 5.4**: ✓ Indicates which indexes contain VUL-RAG enrichment data
- **Requirement 5.5**: ✓ Supports loading appropriate metadata schema without restart

## See Also

- [Enhanced Search Guide](ENHANCED_SEARCH_README.md)
- [Enhanced Index Creation Guide](ENHANCED_INDEX_GUIDE.md)
- [VUL-RAG Importer Guide](VULRAG_IMPORTER_GUIDE.md)
