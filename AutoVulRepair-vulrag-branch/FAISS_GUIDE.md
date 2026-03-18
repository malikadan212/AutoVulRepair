## 🚀 FAISS Setup Guide - FREE Local Vector Database

## What is FAISS?

**FAISS** (Facebook AI Similarity Search) is a library for efficient similarity search developed by Facebook AI Research.

### Key Features:
- ✅ **Completely FREE** - No limits, no costs, open source
- ✅ **Lightning fast** - Optimized for CPU/GPU
- ✅ **Scalable** - Handles billions of vectors
- ✅ **Production-ready** - Used by Facebook, Google, Microsoft
- ✅ **Local** - Your data never leaves your machine
- ✅ **No account needed** - Just install and use

## Quick Start (3 Steps)

### Step 1: Run Setup
```bash
# Just double-click this file:
RUN_ME_FAISS.bat

# Or run manually:
pip install -r faiss_requirements.txt
```

### Step 2: Convert Database
```bash
# All CVEs (FREE!)
python cve_to_faiss.py --index-name cve-full

# Or test with 100 CVEs first
python cve_to_faiss.py --index-name cve-demo --max-records 100
```

### Step 3: Search
```bash
python search_cve_faiss.py --index-name cve-full --query "SQL injection"
```

## Installation

### Option 1: Automated (Easiest)
```bash
RUN_ME_FAISS.bat
```

### Option 2: Manual
```bash
pip install faiss-cpu sentence-transformers tqdm torch numpy
```

### Option 3: With GPU Support (Faster)
```bash
pip install faiss-gpu sentence-transformers tqdm torch numpy
```

## Usage Examples

### Basic Search
```bash
python search_cve_faiss.py --index-name cve-full --query "SQL injection vulnerabilities"
```

### Filtered Search
```bash
# High severity only
python search_cve_faiss.py --index-name cve-full --query "buffer overflow" --severity HIGH

# CVSS score >= 9.0
python search_cve_faiss.py --index-name cve-full --query "remote code execution" --min-cvss 9.0
```

### Find Similar CVEs
```bash
python search_cve_faiss.py --index-name cve-full --similar-to CVE-2023-12345
```

### More Results
```bash
python search_cve_faiss.py --index-name cve-full --query "XSS" --top-k 20
```

## Conversion Options

### Quick Test (100 CVEs) - 1 minute
```bash
python cve_to_faiss.py --index-name cve-demo --max-records 100
```

### Small (1,000 CVEs) - 5 minutes
```bash
python cve_to_faiss.py --index-name cve-small --max-records 1000
```

### Medium (10,000 CVEs) - 30 minutes
```bash
python cve_to_faiss.py --index-name cve-medium --max-records 10000
```

### Large (100,000 CVEs) - 2 hours
```bash
python cve_to_faiss.py --index-name cve-large --max-records 100000
```

### FULL (316,437 CVEs) - 4 hours [FREE!]
```bash
python cve_to_faiss.py --index-name cve-full
```

## File Structure

After conversion, you'll have:

```
faiss_indexes/
├── cve-full.index      # FAISS index file (~485 MB)
├── cve-full.metadata   # CVE metadata (~50 MB)
└── cve-full.info       # Index information
```

## Python Integration

### Basic Usage
```python
from search_cve_faiss import FAISSCVESearch

# Initialize
searcher = FAISSCVESearch('cve-full')

# Search
results = searcher.search("SQL injection", top_k=10)

# Display
for result in results:
    print(f"{result['cve_id']}: {result['description'][:100]}...")
```

### Advanced Usage
```python
# With filters
results = searcher.search(
    query="buffer overflow",
    top_k=10,
    severity_filter="HIGH",
    min_cvss=7.0
)

# Find similar CVEs
similar = searcher.find_similar_to_cve("CVE-2023-12345", top_k=5)

# Get statistics
stats = searcher.get_stats()
print(f"Total CVEs: {stats['total_vectors']:,}")
```

### Build Your Own API
```python
from flask import Flask, request, jsonify
from search_cve_faiss import FAISSCVESearch

app = Flask(__name__)
searcher = FAISSCVESearch('cve-full')

@app.route('/search')
def search():
    query = request.args.get('q')
    results = searcher.search(query, top_k=10)
    return jsonify(results)

if __name__ == '__main__':
    app.run(port=5000)
```

## Performance

### Speed
```
Search time: 1-10ms (local)
vs Pinecone: 50-100ms (network)
Winner: FAISS is 10x faster!
```

### Memory Usage
```
Index: ~485 MB
Model: ~500 MB
Total: ~1 GB RAM
```

### Disk Usage
```
Index: ~485 MB
Metadata: ~50 MB
Total: ~535 MB
```

### Conversion Speed
```
~30-50 CVEs/second
316,437 CVEs in ~2-4 hours
```

## Advanced Features

### Multiple Indexes
```bash
# Create different indexes for different purposes
python cve_to_faiss.py --index-name cve-high-severity --max-records 10000
python cve_to_faiss.py --index-name cve-recent --max-records 5000
python cve_to_faiss.py --index-name cve-full
```

### Batch Processing
```python
from search_cve_faiss import FAISSCVESearch

searcher = FAISSCVESearch('cve-full')

queries = [
    "SQL injection",
    "buffer overflow",
    "XSS vulnerability"
]

for query in queries:
    results = searcher.search(query, top_k=5)
    print(f"\nResults for: {query}")
    for r in results:
        print(f"  - {r['cve_id']}")
```

### Export Results
```python
import json
from search_cve_faiss import FAISSCVESearch

searcher = FAISSCVESearch('cve-full')
results = searcher.search("SQL injection", top_k=100)

# Save to JSON
with open('search_results.json', 'w') as f:
    json.dump(results, f, indent=2)

# Save to CSV
import csv
with open('search_results.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)
```

## Optimization Tips

### 1. Use GPU (if available)
```bash
pip install faiss-gpu
# Same code, 10x faster!
```

### 2. Increase Batch Size
```bash
python cve_to_faiss.py --index-name cve-full --batch-size 500
# Faster conversion
```

### 3. Use SSD Storage
```
Store index on SSD for faster loading
```

### 4. Preload Index
```python
# Load once, use many times
searcher = FAISSCVESearch('cve-full')

# Fast searches
for query in queries:
    results = searcher.search(query)
```

## Backup & Recovery

### Backup
```bash
# Copy these files
faiss_indexes/cve-full.index
faiss_indexes/cve-full.metadata
faiss_indexes/cve-full.info

# To backup location
cp faiss_indexes/* /backup/location/
```

### Recovery
```bash
# Copy back
cp /backup/location/* faiss_indexes/

# Test
python search_cve_faiss.py --index-name cve-full --query "test"
```

## Troubleshooting

### "Index not found"
```bash
# Make sure you've converted first
python cve_to_faiss.py --index-name cve-full
```

### "Out of memory"
```bash
# Reduce batch size
python cve_to_faiss.py --index-name cve-full --batch-size 50

# Or convert in chunks
python cve_to_faiss.py --index-name cve-part1 --max-records 100000
python cve_to_faiss.py --index-name cve-part2 --max-records 100000
```

### "Slow conversion"
```bash
# Use GPU
pip install faiss-gpu

# Or increase batch size
python cve_to_faiss.py --index-name cve-full --batch-size 200
```

### "Module not found"
```bash
pip install -r faiss_requirements.txt
```

## Comparison with Other Solutions

### FAISS vs Pinecone
- FAISS: FREE, local, faster
- Pinecone: Paid, cloud, managed

### FAISS vs Elasticsearch
- FAISS: Semantic search, vectors
- Elasticsearch: Keyword search, text

### FAISS vs ChromaDB
- FAISS: Mature, fast, proven
- ChromaDB: Newer, simpler API

### FAISS vs Milvus
- FAISS: Simple, local
- Milvus: Distributed, complex

## Use Cases

### 1. Security Research
```python
# Find similar vulnerabilities
searcher = FAISSCVESearch('cve-full')
similar = searcher.find_similar_to_cve("CVE-2023-12345")
```

### 2. Threat Intelligence
```python
# Search by attack description
results = searcher.search("remote code execution via deserialization")
```

### 3. Vulnerability Assessment
```python
# Match findings to CVEs
finding = "SQL injection in login form"
matches = searcher.search(finding, top_k=5)
```

### 4. CVE Recommendation
```python
# "Users who looked at this CVE also looked at..."
similar = searcher.find_similar_to_cve(current_cve, top_k=10)
```

## Production Deployment

### Web Service
```python
# app.py
from flask import Flask, request, jsonify
from search_cve_faiss import FAISSCVESearch

app = Flask(__name__)
searcher = FAISSCVESearch('cve-full')

@app.route('/api/search')
def api_search():
    query = request.args.get('q')
    top_k = int(request.args.get('top_k', 10))
    results = searcher.search(query, top_k=top_k)
    return jsonify(results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### Docker Deployment
```dockerfile
FROM python:3.9

WORKDIR /app

COPY faiss_requirements.txt .
RUN pip install -r faiss_requirements.txt

COPY search_cve_faiss.py .
COPY faiss_indexes/ faiss_indexes/

CMD ["python", "app.py"]
```

### Load Balancing
```python
# Use multiple processes
from multiprocessing import Pool

def search_worker(query):
    searcher = FAISSCVESearch('cve-full')
    return searcher.search(query)

with Pool(4) as p:
    results = p.map(search_worker, queries)
```

## Best Practices

### 1. Version Control
```bash
# Track index versions
faiss_indexes/
├── cve-full-v1.index
├── cve-full-v2.index
└── cve-full-latest.index -> cve-full-v2.index
```

### 2. Monitoring
```python
import time

start = time.time()
results = searcher.search(query)
elapsed = time.time() - start

print(f"Search took {elapsed*1000:.2f}ms")
```

### 3. Caching
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def cached_search(query):
    return searcher.search(query)
```

### 4. Error Handling
```python
try:
    results = searcher.search(query)
except FileNotFoundError:
    print("Index not found. Run conversion first.")
except Exception as e:
    print(f"Search error: {e}")
```

## Next Steps

1. ✅ Run `RUN_ME_FAISS.bat`
2. ✅ Convert your CVEs
3. ✅ Try some searches
4. ✅ Integrate into your tools
5. ✅ Build your CVE search API

## Resources

- **FAISS GitHub**: https://github.com/facebookresearch/faiss
- **FAISS Wiki**: https://github.com/facebookresearch/faiss/wiki
- **Sentence Transformers**: https://www.sbert.net/
- **Model**: https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2

## Support

For issues or questions:
1. Check this guide
2. Check FAISS documentation
3. Check error messages
4. Try with smaller dataset first

---

**Ready to start?**

Just run: **`RUN_ME_FAISS.bat`**

It's FREE, FAST, and handles ALL 316,437 CVEs!
