# CVE to Pinecone Vector Database - Setup Guide

## Step 1: Create Pinecone Account (FREE)

1. Go to https://www.pinecone.io/
2. Click "Sign Up" and create a free account
3. Verify your email address
4. Log in to the Pinecone console

## Step 2: Get Your API Key

1. In the Pinecone console, go to "API Keys" section
2. Copy your API key (it looks like: `pcsk_xxxxx...`)
3. Keep this key secure - you'll need it for the script

## Step 3: Install Required Packages

```bash
pip install -r pinecone_requirements.txt
```

This will install:
- `pinecone-client` - Pinecone Python SDK
- `sentence-transformers` - For creating embeddings
- `tqdm` - Progress bars
- `torch` - Required by sentence-transformers

## Step 4: Run the Conversion Script

### Option A: Convert All CVEs (316,437 records)

```bash
python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-vectors
```

**Note:** This will take several hours due to:
- 316K+ CVEs to process
- Embedding generation for each CVE
- Free tier rate limits

### Option B: Test with First 1,000 CVEs (Recommended)

```bash
python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-test --max-records 1000
```

This takes ~5-10 minutes and lets you test the system.

### Option C: Test with First 100 CVEs (Quick Test)

```bash
python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-demo --max-records 100
```

This takes ~1 minute for quick testing.

## Step 5: Test Semantic Search

After conversion, test the search functionality:

```bash
python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-vectors --test-search "SQL injection vulnerability" --skip-conversion
```

Example queries to try:
- "SQL injection vulnerability"
- "buffer overflow in C programs"
- "remote code execution"
- "privilege escalation Linux kernel"
- "cross-site scripting web applications"

## Understanding the Output

The script will:
1. ✓ Initialize Pinecone connection
2. ✓ Load the embedding model (all-MiniLM-L6-v2, 384 dimensions)
3. ✓ Create or connect to the index
4. Process CVEs in batches with progress bar
5. Show final statistics

Example output:
```
Initializing Pinecone...
Loading embedding model (this may take a moment)...
✓ Model loaded: all-MiniLM-L6-v2 (384 dimensions)
✓ Index 'cve-vectors' created successfully

Converting 316,437 CVEs to vector embeddings...
Batch size: 100
This may take a while...

Processing CVEs: 100%|████████████| 316437/316437 [2:45:32<00:00, 31.82it/s]

✓ Conversion complete!
Total vectors in index: 316,437
Index dimension: 384
```

## Pinecone Free Tier Limits

The free tier includes:
- ✓ 1 project
- ✓ 1 serverless index
- ✓ 100K vectors (we have 316K CVEs, so you may need to upgrade or use max-records)
- ✓ 2GB storage
- ✓ Unlimited queries

**Important:** If you have 316K CVEs, you'll exceed the free tier limit. Options:
1. Use `--max-records 100000` to stay within free tier
2. Upgrade to paid tier (~$70/month for 316K vectors)
3. Use multiple indexes with different CVE subsets

## What Gets Stored in Pinecone?

For each CVE, we store:
- **Vector:** 384-dimensional embedding of the CVE description
- **Metadata:**
  - `cve_id`: CVE identifier (e.g., CVE-2023-12345)
  - `description`: First 500 chars of description
  - `published_date`: When CVE was published
  - `severity`: HIGH, MEDIUM, LOW, etc.
  - `cvss_score`: CVSS score (if available)
  - `cwe`: Primary CWE weakness (if available)

## Semantic Search Examples

Once converted, you can search by meaning, not just keywords:

```python
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer

# Initialize
pc = Pinecone(api_key="YOUR_API_KEY")
index = pc.Index("cve-vectors")
model = SentenceTransformer('all-MiniLM-L6-v2')

# Search
query = "vulnerabilities that allow attackers to execute arbitrary code"
query_embedding = model.encode([query])[0].tolist()

results = index.query(
    vector=query_embedding,
    top_k=10,
    include_metadata=True
)

for match in results['matches']:
    print(f"{match['id']}: {match['metadata']['description']}")
```

## Troubleshooting

### Error: "Index already exists"
The script will automatically use the existing index. To start fresh:
```bash
# Delete the index in Pinecone console, then re-run
```

### Error: "Rate limit exceeded"
The script includes rate limiting, but if you hit limits:
- Reduce `--batch-size` (default: 100)
- The script will automatically retry

### Error: "Out of memory"
The embedding model needs ~500MB RAM. If you have limited memory:
- Close other applications
- Process in smaller batches with `--max-records`

### Slow Performance
- First run downloads the embedding model (~90MB)
- Subsequent runs are faster
- Free tier has rate limits, so expect ~30-50 CVEs/second

## Cost Estimation

**Free Tier:**
- 100K vectors: FREE
- Unlimited queries: FREE

**Paid Tier (for 316K CVEs):**
- ~$70/month for serverless
- Includes all 316K vectors
- Unlimited queries

## Next Steps

After conversion, you can:
1. Build a CVE search API
2. Integrate with your security scanning tool
3. Create a CVE recommendation system
4. Build semantic CVE clustering
5. Implement CVE similarity detection

## Support

- Pinecone Docs: https://docs.pinecone.io/
- Sentence Transformers: https://www.sbert.net/
- Issues: Check the script output for detailed error messages
