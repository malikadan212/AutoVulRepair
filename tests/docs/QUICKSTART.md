# Quick Start Guide - CVE to Pinecone

## 🚀 5-Minute Setup

### 1. Create Pinecone Account (2 minutes)
1. Go to https://www.pinecone.io/
2. Sign up for FREE account
3. Get your API key from the console

### 2. Install Dependencies (1 minute)
```bash
pip install -r pinecone_requirements.txt
```

### 3. Test with 100 CVEs (2 minutes)
```bash
python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-demo --max-records 100
```

### 4. Search! (instant)
```bash
python search_cve_vectors.py --api-key YOUR_API_KEY --index-name cve-demo --query "SQL injection"
```

## 📊 What You Get

After running the script, you'll have:
- ✅ Semantic search across CVEs (search by meaning, not keywords)
- ✅ Fast similarity matching (milliseconds)
- ✅ Metadata filtering (by severity, CVSS score, etc.)
- ✅ Scalable vector database

## 🎯 Example Searches

```bash
# Find SQL injection vulnerabilities
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo --query "SQL injection in web applications"

# Find high severity buffer overflows
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo --query "buffer overflow" --severity HIGH

# Find critical vulnerabilities with CVSS > 9.0
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo --query "remote code execution" --min-cvss 9.0
```

## 📈 Scaling Up

### Test (100 CVEs) - 1 minute
```bash
python cve_to_pinecone.py --api-key YOUR_KEY --index-name cve-demo --max-records 100
```

### Medium (10,000 CVEs) - 10 minutes
```bash
python cve_to_pinecone.py --api-key YOUR_KEY --index-name cve-medium --max-records 10000
```

### Free Tier Max (100,000 CVEs) - 1 hour
```bash
python cve_to_pinecone.py --api-key YOUR_KEY --index-name cve-free --max-records 100000
```

### Full Database (316,437 CVEs) - 3-4 hours
**Note:** Requires paid Pinecone plan (~$70/month)
```bash
python cve_to_pinecone.py --api-key YOUR_KEY --index-name cve-full
```

## 🛠️ Management Commands

```bash
# List all your indexes
python manage_pinecone_index.py --api-key YOUR_KEY --action list

# Get statistics
python manage_pinecone_index.py --api-key YOUR_KEY --action stats --index-name cve-demo

# Fetch specific CVE
python manage_pinecone_index.py --api-key YOUR_KEY --action fetch --index-name cve-demo --vector-ids CVE-2023-12345

# Delete index
python manage_pinecone_index.py --api-key YOUR_KEY --action delete --index-name cve-demo
```

## 💡 Use Cases

1. **Security Research**: Find similar vulnerabilities
2. **Threat Intelligence**: Discover related CVEs
3. **Vulnerability Assessment**: Match findings to known CVEs
4. **Patch Prioritization**: Find high-impact vulnerabilities
5. **Security Training**: Explore vulnerability patterns

## 🔍 Search Tips

### Natural Language Queries Work Best
✅ "vulnerabilities that allow remote attackers to execute code"
✅ "SQL injection in PHP web applications"
✅ "privilege escalation in Linux kernel"

### Keywords Also Work
✅ "buffer overflow"
✅ "XSS"
✅ "authentication bypass"

### Combine with Filters
```bash
# High severity memory corruption
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo \
  --query "memory corruption" --severity HIGH

# Critical remote exploits
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo \
  --query "remote code execution" --min-cvss 9.0
```

## 📝 Integration Example

```python
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer

# Initialize once
pc = Pinecone(api_key="YOUR_API_KEY")
index = pc.Index("cve-demo")
model = SentenceTransformer('all-MiniLM-L6-v2')

# Search function
def find_similar_cves(description, top_k=5):
    embedding = model.encode([description])[0].tolist()
    results = index.query(vector=embedding, top_k=top_k, include_metadata=True)
    return [(m['id'], m['metadata']) for m in results['matches']]

# Use it
similar = find_similar_cves("SQL injection in login form")
for cve_id, metadata in similar:
    print(f"{cve_id}: {metadata['description']}")
```

## ⚠️ Important Notes

1. **Free Tier Limit**: 100K vectors max
   - Your database has 316K CVEs
   - Use `--max-records 100000` to stay free
   - Or upgrade to paid tier

2. **First Run**: Downloads ~90MB embedding model
   - Subsequent runs are faster
   - Model is cached locally

3. **Rate Limits**: Free tier has limits
   - Script includes automatic rate limiting
   - Expect ~30-50 CVEs/second

4. **API Key Security**: Never commit your API key
   - Use environment variables
   - Or pass via command line

## 🆘 Troubleshooting

### "Module not found"
```bash
pip install -r pinecone_requirements.txt
```

### "Database not found"
Make sure `cves.db` is in the same directory

### "Index already exists"
That's OK! The script will use the existing index

### "Rate limit exceeded"
The script handles this automatically with retries

## 📚 Next Steps

1. ✅ Complete this quick start
2. 📖 Read [PINECONE_SETUP_GUIDE.md](PINECONE_SETUP_GUIDE.md) for details
3. 🔧 Integrate with your security tools
4. 🚀 Build your CVE search API

## 🎉 You're Done!

You now have a semantic CVE search engine powered by AI embeddings!
