# Files Created for CVE to Pinecone Conversion

## 🎯 START HERE

### **RUN_ME.bat** ⭐ DOUBLE-CLICK THIS!
The easiest way to get started. Just double-click and follow the prompts.

### **README_CVE_PINECONE.md** 📖
Complete guide with everything you need to know.

## 📜 Main Scripts

### **interactive_setup.py**
Interactive wizard that guides you through the entire setup process.
- Checks prerequisites
- Installs packages
- Prompts for API key
- Converts database
- Tests search

**Usage:**
```bash
python interactive_setup.py
```

### **cve_to_pinecone.py**
Main conversion script. Converts CVE database to Pinecone vectors.

**Usage:**
```bash
# Quick test (100 CVEs)
python cve_to_pinecone.py --api-key YOUR_KEY --index-name cve-demo --max-records 100

# Full conversion (316K CVEs)
python cve_to_pinecone.py --api-key YOUR_KEY --index-name cve-full

# With test search
python cve_to_pinecone.py --api-key YOUR_KEY --index-name cve-demo --max-records 100 --test-search "SQL injection"
```

### **search_cve_vectors.py**
Search your CVE vectors using natural language.

**Usage:**
```bash
# Basic search
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo --query "SQL injection"

# With filters
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo --query "buffer overflow" --severity HIGH

# With CVSS filter
python search_cve_vectors.py --api-key YOUR_KEY --index-name cve-demo --query "remote code execution" --min-cvss 9.0
```

### **manage_pinecone_index.py**
Manage your Pinecone indexes (list, stats, delete, fetch).

**Usage:**
```bash
# List all indexes
python manage_pinecone_index.py --api-key YOUR_KEY --action list

# Get statistics
python manage_pinecone_index.py --api-key YOUR_KEY --action stats --index-name cve-demo

# Fetch specific CVE
python manage_pinecone_index.py --api-key YOUR_KEY --action fetch --index-name cve-demo --vector-ids CVE-2023-12345

# Delete index
python manage_pinecone_index.py --api-key YOUR_KEY --action delete --index-name cve-demo
```

## 📚 Documentation

### **QUICKSTART.md**
5-minute quick start guide with minimal steps.

### **PINECONE_SETUP_GUIDE.md**
Detailed setup instructions with troubleshooting.

### **README_CVE_PINECONE.md**
Complete guide covering:
- What the system does
- How to use it
- Examples
- Use cases
- Troubleshooting
- Advanced usage

## 🧪 Testing & Examples

### **test_setup.py**
Verify your setup before running conversion.

**Usage:**
```bash
# Basic test
python test_setup.py

# Test with Pinecone connection
python test_setup.py YOUR_API_KEY
```

### **example_usage.py**
Practical examples showing how to use the vector database.

**Usage:**
```bash
python example_usage.py YOUR_API_KEY YOUR_INDEX_NAME
```

Shows:
- Basic semantic search
- Filtered search
- Finding similar CVEs
- Natural language queries
- Getting statistics

## 📦 Configuration

### **pinecone_requirements.txt**
Required Python packages:
- pinecone-client>=3.0.0
- sentence-transformers>=2.2.0
- tqdm>=4.65.0
- torch>=2.0.0

**Install:**
```bash
pip install -r pinecone_requirements.txt
```

### **setup_and_convert.bat**
Windows batch script for automated setup (alternative to RUN_ME.bat).

## 🗂️ Helper Scripts

### **inspect_cves_db.py**
Inspect the CVE database structure and contents.

**Usage:**
```bash
python inspect_cves_db.py
```

## 📊 What Each Script Does

| Script | Purpose | When to Use |
|--------|---------|-------------|
| **RUN_ME.bat** | One-click setup | First time setup |
| **interactive_setup.py** | Guided setup | If batch file doesn't work |
| **cve_to_pinecone.py** | Convert database | Manual conversion |
| **search_cve_vectors.py** | Search CVEs | After conversion |
| **manage_pinecone_index.py** | Manage indexes | Maintenance |
| **test_setup.py** | Verify setup | Before conversion |
| **example_usage.py** | Learn usage | After conversion |

## 🚀 Recommended Workflow

### First Time Setup
1. Double-click **RUN_ME.bat**
2. Enter your Pinecone API key when prompted
3. Choose "Quick Test (100 CVEs)"
4. Wait ~1 minute
5. Test search when prompted

### After First Test
1. Run **test_setup.py** to verify everything
2. Run **example_usage.py** to see examples
3. Use **search_cve_vectors.py** for custom searches
4. Scale up with more CVEs if needed

### Production Use
1. Convert desired number of CVEs
2. Integrate **search_cve_vectors.py** into your tools
3. Use **manage_pinecone_index.py** for maintenance
4. Monitor usage in Pinecone console

## 💡 Quick Reference

### Get Your API Key
https://app.pinecone.io/ → API Keys

### Free Tier Limits
- 100,000 vectors max
- 1 index
- Unlimited queries

### Conversion Time
- 100 CVEs: ~1 minute
- 1,000 CVEs: ~5 minutes
- 10,000 CVEs: ~30 minutes
- 100,000 CVEs: ~2 hours
- 316,437 CVEs: ~4 hours (requires paid plan)

### Search Examples
```bash
# Natural language
"vulnerabilities allowing remote code execution"

# Specific types
"SQL injection in PHP applications"

# With context
"buffer overflow in network services"

# Technical terms
"use after free memory corruption"
```

## 🎓 Learning Path

1. **Start**: Run RUN_ME.bat with 100 CVEs
2. **Learn**: Read README_CVE_PINECONE.md
3. **Practice**: Run example_usage.py
4. **Experiment**: Try different search queries
5. **Scale**: Convert more CVEs
6. **Integrate**: Build into your tools

## 📞 Need Help?

1. Check **README_CVE_PINECONE.md** for detailed info
2. Check **PINECONE_SETUP_GUIDE.md** for troubleshooting
3. Run **test_setup.py** to diagnose issues
4. Check Pinecone docs: https://docs.pinecone.io/

## ✅ Checklist

Before starting:
- [ ] Python 3.8+ installed
- [ ] cves.db in current directory
- [ ] Pinecone account created
- [ ] API key copied

After setup:
- [ ] Packages installed
- [ ] Database converted
- [ ] Search tested
- [ ] Examples reviewed

## 🎉 You're All Set!

Everything is ready. Just double-click **RUN_ME.bat** to begin!
