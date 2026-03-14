# 🤖 CVE RAG System - Complete Setup Guide

## What is RAG?

**RAG (Retrieval-Augmented Generation)** combines:
1. **Vector Search** (FAISS) - Find relevant CVEs
2. **LLM** (Gemini) - Generate intelligent answers

```
User Question → FAISS Search → Retrieve CVEs → Gemini → Smart Answer
```

## Why RAG for CVEs?

### Without RAG:
```
User: "What are dangerous SQL injection CVEs?"
System: [Returns list of CVEs]
User: *Has to read through all of them*
```

### With RAG:
```
User: "What are dangerous SQL injection CVEs?"
System: "Based on the CVE database, here are the most critical SQL injection 
vulnerabilities:

1. CVE-2023-12345 (CVSS 9.8) - Affects PHP applications...
2. CVE-2023-67890 (CVSS 9.5) - Found in MySQL drivers...

Recommendations:
- Patch immediately if using affected versions
- Use parameterized queries
- Enable WAF rules"
```

## Prerequisites

### 1. Get Gemini API Key (FREE!)

1. Go to https://makersuite.google.com/app/apikey
2. Click "Create API Key"
3. Copy your key (starts with `AIza...`)

**Note:** Gemini has a generous free tier!

### 2. Install Packages

```bash
pip install -r rag_requirements.txt
```

Or manually:
```bash
pip install google-generativeai flask flask-cors
```

### 3. Have FAISS Index Ready

Make sure you've converted your CVEs:
```bash
python cve_to_faiss.py --index-name cve-full
```

## Quick Start

### Option 1: Interactive Chat (Easiest)

```bash
python cve_rag_system.py --api-key YOUR_GEMINI_KEY
```

Then ask questions:
```
You: What are the most dangerous SQL injection CVEs?
Assistant: [Intelligent answer with sources]

You: How do buffer overflows work?
Assistant: [Detailed explanation with examples]
```

### Option 2: Single Question

```bash
python cve_rag_system.py --api-key YOUR_GEMINI_KEY --query "What are critical remote code execution CVEs?"
```

### Option 3: Web API

```bash
python cve_rag_api.py --gemini-key YOUR_GEMINI_KEY --port 5001
```

Then open: http://localhost:5001/

## Usage Examples

### Command Line

```bash
# Ask about SQL injection
python cve_rag_system.py --api-key YOUR_KEY --query "What are SQL injection CVEs?"

# Get more context (retrieve 10 CVEs instead of 5)
python cve_rag_system.py --api-key YOUR_KEY --query "Explain XSS vulnerabilities" --top-k 10

# Hide sources
python cve_rag_system.py --api-key YOUR_KEY --query "What is CVE-2023-12345?" --no-sources
```

### Python Integration

```python
from cve_rag_system import CVERAGSystem

# Initialize
rag = CVERAGSystem(gemini_api_key="YOUR_KEY", index_name="cve-full")

# Ask a question
result = rag.ask("What are the most dangerous SQL injection CVEs?")

print(result['answer'])
for cve in result['sources']:
    print(f"- {cve['cve_id']}: {cve['description'][:100]}...")
```

### REST API

```bash
# Start server
python cve_rag_api.py --gemini-key YOUR_KEY --port 5001

# Make requests
curl "http://localhost:5001/api/ask?q=What+are+SQL+injection+CVEs"

# With more context
curl "http://localhost:5001/api/ask?q=Explain+buffer+overflows&top_k=10"
```

### JavaScript/Frontend

```javascript
async function askCVEQuestion(question) {
    const response = await fetch(
        `http://localhost:5001/api/ask?q=${encodeURIComponent(question)}`
    );
    const data = await response.json();
    
    console.log("Answer:", data.answer);
    console.log("Sources:", data.sources);
}

askCVEQuestion("What are critical RCE CVEs?");
```

## Integration with AutoVulRepair

### Add to Your Flask App

```python
# In app.py
from cve_rag_system import CVERAGSystem

# Initialize once at startup
cve_rag = CVERAGSystem(
    gemini_api_key=os.getenv('GEMINI_API_KEY'),
    index_name='cve-full'
)

@app.route('/api/cve/explain/<cve_id>')
def explain_cve(cve_id):
    """Explain a specific CVE using RAG"""
    result = cve_rag.ask(f"Explain {cve_id} in detail")
    return jsonify(result)

@app.route('/api/vulnerability/analyze', methods=['POST'])
def analyze_vulnerability():
    """Analyze a vulnerability finding"""
    finding = request.json.get('finding')
    
    # Ask RAG system
    question = f"What CVEs are similar to: {finding['description']}"
    result = cve_rag.ask(question, top_k=5)
    
    return jsonify({
        'analysis': result['answer'],
        'related_cves': result['sources']
    })
```

### Enhance Scan Results

```python
@app.route('/detailed-findings/<scan_id>')
def detailed_findings(scan_id):
    # ... existing code ...
    
    # Add AI explanations
    for vuln in vulnerabilities:
        explanation = cve_rag.ask(
            f"Explain this vulnerability: {vuln['description']}",
            top_k=3
        )
        vuln['ai_explanation'] = explanation['answer']
        vuln['related_cves'] = explanation['sources']
    
    return render_template('detailed_findings.html', 
                         vulnerabilities=vulnerabilities)
```

### Smart CVE Recommendations

```python
@app.route('/api/cve/recommend')
def recommend_cves():
    """Get CVE recommendations based on user's context"""
    context = request.args.get('context')
    
    result = cve_rag.ask(
        f"What CVEs should I be aware of for: {context}",
        top_k=10
    )
    
    return jsonify(result)
```

## Example Questions

### General Questions
```
- "What are the most dangerous CVEs?"
- "Explain SQL injection vulnerabilities"
- "What are recent critical CVEs?"
- "How do buffer overflows work?"
```

### Specific CVE Questions
```
- "What is CVE-2023-12345?"
- "Is CVE-2023-12345 dangerous?"
- "How do I fix CVE-2023-12345?"
- "What are CVEs similar to CVE-2023-12345?"
```

### Technology-Specific
```
- "What are PHP SQL injection CVEs?"
- "Show me Linux kernel vulnerabilities"
- "What are critical Apache CVEs?"
- "Find Windows privilege escalation CVEs"
```

### Severity-Based
```
- "What are critical CVSS 10.0 CVEs?"
- "Show me high severity buffer overflows"
- "What are the most exploited CVEs?"
```

### Actionable Questions
```
- "How do I protect against SQL injection?"
- "What should I patch first?"
- "How do I detect XSS vulnerabilities?"
- "What are best practices for preventing buffer overflows?"
```

## Advanced Features

### Custom Prompts

```python
# Modify the prompt in cve_rag_system.py
def create_prompt(self, query: str, context: str) -> str:
    prompt = f"""You are a security expert specializing in {YOUR_DOMAIN}.
    
User Question: {query}

CVE Context:
{context}

Provide a detailed, technical answer with:
1. Vulnerability explanation
2. Attack vectors
3. Mitigation strategies
4. Code examples if relevant

Answer:"""
    return prompt
```

### Filter by Severity

```python
# Retrieve only high severity CVEs
from search_cve_faiss import FAISSCVESearch

searcher = FAISSCVESearch('cve-full')
high_severity_cves = searcher.search(
    query="SQL injection",
    top_k=10,
    severity_filter="HIGH"
)
```

### Batch Processing

```python
questions = [
    "What are SQL injection CVEs?",
    "What are XSS CVEs?",
    "What are RCE CVEs?"
]

for question in questions:
    result = rag.ask(question)
    print(f"Q: {question}")
    print(f"A: {result['answer']}\n")
```

## Performance

### Speed
```
FAISS Search: 1-10ms
Gemini Response: 1-3 seconds
Total: ~1-3 seconds per question
```

### Cost (Gemini Free Tier)
```
Free Tier: 60 requests/minute
Cost: FREE for most use cases
Paid: $0.00025 per 1K characters (very cheap)
```

### Optimization Tips

1. **Cache Common Questions**
```python
from functools import lru_cache

@lru_cache(maxsize=100)
def cached_ask(question):
    return rag.ask(question)
```

2. **Reduce Context Size**
```python
# Use fewer CVEs for faster responses
result = rag.ask(query, top_k=3)  # Instead of 5
```

3. **Batch Similar Questions**
```python
# Group related questions together
```

## Troubleshooting

### "API key not valid"
- Check your Gemini API key
- Make sure it starts with `AIza...`
- Get a new key from https://makersuite.google.com/app/apikey

### "Index not found"
- Run conversion first: `python cve_to_faiss.py --index-name cve-full`
- Check index exists: `ls faiss_indexes/`

### "Slow responses"
- Reduce `top_k` (use 3 instead of 5)
- Use faster Gemini model
- Cache common questions

### "Out of quota"
- Wait for quota reset (1 minute)
- Upgrade to paid tier
- Reduce request frequency

## Security Best Practices

### 1. Protect API Keys
```python
# Use environment variables
import os
api_key = os.getenv('GEMINI_API_KEY')

# Never commit keys to git
# Add to .gitignore:
.env
*.key
```

### 2. Rate Limiting
```python
from flask_limiter import Limiter

limiter = Limiter(app, default_limits=["60 per minute"])

@app.route('/api/ask')
@limiter.limit("10 per minute")
def ask_question():
    # ...
```

### 3. Input Validation
```python
def validate_question(question):
    if len(question) > 500:
        raise ValueError("Question too long")
    if not question.strip():
        raise ValueError("Question cannot be empty")
    return question.strip()
```

## Next Steps

1. ✅ Get Gemini API key
2. ✅ Install packages
3. ✅ Test with interactive chat
4. ✅ Integrate into AutoVulRepair
5. ✅ Deploy API server
6. ✅ Build web interface

## Resources

- **Gemini API**: https://ai.google.dev/
- **FAISS**: https://github.com/facebookresearch/faiss
- **RAG Guide**: https://www.promptingguide.ai/techniques/rag

---

**Ready to start?**

```bash
# Get API key from: https://makersuite.google.com/app/apikey
# Then run:
python cve_rag_system.py --api-key YOUR_KEY
```

Ask your first question and see the magic! ✨
