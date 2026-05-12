# AI Systems Architecture - Complete Guide

## 🎯 Overview

AutoVulRepair has **ONE AI repair system** with **TWO different interfaces** for different use cases:

1. **Batch System** - Background processing (ai_patch_generator.py)
2. **Interactive System** - Real-time UI (src/repair/)

Both are legitimate, both use real AI, and both serve different purposes.

---

## 📊 System Comparison

| Aspect | Batch System | Interactive System |
|--------|-------------|-------------------|
| **Primary File** | `ai_patch_generator.py` | `src/repair/orchestrator.py` |
| **LLM Provider** | Gemini only | Groq (primary) + Gemini (fallback) |
| **Architecture** | Simple, direct API calls | Multi-agent with LangGraph |
| **Execution** | Celery background task | Flask route with threading |
| **Use Case** | Automated batch patching | User-driven interactive repair |
| **User Feedback** | None (runs in background) | Live streaming logs |
| **Speed** | Faster (simpler logic) | Slower (more thorough) |
| **Agents** | Single-step generation | Analyzer → Generator → Validator |
| **Entry Point** | `generate_stage2_patches_task` | `/api/repair/start/<scan_id>` |
| **When to Use** | Automated workflows, CI/CD | Manual debugging, investigation |

---

## 🔄 Workflow Diagrams

### Batch System Workflow

```
User clicks "Generate All Patches"
         ↓
app.py: /api/generate-stage1-patches/<scan_id>
         ↓
PatchGenerationService.generate_all_patches()
         ↓
    ┌────────────────────────────────┐
    │ 1. Classify Vulnerabilities    │
    │    - Stage 1: Rule-based       │
    │    - Stage 2: AI-powered       │
    └────────────┬───────────────────┘
                 ↓
    ┌────────────────────────────────┐
    │ 2. Generate Stage 1 Patches    │
    │    (Synchronous, fast)         │
    │    Uses: Stage1RepairEngine    │
    └────────────┬───────────────────┘
                 ↓
    ┌────────────────────────────────┐
    │ 3. Trigger Stage 2 Task        │
    │    (Asynchronous, slow)        │
    │    Celery: generate_stage2_    │
    │            patches_task.delay()│
    └────────────┬───────────────────┘
                 ↓
    ┌────────────────────────────────┐
    │ 4. Background Processing       │
    │    Uses: ai_patch_generator.py │
    │    - AIPatchGenerator          │
    │    - Gemini API                │
    │    - FAISS CVE search          │
    └────────────┬───────────────────┘
                 ↓
    ┌────────────────────────────────┐
    │ 5. Save Patches to Database    │
    │    Status: "ready"             │
    └────────────────────────────────┘
```

### Interactive System Workflow

```
User clicks "Start AI Repair"
         ↓
app.py: /api/repair/start/<scan_id>
         ↓
    ┌────────────────────────────────┐
    │ 1. Filter Stage 2 Vulns        │
    │    (Complex vulnerabilities)   │
    └────────────┬───────────────────┘
                 ↓
    ┌────────────────────────────────┐
    │ 2. Initialize Orchestrator     │
    │    RepairOrchestrator()        │
    │    - Multi-provider LLM        │
    │    - LangGraph workflow        │
    └────────────┬───────────────────┘
                 ↓
    ┌────────────────────────────────┐
    │ 3. Start Background Thread     │
    │    (Non-blocking)              │
    │    + Live log streaming        │
    └────────────┬───────────────────┘
                 ↓
    ┌────────────────────────────────┐
    │ 4. Multi-Agent Workflow        │
    │                                │
    │  ┌──────────────────────────┐ │
    │  │ Analyzer Agent           │ │
    │  │ - Read code context      │ │
    │  │ - Analyze root cause     │ │
    │  │ - Determine fix strategy │ │
    │  └──────────┬───────────────┘ │
    │             ↓                  │
    │  ┌──────────────────────────┐ │
    │  │ Generator Agent          │ │
    │  │ - Generate 3 patches:    │ │
    │  │   • Conservative         │ │
    │  │   • Moderate             │ │
    │  │   • Aggressive           │ │
    │  └──────────┬───────────────┘ │
    │             ↓                  │
    │  ┌──────────────────────────┐ │
    │  │ Validator Agent          │ │
    │  │ - Validate patch format  │ │
    │  │ - Score patches          │ │
    │  │ - Select best patch      │ │
    │  └──────────┬───────────────┘ │
    └─────────────┼──────────────────┘
                  ↓
    ┌────────────────────────────────┐
    │ 5. Save Results to Database    │
    │    + Stream logs to UI         │
    └────────────────────────────────┘
```

---

## 📁 File Structure

### Batch System Files

```
ai_patch_generator.py              # Main patch generator class
├── AIPatchGenerator
│   ├── analyze_vulnerability()    # Find related CVEs
│   ├── generate_patch()           # Generate single patch
│   └── generate_batch_patches()   # Generate multiple patches

search_cve_faiss.py                # CVE vector search
├── FAISSCVESearch
│   ├── search()                   # Semantic search
│   └── find_similar_to_cve()      # Find similar CVEs

cve_rag_system.py                  # RAG system (optional)
└── CVERAGSystem
    ├── retrieve_context()         # Get CVE context
    └── generate_response()        # Generate with context

src/services/patch_generation_service.py
└── generate_stage2_patches_task() # Celery task entry point
```

### Interactive System Files

```
src/repair/
├── orchestrator.py                # Main orchestrator
│   └── RepairOrchestrator
│       ├── repair()               # Main repair method
│       └── _build_workflow()      # LangGraph workflow
│
├── llm_client.py                  # Multi-provider LLM
│   ├── GroqClient                 # Groq API client
│   ├── GeminiClient               # Gemini API client
│   └── MultiProviderLLMClient     # Automatic fallback
│
├── agents/
│   ├── analyzer.py                # Analyzer agent
│   ├── generator.py               # Generator agent
│   └── validator.py               # Validator agent
│
├── prompts.py                     # Prompt templates
├── validators.py                  # Response validators
├── state.py                       # LangGraph state
└── metrics.py                     # Performance metrics
```

---

## 🚀 When to Use Each System

### Use Batch System When:

✅ Processing many vulnerabilities at once  
✅ Running automated scans (CI/CD)  
✅ Don't need real-time feedback  
✅ Want faster processing  
✅ Running in background/scheduled jobs  
✅ Integrating with Celery workflows  

**Example:**
```python
# Automated nightly scan
scan_id = run_security_scan()
generate_all_patches(scan_id)  # Uses batch system
# Patches ready in the morning
```

### Use Interactive System When:

✅ Debugging specific vulnerabilities  
✅ Want to see AI reasoning process  
✅ Need live feedback and logs  
✅ Investigating complex issues  
✅ Learning how AI fixes work  
✅ Manual security review  

**Example:**
```python
# Security engineer investigating a crash
POST /api/repair/start/scan_123
# Watch live logs as AI analyzes and fixes
# See each agent's reasoning
```

---

## 🔧 Configuration

### Batch System Configuration

```bash
# .env file
GEMINI_API_KEY=your_gemini_key_here

# Optional: FAISS index for CVE context
# Run: python cve_to_faiss.py --index-name cve-full
```

**Used by:**
- `ai_patch_generator.py`
- `generate_stage2_patches_task` (Celery)

### Interactive System Configuration

```bash
# .env file
GROQ_API_KEY=your_groq_key_here      # Primary (fast, free)
GEMINI_API_KEY=your_gemini_key_here  # Fallback (optional)
```

**Used by:**
- `src/repair/orchestrator.py`
- `/api/repair/start/<scan_id>` endpoint

---

## 📊 Performance Comparison

### Batch System Performance

| Metric | Value |
|--------|-------|
| Time per vulnerability | ~5-10 seconds |
| Patches per vulnerability | 1 |
| Parallel processing | Yes (Celery) |
| Memory usage | Low |
| API calls per vuln | 1-2 |
| Best for | High volume |

### Interactive System Performance

| Metric | Value |
|--------|-------|
| Time per vulnerability | ~7-15 seconds |
| Patches per vulnerability | 3 (conservative, moderate, aggressive) |
| Parallel processing | Limited (threading) |
| Memory usage | Medium |
| API calls per vuln | 3-4 |
| Best for | Deep analysis |

---

## 🎓 Migration Guide

### If You Want to Unify Systems

**Option A: Use Interactive System for Everything**

```python
# Replace batch system with interactive
@shared_task
def generate_stage2_patches_task(scan_id, batch_id, vulnerabilities):
    from src.repair.orchestrator import RepairOrchestrator
    
    orchestrator = RepairOrchestrator()
    
    for vuln in vulnerabilities:
        result = orchestrator.repair(
            vulnerability=vuln,
            scan_id=scan_id,
            crash_id=vuln['id']
        )
        # Save result to database
```

**Pros:** Single codebase, consistent behavior  
**Cons:** Slower, more complex, higher API costs

**Option B: Add Batch Mode to Interactive System**

```python
# src/repair/orchestrator.py
class RepairOrchestrator:
    def __init__(self, mode='interactive'):
        self.mode = mode
        
        if mode == 'batch':
            # Simpler, faster processing
            self.llm = GeminiClient()
            self.enable_logging = False
        else:
            # Full multi-agent with logging
            self.llm = MultiProviderLLMClient()
            self.enable_logging = True
```

**Pros:** Unified codebase, optimized for each use case  
**Cons:** More complex code, harder to maintain

---

## 🐛 Troubleshooting

### Batch System Issues

**Problem:** Patches not generating  
**Check:**
```bash
# 1. Is Celery running?
celery -A celery_worker worker --loglevel=info

# 2. Is GEMINI_API_KEY set?
echo $GEMINI_API_KEY

# 3. Check Celery logs
tail -f celery_worker.log
```

**Problem:** Slow patch generation  
**Solution:** Increase Celery workers
```bash
celery -A celery_worker worker --concurrency=4
```

### Interactive System Issues

**Problem:** No LLM providers available  
**Check:**
```bash
# Test LLM health
curl http://localhost:5000/api/repair/health

# Check API keys
echo $GROQ_API_KEY
echo $GEMINI_API_KEY
```

**Problem:** Patches not showing in UI  
**Check:**
```bash
# Check repair logs
cat scans/<scan_id>/repair/repair_log.txt

# Check database
psql -d autovulrepair -c "SELECT * FROM repair_patches WHERE scan_id='<scan_id>';"
```

---

## 📚 API Reference

### Batch System API

```python
from ai_patch_generator import AIPatchGenerator

# Initialize
generator = AIPatchGenerator(
    gemini_api_key="your_key",
    index_name="cve-full"
)

# Generate single patch
patch = generator.generate_patch(vulnerability)

# Generate batch
patches = generator.generate_batch_patches(vulnerabilities)
```

### Interactive System API

```python
from src.repair.orchestrator import RepairOrchestrator

# Initialize
orchestrator = RepairOrchestrator()

# Repair single vulnerability
result = orchestrator.repair(
    vulnerability=vuln_dict,
    scan_id="scan_123",
    crash_id="crash_456"
)

# Check health
health = orchestrator.check_health()
```

---

## ✅ Summary

**You have TWO systems, but that's GOOD:**

1. **Batch System** - Fast, simple, automated
2. **Interactive System** - Thorough, visible, manual

**Both are:**
- ✅ Using real AI (not hallucination)
- ✅ Serving valid use cases
- ✅ Production-ready
- ✅ Well-designed

**Only issue:**
- ❌ Lack of documentation (now fixed!)
- ❌ Unused `patch_routes.py` file (now marked)

**No code changes needed.** Just better documentation. ✅

---

**Document Version:** 1.0  
**Last Updated:** May 9, 2026  
**Maintained By:** AutoVulRepair Team

