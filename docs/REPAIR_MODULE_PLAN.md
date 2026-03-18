# Repair Module Implementation Plan
## Multi-Agent System with LangGraph + Ollama

---

## **PHASE 0: Docker Setup (DO THIS FIRST)**

### What You Need to Do Right Now:

1. **Start Ollama and pull the model:**
   ```bash
   # Windows:
   setup_ollama.bat
   
   # Linux/Mac:
   chmod +x setup_ollama.sh
   ./setup_ollama.sh
   ```

2. **Wait for model download** (~4.7GB, takes 5-15 minutes)

3. **Verify it's working:**
   ```bash
   # Check Ollama is running
   curl http://localhost:11434/api/tags
   
   # Should return JSON with qwen2.5-coder:7b listed
   ```

4. **Test the model:**
   ```bash
   docker-compose exec ollama ollama run qwen2.5-coder:7b "Write a hello world in C"
   ```

### What Changed:
- ✅ Added `ollama` service to docker-compose.yml
- ✅ Models stored in Docker volume (not your laptop)
- ✅ Added OLLAMA_URL environment variable to app and celery
- ✅ Created setup scripts for easy installation

---

## **PHASE 1: Core Infrastructure (Week 1)**

### Day 1-2: LangGraph Setup & State Management

**Files to Create:**
```
src/repair/
├── __init__.py                    ✓ Created
├── state.py                       → Define shared state
├── orchestrator.py                → LangGraph workflow
└── llm_client.py                  → Ollama client wrapper
```

**What We'll Build:**

#### 1. State Definition (`state.py`)
```python
from typing import TypedDict, List, Dict, Optional

class RepairState(TypedDict):
    """Shared state passed between agents"""
    
    # Input data
    scan_id: str
    vulnerability: Dict  # From triage_results.json
    
    # Analyzer outputs
    analysis: Optional[Dict]
    root_cause: Optional[str]
    fix_strategy: Optional[str]
    code_context: Optional[str]
    
    # Generator outputs
    patches: List[Dict]
    
    # Validator outputs
    validation_results: List[Dict]
    best_patch: Optional[Dict]
    
    # Optimizer outputs
    optimized_patch: Optional[Dict]
    
    # Control flow
    retry_count: int
    max_retries: int
    status: str  # "analyzing", "generating", "validating", "optimizing", "complete", "failed"
    error: Optional[str]
    
    # Metadata
    started_at: str
    completed_at: Optional[str]
```

#### 2. Ollama Client (`llm_client.py`)
```python
import requests
import os

class OllamaClient:
    """Wrapper for Ollama API calls"""
    
    def __init__(self):
        self.base_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.model = 'qwen2.5-coder:7b'
    
    def generate(self, prompt: str, system: str = None) -> str:
        """Generate completion from Ollama"""
        # Implementation here
```

#### 3. Orchestrator (`orchestrator.py`)
```python
from langgraph.graph import StateGraph, END

class RepairOrchestrator:
    """Main workflow orchestrator using LangGraph"""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.graph = self._build_graph()
    
    def _build_graph(self):
        """Build the LangGraph state machine"""
        workflow = StateGraph(RepairState)
        
        # Add nodes (agents)
        workflow.add_node("analyze", self._analyze_node)
        workflow.add_node("generate", self._generate_node)
        workflow.add_node("validate", self._validate_node)
        workflow.add_node("optimize", self._optimize_node)
        
        # Define edges (flow)
        workflow.set_entry_point("analyze")
        workflow.add_edge("analyze", "generate")
        workflow.add_edge("generate", "validate")
        
        # Conditional edge: retry or optimize?
        workflow.add_conditional_edges(
            "validate",
            self._should_retry_or_optimize,
            {
                "optimize": "optimize",
                "retry": "generate",
                "end": END
            }
        )
        
        workflow.add_edge("optimize", END)
        
        return workflow.compile()
    
    def repair(self, vulnerability: Dict) -> Dict:
        """Run repair workflow for a vulnerability"""
        # Implementation here
```

**Deliverables:**
- ✅ State management system
- ✅ Ollama client working
- ✅ Basic LangGraph workflow skeleton
- ✅ Can run end-to-end (even if agents are stubs)

---

### Day 3-4: Analyzer Agent

**Files to Create:**
```
src/repair/agents/
├── __init__.py
├── analyzer.py                    → Bug analysis agent
└── base.py                        → Base agent class
```

**What the Analyzer Does:**

1. **Reads source code** around the vulnerability
2. **Analyzes root cause** using LLM
3. **Determines fix strategy**
4. **Extracts relevant context**

**Prompt Template:**
```python
ANALYZER_PROMPT = """You are a security expert analyzing a vulnerability.

Vulnerability Details:
- Type: {crash_type}
- File: {file}
- Function: {function}
- Line: {line}
- Severity: {severity}

Code Context:
```c
{code_context}
```

Stack Trace:
{stack_trace}

Sanitizer Output:
{sanitizer_output}

Analyze this vulnerability and provide:
1. Root cause (why did it crash?)
2. Vulnerable pattern (what code pattern caused it?)
3. Fix strategy (how should we fix it?)
4. Required changes (what needs to be modified?)

Be specific and technical.
"""
```

**Deliverables:**
- ✅ Analyzer agent working
- ✅ Can extract code context from source files
- ✅ Produces structured analysis output
- ✅ Integrated with LangGraph workflow

---

### Day 5-7: Generator Agent

**Files to Create:**
```
src/repair/agents/
├── generator.py                   → Patch generation agent
└── prompts.py                     → All prompt templates
```

**What the Generator Does:**

1. **Takes analyzer output**
2. **Generates 3 patch candidates:**
   - Conservative (minimal changes)
   - Moderate (balanced fix)
   - Aggressive (comprehensive fix)
3. **Creates unified diff format**
4. **Ranks by confidence**

**Prompt Template:**
```python
GENERATOR_PROMPT = """You are a code repair expert. Generate a patch to fix this vulnerability.

Analysis:
{analysis}

Fix Strategy: {fix_strategy}

Code to Fix:
```c
{code_context}
```

Generate a {patch_type} patch that:
- Fixes the vulnerability
- Preserves functionality
- Follows secure coding practices
- Is minimal and focused

Output ONLY the unified diff format (--- / +++ / @@ / - / +).
"""
```

**Deliverables:**
- ✅ Generator agent working
- ✅ Produces 3 different patches
- ✅ Patches in unified diff format
- ✅ Confidence scoring

---

## **PHASE 2: Validation & Testing (Week 2)**

### Day 8-10: Validator Agent

**Files to Create:**
```
src/repair/agents/
└── validator.py                   → Patch validation agent
```

**What the Validator Does:**

1. **For each patch:**
   - Apply to source code
   - Rebuild fuzz target (use your BuildOrchestrator)
   - Re-run fuzzer with crash input
   - Check if crash is fixed
   - Run regression test (5 seconds fuzzing)

2. **Score patches:**
   - Compiles? (+30 points)
   - Fixes crash? (+40 points)
   - No regressions? (+20 points)
   - Performance OK? (+10 points)

3. **Select best patch**

**Integration with Your System:**
```python
class PatchValidator:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.build_orchestrator = BuildOrchestrator(scan_id)
        self.fuzz_executor = FuzzExecutor(scan_id)
    
    def validate_patch(self, patch: Dict, vulnerability: Dict) -> Dict:
        # 1. Apply patch
        self._apply_patch(patch)
        
        # 2. Rebuild
        build_result = self.build_orchestrator.build_target(...)
        
        # 3. Test with crash input
        test_result = self.fuzz_executor.run_with_input(...)
        
        # 4. Score
        score = self._calculate_score(build_result, test_result)
        
        return {
            'patch_id': patch['id'],
            'compiled': build_result['status'] == 'success',
            'crash_fixed': not test_result['crashed'],
            'score': score,
            'recommended': score >= 70
        }
```

**Deliverables:**
- ✅ Validator agent working
- ✅ Integrates with BuildOrchestrator
- ✅ Integrates with FuzzExecutor
- ✅ Objective scoring system
- ✅ Selects best patch automatically

---

### Day 11-12: Optimizer Agent (Optional)

**Files to Create:**
```
src/repair/agents/
└── optimizer.py                   → Patch optimization agent
```

**What the Optimizer Does:**

1. Takes best validated patch
2. Improves code quality:
   - Better variable names
   - Add comments
   - Better error messages
3. Re-validates to ensure still works

**Deliverables:**
- ✅ Optimizer agent working
- ✅ Improves patch quality
- ✅ Re-validates after optimization

---

### Day 13-14: Integration Testing

**Test the full pipeline:**

1. **Unit tests for each agent**
2. **Integration test: end-to-end repair**
3. **Test with real vulnerabilities from your scans**
4. **Measure success rate**

**Test Script:**
```python
# tests/test_repair_workflow.py
def test_full_repair_workflow():
    # Load a real vulnerability from triage
    scan_id = "test-scan-123"
    vulnerability = load_test_vulnerability()
    
    # Run repair
    orchestrator = RepairOrchestrator(scan_id)
    result = orchestrator.repair(vulnerability)
    
    # Verify
    assert result['status'] == 'complete'
    assert result['best_patch'] is not None
    assert result['validation_results'][0]['crash_fixed'] == True
```

---

## **PHASE 3: UI & API (Week 3)**

### Day 15-17: API Endpoints

**Add to `app.py`:**

```python
# ============================================================================
# REPAIR MODULE ROUTES
# ============================================================================

@app.route('/repair/<scan_id>')
def repair_dashboard(scan_id):
    """Repair dashboard showing all repairs"""
    return render_template('repair_dashboard.html', scan_id=scan_id)

@app.route('/api/repair/start/<scan_id>', methods=['POST'])
def start_repair(scan_id):
    """Start repair workflow for all critical/high vulnerabilities"""
    orchestrator = RepairOrchestrator(scan_id)
    results = orchestrator.repair_all()
    return jsonify(results)

@app.route('/api/repair/status/<scan_id>')
def repair_status(scan_id):
    """Get repair status"""
    results = load_repair_results(scan_id)
    return jsonify(results)

@app.route('/api/repair/patch/<scan_id>/<patch_id>')
def get_patch(scan_id, patch_id):
    """Get specific patch details"""
    patch = load_patch(scan_id, patch_id)
    return jsonify(patch)

@app.route('/api/repair/apply/<scan_id>/<patch_id>', methods=['POST'])
def apply_patch(scan_id, patch_id):
    """Apply a patch to the source code"""
    result = apply_patch_to_source(scan_id, patch_id)
    return jsonify(result)
```

---

### Day 18-19: UI Templates

**Files to Create:**
```
templates/
├── repair_dashboard.html          → Main repair dashboard
├── repair_progress.html           → Real-time progress
└── patch_review.html              → Review/approve patches
```

**Features:**
- View all repairs for a scan
- See patch diffs (before/after)
- Approve/reject patches
- Apply patches with one click
- View validation results

---

### Day 20-21: Polish & Documentation

1. **Add logging** throughout the system
2. **Error handling** for edge cases
3. **Documentation:**
   - User guide for repair module
   - API documentation
   - Architecture diagram
4. **Metrics dashboard:**
   - Success rate
   - Average time per repair
   - Most common bug types fixed

---

## **PHASE 4: Testing & Tuning (Week 4)**

### Day 22-25: Real-World Testing

1. **Run on 50+ real vulnerabilities**
2. **Measure success rate**
3. **Identify failure patterns**
4. **Tune prompts based on results**

### Day 26-28: Improvements

1. **Add retry logic for failures**
2. **Improve prompts for low-success bug types**
3. **Add more validation checks**
4. **Optimize performance**

---

## **Success Metrics**

### Target Goals:
- ✅ **60%+ auto-fix rate** for simple bugs
- ✅ **<2 minutes** per repair (analyze + generate + validate)
- ✅ **90%+ compile rate** for generated patches
- ✅ **Zero false positives** (patches that break code)

### Tracking:
```python
# src/repair/metrics.py
class RepairMetrics:
    def track_repair(self, result):
        # Track success/failure
        # Track time taken
        # Track bug type
        # Save to database
```

---

## **File Structure (Final)**

```
src/repair/
├── __init__.py
├── orchestrator.py              # LangGraph workflow
├── state.py                     # State definition
├── llm_client.py               # Ollama client
├── metrics.py                  # Success tracking
├── agents/
│   ├── __init__.py
│   ├── base.py                 # Base agent class
│   ├── analyzer.py             # Analysis agent
│   ├── generator.py            # Patch generation agent
│   ├── validator.py            # Validation agent
│   └── optimizer.py            # Optimization agent
├── tools/
│   ├── __init__.py
│   ├── code_reader.py          # Read source files
│   ├── patch_applier.py        # Apply patches
│   └── diff_generator.py       # Generate diffs
└── prompts.py                  # All prompt templates

templates/
├── repair_dashboard.html
├── repair_progress.html
└── patch_review.html

tests/
└── test_repair/
    ├── test_analyzer.py
    ├── test_generator.py
    ├── test_validator.py
    └── test_workflow.py
```

---

## **Dependencies to Add**

Update `requirements.txt`:
```txt
# Existing dependencies...

# Repair module dependencies
langgraph>=0.0.20
langchain>=0.1.0
langchain-community>=0.0.20
```

---

## **Next Steps (What You Do Now)**

### Immediate (Today):
1. ✅ Run `setup_ollama.bat` (Windows) or `setup_ollama.sh` (Linux/Mac)
2. ✅ Wait for model download (~10 minutes)
3. ✅ Test Ollama: `curl http://localhost:11434/api/tags`
4. ✅ Test model: `docker-compose exec ollama ollama run qwen2.5-coder:7b "Hello"`

### Tomorrow:
1. Install LangGraph: `pip install langgraph langchain langchain-community`
2. I'll create the core infrastructure (state.py, llm_client.py, orchestrator.py)
3. We'll test the basic workflow

### This Week:
1. Build Analyzer Agent
2. Build Generator Agent
3. Test end-to-end (even without validation)

---

## **Questions?**

Before we start coding, any questions about:
- The architecture?
- The timeline?
- The agents?
- Integration with your existing system?

Let me know and I'll clarify!
