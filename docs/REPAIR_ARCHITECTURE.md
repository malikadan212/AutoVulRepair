# Repair Module Architecture

## **System Overview**

```
┌─────────────────────────────────────────────────────────────────────┐
│                         YOUR EXISTING SYSTEM                         │
├─────────────────────────────────────────────────────────────────────┤
│  Static Analysis → Fuzzing → Triage → triage_results.json          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         REPAIR MODULE (NEW)                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              REPAIR ORCHESTRATOR (LangGraph)                 │   │
│  │                                                               │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │   │
│  │  │ ANALYZER │→ │GENERATOR │→ │VALIDATOR │→ │OPTIMIZER │   │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │   │
│  │       ↓             ↓             ↓             ↓           │   │
│  │   Analysis      3 Patches    Test Results  Final Patch     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    OLLAMA (Local LLM)                        │   │
│  │                  qwen2.5-coder:7b model                      │   │
│  │                  (Runs in Docker container)                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                          validated_patches.json
                                    │
                                    ▼
                          Apply to source code
```

---

## **Agent Details**

### **1. Analyzer Agent**

**Purpose:** Deep understanding of the vulnerability

**Input:**
```json
{
  "crash_type": "Heap Buffer Overflow",
  "file": "src/parser.c",
  "function": "parse_input",
  "line": 42,
  "stack_trace": [...],
  "sanitizer_output": "..."
}
```

**Process:**
1. Read source code (±20 lines around bug)
2. Analyze with LLM: "Why did this crash?"
3. Identify vulnerable pattern
4. Determine fix strategy

**Output:**
```json
{
  "root_cause": "Array access without bounds checking",
  "vulnerable_pattern": "buffer[index] with unchecked index",
  "fix_strategy": "Add bounds check before array access",
  "code_context": "... full function code ..."
}
```

**LLM Prompt:**
```
You are a security expert. Analyze this vulnerability:

Code:
[source code]

Crash: Heap Buffer Overflow at line 42
Stack trace: [...]

What is the root cause? What pattern caused it? How should we fix it?
```

---

### **2. Generator Agent**

**Purpose:** Create multiple patch candidates

**Input:** Analyzer's output

**Process:**
1. Generate 3 different patches:
   - **Conservative:** Minimal changes (just add bounds check)
   - **Moderate:** Balanced fix (bounds check + error handling)
   - **Aggressive:** Comprehensive (replace unsafe function)
2. Create unified diff format
3. Rank by confidence

**Output:**
```json
{
  "patches": [
    {
      "id": "patch_1_conservative",
      "diff": "--- a/src/parser.c\n+++ b/src/parser.c\n@@ -40,1 +40,3 @@\n+if (index >= size) return -1;\n buffer[index] = value;",
      "confidence": 0.85,
      "risk": "low"
    },
    {
      "id": "patch_2_moderate",
      "diff": "...",
      "confidence": 0.75,
      "risk": "medium"
    },
    {
      "id": "patch_3_aggressive",
      "diff": "...",
      "confidence": 0.60,
      "risk": "high"
    }
  ]
}
```

**LLM Prompt:**
```
Generate a {conservative/moderate/aggressive} patch to fix:

Root cause: {root_cause}
Fix strategy: {fix_strategy}

Code:
[source code]

Output ONLY the unified diff format.
```

---

### **3. Validator Agent**

**Purpose:** Test patches automatically

**Input:** All 3 patches

**Process:**
For each patch:
1. Apply patch to source code
2. Rebuild fuzz target (using your BuildOrchestrator)
3. Re-run fuzzer with crash input
4. Check: Does it still crash?
5. Run regression test (5 seconds of fuzzing)
6. Score the patch

**Scoring System:**
```python
score = 0
if compiles:           score += 30
if fixes_crash:        score += 40
if no_regressions:     score += 20
if performance_ok:     score += 10
# Total: 0-100
```

**Output:**
```json
{
  "validation_results": [
    {
      "patch_id": "patch_1_conservative",
      "compiled": true,
      "crash_fixed": true,
      "regression_passed": true,
      "score": 95,
      "recommended": true
    },
    {
      "patch_id": "patch_2_moderate",
      "compiled": true,
      "crash_fixed": true,
      "regression_passed": false,
      "score": 60,
      "recommended": false
    },
    {
      "patch_id": "patch_3_aggressive",
      "compiled": false,
      "score": 0,
      "recommended": false
    }
  ],
  "best_patch": "patch_1_conservative"
}
```

**Integration:**
```python
# Uses your existing infrastructure!
build_orchestrator = BuildOrchestrator(scan_id)
fuzz_executor = FuzzExecutor(scan_id)

# Rebuild with patch
build_result = build_orchestrator.build_target(...)

# Test with crash input
test_result = fuzz_executor.run_with_input(crash_input)
```

---

### **4. Optimizer Agent** (Optional)

**Purpose:** Improve the best patch

**Input:** Best validated patch

**Process:**
1. Analyze patch for improvements
2. Add better comments
3. Improve variable names
4. Add error messages
5. Re-validate to ensure still works

**Output:**
```json
{
  "optimized_patch": {
    "diff": "... improved version ...",
    "improvements": [
      "Added descriptive comment",
      "Renamed 'i' to 'buffer_index'",
      "Added error message"
    ]
  }
}
```

---

## **LangGraph Workflow**

### **State Machine:**

```
                    START
                      │
                      ▼
              ┌───────────────┐
              │   ANALYZE     │
              │   (Agent 1)   │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │   GENERATE    │
              │   (Agent 2)   │
              │ Creates 3     │
              │ patches       │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │   VALIDATE    │
              │   (Agent 3)   │
              │ Tests all 3   │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │  Decision:    │
              │  Any worked?  │
              └───┬───────┬───┘
                  │       │
            YES   │       │   NO
                  │       │
                  ▼       ▼
          ┌──────────┐  ┌──────────┐
          │ OPTIMIZE │  │  RETRY   │
          │(Agent 4) │  │ (if <3   │
          └────┬─────┘  │ retries) │
               │        └────┬─────┘
               │             │
               ▼             ▼
          ┌──────────────────────┐
          │    SAVE RESULTS      │
          └──────────────────────┘
                      │
                      ▼
                    END
```

### **State Object:**

```python
class RepairState(TypedDict):
    # Input
    scan_id: str
    vulnerability: Dict
    
    # Agent outputs
    analysis: Dict          # From Analyzer
    patches: List[Dict]     # From Generator
    validation: List[Dict]  # From Validator
    best_patch: Dict        # From Validator
    optimized: Dict         # From Optimizer
    
    # Control
    retry_count: int
    status: str
    error: Optional[str]
```

---

## **Integration Points**

### **With Your Existing System:**

```python
# 1. Load triage results (your existing data)
triage_results = load_triage_results(scan_id)

# 2. For each critical/high vulnerability
for crash in triage_results['crashes']:
    if crash['severity'] in ['Critical', 'High']:
        
        # 3. Run repair workflow
        orchestrator = RepairOrchestrator(scan_id)
        result = orchestrator.repair(crash)
        
        # 4. Save results
        save_repair_results(scan_id, result)
```

### **Uses Your Infrastructure:**

```python
# Build orchestration (already exists)
from src.build.orchestrator import BuildOrchestrator

# Fuzz execution (already exists)
from src.fuzz_exec.executor import FuzzExecutor

# Database (already exists)
from src.models.scan import get_session, Scan
```

---

## **Data Flow Example**

### **Input (from your triage):**
```json
{
  "crash_id": "crash_abc123",
  "target": "parse_input_fuzz",
  "crash_type": "Heap Buffer Overflow",
  "file": "src/parser.c",
  "function": "parse_input",
  "line": 42,
  "severity": "Critical",
  "exploitability": "Exploitable",
  "stack_trace": ["#0 parse_input", "#1 main"],
  "sanitizer_output": "heap-buffer-overflow on address 0x..."
}
```

### **After Analyzer:**
```json
{
  "root_cause": "Array index not validated before use",
  "vulnerable_pattern": "buffer[index] where index from user input",
  "fix_strategy": "Add bounds check: if (index >= size) return error",
  "code_context": "void parse_input(char* buffer, int index) { ... }"
}
```

### **After Generator:**
```json
{
  "patches": [
    {
      "id": "patch_1",
      "diff": "--- a/src/parser.c\n+++ b/src/parser.c\n...",
      "strategy": "Add bounds check"
    },
    // ... 2 more patches
  ]
}
```

### **After Validator:**
```json
{
  "best_patch": {
    "id": "patch_1",
    "compiled": true,
    "crash_fixed": true,
    "score": 95
  }
}
```

### **Final Output:**
```json
{
  "scan_id": "abc123",
  "vulnerability_id": "crash_abc123",
  "status": "complete",
  "patch": {
    "diff": "--- a/src/parser.c\n+++ b/src/parser.c\n...",
    "validated": true,
    "score": 95
  },
  "time_taken": 45.2
}
```

---

## **Technology Stack**

### **Core:**
- **LangGraph** - Agent orchestration
- **Ollama** - Local LLM inference
- **qwen2.5-coder:7b** - Code model

### **Integration:**
- Your BuildOrchestrator
- Your FuzzExecutor
- Your database models

### **Storage:**
- Docker volume for models (~5GB)
- Database for repair results
- File system for patches

---

## **Performance Expectations**

### **Time per Repair:**
- Analyzer: ~10 seconds
- Generator: ~15 seconds (3 patches)
- Validator: ~20 seconds (compile + test)
- Optimizer: ~10 seconds
- **Total: ~60 seconds per vulnerability**

### **Success Rate:**
- Simple bugs: 80-90%
- Medium bugs: 50-70%
- Complex bugs: 20-40%
- **Overall: ~60-70%**

### **Resource Usage:**
- CPU: 2-4 cores (during repair)
- RAM: 8GB recommended
- Disk: 5GB (model in Docker)

---

## **Advantages**

1. **Free & Local** - No API costs, runs on your machine
2. **Leverages Your Work** - Uses your triage data and infrastructure
3. **Automatic Validation** - Tests patches objectively
4. **Multiple Options** - 3 patches to choose from
5. **Extensible** - Easy to add more agents

---

## **Next Steps**

See `REPAIR_QUICKSTART.md` for setup instructions!
