# Architecture Diagram Updates Needed

## What's Missing from Your Current Diagram

Your diagram shows **Modules 1-4** but you've actually implemented **MORE** in Iteration 2!

### ✅ What You Have (Correct)
1. Module 1: Static Analysis ✅
2. Module 2: Fuzz Plan Generator ✅
3. Module 3: Harness Generator ✅
4. Module 4: Build Orchestrator ✅

### ❌ What's Missing (Need to Add)
5. **Module 5: Fuzz Execution** (You implemented this!)
6. **Module 6: Crash Triage** (You implemented this!)
7. **Module 7: Reproduction Kit Generator** (You implemented this!)

---

## Updated Module Flow

```
Module 1: Static Analysis
    ↓ (static_findings.json)
Module 2: Fuzz Plan Generator
    ↓ (fuzzplan.json)
Module 3: Harness Generator
    ↓ (*.cc harness files)
Module 4: Build Orchestrator
    ↓ (compiled fuzz binaries)
Module 5: Fuzz Execution ← MISSING IN YOUR DIAGRAM
    ↓ (campaign_results.json + crash artifacts)
Module 6: Crash Triage ← MISSING IN YOUR DIAGRAM
    ↓ (triage_results.json)
Module 7: Repro Kit Generator ← MISSING IN YOUR DIAGRAM
    ↓ (reproduction kits)
```

---

## What to Add to Your Diagram

### Add Module 5: Fuzz Execution
**Location:** After Module 4 (Build Orchestrator)

**Components:**
- FuzzExecutor
- LibFuzzer Engine
- Crash Monitor

**Input:** Compiled fuzz binaries
**Output:** 
- campaign_results.json
- crash artifacts (crash-*)

**File:** `src/fuzz_exec/executor.py`

---

### Add Module 6: Crash Triage
**Location:** After Module 5 (Fuzz Execution)

**Components:**
- TriageAnalyzer
- Severity Assessor
- Exploitability Evaluator
- CVSS Calculator

**Input:** campaign_results.json + crash artifacts
**Output:** triage_results.json

**File:** `src/triage/analyzer.py`

---

### Add Module 7: Repro Kit Generator
**Location:** After Module 6 (Crash Triage)

**Components:**
- ReproKitGenerator
- Input Minimizer
- Standalone Reproducer Generator
- GDB Script Generator
- Exploit Template Generator

**Input:** triage_results.json
**Output:** Reproduction kits

**File:** `src/repro/generator.py`

---

## Updated Storage Layer

Add these to your File System section:

```
scans/<scan_id>/
├── source/                    ✅ (you have this)
├── artifacts/                 ✅ (you have this)
├── static_findings.json       ✅ (you have this)
├── fuzz/
│   ├── fuzzplan.json         ✅ (you have this)
│   ├── harnesses/            ✅ (you have this)
│   ├── results/              ← ADD THIS
│   │   └── campaign_results.json
│   ├── crashes/              ← ADD THIS
│   │   └── crash-*
│   └── triage/               ← ADD THIS
│       └── triage_results.json
├── build/                     ✅ (you have this)
└── repro_kits/               ← ADD THIS
    └── {crash_id}_*.c
```

---

## Quick Fix Instructions for draw.io

1. **Open your diagram in draw.io**

2. **Add Module 5 box** (after Module 4):
   - Title: "Module 5: Fuzz Execution"
   - Components:
     - FuzzExecutor
     - LibFuzzer Engine
   - Output: campaign_results.json, crash artifacts

3. **Add Module 6 box** (after Module 5):
   - Title: "Module 6: Crash Triage"
   - Components:
     - TriageAnalyzer
     - Severity Assessor
   - Output: triage_results.json

4. **Add Module 7 box** (after Module 6):
   - Title: "Module 7: Repro Kit Generator"
   - Components:
     - ReproKitGenerator
   - Output: Reproduction kits

5. **Add arrows:**
   - Module 4 → Module 5
   - Module 5 → Module 6
   - Module 6 → Module 7

6. **Update Storage Layer:**
   - Add: fuzz/results/
   - Add: fuzz/crashes/
   - Add: fuzz/triage/
   - Add: repro_kits/

---

## Color Coding Suggestion

- **Iteration 1 (Static Analysis):** Blue
  - Module 1: Static Analysis

- **Iteration 2 (Fuzzing Pipeline):** Green
  - Module 2: Fuzz Plan Generator
  - Module 3: Harness Generator
  - Module 4: Build Orchestrator
  - Module 5: Fuzz Execution
  - Module 6: Crash Triage
  - Module 7: Repro Kit Generator

This visually shows what was done in each iteration!

---

## Complete Module List for Your Diagram

| Module | Name | Status | Iteration |
|--------|------|--------|-----------|
| Module 1 | Static Analysis | ✅ Implemented | 1 |
| Module 2 | Fuzz Plan Generator | ✅ Implemented | 2 |
| Module 3 | Harness Generator | ✅ Implemented | 2 |
| Module 4 | Build Orchestrator | ✅ Implemented | 2 |
| Module 5 | Fuzz Execution | ✅ Implemented | 2 |
| Module 6 | Crash Triage | ✅ Implemented | 2 |
| Module 7 | Repro Kit Generator | ✅ Implemented | 2 |

---

## Summary

Your current diagram is **good but incomplete**. You need to add:
- ✅ Module 5: Fuzz Execution
- ✅ Module 6: Crash Triage  
- ✅ Module 7: Repro Kit Generator
- ✅ Updated storage paths

These are **real, working modules** you've implemented - don't forget to show them!
