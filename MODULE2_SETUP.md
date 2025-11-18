# Module 2 Setup Complete! 🎉

## What We've Built

### Component 1: Fuzz-Plan Generator ✅

**Files Created:**
- `src/fuzz_plan/generator.py` - Main fuzz plan generator (FR1-FR4)
- `src/module1/cppcheck_to_findings.py` - Converts Cppcheck XML to standardized JSON
- `convert_scan_to_findings.py` - Helper script for existing scans
- `templates/fuzz_plan.html` - Beautiful web UI for fuzz plan visualization

**Backend Routes Added:**
- `GET /fuzz-plan/<scan_id>` - View fuzz plan page
- `POST /api/fuzz-plan/generate/<scan_id>` - Generate fuzz plan from static findings
- `GET /api/fuzz-plan/<scan_id>` - Get fuzz plan JSON

**Features Implemented:**
- ✅ FR1: Convert static_findings.json to fuzz/fuzzplan.json
- ✅ FR2: Infer bug classes, sanitizers, and priorities
- ✅ FR3: De-duplicate findings by function
- ✅ FR4: Generate complete target metadata

## How to Use

### 1. Start the Flask App (if not running)
```bash
python app.py
```

### 2. Access the Fuzz Plan Page

**Option A: From Detailed Findings Page**
1. Go to: http://127.0.0.1:5000/detailed-findings/679cb872-c202-49c7-84a3-30ef32a34f94
2. Click the "Generate Fuzz Plan" button
3. View the fuzz plan visualization

**Option B: Direct URL**
```
http://127.0.0.1:5000/fuzz-plan/679cb872-c202-49c7-84a3-30ef32a34f94
```

### 3. Generate Fuzz Plan
- Click "Generate Fuzz Plan" button on the page
- Wait for generation (takes ~1 second)
- Page will auto-reload with results

## What You'll See

### Fuzz Plan Dashboard
- **9 Deduplicated Targets** from 20 findings
- **Bug Class Breakdown**: UAF (2), OOB (3), Integer-UB (1), etc.
- **Priority Scores**: Highest priority targets shown first
- **Filter by Bug Class**: OOB, UAF, Integer-UB, Null-Deref

### Each Target Shows:
- Function name and location
- Bug class and severity
- Sanitizers to use (ASan, UBSan, MSan)
- Harness type (bytes_to_api, fdp_adapter, parser_wrapper)
- Priority score (higher = more critical)
- CWE classification
- Original finding message

## Test Data

We're using the scan: `679cb872-c202-49c7-84a3-30ef32a34f94`

**Static Findings:**
- 20 fuzzable vulnerabilities
- 9 unique functions (after deduplication)
- Bug classes: OOB, UAF, Integer-UB, Null-Deref, Resource-Leak, Uninit-Var

**Generated Fuzz Plan:**
```
./scans/679cb872-c202-49c7-84a3-30ef32a34f94/fuzz/fuzzplan.json
```

## Next Steps

### Component 2: Harness Generator (Next)
- Create harness templates (bytes_to_api, fdp_adapter, parser_wrapper)
- Generate .cc files for each target
- Store in `fuzz/targets/`

### Component 3: Build Orchestrator
- Compile harnesses with clang++
- Add sanitizer flags
- Create executables in `build/`

### Component 4: Fuzz Executor
- Run libFuzzer on each target
- Collect crashes
- Manage corpus

### Component 5: Custom Mutator
- Implement LLVMFuzzerCustomMutator
- Protocol-aware mutations

### Component 6: Triage & Repro-Kit
- Minimize crashes
- Generate repro bundles
- Extract metadata

## API Examples

### Generate Fuzz Plan (API)
```bash
curl -X POST http://127.0.0.1:5000/api/fuzz-plan/generate/679cb872-c202-49c7-84a3-30ef32a34f94
```

### Get Fuzz Plan (API)
```bash
curl http://127.0.0.1:5000/api/fuzz-plan/679cb872-c202-49c7-84a3-30ef32a34f94
```

## File Structure

```
project/
├── scans/
│   └── 679cb872-c202-49c7-84a3-30ef32a34f94/
│       ├── artifacts/
│       │   └── cppcheck-report.xml
│       ├── static_findings.json          ← Module 1 output
│       └── fuzz/
│           └── fuzzplan.json             ← Module 2 Component 1 output
├── src/
│   ├── module1/
│   │   └── cppcheck_to_findings.py
│   └── fuzz_plan/
│       └── generator.py
├── templates/
│   └── fuzz_plan.html
└── static_findings.json                  ← Reference copy
```

## Troubleshooting

### "Static findings not found"
Run the converter first:
```bash
python convert_scan_to_findings.py 679cb872-c202-49c7-84a3-30ef32a34f94
```

### "Scan not found"
Make sure the scan directory exists:
```bash
ls scans/679cb872-c202-49c7-84a3-30ef32a34f94
```

### Flask app not running
```bash
python app.py
```

## Success Metrics

✅ **20 findings** → **9 targets** (55% reduction via deduplication)
✅ **Bug class inference** working (OOB, UAF, Integer-UB, etc.)
✅ **Priority scoring** working (17.55 for UAF, 16.2 for OOB)
✅ **Sanitizer selection** working (ASan for memory, UBSan for integer)
✅ **Web UI** beautiful and functional
✅ **API endpoints** working

## Ready for Component 2!

The fuzz plan is generated and visualized. Next, we'll implement the harness generator to create actual fuzzing code for each target.
