# AutoVulRepair - Implementation Guide
## What We Built and Where to Find It

This guide maps each feature to specific files for your presentation.

---

## **ITERATION 1: Web Application & Static Analysis**

### 1. Web Application Infrastructure

**File: `app.py`**
- Lines 1-50: Flask setup, security config (100MB upload limit)
- Lines 100-150: GitHub OAuth authentication
- Lines 200-300: Route handlers for scanning

**Show This Code:**
```python
# app.py - Flask setup
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Security: 100MB limit
```

**File: `src/models/scan.py`**
- Database models for storing scan records
- SQLAlchemy ORM for database operations

**File: `.env`**
- Configuration: GitHub OAuth credentials, Redis URL, secret keys

---

### 2. Authentication System

**File: `app.py` (lines 100-180)**
```python
# GitHub OAuth setup
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    ...
)

@app.route('/login')
def login():
    return github.authorize_redirect(redirect_uri)

@app.route('/auth')
def authorized():
    token = github.authorize_access_token()
    # Create user session
```

**Also supports public access** (no login required) - see `/no-login` route

---

### 3. File Upload Handling

**File: `app.py` (lines 600-800) - `/scan-public` route**

**Three input methods:**
1. **GitHub Repository URL**
2. **ZIP File Upload** 
3. **Code Snippet**

**File: `src/utils/validation.py`**
```python
def is_valid_github_url(url):
    # Validates GitHub URL format
    
def validate_zip_file(file):
    # Checks size, format, security
    
def safe_extract_zip(zip_path, extract_to, timeout=120):
    # Prevents path traversal attacks
    # Prevents zip bombs
```

**Security Features:**
- Path traversal protection (blocks `../` in ZIP files)
- Size limits (100MB max)
- Timeout protection (120s extraction limit)

---

### 4. Module 1: Static Analysis

**File: `src/analysis/cppcheck.py`**
```python
class CppcheckAnalyzer:
    def analyze(self, source_dir):
        # Runs Cppcheck on C/C++ code
        # Generates XML report
        # Returns vulnerabilities
```

**File: `src/analysis/codeql.py`**
- Alternative analyzer using CodeQL

**File: `src/module1/cppcheck_to_findings.py`**
```python
def convert_cppcheck_to_findings(xml_path, output_json):
    # Converts XML → static_findings.json
    # Standardizes vulnerability format
```

**Output: `scans/{scan_id}/static_findings.json`**
```json
{
  "findings": [
    {
      "file": "src/buffer.c",
      "line": 42,
      "severity": "error",
      "bug_class": "Buffer-Overflow",
      "message": "Array index out of bounds"
    }
  ]
}
```

---

### 5. Asynchronous Task Queue

**File: `src/queue/tasks.py`**
```python
from celery import Celery

celery_app = Celery('autovulrepair', broker='redis://localhost:6379/0')

@celery_app.task
def analyze_code(scan_id, analysis_tool):
    # Runs in background worker
    # Updates scan status in database
    # Generates static_findings.json
```

**File: `celery_worker.py`**
- Starts Celery worker process
- Processes queued analysis tasks

**File: `docker-compose.yml`**
```yaml
services:
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
```

**Why Celery?**
- Analysis takes 1-5 minutes
- User doesn't wait for completion
- Can handle multiple scans simultaneously

---

### 6. User Interface

**File: `templates/home.html`**
- Landing page with login options

**File: `templates/no_login_scan.html`**
- Public scan submission form

**File: `templates/scan_progress.html`**
- Real-time progress tracking with AJAX

**File: `templates/detailed_findings.html`**
- Vulnerability list with code context
- Severity badges, file locations

**File: `app.py` - `/api/scan-status/<scan_id>` route**
```python
@app.route('/api/scan-status/<scan_id>')
def api_scan_status(scan_id):
    scan = session_db.query(Scan).filter_by(id=scan_id).first()
    return jsonify({
        'status': scan.status,  # queued, running, completed, failed
        'vulnerabilities_count': len(scan.vulnerabilities_json)
    })
```

**JavaScript in templates:**
- Polls `/api/scan-status/` every 2 seconds
- Updates progress bar dynamically

---

### 7. Database Models

**File: `src/models/scan.py`**
```python
class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=True)  # NULL for public scans
    source_type = Column(String)  # 'repo_url', 'zip', 'code_snippet'
    repo_url = Column(String, nullable=True)
    analysis_tool = Column(String)  # 'cppcheck' or 'codeql'
    status = Column(String)  # 'queued', 'running', 'completed', 'failed'
    vulnerabilities_json = Column(JSON)
    patches_json = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
```

**Database: `scans.db` (SQLite)**
- Stores all scan records
- Persists across restarts

---

## **ITERATION 2: Fuzzing Pipeline & Dynamic Analysis**

### 1. Fuzz Plan Generation

**File: `src/fuzz_plan/generator.py`**
```python
class FuzzPlanGenerator:
    def __init__(self, static_findings_path, source_dir):
        # Loads static_findings.json
        
    def generate_fuzz_plan(self):
        # Analyzes each vulnerability
        # Infers bug class (OOB, UAF, Integer-UB)
        # Calculates priority score
        # Extracts function signatures
        # Selects sanitizers
        # Returns fuzz plan
```

**Key Features:**
- **Bug Class Inference:** Maps Cppcheck errors to fuzzing bug classes
- **Priority Scoring:** Ranks targets by severity + confidence
- **Signature Extraction:** Parses C/C++ to find function parameters
- **Sanitizer Selection:** ASan for OOB, UBSan for integer bugs, etc.

**File: `src/harness/signature_extractor.py`**
```python
def extract_function_signature(source_dir, file_path, function_name):
    # Uses regex to find function definition
    # Extracts return type, parameters
    # Returns signature dict
```

**Output: `scans/{scan_id}/fuzz/fuzzplan.json`**
```json
{
  "targets": [
    {
      "function_name": "parse_input",
      "file": "src/parser.c",
      "bug_class": "Buffer-Overflow",
      "priority": 95,
      "sanitizers": ["ASan", "UBSan"],
      "signature": {
        "return_type": "int",
        "parameters": [
          {"name": "buffer", "type": "char*"},
          {"name": "size", "type": "size_t"}
        ]
      }
    }
  ]
}
```

**Routes in `app.py`:**
- `/fuzz-plan/<scan_id>` - View fuzz plan
- `/api/fuzz-plan/generate/<scan_id>` - Generate plan
- `/api/fuzz-plan/<scan_id>/export/<format>` - Export as JSON/CSV/Markdown

---

### 2. Harness Generation

**File: `src/harness/generator.py`**
```python
class HarnessGenerator:
    def generate_all_harnesses(self, output_dir):
        for target in self.fuzz_plan['targets']:
            harness_code = self.generate_harness(target)
            # Saves to output_dir/{function}_harness.cc
```

**File: `src/harness/toolbox.py`**
- Contains 4 harness templates:
  1. **bytes_to_api** - Direct fuzzing with raw bytes
  2. **fdp_adapter** - FuzzedDataProvider for structured input
  3. **parser_wrapper** - For file parsers
  4. **api_sequence** - For API call sequences

**File: `src/harness/parameter_mapper.py`**
```python
def prepare_parameters(signature, data_source):
    # Maps function parameters to fuzzer input
    # Handles: int, char*, size_t, pointers, structs
    # Generates type-aware preparation code
```

**Example Generated Harness:**
```cpp
// parse_input_harness.cc
#include <stdint.h>
#include <stddef.h>

extern "C" int parse_input(char* buffer, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    
    // Prepare parameters
    char* buffer = (char*)Data;
    size_t size = Size;
    
    // Call target function
    parse_input(buffer, size);
    
    return 0;
}
```

**Routes in `app.py`:**
- `/harness-generation/<scan_id>` - View harnesses
- `/api/harness/generate/<scan_id>` - Generate harnesses
- `/api/harness/download/<scan_id>` - Download single harness
- `/api/harness/download-all/<scan_id>` - Download ZIP

---

### 3. Build Orchestration

**File: `src/build/orchestrator.py`**
```python
class BuildOrchestrator:
    def build_all_targets(self):
        for harness in harnesses:
            # Compile source files with fuzzing instrumentation
            # Patch main() to avoid conflicts
            # Link harness with source objects
            # Apply sanitizers
            # Generate executable
```

**Build Process:**
1. **Compile source:** `clang++ -c -fsanitize=fuzzer,address source.cpp`
2. **Patch main():** Rename to avoid linker conflicts
3. **Compile harness:** `clang++ -fsanitize=fuzzer,address harness.cc`
4. **Link:** `clang++ -o fuzz_target harness.o source.o`

**Sanitizers Applied:**
- **ASan** (AddressSanitizer) - Detects memory errors
- **UBSan** (UndefinedBehaviorSanitizer) - Detects undefined behavior
- **MSan** (MemorySanitizer) - Detects uninitialized memory
- **TSan** (ThreadSanitizer) - Detects data races

**Output: `scans/{scan_id}/build/`**
- Compiled fuzz targets (executables)
- Build log with success/failure status

**Routes in `app.py`:**
- `/build-orchestration/<scan_id>` - View build status
- `/api/build/start/<scan_id>` - Start build
- `/api/build/status/<scan_id>` - Check build progress
- `/api/build/log/<scan_id>` - Download build log

---

### 4. Fuzz Execution

**File: `src/fuzz_exec/executor.py`**
```python
class FuzzExecutor:
    def run_campaign(self, runtime_minutes=5, max_targets=None):
        for target in targets:
            # Execute: ./fuzz_target -max_total_time={runtime}
            # Monitor for crashes
            # Collect crash artifacts
            # Save results
```

**Execution:**
```bash
./parse_input_fuzz -max_total_time=300 -artifact_prefix=crashes/
```

**LibFuzzer Output:**
- Crash inputs saved to `crashes/crash-{hash}`
- Sanitizer reports (stack traces, error details)
- Coverage statistics

**Output: `scans/{scan_id}/fuzz/results/campaign_results.json`**
```json
{
  "targets": [
    {
      "name": "parse_input_fuzz",
      "status": "completed",
      "crashes_found": 3,
      "runtime_seconds": 300,
      "coverage": "45%"
    }
  ]
}
```

**Routes in `app.py`:**
- `/fuzz-execution/<scan_id>` - Fuzzing dashboard
- `/api/fuzz/start/<scan_id>` - Start campaign
- `/api/fuzz/results/<scan_id>` - Get results

---

### 5. Crash Triage

**File: `src/triage/analyzer.py`**
```python
class TriageAnalyzer:
    def analyze_crashes(self, campaign_results):
        for crash in crashes:
            # Classify crash type (SEGV, heap-buffer-overflow, etc.)
            # Assess severity (Critical/High/Medium/Low)
            # Evaluate exploitability
            # Calculate CVSS score
            # Deduplicate by stack trace
```

**Crash Classification:**
- **SEGV** - Segmentation fault
- **heap-buffer-overflow** - Heap overflow
- **stack-buffer-overflow** - Stack overflow
- **use-after-free** - UAF bug
- **integer-overflow** - Integer bug

**Severity Assessment:**
- **Critical:** Remote code execution potential
- **High:** Memory corruption, exploitable
- **Medium:** Denial of service
- **Low:** Minor issues

**Exploitability:**
- **Exploitable:** Direct control of PC/memory
- **Likely:** Partial control
- **Unlikely:** Limited impact

**Output: `scans/{scan_id}/fuzz/triage/triage_results.json`**
```json
{
  "crashes": [
    {
      "crash_id": "crash-a1b2c3",
      "target": "parse_input_fuzz",
      "crash_type": "heap-buffer-overflow",
      "severity": "Critical",
      "exploitability": "Exploitable",
      "cvss_score": 9.8,
      "stack_trace": "...",
      "input_file": "crashes/crash-a1b2c3"
    }
  ]
}
```

---

### 6. Reproduction Kits

**File: `src/repro/generator.py`**
```python
class ReproductionKitGenerator:
    def generate_kit(self, crash):
        # Creates standalone reproduction package
        # Includes: crash input, build script, instructions
```

**Kit Contents:**
- `crash_input` - The input that triggered the crash
- `build.sh` - Script to rebuild the target
- `reproduce.sh` - Script to reproduce the crash
- `README.md` - Instructions and analysis

---

## **Key Technologies Used**

### Backend:
- **Flask** - Web framework
- **SQLAlchemy** - Database ORM
- **Celery** - Task queue
- **Redis** - Message broker

### Analysis Tools:
- **Cppcheck** - Static analyzer
- **CodeQL** - Advanced static analyzer
- **Clang/LLVM** - Fuzzing compiler
- **LibFuzzer** - Fuzzing engine
- **Sanitizers** - Runtime error detection

### Infrastructure:
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration

---

## **Data Flow Summary**

```
User Input (GitHub/ZIP/Snippet)
    ↓
Module 1: Static Analysis (Cppcheck/CodeQL)
    ↓
static_findings.json
    ↓
Module 2.1: Fuzz Plan Generation
    ↓
fuzzplan.json
    ↓
Module 2.2: Harness Generation
    ↓
{function}_harness.cc files
    ↓
Module 2.3: Build Orchestration
    ↓
Compiled fuzz targets (executables)
    ↓
Module 2.4: Fuzz Execution
    ↓
campaign_results.json + crash artifacts
    ↓
Module 2.5: Crash Triage
    ↓
triage_results.json (with severity, exploitability, CVSS)
```

---

## **Quick Demo Script**

### For Iteration 1:
1. Open browser to `http://localhost:5000`
2. Click "Scan Without Login"
3. Enter GitHub URL: `https://github.com/example/vulnerable-c-code`
4. Select "Cppcheck"
5. Submit → Show scan progress page
6. Wait for completion → Show detailed findings
7. **Point to files:** `app.py` (routes), `src/analysis/cppcheck.py`, `templates/detailed_findings.html`

### For Iteration 2:
1. From detailed findings, click "Generate Fuzz Plan"
2. Show fuzz plan with targets, priorities, sanitizers
3. Click "Generate Harnesses" → Show generated C++ code
4. Click "Build Targets" → Show build log
5. Click "Start Fuzzing" → Configure 5 minutes runtime
6. Show campaign results with crashes
7. Show triage report with severity/exploitability
8. **Point to files:** `src/fuzz_plan/generator.py`, `src/harness/generator.py`, `src/build/orchestrator.py`, `src/fuzz_exec/executor.py`, `src/triage/analyzer.py`

---

## **Questions You Might Get**

**Q: How does the fuzzer know what inputs to try?**
A: LibFuzzer uses coverage-guided fuzzing. It mutates inputs and tracks which code paths are executed. Show `src/fuzz_exec/executor.py` and explain the `-max_total_time` parameter.

**Q: What if the code doesn't compile?**
A: Build orchestrator handles common issues like patching `main()` conflicts. Show `src/build/orchestrator.py` - the `patch_main_function()` method.

**Q: How do you prevent malicious ZIP uploads?**
A: Show `src/utils/validation.py` - `safe_extract_zip()` function that blocks path traversal and zip bombs.

**Q: Why use Celery instead of running analysis directly?**
A: Analysis takes 1-5 minutes. Celery allows async processing so users don't wait. Show `src/queue/tasks.py` and explain the `@celery_app.task` decorator.

**Q: How accurate is the exploitability assessment?**
A: Show `src/triage/analyzer.py` - explain it uses heuristics based on crash type, sanitizer output, and stack traces. Not perfect but gives good initial triage.

---

**END OF GUIDE**
