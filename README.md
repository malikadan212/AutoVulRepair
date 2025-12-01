# AutoVulRepair - Automated Vulnerability Detection and Fuzzing

Automated security workflow for C/C++ code: static analysis → fuzz plan generation → harness generation → build orchestration.

## Quick Start (Docker - Recommended)

### Prerequisites
- **Docker Desktop** only! Everything else is bundled.
  - Windows/macOS: https://www.docker.com/products/docker-desktop/
  - Linux: `sudo apt-get install docker.io docker-compose`

### One-Command Setup

```bash
docker-compose up
```

That's it! Open http://localhost:5000

The Docker container includes:
- ✅ Clang/LLVM (fuzzing compiler)
- ✅ Python and all dependencies
- ✅ Redis and Celery worker
- ✅ Everything configured and ready

**No manual installation of clang or other tools needed!**

See [USER_GUIDE.md](USER_GUIDE.md) for detailed instructions.

---

## Alternative: Manual Setup (For Development)

If you want to run without Docker:

### Prerequisites
- Python 3.8+
- Docker Desktop (for Redis only)
- Git
- **Fuzzing Compiler**:
  - **Linux**: `sudo apt-get install clang`
  - **macOS**: `brew install llvm`
  - **Windows**: Use WSL2 or Docker (recommended)

### Setup

1. **Activate Virtual Environment:**
```powershell
.venv\Scripts\Activate.ps1
```

2. **Install Dependencies:**
```powershell
pip install -r requirements.txt
```

3. **Configure Environment:**
Create a `.env` file with:
```
FLASK_SECRET_KEY=your-secret-key
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
REDIS_URL=redis://localhost:6379/0
SCANS_DIR=./scans
```

### Running the Application

1. **Start Redis (required for Celery):**
```powershell
docker-compose up -d
```

2. **Start Celery Worker (in a separate terminal):**
```powershell
python celery_worker.py
```

3. **Start Flask Application:**
```powershell
python app.py
```

4. **Access the application:**
Open your browser to `http://localhost:5000`

## Workflow

### Module 1: Static Analysis
1. Submit a GitHub repository URL or upload a ZIP file
2. Choose analysis tool (Cppcheck or CodeQL)
3. System automatically:
   - Clones/extracts the code
   - Runs static analysis
   - Generates `cppcheck-report.xml`
   - **Automatically converts to `static_findings.json`** (NEW!)
   - Displays vulnerabilities in the UI

### Module 2: Fuzz Plan Generation
1. Click "Generate Fuzz Plan" after scan completes
2. System analyzes `static_findings.json` and creates:
   - Fuzzing targets for critical vulnerabilities
   - Bug class categorization
   - Harness type recommendations
   - Priority rankings
3. Export fuzz plan as JSON, CSV, or Markdown

### Module 3: Harness Generation
1. Click "Generate Harnesses" from fuzz plan page
2. System creates:
   - Signature-aware C++ fuzzing harnesses
   - Proper parameter handling
   - LibFuzzer-compatible code
   - Build scripts and documentation
3. Download individual harnesses or ZIP archive

### Module 4: Build Orchestration
1. Click "Build Harnesses" to compile
2. System orchestrates:
   - Docker-based compilation
   - Sanitizer integration (ASan, UBSan, MSan)
   - Build verification
   - Error reporting

## Recent Improvements

### Automatic Static Findings Conversion
The system now automatically converts Cppcheck XML reports to `static_findings.json` after each scan completes. This eliminates the manual conversion step and ensures Module 2 can immediately generate fuzz plans.

**What changed:**
- Added automatic conversion in `src/queue/tasks.py`
- Runs after Cppcheck analysis completes
- Logs conversion status
- Gracefully handles conversion errors without failing the scan

**Manual conversion (if needed):**
```powershell
python convert_scan_to_findings.py <scan_id>
```

### Signature-Aware Harness Templates
All harness templates now support function signature information:
- Automatic parameter preparation
- Type-aware fuzzing
- Fallback for functions without signatures
- Improved code generation quality

## Project Structure

```
autovulrepair/
├── src/
│   ├── analysis/          # Static analysis tools (Cppcheck, CodeQL)
│   ├── fuzz_plan/         # Fuzz plan generation
│   ├── harness/           # Harness generation and templates
│   ├── build/             # Build orchestration
│   ├── models/            # Database models
│   ├── queue/             # Celery tasks
│   └── utils/             # Utilities and validation
├── templates/             # Flask HTML templates
├── tests/                 # Test suite
├── scans/                 # Scan data and artifacts
├── app.py                 # Flask application
├── celery_worker.py       # Celery worker
└── docker-compose.yml     # Redis configuration
```

## Testing

Run the test suite:
```powershell
pytest tests/
```

Run property-based tests:
```powershell
pytest tests/test_harness_generation_properties.py -v
```

## Troubleshooting

### Redis Connection Issues
If Celery can't connect to Redis:
1. Ensure Docker Desktop is running
2. Check Redis container: `docker ps`
3. Restart Redis: `docker-compose restart`

### Old Tasks in Queue
If you see errors about missing scans:
```powershell
docker exec -it autovulrepair-redis-1 redis-cli FLUSHALL
```

### Static Findings Not Generated
The conversion now happens automatically. If you still don't see `static_findings.json`:
1. Check Celery worker logs for conversion errors
2. Verify `cppcheck-report.xml` exists in `scans/<scan_id>/artifacts/`
3. Run manual conversion: `python convert_scan_to_findings.py <scan_id>`

## Architecture

The system follows a modular pipeline architecture:

1. **Module 1 (Detection):** Static analysis with Cppcheck/CodeQL
2. **Module 2 (Planning):** Fuzz plan generation from findings
3. **Module 3 (Generation):** Harness code generation
4. **Module 4 (Execution):** Build orchestration and compilation

Each module is independent and can be tested separately.

## Contributing

See `.kiro/specs/harness-parameter-passing/` for detailed design documentation and implementation tasks.

## License

[Your License Here]


## Windows Setup

### Option 1: WSL2 (Recommended)

WSL2 provides a full Linux environment on Windows and is the easiest way to run this tool.

1. **Install WSL2:**
```powershell
wsl --install
```

2. **Install Ubuntu from Microsoft Store** (if not auto-installed)

3. **Inside WSL2, install dependencies:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip clang git docker.io
```

4. **Clone and run the tool in WSL2**

### Option 2: Native Windows (Advanced)

Native Windows requires additional setup and may have compatibility issues.

**Requirements:**
1. Install LLVM from https://releases.llvm.org/
2. Install Visual Studio Build Tools
3. Run from "x64 Native Tools Command Prompt"

**Verification:**
```powershell
python verify_fuzzing_setup.py
```

If this fails, use WSL2 instead.

## Troubleshooting

### "No fuzzing compiler found"
Run the verification script:
```bash
python verify_fuzzing_setup.py
```

This will test your environment and provide specific installation instructions.

### Build failures on Windows
If you see errors like `'cstring' file not found`, your clang installation can't find the C++ standard library. Solutions:
1. Switch to WSL2 (recommended)
2. Install Visual Studio Build Tools
3. Run from Developer Command Prompt

### For more help
See [FUZZING_SETUP_GUIDE.md](FUZZING_SETUP_GUIDE.md) for detailed setup instructions.
