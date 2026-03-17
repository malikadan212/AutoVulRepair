# AutoVulRepair - Data Flow Diagrams (DFD)

## Document Information
- **Project**: AutoVulRepair - Automated Vulnerability Detection and Patching System
- **Version**: 1.0
- **Date**: December 7, 2025
- **Purpose**: Complete data flow analysis at multiple levels of abstraction

---

## Table of Contents
1. [DFD Overview](#dfd-overview)
2. [DFD Level 0 - Context Diagram](#dfd-level-0---context-diagram)
3. [DFD Level 1 - System Overview](#dfd-level-1---system-overview)
4. [DFD Level 2 - Detailed Processes](#dfd-level-2---detailed-processes)
5. [Data Dictionary](#data-dictionary)
6. [Data Stores](#data-stores)

---

## DFD Overview

### Purpose
Data Flow Diagrams (DFDs) show how data moves through the AutoVulRepair system, from external entities through processes to data stores. This document provides three levels of detail:

- **Level 0**: Context diagram showing the system as a single process
- **Level 1**: Major processes and data flows between them
- **Level 2**: Detailed sub-processes within each major process

### Notation
```
┌─────────────┐
│  External   │  = External Entity (user, system, service)
│   Entity    │
└─────────────┘

┌─────────────┐
│   Process   │  = Process (transforms data)
│     1.0     │
└─────────────┘

═══════════════  = Data Flow (labeled with data name)

║  Data Store ║  = Data Store (database, file system)
╚═════════════╝
```

---

## DFD Level 0 - Context Diagram

### System Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Context Diagram (Level 0)                            │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────┐
                    │  Developer   │
                    │   (User)     │
                    └──────┬───────┘
                           │
                           │ Source Code
                           │ (GitHub URL / ZIP / Snippet)
                           │
                           ▼
        ┌──────────────────────────────────────────────────┐
        │                                                   │
        │          AutoVulRepair System                    │
        │                                                   │
        │  - Analyzes code for vulnerabilities             │
        │  - Generates fuzzing harnesses                   │
        │  - Executes fuzzing campaigns                    │
        │  - Triages discovered crashes                    │
        │  - Generates AI-powered patches                  │
        │  - Validates patches in sandbox                  │
        │                                                   │
        └──────────────────────────────────────────────────┘
                           │
                           │ Analysis Results
                           │ (Vulnerabilities, Patches, Reports)
                           │
                           ▼
                    ┌──────────────┐
                    │  Developer   │
                    │   (User)     │
                    └──────────────┘


External Entities:
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│  GitHub OAuth    │────────▶│  AutoVulRepair   │◀────────│  Static Analysis │
│   Service        │  Auth   │     System       │  Results│     Tools        │
└──────────────────┘  Token  └──────────────────┘         └──────────────────┘
                                      │
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
                    ▼                 ▼                 ▼
            ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
            │  LLM Service │  │  Docker      │  │  Redis       │
            │  (OpenAI/    │  │  Engine      │  │  (Task       │
            │  Claude)     │  │              │  │  Queue)      │
            └──────────────┘  └──────────────┘  └──────────────┘
```

### External Entities

1. **Developer (User)**
   - **Inputs**: Source code (GitHub URL, ZIP file, code snippet), configuration
   - **Outputs**: Vulnerability reports, patches, triage results, metrics

2. **GitHub OAuth Service**
   - **Inputs**: Authentication requests
   - **Outputs**: OAuth tokens, user profile data

3. **Static Analysis Tools (Cppcheck, CodeQL)**
   - **Inputs**: Source code files
   - **Outputs**: XML/SARIF reports with vulnerabilities

4. **LLM Service (OpenAI/Anthropic)**
   - **Inputs**: Vulnerability context, RAG examples
   - **Outputs**: Generated patch code

5. **Docker Engine**
   - **Inputs**: Build commands, container configurations
   - **Outputs**: Compiled binaries, execution results

6. **Redis (Task Queue)**
   - **Inputs**: Task submissions
   - **Outputs**: Task results, queue status


---

## DFD Level 1 - System Overview

### Major Processes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Level 1 DFD - System Overview                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Developer   │
└──────┬───────┘
       │
       │ 1. Source Code Submission
       │    (repo_url, zip_file, code_snippet)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 1.0                                                 │
│  Scan Management                                             │
│  - Create scan record                                        │
│  - Validate input                                            │
│  - Extract/clone source code                                 │
│  - Queue analysis task                                       │
└─────────────────────────────────────────────────────────────┘
       │
       │ 2. Scan Record
       │    (scan_id, source_path, status)
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D1: scans.db (SQLite Database)                              ║
║  - Scan records                                              ║
║  - User sessions                                             ║
║  - Vulnerabilities (JSON)                                    ║
║  - Patches (JSON)                                            ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ 3. Source Files
       │    (C/C++ code files)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 2.0                                                 │
│  Static Analysis                                             │
│  - Run Cppcheck/CodeQL                                       │
│  - Parse XML/SARIF results                                   │
│  - Convert to static_findings.json                           │
│  - Store vulnerabilities                                     │
└─────────────────────────────────────────────────────────────┘
       │
       │ 4. static_findings.json
       │    (vulnerabilities, rule_ids, locations)
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/ (File System)                        ║
║  - source/          (extracted source code)                  ║
║  - artifacts/       (analysis reports)                       ║
║  - static_findings.json                                      ║
║  - fuzz/            (fuzzing artifacts)                      ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ 5. Vulnerability Data
       │    (findings with metadata)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.0                                                 │
│  Fuzz Plan Generation                                        │
│  - Load static findings                                      │
│  - Infer bug classes                                         │
│  - Calculate priorities                                      │
│  - Extract function signatures                               │
│  - Generate fuzzplan.json                                    │
└─────────────────────────────────────────────────────────────┘
       │
       │ 6. fuzzplan.json
       │    (targets, priorities, sanitizers)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 4.0                                                 │
│  Harness Generation                                          │
│  - Select harness types                                      │
│  - Generate C++ harness code                                 │
│  - Create build scripts                                      │
│  - Generate documentation                                    │
└─────────────────────────────────────────────────────────────┘
       │
       │ 7. Harness Files
       │    (fuzz_*.cc, build scripts)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 5.0                                                 │
│  Build Orchestration                                         │
│  - Compile source files                                      │
│  - Patch main() function                                     │
│  - Link harnesses with source                                │
│  - Apply sanitizers                                          │
│  - Generate build log                                        │
└─────────────────────────────────────────────────────────────┘
       │
       │ 8. Fuzz Target Binaries
       │    (executable files)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 6.0                                                 │
│  Fuzz Execution                                              │
│  - Execute LibFuzzer targets                                 │
│  - Monitor for crashes                                       │
│  - Collect crash artifacts                                   │
│  - Track coverage metrics                                    │
│  - Generate campaign_results.json                            │
└─────────────────────────────────────────────────────────────┘
       │
       │ 9. Crash Artifacts
       │    (crash files, sanitizer output)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.0                                                 │
│  Crash Triage                                                │
│  - Classify crash types                                      │
│  - Assess severity                                           │
│  - Evaluate exploitability                                   │
│  - Calculate CVSS scores                                     │
│  - Deduplicate crashes                                       │
│  - Generate triage_results.json                              │
└─────────────────────────────────────────────────────────────┘
       │
       │ 10. Triage Results
       │     (crash analysis, severity, exploitability)
       │
       ▼
┌──────────────┐
│  Developer   │
│  (Reports)   │
└──────────────┘


Supporting Processes:

┌─────────────────────────────────────────────────────────────┐
│  Process 8.0                                                 │
│  Task Queue Management (Celery + Redis)                      │
│  - Queue analysis tasks                                      │
│  - Distribute to workers                                     │
│  - Track task status                                         │
│  - Handle failures                                           │
└─────────────────────────────────────────────────────────────┘
       │
       │ Task Messages
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D3: Redis (In-Memory Data Store)                            ║
║  - Task queue                                                ║
║  - Task results                                              ║
║  - Session data                                              ║
╚═══════════════════════════════════════════════════════════════╝
```

### Data Flows Summary

| Flow # | From | To | Data | Description |
|--------|------|-----|------|-------------|
| 1 | Developer | Process 1.0 | Source Code | User submits code for analysis |
| 2 | Process 1.0 | D1 (scans.db) | Scan Record | Store scan metadata |
| 3 | D2 (File System) | Process 2.0 | Source Files | Load code for analysis |
| 4 | Process 2.0 | D2 (File System) | static_findings.json | Store analysis results |
| 5 | D2 (File System) | Process 3.0 | Vulnerability Data | Load findings for fuzz plan |
| 6 | Process 3.0 | D2 (File System) | fuzzplan.json | Store fuzz plan |
| 7 | Process 4.0 | D2 (File System) | Harness Files | Store generated harnesses |
| 8 | Process 5.0 | D2 (File System) | Fuzz Binaries | Store compiled targets |
| 9 | Process 6.0 | D2 (File System) | Crash Artifacts | Store discovered crashes |
| 10 | Process 7.0 | Developer | Triage Results | Return analysis results |


---

## DFD Level 2 - Detailed Processes

### Process 1.0 - Scan Management (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Process 1.0 - Scan Management (Level 2)                   │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Developer   │
└──────┬───────┘
       │
       │ Source Code Input
       │ (repo_url / zip_file / code_snippet)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 1.1                                                 │
│  Validate Input                                              │
│  - Check URL format (if GitHub)                              │
│  - Validate ZIP structure (if ZIP)                           │
│  - Check file size limits                                    │
│  - Sanitize filenames                                        │
│  - Detect path traversal attacks                             │
└─────────────────────────────────────────────────────────────┘
       │
       │ Validated Input
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 1.2                                                 │
│  Create Scan Record                                          │
│  - Generate UUID scan_id                                     │
│  - Set source_type (zip/repo_url/code_snippet)              │
│  - Set analysis_tool (cppcheck/codeql)                       │
│  - Set status = 'queued'                                     │
│  - Store user_id (if authenticated)                          │
│  - Set timestamps                                            │
└─────────────────────────────────────────────────────────────┘
       │
       │ Scan Record
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D1: scans.db                                                ║
║  Table: scans                                                ║
║  - id (UUID)                                                 ║
║  - user_id                                                   ║
║  - source_type                                               ║
║  - source_path                                               ║
║  - repo_url                                                  ║
║  - analysis_tool                                             ║
║  - status                                                    ║
║  - created_at                                                ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ scan_id
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 1.3                                                 │
│  Extract/Clone Source Code                                   │
│  - If GitHub: git clone to ./scans/{scan_id}/source         │
│  - If ZIP: extract to ./scans/{scan_id}/source              │
│  - If snippet: save to ./scans/{scan_id}/source/snippet.cpp │
│  - Create artifacts directory                                │
└─────────────────────────────────────────────────────────────┘
       │
       │ Source Files
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/                                      ║
║  - source/                                                   ║
║  - artifacts/                                                ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ scan_id, analysis_tool
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 1.4                                                 │
│  Queue Analysis Task                                         │
│  - Create Celery task                                        │
│  - Pass scan_id and analysis_tool                            │
│  - Publish to Redis queue                                    │
│  - Return task_id                                            │
│  - Fallback to sync if Redis unavailable                     │
└─────────────────────────────────────────────────────────────┘
       │
       │ Task Message
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D3: Redis                                                   ║
║  Queue: celery                                               ║
║  - Task: analyze_code(scan_id, analysis_tool)               ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ scan_id
       │
       ▼
┌──────────────┐
│  Developer   │
│  (Redirect   │
│  to progress)│
└──────────────┘
```

### Process 2.0 - Static Analysis (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Process 2.0 - Static Analysis (Level 2)                   │
└─────────────────────────────────────────────────────────────────────────────┘

║═══════════════════════════════════════════════════════════════║
║  D3: Redis Queue                                             ║
║  Task: analyze_code(scan_id, analysis_tool)                 ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Task Pickup
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 2.1                                                 │
│  Load Scan Data                                              │
│  - Query scan record from database                           │
│  - Get source_path and analysis_tool                         │
│  - Update status to 'running'                                │
│  - Commit to database                                        │
└─────────────────────────────────────────────────────────────┘
       │
       │ source_path, analysis_tool
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 2.2                                                 │
│  Execute Analysis Tool                                       │
│  - If cppcheck: run cppcheck with XML output                │
│  - If codeql: run codeql database create + analyze          │
│  - Set timeout (300 seconds)                                 │
│  - Capture stdout/stderr                                     │
│  - Generate report file                                      │
└─────────────────────────────────────────────────────────────┘
       │
       │ Analysis Report
       │ (XML for Cppcheck, SARIF for CodeQL)
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/artifacts/                            ║
║  - cppcheck-report.xml                                       ║
║  - codeql-results.sarif                                      ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Report File Path
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 2.3                                                 │
│  Parse Analysis Results                                      │
│  - Parse XML/SARIF format                                    │
│  - Extract vulnerabilities                                   │
│  - Map severity levels                                       │
│  - Extract file, line, rule_id                               │
│  - Create vulnerability objects                              │
└─────────────────────────────────────────────────────────────┘
       │
       │ Vulnerability List
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 2.4                                                 │
│  Convert to Standard Format                                  │
│  - Create static_findings.json structure                     │
│  - Add metadata (tool, timestamp, total_findings)            │
│  - Format findings array                                     │
│  - Add file_stem, function, priority_score                   │
│  - Save to file system                                       │
└─────────────────────────────────────────────────────────────┘
       │
       │ static_findings.json
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/static_findings.json                  ║
║  {                                                           ║
║    "tool": "cppcheck",                                       ║
║    "timestamp": "2025-12-07T...",                            ║
║    "total_findings": 15,                                     ║
║    "findings": [                                             ║
║      {                                                       ║
║        "rule_id": "bufferAccessOutOfBounds",                 ║
║        "file": "/source/test.cpp",                           ║
║        "line": 42,                                           ║
║        "severity": "error",                                  ║
║        "message": "Array index out of bounds",               ║
║        "function": "processData",                            ║
║        "file_stem": "test"                                   ║
║      }                                                       ║
║    ]                                                         ║
║  }                                                           ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Vulnerabilities, Patches
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 2.5                                                 │
│  Update Scan Record                                          │
│  - Set status = 'completed'                                  │
│  - Store vulnerabilities_json                                │
│  - Store patches_json                                        │
│  - Set artifacts_path                                        │
│  - Update updated_at timestamp                               │
│  - Commit to database                                        │
└─────────────────────────────────────────────────────────────┘
       │
       │ Updated Scan Record
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D1: scans.db                                                ║
║  UPDATE scans SET                                            ║
║    status = 'completed',                                     ║
║    vulnerabilities_json = [...],                             ║
║    patches_json = [...],                                     ║
║    artifacts_path = './scans/{scan_id}/artifacts'            ║
║  WHERE id = scan_id                                          ║
╚═══════════════════════════════════════════════════════════════╝
```

### Process 3.0 - Fuzz Plan Generation (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  Process 3.0 - Fuzz Plan Generation (Level 2)                │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Developer   │
│  (Click      │
│  "Generate   │
│  Fuzz Plan") │
└──────┬───────┘
       │
       │ scan_id
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.1                                                 │
│  Load Static Findings                                        │
│  - Read static_findings.json                                 │
│  - Validate JSON structure                                   │
│  - Extract findings array                                    │
│  - Check for required fields                                 │
└─────────────────────────────────────────────────────────────┘
       │
       │ Findings List
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.2                                                 │
│  Infer Bug Classes                                           │
│  - Map rule_id to bug class                                  │
│  - Use BUG_CLASS_MAP dictionary                              │
│  - Assign: OOB, UAF, Integer-UB, Null-Deref, etc.          │
│  - Default to 'Unknown' if not mapped                        │
└─────────────────────────────────────────────────────────────┘
       │
       │ Findings with Bug Classes
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.3                                                 │
│  Calculate Priority Scores                                   │
│  - Base score from severity                                  │
│  - Apply confidence boost                                    │
│  - Apply bug class boost                                     │
│  - Apply CWE boost                                           │
│  - Apply location boost                                      │
│  - Formula: priority = base × conf × bug × cwe × loc        │
└─────────────────────────────────────────────────────────────┘
       │
       │ Findings with Priorities
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.4                                                 │
│  Deduplicate Targets                                         │
│  - Group by <file_stem>::<function>                          │
│  - Keep highest priority per group                           │
│  - Allow multiple bug classes per function (max 3)           │
│  - Create unique target_id                                   │
└─────────────────────────────────────────────────────────────┘
       │
       │ Deduplicated Targets
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.5                                                 │
│  Extract Function Signatures                                 │
│  - Read source files                                         │
│  - Parse C++ function declarations                           │
│  - Extract return type, parameters                           │
│  - Store signature metadata                                  │
│  - Mark extraction status                                    │
└─────────────────────────────────────────────────────────────┘
       │
       │ Targets with Signatures
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.6                                                 │
│  Select Sanitizers and Seeds                                 │
│  - Map bug class to sanitizers (ASan, UBSan, etc.)          │
│  - Select seed directories                                   │
│  - Select fuzzing dictionaries                               │
│  - Infer harness type                                        │
└─────────────────────────────────────────────────────────────┘
       │
       │ Complete Target Metadata
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 3.7                                                 │
│  Generate Fuzz Plan                                          │
│  - Create fuzzplan.json structure                            │
│  - Add metadata (version, timestamp, totals)                 │
│  - Add targets array                                         │
│  - Calculate bug class breakdown                             │
│  - Sort targets by priority                                  │
│  - Apply max_targets limit (100)                             │
│  - Save to file system                                       │
└─────────────────────────────────────────────────────────────┘
       │
       │ fuzzplan.json
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/fuzz/fuzzplan.json                    ║
║  {                                                           ║
║    "version": "1.0",                                         ║
║    "generated_at": "2025-12-07T...",                         ║
║    "source": "./scans/{scan_id}/static_findings.json",       ║
║    "targets": [                                              ║
║      {                                                       ║
║        "target_id": "test_processData",                      ║
║        "function_name": "processData",                       ║
║        "bug_class": "OOB",                                   ║
║        "priority": 9.5,                                      ║
║        "sanitizers": ["address", "undefined"],               ║
║        "harness_type": "bytes_to_api",                       ║
║        "function_signature": {...}                           ║
║      }                                                       ║
║    ],                                                        ║
║    "metadata": {                                             ║
║      "total_findings": 15,                                   ║
║      "deduplicated_targets": 8,                              ║
║      "bug_class_breakdown": {"OOB": 3, "UAF": 2, ...}       ║
║    }                                                         ║
║  }                                                           ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Fuzz Plan
       │
       ▼
┌──────────────┐
│  Developer   │
│  (View Plan) │
└──────────────┘
```


### Process 4.0 - Harness Generation (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  Process 4.0 - Harness Generation (Level 2)                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Developer   │
│  (Click      │
│  "Generate   │
│  Harnesses") │
└──────┬───────┘
       │
       │ scan_id
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 4.1                                                 │
│  Load Fuzz Plan                                              │
│  - Read fuzzplan.json                                        │
│  - Validate structure                                        │
│  - Extract targets array                                     │
└─────────────────────────────────────────────────────────────┘
       │
       │ Targets List
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 4.2                                                 │
│  Select Harness Type                                         │
│  - For each target:                                          │
│    - Check harness_type field                                │
│    - Use toolbox selection logic                             │
│    - Choose: bytes_to_api, fdp_adapter,                      │
│      parser_wrapper, or api_sequence                         │
└─────────────────────────────────────────────────────────────┘
       │
       │ Target with Harness Type
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 4.3                                                 │
│  Generate Harness Code                                       │
│  - Load template for harness type                            │
│  - Substitute function name                                  │
│  - Add function signature if available                       │
│  - Add bug class hints                                       │
│  - Add sanitizer comments                                    │
│  - Format code with proper indentation                       │
└─────────────────────────────────────────────────────────────┘
       │
       │ Harness Code (C++)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 4.4                                                 │
│  Create Harness File                                         │
│  - Generate filename: fuzz_<file_stem>_<function>.cc        │
│  - Write code to file                                        │
│  - Set file permissions                                      │
│  - Store metadata                                            │
└─────────────────────────────────────────────────────────────┘
       │
       │ Harness File
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/fuzz/harnesses/                       ║
║  - fuzz_test_processData.cc                                  ║
║  - fuzz_test_parseInput.cc                                   ║
║  - fuzz_test_handleBuffer.cc                                 ║
║  - ...                                                       ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Harness Metadata
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 4.5                                                 │
│  Generate Build Script                                       │
│  - Create build_harnesses.sh                                 │
│  - Add compilation commands for each harness                 │
│  - Include sanitizer flags                                   │
│  - Add linking commands                                      │
│  - Make script executable                                    │
└─────────────────────────────────────────────────────────────┘
       │
       │ Build Script
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 4.6                                                 │
│  Generate Documentation                                      │
│  - Create README.md                                          │
│  - Add harness overview                                      │
│  - Add build instructions                                    │
│  - Add usage examples                                        │
│  - Create .metadata.json                                     │
└─────────────────────────────────────────────────────────────┘
       │
       │ Documentation Files
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/fuzz/harnesses/                       ║
║  - build_harnesses.sh                                        ║
║  - README.md                                                 ║
║  - .metadata.json                                            ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Generation Complete
       │
       ▼
┌──────────────┐
│  Developer   │
│  (View/      │
│  Download)   │
└──────────────┘
```

### Process 5.0 - Build Orchestration (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  Process 5.0 - Build Orchestration (Level 2)                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Developer   │
│  (Click      │
│  "Build      │
│  Targets")   │
└──────┬───────┘
       │
       │ scan_id
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 5.1                                                 │
│  Detect Compiler                                             │
│  - Check for clang++ (LibFuzzer)                            │
│  - Check for afl-clang-fast++ (AFL++)                       │
│  - Determine if running in Docker                            │
│  - Set compiler path and flags                               │
└─────────────────────────────────────────────────────────────┘
       │
       │ Compiler Info
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 5.2                                                 │
│  Patch Source Files                                          │
│  - Read source files                                         │
│  - Wrap main() with preprocessor guards                      │
│  - Replace deprecated functions (gets → fgets)               │
│  - Write patched files back                                  │
└─────────────────────────────────────────────────────────────┘
       │
       │ Patched Source
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 5.3                                                 │
│  Compile Source Object File                                  │
│  - Compile source with -c flag                               │
│  - Add -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION           │
│  - Apply sanitizers                                          │
│  - Generate test_source.o                                    │
│  - Store in build directory                                  │
└─────────────────────────────────────────────────────────────┘
       │
       │ Source Object File
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/build/                                ║
║  - test_source.o                                             ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Object File Path
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 5.4                                                 │
│  Build Each Harness                                          │
│  - For each harness file:                                    │
│    - Compile harness with fuzzing instrumentation            │
│    - Link with source object file                            │
│    - Apply sanitizers (ASan, UBSan, etc.)                    │
│    - Generate executable                                     │
│    - Capture build output                                    │
│    - Handle errors                                           │
└─────────────────────────────────────────────────────────────┘
       │
       │ Build Results
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 5.5                                                 │
│  Generate Build Log                                          │
│  - Create .build_log.json                                    │
│  - Store build results for each target                       │
│  - Include: status, time, command, errors                    │
│  - Calculate success/failure counts                          │
│  - Add timestamp                                             │
└─────────────────────────────────────────────────────────────┘
       │
       │ Build Log
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/build/                                ║
║  - fuzz_test_processData (executable)                        ║
║  - fuzz_test_parseInput (executable)                         ║
║  - .build_log.json                                           ║
║  {                                                           ║
║    "timestamp": "2025-12-07T...",                            ║
║    "total_targets": 8,                                       ║
║    "successful": 6,                                          ║
║    "failed": 2,                                              ║
║    "builds": [                                               ║
║      {                                                       ║
║        "target_name": "fuzz_test_processData",               ║
║        "status": "success",                                  ║
║        "build_time": 3.45,                                   ║
║        "command": "clang++ -fsanitize=fuzzer,address...",    ║
║        "output_path": "./build/fuzz_test_processData"        ║
║      }                                                       ║
║    ]                                                         ║
║  }                                                           ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Build Complete
       │
       ▼
┌──────────────┐
│  Developer   │
│  (View Build │
│  Results)    │
└──────────────┘
```

### Process 6.0 - Fuzz Execution (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Process 6.0 - Fuzz Execution (Level 2)                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Developer   │
│  (Click      │
│  "Start      │
│  Fuzzing")   │
└──────┬───────┘
       │
       │ scan_id, runtime_minutes
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 6.1                                                 │
│  Find Fuzz Targets                                           │
│  - List files in build directory                             │
│  - Filter executables starting with "fuzz_"                  │
│  - Check execute permissions                                 │
│  - Create target list                                        │
└─────────────────────────────────────────────────────────────┘
       │
       │ Target List
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 6.2                                                 │
│  Create Crash Directories                                    │
│  - For each target:                                          │
│    - Create ./fuzz/crashes/{target_name}/                    │
│    - Set permissions                                         │
└─────────────────────────────────────────────────────────────┘
       │
       │ Crash Directories
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 6.3                                                 │
│  Execute Fuzz Target                                         │
│  - For each target:                                          │
│    - Build LibFuzzer command                                 │
│    - Set max_total_time                                      │
│    - Set artifact_prefix                                     │
│    - Execute in subprocess                                   │
│    - Capture stdout/stderr                                   │
│    - Monitor for timeout                                     │
└─────────────────────────────────────────────────────────────┘
       │
       │ Fuzzer Output
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 6.4                                                 │
│  Parse Fuzzer Statistics                                     │
│  - Extract coverage (cov:)                                   │
│  - Extract corpus size (corp:)                               │
│  - Extract exec/s                                            │
│  - Extract feature count (ft:)                               │
│  - Store statistics                                          │
└─────────────────────────────────────────────────────────────┘
       │
       │ Statistics
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 6.5                                                 │
│  Collect Crash Artifacts                                     │
│  - Scan crash directory                                      │
│  - Find files: crash-*, leak-*, timeout-*                    │
│  - Get file size and path                                    │
│  - Create crash metadata                                     │
└─────────────────────────────────────────────────────────────┘
       │
       │ Crash List
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/fuzz/crashes/{target}/                ║
║  - crash-0a1b2c3d4e5f                                        ║
║  - crash-1f2e3d4c5b6a                                        ║
║  - leak-7g8h9i0j1k2l                                         ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Execution Results
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 6.6                                                 │
│  Generate Campaign Results                                   │
│  - Create campaign_results.json                              │
│  - Add timestamp and metadata                                │
│  - Add results for each target                               │
│  - Include: status, runtime, crashes, stats                  │
│  - Calculate totals                                          │
│  - Save to file system                                       │
└─────────────────────────────────────────────────────────────┘
       │
       │ campaign_results.json
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/fuzz/results/campaign_results.json    ║
║  {                                                           ║
║    "timestamp": "2025-12-07T...",                            ║
║    "runtime_minutes": 5,                                     ║
║    "total_targets": 6,                                       ║
║    "total_time": 1823.45,                                    ║
║    "results": [                                              ║
║      {                                                       ║
║        "target": "fuzz_test_processData",                    ║
║        "status": "completed",                                ║
║        "runtime": 302.15,                                    ║
║        "crashes_found": 3,                                   ║
║        "crashes": [                                          ║
║          {                                                   ║
║            "filename": "crash-0a1b2c3d",                     ║
║            "size": 128,                                      ║
║            "path": "./fuzz/crashes/..."                      ║
║          }                                                   ║
║        ],                                                    ║
║        "stats": {                                            ║
║          "coverage": "245",                                  ║
║          "corpus": "89/12345b"                               ║
║        }                                                     ║
║      }                                                       ║
║    ]                                                         ║
║  }                                                           ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Campaign Complete
       │
       ▼
┌──────────────┐
│  Developer   │
│  (View       │
│  Results)    │
└──────────────┘
```


### Process 7.0 - Crash Triage (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Process 7.0 - Crash Triage (Level 2)                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Developer   │
│  (Click      │
│  "Analyze    │
│  Crashes")   │
└──────┬───────┘
       │
       │ scan_id
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.1                                                 │
│  Load Campaign Results                                       │
│  - Read campaign_results.json                                │
│  - Extract results array                                     │
│  - Get crash artifacts for each target                       │
└─────────────────────────────────────────────────────────────┘
       │
       │ Campaign Results
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.2                                                 │
│  Extract Crash Type                                          │
│  - For each crash:                                           │
│    - Parse filename (crash-*, leak-*, timeout-*)             │
│    - Parse sanitizer output                                  │
│    - Identify: Heap Buffer Overflow, Stack Buffer           │
│      Overflow, UAF, Double Free, Null Deref, etc.           │
└─────────────────────────────────────────────────────────────┘
       │
       │ Crash with Type
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.3                                                 │
│  Assess Severity                                             │
│  - Map crash type to severity                                │
│  - Critical: Heap/Stack Buffer Overflow, UAF, Double Free   │
│  - High: Stack Overflow, Null Deref, Memory Corruption      │
│  - Medium: Memory Leak, Timeout                              │
│  - Low: Other                                                │
└─────────────────────────────────────────────────────────────┘
       │
       │ Crash with Severity
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.4                                                 │
│  Assess Exploitability                                       │
│  - Map crash type to exploitability                          │
│  - Exploitable: Heap/Stack Overflow, UAF, Double Free       │
│  - Likely Exploitable: Stack Overflow, Memory Corruption    │
│  - Unlikely Exploitable: Memory Leak, Timeout, Null Deref   │
└─────────────────────────────────────────────────────────────┘
       │
       │ Crash with Exploitability
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.5                                                 │
│  Extract Stack Trace                                         │
│  - Parse sanitizer output                                    │
│  - Find stack trace markers (#0, #1, #2, ...)               │
│  - Extract top 10 frames                                     │
│  - Parse: frame number, address, function, file, line       │
└─────────────────────────────────────────────────────────────┘
       │
       │ Stack Trace
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.6                                                 │
│  Calculate CVSS Score                                        │
│  - Base score from severity                                  │
│  - Apply exploitability modifier                             │
│  - Formula: CVSS = min(10, base × exploit + (1-exploit)×2)  │
│  - Round to 1 decimal place                                  │
└─────────────────────────────────────────────────────────────┘
       │
       │ CVSS Score
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.7                                                 │
│  Deduplicate Crashes                                         │
│  - Create signature from crash type + top 3 stack frames    │
│  - Group crashes by signature                                │
│  - Keep first occurrence                                     │
│  - Mark duplicates                                           │
└─────────────────────────────────────────────────────────────┘
       │
       │ Unique Crashes
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Process 7.8                                                 │
│  Generate Triage Report                                      │
│  - Create triage_results.json                                │
│  - Add summary statistics                                    │
│  - Add crash analyses array                                  │
│  - Calculate counts by severity                              │
│  - Calculate counts by exploitability                        │
│  - Add timestamp                                             │
│  - Save to file system                                       │
└─────────────────────────────────────────────────────────────┘
       │
       │ triage_results.json
       │
       ▼
║═══════════════════════════════════════════════════════════════║
║  D2: ./scans/{scan_id}/fuzz/triage/triage_results.json       ║
║  {                                                           ║
║    "timestamp": "2025-12-07T...",                            ║
║    "scan_dir": "./scans/{scan_id}",                          ║
║    "summary": {                                              ║
║      "total_crashes": 8,                                     ║
║      "by_severity": {                                        ║
║        "Critical": 3,                                        ║
║        "High": 2,                                            ║
║        "Medium": 2,                                          ║
║        "Low": 1                                              ║
║      },                                                      ║
║      "by_type": {                                            ║
║        "Heap Buffer Overflow": 2,                            ║
║        "Use After Free": 1,                                  ║
║        "Null Pointer Dereference": 2,                        ║
║        "Memory Leak": 2,                                     ║
║        "Timeout": 1                                          ║
║      },                                                      ║
║      "by_exploitability": {                                  ║
║        "High": 3,                                            ║
║        "Medium": 2,                                          ║
║        "Low": 3                                              ║
║      }                                                       ║
║    },                                                        ║
║    "crashes": [                                              ║
║      {                                                       ║
║        "id": "crash_fuzz_test_processData_0a1b2c3d",         ║
║        "target": "fuzz_test_processData",                    ║
║        "crash_file": "crash-0a1b2c3d4e5f",                   ║
║        "crash_type": "Heap Buffer Overflow",                 ║
║        "severity": "Critical",                               ║
║        "exploitability": "Exploitable",                      ║
║        "cvss_score": 9.0,                                    ║
║        "stack_trace": [                                      ║
║          "#0 0x12345678 in processData test.cpp:42",         ║
║          "#1 0x23456789 in main test.cpp:100"                ║
║        ],                                                    ║
║        "root_cause": "SUMMARY: AddressSanitizer: heap-buffer-overflow"║
║      }                                                       ║
║    ]                                                         ║
║  }                                                           ║
╚═══════════════════════════════════════════════════════════════╝
       │
       │ Triage Results
       │
       ▼
┌──────────────┐
│  Developer   │
│  (View       │
│  Dashboard)  │
└──────────────┘
```

---

## Data Dictionary

### Data Elements

| Data Element | Description | Type | Format | Source | Destination |
|--------------|-------------|------|--------|--------|-------------|
| **scan_id** | Unique scan identifier | String | UUID v4 | System generated | All processes |
| **source_code** | User-submitted code | Binary/Text | ZIP/Git/Text | Developer | Process 1.0 |
| **repo_url** | GitHub repository URL | String | URL | Developer | Process 1.0 |
| **source_type** | Type of source submission | Enum | zip/repo_url/code_snippet | Developer | Process 1.0 |
| **analysis_tool** | Static analysis tool | Enum | cppcheck/codeql | Developer | Process 2.0 |
| **scan_status** | Current scan state | Enum | queued/running/completed/failed | Process 1.0 | D1 (scans.db) |
| **static_findings.json** | Standardized vulnerability report | JSON | Custom schema | Process 2.0 | D2 (File System) |
| **vulnerabilities** | List of discovered vulnerabilities | Array | JSON objects | Process 2.0 | D1 (scans.db) |
| **rule_id** | Analysis tool rule identifier | String | Tool-specific | Process 2.0 | static_findings.json |
| **severity** | Vulnerability severity | Enum | error/warning/style/information | Process 2.0 | static_findings.json |
| **file_path** | Source file location | String | Absolute path | Process 2.0 | static_findings.json |
| **line_number** | Line number of vulnerability | Integer | 1-N | Process 2.0 | static_findings.json |
| **bug_class** | Inferred bug classification | Enum | OOB/UAF/Integer-UB/Null-Deref/etc | Process 3.0 | fuzzplan.json |
| **priority_score** | Calculated priority | Float | 0.0-10.0 | Process 3.0 | fuzzplan.json |
| **fuzzplan.json** | Fuzzing campaign plan | JSON | Custom schema | Process 3.0 | D2 (File System) |
| **fuzz_target** | Fuzzing target metadata | Object | JSON object | Process 3.0 | fuzzplan.json |
| **function_signature** | Extracted function signature | Object | JSON object | Process 3.0 | fuzzplan.json |
| **sanitizers** | List of sanitizers to apply | Array | Strings | Process 3.0 | fuzzplan.json |
| **harness_type** | Type of harness template | Enum | bytes_to_api/fdp_adapter/parser_wrapper/api_sequence | Process 4.0 | Harness file |
| **harness_code** | Generated C++ harness code | Text | C++ source | Process 4.0 | D2 (File System) |
| **build_command** | Compilation command | String | Shell command | Process 5.0 | Build log |
| **build_status** | Build result | Enum | success/error/timeout | Process 5.0 | Build log |
| **fuzz_binary** | Compiled fuzz target | Binary | Executable | Process 5.0 | D2 (File System) |
| **runtime_minutes** | Fuzzing duration per target | Integer | 1-60 | Developer | Process 6.0 |
| **crash_artifact** | Crash input file | Binary | Raw bytes | Process 6.0 | D2 (File System) |
| **sanitizer_output** | Sanitizer error message | Text | Plain text | Process 6.0 | campaign_results.json |
| **coverage** | Code coverage metric | String | Number | Process 6.0 | campaign_results.json |
| **campaign_results.json** | Fuzzing campaign results | JSON | Custom schema | Process 6.0 | D2 (File System) |
| **crash_type** | Type of crash | Enum | Heap Buffer Overflow/UAF/etc | Process 7.0 | triage_results.json |
| **exploitability** | Exploitability assessment | Enum | Exploitable/Likely/Unlikely | Process 7.0 | triage_results.json |
| **cvss_score** | CVSS vulnerability score | Float | 0.0-10.0 | Process 7.0 | triage_results.json |
| **stack_trace** | Crash stack trace | Array | Strings | Process 7.0 | triage_results.json |
| **triage_results.json** | Crash triage analysis | JSON | Custom schema | Process 7.0 | D2 (File System) |

---

## Data Stores

### D1: scans.db (SQLite Database)

**Purpose**: Persistent storage for scan metadata and results

**Schema**:
```sql
CREATE TABLE scans (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36),
    source_type VARCHAR(20) NOT NULL,
    source_path TEXT,
    repo_url TEXT,
    analysis_tool VARCHAR(20) NOT NULL DEFAULT 'cppcheck',
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    artifacts_path TEXT,
    vulnerabilities_json JSON,
    patches_json JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Access Patterns**:
- **Write**: Process 1.0 (create), Process 2.0 (update)
- **Read**: All processes (query scan data)
- **Update**: Process 2.0 (status, results)

**Data Retention**: Indefinite (user-managed)

---

### D2: ./scans/{scan_id}/ (File System)

**Purpose**: Storage for scan artifacts, source code, and analysis results

**Directory Structure**:
```
./scans/{scan_id}/
├── source/                      # Extracted source code
│   ├── test.cpp
│   ├── test.h
│   └── ...
├── artifacts/                   # Analysis tool outputs
│   ├── cppcheck-report.xml
│   └── codeql-results.sarif
├── static_findings.json         # Standardized findings
├── fuzz/                        # Fuzzing artifacts
│   ├── fuzzplan.json            # Fuzz plan
│   ├── harnesses/               # Generated harnesses
│   │   ├── fuzz_test_processData.cc
│   │   ├── build_harnesses.sh
│   │   ├── README.md
│   │   └── .metadata.json
│   ├── results/                 # Fuzzing results
│   │   └── campaign_results.json
│   ├── crashes/                 # Crash artifacts
│   │   ├── fuzz_test_processData/
│   │   │   ├── crash-0a1b2c3d
│   │   │   └── leak-1f2e3d4c
│   │   └── ...
│   └── triage/                  # Triage analysis
│       └── triage_results.json
└── build/                       # Compiled binaries
    ├── fuzz_test_processData
    ├── test_source.o
    └── .build_log.json
```

**Access Patterns**:
- **Write**: All processes (create artifacts)
- **Read**: All processes (load artifacts)
- **Delete**: Cleanup process (after retention period)

**Data Retention**: 30 days minimum

---

### D3: Redis (In-Memory Data Store)

**Purpose**: Task queue and result backend for Celery

**Data Structures**:
```
# Task Queue
celery:queue:default = [
    "analyze_code(scan_id='abc123', analysis_tool='cppcheck')",
    ...
]

# Task Results
celery-task-meta-{task_id} = {
    "status": "SUCCESS",
    "result": {"status": "completed", "vulnerabilities": 15},
    "traceback": null,
    "children": []
}

# Session Data (optional)
session:{session_id} = {
    "user_id": "user123",
    "github_token": "...",
    "scans": {...}
}
```

**Access Patterns**:
- **Write**: Process 1.0 (queue tasks), Process 2.0 (store results)
- **Read**: Celery workers (consume tasks), Application (check status)
- **Delete**: Automatic (TTL-based expiration)

**Data Retention**: 24 hours (configurable)

---

## Conclusion

This Data Flow Diagram document provides three levels of detail:

✅ **Level 0 (Context)**: System as a single process with external entities
✅ **Level 1 (Overview)**: 7 major processes with data flows between them
✅ **Level 2 (Detailed)**: Sub-processes within each major process

The DFDs show:
- How data enters the system (source code from developer)
- How data is transformed (analysis, fuzzing, triage)
- Where data is stored (database, file system, Redis)
- How data flows between processes
- What data is returned to the user (reports, results)

All diagrams are based on the actual implementation in the AutoVulRepair project, with no hallucinated features or processes.

