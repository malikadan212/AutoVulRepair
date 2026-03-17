# AutoVulRepair - Consolidated Use Cases

## Document Information
- **Project**: AutoVulRepair - Automated Vulnerability Detection and Patching System
- **Version**: 1.0
- **Date**: 2024-01-XX
- **Primary Actor**: Developer
- **Total Use Cases**: 10 (Consolidated from 80+ detailed use cases)

---

## Table of Contents
1. [UC-01: Authenticate and Manage Account](#uc-01-authenticate-and-manage-account)
2. [UC-02: Submit Code for Security Analysis](#uc-02-submit-code-for-security-analysis)
3. [UC-03: Generate and Execute Fuzzing Campaign](#uc-03-generate-and-execute-fuzzing-campaign)
4. [UC-04: Generate AI-Powered Vulnerability Patches](#uc-04-generate-ai-powered-vulnerability-patches)
5. [UC-05: Validate Patches in Sandbox Environment](#uc-05-validate-patches-in-sandbox-environment)
6. [UC-06: Configure CI/CD Pipeline Integration](#uc-06-configure-cicd-pipeline-integration)
7. [UC-07: Monitor System Performance and Metrics](#uc-07-monitor-system-performance-and-metrics)
8. [UC-08: Review and Export Analysis Results](#uc-08-review-and-export-analysis-results)
9. [UC-09: Manage Automated Workflows](#uc-09-manage-automated-workflows)
10. [UC-10: Triage and Analyze Discovered Vulnerabilities](#uc-10-triage-and-analyze-discovered-vulnerabilities)

---

## UC-01: Authenticate and Manage Account

### Use Case Name
Authenticate and Manage Account

### Scope
AutoVulRepair System

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants to securely access the system and manage their account settings
2. System Administrator wants to ensure secure authentication and user management
3. Organization wants to track user activity and maintain audit logs

### Preconditions
1. The system must be operational and accessible
2. For GitHub OAuth: Developer must have a valid GitHub account
3. For API access: Developer must have generated API keys

### Postconditions
1. Developer is successfully authenticated and has access to the system
2. User session is created and stored securely
3. User activity is logged for audit purposes
4. API keys are securely generated and stored (if requested)

### Main Success Scenario
1. Developer navigates to the AutoVulRepair system homepage
2. System displays login options (GitHub OAuth or Public Access)
3. Developer selects GitHub OAuth login
4. System redirects to GitHub authorization page
5. Developer authorizes the application
6. GitHub returns authorization token to the system
7. System validates the token and fetches user profile
8. System creates user session and stores user data
9. System redirects Developer to personal dashboard
10. Developer views their dashboard with scan history and statistics
11. Developer can generate API keys for programmatic access
12. System displays API key once and stores hashed version
13. Developer can revoke API keys when needed
14. Developer can logout to terminate session

### Extensions
**3a. Developer chooses Public Access (no authentication):**
- 3a.1. System loads public scanning interface
- 3a.2. Developer can submit code for analysis without login
- 3a.3. No scan history or dashboard access available
- 3a.4. Use case continues at UC-02

**5a. Developer denies authorization:**
- 5a.1. GitHub returns error to system
- 5a.2. System displays authentication failed message
- 5a.3. System redirects to homepage
- 5a.4. Use case ends

**6a. GitHub OAuth service is unavailable:**
- 6a.1. System detects connection timeout
- 6a.2. System displays service unavailable message
- 6a.3. System suggests trying public access or retry later
- 6a.4. Use case ends

**8a. Database error during session creation:**
- 8a.1. System logs error details
- 8a.2. System displays generic error message
- 8a.3. System cleans up partial session data
- 8a.4. Use case ends

**11a. API key generation fails:**
- 11a.1. System logs error
- 11a.2. System displays error message to Developer
- 11a.3. Developer can retry generation
- 11a.4. Use case continues at step 11

**12a. Session expires during use:**
- 12a.1. System detects expired session on next request
- 12a.2. System invalidates session
- 12a.3. System redirects to login page
- 12a.4. Use case restarts at step 1

### Special Requirements
- SR-1: GitHub OAuth must use secure HTTPS connections
- SR-2: API keys must be cryptographically secure (256-bit minimum)
- SR-3: Session timeout must be configurable (default 24 hours)
- SR-4: Failed login attempts must be rate-limited
- SR-5: All authentication events must be logged

### Technology and Data Variations
- OAuth provider: GitHub (primary), extensible to other providers
- Session storage: Redis or in-memory (configurable)
- API key storage: Database with bcrypt hashing

### Frequency of Occurrence
- Login: Multiple times per day per developer
- API key generation: Once per CI/CD setup
- Logout: Once per session

### Related Use Cases
- UC-02: Submit Code for Security Analysis (requires authentication for full features)
- UC-08: Review and Export Analysis Results (requires authentication for history)

---

## UC-02: Submit Code for Security Analysis

### Use Case Name
Submit Code for Security Analysis

### Scope
AutoVulRepair System - Module 1 (Static Analysis)

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants to identify security vulnerabilities in their C/C++ codebase
2. Security team wants comprehensive vulnerability reports
3. Organization wants to ensure code quality before deployment

### Preconditions
1. System must be operational with analysis tools (Cppcheck/CodeQL) available
2. Developer has code to analyze (GitHub repository, ZIP file, or code snippet)
3. For GitHub repositories: Repository must be accessible (public or authorized)
4. For ZIP files: File size must be under 100MB

### Postconditions
1. Code is successfully submitted and stored in the system
2. Scan record is created with unique scan ID
3. Analysis task is queued for execution
4. Static analysis is completed and results are stored
5. Vulnerabilities are converted to standardized format (static_findings.json)
6. Developer receives scan ID and can track progress

### Main Success Scenario
1. Developer accesses the scan submission interface
2. System displays submission form with three options: GitHub URL, ZIP upload, or code snippet
3. Developer selects GitHub repository option
4. Developer enters valid GitHub repository URL
5. System validates URL format
6. Developer selects analysis tool (Cppcheck or CodeQL)
7. Developer submits the scan request
8. System generates unique scan ID
9. System creates scan record in database with status "queued"
10. System clones the repository to scan directory
11. System queues analysis task to Celery worker
12. System redirects Developer to scan progress page
13. Celery worker picks up the task
14. System updates scan status to "running"
15. System executes selected analysis tool (Cppcheck or CodeQL)
16. Analysis tool generates report (XML or SARIF format)
17. System converts report to static_findings.json
18. System stores vulnerabilities in database
19. System updates scan status to "completed"
20. Developer views detailed findings with code context

### Extensions
**3a. Developer selects ZIP file upload:**
- 3a.1. Developer clicks ZIP upload option
- 3a.2. System displays file upload dialog
- 3a.3. Developer selects ZIP file from local system
- 3a.4. System validates file size (< 100MB)
- 3a.5. System validates ZIP structure
- 3a.6. System checks for path traversal attacks
- 3a.7. System extracts ZIP to scan directory
- 3a.8. Use case continues at step 6

**3b. Developer selects code snippet:**
- 3b.1. Developer clicks code snippet option
- 3b.2. System displays text area for code input
- 3b.3. Developer pastes code snippet
- 3b.4. System validates snippet size (< 10KB)
- 3b.5. System detects programming language
- 3b.6. System saves snippet to temporary file
- 3b.7. Use case continues at step 6

**5a. Invalid GitHub URL format:**
- 5a.1. System detects invalid URL pattern
- 5a.2. System displays error message: "Invalid GitHub URL format"
- 5a.3. System highlights URL input field
- 5a.4. Use case continues at step 4

**5b. Repository is private and not accessible:**
- 5b.1. System attempts to clone repository
- 5b.2. Git returns authentication error
- 5b.3. System displays error: "Repository not accessible"
- 5b.4. System suggests making repository public or using ZIP upload
- 5b.5. Use case ends

**3a.4a. ZIP file exceeds size limit:**
- 3a.4a.1. System rejects upload
- 3a.4a.2. System displays error: "File size exceeds 100MB limit"
- 3a.4a.3. System suggests using GitHub URL instead
- 3a.4a.4. Use case continues at step 3

**3a.6a. ZIP contains path traversal attack:**
- 3a.6a.1. System detects malicious paths (../, absolute paths)
- 3a.6a.2. System rejects ZIP file
- 3a.6a.3. System displays security error message
- 3a.6a.4. System logs security incident
- 3a.6a.5. Use case ends

**10a. Repository clone fails:**
- 10a.1. System detects clone timeout or error
- 10a.2. System updates scan status to "failed"
- 10a.3. System stores error message
- 10a.4. System notifies Developer
- 10a.5. Use case ends

**15a. Analysis tool execution fails:**
- 15a.1. System detects tool error or timeout
- 15a.2. System captures error output
- 15a.3. System updates scan status to "failed"
- 15a.4. System stores error details
- 15a.5. Developer can view error log
- 15a.6. Use case ends

**15b. No C/C++ files found in source:**
- 15b.1. Analysis tool finds no compatible files
- 15b.2. System updates scan status to "completed"
- 15b.3. System stores message: "No C/C++ files found"
- 15b.4. Developer views empty results
- 15b.5. Use case ends

**17a. Conversion to static_findings.json fails:**
- 17a.1. System logs conversion error
- 17a.2. System stores raw XML/SARIF report
- 17a.3. System marks conversion as failed
- 17a.4. Developer can still view raw report
- 17a.5. Use case continues at step 19

**13a. Celery worker unavailable (Redis down):**
- 13a.1. System detects Celery connection failure
- 13a.2. System falls back to synchronous execution
- 13a.3. System logs fallback mode
- 13a.4. Use case continues at step 14

### Special Requirements
- SR-1: Analysis must complete within 5 minutes for typical codebases
- SR-2: System must support concurrent scans (minimum 10 simultaneous)
- SR-3: Scan results must be retained for at least 30 days
- SR-4: Code must be stored securely and deleted after analysis
- SR-5: System must handle repositories up to 1GB in size
- SR-6: Real-time progress updates must be available via API

### Technology and Data Variations
- Analysis tools: Cppcheck (default), CodeQL (optional)
- Source formats: GitHub URL, ZIP file, code snippet
- Output formats: XML (Cppcheck), SARIF (CodeQL), JSON (standardized)
- Storage: Local filesystem or cloud storage (configurable)

### Frequency of Occurrence
- Multiple times per day per developer
- Peak usage during development sprints
- Automated scans via CI/CD: Every code commit

### Related Use Cases
- UC-01: Authenticate and Manage Account (optional for public scans)
- UC-03: Generate and Execute Fuzzing Campaign (uses static_findings.json)
- UC-08: Review and Export Analysis Results (displays findings)
- UC-10: Triage and Analyze Discovered Vulnerabilities (analyzes findings)

---

## UC-03: Generate and Execute Fuzzing Campaign

### Use Case Name
Generate and Execute Fuzzing Campaign

### Scope
AutoVulRepair System - Module 2 (Dynamic Analysis / Fuzzing)

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants to discover runtime vulnerabilities through dynamic testing
2. Security team wants comprehensive crash analysis and exploitability assessment
3. Organization wants to validate code robustness before production deployment

### Preconditions
1. Static analysis must be completed (static_findings.json exists)
2. Source code must be available in scan directory
3. Fuzzing compiler (Clang with LibFuzzer) must be available
4. System must have sufficient resources for compilation and fuzzing

### Postconditions
1. Fuzz plan is generated with prioritized targets
2. Fuzzing harnesses are generated for vulnerable functions
3. Harnesses are compiled into executable fuzz targets
4. Fuzzing campaign is executed for specified duration
5. Crashes are collected and analyzed
6. Triage results are available with severity and exploitability ratings
7. Reproduction kits are generated for discovered crashes

### Main Success Scenario
1. Developer navigates to fuzz plan generation page for completed scan
2. System displays option to generate fuzz plan
3. Developer clicks "Generate Fuzz Plan" button
4. System loads static_findings.json
5. System analyzes each vulnerability and infers bug classes (OOB, UAF, Integer-UB, etc.)
6. System calculates priority scores based on severity, confidence, and bug class
7. System extracts function signatures from source code
8. System deduplicates findings by file and function
9. System selects appropriate sanitizers for each bug class
10. System generates fuzzplan.json with complete target metadata
11. System displays fuzz plan with targets table and statistics
12. Developer reviews fuzz plan and clicks "Generate Harnesses"
13. System loads fuzz plan and selects harness type for each target
14. System generates C++ harness files using toolbox approach (bytes_to_api, fdp_adapter, parser_wrapper, api_sequence)
15. System creates build scripts and README documentation
16. System saves harnesses to scan directory
17. Developer reviews generated harnesses and clicks "Build Targets"
18. System compiles source files with fuzzing instrumentation
19. System patches main() function to avoid conflicts
20. System links harnesses with source object files
21. System applies sanitizers (ASan, UBSan, MSan, TSan)
22. System generates executable fuzz targets
23. System saves build log with success/failure status
24. Developer configures fuzzing campaign (runtime: 5 minutes per target)
25. Developer clicks "Start Fuzzing Campaign"
26. System creates crash directories for each target
27. System executes each fuzz target with LibFuzzer
28. System monitors for crashes, leaks, and timeouts
29. System collects crash artifacts and sanitizer output
30. System saves campaign results (campaign_results.json)
31. Developer clicks "Analyze Crashes"
32. System loads campaign results and classifies crash types
33. System assesses severity (Critical/High/Medium/Low)
34. System evaluates exploitability (Exploitable/Likely/Unlikely)
35. System calculates CVSS scores
36. System deduplicates similar crashes by stack trace
37. System generates triage report (triage_results.json)
38. Developer views triage dashboard with crash statistics
39. Developer downloads crash artifacts and reproduction kits

### Extensions
**4a. static_findings.json not found:**
- 4a.1. System displays error: "Static analysis not completed"
- 4a.2. System suggests running static analysis first
- 4a.3. System provides link to UC-02
- 4a.4. Use case ends

**5a. No vulnerabilities found in static analysis:**
- 5a.1. System detects empty findings list
- 5a.2. System displays message: "No vulnerabilities to fuzz"
- 5a.3. System suggests trying different analysis tool
- 5a.4. Use case ends

**7a. Function signatures cannot be extracted:**
- 7a.1. System logs signature extraction failure
- 7a.2. System continues with generic harness templates
- 7a.3. System marks targets as "signature unavailable"
- 7a.4. Use case continues at step 8

**10a. Fuzz plan generation fails:**
- 10a.1. System logs error details
- 10a.2. System displays error message to Developer
- 10a.3. Developer can retry generation
- 10a.4. Use case ends

**14a. Harness generation fails for some targets:**
- 14a.1. System logs failed targets
- 14a.2. System continues with successful harnesses
- 14a.3. System displays partial success message
- 14a.4. Use case continues at step 16

**18a. Source compilation fails:**
- 18a.1. System captures compiler errors
- 18a.2. System attempts to patch common issues (deprecated functions)
- 18a.3. If patching succeeds, use case continues at step 19
- 18a.4. If patching fails, system logs error and marks build as failed
- 18a.5. Developer can view build log
- 18a.6. Use case ends

**22a. Some targets fail to build:**
- 22a.1. System logs build failures
- 22a.2. System continues with successfully built targets
- 22a.3. System displays build summary (X successful, Y failed)
- 22a.4. Use case continues at step 24

**27a. Fuzzing target crashes immediately:**
- 27a.1. System detects immediate crash
- 27a.2. System saves crash input
- 27a.3. System continues with next target
- 27a.4. Use case continues at step 28

**28a. No crashes found during campaign:**
- 28a.1. System completes fuzzing without crashes
- 28a.2. System saves campaign results with zero crashes
- 28a.3. System displays success message: "No crashes found"
- 28a.4. Developer views coverage statistics
- 28a.5. Use case ends at step 30

**32a. Crash classification fails:**
- 32a.1. System logs classification error
- 32a.2. System marks crash as "Unknown" type
- 32a.3. System continues with other crashes
- 32a.4. Use case continues at step 33

**27b. Fuzzing timeout occurs:**
- 27b.1. System detects execution timeout
- 27b.2. System terminates fuzzing process
- 27b.3. System collects partial results
- 27b.4. System continues with next target
- 27b.5. Use case continues at step 28

### Special Requirements
- SR-1: Fuzz plan generation must complete within 30 seconds
- SR-2: Harness generation must support all 4 toolbox types
- SR-3: Build process must handle legacy C/C++ code
- SR-4: Fuzzing must support configurable runtime (1-60 minutes per target)
- SR-5: Crash artifacts must be preserved for at least 30 days
- SR-6: System must support parallel fuzzing of multiple targets
- SR-7: Triage must calculate accurate CVSS scores

### Technology and Data Variations
- Fuzzing engine: LibFuzzer (default), AFL++ (optional)
- Sanitizers: ASan, UBSan, MSan, TSan, LSan
- Harness types: bytes_to_api, fdp_adapter, parser_wrapper, api_sequence
- Crash formats: Raw input files, sanitizer reports, stack traces

### Frequency of Occurrence
- Fuzz plan generation: Once per scan
- Harness generation: Once per fuzz plan
- Build: Once per harness set
- Fuzzing campaign: Multiple times during development
- Triage: After each fuzzing campaign

### Related Use Cases
- UC-02: Submit Code for Security Analysis (provides static_findings.json)
- UC-04: Generate AI-Powered Vulnerability Patches (uses triage results)
- UC-08: Review and Export Analysis Results (displays fuzzing results)
- UC-10: Triage and Analyze Discovered Vulnerabilities (detailed crash analysis)

---

## UC-04: Generate AI-Powered Vulnerability Patches

### Use Case Name
Generate AI-Powered Vulnerability Patches

### Scope
AutoVulRepair System - Module 3 (Patch Generation - Vul-RAG)

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants automated patch suggestions for discovered vulnerabilities
2. Security team wants validated and compilable patches
3. Organization wants to reduce time-to-fix for security issues

### Preconditions
1. Static and/or dynamic analysis completed (findings available)
2. LLM service (OpenAI/Anthropic/Local) is configured and accessible
3. RAG knowledge base is initialized with vulnerability fix patterns
4. Source code is available for context extraction

### Postconditions
1. Vulnerabilities are ranked by severity and exploitability
2. AI-generated patches are created for high-priority vulnerabilities
3. Patches are validated through compiler feedback loop
4. Compilable patches are stored in fix_suggestions.json
5. Developer can review, accept, reject, or request refinement

### Main Success Scenario
1. Developer navigates to patch generation page for completed scan
2. System loads static_findings.json and dynamic-findings.json
3. System merges vulnerability data from both sources
4. System calculates severity scores and CVSS ratings
5. System ranks vulnerabilities by priority (critical first)
6. System saves vulnerability_ranking.json
7. Developer clicks "Generate Patches" for top vulnerabilities
8. System selects high-priority vulnerability
9. System extracts vulnerability context (code, location, type)
10. System queries RAG knowledge base for similar fixes
11. System retrieves top-k relevant patch examples
12. System constructs LLM prompt with context and examples
13. System sends request to LLM service
14. LLM analyzes vulnerability and generates patch code
15. System receives patch suggestion from LLM
16. System applies patch to source code
17. System attempts compilation
18. If compilation fails, system parses errors and refines patch (max 3 iterations)
19. System marks patch as compilable
20. System stores patch in fix_suggestions.json
21. System repeats steps 8-20 for remaining vulnerabilities
22. Developer views patch recommendations list
23. Developer selects patch to review
24. System displays patch with diff view and vulnerability context
25. Developer accepts patch
26. System marks patch as accepted and queues for validation (UC-05)

### Extensions
**2a. No findings available:**
- 2a.1. System displays error: "No vulnerabilities found"
- 2a.2. System suggests running analysis first
- 2a.3. Use case ends

**13a. LLM service unavailable:**
- 13a.1. System detects connection timeout
- 13a.2. System logs error and retries (max 3 attempts)
- 13a.3. If all retries fail, system skips this vulnerability
- 13a.4. Use case continues with next vulnerability

**14a. LLM generates invalid patch:**
- 14a.1. System detects malformed code
- 14a.2. System requests alternative from LLM
- 14a.3. If alternative fails, system marks patch as failed
- 14a.4. Use case continues with next vulnerability

**18a. Compilation fails after max retries:**
- 18a.1. System marks patch as non-compilable
- 18a.2. System stores partial patch and error log
- 18a.3. Developer can manually review and fix
- 18a.4. Use case continues with next vulnerability

**25a. Developer rejects patch:**
- 25a.1. System marks patch as rejected
- 25a.2. System stores rejection reason
- 25a.3. Developer can request alternative patch
- 25a.4. Use case continues at step 12 with refined prompt

**25b. Developer requests patch refinement:**
- 25b.1. Developer provides feedback/requirements
- 25b.2. System adds feedback to LLM prompt
- 25b.3. Use case continues at step 13

**11a. RAG knowledge base empty:**
- 11a.1. System proceeds without examples
- 11a.2. System uses generic patch templates
- 11a.3. Use case continues at step 12

### Special Requirements
- SR-1: Patch generation must complete within 2 minutes per vulnerability
- SR-2: Compiler feedback loop must limit to 3 iterations
- SR-3: Patches must maintain code functionality
- SR-4: System must support multiple LLM providers
- SR-5: RAG knowledge base must be updateable with verified patches

### Technology and Data Variations
- LLM providers: OpenAI GPT-4, Anthropic Claude, Local models
- RAG database: ChromaDB, Pinecone, Weaviate
- Compilers: GCC, Clang
- Patch formats: Unified diff, inline replacement

### Frequency of Occurrence
- Once per scan after analysis completion
- On-demand for specific vulnerabilities

### Related Use Cases
- UC-02: Submit Code for Security Analysis (provides findings)
- UC-03: Generate and Execute Fuzzing Campaign (provides dynamic findings)
- UC-05: Validate Patches in Sandbox Environment (validates patches)
- UC-08: Review and Export Analysis Results (displays patches)

---

## UC-05: Validate Patches in Sandbox Environment

### Use Case Name
Validate Patches in Sandbox Environment

### Scope
AutoVulRepair System - Module 5 (Sandbox Testing)

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants to ensure patches don't break functionality or degrade performance
2. Security team wants validated patches before production deployment
3. Organization wants to minimize risk of patch-induced bugs

### Preconditions
1. Patches have been generated and accepted (fix_suggestions.json exists)
2. gVisor sandbox environment is configured
3. Google Benchmark suite is available
4. Regression test suite exists for the codebase
5. Baseline performance metrics are available

### Postconditions
1. Patched code is executed safely in isolated sandbox
2. Performance benchmarks are collected and compared
3. Regression tests are executed
4. Patches are marked as verified or problematic
5. Validation report is generated with detailed results

### Main Success Scenario
1. Developer navigates to patch validation page
2. System displays list of accepted patches
3. Developer selects patches to validate and clicks "Validate"
4. System creates gVisor sandbox instance
5. System applies first patch to source code
6. System compiles patched code inside sandbox
7. System executes patched code in isolated environment
8. System monitors for anomalies (crashes, security violations)
9. No anomalies detected - execution completes successfully
10. System runs Google Benchmark on critical functions
11. System collects timing data and calculates statistics
12. System loads baseline performance metrics
13. System calculates performance delta (% change)
14. Performance delta is within acceptable threshold (< 5% degradation)
15. System executes regression test suite
16. All regression tests pass
17. System marks patch as "verified"
18. System stores validation results
19. System repeats steps 5-18 for remaining patches
20. System generates comprehensive validation report
21. Developer views validation results with pass/fail status
22. Developer downloads verified patches for deployment

### Extensions
**8a. Sandbox detects anomaly:**
- 8a.1. System captures anomaly details (crash, security violation)
- 8a.2. System terminates sandbox execution
- 8a.3. System marks patch as "unsafe"
- 8a.4. System logs security violation
- 8a.5. Developer is notified
- 8a.6. Use case continues with next patch

**6a. Compilation fails in sandbox:**
- 6a.1. System captures compiler errors
- 6a.2. System marks patch as "non-compilable"
- 6a.3. System stores error log
- 6a.4. Developer can review and fix patch
- 6a.5. Use case continues with next patch

**14a. Performance degradation exceeds threshold:**
- 14a.1. System detects > 5% performance loss
- 14a.2. System marks patch as "performance issue"
- 14a.3. System logs degradation details
- 14a.4. System flags patch for review
- 14a.5. Developer can accept degradation or reject patch
- 14a.6. Use case continues with next patch

**16a. Regression tests fail:**
- 16a.1. System captures failed test details
- 16a.2. System marks patch as "breaking"
- 16a.3. System logs failure reasons
- 16a.4. Developer can review test failures
- 16a.5. Use case continues with next patch

**7a. Sandbox execution timeout:**
- 7a.1. System detects execution exceeds time limit
- 7a.2. System terminates sandbox
- 7a.3. System marks patch as "timeout"
- 7a.4. System logs timeout event
- 7a.5. Use case continues with next patch

**10a. Benchmark suite unavailable:**
- 10a.1. System skips performance testing
- 10a.2. System logs warning
- 10a.3. System proceeds to regression tests
- 10a.4. Use case continues at step 15

**15a. No regression tests available:**
- 15a.1. System skips regression testing
- 15a.2. System logs warning
- 15a.3. System marks patch as "partially validated"
- 15a.4. Use case continues at step 17

### Special Requirements
- SR-1: Sandbox must provide complete isolation (gVisor)
- SR-2: Performance threshold must be configurable (default 5%)
- SR-3: Validation must complete within 10 minutes per patch
- SR-4: System must support custom benchmark suites
- SR-5: Regression tests must cover critical functionality

### Technology and Data Variations
- Sandbox: gVisor (default), Docker (fallback)
- Benchmark framework: Google Benchmark, custom scripts
- Test frameworks: Google Test, Catch2, custom tests
- Performance metrics: Execution time, memory usage, CPU cycles

### Frequency of Occurrence
- After each patch generation session
- Before production deployment
- On-demand for specific patches

### Related Use Cases
- UC-04: Generate AI-Powered Vulnerability Patches (provides patches)
- UC-08: Review and Export Analysis Results (displays validation results)
- UC-09: Manage Automated Workflows (automates validation in CI/CD)

---

## UC-06: Configure CI/CD Pipeline Integration

### Use Case Name
Configure CI/CD Pipeline Integration

### Scope
AutoVulRepair System - Module 4 (CI/CD Orchestration)

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants automated security scanning in their development workflow
2. DevOps team wants seamless integration with existing CI/CD tools
3. Organization wants to enforce security gates before deployment

### Preconditions
1. Developer has access to CI/CD system (GitHub Actions, Jenkins, GitLab CI)
2. AutoVulRepair API is accessible from CI/CD environment
3. Developer has generated API keys for authentication
4. Repository is connected to CI/CD system

### Postconditions
1. CI/CD pipeline is configured with AutoVulRepair integration
2. Automated scans trigger on code push/pull request
3. Security gates are enforced based on vulnerability severity
4. Scan results are reported back to CI/CD system
5. Deployments are blocked if critical vulnerabilities found

### Main Success Scenario
1. Developer navigates to CI/CD configuration page
2. System displays supported CI/CD platforms
3. Developer selects platform (GitHub Actions)
4. System generates pipeline configuration template
5. Developer copies configuration to repository
6. Developer configures webhook for automated triggers
7. Developer sets severity thresholds (block on critical/high)
8. Developer commits code changes to repository
9. CI/CD system detects commit and triggers workflow
10. Workflow calls AutoVulRepair API with code and API key
11. System validates API key and creates scan
12. System executes full analysis pipeline (UC-02 → UC-03 → UC-04)
13. System returns results to CI/CD system
14. CI/CD evaluates results against thresholds
15. No critical vulnerabilities found - deployment proceeds
16. Developer receives notification with scan report

### Extensions
**15a. Critical vulnerabilities detected:**
- 15a.1. CI/CD blocks deployment
- 15a.2. System creates issue in issue tracker
- 15a.3. Developer receives notification with details
- 15a.4. Developer must fix vulnerabilities before deployment
- 15a.5. Use case ends

**10a. API authentication fails:**
- 10a.1. System returns 401 Unauthorized
- 10a.2. CI/CD workflow fails
- 10a.3. Developer receives error notification
- 10a.4. Developer must regenerate API key
- 10a.5. Use case ends

**12a. Analysis pipeline fails:**
- 12a.1. System returns error status
- 12a.2. CI/CD workflow fails
- 12a.3. Developer receives error details
- 12a.4. Developer can retry or investigate
- 12a.5. Use case ends

### Special Requirements
- SR-1: API must support all major CI/CD platforms
- SR-2: Webhook integration must be secure (HMAC signatures)
- SR-3: Pipeline must complete within CI/CD timeout limits
- SR-4: Results must be returned in CI/CD-compatible format

### Frequency of Occurrence
- Configuration: Once per repository
- Automated scans: Every code commit/pull request

### Related Use Cases
- UC-01: Authenticate and Manage Account (API key generation)
- UC-02: Submit Code for Security Analysis (triggered by CI/CD)
- UC-09: Manage Automated Workflows (orchestrates pipeline)

---

## UC-07: Monitor System Performance and Metrics

### Use Case Name
Monitor System Performance and Metrics

### Scope
AutoVulRepair System - Module 6 (Monitoring & Metrics)

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants visibility into system performance and scan results
2. DevOps team wants to monitor system health and resource usage
3. Organization wants metrics for security posture improvement

### Preconditions
1. Prometheus is configured and collecting metrics
2. Grafana dashboards are deployed
3. System has historical data for trend analysis

### Postconditions
1. Real-time metrics are displayed in dashboards
2. Historical trends are visualized
3. Alerts are configured for anomalies
4. Evaluation reports are generated
5. Audit logs are available for compliance

### Main Success Scenario
1. Developer navigates to monitoring dashboard
2. System displays Grafana dashboard with real-time metrics
3. Developer views key metrics (scan success rate, patch success rate, code coverage)
4. Developer selects time range for historical analysis
5. System displays trend graphs showing improvement over time
6. Developer views alert configuration
7. System shows active alerts and thresholds
8. Developer requests evaluation report for last month
9. System aggregates metrics from all scans
10. System generates comprehensive report with statistics and charts
11. Developer downloads report as PDF
12. Developer views audit logs for compliance review

### Extensions
**2a. Grafana unavailable:**
- 2a.1. System displays error message
- 2a.2. System suggests checking Grafana service
- 2a.3. Use case ends

**7a. Alert threshold exceeded:**
- 7a.1. System sends notification (email/Slack)
- 7a.2. Developer acknowledges alert
- 7a.3. Developer investigates issue
- 7a.4. Use case continues

### Special Requirements
- SR-1: Dashboards must update in real-time (< 5 second delay)
- SR-2: System must retain metrics for at least 90 days
- SR-3: Reports must be exportable in multiple formats

### Frequency of Occurrence
- Dashboard viewing: Multiple times per day
- Report generation: Weekly/monthly
- Alert notifications: As needed

### Related Use Cases
- All use cases (monitoring observes all system activities)

---

## UC-08: Review and Export Analysis Results

### Use Case Name
Review and Export Analysis Results

### Scope
AutoVulRepair System - All Modules

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants to review detailed vulnerability findings
2. Security team wants exportable reports for documentation
3. Compliance team wants audit trails

### Preconditions
1. At least one scan has been completed
2. Analysis results are stored in database

### Postconditions
1. Developer has reviewed vulnerability details
2. Results are exported in requested format
3. Code context is displayed for each finding
4. Reports are available for sharing

### Main Success Scenario
1. Developer navigates to scan results page
2. System displays list of completed scans
3. Developer selects scan to review
4. System loads detailed findings with code context
5. Developer views vulnerability details (severity, location, description)
6. Developer examines code context (±5 lines around vulnerability)
7. Developer views fuzz plan and harness generation results
8. Developer reviews crash triage analysis
9. Developer views AI-generated patches
10. Developer views sandbox validation results
11. Developer clicks "Export Results"
12. System displays export format options (JSON/CSV/PDF/Markdown)
13. Developer selects PDF format
14. System generates comprehensive report with all findings
15. Developer downloads report
16. Developer shares report with security team

### Extensions
**4a. Scan still in progress:**
- 4a.1. System displays progress indicator
- 4a.2. System shows partial results if available
- 4a.3. Developer can wait or return later
- 4a.4. Use case ends

**14a. Report generation fails:**
- 14a.1. System logs error
- 14a.2. System displays error message
- 14a.3. Developer can retry with different format
- 14a.4. Use case continues at step 12

### Special Requirements
- SR-1: Results must be displayed within 2 seconds
- SR-2: Export must support multiple formats
- SR-3: Code context must be syntax-highlighted

### Frequency of Occurrence
- Multiple times per scan
- Export: Once per scan for documentation

### Related Use Cases
- UC-02: Submit Code for Security Analysis (generates findings)
- UC-03: Generate and Execute Fuzzing Campaign (generates results)
- UC-04: Generate AI-Powered Vulnerability Patches (generates patches)

---

## UC-09: Manage Automated Workflows

### Use Case Name
Manage Automated Workflows

### Scope
AutoVulRepair System - Module 4 (CI/CD Orchestration)

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants to automate the entire security pipeline
2. DevOps team wants efficient resource utilization
3. Organization wants consistent security processes

### Preconditions
1. Kubernetes cluster is operational
2. Docker images are built and available
3. Workflow definitions are configured

### Postconditions
1. Automated workflow is triggered successfully
2. All pipeline stages execute in sequence
3. Resources are allocated and deallocated efficiently
4. Results are stored and notifications sent

### Main Success Scenario
1. Developer configures automated workflow
2. System defines pipeline stages (Static → Dynamic → Patch → Validate)
3. Developer sets trigger conditions (on commit, scheduled, manual)
4. Developer commits code to repository
5. System detects trigger event
6. System creates Kubernetes job for Module 1 (Static Analysis)
7. K8s schedules job on available node
8. Module 1 completes and stores results
9. System automatically triggers Module 2 (Fuzzing)
10. Module 2 completes and stores results
11. System automatically triggers Module 3 (Patching)
12. Module 3 completes and stores patches
13. System automatically triggers Module 5 (Validation)
14. Module 5 completes validation
15. System generates final evaluation report
16. System sends notification to Developer with results
17. System cleans up resources

### Extensions
**8a. Module 1 fails:**
- 8a.1. System logs failure
- 8a.2. System stops pipeline
- 8a.3. System sends failure notification
- 8a.4. Use case ends

**7a. No K8s nodes available:**
- 7a.1. System queues job
- 7a.2. System waits for node availability
- 7a.3. System retries when node becomes available
- 7a.4. Use case continues at step 7

### Special Requirements
- SR-1: Pipeline must support parallel execution where possible
- SR-2: System must handle job failures gracefully
- SR-3: Resources must be cleaned up after completion

### Frequency of Occurrence
- Every code commit (if configured)
- Scheduled (daily/weekly)
- On-demand

### Related Use Cases
- UC-02, UC-03, UC-04, UC-05 (orchestrates all modules)
- UC-06: Configure CI/CD Pipeline Integration

---

## UC-10: Triage and Analyze Discovered Vulnerabilities

### Use Case Name
Triage and Analyze Discovered Vulnerabilities

### Scope
AutoVulRepair System - Modules 1, 2, 3

### Level
User Goal

### Primary Actor
Developer

### Stakeholders and Interests
1. Developer wants to prioritize vulnerability fixes
2. Security team wants accurate risk assessment
3. Organization wants to focus on critical issues first

### Preconditions
1. Vulnerabilities have been discovered (static or dynamic analysis)
2. Crash artifacts are available (for dynamic analysis)

### Postconditions
1. Vulnerabilities are classified by type and severity
2. Exploitability is assessed
3. CVSS scores are calculated
4. Vulnerabilities are prioritized
5. Recommendations are provided

### Main Success Scenario
1. Developer navigates to triage dashboard
2. System loads all discovered vulnerabilities
3. System classifies each vulnerability by type (Buffer Overflow, UAF, etc.)
4. System assesses severity (Critical/High/Medium/Low)
5. System evaluates exploitability (Exploitable/Likely/Unlikely)
6. System calculates CVSS scores
7. System deduplicates similar vulnerabilities
8. System ranks vulnerabilities by priority
9. Developer views prioritized list
10. Developer selects vulnerability for detailed analysis
11. System displays vulnerability details, code context, and stack trace
12. Developer views recommended fixes
13. Developer marks vulnerability for patching
14. System queues vulnerability for UC-04 (Patch Generation)

### Extensions
**3a. Unknown vulnerability type:**
- 3a.1. System marks as "Unknown"
- 3a.2. System uses generic severity assessment
- 3a.3. Use case continues at step 4

**7a. All vulnerabilities are duplicates:**
- 7a.1. System keeps only unique instances
- 7a.2. System logs deduplication statistics
- 7a.3. Use case continues at step 8

### Special Requirements
- SR-1: Triage must complete within 1 minute
- SR-2: CVSS calculation must follow standard methodology
- SR-3: Deduplication must be accurate (< 5% false positives)

### Frequency of Occurrence
- After each analysis session
- On-demand for specific vulnerabilities

### Related Use Cases
- UC-02: Submit Code for Security Analysis (discovers vulnerabilities)
- UC-03: Generate and Execute Fuzzing Campaign (discovers crashes)
- UC-04: Generate AI-Powered Vulnerability Patches (fixes vulnerabilities)
