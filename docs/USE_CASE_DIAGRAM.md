# AutoVulRepair - Use Case Diagram and Event-Response Specification

## Document Overview
This document provides a comprehensive use case analysis for the AutoVulRepair system, including:
- Actor identification and roles
- Complete use case catalog
- Use case diagram description
- Detailed event-response tables for all interactions

---

## 1. System Actors

### 1.1 Primary Actor

#### **Developer**
- **Description**: The primary user of the AutoVulRepair system - a software developer who wants to analyze code for vulnerabilities and receive automated patches
- **Goals**: 
  - Find security vulnerabilities in their codebase (static and dynamic analysis)
  - Generate fuzzing harnesses and execute fuzzing campaigns
  - Get AI-generated patches for discovered vulnerabilities
  - Validate patches in sandbox environments
  - Integrate security testing into development workflow
  - Monitor system performance and metrics
- **Characteristics**: 
  - Has GitHub account for authentication
  - Familiar with C/C++ development
  - Can access system via web UI or API
  - May use CI/CD integration for automated workflows
- **Interactions**: Uses all 6 modules of the system

### 1.2 Secondary Actors

#### **Static Analysis Tools**
- **Description**: External analysis engines (Cppcheck, CodeQL)
- **Role**: Provide vulnerability detection capabilities for Module 1

#### **LLM Service**
- **Description**: Large Language Model API (OpenAI, Anthropic, or local models)
- **Role**: Generate vulnerability patches via Vul-RAG in Module 3

#### **Container Orchestrator (Kubernetes)**
- **Description**: Kubernetes cluster managing workloads
- **Role**: Execute analysis jobs, manage resources, scale workers in Module 4

#### **Monitoring System (Prometheus + Grafana)**
- **Description**: Observability stack for metrics and visualization
- **Role**: Collect metrics, visualize dashboards, send alerts in Module 6

#### **Sandbox Environment (gVisor)**
- **Description**: Isolated runtime for safe code execution
- **Role**: Execute patched code safely for validation in Module 5

#### **CI/CD System**
- **Description**: Automated build/deployment system (GitHub Actions, Jenkins, GitLab CI)
- **Role**: Trigger automated workflows, integrate with developer's pipeline in Module 4
- **Note**: Acts on behalf of the Developer for automated operations

---

## 2. Use Case Catalog

### 2.1 Module 1: Static Analysis Use Cases

#### UC-SA-01: Submit Code for Analysis
- **Actor**: Developer
- **Precondition**: Developer has code to analyze
- **Postcondition**: Scan initiated, scan ID returned
- **Includes**: UC-SA-02, UC-SA-03, UC-SA-04
- **Note**: Can be triggered manually via web UI or automatically via CI/CD

#### UC-SA-02: Submit GitHub Repository
- **Actor**: Developer
- **Precondition**: Valid GitHub URL provided
- **Postcondition**: Repository cloned, analysis queued

#### UC-SA-03: Upload ZIP File
- **Actor**: Developer
- **Precondition**: Valid ZIP file with C/C++ code
- **Postcondition**: ZIP extracted, analysis queued


#### UC-SA-04: Submit Code Snippet
- **Actor**: Developer
- **Precondition**: Code snippet provided
- **Postcondition**: Snippet saved, analysis queued

#### UC-SA-05: Run Cppcheck Analysis
- **Actor**: System (triggered by UC-SA-01)
- **Precondition**: Source code available
- **Postcondition**: cppcheck-report.xml generated

#### UC-SA-06: Run CodeQL Analysis
- **Actor**: System (triggered by UC-SA-01)
- **Precondition**: Source code available
- **Postcondition**: codeql-results.sarif generated

#### UC-SA-07: Convert Analysis Results
- **Actor**: System
- **Precondition**: XML/SARIF report exists
- **Postcondition**: static_findings.json created

#### UC-SA-08: View Vulnerability Findings
- **Actor**: Developer
- **Precondition**: Analysis completed
- **Postcondition**: Vulnerabilities displayed with code context

#### UC-SA-09: Export Findings Report
- **Actor**: Developer
- **Precondition**: Findings available
- **Postcondition**: Report exported (JSON/CSV/PDF)

#### UC-SA-10: Check Scan Status
- **Actor**: Developer
- **Precondition**: Scan initiated
- **Postcondition**: Current status returned

### 2.2 Module 2: Dynamic Analysis (Fuzzing) Use Cases

#### UC-DA-01: Generate Fuzz Plan
- **Actor**: Developer, System
- **Precondition**: static_findings.json exists
- **Postcondition**: fuzzplan.json created with targets

#### UC-DA-02: View Fuzz Plan
- **Actor**: Developer
- **Precondition**: Fuzz plan generated
- **Postcondition**: Targets displayed with priorities

#### UC-DA-03: Export Fuzz Plan
- **Actor**: Developer, CI/CD System
- **Precondition**: Fuzz plan exists
- **Postcondition**: Plan exported (JSON/CSV/Markdown)

#### UC-DA-04: Generate Fuzzing Harnesses
- **Actor**: Developer, System
- **Precondition**: Fuzz plan exists
- **Postcondition**: Harness .cc files generated

#### UC-DA-05: View Generated Harnesses
- **Actor**: Developer
- **Precondition**: Harnesses generated
- **Postcondition**: Harness code displayed


#### UC-DA-06: Download Harness Files
- **Actor**: Developer
- **Precondition**: Harnesses generated
- **Postcondition**: Files downloaded (single or ZIP)

#### UC-DA-07: Build Fuzz Targets
- **Actor**: Developer, System
- **Precondition**: Harnesses exist
- **Postcondition**: Executable fuzz targets compiled

#### UC-DA-08: View Build Status
- **Actor**: Developer
- **Precondition**: Build initiated
- **Postcondition**: Build results displayed

#### UC-DA-09: Download Build Artifacts
- **Actor**: Developer
- **Precondition**: Build successful
- **Postcondition**: Binaries downloaded

#### UC-DA-10: Execute Fuzzing Campaign
- **Actor**: Developer, CI/CD System
- **Precondition**: Fuzz targets built
- **Postcondition**: Fuzzing completed, crashes collected

#### UC-DA-11: Monitor Fuzzing Progress
- **Actor**: Developer
- **Precondition**: Fuzzing running
- **Postcondition**: Real-time stats displayed


#### UC-DA-12: Analyze Crash Results
- **Actor**: System
- **Precondition**: Crashes found
- **Postcondition**: Crashes triaged and classified

#### UC-DA-13: View Triage Dashboard
- **Actor**: Developer, Security Researcher
- **Precondition**: Triage completed
- **Postcondition**: Crash analysis displayed

#### UC-DA-14: Download Crash Artifacts
- **Actor**: Developer
- **Precondition**: Crashes exist
- **Postcondition**: Crash files downloaded

#### UC-DA-15: Generate Reproduction Kit
- **Actor**: Developer
- **Precondition**: Crashes triaged
- **Postcondition**: Repro kit with instructions created

### 2.3 Module 3: Patch Generation (Vul-RAG) Use Cases

#### UC-PG-01: Load Vulnerability Data
- **Actor**: System
- **Precondition**: Static and/or dynamic findings exist
- **Postcondition**: Vulnerabilities loaded into Vul-RAG

#### UC-PG-02: Rank Vulnerabilities by Severity
- **Actor**: System
- **Precondition**: Vulnerabilities loaded
- **Postcondition**: vulnerability_ranking.json created


#### UC-PG-03: Generate AI Patch
- **Actor**: System (LLM Service)
- **Precondition**: Vulnerability selected
- **Postcondition**: Patch code generated

#### UC-PG-04: Apply Compiler Feedback Loop
- **Actor**: System
- **Precondition**: Patch generated
- **Postcondition**: Patch refined until compilation succeeds

#### UC-PG-05: Store Patch Suggestions
- **Actor**: System
- **Precondition**: Patches generated
- **Postcondition**: fix_suggestions.json created

#### UC-PG-06: View Patch Recommendations
- **Actor**: Developer
- **Precondition**: Patches generated
- **Postcondition**: Patches displayed with diff view

#### UC-PG-07: Review Patch Details
- **Actor**: Developer
- **Precondition**: Patch selected
- **Postcondition**: Full patch context displayed

#### UC-PG-08: Accept Patch
- **Actor**: Developer
- **Precondition**: Patch reviewed
- **Postcondition**: Patch marked for application


#### UC-PG-09: Reject Patch
- **Actor**: Developer
- **Precondition**: Patch reviewed
- **Postcondition**: Patch marked as rejected

#### UC-PG-10: Request Patch Refinement
- **Actor**: Developer
- **Precondition**: Patch needs improvement
- **Postcondition**: LLM generates alternative patch

#### UC-PG-11: Export Patch Bundle
- **Actor**: Developer, CI/CD System
- **Precondition**: Patches generated
- **Postcondition**: Patch files exported

### 2.4 Module 4: Cloud-Native Deployment & CI/CD Use Cases

#### UC-CD-01: Deploy to Kubernetes
- **Actor**: DevOps Engineer
- **Precondition**: Docker images built
- **Postcondition**: Services deployed to K8s cluster

#### UC-CD-02: Configure CI/CD Pipeline
- **Actor**: DevOps Engineer
- **Precondition**: Repository connected
- **Postcondition**: Pipeline configured

#### UC-CD-03: Trigger Automated Scan
- **Actor**: CI/CD System
- **Precondition**: Code pushed to repository
- **Postcondition**: Scan workflow initiated


#### UC-CD-04: Execute Workflow Pipeline
- **Actor**: CI/CD System
- **Precondition**: Workflow triggered
- **Postcondition**: All stages executed sequentially

#### UC-CD-05: Block Deployment on Critical Vulnerabilities
- **Actor**: CI/CD System
- **Precondition**: Critical vulnerabilities found
- **Postcondition**: Deployment prevented, notification sent

#### UC-CD-06: Scale Analysis Workers
- **Actor**: Container Orchestrator
- **Precondition**: High workload detected
- **Postcondition**: Additional pods spawned

#### UC-CD-07: Manage Job Queue
- **Actor**: Container Orchestrator
- **Precondition**: Multiple scans queued
- **Postcondition**: Jobs distributed across workers

#### UC-CD-08: Configure Cloud Provider
- **Actor**: DevOps Engineer
- **Precondition**: Cloud credentials available
- **Postcondition**: Cloud resources provisioned

#### UC-CD-09: Setup Webhook Integration
- **Actor**: DevOps Engineer
- **Precondition**: External system identified
- **Postcondition**: Webhooks configured


### 2.5 Module 5: Sandbox Testing Use Cases

#### UC-ST-01: Execute Patch in Sandbox
- **Actor**: System (Sandbox Environment)
- **Precondition**: Patch accepted
- **Postcondition**: Patched code executed in gVisor

#### UC-ST-02: Run Performance Benchmarks
- **Actor**: System
- **Precondition**: Patched code running
- **Postcondition**: Benchmark results collected

#### UC-ST-03: Compare Performance Metrics
- **Actor**: System
- **Precondition**: Benchmarks completed
- **Postcondition**: Performance delta calculated

#### UC-ST-04: Validate Performance Threshold
- **Actor**: System
- **Precondition**: Performance compared
- **Postcondition**: Pass/fail decision made

#### UC-ST-05: Execute Regression Tests
- **Actor**: System
- **Precondition**: Patch applied
- **Postcondition**: Test results collected

#### UC-ST-06: Detect Anomalies
- **Actor**: System (Sandbox Environment)
- **Precondition**: Code executing
- **Postcondition**: Anomalies logged


#### UC-ST-07: Mark Patch as Verified
- **Actor**: System
- **Precondition**: All tests passed
- **Postcondition**: Patch status updated to verified

#### UC-ST-08: Flag Problematic Patch
- **Actor**: System
- **Precondition**: Tests failed or performance degraded
- **Postcondition**: Patch flagged for review

#### UC-ST-09: View Validation Results
- **Actor**: Developer
- **Precondition**: Validation completed
- **Postcondition**: Test results displayed

### 2.6 Module 6: Monitoring & Metrics Use Cases

#### UC-MM-01: Collect System Metrics
- **Actor**: Monitoring System (Prometheus)
- **Precondition**: System running
- **Postcondition**: Metrics scraped and stored

#### UC-MM-02: View Grafana Dashboard
- **Actor**: DevOps Engineer, System Administrator
- **Precondition**: Metrics collected
- **Postcondition**: Real-time dashboard displayed

#### UC-MM-03: Configure Alerts
- **Actor**: DevOps Engineer
- **Precondition**: Alert rules defined
- **Postcondition**: Alerts configured in Prometheus


#### UC-MM-04: Receive Alert Notification
- **Actor**: DevOps Engineer, System Administrator
- **Precondition**: Threshold exceeded
- **Postcondition**: Alert sent via email/Slack/PagerDuty

#### UC-MM-05: View Historical Trends
- **Actor**: DevOps Engineer, Developer
- **Precondition**: Historical data exists
- **Postcondition**: Trend graphs displayed

#### UC-MM-06: Generate Evaluation Report
- **Actor**: System
- **Precondition**: CI/CD run completed
- **Postcondition**: Summary report generated

#### UC-MM-07: Export Audit Logs
- **Actor**: System Administrator
- **Precondition**: Logs exist
- **Postcondition**: Logs exported for compliance

#### UC-MM-08: Track Patch Success Rate
- **Actor**: Monitoring System
- **Precondition**: Patches applied
- **Postcondition**: Success rate calculated

#### UC-MM-09: Monitor Code Coverage
- **Actor**: Monitoring System
- **Precondition**: Fuzzing completed
- **Postcondition**: Coverage metrics updated


#### UC-MM-10: Track Runtime Stability
- **Actor**: Monitoring System
- **Precondition**: Patches deployed
- **Postcondition**: Stability metrics recorded

### 2.7 Authentication & User Management Use Cases

#### UC-AU-01: Login with GitHub OAuth
- **Actor**: Developer
- **Precondition**: User has GitHub account
- **Postcondition**: User authenticated, session created

#### UC-AU-02: Access Public Scanning
- **Actor**: Security Researcher
- **Precondition**: None
- **Postcondition**: Public scan interface accessible

#### UC-AU-03: Logout
- **Actor**: Developer
- **Precondition**: User logged in
- **Postcondition**: Session terminated

#### UC-AU-04: View User Dashboard
- **Actor**: Developer
- **Precondition**: User authenticated
- **Postcondition**: Personal dashboard displayed

#### UC-AU-05: Manage API Keys
- **Actor**: Developer, CI/CD System
- **Precondition**: User authenticated
- **Postcondition**: API keys generated/revoked


### 2.8 System Administration Use Cases

#### UC-AD-01: View System Health
- **Actor**: System Administrator
- **Precondition**: Admin access
- **Postcondition**: System status displayed

#### UC-AD-02: Manage User Access
- **Actor**: System Administrator
- **Precondition**: Admin access
- **Postcondition**: User permissions updated

#### UC-AD-03: Configure System Settings
- **Actor**: System Administrator
- **Precondition**: Admin access
- **Postcondition**: Settings updated

#### UC-AD-04: Review Audit Logs
- **Actor**: System Administrator
- **Precondition**: Logs exist
- **Postcondition**: Audit trail reviewed

#### UC-AD-05: Manage Resource Quotas
- **Actor**: System Administrator
- **Precondition**: Admin access
- **Postcondition**: Quotas configured

---

## 3. Use Case Diagram Description

### 3.1 Diagram Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                      AutoVulRepair System                            │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  MODULE 1: STATIC ANALYSIS                                  │    │
│  │  • Submit Code (UC-SA-01)                                   │    │
│  │  • Run Analysis (UC-SA-05, UC-SA-06)                        │    │
│  │  • View Findings (UC-SA-08)                                 │    │
│  └────────────────────────────────────────────────────────────┘    │

│                           │                                           │
│                           ▼                                           │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  MODULE 2: DYNAMIC ANALYSIS (FUZZING)                       │    │
│  │  • Generate Fuzz Plan (UC-DA-01)                            │    │
│  │  • Generate Harnesses (UC-DA-04)                            │    │
│  │  • Build Targets (UC-DA-07)                                 │    │
│  │  • Execute Fuzzing (UC-DA-10)                               │    │
│  │  • Triage Crashes (UC-DA-12)                                │    │
│  └────────────────────────────────────────────────────────────┘    │
│                           │                                           │
│                           ▼                                           │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  MODULE 3: PATCH GENERATION (VUL-RAG)                       │    │
│  │  • Rank Vulnerabilities (UC-PG-02)                          │    │
│  │  • Generate Patches (UC-PG-03)                              │    │
│  │  • Compiler Feedback (UC-PG-04)                             │    │
│  │  • Review Patches (UC-PG-06)                                │    │
│  └────────────────────────────────────────────────────────────┘    │
│                           │                                           │
│                           ▼                                           │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  MODULE 5: SANDBOX TESTING                                  │    │
│  │  • Execute in Sandbox (UC-ST-01)                            │    │
│  │  • Run Benchmarks (UC-ST-02)                                │    │
│  │  • Validate Performance (UC-ST-04)                          │    │
│  │  • Run Regression Tests (UC-ST-05)                          │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  MODULE 4: CI/CD ORCHESTRATION (Manages All Modules)        │    │
│  │  • Deploy to K8s (UC-CD-01)                                 │    │
│  │  • Trigger Workflows (UC-CD-03)                             │    │
│  │  • Execute Pipeline (UC-CD-04)                              │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  MODULE 6: MONITORING & METRICS (Observes All Modules)      │    │
│  │  • Collect Metrics (UC-MM-01)                               │    │
│  │  • View Dashboards (UC-MM-02)                               │    │
│  │  • Generate Reports (UC-MM-06)                              │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘


PRIMARY ACTOR:
┌──────────────────────────────────────────────────────────────┐
│                        DEVELOPER                              │
│  (Single primary user - interacts with all 6 modules)        │
└──────────────────────────────────────────────────────────────┘
                               │
                               │ Uses
                               ▼
                    ┌──────────────────────┐
                    │  AutoVulRepair       │
                    │  System              │
                    │  (All 6 Modules)     │
                    └──────────────────────┘

SECONDARY ACTORS (Support Developer's workflow):
┌──────────────────┐
│ Static Analysis  │ ──► Executes vulnerability detection
│ Tools            │
└──────────────────┘

┌──────────────────┐
│ LLM Service      │ ──► Generates patches via Vul-RAG
└──────────────────┘

┌──────────────────┐
│ Container        │ ──► Orchestrates jobs in Kubernetes
│ Orchestrator     │
└──────────────────┘

┌──────────────────┐
│ Monitoring       │ ──► Collects metrics and alerts
│ System           │
└──────────────────┘

┌──────────────────┐
│ Sandbox          │ ──► Validates patches safely
│ Environment      │
└──────────────────┘

┌──────────────────┐
│ CI/CD System     │ ──► Automates Developer's workflows
└──────────────────┘
```

### 3.2 Actor-Use Case Relationships

#### Developer (Primary Actor) - Interacts with ALL modules:

**Module 1 - Static Analysis:**
- UC-SA-01 through UC-SA-10 (Submit code, view findings, export reports)

**Module 2 - Dynamic Analysis (Fuzzing):**
- UC-DA-01 through UC-DA-16 (Generate fuzz plans, harnesses, build, execute, triage)

**Module 3 - Patch Generation (Vul-RAG):**
- UC-PG-01 through UC-PG-11 (View patches, review, accept/reject, export)

**Module 4 - CI/CD Orchestration:**
- UC-CD-02, UC-CD-03, UC-CD-09 (Configure pipelines, trigger workflows, setup webhooks)

**Module 5 - Sandbox Testing:**
- UC-ST-09 (View validation results)

**Module 6 - Monitoring & Metrics:**
- UC-MM-02, UC-MM-05, UC-MM-06 (View dashboards, trends, reports)

**Authentication:**
- UC-AU-01, UC-AU-03, UC-AU-04, UC-AU-05 (Login, logout, dashboard, API keys)

#### Secondary Actors - Support Developer's workflow:

**Static Analysis Tools**: Execute UC-SA-05, UC-SA-06
**LLM Service**: Execute UC-PG-03, UC-PG-04
**Container Orchestrator**: Execute UC-CD-06, UC-CD-07
**Monitoring System**: Execute UC-MM-01, UC-MM-04
**Sandbox Environment**: Execute UC-ST-01 through UC-ST-08
**CI/CD System**: Automates Developer's workflows (UC-CD-03, UC-CD-04, UC-CD-05)

---

## 4. Event-Response Tables

### 4.1 Module 1: Static Analysis Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-SA-001 | Developer submits GitHub URL | Developer | Valid GitHub URL provided | 1. Validate URL format<br>2. Create scan record<br>3. Queue clone task<br>4. Return scan ID | Scan record created with status "queued" | UC-SA-01, UC-SA-02 |
| E-SA-002 | Developer uploads ZIP file | Developer | ZIP file < 100MB | 1. Validate ZIP structure<br>2. Check for path traversal<br>3. Extract to scan directory<br>4. Queue analysis task | Source files extracted, scan queued | UC-SA-01, UC-SA-03 |
| E-SA-003 | Developer submits code snippet | Developer | Code snippet < 10KB | 1. Validate code content<br>2. Detect language<br>3. Save to temp file<br>4. Queue analysis | Code file created, scan queued | UC-SA-01, UC-SA-04 |
| E-SA-004 | Celery worker picks up scan | System | Scan in queue, worker available | 1. Update status to "running"<br>2. Clone repo or load files<br>3. Execute analysis tool | Analysis in progress | UC-SA-05, UC-SA-06 |

| E-SA-005 | Cppcheck analysis completes | System | Source files available | 1. Parse XML output<br>2. Convert to static_findings.json<br>3. Store vulnerabilities in DB<br>4. Update scan status to "completed" | Vulnerabilities stored, findings available | UC-SA-05, UC-SA-07 |
| E-SA-006 | CodeQL analysis completes | System | Source files available | 1. Parse SARIF output<br>2. Convert to static_findings.json<br>3. Store vulnerabilities in DB<br>4. Update scan status | Vulnerabilities stored, findings available | UC-SA-06, UC-SA-07 |
| E-SA-007 | Developer requests findings view | Developer | Scan completed | 1. Load scan from DB<br>2. Extract code context<br>3. Render findings page | Findings displayed with code snippets | UC-SA-08 |
| E-SA-008 | Developer exports findings | Developer | Findings available | 1. Load findings data<br>2. Format as requested (JSON/CSV/PDF)<br>3. Generate download | Report file downloaded | UC-SA-09 |
| E-SA-009 | Developer checks scan status | Developer | Scan exists | 1. Query scan record<br>2. Calculate elapsed time<br>3. Return status JSON | Status information returned | UC-SA-10 |
| E-SA-010 | Analysis fails | System | Error during analysis | 1. Log error details<br>2. Update scan status to "failed"<br>3. Store error message | Scan marked as failed, error logged | All SA use cases |
| E-SA-011 | User requests detailed finding | Developer | Finding selected | 1. Load vulnerability details<br>2. Extract code context (±5 lines)<br>3. Render detail view | Detailed view displayed | UC-SA-08 |


### 4.2 Module 2: Dynamic Analysis (Fuzzing) Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-DA-001 | User requests fuzz plan generation | Developer | static_findings.json exists | 1. Load static findings<br>2. Infer bug classes<br>3. Calculate priorities<br>4. Extract function signatures<br>5. Generate fuzzplan.json | Fuzz plan created with targets | UC-DA-01 |
| E-DA-002 | User views fuzz plan | Developer | Fuzz plan exists | 1. Load fuzzplan.json<br>2. Render targets table<br>3. Display bug class breakdown | Fuzz plan displayed | UC-DA-02 |
| E-DA-003 | User exports fuzz plan | Developer, CI/CD | Fuzz plan exists | 1. Load fuzz plan<br>2. Format as requested (CSV/MD)<br>3. Generate download | Export file downloaded | UC-DA-03 |
| E-DA-004 | User requests harness generation | Developer | Fuzz plan exists | 1. Load fuzz plan<br>2. For each target, select harness type<br>3. Generate .cc files<br>4. Create build scripts<br>5. Generate README | Harness files created | UC-DA-04 |
| E-DA-005 | User views harness code | Developer | Harnesses generated | 1. Load harness file<br>2. Syntax highlight<br>3. Display in viewer | Harness code displayed | UC-DA-05 |
| E-DA-006 | User downloads harnesses | Developer | Harnesses exist | 1. Create ZIP archive<br>2. Include all .cc files and scripts<br>3. Generate download | ZIP file downloaded | UC-DA-06 |

| E-DA-007 | User initiates build | Developer | Harnesses exist | 1. Compile source files<br>2. Patch main() function<br>3. Link harnesses with source<br>4. Apply sanitizers<br>5. Generate build log | Fuzz targets built | UC-DA-07 |
| E-DA-008 | Build completes | System | Compilation finished | 1. Save build results<br>2. Update build status<br>3. Store binary paths | Build log saved | UC-DA-08 |
| E-DA-009 | Build fails | System | Compilation error | 1. Capture error output<br>2. Log failure details<br>3. Update status to failed | Build marked as failed | UC-DA-08 |
| E-DA-010 | User starts fuzzing campaign | Developer, CI/CD | Targets built | 1. Configure runtime<br>2. Create crash directories<br>3. Execute each target<br>4. Monitor for crashes | Fuzzing in progress | UC-DA-10 |
| E-DA-011 | Fuzzing completes | System | Runtime elapsed | 1. Collect crash artifacts<br>2. Parse fuzzer stats<br>3. Save campaign results | campaign_results.json created | UC-DA-11 |
| E-DA-012 | Crash detected | System | Fuzzer found crash | 1. Save crash input<br>2. Capture sanitizer output<br>3. Log crash details | Crash artifact saved | UC-DA-12 |
| E-DA-013 | User requests triage | Developer | Crashes exist | 1. Load campaign results<br>2. Classify crash types<br>3. Assess severity<br>4. Calculate CVSS<br>5. Deduplicate crashes | triage_results.json created | UC-DA-12 |
| E-DA-014 | User views triage dashboard | Developer | Triage completed | 1. Load triage results<br>2. Render crash statistics<br>3. Display exploitability | Dashboard displayed | UC-DA-13 |

| E-DA-015 | User downloads crash artifacts | Developer | Crashes exist | 1. Locate crash files<br>2. Create archive<br>3. Generate download | Crash files downloaded | UC-DA-14 |
| E-DA-016 | User generates repro kit | Developer | Triage completed | 1. Create repro directory<br>2. Copy crash inputs<br>3. Generate instructions<br>4. Package as ZIP | Repro kit created | UC-DA-15 |

### 4.3 Module 3: Patch Generation (Vul-RAG) Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-PG-001 | System loads vulnerability data | System | Static/dynamic findings exist | 1. Load static_findings.json<br>2. Load dynamic-findings.json<br>3. Merge vulnerability data<br>4. Prepare for RAG | Vulnerabilities loaded | UC-PG-01 |
| E-PG-002 | System ranks vulnerabilities | System | Vulnerabilities loaded | 1. Calculate severity scores<br>2. Assess exploitability<br>3. Consider CVSS<br>4. Sort by priority<br>5. Save vulnerability_ranking.json | Rankings created | UC-PG-02 |
| E-PG-003 | User requests patch generation | Developer | Vulnerabilities ranked | 1. Select high-priority vulnerabilities<br>2. Query RAG knowledge base<br>3. Generate LLM prompt<br>4. Request patch from LLM | Patch generation initiated | UC-PG-03 |
| E-PG-004 | LLM generates patch | LLM Service | Prompt received | 1. Analyze vulnerability context<br>2. Retrieve similar fixes from RAG<br>3. Generate patch code<br>4. Return patch suggestion | Patch code generated | UC-PG-03 |

| E-PG-005 | System applies compiler feedback | System | Patch generated | 1. Apply patch to source<br>2. Attempt compilation<br>3. Parse compiler errors<br>4. If errors, refine patch<br>5. Repeat until success | Patch compiles successfully | UC-PG-04 |
| E-PG-006 | Compilation succeeds | System | Patch applied | 1. Mark patch as compilable<
br>2. Store in fix_suggestions.json<br>3. Notify user | Patch ready for review | UC-PG-05 |
| E-PG-007 | Compilation fails after max retries | System | Feedback loop exhausted | 1. Mark patch as failed<br>2. Log compilation errors<br>3. Store partial patch | Patch marked as non-compilable | UC-PG-04 |
| E-PG-008 | User views patch recommendations | Developer | Patches generated | 1. Load fix_suggestions.json<br>2. Load vulnerability_ranking.json<br>3. Render patch list with priorities | Patches displayed | UC-PG-06 |
| E-PG-009 | User reviews patch details | Developer | Patch selected | 1. Load patch content<br>2. Load original code<br>3. Generate diff view<br>4. Display vulnerability context | Patch details displayed | UC-PG-07 |
| E-PG-010 | User accepts patch | Developer | Patch reviewed | 1. Mark patch as accepted<br>2. Update patch status in DB<br>3. Queue for sandbox testing | Patch accepted, ready for validation | UC-PG-08 |
| E-PG-011 | User rejects patch | Developer | Patch reviewed | 1. Mark patch as rejected<br>2. Store rejection reason<br>3. Update statistics | Patch rejected, logged | UC-PG-09 |
| E-PG-012 | User requests patch refinement | Developer | Patch needs improvement | 1. Load original patch<br>2. Add user feedback to prompt<br>3. Request alternative from LLM<br>4. Generate new patch | Alternative patch generated | UC-PG-10 |
| E-PG-013 | User exports patch bundle | Developer, CI/CD | Patches available | 1. Collect accepted patches<br>2. Generate unified diff<br>3. Create patch files<br>4. Package as archive | Patch bundle downloaded | UC-PG-11 |
| E-PG-014 | RAG retrieves similar fixes | System | Vulnerability analyzed | 1. Vectorize vulnerability description<br>2. Query vector database<br>3. Retrieve top-k similar fixes<br>4. Return context to LLM | Similar fixes retrieved | UC-PG-03 |
| E-PG-015 | System updates RAG knowledge base | System | New patch verified | 1. Vectorize patch and context<br>2. Store in vector database<br>3. Update embeddings | Knowledge base updated | UC-PG-03 |

### 4.4 Module 4: Cloud-Native Deployment & CI/CD Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-CD-001 | DevOps deploys to Kubernetes | DevOps Engineer | Docker images built, K8s cluster available | 1. Apply Kubernetes manifests<br>2. Create deployments and services<br>3. Configure ingress<br>4. Verify pod health | Services deployed to K8s | UC-CD-01 |
| E-CD-002 | DevOps configures CI/CD pipeline | DevOps Engineer | Repository connected | 1. Create pipeline configuration<br>2. Define stages and jobs<br>3. Configure secrets<br>4. Set up webhooks | Pipeline configured | UC-CD-02 |
| E-CD-003 | Code pushed to repository | Developer | Repository configured | 1. Webhook triggered<br>2. CI/CD system receives event<br>3. Queue workflow execution | Workflow queued | UC-CD-03 |
| E-CD-004 | CI/CD triggers automated scan | CI/CD System | Code push detected | 1. Clone repository<br>2. Create scan job<br>3. Submit to AutoVulRepair API<br>4. Monitor scan progress | Scan initiated | UC-CD-03 |
| E-CD-005 | Workflow pipeline executes | CI/CD System | Workflow triggered | 1. Execute Module 1 (Static Analysis)<br>2. Wait for completion<br>3. Execute Module 2 (Fuzzing)<br>4. Execute Module 3 (Patching)<br>5. Execute Module 5 (Validation) | All stages completed | UC-CD-04 |
| E-CD-006 | Critical vulnerabilities detected | CI/CD System | Scan completed | 1. Parse scan results<br>2. Check severity thresholds<br>3. Block deployment<br>4. Send notifications<br>5. Create issue in tracker | Deployment blocked | UC-CD-05 |
| E-CD-007 | No critical issues found | CI/CD System | Scan completed | 1. Parse scan results<br>2. Verify thresholds passed<br>3. Approve deployment<br>4. Proceed to next stage | Deployment approved | UC-CD-04 |
| E-CD-008 | High workload detected | Container Orchestrator | Queue length exceeds threshold | 1. Calculate required replicas<br>2. Scale deployment<br>3. Spawn additional pods<br>4. Distribute workload | Workers scaled up | UC-CD-06 |
| E-CD-009 | Workload decreases | Container Orchestrator | Queue length below threshold | 1. Identify idle pods<br>2. Scale down deployment<br>3. Terminate excess pods | Workers scaled down | UC-CD-06 |
| E-CD-010 | Job queued for execution | CI/CD System | Scan requested | 1. Create job manifest<br>2. Submit to K8s scheduler<br>3. Assign to available node<br>4. Monitor job status | Job scheduled | UC-CD-07 |
| E-CD-011 | Job completes successfully | Container Orchestrator | Job finished | 1. Collect job logs<br>2. Store results<br>3. Clean up resources<br>4. Trigger next stage | Job completed, resources freed | UC-CD-07 |
| E-CD-012 | Job fails | Container Orchestrator | Job error occurred | 1. Capture error logs<br>2. Retry if configured<br>3. Send failure notification<br>4. Clean up resources | Job failed, logged | UC-CD-07 |
| E-CD-013 | DevOps configures cloud provider | DevOps Engineer | Cloud credentials available | 1. Authenticate with cloud API<br>2. Provision resources (VMs, storage, network)<br>3. Configure security groups<br>4. Deploy K8s cluster | Cloud resources provisioned | UC-CD-08 |
| E-CD-014 | DevOps sets up webhook | DevOps Engineer | External system identified | 1. Generate webhook URL<br>2. Configure authentication<br>3. Define event triggers<br>4. Test webhook | Webhook configured | UC-CD-09 |
| E-CD-015 | Webhook receives event | System | Webhook configured | 1. Validate webhook signature<br>2. Parse event payload<br>3. Trigger corresponding action<br>4. Return acknowledgment | Event processed | UC-CD-09 |

### 4.5 Module 5: Sandbox Testing Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-ST-001 | System executes patch in sandbox | System | Patch accepted | 1. Create gVisor sandbox<br>2. Apply patch to source<br>3. Compile patched code<br>4. Execute in isolated environment<br>5. Monitor for anomalies | Patched code executed | UC-ST-01 |
| E-ST-002 | Sandbox detects anomaly | Sandbox Environment | Code executing | 1. Capture anomaly details<br>2. Terminate execution<br>3. Log security violation<br>4. Mark patch as unsafe | Anomaly detected and logged | UC-ST-06 |
| E-ST-003 | Sandbox execution completes | Sandbox Environment | No anomalies detected | 1. Collect execution logs<br>2. Verify clean exit<br>3. Proceed to benchmarking | Execution successful | UC-ST-01 |
| E-ST-004 | System runs performance benchmarks | System | Patched code running | 1. Execute Google Benchmark suite<br>2. Measure critical functions<br>3. Collect timing data<br>4. Calculate statistics | Benchmark results collected | UC-ST-02 |
| E-ST-005 | System compares performance | System | Benchmarks completed | 1. Load baseline metrics<br>2. Calculate performance delta<br>3. Identify regressions<br>4. Generate comparison report | Performance delta calculated | UC-ST-03 |
| E-ST-006 | Performance within threshold | System | Comparison completed | 1. Mark performance as acceptable<br>2. Update patch status<br>3. Proceed to regression tests | Performance validated | UC-ST-04 |
| E-ST-007 | Performance degradation detected | System | Delta exceeds threshold | 1. Mark patch as performance issue<br>2. Log degradation details<br>3. Flag for review<br>4. Halt validation | Patch flagged for performance | UC-ST-04, UC-ST-08 |
| E-ST-008 | System executes regression tests | System | Performance validated | 1. Load test suite<br>2. Execute all tests<br>3. Collect test results<br>4. Check for failures | Test results collected | UC-ST-05 |
| E-ST-009 | All regression tests pass | System | Tests completed | 1. Mark tests as passed<br>2. Update patch status<br>3. Proceed to verification | Tests passed | UC-ST-05 |
| E-ST-010 | Regression tests fail | System | Test failures detected | 1. Capture failed test details<br>2. Mark patch as breaking<br>3. Log failure reasons<br>4. Halt validation | Patch flagged for test failures | UC-ST-05, UC-ST-08 |
| E-ST-011 | System marks patch as verified | System | All validations passed | 1. Update patch status to "verified"<br>2. Store validation results<br>3. Generate verification report<br>4. Notify stakeholders | Patch verified | UC-ST-07 |
| E-ST-012 | System flags problematic patch | System | Validation failed | 1. Update patch status to "problematic"<br>2. Store failure details<br>3. Generate failure report<br>4. Notify developer | Patch flagged | UC-ST-08 |
| E-ST-013 | User views validation results | Developer | Validation completed | 1. Load validation report<br>2. Display test results<br>3. Show performance metrics<br>4. Render sandbox logs | Results displayed | UC-ST-09 |
| E-ST-014 | Sandbox timeout occurs | Sandbox Environment | Execution exceeds limit | 1. Terminate sandbox<br>2. Log timeout event<br>3. Mark patch as timeout<br>4. Clean up resources | Execution terminated | UC-ST-06 |

### 4.6 Module 6: Monitoring & Metrics Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-MM-001 | Prometheus scrapes metrics | Monitoring System | System running, exporters configured | 1. Query metrics endpoints<br>2. Collect time-series data<br>3. Store in TSDB<br>4. Update metric values | Metrics collected | UC-MM-01 |
| E-MM-002 | User views Grafana dashboard | DevOps Engineer, Admin | Metrics collected | 1. Load dashboard configuration<br>2. Query Prometheus<br>3. Render visualizations<br>4. Display real-time data | Dashboard displayed | UC-MM-02 |
| E-MM-003 | DevOps configures alerts | DevOps Engineer | Alert rules defined | 1. Create alert rules in Prometheus<br>2. Configure notification channels<br>3. Set thresholds<br>4. Enable alerting | Alerts configured | UC-MM-03 |
| E-MM-004 | Metric threshold exceeded | Monitoring System | Alert rule triggered | 1. Evaluate alert condition<br>2. Generate alert notification<br>3. Send via configured channels<br>4. Log alert event | Alert sent | UC-MM-04 |
| E-MM-005 | User receives alert notification | DevOps Engineer, Admin | Alert triggered | 1. Receive notification (email/Slack/PagerDuty)<br>2. View alert details<br>3. Acknowledge alert<br>4. Take action | Alert acknowledged | UC-MM-04 |
| E-MM-006 | User views historical trends | DevOps Engineer, Developer | Historical data exists | 1. Query time-range data<br>2. Aggregate metrics<br>3. Generate trend graphs<br>4. Display analysis | Trends displayed | UC-MM-05 |
| E-MM-007 | CI/CD run completes | System | Pipeline finished | 1. Collect run metrics<br>2. Aggregate results<br>3. Generate evaluation report<br>4. Store report | Report generated | UC-MM-06 |
| E-MM-008 | Admin exports audit logs | System Administrator | Logs exist | 1. Query audit log database<br>2. Filter by criteria<br>3. Format as requested<br>4. Generate export file | Logs exported | UC-MM-07 |
| E-MM-009 | System tracks patch success rate | Monitoring System | Patches applied | 1. Count total patches<br>2. Count successful patches<br>3. Calculate success rate<br>4. Update metric | Success rate calculated | UC-MM-08 |
| E-MM-010 | System monitors code coverage | Monitoring System | Fuzzing completed | 1. Parse coverage data<br>2. Calculate coverage percentage<br>3. Compare with baseline<br>4. Update metric | Coverage metrics updated | UC-MM-09 |
| E-MM-011 | System tracks runtime stability | Monitoring System | Patches deployed | 1. Monitor crash rates<br>2. Track uptime<br>3. Measure error rates<br>4. Calculate stability score | Stability metrics recorded | UC-MM-10 |
| E-MM-012 | Dashboard auto-refreshes | Grafana | Refresh interval elapsed | 1. Re-query Prometheus<br>2. Update visualizations<br>3. Refresh panels<br>4. Display latest data | Dashboard updated | UC-MM-02 |
| E-MM-013 | Alert resolves automatically | Monitoring System | Metric returns to normal | 1. Evaluate alert condition<br>2. Mark alert as resolved<br>3. Send resolution notification<br>4. Log resolution | Alert resolved | UC-MM-04 |
| E-MM-014 | System generates summary report | System | Evaluation period ended | 1. Aggregate all metrics<br>2. Calculate statistics<br>3. Generate charts<br>4. Create PDF/HTML report | Summary report created | UC-MM-06 |

### 4.7 Authentication & User Management Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-AU-001 | User initiates GitHub OAuth | Developer | User has GitHub account | 1. Redirect to GitHub OAuth<br>2. Request user authorization<br>3. Receive authorization code | OAuth flow initiated | UC-AU-01 |
| E-AU-002 | GitHub returns OAuth token | System | User authorized | 1. Exchange code for token<br>2. Fetch user profile<br>3. Create user session<br>4. Store user data | User authenticated | UC-AU-01 |
| E-AU-003 | OAuth authentication fails | System | User denied or error | 1. Log failure reason<br>2. Display error message<br>3. Redirect to home | Authentication failed | UC-AU-01 |
| E-AU-004 | User accesses public scanning | Security Researcher | None | 1. Load public scan interface<br>2. Display submission form<br>3. No authentication required | Public interface accessible | UC-AU-02 |
| E-AU-005 | User logs out | Developer | User authenticated | 1. Invalidate session<br>2. Clear session cookies<br>3. Redirect to home | User logged out | UC-AU-03 |
| E-AU-006 | User views dashboard | Developer | User authenticated | 1. Load user's scans<br>2. Fetch recent activity<br>3. Display statistics<br>4. Render dashboard | Dashboard displayed | UC-AU-04 |
| E-AU-007 | User generates API key | Developer, CI/CD | User authenticated | 1. Generate secure token<br>2. Store hashed key<br>3. Display key once<br>4. Log key creation | API key created | UC-AU-05 |
| E-AU-008 | User revokes API key | Developer | API key exists | 1. Invalidate key<br>2. Remove from database<br>3. Log revocation<br>4. Confirm to user | API key revoked | UC-AU-05 |
| E-AU-009 | API request with key | CI/CD System | Valid API key provided | 1. Validate API key<br>2. Authenticate request<br>3. Check rate limits<br>4. Process request | Request authenticated | UC-AU-05 |
| E-AU-010 | Invalid API key used | CI/CD System | Invalid key provided | 1. Log authentication attempt<br>2. Return 401 Unauthorized<br>3. Increment failed attempts | Request rejected | UC-AU-05 |
| E-AU-011 | Session expires | System | Session timeout reached | 1. Invalidate session<br>2. Clear session data<br>3. Redirect to login on next request | Session expired | UC-AU-01 |

### 4.8 System Administration Events

| Event ID | Event Name | Triggering Actor | Preconditions | System Response | Postconditions | Related Use Cases |
|----------|------------|------------------|---------------|-----------------|----------------|-------------------|
| E-AD-001 | Admin views system health | System Administrator | Admin authenticated | 1. Query system metrics<br>2. Check service status<br>3. Verify database connectivity<br>4. Display health dashboard | Health status displayed | UC-AD-01 |
| E-AD-002 | Admin manages user access | System Administrator | Admin authenticated | 1. Load user list<br>2. Display permissions<br>3. Allow permission changes<br>4. Update access control | User access updated | UC-AD-02 |
| E-AD-003 | Admin configures system settings | System Administrator | Admin authenticated | 1. Load current settings<br>2. Display configuration form<br>3. Validate changes<br>4. Apply new settings | Settings updated | UC-AD-03 |
| E-AD-004 | Admin reviews audit logs | System Administrator | Logs exist | 1. Query audit log database<br>2. Filter by criteria<br>3. Display log entries<br>4. Allow export | Audit trail reviewed | UC-AD-04 |
| E-AD-005 | Admin manages resource quotas | System Administrator | Admin authenticated | 1. Load current quotas<br>2. Display usage statistics<br>3. Allow quota changes<br>4. Apply new limits | Quotas configured | UC-AD-05 |
| E-AD-006 | System health check fails | System | Health check executed | 1. Detect service failure<br>2. Log failure details<br>3. Send alert to admin<br>4. Attempt auto-recovery | Failure detected and logged | UC-AD-01 |
| E-AD-007 | Admin restarts service | System Administrator | Service unhealthy | 1. Gracefully stop service<br>2. Clear stale connections<br>3. Restart service<br>4. Verify health | Service restarted | UC-AD-01 |
| E-AD-008 | Admin views user activity | System Administrator | Admin authenticated | 1. Query user activity logs<br>2. Display recent actions<br>3. Show resource usage<br>4. Generate activity report | Activity displayed | UC-AD-02 |
| E-AD-009 | Admin blocks user | System Administrator | User identified | 1. Disable user account<br>2. Invalidate sessions<br>3. Revoke API keys<br>4. Log action | User blocked | UC-AD-02
 |
| E-AD-010 | Admin unblocks user | System Administrator | User blocked | 1. Re-enable user account<br>2. Restore permissions<br>3. Log action<br>4. Notify user | User unblocked | UC-AD-02 |
