# AutoVulRepair - Domain Model and ERD

## Document Information
- **Project**: AutoVulRepair - Automated Vulnerability Detection and Patching System
- **Version**: 1.0
- **Date**: December 7, 2025
- **Purpose**: Complete domain model and entity-relationship diagram

---

## Table of Contents
1. [Domain Model Overview](#domain-model-overview)
2. [Core Domain Entities](#core-domain-entities)
3. [Entity Relationships](#entity-relationships)
4. [Entity-Relationship Diagram (ERD)](#entity-relationship-diagram-erd)
5. [Domain Services](#domain-services)
6. [Value Objects](#value-objects)
7. [Aggregates](#aggregates)
8. [Domain Events](#domain-events)

---

## Domain Model Overview

AutoVulRepair is a comprehensive security analysis platform that automates the detection, fuzzing, and patching of vulnerabilities in C/C++ codebases. The system follows a pipeline architecture with 6 main modules:

### System Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    AutoVulRepair Domain                          │
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Module 1   │───▶│   Module 2   │───▶│   Module 3   │      │
│  │   Static     │    │   Dynamic    │    │   Patch      │      │
│  │   Analysis   │    │   Analysis   │    │   Generation │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │              │
│         └────────────────────┴────────────────────┘              │
│                              │                                   │
│                              ▼                                   │
│                    ┌──────────────────┐                         │
│                    │    Module 5      │                         │
│                    │    Sandbox       │                         │
│                    │    Validation    │                         │
│                    └──────────────────┘                         │
│                                                                   │
│  ┌──────────────────────────────────────────────────┐          │
│  │  Module 4: CI/CD Orchestration (Manages All)     │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────────────────────────────────────────┐          │
│  │  Module 6: Monitoring & Metrics (Observes All)   │          │
│  └──────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```


---

## Core Domain Entities

### 1. **Scan** (Aggregate Root)
The central entity representing a security analysis session.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `user_id` (String, nullable): Owner of the scan (null for public scans)
- `source_type` (Enum): 'zip', 'repo_url', 'code_snippet'
- `source_path` (String): Local file path for zip/snippet
- `repo_url` (String): GitHub repository URL
- `analysis_tool` (Enum): 'cppcheck', 'codeql'
- `status` (Enum): 'queued', 'running', 'completed', 'failed'
- `artifacts_path` (String): Path to analysis artifacts
- `vulnerabilities_json` (JSON): Stored vulnerability findings
- `patches_json` (JSON): Generated patches
- `created_at` (DateTime): Creation timestamp
- `updated_at` (DateTime): Last update timestamp

**Relationships:**
- Has many: Vulnerabilities
- Has many: FuzzTargets
- Has many: Patches
- Has one: FuzzPlan
- Has one: BuildResult
- Has one: FuzzCampaign
- Has one: TriageResult

**Business Rules:**
- A scan must have a valid source (repo_url, zip, or snippet)
- Status transitions: queued → running → completed/failed
- Artifacts are retained for 30 days minimum
- Public scans (user_id = null) have limited features

---

### 2. **Vulnerability** (Entity)
Represents a security vulnerability discovered during static analysis.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `scan_id` (String, FK): Parent scan
- `rule_id` (String): Analysis tool rule identifier
- `file` (String): Source file path
- `file_stem` (String): Filename without extension
- `function` (String): Function name containing vulnerability
- `line_number` (Integer): Line number
- `column_number` (Integer): Column number
- `severity` (Enum): 'error', 'warning', 'style', 'information'
- `confidence` (Enum): 'high', 'medium', 'low'
- `message` (Text): Vulnerability description
- `cwe` (String): Common Weakness Enumeration ID
- `priority_score` (Float): Calculated priority (0-10)
- `bug_class` (Enum): Inferred bug classification
- `code_context` (JSON): Surrounding code lines

**Relationships:**
- Belongs to: Scan
- Has many: FuzzTargets (one vulnerability can generate multiple targets)
- Has many: Patches

**Business Rules:**
- Priority score calculated from severity, confidence, CWE, and bug class
- Bug class inferred from rule_id using mapping table
- Code context extracted as ±5 lines around vulnerability

---

### 3. **FuzzPlan** (Entity)
Strategic plan for fuzzing campaign generated from static findings.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `scan_id` (String, FK): Parent scan
- `version` (String): Plan version
- `generated_at` (DateTime): Generation timestamp
- `total_findings` (Integer): Original findings count
- `deduplicated_targets` (Integer): Unique targets after deduplication
- `bug_class_breakdown` (JSON): Count by bug class
- `sanitizers_used` (Array): List of sanitizers
- `signatures_extracted` (Integer): Functions with extracted signatures
- `signatures_failed` (Integer): Functions without signatures
- `targets` (JSON): Array of FuzzTarget metadata

**Relationships:**
- Belongs to: Scan
- Has many: FuzzTargets
- Has many: Harnesses

**Business Rules:**
- Generated from static_findings.json
- Targets deduplicated by <file_stem>::<function>
- Maximum 100 targets per plan (configurable)
- Targets prioritized by severity and exploitability


---

### 4. **FuzzTarget** (Entity)
Individual fuzzing target with complete metadata for harness generation.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `fuzz_plan_id` (String, FK): Parent fuzz plan
- `target_id` (String): Unique target identifier (file_stem_function)
- `source_file` (String): Source file path
- `file_stem` (String): Filename without extension
- `function_name` (String): Target function name
- `bug_class` (Enum): OOB, UAF, Integer-UB, Null-Deref, etc.
- `rule_id` (String): Original static analysis rule
- `severity` (Enum): error, warning, style, information
- `confidence` (Enum): high, medium, low
- `line_number` (Integer): Vulnerability line
- `column_number` (Integer): Vulnerability column
- `message` (Text): Vulnerability description
- `cwe` (String): CWE identifier
- `sanitizers` (Array): [ASan, UBSan, MSan, TSan, LSan]
- `seed_directories` (Array): Seed corpus paths
- `dictionaries` (Array): Fuzzing dictionary paths
- `priority` (Float): Calculated priority score
- `harness_type` (Enum): bytes_to_api, fdp_adapter, parser_wrapper, api_sequence
- `harness_template` (String): Template name
- `function_signature` (JSON): Extracted function signature
- `signature_status` (Enum): extracted, not_extracted, no_source_dir

**Relationships:**
- Belongs to: FuzzPlan
- Belongs to: Vulnerability (optional)
- Has one: Harness
- Has one: BuildResult
- Has many: CrashArtifacts

**Business Rules:**
- Harness type inferred from function name, bug class, and context
- Sanitizers selected based on bug class
- Priority calculated from severity, confidence, CWE, and bug class
- Function signature extracted from source if available

---

### 5. **Harness** (Entity)
Generated fuzzing harness code for a specific target.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `fuzz_target_id` (String, FK): Parent fuzz target
- `filename` (String): Harness filename (fuzz_<file_stem>_<function>.cc)
- `file_path` (String): Relative path
- `full_path` (String): Absolute path
- `harness_type` (Enum): bytes_to_api, fdp_adapter, parser_wrapper, api_sequence
- `code` (Text): Generated harness code
- `file_size` (Integer): File size in bytes
- `lines` (Integer): Line count
- `generation_timestamp` (DateTime): When generated
- `generator_version` (String): Generator version
- `build_status` (Enum): not_built, building, success, failed

**Relationships:**
- Belongs to: FuzzTarget
- Has one: BuildResult

**Business Rules:**
- Filename follows convention: fuzz_<file_stem>_<function>.cc
- Code generated using toolbox templates
- Includes function signature if available
- Contains bug class specific implementation hints

---

### 6. **BuildResult** (Entity)
Result of compiling a harness into an executable fuzz target.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `harness_id` (String, FK): Parent harness
- `target_name` (String): Output binary name
- `output_path` (String): Path to compiled binary
- `status` (Enum): success, error, timeout
- `build_time` (Float): Compilation time in seconds
- `command` (Text): Compilation command
- `log` (Text): Build output/errors
- `compiler` (String): Compiler used (clang++, afl-g++, etc.)
- `sanitizers` (String): Applied sanitizers
- `timestamp` (DateTime): Build timestamp

**Relationships:**
- Belongs to: Harness
- Has one: FuzzExecution

**Business Rules:**
- Compilation timeout: 60 seconds
- Source file main() function wrapped with preprocessor guards
- Deprecated functions (gets) automatically patched
- Shared source object file linked if available

---

### 7. **FuzzCampaign** (Entity)
Execution of fuzzing campaign across multiple targets.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `scan_id` (String, FK): Parent scan
- `start_time` (DateTime): Campaign start
- `end_time` (DateTime): Campaign end
- `runtime_per_target` (Integer): Seconds per target
- `total_targets` (Integer): Number of targets
- `completed_targets` (Integer): Completed count
- `total_executions` (Integer): Total fuzzer executions
- `total_crashes` (Integer): Total crashes found
- `status` (Enum): running, completed, failed

**Relationships:**
- Belongs to: Scan
- Has many: FuzzExecutions
- Has one: TriageResult

**Business Rules:**
- Default runtime: 5 minutes per target
- Configurable: 1-60 minutes per target
- Crashes collected in real-time
- Campaign can be paused/resumed


---

### 8. **FuzzExecution** (Entity)
Individual fuzzing execution for a specific target.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `campaign_id` (String, FK): Parent campaign
- `build_result_id` (String, FK): Compiled target
- `target_name` (String): Target binary name
- `start_time` (DateTime): Execution start
- `end_time` (DateTime): Execution end
- `runtime` (Integer): Actual runtime in seconds
- `executions` (Integer): Number of fuzzer iterations
- `crashes_found` (Integer): Crashes discovered
- `coverage` (Float): Code coverage percentage
- `status` (Enum): running, completed, timeout, crashed
- `output` (Text): Fuzzer output

**Relationships:**
- Belongs to: FuzzCampaign
- Belongs to: BuildResult
- Has many: CrashArtifacts

**Business Rules:**
- Timeout enforced per target
- Coverage tracked via LibFuzzer stats
- Output captured for crash analysis
- Artifacts saved to crash directory

---

### 9. **CrashArtifact** (Entity)
Crash input and metadata discovered during fuzzing.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `execution_id` (String, FK): Parent execution
- `filename` (String): Crash file name
- `file_path` (String): Path to crash input
- `file_size` (Integer): Input size in bytes
- `crash_type` (Enum): Heap Buffer Overflow, Stack Buffer Overflow, UAF, etc.
- `sanitizer_output` (Text): Sanitizer error message
- `stack_trace` (JSON): Stack trace frames
- `discovered_at` (DateTime): Discovery timestamp

**Relationships:**
- Belongs to: FuzzExecution
- Has one: TriageAnalysis

**Business Rules:**
- Crash files preserved for 30 days minimum
- Stack trace extracted from sanitizer output
- Crash type inferred from filename and output
- Artifacts stored in scan_dir/fuzz/crashes/

---

### 10. **TriageResult** (Entity)
Comprehensive crash triage analysis for a campaign.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `campaign_id` (String, FK): Parent campaign
- `timestamp` (DateTime): Analysis timestamp
- `total_crashes` (Integer): Total crashes analyzed
- `unique_crashes` (Integer): After deduplication
- `critical_count` (Integer): Critical severity
- `high_count` (Integer): High severity
- `medium_count` (Integer): Medium severity
- `low_count` (Integer): Low severity
- `exploitable_count` (Integer): Exploitable crashes
- `likely_exploitable_count` (Integer): Likely exploitable
- `unlikely_exploitable_count` (Integer): Unlikely exploitable
- `summary` (JSON): Detailed breakdown

**Relationships:**
- Belongs to: FuzzCampaign
- Has many: TriageAnalyses

**Business Rules:**
- Crashes deduplicated by stack trace similarity
- Severity assessed from crash type
- Exploitability evaluated per crash
- CVSS scores calculated for each crash

---

### 11. **TriageAnalysis** (Entity)
Individual crash analysis with severity and exploitability assessment.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `triage_result_id` (String, FK): Parent triage result
- `crash_artifact_id` (String, FK): Analyzed crash
- `crash_type` (Enum): Heap Buffer Overflow, Stack Buffer Overflow, etc.
- `severity` (Enum): Critical, High, Medium, Low
- `exploitability` (Enum): Exploitable, Likely Exploitable, Unlikely Exploitable
- `cvss_score` (Float): CVSS score (0-10)
- `root_cause` (Text): Root cause description
- `stack_trace` (JSON): Top 10 stack frames
- `is_duplicate` (Boolean): Duplicate of another crash
- `recommendations` (Text): Fix recommendations

**Relationships:**
- Belongs to: TriageResult
- Belongs to: CrashArtifact
- Has many: Patches (generated from this analysis)

**Business Rules:**
- CVSS calculated from severity and exploitability
- Duplicates identified by stack trace signature
- Root cause extracted from sanitizer summary
- Recommendations based on crash type

---

### 12. **Patch** (Entity)
AI-generated vulnerability patch with validation status.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `scan_id` (String, FK): Parent scan
- `vulnerability_id` (String, FK): Target vulnerability (optional)
- `triage_analysis_id` (String, FK): Target crash (optional)
- `patch_code` (Text): Generated patch code
- `diff` (Text): Unified diff format
- `generation_method` (Enum): llm_rag, template, manual
- `llm_model` (String): LLM model used
- `compilation_status` (Enum): not_compiled, success, failed
- `compilation_attempts` (Integer): Feedback loop iterations
- `validation_status` (Enum): not_validated, passed, failed
- `performance_impact` (Float): Performance delta percentage
- `status` (Enum): pending, accepted, rejected, applied
- `created_at` (DateTime): Generation timestamp
- `applied_at` (DateTime): Application timestamp

**Relationships:**
- Belongs to: Scan
- Belongs to: Vulnerability (optional)
- Belongs to: TriageAnalysis (optional)
- Has one: ValidationResult

**Business Rules:**
- Generated using LLM with RAG knowledge base
- Compiler feedback loop: max 3 iterations
- Must compile successfully before validation
- Performance impact must be < 5% degradation
- Patches ranked by vulnerability priority


---

### 13. **ValidationResult** (Entity)
Sandbox validation result for a patch.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `patch_id` (String, FK): Parent patch
- `sandbox_type` (String): gVisor, Docker, etc.
- `execution_status` (Enum): success, crashed, timeout, security_violation
- `performance_baseline` (JSON): Original performance metrics
- `performance_patched` (JSON): Patched performance metrics
- `performance_delta` (Float): Percentage change
- `regression_tests_passed` (Integer): Passed test count
- `regression_tests_failed` (Integer): Failed test count
- `anomalies_detected` (Array): List of anomalies
- `validation_time` (Float): Validation duration
- `timestamp` (DateTime): Validation timestamp

**Relationships:**
- Belongs to: Patch

**Business Rules:**
- Executed in isolated gVisor sandbox
- Performance benchmarks using Google Benchmark
- Regression tests must all pass
- Performance degradation threshold: 5%
- Anomalies include crashes, security violations, leaks

---

### 14. **User** (Entity)
System user with authentication and authorization.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `github_id` (String): GitHub user ID
- `username` (String): GitHub username
- `email` (String): User email
- `access_token` (String, encrypted): GitHub OAuth token
- `api_keys` (JSON): Generated API keys (hashed)
- `role` (Enum): developer, admin
- `created_at` (DateTime): Registration timestamp
- `last_login` (DateTime): Last login timestamp

**Relationships:**
- Has many: Scans
- Has many: APIKeys

**Business Rules:**
- Authentication via GitHub OAuth
- API keys for programmatic access
- Public scans don't require authentication
- Session timeout: 24 hours (configurable)

---

### 15. **APIKey** (Entity)
API key for programmatic access.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `user_id` (String, FK): Owner
- `key_hash` (String): Bcrypt hashed key
- `name` (String): Key description
- `created_at` (DateTime): Creation timestamp
- `last_used` (DateTime): Last usage timestamp
- `expires_at` (DateTime): Expiration timestamp
- `is_active` (Boolean): Active status

**Relationships:**
- Belongs to: User

**Business Rules:**
- Keys are 256-bit cryptographically secure
- Displayed once at creation
- Stored as bcrypt hash
- Can be revoked by user
- Rate limited per key

---

### 16. **WorkflowExecution** (Entity)
CI/CD automated workflow execution.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `scan_id` (String, FK): Associated scan
- `trigger_type` (Enum): commit, pull_request, scheduled, manual
- `ci_system` (Enum): github_actions, jenkins, gitlab_ci
- `pipeline_stages` (JSON): Stage execution details
- `start_time` (DateTime): Execution start
- `end_time` (DateTime): Execution end
- `status` (Enum): running, success, failed, blocked
- `blocked_reason` (Text): Why deployment was blocked
- `webhook_payload` (JSON): Trigger payload

**Relationships:**
- Belongs to: Scan

**Business Rules:**
- Triggered by code commits or schedules
- Executes full pipeline: Static → Dynamic → Patch → Validate
- Blocks deployment if critical vulnerabilities found
- Sends notifications on completion
- Kubernetes jobs for scalability

---

### 17. **MetricsSnapshot** (Entity)
System performance and usage metrics snapshot.

**Attributes:**
- `id` (String, UUID): Unique identifier
- `timestamp` (DateTime): Snapshot time
- `scan_success_rate` (Float): Percentage of successful scans
- `patch_success_rate` (Float): Percentage of compilable patches
- `average_scan_time` (Float): Average scan duration
- `average_patch_time` (Float): Average patch generation time
- `total_scans` (Integer): Total scans in period
- `total_vulnerabilities` (Integer): Total vulnerabilities found
- `total_patches` (Integer): Total patches generated
- `code_coverage` (Float): Average fuzzing coverage
- `system_health` (JSON): Resource usage metrics

**Relationships:**
- None (time-series data)

**Business Rules:**
- Collected every 5 minutes
- Retained for 90 days
- Exported to Prometheus
- Visualized in Grafana dashboards
- Alerts configured on thresholds


---

## Entity Relationships

### Relationship Summary

```
User (1) ──────< (N) Scan
Scan (1) ──────< (N) Vulnerability
Scan (1) ────── (1) FuzzPlan
FuzzPlan (1) ──────< (N) FuzzTarget
FuzzTarget (1) ────── (1) Harness
Harness (1) ────── (1) BuildResult
Scan (1) ────── (1) FuzzCampaign
FuzzCampaign (1) ──────< (N) FuzzExecution
FuzzExecution (1) ──────< (N) CrashArtifact
FuzzCampaign (1) ────── (1) TriageResult
TriageResult (1) ──────< (N) TriageAnalysis
CrashArtifact (1) ────── (1) TriageAnalysis
Scan (1) ──────< (N) Patch
Vulnerability (1) ──────< (N) Patch
TriageAnalysis (1) ──────< (N) Patch
Patch (1) ────── (1) ValidationResult
User (1) ──────< (N) APIKey
Scan (1) ────── (1) WorkflowExecution
```

### Detailed Relationships

#### 1. User → Scan (One-to-Many)
- **Cardinality**: 1:N
- **Description**: A user can create multiple scans
- **Foreign Key**: Scan.user_id → User.id
- **Cascade**: ON DELETE SET NULL (preserve scans for audit)
- **Business Rule**: Public scans have user_id = NULL

#### 2. Scan → Vulnerability (One-to-Many)
- **Cardinality**: 1:N
- **Description**: A scan discovers multiple vulnerabilities
- **Foreign Key**: Vulnerability.scan_id → Scan.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Vulnerabilities stored as JSON in Scan.vulnerabilities_json

#### 3. Scan → FuzzPlan (One-to-One)
- **Cardinality**: 1:1
- **Description**: Each scan has one fuzz plan
- **Foreign Key**: FuzzPlan.scan_id → Scan.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Generated from static_findings.json

#### 4. FuzzPlan → FuzzTarget (One-to-Many)
- **Cardinality**: 1:N
- **Description**: A fuzz plan contains multiple targets
- **Foreign Key**: FuzzTarget.fuzz_plan_id → FuzzPlan.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Maximum 100 targets per plan

#### 5. FuzzTarget → Harness (One-to-One)
- **Cardinality**: 1:1
- **Description**: Each target has one generated harness
- **Foreign Key**: Harness.fuzz_target_id → FuzzTarget.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Harness code generated using toolbox templates

#### 6. Harness → BuildResult (One-to-One)
- **Cardinality**: 1:1
- **Description**: Each harness has one build result
- **Foreign Key**: BuildResult.harness_id → Harness.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Build timeout: 60 seconds

#### 7. Scan → FuzzCampaign (One-to-One)
- **Cardinality**: 1:1
- **Description**: Each scan has one fuzzing campaign
- **Foreign Key**: FuzzCampaign.scan_id → Scan.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Campaign executes all built targets

#### 8. FuzzCampaign → FuzzExecution (One-to-Many)
- **Cardinality**: 1:N
- **Description**: A campaign has multiple target executions
- **Foreign Key**: FuzzExecution.campaign_id → FuzzCampaign.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: One execution per built target

#### 9. FuzzExecution → CrashArtifact (One-to-Many)
- **Cardinality**: 1:N
- **Description**: An execution can discover multiple crashes
- **Foreign Key**: CrashArtifact.execution_id → FuzzExecution.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Crashes preserved for 30 days

#### 10. FuzzCampaign → TriageResult (One-to-One)
- **Cardinality**: 1:1
- **Description**: Each campaign has one triage result
- **Foreign Key**: TriageResult.campaign_id → FuzzCampaign.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Generated after campaign completion

#### 11. TriageResult → TriageAnalysis (One-to-Many)
- **Cardinality**: 1:N
- **Description**: A triage result contains multiple analyses
- **Foreign Key**: TriageAnalysis.triage_result_id → TriageResult.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: One analysis per unique crash

#### 12. CrashArtifact → TriageAnalysis (One-to-One)
- **Cardinality**: 1:1
- **Description**: Each crash has one triage analysis
- **Foreign Key**: TriageAnalysis.crash_artifact_id → CrashArtifact.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Analysis includes severity and exploitability

#### 13. Scan → Patch (One-to-Many)
- **Cardinality**: 1:N
- **Description**: A scan generates multiple patches
- **Foreign Key**: Patch.scan_id → Scan.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Patches stored as JSON in Scan.patches_json

#### 14. Vulnerability → Patch (One-to-Many)
- **Cardinality**: 1:N (optional)
- **Description**: A vulnerability can have multiple patch attempts
- **Foreign Key**: Patch.vulnerability_id → Vulnerability.id
- **Cascade**: ON DELETE SET NULL
- **Business Rule**: Patches can also be generated from crashes

#### 15. TriageAnalysis → Patch (One-to-Many)
- **Cardinality**: 1:N (optional)
- **Description**: A crash analysis can generate patches
- **Foreign Key**: Patch.triage_analysis_id → TriageAnalysis.id
- **Cascade**: ON DELETE SET NULL
- **Business Rule**: Patches address discovered crashes

#### 16. Patch → ValidationResult (One-to-One)
- **Cardinality**: 1:1
- **Description**: Each patch has one validation result
- **Foreign Key**: ValidationResult.patch_id → Patch.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Validation in gVisor sandbox

#### 17. User → APIKey (One-to-Many)
- **Cardinality**: 1:N
- **Description**: A user can have multiple API keys
- **Foreign Key**: APIKey.user_id → User.id
- **Cascade**: ON DELETE CASCADE
- **Business Rule**: Keys are bcrypt hashed

#### 18. Scan → WorkflowExecution (One-to-One)
- **Cardinality**: 1:1 (optional)
- **Description**: A scan can be triggered by CI/CD workflow
- **Foreign Key**: WorkflowExecution.scan_id → Scan.id
- **Cascade**: ON DELETE SET NULL
- **Business Rule**: Automated scans have workflow execution


---

## Entity-Relationship Diagram (ERD)

### Complete ERD (Crow's Foot Notation)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AutoVulRepair ERD                                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐
│      User        │
├──────────────────┤
│ PK id            │
│    github_id     │
│    username      │
│    email         │
│    access_token  │
│    api_keys      │
│    role          │
│    created_at    │
│    last_login    │
└──────────────────┘
        │
        │ 1
        │
        │ N
        ▼
┌──────────────────┐         ┌──────────────────┐
│     APIKey       │         │  WorkflowExec    │
├──────────────────┤         ├──────────────────┤
│ PK id            │         │ PK id            │
│ FK user_id       │         │ FK scan_id       │
│    key_hash      │         │    trigger_type  │
│    name          │         │    ci_system     │
│    created_at    │         │    pipeline      │
│    last_used     │         │    start_time    │
│    expires_at    │         │    end_time      │
│    is_active     │         │    status        │
└──────────────────┘         │    blocked_reason│
                             └──────────────────┘
                                      ▲
                                      │ 1
                                      │
                                      │ 1
┌──────────────────────────────────────────────────────────────────────────────┐
│                                  Scan                                         │
├──────────────────────────────────────────────────────────────────────────────┤
│ PK id                                                                         │
│ FK user_id (nullable)                                                         │
│    source_type (zip, repo_url, code_snippet)                                 │
│    source_path                                                                │
│    repo_url                                                                   │
│    analysis_tool (cppcheck, codeql)                                           │
│    status (queued, running, completed, failed)                                │
│    artifacts_path                                                             │
│    vulnerabilities_json                                                       │
│    patches_json                                                               │
│    created_at                                                                 │
│    updated_at                                                                 │
└──────────────────────────────────────────────────────────────────────────────┘
        │                    │                    │                    │
        │ 1                  │ 1                  │ 1                  │ 1
        │                    │                    │                    │
        │ N                  │ 1                  │ 1                  │ N
        ▼                    ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│Vulnerability │    │  FuzzPlan    │    │FuzzCampaign  │    │    Patch     │
├──────────────┤    ├──────────────┤    ├──────────────┤    ├──────────────┤
│ PK id        │    │ PK id        │    │ PK id        │    │ PK id        │
│ FK scan_id   │    │ FK scan_id   │    │ FK scan_id   │    │ FK scan_id   │
│    rule_id   │    │    version   │    │    start_time│    │ FK vuln_id   │
│    file      │    │    generated │    │    end_time  │    │ FK triage_id │
│    file_stem │    │    total_find│    │    runtime   │    │    code      │
│    function  │    │    dedup_tgt │    │    total_tgt │    │    diff      │
│    line_num  │    │    bug_class │    │    completed │    │    method    │
│    column    │    │    sanitizers│    │    total_exec│    │    llm_model │
│    severity  │    │    sigs_ext  │    │    crashes   │    │    compile   │
│    confidence│    │    sigs_fail │    │    status    │    │    attempts  │
│    message   │    │    targets   │    └──────────────┘    │    validate  │
│    cwe       │    └──────────────┘            │            │    perf_imp  │
│    priority  │            │                   │ 1          │    status    │
│    bug_class │            │ 1                 │            │    created   │
│    context   │            │                   │ N          │    applied   │
└──────────────┘            │ N                 ▼            └──────────────┘
        │                   ▼          ┌──────────────┐              │
        │ 1         ┌──────────────┐   │FuzzExecution │              │ 1
        │           │  FuzzTarget  │   ├──────────────┤              │
        │ N         ├──────────────┤   │ PK id        │              │ 1
        ▼           │ PK id        │   │ FK campaign  │              ▼
┌──────────────┐    │ FK plan_id   │   │ FK build_id  │    ┌──────────────┐
│    Patch     │    │    target_id │   │    target    │    │ Validation   │
│  (duplicate) │    │    source    │   │    start     │    │   Result     │
└──────────────┘    │    file_stem │   │    end       │    ├──────────────┤
                    │    function  │   │    runtime   │    │ PK id        │
                    │    bug_class │   │    executions│    │ FK patch_id  │
                    │    rule_id   │   │    crashes   │    │    sandbox   │
                    │    severity  │   │    coverage  │    │    exec_stat │
                    │    confidence│   │    status    │    │    perf_base │
                    │    line_num  │   │    output    │    │    perf_patch│
                    │    column    │   └──────────────┘    │    perf_delta│
                    │    message   │            │           │    tests_pass│
                    │    cwe       │            │ 1         │    tests_fail│
                    │    sanitizers│            │           │    anomalies │
                    │    seeds     │            │ N         │    time      │
                    │    dicts     │            ▼           │    timestamp │
                    │    priority  │   ┌──────────────┐    └──────────────┘
                    │    harness_t │   │CrashArtifact │
                    │    signature │   ├──────────────┤
                    │    sig_status│   │ PK id        │
                    └──────────────┘   │ FK exec_id   │
                            │          │    filename  │
                            │ 1        │    path      │
                            │          │    size      │
                            │ 1        │    type      │
                            ▼          │    sanitizer │
                    ┌──────────────┐   │    stack     │
                    │   Harness    │   │    discovered│
                    ├──────────────┤   └──────────────┘
                    │ PK id        │            │
                    │ FK target_id │            │ 1
                    │    filename  │            │
                    │    path      │            │ 1
                    │    full_path │            ▼
                    │    type      │   ┌──────────────┐
                    │    code      │   │TriageAnalysis│
                    │    size      │   ├──────────────┤
                    │    lines     │   │ PK id        │
                    │    generated │   │ FK triage_id │
                    │    version   │   │ FK crash_id  │
                    │    build_stat│   │    type      │
                    └──────────────┘   │    severity  │
                            │          │    exploit   │
                            │ 1        │    cvss      │
                            │          │    root_cause│
                            │ 1        │    stack     │
                            ▼          │    duplicate │
                    ┌──────────────┐   │    recommend │
                    │ BuildResult  │   └──────────────┘
                    ├──────────────┤            ▲
                    │ PK id        │            │ N
                    │ FK harness_id│            │
                    │    target    │            │ 1
                    │    output    │   ┌──────────────┐
                    │    status    │   │TriageResult  │
                    │    time      │   ├──────────────┤
                    │    command   │   │ PK id        │
                    │    log       │   │ FK campaign  │
                    │    compiler  │   │    timestamp │
                    │    sanitizers│   │    total     │
                    │    timestamp │   │    unique    │
                    └──────────────┘   │    critical  │
                                       │    high      │
                                       │    medium    │
                                       │    low       │
                                       │    exploitable│
                                       │    likely_exp│
                                       │    unlikely  │
                                       │    summary   │
                                       └──────────────┘

┌──────────────────┐
│ MetricsSnapshot  │
├──────────────────┤
│ PK id            │
│    timestamp     │
│    scan_success  │
│    patch_success │
│    avg_scan_time │
│    avg_patch_time│
│    total_scans   │
│    total_vulns   │
│    total_patches │
│    coverage      │
│    system_health │
└──────────────────┘
```


---

## Domain Services

Domain services encapsulate business logic that doesn't naturally fit within a single entity.

### 1. **ScanOrchestrationService**
Coordinates the entire scan workflow across modules.

**Responsibilities:**
- Create and initialize scan
- Queue analysis tasks to Celery
- Monitor scan progress
- Update scan status
- Handle failures and retries

**Key Methods:**
- `create_scan(source, analysis_tool, user_id)`
- `execute_scan_pipeline(scan_id)`
- `get_scan_status(scan_id)`
- `cancel_scan(scan_id)`

---

### 2. **FuzzPlanGenerationService**
Generates fuzz plans from static analysis findings.

**Responsibilities:**
- Load and validate static findings
- Infer bug classes from rule IDs
- Calculate priority scores
- Deduplicate targets
- Extract function signatures
- Generate complete fuzz plan

**Key Methods:**
- `generate_fuzz_plan(scan_id)`
- `infer_bug_class(rule_id)`
- `calculate_priority(finding)`
- `deduplicate_findings(findings)`
- `extract_signature(source_file, function)`

---

### 3. **HarnessGenerationService**
Generates fuzzing harnesses using toolbox approach.

**Responsibilities:**
- Select appropriate harness type
- Generate harness code from templates
- Include function signatures
- Add bug class hints
- Create build scripts and documentation

**Key Methods:**
- `generate_harnesses(fuzz_plan_id)`
- `select_harness_type(target)`
- `generate_harness_code(target, type)`
- `create_build_script(harnesses)`

---

### 4. **BuildOrchestrationService**
Compiles harnesses into executable fuzz targets.

**Responsibilities:**
- Detect available compilers
- Patch source files for fuzzing
- Compile source object files
- Link harnesses with source
- Apply sanitizers
- Generate build logs

**Key Methods:**
- `build_all_targets(scan_id)`
- `build_single_target(harness_id)`
- `patch_source_file(file_path)`
- `get_build_results(scan_id)`

---

### 5. **FuzzExecutionService**
Executes fuzzing campaigns and collects crashes.

**Responsibilities:**
- Configure fuzzing runtime
- Execute LibFuzzer targets
- Monitor for crashes
- Collect crash artifacts
- Track coverage metrics
- Generate campaign results

**Key Methods:**
- `execute_campaign(scan_id, runtime)`
- `execute_target(build_result_id)`
- `collect_crashes(execution_id)`
- `get_campaign_results(scan_id)`

---

### 6. **CrashTriageService**
Analyzes and classifies discovered crashes.

**Responsibilities:**
- Extract crash types from artifacts
- Assess severity and exploitability
- Calculate CVSS scores
- Deduplicate similar crashes
- Extract stack traces and root causes
- Generate triage reports

**Key Methods:**
- `analyze_campaign(campaign_id)`
- `analyze_crash(crash_artifact_id)`
- `assess_severity(crash_type)`
- `assess_exploitability(crash_type)`
- `calculate_cvss(severity, exploitability)`
- `deduplicate_crashes(crashes)`

---

### 7. **PatchGenerationService**
Generates AI-powered vulnerability patches using Vul-RAG.

**Responsibilities:**
- Rank vulnerabilities by priority
- Query RAG knowledge base
- Generate LLM prompts with context
- Request patches from LLM
- Apply compiler feedback loop
- Store patch suggestions

**Key Methods:**
- `generate_patches(scan_id)`
- `rank_vulnerabilities(vulnerabilities)`
- `query_rag_knowledge_base(vulnerability)`
- `generate_patch_with_llm(vulnerability, examples)`
- `apply_compiler_feedback(patch, errors)`

---

### 8. **PatchValidationService**
Validates patches in isolated sandbox environment.

**Responsibilities:**
- Create gVisor sandbox instance
- Apply patch to source code
- Compile patched code
- Execute in sandbox
- Run performance benchmarks
- Execute regression tests
- Detect anomalies
- Generate validation report

**Key Methods:**
- `validate_patch(patch_id)`
- `create_sandbox()`
- `run_benchmarks(patched_code)`
- `run_regression_tests(patched_code)`
- `detect_anomalies(execution)`

---

### 9. **WorkflowOrchestrationService**
Manages CI/CD automated workflows.

**Responsibilities:**
- Configure pipeline stages
- Handle webhook triggers
- Create Kubernetes jobs
- Execute pipeline stages
- Evaluate security gates
- Send notifications
- Clean up resources

**Key Methods:**
- `configure_workflow(scan_id, ci_system)`
- `trigger_workflow(webhook_payload)`
- `execute_pipeline(workflow_id)`
- `evaluate_security_gates(scan_results)`
- `block_deployment(reason)`

---

### 10. **MetricsCollectionService**
Collects and exports system metrics.

**Responsibilities:**
- Collect performance metrics
- Calculate success rates
- Track resource usage
- Export to Prometheus
- Generate evaluation reports
- Maintain audit logs

**Key Methods:**
- `collect_metrics()`
- `calculate_success_rates()`
- `export_to_prometheus(metrics)`
- `generate_evaluation_report(time_range)`
- `export_audit_logs()`


---

## Value Objects

Value objects are immutable objects defined by their attributes rather than identity.

### 1. **FunctionSignature**
Represents a C/C++ function signature.

**Attributes:**
- `return_type` (String): Function return type
- `function_name` (String): Function name
- `parameters` (Array): List of Parameter objects
- `is_variadic` (Boolean): Has variadic arguments (...)

**Methods:**
- `to_dict()`: Convert to dictionary
- `from_dict(data)`: Create from dictionary
- `to_string()`: Format as C++ signature

---

### 2. **Parameter**
Represents a function parameter.

**Attributes:**
- `type` (String): Parameter type (int, char*, etc.)
- `name` (String): Parameter name
- `is_pointer` (Boolean): Is pointer type
- `is_const` (Boolean): Is const qualified
- `is_reference` (Boolean): Is reference type

---

### 3. **CodeContext**
Represents code context around a vulnerability.

**Attributes:**
- `file_path` (String): Source file path
- `line_number` (Integer): Target line
- `lines` (Array): List of CodeLine objects
- `language` (String): Programming language

---

### 4. **CodeLine**
Represents a single line of code with metadata.

**Attributes:**
- `line_number` (Integer): Line number
- `code` (String): Code content
- `is_vulnerable` (Boolean): Is the vulnerability line
- `is_highlighted` (Boolean): Should be highlighted

---

### 5. **StackFrame**
Represents a stack trace frame.

**Attributes:**
- `frame_number` (Integer): Frame index
- `address` (String): Memory address
- `function` (String): Function name
- `file` (String): Source file
- `line` (Integer): Line number

---

### 6. **SanitizerConfig**
Represents sanitizer configuration.

**Attributes:**
- `sanitizers` (Array): List of sanitizer names
- `flags` (Array): Compiler flags
- `environment_vars` (Dict): Environment variables

**Methods:**
- `to_compiler_flags()`: Generate compiler flags
- `to_env_vars()`: Generate environment variables

---

### 7. **BugClass**
Represents a bug classification.

**Attributes:**
- `name` (String): Bug class name (OOB, UAF, etc.)
- `description` (String): Description
- `severity_weight` (Float): Severity multiplier
- `recommended_sanitizers` (Array): Sanitizer list
- `cwe_mappings` (Array): Related CWE IDs

---

### 8. **CVSSScore**
Represents a CVSS vulnerability score.

**Attributes:**
- `base_score` (Float): Base CVSS score (0-10)
- `severity` (String): Critical, High, Medium, Low
- `exploitability` (String): Exploitability assessment
- `impact` (String): Impact assessment
- `vector_string` (String): CVSS vector string

**Methods:**
- `calculate(severity, exploitability)`: Calculate score
- `to_string()`: Format as string

---

### 9. **PerformanceMetrics**
Represents performance benchmark results.

**Attributes:**
- `execution_time` (Float): Average execution time
- `memory_usage` (Integer): Peak memory usage
- `cpu_cycles` (Integer): CPU cycles
- `iterations` (Integer): Number of iterations

**Methods:**
- `calculate_delta(baseline, patched)`: Calculate percentage change
- `is_acceptable(threshold)`: Check if within threshold

---

### 10. **DiffPatch**
Represents a code patch in unified diff format.

**Attributes:**
- `original_file` (String): Original file path
- `patched_file` (String): Patched file path
- `hunks` (Array): List of DiffHunk objects
- `additions` (Integer): Lines added
- `deletions` (Integer): Lines deleted

**Methods:**
- `apply_to_file(file_path)`: Apply patch to file
- `to_unified_diff()`: Generate unified diff string

---

## Aggregates

Aggregates are clusters of entities and value objects with a root entity.

### 1. **Scan Aggregate**
**Root**: Scan
**Entities**: Vulnerability, FuzzPlan, FuzzCampaign, Patch
**Invariants**:
- Scan must have valid source
- Status transitions must be valid
- Artifacts must be retained for 30 days

---

### 2. **FuzzPlan Aggregate**
**Root**: FuzzPlan
**Entities**: FuzzTarget, Harness, BuildResult
**Invariants**:
- Maximum 100 targets per plan
- Each target must have unique target_id
- Harness filename must follow convention

---

### 3. **FuzzCampaign Aggregate**
**Root**: FuzzCampaign
**Entities**: FuzzExecution, CrashArtifact, TriageResult, TriageAnalysis
**Invariants**:
- One execution per built target
- Crashes must be preserved
- Triage must deduplicate crashes

---

### 4. **Patch Aggregate**
**Root**: Patch
**Entities**: ValidationResult
**Invariants**:
- Must compile before validation
- Performance impact < 5%
- All regression tests must pass

---

## Domain Events

Domain events represent significant occurrences in the domain.

### 1. **ScanCreated**
- `scan_id`
- `user_id`
- `source_type`
- `timestamp`

### 2. **ScanCompleted**
- `scan_id`
- `vulnerabilities_count`
- `duration`
- `timestamp`

### 3. **ScanFailed**
- `scan_id`
- `error_message`
- `timestamp`

### 4. **FuzzPlanGenerated**
- `scan_id`
- `targets_count`
- `bug_class_breakdown`
- `timestamp`

### 5. **HarnessesGenerated**
- `scan_id`
- `harnesses_count`
- `toolbox_types`
- `timestamp`

### 6. **BuildCompleted**
- `scan_id`
- `successful_builds`
- `failed_builds`
- `timestamp`

### 7. **FuzzCampaignStarted**
- `campaign_id`
- `targets_count`
- `runtime_per_target`
- `timestamp`

### 8. **FuzzCampaignCompleted**
- `campaign_id`
- `crashes_found`
- `coverage`
- `timestamp`

### 9. **CrashDiscovered**
- `execution_id`
- `crash_type`
- `severity`
- `timestamp`

### 10. **TriageCompleted**
- `campaign_id`
- `unique_crashes`
- `critical_count`
- `timestamp`

### 11. **PatchGenerated**
- `patch_id`
- `vulnerability_id`
- `llm_model`
- `timestamp`

### 12. **PatchValidated**
- `patch_id`
- `validation_status`
- `performance_delta`
- `timestamp`

### 13. **PatchApplied**
- `patch_id`
- `scan_id`
- `timestamp`

### 14. **WorkflowTriggered**
- `workflow_id`
- `trigger_type`
- `ci_system`
- `timestamp`

### 15. **DeploymentBlocked**
- `workflow_id`
- `reason`
- `critical_vulnerabilities`
- `timestamp`


---

## Data Flow Diagram

### Complete System Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AutoVulRepair Data Flow                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐
│Developer │
└────┬─────┘
     │
     │ 1. Submit Code (GitHub URL / ZIP / Snippet)
     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            MODULE 1: Static Analysis                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐                  │
│  │  Scan    │───▶│  Cppcheck/   │───▶│ static_findings  │                  │
│  │  Entity  │    │  CodeQL      │    │     .json        │                  │
│  └──────────┘    └──────────────┘    └──────────────────┘                  │
│                                                │                              │
│                                                │ Contains:                    │
│                                                │ - Vulnerabilities            │
│                                                │ - Rule IDs                   │
│                                                │ - File locations             │
│                                                │ - Severity                   │
│                                                │ - CWE mappings               │
└────────────────────────────────────────────────┼──────────────────────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MODULE 2: Dynamic Analysis (Fuzzing)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Step 1: Fuzz Plan Generation                                                │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │ static_findings  │───▶│  FuzzPlan        │───▶│  fuzzplan.json   │      │
│  │     .json        │    │  Generator       │    │                  │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            │ Contains:        │
│                                                            │ - FuzzTargets    │
│                                                            │ - Bug classes    │
│                                                            │ - Priorities     │
│                                                            │ - Sanitizers     │
│                                                            │ - Signatures     │
│                                                            ▼                  │
│  Step 2: Harness Generation                                                  │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  fuzzplan.json   │───▶│  Harness         │───▶│  Harness .cc     │      │
│  │                  │    │  Generator       │    │  files           │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            │ Types:           │
│                                                            │ - bytes_to_api   │
│                                                            │ - fdp_adapter    │
│                                                            │ - parser_wrapper │
│                                                            │ - api_sequence   │
│                                                            ▼                  │
│  Step 3: Build Orchestration                                                 │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Harness .cc     │───▶│  Build           │───▶│  Fuzz Target     │      │
│  │  files           │    │  Orchestrator    │    │  Binaries        │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            │ With:            │
│                                                            │ - Sanitizers     │
│                                                            │ - Instrumentation│
│                                                            │ - Source linking │
│                                                            ▼                  │
│  Step 4: Fuzz Execution                                                      │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Fuzz Target     │───▶│  LibFuzzer       │───▶│  Crash           │      │
│  │  Binaries        │    │  Executor        │    │  Artifacts       │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            │ Contains:        │
│                                                            │ - Crash inputs   │
│                                                            │ - Stack traces   │
│                                                            │ - Sanitizer logs │
│                                                            ▼                  │
│  Step 5: Crash Triage                                                        │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Crash           │───▶│  Triage          │───▶│  triage_results  │      │
│  │  Artifacts       │    │  Analyzer        │    │     .json        │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            │ Contains:        │
│                                                            │ - Crash types    │
│                                                            │ - Severity       │
│                                                            │ - Exploitability │
│                                                            │ - CVSS scores    │
└────────────────────────────────────────────────────┼──────────────────────────┘
                                                     │
                                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MODULE 3: Patch Generation (Vul-RAG)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────┐    ┌──────────────────┐                               │
│  │ static_findings  │───▶│                  │                               │
│  │     .json        │    │  Vulnerability   │                               │
│  └──────────────────┘    │  Ranking         │                               │
│                          │                  │                               │
│  ┌──────────────────┐    │                  │    ┌──────────────────┐      │
│  │ triage_results   │───▶│                  │───▶│ vulnerability_   │      │
│  │     .json        │    │                  │    │  ranking.json    │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            ▼                  │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │ RAG Knowledge    │───▶│  LLM Service     │───▶│  Patch Code      │      │
│  │ Base             │    │  (OpenAI/Claude) │    │                  │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                  │                         │                  │
│                                  │ Feedback Loop           │                  │
│                                  │ (max 3 iterations)      │                  │
│                                  ▼                         ▼                  │
│                          ┌──────────────────┐    ┌──────────────────┐      │
│                          │  Compiler        │───▶│ fix_suggestions  │      │
│                          │  Validation      │    │     .json        │      │
│                          └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            │ Contains:        │
│                                                            │ - Patch code     │
│                                                            │ - Diffs          │
│                                                            │ - Compilation    │
│                                                            │ - Metadata       │
└────────────────────────────────────────────────────┼──────────────────────────┘
                                                     │
                                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      MODULE 5: Sandbox Validation                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │ fix_suggestions  │───▶│  gVisor          │───▶│  Execution       │      │
│  │     .json        │    │  Sandbox         │    │  Results         │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                  │                         │                  │
│                                  ▼                         ▼                  │
│                          ┌──────────────────┐    ┌──────────────────┐      │
│                          │  Google          │───▶│  Performance     │      │
│                          │  Benchmark       │    │  Metrics         │      │
│                          └──────────────────┘    └──────────────────┘      │
│                                  │                         │                  │
│                                  ▼                         ▼                  │
│                          ┌──────────────────┐    ┌──────────────────┐      │
│                          │  Regression      │───▶│  Validation      │      │
│                          │  Tests           │    │  Report          │      │
│                          └──────────────────┘    └──────────────────┘      │
│                                                            │                  │
│                                                            │ Contains:        │
│                                                            │ - Pass/Fail      │
│                                                            │ - Perf delta     │
│                                                            │ - Anomalies      │
│                                                            │ - Test results   │
└────────────────────────────────────────────────────┼──────────────────────────┘
                                                     │
                                                     ▼
                                            ┌──────────────┐
                                            │  Developer   │
                                            │  Reviews &   │
                                            │  Accepts     │
                                            └──────────────┘
```


---

## Database Schema (SQLite)

### Current Implementation

```sql
-- Scans table (main entity)
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

-- Indexes for performance
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);
```

### Recommended Extended Schema

```sql
-- Users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    github_id VARCHAR(50) UNIQUE NOT NULL,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    access_token TEXT,
    api_keys JSON,
    role VARCHAR(20) DEFAULT 'developer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

-- API Keys table
CREATE TABLE api_keys (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(100),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,
    expires_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL,
    rule_id VARCHAR(100) NOT NULL,
    file TEXT NOT NULL,
    file_stem VARCHAR(255),
    function VARCHAR(255),
    line_number INTEGER,
    column_number INTEGER,
    severity VARCHAR(20),
    confidence VARCHAR(20),
    message TEXT,
    cwe VARCHAR(20),
    priority_score REAL,
    bug_class VARCHAR(50),
    code_context JSON,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_bug_class ON vulnerabilities(bug_class);

-- Fuzz Plans table
CREATE TABLE fuzz_plans (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL UNIQUE,
    version VARCHAR(20),
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_findings INTEGER,
    deduplicated_targets INTEGER,
    bug_class_breakdown JSON,
    sanitizers_used JSON,
    signatures_extracted INTEGER,
    signatures_failed INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Fuzz Targets table
CREATE TABLE fuzz_targets (
    id VARCHAR(36) PRIMARY KEY,
    fuzz_plan_id VARCHAR(36) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    source_file TEXT,
    file_stem VARCHAR(255),
    function_name VARCHAR(255),
    bug_class VARCHAR(50),
    rule_id VARCHAR(100),
    severity VARCHAR(20),
    confidence VARCHAR(20),
    line_number INTEGER,
    column_number INTEGER,
    message TEXT,
    cwe VARCHAR(20),
    sanitizers JSON,
    seed_directories JSON,
    dictionaries JSON,
    priority REAL,
    harness_type VARCHAR(50),
    function_signature JSON,
    signature_status VARCHAR(50),
    FOREIGN KEY (fuzz_plan_id) REFERENCES fuzz_plans(id) ON DELETE CASCADE
);

CREATE INDEX idx_fuzz_targets_plan_id ON fuzz_targets(fuzz_plan_id);
CREATE INDEX idx_fuzz_targets_priority ON fuzz_targets(priority DESC);

-- Harnesses table
CREATE TABLE harnesses (
    id VARCHAR(36) PRIMARY KEY,
    fuzz_target_id VARCHAR(36) NOT NULL UNIQUE,
    filename VARCHAR(255) NOT NULL,
    file_path TEXT,
    full_path TEXT,
    harness_type VARCHAR(50),
    code TEXT,
    file_size INTEGER,
    lines INTEGER,
    generation_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    generator_version VARCHAR(20),
    build_status VARCHAR(20) DEFAULT 'not_built',
    FOREIGN KEY (fuzz_target_id) REFERENCES fuzz_targets(id) ON DELETE CASCADE
);

-- Build Results table
CREATE TABLE build_results (
    id VARCHAR(36) PRIMARY KEY,
    harness_id VARCHAR(36) NOT NULL UNIQUE,
    target_name VARCHAR(255),
    output_path TEXT,
    status VARCHAR(20),
    build_time REAL,
    command TEXT,
    log TEXT,
    compiler VARCHAR(50),
    sanitizers VARCHAR(255),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (harness_id) REFERENCES harnesses(id) ON DELETE CASCADE
);

-- Fuzz Campaigns table
CREATE TABLE fuzz_campaigns (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL UNIQUE,
    start_time DATETIME,
    end_time DATETIME,
    runtime_per_target INTEGER,
    total_targets INTEGER,
    completed_targets INTEGER,
    total_executions INTEGER,
    total_crashes INTEGER,
    status VARCHAR(20),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Fuzz Executions table
CREATE TABLE fuzz_executions (
    id VARCHAR(36) PRIMARY KEY,
    campaign_id VARCHAR(36) NOT NULL,
    build_result_id VARCHAR(36) NOT NULL,
    target_name VARCHAR(255),
    start_time DATETIME,
    end_time DATETIME,
    runtime INTEGER,
    executions INTEGER,
    crashes_found INTEGER,
    coverage REAL,
    status VARCHAR(20),
    output TEXT,
    FOREIGN KEY (campaign_id) REFERENCES fuzz_campaigns(id) ON DELETE CASCADE,
    FOREIGN KEY (build_result_id) REFERENCES build_results(id) ON DELETE CASCADE
);

CREATE INDEX idx_fuzz_executions_campaign_id ON fuzz_executions(campaign_id);

-- Crash Artifacts table
CREATE TABLE crash_artifacts (
    id VARCHAR(36) PRIMARY KEY,
    execution_id VARCHAR(36) NOT NULL,
    filename VARCHAR(255),
    file_path TEXT,
    file_size INTEGER,
    crash_type VARCHAR(100),
    sanitizer_output TEXT,
    stack_trace JSON,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (execution_id) REFERENCES fuzz_executions(id) ON DELETE CASCADE
);

CREATE INDEX idx_crash_artifacts_execution_id ON crash_artifacts(execution_id);
CREATE INDEX idx_crash_artifacts_crash_type ON crash_artifacts(crash_type);

-- Triage Results table
CREATE TABLE triage_results (
    id VARCHAR(36) PRIMARY KEY,
    campaign_id VARCHAR(36) NOT NULL UNIQUE,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_crashes INTEGER,
    unique_crashes INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    exploitable_count INTEGER,
    likely_exploitable_count INTEGER,
    unlikely_exploitable_count INTEGER,
    summary JSON,
    FOREIGN KEY (campaign_id) REFERENCES fuzz_campaigns(id) ON DELETE CASCADE
);

-- Triage Analyses table
CREATE TABLE triage_analyses (
    id VARCHAR(36) PRIMARY KEY,
    triage_result_id VARCHAR(36) NOT NULL,
    crash_artifact_id VARCHAR(36) NOT NULL UNIQUE,
    crash_type VARCHAR(100),
    severity VARCHAR(20),
    exploitability VARCHAR(50),
    cvss_score REAL,
    root_cause TEXT,
    stack_trace JSON,
    is_duplicate BOOLEAN DEFAULT FALSE,
    recommendations TEXT,
    FOREIGN KEY (triage_result_id) REFERENCES triage_results(id) ON DELETE CASCADE,
    FOREIGN KEY (crash_artifact_id) REFERENCES crash_artifacts(id) ON DELETE CASCADE
);

CREATE INDEX idx_triage_analyses_result_id ON triage_analyses(triage_result_id);
CREATE INDEX idx_triage_analyses_severity ON triage_analyses(severity);

-- Patches table
CREATE TABLE patches (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL,
    vulnerability_id VARCHAR(36),
    triage_analysis_id VARCHAR(36),
    patch_code TEXT,
    diff TEXT,
    generation_method VARCHAR(50),
    llm_model VARCHAR(100),
    compilation_status VARCHAR(20),
    compilation_attempts INTEGER DEFAULT 0,
    validation_status VARCHAR(20),
    performance_impact REAL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    applied_at DATETIME,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    FOREIGN KEY (triage_analysis_id) REFERENCES triage_analyses(id) ON DELETE SET NULL
);

CREATE INDEX idx_patches_scan_id ON patches(scan_id);
CREATE INDEX idx_patches_status ON patches(status);

-- Validation Results table
CREATE TABLE validation_results (
    id VARCHAR(36) PRIMARY KEY,
    patch_id VARCHAR(36) NOT NULL UNIQUE,
    sandbox_type VARCHAR(50),
    execution_status VARCHAR(20),
    performance_baseline JSON,
    performance_patched JSON,
    performance_delta REAL,
    regression_tests_passed INTEGER,
    regression_tests_failed INTEGER,
    anomalies_detected JSON,
    validation_time REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patch_id) REFERENCES patches(id) ON DELETE CASCADE
);

-- Workflow Executions table
CREATE TABLE workflow_executions (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL UNIQUE,
    trigger_type VARCHAR(50),
    ci_system VARCHAR(50),
    pipeline_stages JSON,
    start_time DATETIME,
    end_time DATETIME,
    status VARCHAR(20),
    blocked_reason TEXT,
    webhook_payload JSON,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

-- Metrics Snapshots table
CREATE TABLE metrics_snapshots (
    id VARCHAR(36) PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    scan_success_rate REAL,
    patch_success_rate REAL,
    average_scan_time REAL,
    average_patch_time REAL,
    total_scans INTEGER,
    total_vulnerabilities INTEGER,
    total_patches INTEGER,
    code_coverage REAL,
    system_health JSON
);

CREATE INDEX idx_metrics_snapshots_timestamp ON metrics_snapshots(timestamp);
```


---

## Domain Model Summary

### Key Domain Concepts

#### 1. **Scan Lifecycle**
```
Created → Queued → Running → Completed/Failed
```

#### 2. **Analysis Pipeline**
```
Static Analysis → Fuzz Plan → Harness Generation → Build → Execution → Triage → Patching → Validation
```

#### 3. **Bug Classification Hierarchy**
```
Bug Class (OOB, UAF, Integer-UB, etc.)
    ├─ Severity (Critical, High, Medium, Low)
    ├─ Exploitability (Exploitable, Likely, Unlikely)
    └─ CVSS Score (0-10)
```

#### 4. **Harness Types (Toolbox)**
```
1. bytes_to_api: Direct byte stream → function call
2. fdp_adapter: FuzzedDataProvider for typed parameters
3. parser_wrapper: Parser-specific with null-termination
4. api_sequence: Stateful API with init/cleanup
```

#### 5. **Sanitizer Selection**
```
OOB → ASan + UBSan
UAF → ASan
Integer-UB → UBSan
Null-Deref → ASan + UBSan
Race-Condition → TSan
Memory-Leak → LSan
```

#### 6. **Priority Calculation**
```
Priority = base_score × confidence_boost × bug_class_boost × cwe_boost × location_boost
```

#### 7. **Patch Generation Flow**
```
Vulnerability → RAG Query → LLM Prompt → Patch Code → Compiler Feedback (max 3) → Validated Patch
```

#### 8. **Validation Criteria**
```
✓ Compiles successfully
✓ Performance delta < 5%
✓ All regression tests pass
✓ No sandbox anomalies
```

---

## Business Rules Summary

### Scan Management
1. Public scans (user_id = NULL) have limited features
2. Scan artifacts retained for minimum 30 days
3. Maximum scan size: 1GB repository, 100MB ZIP
4. Scan timeout: 5 minutes for typical codebases

### Fuzz Plan Generation
1. Maximum 100 targets per plan (configurable)
2. Targets deduplicated by <file_stem>::<function>
3. Multiple bug classes per function allowed (max 3)
4. Function signatures extracted when source available

### Harness Generation
1. Filename convention: fuzz_<file_stem>_<function>.cc
2. Harness type inferred from function characteristics
3. Bug class hints included in generated code
4. Build scripts and documentation auto-generated

### Build Orchestration
1. Build timeout: 60 seconds per target
2. Source main() wrapped with preprocessor guards
3. Deprecated functions (gets) auto-patched
4. Shared source object file linked when available

### Fuzzing Execution
1. Default runtime: 5 minutes per target
2. Configurable: 1-60 minutes per target
3. Crashes preserved for 30 days minimum
4. Coverage tracked via LibFuzzer stats

### Crash Triage
1. Crashes deduplicated by stack trace similarity
2. Severity assessed from crash type
3. Exploitability evaluated per crash
4. CVSS scores calculated automatically

### Patch Generation
1. Compiler feedback loop: maximum 3 iterations
2. Patches must compile before validation
3. Patches ranked by vulnerability priority
4. RAG knowledge base used for context

### Patch Validation
1. Executed in isolated gVisor sandbox
2. Performance degradation threshold: 5%
3. All regression tests must pass
4. Anomalies include crashes, violations, leaks

### CI/CD Integration
1. Deployment blocked on critical vulnerabilities
2. Webhook integration with HMAC signatures
3. Pipeline stages: Static → Dynamic → Patch → Validate
4. Kubernetes jobs for scalability

### Monitoring & Metrics
1. Metrics collected every 5 minutes
2. Data retained for 90 days
3. Exported to Prometheus
4. Alerts configured on thresholds

---