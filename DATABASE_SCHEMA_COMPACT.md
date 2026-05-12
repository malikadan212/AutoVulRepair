# AutoVulRepair Database Schema (Compact)

## Overview
- **19 Tables** | **12,596 Total Rows** | **2 Sequences** | **1 Function** | **1 Trigger**

---

## Tables

### 1. users (2 rows)
User accounts with GitHub integration
```
PK: id (varchar36)
Columns: username*, email, avatar_url, github_token, is_active, created_at, updated_at, last_login
```

### 2. scans (5 rows) - LEGACY
Old scan table
```
PK: id (varchar36)
FK: user_id → users.id
Columns: source_type*, repo_url, analysis_tool*, status*, artifacts_path, vulnerabilities_json, patches_json, created_at, updated_at
```

### 3. scans_v2 (530 rows)
New scan orchestration system
```
PK: id (uuid)
UNIQUE: scan_id (varchar255)
Columns: user_id, repo_url, source_type*, analysis_tool*, status*, priority, created_at, started_at, completed_at, error_message, metadata_json
```

### 4. static_findings (10,886 rows) ⭐ LARGEST
Vulnerability findings from static analysis
```
PK: id (uuid)
FK: scan_id → scans_v2.scan_id
Columns: rule_id*, severity*, confidence*, file_path*, line_number*, column_number, function_name, message*, description, cwe, cvss_score, exploitability_score, created_at, metadata_json
```

### 5. scan_sources (611 rows)
Source code files for scans
```
PK: id (uuid)
FK: scan_id → scans_v2.scan_id
Columns: file_path*, file_content*, file_size*, file_hash*, created_at
```

### 6. repair_patches (116 rows)
Stage 1 & 2 repair patches
```
PK: id (uuid)
FK: scan_id → scans_v2.scan_id, finding_id → static_findings.id
Columns: file_path*, original_code*, patched_code*, patch_diff*, repair_method*, confidence_score, validation_status, applied_at, created_at
```

### 7. patch_batches (1 row)
Batch patch management system
```
PK: id (varchar36, default: gen_random_uuid())
FK: scan_id → scans.id (UNIQUE), applied_by → users.id
Columns: status* (default: 'generating'), stage1_complete, stage2_complete, stage1_patches_count, stage2_patches_count, total_patches_count, stage1_vulnerabilities_count, stage2_vulnerabilities_count, created_at, stage1_completed_at, stage2_completed_at, applied_at, commit_sha, pr_url, branch_name, notes
Trigger: trigger_update_batch_total (AFTER UPDATE) → update_batch_total_patches()
```

### 8. patches (10 rows) - LEGACY
Old patches table
```
PK: id (serial)
FK: user_id → users.id, scan_id → scans.id, batch_id → patch_batches.id
Columns: vulnerability_id, patch_content*, status (default: 'pending'), confidence_score, created_at, applied_at, file_path, line_number, patch_type, ai_model, stage (default: 1, CHECK: 1 or 2), selected_for_application (default: true)
Indexes: user_id, scan_id, status, stage, batch_id
```

### 9. fuzz_plans (2 rows)
Fuzzing strategy plans
```
PK: id (uuid)
FK: scan_id → scans_v2.scan_id
Columns: version, total_targets*, generated_at, metadata_json
```

### 10. fuzz_targets (0 rows)
Individual functions to fuzz
```
PK: id (uuid)
FK: plan_id → fuzz_plans.id
Columns: scan_id*, target_id*, function_name*, file_path*, line_number*, bug_class*, priority*, harness_type*, sanitizers*, seeds, dictionaries, function_signature, created_at
```

### 11. fuzz_campaigns (0 rows)
Fuzzing campaign orchestration
```
PK: id (uuid)
FK: scan_id → scans_v2.scan_id
Columns: runtime_minutes*, total_targets*, targets_executed, total_executions, total_crashes, status, started_at, completed_at, total_time_seconds, metadata_json
```

### 12. fuzz_executions (0 rows)
Individual fuzzing target executions
```
PK: id (uuid)
FK: campaign_id → fuzz_campaigns.id, target_id → fuzz_targets.id
Columns: scan_id*, target_name*, status*, runtime_seconds, exit_code, executions_count, crashes_found, coverage_stats, fuzzer_output, created_at
```

### 13. harness_files (0 rows)
Generated fuzzing harness code
```
PK: id (uuid)
FK: target_id → fuzz_targets.id
Columns: scan_id*, filename*, harness_code*, harness_type*, build_status, build_log, binary_path, created_at
```

### 14. crash_artifacts (0 rows)
Crash data from fuzzing executions
```
PK: id (uuid)
FK: execution_id → fuzz_executions.id
Columns: scan_id*, filename*, crash_type, file_size*, crash_data, stack_trace, sanitizer_output, severity, exploitability, created_at
```

### 15. fuzzing_results (12 rows) - LEGACY
Old fuzzing results table
```
PK: id (serial)
FK: user_id → users.id, scan_id → scans.id
Columns: target_binary*, test_case_id, crash_found (default: false), coverage_percent (default: 0.0), execution_time_ms, input_data, crash_details, created_at, fuzzer_type, iterations (default: 0), unique_crashes (default: 0)
Indexes: user_id, scan_id, target_binary, crash_found
```

### 16. job_queue (38 rows)
Async job queue for background tasks
```
PK: id (uuid)
Columns: job_type*, scan_id*, priority, status, attempts, max_attempts, payload*, result, error_message, created_at, started_at, completed_at
```

### 17. github_installations (1 row)
GitHub App installations per user
```
PK: id (uuid)
UNIQUE: installation_id (bigint)
Columns: user_id*, github_account_login*, github_account_id, github_account_type, repository_selection, permissions, is_active, installed_at, updated_at
```

### 18. github_app_tokens (1 row)
GitHub App access tokens with expiration
```
PK: id (uuid)
UNIQUE: installation_id (bigint)
Columns: access_token*, expires_at*, created_at, updated_at
```

### 19. installation_repositories (1 row)
Repositories with automation enabled
```
PK: id (uuid)
FK: installation_id → github_installations.id
Columns: repository_full_name*, repository_id*, repository_name, repository_private, repository_language, automation_enabled, auto_scan_on_push, auto_create_prs, auto_scan_on_pr, settings, is_active, last_scanned_at, last_scan_status, added_at, updated_at
```

---

## Sequences
- **fuzzing_results_id_seq**: integer (1 to 2147483647, increment 1)
- **patches_id_seq**: integer (1 to 2147483647, increment 1)

---

## Functions
- **update_batch_total_patches()**: Trigger function that updates `patch_batches.total_patches_count = stage1_patches_count + stage2_patches_count`

---

## Key Relationships

**Scan Flow:**
```
users → scans_v2 → static_findings (10,886)
              ↓
         scan_sources (611)
              ↓
         repair_patches (116)
              ↓
         fuzz_plans (2)
```

**Fuzzing Pipeline:**
```
fuzz_plans → fuzz_targets → fuzz_campaigns → fuzz_executions → crash_artifacts
                        ↓
                  harness_files
```

**GitHub Integration:**
```
users → github_installations → installation_repositories
                           ↓
                    github_app_tokens
```

**Patch Management:**
```
scans → patch_batches → patches
static_findings → repair_patches
```

---

## Legend
- `*` = NOT NULL
- `PK` = Primary Key
- `FK` = Foreign Key
- `UNIQUE` = Unique Constraint
- Numbers in parentheses = row count
