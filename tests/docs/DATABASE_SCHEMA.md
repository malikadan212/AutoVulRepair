# PostgreSQL Database Schema - AutoVulRepair
**Total Tables:** 19
**Total Sequences:** 2
**Total Views:** 0
**Total Functions:** 1
**Total Triggers:** 1

---

## Tables

### crash_artifacts

**Type:** BASE TABLE
**Row Count:** 0
**Total Size:** 16 kB
**Table Size:** 0 bytes
**Indexes Size:** 16 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| execution_id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| filename | character varying(255) | NO | - | 255 | - | - |
| crash_type | character varying(50) | YES | - | 50 | - | - |
| file_size | integer(32) | NO | - | - | 32 | - |
| crash_data | bytea | YES | - | - | - | - |
| stack_trace | text | YES | - | - | - | - |
| sanitizer_output | text | YES | - | - | - | - |
| severity | character varying(20) | YES | - | 20 | - | - |
| exploitability | character varying(20) | YES | - | 20 | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `crash_artifacts_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| execution_id | fuzz_executions.id | crash_artifacts_execution_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24714_1_not_null**: `id IS NOT NULL`
- **24584_24714_2_not_null**: `execution_id IS NOT NULL`
- **24584_24714_3_not_null**: `scan_id IS NOT NULL`
- **24584_24714_4_not_null**: `filename IS NOT NULL`
- **24584_24714_6_not_null**: `file_size IS NOT NULL`

#### Indexes

**crash_artifacts_pkey**
```sql
CREATE UNIQUE INDEX crash_artifacts_pkey ON public.crash_artifacts USING btree (id)
```

---

### fuzz_campaigns

**Type:** BASE TABLE
**Row Count:** 0
**Total Size:** 16 kB
**Table Size:** 0 bytes
**Indexes Size:** 16 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| runtime_minutes | integer(32) | NO | - | - | 32 | - |
| total_targets | integer(32) | NO | - | - | 32 | - |
| targets_executed | integer(32) | YES | - | - | 32 | - |
| total_executions | integer(32) | YES | - | - | 32 | - |
| total_crashes | integer(32) | YES | - | - | 32 | - |
| status | character varying(20) | YES | - | 20 | - | - |
| started_at | timestamp without time zone | YES | - | - | - | - |
| completed_at | timestamp without time zone | YES | - | - | - | - |
| total_time_seconds | integer(32) | YES | - | - | 32 | - |
| metadata_json | jsonb | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `fuzz_campaigns_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| scan_id | scans_v2.scan_id | fuzz_campaigns_scan_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24644_1_not_null**: `id IS NOT NULL`
- **24584_24644_2_not_null**: `scan_id IS NOT NULL`
- **24584_24644_3_not_null**: `runtime_minutes IS NOT NULL`
- **24584_24644_4_not_null**: `total_targets IS NOT NULL`

#### Indexes

**fuzz_campaigns_pkey**
```sql
CREATE UNIQUE INDEX fuzz_campaigns_pkey ON public.fuzz_campaigns USING btree (id)
```

---

### fuzz_executions

**Type:** BASE TABLE
**Row Count:** 0
**Total Size:** 16 kB
**Table Size:** 0 bytes
**Indexes Size:** 16 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| campaign_id | uuid | NO | - | - | - | - |
| target_id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| target_name | character varying(255) | NO | - | 255 | - | - |
| status | character varying(20) | NO | - | 20 | - | - |
| runtime_seconds | numeric(8,2) | YES | - | - | 8 | 2 |
| exit_code | integer(32) | YES | - | - | 32 | - |
| executions_count | integer(32) | YES | - | - | 32 | - |
| crashes_found | integer(32) | YES | - | - | 32 | - |
| coverage_stats | json | YES | - | - | - | - |
| fuzzer_output | text | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `fuzz_executions_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| campaign_id | fuzz_campaigns.id | fuzz_executions_campaign_id_fkey | NO ACTION | NO ACTION |
| target_id | fuzz_targets.id | fuzz_executions_target_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24697_1_not_null**: `id IS NOT NULL`
- **24584_24697_2_not_null**: `campaign_id IS NOT NULL`
- **24584_24697_3_not_null**: `target_id IS NOT NULL`
- **24584_24697_4_not_null**: `scan_id IS NOT NULL`
- **24584_24697_5_not_null**: `target_name IS NOT NULL`
- **24584_24697_6_not_null**: `status IS NOT NULL`

#### Indexes

**fuzz_executions_pkey**
```sql
CREATE UNIQUE INDEX fuzz_executions_pkey ON public.fuzz_executions USING btree (id)
```

---

### fuzz_plans

**Type:** BASE TABLE
**Row Count:** 2
**Total Size:** 32 kB
**Table Size:** 8192 bytes
**Indexes Size:** 24 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| version | character varying(10) | YES | - | 10 | - | - |
| total_targets | integer(32) | NO | - | - | 32 | - |
| generated_at | timestamp without time zone | YES | - | - | - | - |
| metadata_json | jsonb | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `fuzz_plans_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| scan_id | scans_v2.scan_id | fuzz_plans_scan_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24632_1_not_null**: `id IS NOT NULL`
- **24584_24632_2_not_null**: `scan_id IS NOT NULL`
- **24584_24632_4_not_null**: `total_targets IS NOT NULL`

#### Indexes

**fuzz_plans_pkey**
```sql
CREATE UNIQUE INDEX fuzz_plans_pkey ON public.fuzz_plans USING btree (id)
```

---

### fuzz_targets

**Type:** BASE TABLE
**Row Count:** 0
**Total Size:** 16 kB
**Table Size:** 0 bytes
**Indexes Size:** 16 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| plan_id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| target_id | character varying(255) | NO | - | 255 | - | - |
| function_name | character varying(255) | NO | - | 255 | - | - |
| file_path | text | NO | - | - | - | - |
| line_number | integer(32) | NO | - | - | 32 | - |
| bug_class | character varying(50) | NO | - | 50 | - | - |
| priority | numeric(4,2) | NO | - | - | 4 | 2 |
| harness_type | character varying(50) | NO | - | 50 | - | - |
| sanitizers | json | NO | - | - | - | - |
| seeds | json | YES | - | - | - | - |
| dictionaries | json | YES | - | - | - | - |
| function_signature | json | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `fuzz_targets_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| plan_id | fuzz_plans.id | fuzz_targets_plan_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24656_1_not_null**: `id IS NOT NULL`
- **24584_24656_2_not_null**: `plan_id IS NOT NULL`
- **24584_24656_3_not_null**: `scan_id IS NOT NULL`
- **24584_24656_4_not_null**: `target_id IS NOT NULL`
- **24584_24656_5_not_null**: `function_name IS NOT NULL`
- **24584_24656_6_not_null**: `file_path IS NOT NULL`
- **24584_24656_7_not_null**: `line_number IS NOT NULL`
- **24584_24656_8_not_null**: `bug_class IS NOT NULL`
- **24584_24656_9_not_null**: `priority IS NOT NULL`
- **24584_24656_10_not_null**: `harness_type IS NOT NULL`
- **24584_24656_11_not_null**: `sanitizers IS NOT NULL`

#### Indexes

**fuzz_targets_pkey**
```sql
CREATE UNIQUE INDEX fuzz_targets_pkey ON public.fuzz_targets USING btree (id)
```

---

### fuzzing_results

**Type:** BASE TABLE
**Row Count:** 12
**Total Size:** 96 kB
**Table Size:** 8192 bytes
**Indexes Size:** 88 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | integer(32) | NO | nextval('fuzzing_results_id_seq'::regclass) | - | 32 | - |
| user_id | character varying(255) | NO | - | 255 | - | - |
| scan_id | character varying(36) | YES | - | 36 | - | - |
| target_binary | character varying(500) | NO | - | 500 | - | - |
| test_case_id | character varying(255) | YES | - | 255 | - | - |
| crash_found | boolean | YES | false | - | - | - |
| coverage_percent | numeric(5,2) | YES | 0.0 | - | 5 | 2 |
| execution_time_ms | integer(32) | YES | - | - | 32 | - |
| input_data | text | YES | - | - | - | - |
| crash_details | text | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | CURRENT_TIMESTAMP | - | - | - |
| fuzzer_type | character varying(100) | YES | - | 100 | - | - |
| iterations | integer(32) | YES | 0 | - | 32 | - |
| unique_crashes | integer(32) | YES | 0 | - | 32 | - |

#### Primary Keys

- **id** (Constraint: `fuzzing_results_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| user_id | users.id | fuzzing_results_user_id_fkey | NO ACTION | CASCADE |
| scan_id | scans.id | fuzzing_results_scan_id_fkey | NO ACTION | CASCADE |

#### Check Constraints

- **24584_41321_1_not_null**: `id IS NOT NULL`
- **24584_41321_2_not_null**: `user_id IS NOT NULL`
- **24584_41321_4_not_null**: `target_binary IS NOT NULL`

#### Indexes

**fuzzing_results_pkey**
```sql
CREATE UNIQUE INDEX fuzzing_results_pkey ON public.fuzzing_results USING btree (id)
```

**idx_fuzzing_user_id**
```sql
CREATE INDEX idx_fuzzing_user_id ON public.fuzzing_results USING btree (user_id)
```

**idx_fuzzing_scan_id**
```sql
CREATE INDEX idx_fuzzing_scan_id ON public.fuzzing_results USING btree (scan_id)
```

**idx_fuzzing_target**
```sql
CREATE INDEX idx_fuzzing_target ON public.fuzzing_results USING btree (target_binary)
```

**idx_fuzzing_crash**
```sql
CREATE INDEX idx_fuzzing_crash ON public.fuzzing_results USING btree (crash_found)
```

---

### github_app_tokens

**Type:** BASE TABLE
**Row Count:** 1
**Total Size:** 48 kB
**Table Size:** 8192 bytes
**Indexes Size:** 40 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| installation_id | bigint(64) | NO | - | - | 64 | - |
| access_token | text | NO | - | - | - | - |
| expires_at | timestamp without time zone | NO | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |
| updated_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `github_app_tokens_pkey`)

#### Unique Constraints

- **installation_id** (Constraint: `github_app_tokens_installation_id_key`)

#### Check Constraints

- **24584_41245_1_not_null**: `id IS NOT NULL`
- **24584_41245_2_not_null**: `installation_id IS NOT NULL`
- **24584_41245_3_not_null**: `access_token IS NOT NULL`
- **24584_41245_4_not_null**: `expires_at IS NOT NULL`

#### Indexes

**github_app_tokens_pkey**
```sql
CREATE UNIQUE INDEX github_app_tokens_pkey ON public.github_app_tokens USING btree (id)
```

**github_app_tokens_installation_id_key**
```sql
CREATE UNIQUE INDEX github_app_tokens_installation_id_key ON public.github_app_tokens USING btree (installation_id)
```

---

### github_installations

**Type:** BASE TABLE
**Row Count:** 1
**Total Size:** 48 kB
**Table Size:** 8192 bytes
**Indexes Size:** 40 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| installation_id | bigint(64) | NO | - | - | 64 | - |
| user_id | character varying(255) | NO | - | 255 | - | - |
| github_account_login | character varying(255) | NO | - | 255 | - | - |
| github_account_id | bigint(64) | YES | - | - | 64 | - |
| github_account_type | character varying(50) | YES | - | 50 | - | - |
| repository_selection | character varying(50) | YES | - | 50 | - | - |
| permissions | json | YES | - | - | - | - |
| is_active | boolean | YES | - | - | - | - |
| installed_at | timestamp without time zone | YES | - | - | - | - |
| updated_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `github_installations_pkey`)

#### Unique Constraints

- **installation_id** (Constraint: `github_installations_installation_id_key`)

#### Check Constraints

- **24584_41236_1_not_null**: `id IS NOT NULL`
- **24584_41236_2_not_null**: `installation_id IS NOT NULL`
- **24584_41236_3_not_null**: `user_id IS NOT NULL`
- **24584_41236_4_not_null**: `github_account_login IS NOT NULL`

#### Indexes

**github_installations_pkey**
```sql
CREATE UNIQUE INDEX github_installations_pkey ON public.github_installations USING btree (id)
```

**github_installations_installation_id_key**
```sql
CREATE UNIQUE INDEX github_installations_installation_id_key ON public.github_installations USING btree (installation_id)
```

---

### harness_files

**Type:** BASE TABLE
**Row Count:** 0
**Total Size:** 16 kB
**Table Size:** 0 bytes
**Indexes Size:** 16 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| target_id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| filename | character varying(255) | NO | - | 255 | - | - |
| harness_code | text | NO | - | - | - | - |
| harness_type | character varying(50) | NO | - | 50 | - | - |
| build_status | character varying(20) | YES | - | 20 | - | - |
| build_log | text | YES | - | - | - | - |
| binary_path | text | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `harness_files_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| target_id | fuzz_targets.id | harness_files_target_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24685_1_not_null**: `id IS NOT NULL`
- **24584_24685_2_not_null**: `target_id IS NOT NULL`
- **24584_24685_3_not_null**: `scan_id IS NOT NULL`
- **24584_24685_4_not_null**: `filename IS NOT NULL`
- **24584_24685_5_not_null**: `harness_code IS NOT NULL`
- **24584_24685_6_not_null**: `harness_type IS NOT NULL`

#### Indexes

**harness_files_pkey**
```sql
CREATE UNIQUE INDEX harness_files_pkey ON public.harness_files USING btree (id)
```

---

### installation_repositories

**Type:** BASE TABLE
**Row Count:** 1
**Total Size:** 32 kB
**Table Size:** 8192 bytes
**Indexes Size:** 24 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| installation_id | uuid | NO | - | - | - | - |
| repository_full_name | character varying(255) | NO | - | 255 | - | - |
| repository_id | bigint(64) | NO | - | - | 64 | - |
| repository_name | character varying(255) | YES | - | 255 | - | - |
| repository_private | boolean | YES | - | - | - | - |
| repository_language | character varying(100) | YES | - | 100 | - | - |
| automation_enabled | boolean | YES | - | - | - | - |
| auto_scan_on_push | boolean | YES | - | - | - | - |
| auto_create_prs | boolean | YES | - | - | - | - |
| auto_scan_on_pr | boolean | YES | - | - | - | - |
| settings | json | YES | - | - | - | - |
| is_active | boolean | YES | - | - | - | - |
| last_scanned_at | timestamp without time zone | YES | - | - | - | - |
| last_scan_status | character varying(50) | YES | - | 50 | - | - |
| added_at | timestamp without time zone | YES | - | - | - | - |
| updated_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `installation_repositories_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| installation_id | github_installations.id | installation_repositories_installation_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_41254_1_not_null**: `id IS NOT NULL`
- **24584_41254_2_not_null**: `installation_id IS NOT NULL`
- **24584_41254_3_not_null**: `repository_full_name IS NOT NULL`
- **24584_41254_4_not_null**: `repository_id IS NOT NULL`

#### Indexes

**installation_repositories_pkey**
```sql
CREATE UNIQUE INDEX installation_repositories_pkey ON public.installation_repositories USING btree (id)
```

---

### job_queue

**Type:** BASE TABLE
**Row Count:** 38
**Total Size:** 64 kB
**Table Size:** 16 kB
**Indexes Size:** 48 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| job_type | character varying(50) | NO | - | 50 | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| priority | integer(32) | YES | - | - | 32 | - |
| status | character varying(20) | YES | - | 20 | - | - |
| attempts | integer(32) | YES | - | - | 32 | - |
| max_attempts | integer(32) | YES | - | - | 32 | - |
| payload | jsonb | NO | - | - | - | - |
| result | jsonb | YES | - | - | - | - |
| error_message | text | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |
| started_at | timestamp without time zone | YES | - | - | - | - |
| completed_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `job_queue_pkey`)

#### Check Constraints

- **24584_24601_1_not_null**: `id IS NOT NULL`
- **24584_24601_2_not_null**: `job_type IS NOT NULL`
- **24584_24601_3_not_null**: `scan_id IS NOT NULL`
- **24584_24601_8_not_null**: `payload IS NOT NULL`

#### Indexes

**job_queue_pkey**
```sql
CREATE UNIQUE INDEX job_queue_pkey ON public.job_queue USING btree (id)
```

---

### patch_batches

**Type:** BASE TABLE
**Row Count:** 1
**Total Size:** 80 kB
**Table Size:** 8192 bytes
**Indexes Size:** 72 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | character varying(36) | NO | (gen_random_uuid())::text | 36 | - | - |
| scan_id | character varying(36) | NO | - | 36 | - | - |
| status | character varying(50) | NO | 'generating'::character varying | 50 | - | - |
| stage1_complete | boolean | YES | false | - | - | - |
| stage2_complete | boolean | YES | false | - | - | - |
| stage1_patches_count | integer(32) | YES | 0 | - | 32 | - |
| stage2_patches_count | integer(32) | YES | 0 | - | 32 | - |
| total_patches_count | integer(32) | YES | 0 | - | 32 | - |
| stage1_vulnerabilities_count | integer(32) | YES | 0 | - | 32 | - |
| stage2_vulnerabilities_count | integer(32) | YES | 0 | - | 32 | - |
| created_at | timestamp without time zone | YES | now() | - | - | - |
| stage1_completed_at | timestamp without time zone | YES | - | - | - | - |
| stage2_completed_at | timestamp without time zone | YES | - | - | - | - |
| applied_at | timestamp without time zone | YES | - | - | - | - |
| applied_by | character varying(36) | YES | - | 36 | - | - |
| commit_sha | character varying(255) | YES | - | 255 | - | - |
| pr_url | text | YES | - | - | - | - |
| branch_name | character varying(255) | YES | - | 255 | - | - |
| notes | text | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `patch_batches_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| scan_id | scans.id | patch_batches_scan_id_fkey | NO ACTION | CASCADE |
| applied_by | users.id | patch_batches_applied_by_fkey | NO ACTION | NO ACTION |

#### Unique Constraints

- **scan_id** (Constraint: `patch_batches_scan_id_key`)

#### Check Constraints

- **24584_49382_1_not_null**: `id IS NOT NULL`
- **24584_49382_2_not_null**: `scan_id IS NOT NULL`
- **24584_49382_3_not_null**: `status IS NOT NULL`

#### Indexes

**patch_batches_pkey**
```sql
CREATE UNIQUE INDEX patch_batches_pkey ON public.patch_batches USING btree (id)
```

**patch_batches_scan_id_key**
```sql
CREATE UNIQUE INDEX patch_batches_scan_id_key ON public.patch_batches USING btree (scan_id)
```

**idx_patch_batches_scan_id**
```sql
CREATE INDEX idx_patch_batches_scan_id ON public.patch_batches USING btree (scan_id)
```

**idx_patch_batches_status**
```sql
CREATE INDEX idx_patch_batches_status ON public.patch_batches USING btree (status)
```

---

### patches

**Type:** BASE TABLE
**Row Count:** 10
**Total Size:** 112 kB
**Table Size:** 8192 bytes
**Indexes Size:** 104 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | integer(32) | NO | nextval('patches_id_seq'::regclass) | - | 32 | - |
| user_id | character varying(255) | NO | - | 255 | - | - |
| scan_id | character varying(36) | YES | - | 36 | - | - |
| vulnerability_id | character varying(255) | YES | - | 255 | - | - |
| patch_content | text | NO | - | - | - | - |
| status | character varying(50) | YES | 'pending'::character varying | 50 | - | - |
| confidence_score | numeric(5,2) | YES | 0.0 | - | 5 | 2 |
| created_at | timestamp without time zone | YES | CURRENT_TIMESTAMP | - | - | - |
| applied_at | timestamp without time zone | YES | - | - | - | - |
| file_path | character varying(500) | YES | - | 500 | - | - |
| line_number | integer(32) | YES | - | - | 32 | - |
| patch_type | character varying(100) | YES | - | 100 | - | - |
| ai_model | character varying(100) | YES | - | 100 | - | - |
| stage | integer(32) | YES | 1 | - | 32 | - |
| selected_for_application | boolean | YES | true | - | - | - |
| batch_id | character varying(36) | YES | - | 36 | - | - |

#### Primary Keys

- **id** (Constraint: `patches_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| user_id | users.id | patches_user_id_fkey | NO ACTION | CASCADE |
| scan_id | scans.id | patches_scan_id_fkey | NO ACTION | CASCADE |
| batch_id | patch_batches.id | patches_batch_id_fkey | NO ACTION | SET NULL |

#### Check Constraints

- **patches_stage_check**: `((stage = ANY (ARRAY[1, 2])))`
- **24584_41296_1_not_null**: `id IS NOT NULL`
- **24584_41296_2_not_null**: `user_id IS NOT NULL`
- **24584_41296_5_not_null**: `patch_content IS NOT NULL`

#### Indexes

**patches_pkey**
```sql
CREATE UNIQUE INDEX patches_pkey ON public.patches USING btree (id)
```

**idx_patches_user_id**
```sql
CREATE INDEX idx_patches_user_id ON public.patches USING btree (user_id)
```

**idx_patches_scan_id**
```sql
CREATE INDEX idx_patches_scan_id ON public.patches USING btree (scan_id)
```

**idx_patches_status**
```sql
CREATE INDEX idx_patches_status ON public.patches USING btree (status)
```

**idx_patches_stage**
```sql
CREATE INDEX idx_patches_stage ON public.patches USING btree (stage)
```

**idx_patches_batch_id**
```sql
CREATE INDEX idx_patches_batch_id ON public.patches USING btree (batch_id)
```

---

### repair_patches

**Type:** BASE TABLE
**Row Count:** 116
**Total Size:** 168 kB
**Table Size:** 96 kB
**Indexes Size:** 72 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| finding_id | uuid | YES | - | - | - | - |
| file_path | text | NO | - | - | - | - |
| original_code | text | NO | - | - | - | - |
| patched_code | text | NO | - | - | - | - |
| patch_diff | text | NO | - | - | - | - |
| repair_method | character varying(50) | NO | - | 50 | - | - |
| confidence_score | numeric(3,2) | YES | - | - | 3 | 2 |
| validation_status | character varying(20) | YES | - | 20 | - | - |
| applied_at | timestamp without time zone | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `repair_patches_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| scan_id | scans_v2.scan_id | repair_patches_scan_id_fkey | NO ACTION | NO ACTION |
| finding_id | static_findings.id | repair_patches_finding_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24668_1_not_null**: `id IS NOT NULL`
- **24584_24668_2_not_null**: `scan_id IS NOT NULL`
- **24584_24668_4_not_null**: `file_path IS NOT NULL`
- **24584_24668_5_not_null**: `original_code IS NOT NULL`
- **24584_24668_6_not_null**: `patched_code IS NOT NULL`
- **24584_24668_7_not_null**: `patch_diff IS NOT NULL`
- **24584_24668_8_not_null**: `repair_method IS NOT NULL`

#### Indexes

**repair_patches_pkey**
```sql
CREATE UNIQUE INDEX repair_patches_pkey ON public.repair_patches USING btree (id)
```

---

### scan_sources

**Type:** BASE TABLE
**Row Count:** 611
**Total Size:** 952 kB
**Table Size:** 544 kB
**Indexes Size:** 408 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| file_path | text | NO | - | - | - | - |
| file_content | text | NO | - | - | - | - |
| file_size | integer(32) | NO | - | - | 32 | - |
| file_hash | character varying(64) | NO | - | 64 | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `scan_sources_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| scan_id | scans_v2.scan_id | scan_sources_scan_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24608_1_not_null**: `id IS NOT NULL`
- **24584_24608_2_not_null**: `scan_id IS NOT NULL`
- **24584_24608_3_not_null**: `file_path IS NOT NULL`
- **24584_24608_4_not_null**: `file_content IS NOT NULL`
- **24584_24608_5_not_null**: `file_size IS NOT NULL`
- **24584_24608_6_not_null**: `file_hash IS NOT NULL`

#### Indexes

**scan_sources_pkey**
```sql
CREATE UNIQUE INDEX scan_sources_pkey ON public.scan_sources USING btree (id)
```

---

### scans

**Type:** BASE TABLE
**Row Count:** 5
**Total Size:** 32 kB
**Table Size:** 8192 bytes
**Indexes Size:** 24 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | character varying(36) | NO | - | 36 | - | - |
| user_id | character varying(36) | YES | - | 36 | - | - |
| source_type | character varying(20) | NO | - | 20 | - | - |
| source_path | text | YES | - | - | - | - |
| repo_url | text | YES | - | - | - | - |
| analysis_tool | character varying(20) | NO | - | 20 | - | - |
| status | character varying(20) | NO | - | 20 | - | - |
| artifacts_path | text | YES | - | - | - | - |
| vulnerabilities_json | json | YES | - | - | - | - |
| patches_json | json | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |
| updated_at | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `scans_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| user_id | users.id | scans_user_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24585_1_not_null**: `id IS NOT NULL`
- **24584_24585_3_not_null**: `source_type IS NOT NULL`
- **24584_24585_6_not_null**: `analysis_tool IS NOT NULL`
- **24584_24585_7_not_null**: `status IS NOT NULL`

#### Indexes

**scans_pkey**
```sql
CREATE UNIQUE INDEX scans_pkey ON public.scans USING btree (id)
```

---

### scans_v2

**Type:** BASE TABLE
**Row Count:** 530
**Total Size:** 352 kB
**Table Size:** 216 kB
**Indexes Size:** 136 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| user_id | character varying(255) | YES | - | 255 | - | - |
| repo_url | text | YES | - | - | - | - |
| source_type | character varying(50) | NO | - | 50 | - | - |
| analysis_tool | character varying(50) | NO | - | 50 | - | - |
| status | character varying(50) | NO | - | 50 | - | - |
| priority | integer(32) | YES | - | - | 32 | - |
| created_at | timestamp without time zone | YES | - | - | - | - |
| started_at | timestamp without time zone | YES | - | - | - | - |
| completed_at | timestamp without time zone | YES | - | - | - | - |
| error_message | text | YES | - | - | - | - |
| metadata_json | jsonb | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `scans_v2_pkey`)

#### Unique Constraints

- **scan_id** (Constraint: `scans_v2_scan_id_key`)

#### Check Constraints

- **24584_24592_1_not_null**: `id IS NOT NULL`
- **24584_24592_2_not_null**: `scan_id IS NOT NULL`
- **24584_24592_5_not_null**: `source_type IS NOT NULL`
- **24584_24592_6_not_null**: `analysis_tool IS NOT NULL`
- **24584_24592_7_not_null**: `status IS NOT NULL`

#### Indexes

**scans_v2_pkey**
```sql
CREATE UNIQUE INDEX scans_v2_pkey ON public.scans_v2 USING btree (id)
```

**scans_v2_scan_id_key**
```sql
CREATE UNIQUE INDEX scans_v2_scan_id_key ON public.scans_v2 USING btree (scan_id)
```

---

### static_findings

**Type:** BASE TABLE
**Row Count:** 10,886
**Total Size:** 3040 kB
**Table Size:** 2536 kB
**Indexes Size:** 504 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | uuid | NO | - | - | - | - |
| scan_id | character varying(255) | NO | - | 255 | - | - |
| rule_id | character varying(100) | NO | - | 100 | - | - |
| severity | character varying(20) | NO | - | 20 | - | - |
| confidence | character varying(20) | NO | - | 20 | - | - |
| file_path | text | NO | - | - | - | - |
| line_number | integer(32) | NO | - | - | 32 | - |
| column_number | integer(32) | YES | - | - | 32 | - |
| function_name | character varying(255) | YES | - | 255 | - | - |
| message | text | NO | - | - | - | - |
| description | text | YES | - | - | - | - |
| cwe | character varying(20) | YES | - | 20 | - | - |
| cvss_score | numeric(3,1) | YES | - | - | 3 | 1 |
| exploitability_score | numeric(3,1) | YES | - | - | 3 | 1 |
| created_at | timestamp without time zone | YES | - | - | - | - |
| metadata_json | jsonb | YES | '{}'::jsonb | - | - | - |

#### Primary Keys

- **id** (Constraint: `static_findings_pkey`)

#### Foreign Keys

| Column | References | Constraint | On Update | On Delete |
|--------|------------|------------|-----------|----------|
| scan_id | scans_v2.scan_id | static_findings_scan_id_fkey | NO ACTION | NO ACTION |

#### Check Constraints

- **24584_24620_1_not_null**: `id IS NOT NULL`
- **24584_24620_2_not_null**: `scan_id IS NOT NULL`
- **24584_24620_3_not_null**: `rule_id IS NOT NULL`
- **24584_24620_4_not_null**: `severity IS NOT NULL`
- **24584_24620_5_not_null**: `confidence IS NOT NULL`
- **24584_24620_6_not_null**: `file_path IS NOT NULL`
- **24584_24620_7_not_null**: `line_number IS NOT NULL`
- **24584_24620_10_not_null**: `message IS NOT NULL`

#### Indexes

**static_findings_pkey**
```sql
CREATE UNIQUE INDEX static_findings_pkey ON public.static_findings USING btree (id)
```

---

### users

**Type:** BASE TABLE
**Row Count:** 2
**Total Size:** 32 kB
**Table Size:** 8192 bytes
**Indexes Size:** 24 kB

#### Columns

| Column | Type | Nullable | Default | Max Length | Precision | Scale |
|--------|------|----------|---------|------------|-----------|-------|
| id | character varying(36) | NO | - | 36 | - | - |
| username | character varying(100) | NO | - | 100 | - | - |
| email | character varying(255) | YES | - | 255 | - | - |
| avatar_url | text | YES | - | - | - | - |
| github_token | text | YES | - | - | - | - |
| is_active | boolean | YES | - | - | - | - |
| created_at | timestamp without time zone | YES | - | - | - | - |
| updated_at | timestamp without time zone | YES | - | - | - | - |
| last_login | timestamp without time zone | YES | - | - | - | - |

#### Primary Keys

- **id** (Constraint: `users_pkey`)

#### Check Constraints

- **24584_24739_1_not_null**: `id IS NOT NULL`
- **24584_24739_2_not_null**: `username IS NOT NULL`

#### Indexes

**users_pkey**
```sql
CREATE UNIQUE INDEX users_pkey ON public.users USING btree (id)
```

---

## Sequences

### fuzzing_results_id_seq

- **Data Type:** integer
- **Start Value:** 1
- **Min Value:** 1
- **Max Value:** 2147483647
- **Increment:** 1
- **Cycle:** NO

### patches_id_seq

- **Data Type:** integer
- **Start Value:** 1
- **Min Value:** 1
- **Max Value:** 2147483647
- **Increment:** 1
- **Cycle:** NO

## Functions

### update_batch_total_patches

- **Type:** FUNCTION
- **Return Type:** trigger

```sql

BEGIN
    UPDATE patch_batches
    SET total_patches_count = stage1_patches_count + stage2_patches_count
    WHERE id = NEW.id;
    RETURN NEW;
END;

```

## Triggers

### trigger_update_batch_total

- **Event:** UPDATE
- **Table:** patch_batches
- **Timing:** AFTER
- **Action:** `EXECUTE FUNCTION update_batch_total_patches()`

