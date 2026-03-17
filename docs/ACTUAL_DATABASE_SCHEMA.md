# AutoVulRepair - Actual Database Schema
## What's Really Implemented

**Date:** December 9, 2024  
**Database:** SQLite (`scans.db`)  
**Verified:** ✅ Using `verify_database.py`

---

## Current Implementation Status

### ✅ What We Have (Iteration 1 & 2)
- **1 Table:** `scans`
- **Storage:** File-based (JSON files in `scans/` directory)
- **Reason:** Simplified MVP approach - store metadata in DB, artifacts as files

### 🔨 What's Planned (Future)
- Additional tables for Users, Vulnerabilities, Patches (if needed)
- Currently using JSON columns instead of separate tables

---

## Database Schema

### Table: `scans`

**Purpose:** Stores metadata for all security scans

| Column Name | Type | Nullable | Description |
|-------------|------|----------|-------------|
| `id` | VARCHAR(36) | No | UUID primary key |
| `user_id` | VARCHAR(36) | Yes | GitHub user ID (NULL for public scans) |
| `source_type` | VARCHAR(20) | No | 'repo_url', 'zip', or 'code_snippet' |
| `source_path` | TEXT | Yes | Local path for ZIP/snippet |
| `repo_url` | TEXT | Yes | GitHub repository URL |
| `analysis_tool` | VARCHAR(20) | No | 'cppcheck' or 'codeql' |
| `status` | VARCHAR(20) | No | 'queued', 'running', 'completed', 'failed' |
| `artifacts_path` | TEXT | Yes | Path to analysis artifacts |
| `vulnerabilities_json` | JSON | Yes | Array of vulnerability objects |
| `patches_json` | JSON | Yes | Array of patch objects |
| `created_at` | DATETIME | Yes | Scan creation timestamp |
| `updated_at` | DATETIME | Yes | Last update timestamp |

**Primary Key:** `id`

**Indexes:** None (small dataset, not needed yet)

---

## Data Storage Architecture

### Hybrid Approach: Database + File System

```
scans.db (SQLite)
    └── scans table (metadata only)

scans/ (File System)
    └── {scan_id}/
        ├── source/                    # Cloned/extracted source code
        ├── artifacts/
        │   ├── cppcheck-report.xml    # Raw analysis output
        │   └── codeql-results.sarif
        ├── static_findings.json       # Standardized findings
        ├── fuzz/
        │   ├── fuzzplan.json          # Fuzz plan
        │   ├── harnesses/             # Generated harness files
        │   │   └── *.cc
        │   ├── results/
        │   │   └── campaign_results.json
        │   ├── crashes/               # Crash artifacts
        │   │   └── crash-*
        │   └── triage/
        │       └── triage_results.json
        ├── build/
        │   ├── *.o                    # Compiled objects
        │   ├── fuzz_*                 # Fuzz binaries
        │   └── .build_log.json
        └── repro_kits/
            └── {crash_id}_*.c
```

**Why This Design?**
- ✅ Simple: One table for metadata
- ✅ Flexible: JSON columns for complex data
- ✅ Scalable: Large files (source code, binaries) stored on disk
- ✅ Fast: No complex joins needed
- ✅ Portable: Easy to backup/restore

---

## JSON Column Schemas

### `vulnerabilities_json` Format

```json
[
  {
    "id": "vuln-001",
    "file": "src/buffer.c",
    "line": 42,
    "column": 10,
    "severity": "error",
    "message": "Array index out of bounds",
    "rule_id": "arrayIndexOutOfBounds",
    "cwe": "CWE-119",
    "bug_class": "Buffer-Overflow"
  }
]
```

### `patches_json` Format

```json
[
  {
    "id": "patch-001",
    "vulnerability_id": "vuln-001",
    "file": "src/buffer.c",
    "patch_code": "if (index < size) { ... }",
    "diff": "--- a/buffer.c\n+++ b/buffer.c\n...",
    "status": "pending"
  }
]
```

---

## Entity Relationships (Simplified)

```
User (GitHub OAuth)
    │
    │ (not stored in DB, session-based)
    │
    ▼
Scan (scans table)
    │
    ├── vulnerabilities_json (embedded)
    ├── patches_json (embedded)
    │
    └── File System:
        ├── static_findings.json
        ├── fuzzplan.json
        ├── harnesses/*.cc
        ├── campaign_results.json
        ├── triage_results.json
        └── repro_kits/*
```

**Key Points:**
- No foreign keys (single table design)
- Relationships maintained via file paths
- `scan_id` is the linking key across all files

---

## Database Operations

### Create Scan
```python
from src.models.scan import get_session, Scan

session = get_session()
scan = Scan(
    id=scan_id,
    user_id=None,  # Public scan
    source_type='repo_url',
    repo_url='https://github.com/user/repo',
    analysis_tool='cppcheck',
    status='queued'
)
session.add(scan)
session.commit()
```

### Update Scan Status
```python
scan = session.query(Scan).filter_by(id=scan_id).first()
scan.status = 'completed'
scan.vulnerabilities_json = vulnerabilities_list
session.commit()
```

### Query Scans
```python
# Get all completed scans
completed = session.query(Scan).filter_by(status='completed').all()

# Get scans by user
user_scans = session.query(Scan).filter_by(user_id=user_id).all()

# Get recent scans
recent = session.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
```

---

## Verification Commands

### Check Database Schema
```bash
python verify_database.py
```

### Query Database Directly
```bash
sqlite3 scans.db
```

```sql
-- View all tables
.tables

-- View schema
.schema scans

-- Count records
SELECT COUNT(*) FROM scans;

-- View recent scans
SELECT id, source_type, status, created_at 
FROM scans 
ORDER BY created_at DESC 
LIMIT 5;

-- View scans by status
SELECT status, COUNT(*) 
FROM scans 
GROUP BY status;
```

---

## Database File Location

**Development:** `./scans.db` (project root)  
**Docker:** `/app/scans.db` (inside container)  
**Configured via:** `DATABASE_PATH` environment variable

---

## Backup & Restore

### Backup
```bash
# Copy database file
cp scans.db scans_backup_$(date +%Y%m%d).db

# Backup with scans directory
tar -czf backup.tar.gz scans.db scans/
```

### Restore
```bash
# Restore database
cp scans_backup_20241209.db scans.db

# Restore full backup
tar -xzf backup.tar.gz
```

---

## Performance Considerations

### Current Scale
- **Expected:** 100-1000 scans
- **Database Size:** < 10 MB
- **Query Time:** < 10ms

### If Scaling Needed
1. Add indexes on `status`, `created_at`, `user_id`
2. Move to PostgreSQL for better JSON querying
3. Separate tables for Vulnerabilities, Patches
4. Add caching layer (Redis)

---

## Comparison: Planned vs. Actual

| Entity | Planned (ERD) | Actual (Implemented) |
|--------|---------------|----------------------|
| User | Separate table | Session-based (in-memory) |
| Scan | ✅ Table | ✅ Table |
| Vulnerability | Separate table | JSON column in Scan |
| FuzzPlan | Separate table | File: fuzzplan.json |
| FuzzTarget | Separate table | Embedded in fuzzplan.json |
| Harness | Separate table | Files: *.cc |
| BuildResult | Separate table | File: .build_log.json |
| FuzzCampaign | Separate table | File: campaign_results.json |
| CrashArtifact | Separate table | Files: crash-* |
| TriageResult | Separate table | File: triage_results.json |
| Patch | Separate table | JSON column in Scan |
| ValidationResult | Separate table | Not implemented yet |

**Why the difference?**
- ✅ **Faster development:** Single table is simpler
- ✅ **Sufficient for MVP:** Handles current scale
- ✅ **Easy to migrate:** Can normalize later if needed
- ✅ **File-based storage:** Better for large artifacts

---

## For Your Presentation

### Show This:
1. **Run:** `python verify_database.py`
2. **Show output:** Schema with 12 columns
3. **Explain:** "We use a hybrid approach - metadata in SQLite, artifacts as files"
4. **Show file structure:** `scans/{scan_id}/` directory tree
5. **Explain benefit:** "Simple, fast, and scalable for our use case"

### If Asked: "Why not follow the ERD exactly?"
**Answer:** "The ERD shows the logical domain model. For the MVP, we implemented a simplified physical model using JSON columns and file storage. This gives us the same functionality with less complexity. We can normalize to separate tables later if needed for performance or querying."

---

## Summary

✅ **Database:** 1 table (`scans`) with 12 columns  
✅ **Storage:** Hybrid (DB metadata + file system artifacts)  
✅ **Status:** Fully functional for Iterations 1 & 2  
✅ **Verified:** Using `verify_database.py`  
✅ **Scalable:** Can handle 1000+ scans without issues  

**This is what you actually built and what works!**
