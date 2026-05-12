# VUL-RAG Database Schema Migration

This directory contains the database migration script for integrating VUL-RAG enrichment data into the CVE database.

## Overview

The migration adds a new `vulrag_enrichment` table to store additional vulnerability metadata including:
- Root causes
- Fix strategies
- Code patterns
- Attack conditions
- Vulnerability types

## Files

- `migrate_vulrag_schema.py` - Main migration script
- `test_migration.py` - Comprehensive test suite for the migration
- `verify_vulrag_schema.py` - Schema verification utility

## Usage

### Running the Migration

To migrate the default `cves.db` database:

```bash
python migrate_vulrag_schema.py
```

To migrate a custom database:

```bash
python migrate_vulrag_schema.py --db-path /path/to/custom_cves.db
```

### Testing the Migration

Run the comprehensive test suite:

```bash
python test_migration.py
```

This will test:
- Fresh database migration
- Idempotent migration (running twice on same database)
- Foreign key constraints
- Index creation and performance

### Verifying the Schema

To verify the schema was created correctly:

```bash
python verify_vulrag_schema.py
```

## Database Schema

### vulrag_enrichment Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique identifier |
| cve_id | TEXT | UNIQUE, NOT NULL, FOREIGN KEY | CVE identifier (links to cves table) |
| cwe_id | TEXT | | Common Weakness Enumeration ID |
| vulnerability_type | TEXT | | Type of vulnerability |
| root_cause | TEXT | | Root cause analysis |
| attack_condition | TEXT | | Conditions required for attack |
| fix_strategy | TEXT | | Recommended fix strategy |
| code_pattern | TEXT | | Common code patterns associated with vulnerability |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record creation timestamp |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record update timestamp |

### Indexes

- `idx_vulrag_cve_id` - Index on `cve_id` for fast lookups

### Foreign Keys

- `cve_id` references `cves(cve_id)` - Ensures enrichment data links to valid CVEs

## Migration Features

### Idempotent

The migration can be run multiple times safely. If the table already exists, it will verify the schema and report success without making changes.

### Safe

- Checks for database existence before running
- Verifies the `cves` table exists
- Uses transactions for atomic operations
- Includes rollback on errors

### Comprehensive Testing

- Tests insert and retrieve operations
- Verifies foreign key constraints
- Confirms index creation
- Validates schema structure

## Requirements

- Python 3.6+
- sqlite3 (included in Python standard library)
- Existing CVE database with `cves` table

## Migration Status

✓ Migration completed successfully on `cves.db`
- Table created: `vulrag_enrichment`
- Index created: `idx_vulrag_cve_id`
- Foreign key constraint: `cve_id -> cves(cve_id)`
- All tests passed

## Next Steps

After running the migration, you can:

1. Import VUL-RAG data using the data importer (Task 2)
2. Create enhanced embeddings with VUL-RAG fields (Task 3)
3. Build enhanced FAISS indexes (Task 4)
4. Use enhanced search functionality (Task 5)

## Troubleshooting

### Database not found

Ensure the CVE database exists at the specified path. The default is `cves.db` in the current directory.

### cves table not found

The migration requires an existing `cves` table. Ensure you have a valid CVE database before running the migration.

### Foreign key constraint not enforced

SQLite requires `PRAGMA foreign_keys = ON` to enforce foreign key constraints. The migration creates the constraint, but enforcement depends on the connection settings.

## Support

For issues or questions about the migration, refer to:
- Design document: `.kiro/specs/vulrag-knowledge-integration/design.md`
- Requirements: `.kiro/specs/vulrag-knowledge-integration/requirements.md`
- Tasks: `.kiro/specs/vulrag-knowledge-integration/tasks.md`
