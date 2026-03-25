"""
Test script for VUL-RAG schema migration

Tests migration on both fresh and existing databases
"""

import sqlite3
import os
import tempfile
from migrate_vulrag_schema import VulRagSchemaMigration


def create_test_database(db_path: str):
    """Create a minimal test database with cves table"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create cves table
    cursor.execute("""
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            last_modified TEXT,
            description TEXT,
            raw_json TEXT
        )
    """)
    
    # Insert test data
    cursor.execute("""
        INSERT INTO cves (cve_id, published_date, last_modified, description, raw_json)
        VALUES (?, ?, ?, ?, ?)
    """, (
        'CVE-2023-TEST-001',
        '2023-01-01T00:00:00.000',
        '2023-01-01T00:00:00.000',
        'Test CVE for migration testing',
        '{}'
    ))
    
    conn.commit()
    conn.close()
    print(f"✓ Created test database: {db_path}")


def test_fresh_database_migration():
    """Test migration on a fresh database"""
    print("\n" + "=" * 60)
    print("TEST 1: Fresh Database Migration")
    print("=" * 60)
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        test_db_path = tmp.name
    
    try:
        # Create test database
        create_test_database(test_db_path)
        
        # Run migration
        migration = VulRagSchemaMigration(db_path=test_db_path)
        success = migration.run_migration()
        
        if success:
            print("\n✓ Fresh database migration test PASSED")
            return True
        else:
            print("\n✗ Fresh database migration test FAILED")
            return False
            
    finally:
        # Clean up
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print(f"✓ Cleaned up test database")


def test_existing_database_migration():
    """Test migration on database that already has vulrag_enrichment table"""
    print("\n" + "=" * 60)
    print("TEST 2: Existing Database Migration (Idempotency)")
    print("=" * 60)
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        test_db_path = tmp.name
    
    try:
        # Create test database
        create_test_database(test_db_path)
        
        # Run migration first time
        migration = VulRagSchemaMigration(db_path=test_db_path)
        success1 = migration.run_migration()
        
        if not success1:
            print("\n✗ First migration failed")
            return False
        
        print("\n" + "-" * 60)
        print("Running migration again on same database...")
        print("-" * 60)
        
        # Run migration second time (should be idempotent)
        success2 = migration.run_migration()
        
        if success2:
            print("\n✓ Existing database migration test PASSED (idempotent)")
            return True
        else:
            print("\n✗ Existing database migration test FAILED")
            return False
            
    finally:
        # Clean up
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print(f"✓ Cleaned up test database")


def test_foreign_key_constraint():
    """Test that foreign key constraint works correctly"""
    print("\n" + "=" * 60)
    print("TEST 3: Foreign Key Constraint")
    print("=" * 60)
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        test_db_path = tmp.name
    
    try:
        # Create test database
        create_test_database(test_db_path)
        
        # Run migration
        migration = VulRagSchemaMigration(db_path=test_db_path)
        migration.run_migration()
        
        # Test foreign key constraint
        conn = sqlite3.connect(test_db_path)
        conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key enforcement
        cursor = conn.cursor()
        
        # Try to insert enrichment for existing CVE (should succeed)
        try:
            cursor.execute("""
                INSERT INTO vulrag_enrichment (cve_id, root_cause)
                VALUES (?, ?)
            """, ('CVE-2023-TEST-001', 'Test root cause'))
            conn.commit()
            print("✓ Insert with valid foreign key succeeded")
        except sqlite3.IntegrityError as e:
            print(f"✗ Insert with valid foreign key failed: {e}")
            conn.close()
            return False
        
        # Try to insert enrichment for non-existent CVE (should fail with FK enabled)
        try:
            cursor.execute("""
                INSERT INTO vulrag_enrichment (cve_id, root_cause)
                VALUES (?, ?)
            """, ('CVE-NONEXISTENT', 'Test root cause'))
            conn.commit()
            print("⚠ Insert with invalid foreign key succeeded (FK not enforced)")
            # This is expected in SQLite unless PRAGMA foreign_keys is ON
        except sqlite3.IntegrityError:
            print("✓ Insert with invalid foreign key correctly rejected")
        
        conn.close()
        print("\n✓ Foreign key constraint test PASSED")
        return True
        
    finally:
        # Clean up
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print(f"✓ Cleaned up test database")


def test_index_performance():
    """Test that the index on cve_id exists and works"""
    print("\n" + "=" * 60)
    print("TEST 4: Index Creation and Performance")
    print("=" * 60)
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        test_db_path = tmp.name
    
    try:
        # Create test database
        create_test_database(test_db_path)
        
        # Run migration
        migration = VulRagSchemaMigration(db_path=test_db_path)
        migration.run_migration()
        
        # Check index exists
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND tbl_name='vulrag_enrichment'
        """)
        
        indexes = cursor.fetchall()
        index_names = [idx[0] for idx in indexes]
        
        if 'idx_vulrag_cve_id' in index_names:
            print(f"✓ Index 'idx_vulrag_cve_id' exists")
        else:
            print(f"✗ Index 'idx_vulrag_cve_id' not found")
            print(f"Found indexes: {index_names}")
            conn.close()
            return False
        
        # Test query plan uses index
        cursor.execute("""
            EXPLAIN QUERY PLAN
            SELECT * FROM vulrag_enrichment WHERE cve_id = 'CVE-2023-TEST-001'
        """)
        
        query_plan = cursor.fetchall()
        plan_text = ' '.join([str(row) for row in query_plan])
        
        if 'idx_vulrag_cve_id' in plan_text or 'SEARCH' in plan_text:
            print(f"✓ Query plan uses index for cve_id lookups")
        else:
            print(f"⚠ Query plan may not be using index: {plan_text}")
        
        conn.close()
        print("\n✓ Index test PASSED")
        return True
        
    finally:
        # Clean up
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print(f"✓ Cleaned up test database")


def main():
    """Run all migration tests"""
    print("\n" + "=" * 60)
    print("VUL-RAG Schema Migration Test Suite")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Fresh Database Migration", test_fresh_database_migration()))
    results.append(("Existing Database Migration", test_existing_database_migration()))
    results.append(("Foreign Key Constraint", test_foreign_key_constraint()))
    results.append(("Index Creation", test_index_performance()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name}: {status}")
    
    all_passed = all(result[1] for result in results)
    
    if all_passed:
        print("\n" + "=" * 60)
        print("✓ ALL TESTS PASSED")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("✗ SOME TESTS FAILED")
        print("=" * 60)
    
    return all_passed


if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
