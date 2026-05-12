"""
Database Migration Script for VUL-RAG Enrichment

This script adds the vulrag_enrichment table to the CVE database to support
VUL-RAG knowledge base integration with fix strategies and root cause analysis.

Usage:
    python migrate_vulrag_schema.py
    python migrate_vulrag_schema.py --db-path custom_cves.db
"""

import sqlite3
import argparse
import os
from datetime import datetime


class VulRagSchemaMigration:
    """Handles database schema migration for VUL-RAG enrichment"""
    
    def __init__(self, db_path: str = 'cves.db'):
        """Initialize migration with database path"""
        self.db_path = db_path
        
    def check_database_exists(self) -> bool:
        """Check if the database file exists"""
        return os.path.exists(self.db_path)
    
    def check_cves_table_exists(self) -> bool:
        """Check if the cves table exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='cves'
        """)
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def check_vulrag_table_exists(self) -> bool:
        """Check if the vulrag_enrichment table already exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='vulrag_enrichment'
        """)
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def create_vulrag_enrichment_table(self):
        """Create the vulrag_enrichment table with all required fields"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Create the vulrag_enrichment table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulrag_enrichment (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    cwe_id TEXT,
                    vulnerability_type TEXT,
                    root_cause TEXT,
                    attack_condition TEXT,
                    fix_strategy TEXT,
                    code_pattern TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
                )
            """)
            
            # Create index on cve_id for fast lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulrag_cve_id 
                ON vulrag_enrichment(cve_id)
            """)
            
            conn.commit()
            print("✓ vulrag_enrichment table created successfully")
            print("✓ Index on cve_id created successfully")
            
        except sqlite3.Error as e:
            conn.rollback()
            print(f"✗ Error creating table: {e}")
            raise
        finally:
            conn.close()
    
    def verify_schema(self) -> bool:
        """Verify that the schema was created correctly"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check table exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='vulrag_enrichment'
            """)
            
            if not cursor.fetchone():
                print("✗ Table vulrag_enrichment not found")
                return False
            
            # Check table schema
            cursor.execute("PRAGMA table_info(vulrag_enrichment)")
            columns = cursor.fetchall()
            
            expected_columns = {
                'id', 'cve_id', 'cwe_id', 'vulnerability_type',
                'root_cause', 'attack_condition', 'fix_strategy',
                'code_pattern', 'created_at', 'updated_at'
            }
            
            actual_columns = {col[1] for col in columns}
            
            if expected_columns != actual_columns:
                print(f"✗ Column mismatch. Expected: {expected_columns}, Got: {actual_columns}")
                return False
            
            # Check index exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='index' AND name='idx_vulrag_cve_id'
            """)
            
            if not cursor.fetchone():
                print("✗ Index idx_vulrag_cve_id not found")
                return False
            
            # Check foreign key constraint
            cursor.execute("PRAGMA foreign_key_list(vulrag_enrichment)")
            fk_info = cursor.fetchall()
            
            if not fk_info:
                print("⚠ Warning: Foreign key constraint not found (may not be enforced)")
            else:
                # Verify it references cves table
                fk_table = fk_info[0][2]
                fk_column = fk_info[0][3]
                if fk_table != 'cves' or fk_column != 'cve_id':
                    print(f"✗ Foreign key references wrong table/column: {fk_table}.{fk_column}")
                    return False
            
            print("✓ Schema verification passed")
            return True
            
        except sqlite3.Error as e:
            print(f"✗ Error verifying schema: {e}")
            return False
        finally:
            conn.close()
    
    def test_insert_and_retrieve(self) -> bool:
        """Test inserting and retrieving a sample record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        test_cve_id = f"TEST-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        try:
            # First, check if we need to insert a test CVE
            cursor.execute("SELECT cve_id FROM cves LIMIT 1")
            existing_cve = cursor.fetchone()
            
            if existing_cve:
                test_cve_id = existing_cve[0]
                print(f"Using existing CVE for test: {test_cve_id}")
            else:
                print("⚠ No CVEs in database, skipping insert test")
                return True
            
            # Insert test enrichment data
            cursor.execute("""
                INSERT INTO vulrag_enrichment 
                (cve_id, cwe_id, vulnerability_type, root_cause, attack_condition, 
                 fix_strategy, code_pattern)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                test_cve_id,
                'CWE-79',
                'Cross-Site Scripting',
                'Insufficient input validation',
                'Attacker can inject scripts',
                'Implement input sanitization',
                'Unescaped user input'
            ))
            
            conn.commit()
            
            # Retrieve the data
            cursor.execute("""
                SELECT cve_id, cwe_id, vulnerability_type, root_cause, 
                       attack_condition, fix_strategy, code_pattern
                FROM vulrag_enrichment
                WHERE cve_id = ?
            """, (test_cve_id,))
            
            result = cursor.fetchone()
            
            if not result:
                print("✗ Failed to retrieve test data")
                return False
            
            # Verify data matches
            if result[0] != test_cve_id:
                print("✗ Retrieved data doesn't match inserted data")
                return False
            
            # Clean up test data
            cursor.execute("DELETE FROM vulrag_enrichment WHERE cve_id = ?", (test_cve_id,))
            conn.commit()
            
            print("✓ Insert and retrieve test passed")
            return True
            
        except sqlite3.Error as e:
            conn.rollback()
            print(f"✗ Error during insert/retrieve test: {e}")
            return False
        finally:
            conn.close()
    
    def run_migration(self):
        """Run the complete migration process"""
        print("=" * 60)
        print("VUL-RAG Database Schema Migration")
        print("=" * 60)
        print(f"Database: {self.db_path}\n")
        
        # Check if database exists
        if not self.check_database_exists():
            print(f"✗ Database file '{self.db_path}' not found!")
            print("Please ensure the CVE database exists before running migration.")
            return False
        
        print("✓ Database file found")
        
        # Check if cves table exists
        if not self.check_cves_table_exists():
            print("✗ The 'cves' table does not exist in the database!")
            print("Please ensure you have a valid CVE database.")
            return False
        
        print("✓ cves table exists")
        
        # Check if vulrag_enrichment table already exists
        if self.check_vulrag_table_exists():
            print("⚠ vulrag_enrichment table already exists")
            print("Migration may have already been run.")
            
            # Verify schema anyway
            if self.verify_schema():
                print("\n✓ Migration already complete and schema is valid")
                return True
            else:
                print("\n✗ Existing schema has issues")
                return False
        
        # Create the table
        print("\nCreating vulrag_enrichment table...")
        self.create_vulrag_enrichment_table()
        
        # Verify the schema
        print("\nVerifying schema...")
        if not self.verify_schema():
            print("\n✗ Migration failed - schema verification failed")
            return False
        
        # Test insert and retrieve
        print("\nTesting insert and retrieve...")
        if not self.test_insert_and_retrieve():
            print("\n✗ Migration failed - insert/retrieve test failed")
            return False
        
        print("\n" + "=" * 60)
        print("✓ Migration completed successfully!")
        print("=" * 60)
        print("\nThe database is now ready for VUL-RAG enrichment data.")
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Migrate CVE database schema for VUL-RAG enrichment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Migrate default database
  python migrate_vulrag_schema.py
  
  # Migrate custom database
  python migrate_vulrag_schema.py --db-path /path/to/custom_cves.db
        """
    )
    
    parser.add_argument(
        '--db-path',
        default='cves.db',
        help='Path to CVE database (default: cves.db)'
    )
    
    args = parser.parse_args()
    
    # Run migration
    migration = VulRagSchemaMigration(db_path=args.db_path)
    success = migration.run_migration()
    
    exit(0 if success else 1)


if __name__ == '__main__':
    main()
