"""
Verification script for VUL-RAG enrichment schema

Displays detailed information about the vulrag_enrichment table
"""

import sqlite3


def verify_schema(db_path: str = 'cves.db'):
    """Verify and display the vulrag_enrichment schema"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("=" * 60)
    print("VUL-RAG Enrichment Schema Verification")
    print("=" * 60)
    print(f"Database: {db_path}\n")
    
    # Check table exists
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='vulrag_enrichment'
    """)
    
    if not cursor.fetchone():
        print("✗ Table 'vulrag_enrichment' not found!")
        conn.close()
        return
    
    print("✓ Table 'vulrag_enrichment' exists\n")
    
    # Display schema
    print("Table Schema:")
    print("-" * 60)
    cursor.execute("PRAGMA table_info(vulrag_enrichment)")
    columns = cursor.fetchall()
    
    for col in columns:
        col_id, name, col_type, not_null, default, pk = col
        constraints = []
        if pk:
            constraints.append("PRIMARY KEY")
        if not_null:
            constraints.append("NOT NULL")
        if default:
            constraints.append(f"DEFAULT {default}")
        
        constraint_str = f" ({', '.join(constraints)})" if constraints else ""
        print(f"  {name:20} {col_type:15} {constraint_str}")
    
    # Display indexes
    print("\nIndexes:")
    print("-" * 60)
    cursor.execute("""
        SELECT name, sql FROM sqlite_master 
        WHERE type='index' AND tbl_name='vulrag_enrichment'
    """)
    
    indexes = cursor.fetchall()
    if indexes:
        for idx_name, idx_sql in indexes:
            if idx_sql:  # Skip auto-created indexes
                print(f"  {idx_name}")
                print(f"    {idx_sql}")
    else:
        print("  No indexes found")
    
    # Display foreign keys
    print("\nForeign Keys:")
    print("-" * 60)
    cursor.execute("PRAGMA foreign_key_list(vulrag_enrichment)")
    fks = cursor.fetchall()
    
    if fks:
        for fk in fks:
            fk_id, seq, table, from_col, to_col, on_update, on_delete, match = fk
            print(f"  {from_col} -> {table}({to_col})")
    else:
        print("  No foreign keys found")
    
    # Display record count
    print("\nRecord Count:")
    print("-" * 60)
    cursor.execute("SELECT COUNT(*) FROM vulrag_enrichment")
    count = cursor.fetchone()[0]
    print(f"  Total records: {count}")
    
    # Display sample data if any
    if count > 0:
        print("\nSample Records:")
        print("-" * 60)
        cursor.execute("SELECT * FROM vulrag_enrichment LIMIT 3")
        samples = cursor.fetchall()
        
        for sample in samples:
            print(f"\n  CVE ID: {sample[1]}")
            print(f"  CWE ID: {sample[2]}")
            print(f"  Vulnerability Type: {sample[3]}")
            print(f"  Root Cause: {sample[4][:50] if sample[4] else 'N/A'}...")
            print(f"  Fix Strategy: {sample[5][:50] if sample[5] else 'N/A'}...")
    
    print("\n" + "=" * 60)
    print("✓ Schema verification complete")
    print("=" * 60)
    
    conn.close()


if __name__ == '__main__':
    verify_schema()
