"""Quick verification script for VUL-RAG importer"""
import sqlite3

conn = sqlite3.connect('cves.db')
cursor = conn.cursor()

# Get all enrichment data
cursor.execute("""
    SELECT cve_id, cwe_id, vulnerability_type, root_cause, fix_strategy
    FROM vulrag_enrichment
""")

results = cursor.fetchall()

print("Imported VUL-RAG Enrichment Data:")
print("=" * 80)
for row in results:
    print(f"\nCVE ID: {row[0]}")
    print(f"CWE ID: {row[1]}")
    print(f"Type: {row[2]}")
    print(f"Root Cause: {row[3]}")
    print(f"Fix Strategy: {row[4]}")
    print("-" * 80)

conn.close()
