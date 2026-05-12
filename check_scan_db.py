#!/usr/bin/env python3
import sqlite3
import json

scan_id = '91b543c8-4695-42a9-8ff9-267ef627c552'

conn = sqlite3.connect('autovulrepair.db')
cursor = conn.cursor()

# List tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [row[0] for row in cursor.fetchall()]
print(f"Tables: {tables}\n")

# Check scan_results table
if 'scan_results' in tables:
    cursor.execute("SELECT scan_id, analysis_tool, status FROM scan_results WHERE scan_id = ?", (scan_id,))
    result = cursor.fetchone()
    if result:
        print(f"Scan record: {result}")
    else:
        print(f"No scan found with ID: {scan_id}")
    
    # Check vulnerabilities
    cursor.execute("SELECT COUNT(*), tool FROM vulnerabilities WHERE scan_id = ? GROUP BY tool", (scan_id,))
    vuln_counts = cursor.fetchall()
    print(f"\nVulnerability counts by tool:")
    for count, tool in vuln_counts:
        print(f"  {tool}: {count}")
    
    # Sample vulnerability
    cursor.execute("SELECT tool, confidence, message FROM vulnerabilities WHERE scan_id = ? LIMIT 1", (scan_id,))
    sample = cursor.fetchone()
    if sample:
        print(f"\nSample vulnerability:")
        print(f"  Tool: {sample[0]}")
        print(f"  Confidence: {sample[1]}")
        print(f"  Message: {sample[2][:80]}...")

conn.close()
