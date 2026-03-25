"""
Integration test demonstrating the complete VUL-RAG import workflow
"""

import json
import tempfile
import os
from vulrag_importer import VulRagImporter


def main():
    print("=" * 70)
    print("VUL-RAG Import Workflow Demonstration")
    print("=" * 70)
    
    # Step 1: Create sample VUL-RAG data
    print("\n1. Creating sample VUL-RAG data...")
    sample_data = [
        {
            "cve_id": "CVE-2024-WORKFLOW1",
            "cwe_id": "CWE-79",
            "vulnerability_type": "Cross-Site Scripting",
            "root_cause": "Insufficient input validation",
            "attack_condition": "User can inject scripts",
            "fix_strategy": "Implement input sanitization",
            "code_pattern": "Unescaped user input",
            "description": "XSS vulnerability in form handler"
        },
        {
            "cve_id": "CVE-2024-WORKFLOW2",
            "cwe_id": "CWE-89",
            "vulnerability_type": "SQL Injection",
            "root_cause": "String concatenation in SQL",
            "attack_condition": "User can manipulate queries",
            "fix_strategy": "Use parameterized queries",
            "code_pattern": "Direct string concatenation",
            "description": "SQL injection in login form"
        },
        {
            "cve_id": "CVE-2024-INVALID",
            "description": ""  # Invalid: empty description
        }
    ]
    
    # Save to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_data, f)
        temp_file = f.name
    
    print(f"✓ Created sample data with {len(sample_data)} entries")
    
    try:
        # Step 2: Initialize importer
        print("\n2. Initializing VUL-RAG importer...")
        importer = VulRagImporter(db_path='cves.db')
        print("✓ Importer initialized")
        
        # Step 3: Import data
        print("\n3. Importing VUL-RAG data...")
        result = importer.import_from_json(temp_file)
        
        print(f"\n   Import Results:")
        print(f"   - Total entries: {result.total_entries}")
        print(f"   - Successfully imported: {result.success_count}")
        print(f"   - Errors: {result.error_count}")
        
        if result.errors:
            print(f"\n   Error details:")
            for error in result.errors:
                print(f"   - Entry {error['entry_index']} ({error['cve_id']}): {error['error']}")
        
        # Step 4: Verify import
        print("\n4. Verifying imported data...")
        stats = importer.get_import_stats()
        print(f"   Total enrichments in database: {stats['total_enrichments']}")
        
        # Step 5: Test duplicate handling
        print("\n5. Testing duplicate handling (re-importing same data)...")
        result2 = importer.import_from_json(temp_file)
        stats2 = importer.get_import_stats()
        
        print(f"   Second import: {result2.success_count} successful")
        print(f"   Total enrichments (should be same): {stats2['total_enrichments']}")
        
        if stats2['total_enrichments'] == stats['total_enrichments']:
            print("   ✓ Duplicates were merged correctly!")
        
        print("\n" + "=" * 70)
        print("✓ Workflow completed successfully!")
        print("=" * 70)
        
    finally:
        # Cleanup
        os.unlink(temp_file)


if __name__ == '__main__':
    main()
