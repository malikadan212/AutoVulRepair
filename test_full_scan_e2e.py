#!/usr/bin/env python3
"""
Complete end-to-end test of scan system
Simulates what happens when a user submits a scan
"""
import tempfile
import os
import json
from src.services.scan_service import ScanService
from src.repositories.scan_repository import ScanRepository
from src.models.scan_v2 import DatabaseManager

print("=" * 80)
print("END-TO-END SCAN TEST")
print("=" * 80)

# Initialize components
import os
db_url = os.getenv('DATABASE_URL', 'postgresql://autovulrepair:password@postgres:5432/autovulrepair')
db_manager = DatabaseManager(db_url)
repository = ScanRepository(db_manager)
service = ScanService(repository)

# Create test repository with vulnerable code
with tempfile.TemporaryDirectory() as tmpdir:
    # Create a vulnerable C file
    test_file = os.path.join(tmpdir, 'vulnerable.c')
    with open(test_file, 'w') as f:
        f.write('''#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    // CWE-119: Buffer overflow
    char small_buffer[10];
    strcpy(small_buffer, "This string is way too long for the buffer");
    
    // CWE-401: Memory leak
    int *leaked_ptr = malloc(100 * sizeof(int));
    // No free() - memory leak!
    
    // CWE-476: Null pointer dereference
    char *null_ptr = NULL;
    if (strlen(null_ptr) > 0) {  // Will crash
        printf("Never reached\\n");
    }
    
    return 0;
}
''')
    
    print(f"\n✓ Created test file: {test_file}")
    print(f"  Size: {os.path.getsize(test_file)} bytes")
    
    # Run static analysis (this is what the worker does)
    print("\n" + "=" * 80)
    print("RUNNING STATIC ANALYSIS")
    print("=" * 80)
    
    # Create a scan record
    import uuid
    scan_id = f'test-scan-{uuid.uuid4().hex[:8]}'
    scan_data = {
        'scan_id': scan_id,
        'user_id': 'test-user',
        'repo_url': 'test://repo',
        'source_type': 'snippet',
        'analysis_tool': 'cppcheck',
        'metadata': {'test': True}
    }
    
    scan_id = repository.create_scan(scan_data)
    print(f"\n✓ Created scan: {scan_id}")
    
    # Store source files
    with open(test_file, 'r') as f:
        content = f.read()
    
    repository.store_source_files(scan_id, [{
        'path': 'vulnerable.c',
        'content': content
    }])
    print(f"✓ Stored source files")
    
    # Run analysis
    print(f"\n→ Running Cppcheck analysis...")
    result = service.run_static_analysis(scan_id, 'cppcheck')
    
    print("\n" + "=" * 80)
    print("ANALYSIS RESULTS")
    print("=" * 80)
    
    print(f"\nStatus: {result['status']}")
    print(f"Findings: {result.get('findings_count', 0)}")
    
    # Get findings
    findings = repository.get_static_findings(scan_id)
    
    if findings:
        print(f"\n✓ Found {len(findings)} vulnerabilities\n")
        
        # Check for CWE IDs
        has_cwe = 0
        has_tool = 0
        is_fallback = 0
        
        for i, finding in enumerate(findings[:5], 1):  # Show first 5
            print(f"{i}. {finding.get('message', 'N/A')}")
            print(f"   Rule ID: {finding.get('rule_id', 'N/A')}")
            print(f"   CWE: {finding.get('cwe', 'N/A')}")
            print(f"   Tool: {finding.get('tool', 'N/A')}")
            print(f"   Confidence: {finding.get('confidence', 'N/A')}")
            print(f"   Severity: {finding.get('severity', 'N/A')}")
            
            if finding.get('cwe') and finding.get('cwe') != 'N/A':
                has_cwe += 1
            if finding.get('tool'):
                has_tool += 1
            if finding.get('tool') == 'Pattern-Based Fallback':
                is_fallback += 1
            print()
        
        # Summary
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        print(f"Total findings: {len(findings)}")
        print(f"Findings with CWE: {has_cwe}/{len(findings)}")
        print(f"Findings with tool label: {has_tool}/{len(findings)}")
        print(f"Fallback findings: {is_fallback}/{len(findings)}")
        
        # Determine if test passed
        if is_fallback > 0:
            print("\n❌ TEST FAILED: Using fallback analysis instead of real Cppcheck")
            print("   This means Docker is not accessible to the worker")
        elif has_cwe == 0:
            print("\n⚠️  TEST WARNING: No CWE IDs found")
            print("   CWE mapping may not be working")
        elif has_cwe == len(findings):
            print("\n✅ TEST PASSED: All findings have CWE IDs from real Cppcheck!")
        else:
            print(f"\n⚠️  TEST PARTIAL: {has_cwe}/{len(findings)} findings have CWE IDs")
    else:
        print("\n❌ No findings generated")
    
    # Check the JSON file that would be served to the UI
    scan_dir = os.path.join(service.scans_dir, scan_id)
    json_file = os.path.join(scan_dir, 'static_findings.json')
    
    if os.path.exists(json_file):
        print(f"\n✓ JSON file created: {json_file}")
        with open(json_file, 'r') as f:
            data = json.load(f)
        print(f"  Tool in JSON: {data.get('tool', 'N/A')}")
        print(f"  Total findings in JSON: {data.get('total_findings', 0)}")
        
        if data.get('findings'):
            first = data['findings'][0]
            print(f"  First finding CWE: {first.get('cwe', 'N/A')}")
            print(f"  First finding tool: {first.get('tool', 'N/A')}")
    else:
        print(f"\n⚠️  JSON file not created at {json_file}")

print("\n" + "=" * 80)
