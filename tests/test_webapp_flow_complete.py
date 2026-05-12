#!/usr/bin/env python3
"""
Complete verification of web app scan flow:
1. User submits scan via web form
2. Celery worker picks up the task
3. Worker runs Cppcheck via Docker
4. Results are stored in database
5. Web app displays results with CWE IDs
"""
import sys
import time
import json
import os
from src.services.scan_service import ScanService
from src.repositories.scan_repository import ScanRepository
from src.models.scan_v2 import DatabaseManager

print("=" * 80)
print("WEB APP SCAN FLOW - COMPLETE VERIFICATION")
print("=" * 80)

# Initialize (same as web app does)
db_url = os.getenv('DATABASE_URL', 'postgresql://autovulrepair:password@postgres:5432/autovulrepair')
db_manager = DatabaseManager(db_url)
repository = ScanRepository(db_manager)
service = ScanService(repository)

print("\n[STEP 1] User submits scan via web form")
print("-" * 80)

# Simulate what happens when user submits the scan form
scan_data = {
    'source_type': 'snippet',
    'analysis_tool': 'cppcheck',
    'code_snippet': '''#include <string.h>
#include <stdlib.h>

int main() {
    // CWE-119: Buffer overflow
    char small[10];
    strcpy(small, "This is way too long for the buffer!");
    
    // CWE-401: Memory leak
    int *leaked = malloc(100);
    // No free()
    
    // CWE-476: Null pointer dereference
    char *null_ptr = NULL;
    strcpy(null_ptr, "crash");
    
    return 0;
}
''',
    'repo_url': None,
    'file_upload': None
}

print(f"✓ Scan type: {scan_data['source_type']}")
print(f"✓ Analysis tool: {scan_data['analysis_tool']}")
print(f"✓ Code size: {len(scan_data['code_snippet'])} bytes")

# Create scan (this is what the web app does)
result = service.create_scan(
    source_type=scan_data['source_type'],
    code_snippet=scan_data['code_snippet'],
    analysis_tool=scan_data['analysis_tool'],
    user_id='test-user-webapp'
)

scan_id = result['scan_id']
print(f"\n✓ Scan created: {scan_id}")
print(f"✓ Status: {result['status']}")

if 'task_id' in result:
    print(f"✓ Celery task ID: {result['task_id']}")
    print("\n[STEP 2] Celery worker processing")
    print("-" * 80)
    print("✓ Task queued to Celery")
    print("✓ Worker will pick up task from Redis queue")
    
    # Wait for processing
    print("\nWaiting for Celery worker to process...")
    max_wait = 30
    waited = 0
    
    while waited < max_wait:
        scan_status = service.get_scan_status(scan_id)
        status = scan_status.get('status') if scan_status else 'unknown'
        
        if status == 'completed':
            print(f"✓ Scan completed in {waited} seconds")
            break
        elif status == 'failed':
            print(f"✗ Scan failed: {scan_status.get('error_message')}")
            sys.exit(1)
        
        time.sleep(1)
        waited += 1
        if waited % 5 == 0:
            print(f"  Still processing... ({waited}s)")
    
    if waited >= max_wait:
        print(f"✗ Timeout after {max_wait} seconds")
        sys.exit(1)
else:
    print("\n⚠️  No Celery task ID - running synchronously")

print("\n[STEP 3] Verify Docker + Cppcheck execution")
print("-" * 80)

# Check the scan results
scan_results = service.get_scan_results(scan_id)

if scan_results.get('error'):
    print(f"✗ Error: {scan_results['error']}")
    sys.exit(1)

findings = scan_results.get('findings', [])
print(f"✓ Found {len(findings)} vulnerabilities")

# Verify findings have proper structure
if not findings:
    print("✗ No findings generated!")
    sys.exit(1)

print("\n[STEP 4] Verify Cppcheck output quality")
print("-" * 80)

# Check for real Cppcheck indicators
has_cwe = 0
has_tool = 0
is_fallback = 0
cwe_list = []

for finding in findings:
    if finding.get('cwe'):
        has_cwe += 1
        cwe_list.append(finding.get('cwe'))
    
    tool = finding.get('tool') or finding.get('metadata_json', {}).get('tool')
    if tool:
        has_tool += 1
        if tool == 'Pattern-Based Fallback':
            is_fallback += 1

print(f"✓ Findings with CWE: {has_cwe}/{len(findings)}")
print(f"✓ Findings with tool label: {has_tool}/{len(findings)}")
print(f"✓ Fallback findings: {is_fallback}/{len(findings)}")

if is_fallback > 0:
    print("\n✗ FAIL: Using fallback analysis instead of real Cppcheck!")
    print("  This means Docker is not accessible to Celery workers")
    sys.exit(1)

if has_cwe == 0:
    print("\n✗ FAIL: No CWE IDs found!")
    print("  CWE extraction is not working")
    sys.exit(1)

print(f"\n✓ CWE IDs found: {', '.join(set(cwe_list))}")

print("\n[STEP 5] Verify web app display data")
print("-" * 80)

# Check the JSON file that web app would serve
scan_dir = os.path.join(service.scans_dir, scan_id)
json_file = os.path.join(scan_dir, 'static_findings.json')

if not os.path.exists(json_file):
    print(f"✗ JSON file not created: {json_file}")
    sys.exit(1)

with open(json_file, 'r') as f:
    json_data = json.load(f)

print(f"✓ JSON file exists: {json_file}")
print(f"✓ Total findings in JSON: {json_data.get('total_findings', 0)}")

# Show sample findings
print("\n[STEP 6] Sample findings (what user sees)")
print("-" * 80)

for i, finding in enumerate(findings[:3], 1):
    print(f"\n{i}. {finding.get('message', 'N/A')}")
    print(f"   File: {finding.get('file_path', 'N/A')}")
    print(f"   Line: {finding.get('line_number', 'N/A')}")
    print(f"   CWE: {finding.get('cwe', 'N/A')}")
    print(f"   Severity: {finding.get('severity', 'N/A')}")
    print(f"   Confidence: {finding.get('confidence', 'N/A')}")
    tool = finding.get('tool') or finding.get('metadata_json', {}).get('tool', 'N/A')
    print(f"   Tool: {tool}")

print("\n" + "=" * 80)
print("VERIFICATION RESULT")
print("=" * 80)

# Final checks
checks = {
    'Celery task created': 'task_id' in result,
    'Scan completed': scan_results.get('scan', {}).get('status') == 'completed',
    'Findings generated': len(findings) > 0,
    'CWE IDs present': has_cwe > 0,
    'Using real Cppcheck': is_fallback == 0,
    'JSON file created': os.path.exists(json_file),
    'High confidence': all(f.get('confidence') == 'high' for f in findings if f.get('confidence'))
}

all_passed = all(checks.values())

for check, passed in checks.items():
    status = "✅" if passed else "❌"
    print(f"{status} {check}")

print("\n" + "=" * 80)
if all_passed:
    print("✅ ALL CHECKS PASSED - Web app flow is working correctly!")
    print("\nThe system is:")
    print("  • Using Celery for background processing")
    print("  • Running real Cppcheck via Docker")
    print("  • Extracting CWE IDs correctly")
    print("  • Storing results in database")
    print("  • Creating JSON files for web display")
    sys.exit(0)
else:
    print("❌ SOME CHECKS FAILED - See details above")
    sys.exit(1)
