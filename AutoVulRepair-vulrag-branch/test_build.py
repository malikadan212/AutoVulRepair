#!/usr/bin/env python3
"""Test script to trigger a build"""

from src.build.orchestrator import BuildOrchestrator

scan_id = 'db0b7f9d-24cc-4a7f-ae59-7924ae0ec05e'
scan_dir = f'/app/scans/{scan_id}'

print(f"Building targets for scan: {scan_id}")
bo = BuildOrchestrator(scan_dir)
results = bo.build_all_targets()

success_count = sum(1 for r in results if r['status'] == 'success')
error_count = sum(1 for r in results if r['status'] == 'error')

print(f"\nBuild Results:")
print(f"  Success: {success_count}")
print(f"  Failed: {error_count}")

if error_count > 0:
    print("\nFailed builds:")
    for r in results:
        if r['status'] == 'error':
            print(f"  - {r['target_name']}: {r['log'][:100]}")
