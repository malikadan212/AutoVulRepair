#!/usr/bin/env python3
"""Test script to trigger a build for the new scan"""

from src.build.orchestrator import BuildOrchestrator

scan_id = '3a1307b0-0740-4cfb-974c-07340ff3b70a'
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
            print(f"  - {r['target_name']}: {r['log'][:200]}")
