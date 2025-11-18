#!/usr/bin/env python3
"""
Helper script to convert existing scan artifacts to static_findings.json
This bridges Module 1 output to Module 2 input
"""
import os
import sys
from src.module1.cppcheck_to_findings import convert_cppcheck_to_findings

def convert_scan(scan_id):
    """Convert a scan's artifacts to static_findings.json"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    if not os.path.exists(scan_dir):
        print(f"Error: Scan directory not found: {scan_dir}")
        return False
    
    # Look for cppcheck XML
    artifacts_dir = os.path.join(scan_dir, 'artifacts')
    cppcheck_xml = os.path.join(artifacts_dir, 'cppcheck-report.xml')
    
    if not os.path.exists(cppcheck_xml):
        print(f"Error: Cppcheck XML not found: {cppcheck_xml}")
        return False
    
    # Convert to static_findings.json
    output_path = os.path.join(scan_dir, 'static_findings.json')
    print(f"Converting {cppcheck_xml} to {output_path}")
    
    convert_cppcheck_to_findings(cppcheck_xml, output_path)
    print(f"✓ Conversion complete: {output_path}")
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python convert_scan_to_findings.py <scan_id>")
        sys.exit(1)
    
    scan_id = sys.argv[1]
    success = convert_scan(scan_id)
    sys.exit(0 if success else 1)
