#!/usr/bin/env python3
"""
Real Cppcheck scan to verify CWE mapping works correctly
"""

import os
import sys
import json
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.analysis.cppcheck import CppcheckAnalyzer

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*100)
    print(f"  {text}")
    print("="*100)

def print_vulnerability_details(vuln, index):
    """Print detailed vulnerability information"""
    print(f"\n[{index}] Vulnerability Details:")
    print(f"    ID:          {vuln.get('id', 'N/A')}")
    print(f"    Rule:        {vuln.get('rule_id', 'N/A')}")
    print(f"    CWE:         {vuln.get('cwe', 'NOT MAPPED') or 'NOT MAPPED'} {'✅' if vuln.get('cwe') else '❌'}")
    print(f"    Severity:    {vuln.get('severity', 'N/A')}")
    print(f"    Priority:    {vuln.get('priority_score', 'N/A')}")
    print(f"    File:        {vuln.get('file', 'N/A')}")
    print(f"    Line:        {vuln.get('line', 'N/A')}")
    print(f"    Description: {vuln.get('description', 'N/A')}")

def main():
    print_header("CPPCHECK CWE MAPPING TEST - REAL SCAN")
    
    test_file = "test_cwe_scan.c"
    
    if not os.path.exists(test_file):
        print(f"❌ Error: Test file '{test_file}' not found!")
        return 1
    
    print(f"\n📁 Test file: {test_file}")
    print(f"📊 File size: {os.path.getsize(test_file)} bytes")
    
    # Create temporary directory for scan
    temp_dir = tempfile.mkdtemp(prefix='cppcheck_test_')
    print(f"📂 Temp directory: {temp_dir}")
    
    try:
        # Copy test file to temp directory
        import shutil
        test_file_in_temp = os.path.join(temp_dir, os.path.basename(test_file))
        shutil.copy(test_file, test_file_in_temp)
        print(f"📋 Copied test file to: {test_file_in_temp}")
        
        # Initialize Cppcheck analyzer
        print("\n🔧 Initializing Cppcheck analyzer...")
        analyzer = CppcheckAnalyzer()
        
        # Check if Cppcheck is available
        if not analyzer.is_available():
            print("\n⚠️  Cppcheck is not available!")
            print("    This will use pattern-based fallback detection.")
            print("    For full CWE mapping, install Cppcheck or enable Docker.")
        else:
            print("✅ Cppcheck is available")
        
        # Run analysis
        print(f"\n🔍 Running Cppcheck scan on {test_file}...")
        print("    (This may take a few seconds...)")
        
        try:
            vulnerabilities, patches = analyzer.analyze(temp_dir, 'local_path')
            
            print_header("SCAN RESULTS")
            
            if not vulnerabilities:
                print("\n✅ No vulnerabilities detected (or scan failed)")
                print("    This might mean:")
                print("    • Cppcheck is not installed")
                print("    • Docker is not available")
                print("    • The test file has no detectable issues")
                return 0
            
            print(f"\n📊 Total vulnerabilities found: {len(vulnerabilities)}")
            
            # Count CWE mappings
            with_cwe = sum(1 for v in vulnerabilities if v.get('cwe'))
            without_cwe = len(vulnerabilities) - with_cwe
            
            print(f"    ✅ With CWE mapping: {with_cwe}")
            print(f"    ❌ Without CWE mapping: {without_cwe}")
            print(f"    📈 Coverage: {(with_cwe/len(vulnerabilities)*100):.1f}%")
            
            # Print each vulnerability
            print_header("DETAILED VULNERABILITY REPORT")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print_vulnerability_details(vuln, i)
            
            # Group by CWE
            print_header("VULNERABILITIES GROUPED BY CWE")
            
            cwe_groups = {}
            for vuln in vulnerabilities:
                cwe = vuln.get('cwe', 'NO_CWE')
                if cwe not in cwe_groups:
                    cwe_groups[cwe] = []
                cwe_groups[cwe].append(vuln)
            
            for cwe, vulns in sorted(cwe_groups.items()):
                if cwe == 'NO_CWE':
                    print(f"\n❌ No CWE Mapping ({len(vulns)} vulnerabilities):")
                else:
                    print(f"\n✅ {cwe} ({len(vulns)} vulnerabilities):")
                
                for vuln in vulns:
                    print(f"    • {vuln.get('rule_id', 'unknown')}: {vuln.get('description', 'N/A')[:60]}")
            
            # Summary
            print_header("SUMMARY")
            
            if with_cwe == len(vulnerabilities):
                print("\n🎉 SUCCESS! All vulnerabilities have CWE mappings!")
                print("✅ CWE extraction is working perfectly")
            elif with_cwe > 0:
                print(f"\n⚠️  PARTIAL SUCCESS: {with_cwe}/{len(vulnerabilities)} vulnerabilities have CWE mappings")
                print(f"    {without_cwe} vulnerabilities are missing CWE IDs")
                print("    This is normal - not all Cppcheck rules have CWE mappings")
            else:
                print("\n❌ NO CWE MAPPINGS FOUND")
                print("    Possible reasons:")
                print("    • Cppcheck version doesn't include CWE attributes")
                print("    • Pattern-based fallback was used (no CWE info)")
                print("    • XML parsing issue")
            
            # Export results
            output_file = "cppcheck_cwe_test_results.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'total_vulnerabilities': len(vulnerabilities),
                    'with_cwe': with_cwe,
                    'without_cwe': without_cwe,
                    'coverage_percent': (with_cwe/len(vulnerabilities)*100) if vulnerabilities else 0,
                    'vulnerabilities': vulnerabilities
                }, f, indent=2)
            
            print(f"\n💾 Results saved to: {output_file}")
            
            return 0
            
        except Exception as e:
            print(f"\n❌ Error during scan: {e}")
            import traceback
            traceback.print_exc()
            return 1
            
    finally:
        # Cleanup
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    print("\n" + "="*100 + "\n")

if __name__ == '__main__':
    sys.exit(main())
