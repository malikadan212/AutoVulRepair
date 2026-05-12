#!/usr/bin/env python3
"""Test to see actual Cppcheck XML output"""
import tempfile
import os
from src.analysis.cppcheck import CppcheckAnalyzer

# Create test file with known vulnerability
with tempfile.TemporaryDirectory() as tmpdir:
    test_file = os.path.join(tmpdir, 'test.c')
    with open(test_file, 'w') as f:
        f.write('''#include <string.h>
#include <stdlib.h>

int main() { 
    char buf[10]; 
    strcpy(buf, "this is way too long and will overflow"); 
    
    int *ptr = malloc(100);
    // Memory leak - no free()
    
    return 0; 
}''')
    
    # Run analysis
    analyzer = CppcheckAnalyzer()
    print('Running Cppcheck...')
    vulns, patches = analyzer.analyze(tmpdir, 'test_repo')
    
    print(f'\n✅ Found {len(vulns)} vulnerabilities\n')
    
    for i, vuln in enumerate(vulns, 1):
        print(f'{i}. {vuln.get("description", "N/A")}')
        print(f'   CWE: {vuln.get("cwe", "N/A")}')
        print(f'   Rule: {vuln.get("rule_id", "N/A")}')
        print(f'   Severity: {vuln.get("severity", "N/A")}')
        print()
