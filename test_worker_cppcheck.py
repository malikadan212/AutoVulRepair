#!/usr/bin/env python3
"""Test script to verify Cppcheck works in worker"""
import tempfile
import os
from src.analysis.cppcheck import CppcheckAnalyzer

# Create test file
with tempfile.TemporaryDirectory() as tmpdir:
    test_file = os.path.join(tmpdir, 'test.c')
    with open(test_file, 'w') as f:
        f.write('''#include <string.h>
int main() { 
    char buf[10]; 
    strcpy(buf, "this is way too long and will overflow"); 
    return 0; 
}''')
    
    # Run analysis
    analyzer = CppcheckAnalyzer()
    print('Testing Cppcheck in worker...')
    print(f'Cppcheck available: {analyzer.is_available()}')
    
    if analyzer.is_available():
        print('Running analysis...')
        vulns, patches = analyzer.analyze(tmpdir, 'test_repo')
        print(f'\n✅ Found {len(vulns)} vulnerabilities')
        
        if vulns:
            print('\nFirst vulnerability:')
            print(f'  Description: {vulns[0].get("description", "N/A")}')
            print(f'  CWE: {vulns[0].get("cwe", "N/A")}')
            print(f'  Tool: {vulns[0].get("tool", "N/A")}')
            print(f'  Severity: {vulns[0].get("severity", "N/A")}')
        else:
            print('⚠️  No vulnerabilities found (unexpected)')
    else:
        print('❌ Cppcheck not available')
