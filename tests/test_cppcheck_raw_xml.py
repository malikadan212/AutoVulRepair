#!/usr/bin/env python3
"""Check if Cppcheck actually outputs CWE IDs in XML"""
import tempfile
import os
from src.utils.docker_helper import DockerToolRunner

# Create test file
with tempfile.TemporaryDirectory() as tmpdir:
    test_file = os.path.join(tmpdir, 'test.c')
    with open(test_file, 'w') as f:
        f.write('''#include <string.h>
int main() { 
    char buf[10]; 
    strcpy(buf, "overflow"); 
    return 0; 
}''')
    
    # Run Cppcheck and get raw XML
    docker_runner = DockerToolRunner()
    output_file = os.path.join(tmpdir, 'results.xml')
    
    stdout, stderr, exit_code = docker_runner.run_cppcheck(tmpdir, output_file)
    
    print("=" * 80)
    print("RAW CPPCHECK XML OUTPUT")
    print("=" * 80)
    print(stdout)
    print("\n" + "=" * 80)
    
    # Check for CWE attribute
    if 'cwe=' in stdout.lower():
        print("✅ CWE IDs ARE in the XML output!")
        # Extract CWE lines
        for line in stdout.split('\n'):
            if 'cwe=' in line.lower():
                print(f"  {line.strip()}")
    else:
        print("❌ NO CWE IDs in the XML output")
        print("   This version of Cppcheck doesn't include CWE by default")
