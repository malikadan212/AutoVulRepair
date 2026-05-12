#!/usr/bin/env python3
"""Check Cppcheck XML output with more obvious vulnerabilities"""
import tempfile
import os
from src.utils.docker_helper import DockerToolRunner

# Create test file with obvious vulnerabilities
with tempfile.TemporaryDirectory() as tmpdir:
    test_file = os.path.join(tmpdir, 'vuln.c')
    with open(test_file, 'w') as f:
        f.write('''#include <string.h>
#include <stdlib.h>

void buffer_overflow() {
    char small[5];
    char large[100] = "This is a very long string that will overflow";
    strcpy(small, large);  // Buffer overflow
}

void memory_leak() {
    int *ptr = malloc(100);
    // No free() - memory leak
}

void null_deref() {
    int *ptr = NULL;
    *ptr = 42;  // Null pointer dereference
}

int main() {
    buffer_overflow();
    memory_leak();
    null_deref();
    return 0;
}
''')
    
    # Run Cppcheck
    docker_runner = DockerToolRunner()
    output_file = os.path.join(tmpdir, 'results.xml')
    
    stdout, stderr, exit_code = docker_runner.run_cppcheck(tmpdir, output_file)
    
    print("=" * 80)
    print("RAW XML OUTPUT")
    print("=" * 80)
    print(stdout)
    
    print("\n" + "=" * 80)
    print("ANALYSIS")
    print("=" * 80)
    
    # Count errors
    error_count = stdout.count('<error ')
    print(f"Total <error> tags: {error_count}")
    
    # Check for CWE
    if 'cwe=' in stdout or 'cwe"' in stdout:
        print("\n✅ CWE attribute FOUND in XML!")
        for line in stdout.split('\n'):
            if 'cwe' in line.lower():
                print(f"  {line.strip()}")
    else:
        print("\n❌ NO CWE attribute in XML")
        print("   Cppcheck 2.7 does NOT include CWE IDs by default")
        print("   Manual mapping is required (which we implemented)")
