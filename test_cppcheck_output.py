#!/usr/bin/env python3
"""Test to see actual Cppcheck XML output"""
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
    strcpy(buf, "this is way too long and will overflow"); 
    return 0; 
}''')
    
    # Run Cppcheck via Docker
    docker_runner = DockerToolRunner()
    output_file = os.path.join(tmpdir, 'results.xml')
    
    cmd = [
        'cppcheck',
        '--enable=all',
        '--xml',
        '--xml-version=2',
        f'--output-file=/tmp/results.xml',
        '/tmp/source'
    ]
    
    result = docker_runner.run_tool(
        image='vuln-scanner/cppcheck:latest',
        command=cmd,
        source_dir=tmpdir,
        output_file=output_file
    )
    
    print('Cppcheck exit code:', result['exit_code'])
    print('\n=== XML Output ===')
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            print(f.read())
    else:
        print('No output file created')
