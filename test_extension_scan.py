#!/usr/bin/env python3
"""Test the exact same scan that the VS Code extension would perform"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"

# The exact code from test.c
code_snippet = """#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    gets(buffer);  // Vulnerable: buffer overflow
    strcpy(buffer, "This is too long for the buffer");  // Another vulnerability
    printf("Buffer: %s\\n", buffer);
    return 0;
}
"""

print("=" * 80)
print("Testing VS Code Extension Scan Flow")
print("=" * 80)

# Step 1: Initiate scan
print("\n1. Initiating scan...")
scan_request = {
    "code_snippet": code_snippet,
    "analysis_tool": "cppcheck"
}

response = requests.post(f"{BASE_URL}/api/scan", json=scan_request)
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

if response.status_code != 202:
    print("ERROR: Scan initiation failed!")
    exit(1)

scan_id = response.json().get('scanId')
print(f"\nScan ID: {scan_id}")

# Step 2: Poll for results
print("\n2. Polling for results...")
max_attempts = 60  # 2 minutes
attempt = 0

while attempt < max_attempts:
    attempt += 1
    print(f"\nAttempt {attempt}/{max_attempts}...")
    
    response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/results")
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"Scan Status: {data.get('status')}")
        print(f"Progress: {data.get('progress')}%")
        print(f"Stage: {data.get('stage')}")
        
        if data.get('status') == 'completed':
            print("\n" + "=" * 80)
            print("SCAN COMPLETED!")
            print("=" * 80)
            print(f"\nVulnerabilities found: {len(data.get('vulnerabilities', []))}")
            
            if data.get('vulnerabilities'):
                print("\nVulnerability Details:")
                for i, vuln in enumerate(data['vulnerabilities'], 1):
                    print(f"\n{i}. {vuln.get('type')} - {vuln.get('severity')}")
                    print(f"   File: {vuln.get('file')}")
                    print(f"   Line: {vuln.get('line')}")
                    print(f"   Description: {vuln.get('description')}")
            else:
                print("\nWARNING: No vulnerabilities found!")
                print("This is unexpected - test.c has clear vulnerabilities!")
            
            print(f"\nFull response:")
            print(json.dumps(data, indent=2))
            break
        
        elif data.get('status') in ['failed', 'cancelled']:
            print(f"\nERROR: Scan {data.get('status')}!")
            break
    
    elif response.status_code == 404:
        print("Scan not found yet, waiting...")
    else:
        print(f"Unexpected status code: {response.status_code}")
        print(f"Response: {response.text}")
    
    time.sleep(2)
else:
    print("\nERROR: Timeout waiting for scan to complete!")
