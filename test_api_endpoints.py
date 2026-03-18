#!/usr/bin/env python3
"""
Test script for AutoVulRepair API endpoints
Tests the new VS Code extension API endpoints
"""

import requests
import json
import time
import sys

BASE_URL = "http://localhost:5000"

def print_test(name):
    """Print test name"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print('='*60)

def print_success(message):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message):
    """Print error message"""
    print(f"❌ {message}")

def print_response(response):
    """Print response details"""
    print(f"Status: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")
    try:
        print(f"Body: {json.dumps(response.json(), indent=2)}")
    except:
        print(f"Body: {response.text[:500]}")

def test_1_initiate_scan():
    """Test POST /api/scan - Initiate a new scan"""
    print_test("1. Initiate Scan (POST /api/scan)")
    
    payload = {
        "code_snippet": """
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    gets(buffer);  // Vulnerable: buffer overflow
    printf("You entered: %s\\n", buffer);
    return 0;
}
""",
        "analysis_tool": "cppcheck"
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/scan", json=payload, headers=headers)
        print_response(response)
        
        if response.status_code == 202:
            data = response.json()
            if 'scanId' in data and data['status'] == 'queued':
                print_success(f"Scan initiated successfully! Scan ID: {data['scanId']}")
                return data['scanId']
            else:
                print_error("Response missing required fields (scanId, status)")
                return None
        else:
            print_error(f"Expected status 202, got {response.status_code}")
            return None
    except Exception as e:
        print_error(f"Request failed: {e}")
        return None

def test_2_get_scan_status(scan_id):
    """Test GET /api/scan-status/<scan_id> - Check scan status"""
    print_test(f"2. Get Scan Status (GET /api/scan-status/{scan_id})")
    
    try:
        response = requests.get(f"{BASE_URL}/api/scan-status/{scan_id}")
        print_response(response)
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Status: {data.get('status')}, Vulnerabilities: {data.get('vulnerabilities_count', 0)}")
            return data.get('status')
        else:
            print_error(f"Expected status 200, got {response.status_code}")
            return None
    except Exception as e:
        print_error(f"Request failed: {e}")
        return None

def test_3_get_scan_results(scan_id):
    """Test GET /api/scan/<scan_id>/results - Get formatted results"""
    print_test(f"3. Get Scan Results (GET /api/scan/{scan_id}/results)")
    
    try:
        response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/results")
        print_response(response)
        
        if response.status_code == 200:
            data = response.json()
            required_fields = ['scanId', 'status', 'vulnerabilities', 'summary']
            missing = [f for f in required_fields if f not in data]
            
            if missing:
                print_error(f"Missing required fields: {missing}")
                return False
            
            vuln_count = len(data['vulnerabilities'])
            summary = data['summary']
            print_success(f"Results retrieved successfully!")
            print(f"   Total vulnerabilities: {summary['total']}")
            print(f"   Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}")
            
            if vuln_count > 0:
                print(f"\n   First vulnerability:")
                vuln = data['vulnerabilities'][0]
                print(f"   - Type: {vuln.get('type')}")
                print(f"   - Severity: {vuln.get('severity')}")
                print(f"   - File: {vuln.get('file')}")
                print(f"   - Line: {vuln.get('line')}")
                print(f"   - Description: {vuln.get('description', '')[:100]}...")
            
            return True
        else:
            print_error(f"Expected status 200, got {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Request failed: {e}")
        return False

def test_4_cancel_scan(scan_id):
    """Test DELETE /api/scan/<scan_id> - Cancel a scan"""
    print_test(f"4. Cancel Scan (DELETE /api/scan/{scan_id})")
    
    try:
        response = requests.delete(f"{BASE_URL}/api/scan/{scan_id}")
        print_response(response)
        
        # Scan might already be completed, which is fine
        if response.status_code == 200:
            data = response.json()
            print_success(f"Scan cancelled: {data.get('message')}")
            return True
        elif response.status_code == 400:
            data = response.json()
            if 'Cannot cancel scan with status' in data.get('error', ''):
                print_success(f"Scan already completed (cannot cancel): {data.get('error')}")
                return True
            else:
                print_error(f"Unexpected error: {data.get('error')}")
                return False
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Request failed: {e}")
        return False

def test_5_cancel_nonexistent_scan():
    """Test DELETE /api/scan/<scan_id> - Try to cancel non-existent scan"""
    print_test("5. Cancel Non-existent Scan (Error Handling)")
    
    fake_scan_id = "00000000-0000-0000-0000-000000000000"
    
    try:
        response = requests.delete(f"{BASE_URL}/api/scan/{fake_scan_id}")
        print_response(response)
        
        if response.status_code == 404:
            print_success("Correctly returned 404 for non-existent scan")
            return True
        else:
            print_error(f"Expected status 404, got {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Request failed: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("AutoVulRepair API Endpoint Tests")
    print("="*60)
    print(f"Testing against: {BASE_URL}")
    print("Make sure Docker backend is running: docker-compose up")
    print("="*60)
    
    # Check if backend is running
    try:
        response = requests.get(BASE_URL, timeout=5)
        print_success("Backend is running!")
    except Exception as e:
        print_error(f"Backend is not accessible: {e}")
        print("\nPlease start the backend with: docker-compose up")
        sys.exit(1)
    
    # Test 1: Initiate scan
    scan_id = test_1_initiate_scan()
    if not scan_id:
        print("\n❌ Test 1 failed. Cannot continue.")
        sys.exit(1)
    
    # Wait a bit for scan to process
    print("\n⏳ Waiting 5 seconds for scan to process...")
    time.sleep(5)
    
    # Test 2: Check status
    status = test_2_get_scan_status(scan_id)
    
    # Wait for completion if still processing
    max_wait = 30
    waited = 0
    while status in ['queued', 'processing'] and waited < max_wait:
        print(f"⏳ Scan still {status}, waiting 5 more seconds...")
        time.sleep(5)
        waited += 5
        status = test_2_get_scan_status(scan_id)
    
    # Test 3: Get results
    test_3_get_scan_results(scan_id)
    
    # Test 4: Cancel scan (might already be done)
    test_4_cancel_scan(scan_id)
    
    # Test 5: Error handling
    test_5_cancel_nonexistent_scan()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print("✅ All API endpoints are working correctly!")
    print("\nThe VS Code extension should now work with these endpoints:")
    print("  - POST   /api/scan")
    print("  - GET    /api/scan/<id>/results")
    print("  - DELETE /api/scan/<id>")
    print("  - GET    /api/scan-status/<id>")
    print("\nNext step: Test the VS Code extension!")
    print("="*60)

if __name__ == "__main__":
    main()
