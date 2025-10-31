#!/usr/bin/env python3
"""
Quick test to verify all functionality is working
"""
import sys
sys.path.insert(0, '.')
from app import app
import json

def test_api():
    app.config['TESTING'] = True
    client = app.test_client()

    print('🧪 Testing Flask API endpoints...')

    # Test 1: Tool status endpoint
    print('\n1. Testing /api/tool-status')
    response = client.get('/api/tool-status')
    print(f'   Status: {response.status_code}')
    data = json.loads(response.data)
    print(f'   CodeQL available: {data["codeql"]["available"]}')
    print(f'   Cppcheck available: {data["cppcheck"]["available"]}')

    # Test 2: Code snippet submission
    print('\n2. Testing /scan-public with code snippet')
    vulnerable_code = '''#include <stdio.h>
int main() {
    char buffer[10];
    gets(buffer);  // Vulnerable function
    return 0;
}'''

    response = client.post('/scan-public', data={
        'code_snippet': vulnerable_code,
        'analysis_tool': 'cppcheck'
    })
    print(f'   Status: {response.status_code}')
    if response.status_code == 202:
        data = json.loads(response.data)
        scan_id = data['scan_id']
        print(f'   Scan ID: {scan_id}')
        print(f'   Status: {data["status"]}')
        
        # Test 3: Check scan status
        print('\n3. Testing /api/scan-status/{scan_id}')
        status_response = client.get(f'/api/scan-status/{scan_id}')
        print(f'   Status: {status_response.status_code}')
        if status_response.status_code == 200:
            status_data = json.loads(status_response.data)
            print(f'   Scan status: {status_data["status"]}')
            print(f'   Analysis tool: {status_data["analysis_tool"]}')
    else:
        print(f'   Error: {response.data.decode()}')

    # Test 4: Input validation
    print('\n4. Testing input validation')
    
    # Invalid GitHub URL
    response = client.post('/scan-public', data={
        'repo_url': 'invalid-url',
        'analysis_tool': 'cppcheck'
    })
    print(f'   Invalid URL status: {response.status_code} (should be 400)')
    
    # Invalid analysis tool
    response = client.post('/scan-public', data={
        'analysis_tool': 'invalid_tool',
        'code_snippet': 'test code'
    })
    print(f'   Invalid tool status: {response.status_code} (should be 400)')
    
    # Multiple sources (should fail)
    response = client.post('/scan-public', data={
        'repo_url': 'https://github.com/user/repo',
        'code_snippet': 'test code',
        'analysis_tool': 'cppcheck'
    })
    print(f'   Multiple sources status: {response.status_code} (should be 400)')

    # Valid GitHub URL
    response = client.post('/scan-public', data={
        'repo_url': 'https://github.com/user/repo',
        'analysis_tool': 'codeql'
    })
    print(f'   Valid GitHub URL status: {response.status_code} (should be 202)')

    print('\n🎉 API testing completed!')
    return True

if __name__ == '__main__':
    test_api()