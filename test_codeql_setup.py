#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Quick test to verify CodeQL setup is working
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.analysis.codeql import CodeQLAnalyzer

def test_codeql_setup():
    print("=" * 60)
    print("Testing CodeQL Setup")
    print("=" * 60)
    
    analyzer = CodeQLAnalyzer()
    
    # Test 1: Is CodeQL available?
    print("\n[TEST 1] Checking if CodeQL is available...")
    is_available = analyzer.is_available()
    if is_available:
        print("  [OK] CodeQL is available")
    else:
        print("  [ERROR] CodeQL is NOT available")
        return False
    
    # Test 2: Check Docker
    print("\n[TEST 2] Checking Docker setup...")
    if analyzer.docker_runner and analyzer.docker_runner.is_docker_available():
        print("  [OK] Docker is available")
        
        # Check for CodeQL image
        has_image = (analyzer.docker_runner.image_exists('vuln-scanner/codeql:latest') or 
                    analyzer.docker_runner.image_exists('mcr.microsoft.com/cstsectools/codeql-container:latest'))
        if has_image:
            print("  [OK] CodeQL Docker image found")
        else:
            print("  [ERROR] CodeQL Docker image not found")
            return False
    else:
        print("  [WARNING] Docker not available, will use direct execution")
    
    # Test 3: Test language detection
    print("\n[TEST 3] Testing language detection...")
    test_dir = os.path.dirname(__file__)
    languages = analyzer.detect_languages(test_dir)
    print(f"  Detected languages in project: {languages}")
    
    print("\n" + "=" * 60)
    print("[SUCCESS] All basic checks passed!")
    print("=" * 60)
    print("\nNext step: Run a real scan from the web UI:")
    print("  1. Go to http://127.0.0.1:5000/scan-public")
    print("  2. Enter: https://github.com/malikadan212/Test-Repo")
    print("  3. Select: CodeQL")
    print("  4. Click Start Scan")
    print("\nExpected result: CodeQL should detect C++, build with Make, and find vulnerabilities")
    return True

if __name__ == '__main__':
    success = test_codeql_setup()
    sys.exit(0 if success else 1)

