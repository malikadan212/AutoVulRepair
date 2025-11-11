#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick check: what do you need to do?"""
import subprocess
import sys

print("Checking your setup...\n")

# Check Docker
try:
    subprocess.run(['docker', '--version'], capture_output=True, check=True, timeout=5)
    print("[OK] Docker is installed")
    try:
        subprocess.run(['docker', 'info'], capture_output=True, check=True, timeout=5)
        print("[OK] Docker is running\n")
        
        # Check images
        result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'], 
                              capture_output=True, text=True, timeout=5)
        has_cppcheck = 'vuln-scanner/cppcheck' in result.stdout
        has_codeql = 'vuln-scanner/codeql' in result.stdout
        
        if has_cppcheck:
            print("[OK] Cppcheck Docker image exists")
        else:
            print("[MISSING] Cppcheck Docker image missing")
            print("   Run: python build_docker_tools.py")
            
        if has_codeql:
            print("[OK] CodeQL Docker image exists")
        else:
            print("[MISSING] CodeQL Docker image missing")
            print("   Run: python build_docker_tools.py")
    except:
        print("[ERROR] Docker is installed but NOT running")
        print("   Start Docker Desktop app and wait for it to fully start")
except:
    print("[NOT FOUND] Docker not found")
    print("\nYou have 2 options:")
    print("\nOption 1: Install Docker (recommended)")
    print("  1. Download: https://www.docker.com/products/docker-desktop")
    print("  2. Install and start Docker Desktop")
    print("  3. Run: python build_docker_tools.py")
    print("\nOption 2: Install tools directly (no Docker)")
    print("  - Install Cppcheck: https://github.com/danmar/cppcheck/releases")
    print("  - Install CodeQL: https://github.com/github/codeql-cli-binaries/releases")
    print("  - Add them to your PATH")

# Check direct tools
print("\nChecking for direct tool installation...")
try:
    result = subprocess.run(['cppcheck', '--version'], capture_output=True, timeout=5)
    if result.returncode == 0:
        print("[OK] Cppcheck installed directly")
except:
    print("[NOT FOUND] Cppcheck not found (will use Docker or simulation)")

try:
    result = subprocess.run(['codeql', '--version'], capture_output=True, timeout=5)
    if result.returncode == 0:
        print("[OK] CodeQL installed directly")
except:
    print("[NOT FOUND] CodeQL not found (will use Docker or simulation)")

print("\n" + "="*50)
print("Current status: The code will try Docker first, then direct")
print("tools, then fall back to simulation if nothing works.")
print("="*50)

