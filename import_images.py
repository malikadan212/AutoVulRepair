#!/usr/bin/env python3
"""Import Docker images from .tar files"""
import subprocess
import sys
import os

print("Looking for .tar image files...\n")

tar_files = [f for f in os.listdir('.') if f.endswith('.tar')]
if not tar_files:
    print("No .tar files found in current directory.")
    print("Put the exported image files here and run this script again.")
    sys.exit(1)

for tar_file in tar_files:
    print(f"Loading {tar_file}...")
    try:
        result = subprocess.run(['docker', 'load', '-i', tar_file], 
                              capture_output=True, text=True, check=True)
        print(f"[OK] Loaded {tar_file}\n")
        if result.stdout:
            print(result.stdout)
    except Exception as e:
        print(f"[ERROR] Failed to load {tar_file}: {e}\n")

print("Done! Verify with: docker images | grep vuln-scanner")

