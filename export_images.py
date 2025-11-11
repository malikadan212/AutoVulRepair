#!/usr/bin/env python3
"""Export Docker images to share with others"""
import subprocess
import sys
import os

images = ['vuln-scanner/cppcheck:latest', 'vuln-scanner/codeql:latest']

print("Exporting Docker images...\n")

for image in images:
    # Check if image exists
    result = subprocess.run(['docker', 'images', '-q', image], capture_output=True, text=True)
    if not result.stdout.strip():
        print(f"[SKIP] {image} not found. Build it first: python build_docker_tools.py")
        continue
    
    filename = image.replace('/', '_').replace(':', '_') + '.tar'
    print(f"Exporting {image} to {filename}...")
    
    try:
        subprocess.run(['docker', 'save', image, '-o', filename], check=True)
        size = os.path.getsize(filename) / (1024*1024)  # MB
        print(f"[OK] Saved {filename} ({size:.1f} MB)\n")
    except Exception as e:
        print(f"[ERROR] Failed: {e}\n")
        sys.exit(1)

print("Done! Share the .tar files with your teammate.")

