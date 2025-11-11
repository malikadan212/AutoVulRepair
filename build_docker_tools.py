#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build Docker images for analysis tools
"""
import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and show progress"""
    print(f"\n[BUILD] {description}...")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"[OK] {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} failed")
        print(f"Error: {e.stderr}")
        return False
    except Exception as e:
        print(f"[ERROR] {description} failed: {e}")
        return False

def check_docker():
    """Check if Docker is available"""
    print("[CHECK] Checking Docker availability...")
    try:
        result = subprocess.run(['docker', 'info'], capture_output=True, timeout=10)
        if result.returncode == 0:
            print("[OK] Docker is running")
            return True
        else:
            print("[ERROR] Docker is not running")
            print("Please start Docker Desktop and try again")
            return False
    except FileNotFoundError:
        print("[ERROR] Docker not found")
        print("Please install Docker Desktop: https://www.docker.com/products/docker-desktop")
        return False
    except Exception as e:
        print(f"[ERROR] Docker check failed: {e}")
        return False

def remove_image(image_name, description):
    """Try to remove existing image (ignore errors)"""
    try:
        subprocess.run(['docker', 'rmi', '-f', image_name], 
                      capture_output=True, timeout=10)
        print(f"[CLEAN] Removed existing {description}")
    except:
        pass  # Image might not exist, that's fine

def build_images():
    """Build all Docker images"""
    print("[BUILD] Building Docker Images for Vulnerability Scanner")
    print("=" * 55)
    
    if not check_docker():
        return False
    
    # Ensure directories exist
    os.makedirs('dockerfiles/cppcheck', exist_ok=True)
    os.makedirs('dockerfiles/codeql', exist_ok=True)
    
    # Remove existing images to avoid conflicts
    print("\n[CLEAN] Removing existing images if present...")
    # remove_image('vuln-scanner/cppcheck:latest', 'Cppcheck image')  # Commented out - setting up CodeQL
    remove_image('vuln-scanner/codeql:latest', 'CodeQL image')
    
    success = True
    
    # Build Cppcheck image
    # COMMENTED OUT: Setting up CodeQL first
    # if not run_command([
    #     'docker', 'build', 
    #     '-t', 'vuln-scanner/cppcheck:latest',
    #     '-f', 'dockerfiles/cppcheck/Dockerfile',
    #     'dockerfiles/cppcheck'
    # ], "Building Cppcheck Docker image"):
    #     success = False
    
    # Pull Microsoft CodeQL container (pre-built, faster)
    if not run_command([
        'docker', 'pull',
        'mcr.microsoft.com/cstsectools/codeql-container:latest'
    ], "Pulling Microsoft CodeQL container (pre-built)"):
        success = False
    else:
        # Tag it for convenience
        run_command([
            'docker', 'tag',
            'mcr.microsoft.com/cstsectools/codeql-container:latest',
            'vuln-scanner/codeql:latest'
        ], "Tagging Microsoft CodeQL container")
    
    if success:
        print("\n[SUCCESS] All Docker images built successfully!")
        print("\nNext steps:")
        print("1. Test the setup: python verify_static_analysis.py")
        print("2. Run a real vulnerability scan!")
        
        # Show image sizes
        print("\n[DOCKER] Docker Images:")
        try:
            result = subprocess.run([
                'docker', 'images', 
                '--filter', 'reference=vuln-scanner/*',
                '--format', 'table {{.Repository}}:{{.Tag}}\\t{{.Size}}'
            ], capture_output=True, text=True)
            print(result.stdout)
        except:
            pass
            
    else:
        print("\n[ERROR] Some images failed to build")
        print("Check the error messages above and try again")
    
    return success

if __name__ == '__main__':
    success = build_images()
    sys.exit(0 if success else 1)