#!/usr/bin/env python3
"""
Build Docker images for analysis tools
"""
import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and show progress"""
    print(f"\n🔨 {description}...")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed")
        print(f"Error: {e.stderr}")
        return False
    except Exception as e:
        print(f"❌ {description} failed: {e}")
        return False

def check_docker():
    """Check if Docker is available"""
    print("🐳 Checking Docker availability...")
    try:
        result = subprocess.run(['docker', 'info'], capture_output=True, timeout=10)
        if result.returncode == 0:
            print("✅ Docker is running")
            return True
        else:
            print("❌ Docker is not running")
            print("Please start Docker Desktop and try again")
            return False
    except FileNotFoundError:
        print("❌ Docker not found")
        print("Please install Docker Desktop: https://www.docker.com/products/docker-desktop")
        return False
    except Exception as e:
        print(f"❌ Docker check failed: {e}")
        return False

def build_images():
    """Build all Docker images"""
    print("🚀 Building Docker Images for Vulnerability Scanner")
    print("=" * 55)
    
    if not check_docker():
        return False
    
    # Ensure directories exist
    os.makedirs('docker/cppcheck', exist_ok=True)
    os.makedirs('docker/codeql', exist_ok=True)
    
    success = True
    
    # Build Cppcheck image
    if not run_command([
        'docker', 'build', 
        '-t', 'vuln-scanner/cppcheck:latest',
        '-f', 'docker/cppcheck/Dockerfile',
        'docker/cppcheck'
    ], "Building Cppcheck Docker image"):
        success = False
    
    # Build CodeQL image (this takes longer)
    if not run_command([
        'docker', 'build',
        '-t', 'vuln-scanner/codeql:latest', 
        '-f', 'docker/codeql/Dockerfile',
        'docker/codeql'
    ], "Building CodeQL Docker image (this may take several minutes)"):
        success = False
    
    if success:
        print("\n🎉 All Docker images built successfully!")
        print("\nNext steps:")
        print("1. Test the setup: python test_docker_tools.py")
        print("2. Update your analyzers to use Docker")
        print("3. Run a real vulnerability scan!")
        
        # Show image sizes
        print("\n📊 Docker Images:")
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
        print("\n❌ Some images failed to build")
        print("Check the error messages above and try again")
    
    return success

if __name__ == '__main__':
    success = build_images()
    sys.exit(0 if success else 1)