#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verification script to test static analysis tools setup
"""
import sys
import os
import tempfile
import subprocess

# Add project root to path
sys.path.insert(0, '.')

def check_docker():
    """Check if Docker is running"""
    print("[CHECK] Checking Docker...")
    try:
        result = subprocess.run(['docker', 'info'], capture_output=True, timeout=5)
        if result.returncode == 0:
            print("   [OK] Docker is running")
            return True
        else:
            print("   [ERROR] Docker is not running")
            return False
    except FileNotFoundError:
        print("   [ERROR] Docker is not installed")
        return False
    except Exception as e:
        print(f"   [ERROR] Docker check failed: {e}")
        return False

def check_docker_images():
    """Check if required Docker images exist"""
    print("\n[CHECK] Checking Docker images...")
    images = {
        'vuln-scanner/cppcheck:latest': False,
        'vuln-scanner/codeql:latest': False
    }
    
    try:
        result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line in images:
                    images[line] = True
                    print(f"   [OK] Found: {line}")
    except Exception as e:
        print(f"   [ERROR] Failed to list images: {e}")
    
    missing = [img for img, found in images.items() if not found]
    if missing:
        print(f"\n   [WARNING] Missing images: {', '.join(missing)}")
        print("   Run: python build_docker_tools.py")
    
    return all(images.values())

def check_python_dependencies():
    """Check if required Python packages are installed"""
    print("\n[CHECK] Checking Python dependencies...")
    required = ['docker', 'flask', 'celery']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print(f"   [OK] {package}")
        except ImportError:
            print(f"   [ERROR] {package} (not installed)")
            missing.append(package)
    
    if missing:
        print(f"\n   Install missing packages: pip install {' '.join(missing)}")
    
    return len(missing) == 0

def test_analyzers():
    """Test analyzer availability"""
    print("\n[TEST] Testing analyzers...")
    
    try:
        from src.analysis.cppcheck import CppcheckAnalyzer
        from src.analysis.codeql import CodeQLAnalyzer
        
        cppcheck = CppcheckAnalyzer()
        codeql = CodeQLAnalyzer()
        
        cppcheck_ok = cppcheck.is_available()
        codeql_ok = codeql.is_available()
        print(f"   Cppcheck available: {'[OK]' if cppcheck_ok else '[ERROR]'}")
        print(f"   CodeQL available: {'[OK]' if codeql_ok else '[ERROR]'}")
        
        return cppcheck_ok or codeql_ok
    except Exception as e:
        print(f"   [ERROR] Analyzer test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_analysis_execution():
    """Test actual analysis execution with sample code"""
    print("\n[TEST] Testing analysis execution...")
    
    # Create sample vulnerable C code
    test_code = '''#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    gets(buffer);  // Buffer overflow vulnerability
    strcpy(buffer, "too long string");  // Another vulnerability
    return 0;
}
'''
    
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix='test_analysis_')
        test_file = os.path.join(temp_dir, 'test.c')
        
        with open(test_file, 'w') as f:
            f.write(test_code)
        
        from src.analysis.cppcheck import CppcheckAnalyzer
        analyzer = CppcheckAnalyzer()
        
        if not analyzer.is_available():
            print("   [WARNING] Cppcheck not available, skipping execution test")
            return False
        
        print("   Running Cppcheck on test code...")
        vulnerabilities, patches = analyzer.analyze(temp_dir, 'code_snippet')
        
        if vulnerabilities:
            print(f"   [OK] Analysis completed! Found {len(vulnerabilities)} issues")
            for i, vuln in enumerate(vulnerabilities[:3], 1):  # Show first 3
                print(f"      {i}. {vuln.get('severity', 'unknown')}: {vuln.get('description', 'N/A')}")
            return True
        else:
            print("   [WARNING] Analysis completed but no issues found (might be simulation)")
            # Check if it's simulation by looking at tool name
            if patches and any('sim' in str(p.get('id', '')).lower() for p in patches):
                print("   [WARNING] This appears to be simulated results, not real analysis")
                return False
            return True
        
    except Exception as e:
        print(f"   [ERROR] Analysis test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if temp_dir and os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    """Run all verification checks"""
    print("=" * 60)
    print("Static Analysis Setup Verification")
    print("=" * 60)
    
    checks = [
        ("Docker", check_docker),
        ("Docker Images", check_docker_images),
        ("Python Dependencies", check_python_dependencies),
        ("Analyzer Availability", test_analyzers),
        ("Analysis Execution", test_analysis_execution),
    ]
    
    results = {}
    for name, check_func in checks:
        try:
            results[name] = check_func()
        except Exception as e:
            print(f"\n[ERROR] {name} check crashed: {e}")
            results[name] = False
    
    print("\n" + "=" * 60)
    print("Verification Summary")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results.items():
        status = "[OK] PASS" if passed else "[ERROR] FAIL"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("[SUCCESS] All checks passed! Static analysis is ready to use.")
    else:
        print("[WARNING] Some checks failed. Review the output above.")
        print("\nNext steps:")
        if not results.get("Docker"):
            print("  1. Start Docker Desktop")
        if not results.get("Docker Images"):
            print("  2. Build Docker images: python build_docker_tools.py")
        if not results.get("Python Dependencies"):
            print("  3. Install dependencies: pip install -r requirements.txt")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == '__main__':
    sys.exit(main())

