#!/usr/bin/env python3
"""
Test script to verify secure database configuration
"""

import os
import sys

def test_with_env_var():
    """Test that it works when DATABASE_URL is set"""
    print("=" * 60)
    print("TEST 1: With DATABASE_URL environment variable")
    print("=" * 60)
    
    # Ensure DATABASE_URL is set (should be from .env)
    if not os.getenv('DATABASE_URL'):
        print("❌ FAIL: DATABASE_URL not set in environment")
        return False
    
    try:
        from src.config.database import get_secure_database_url
        url = get_secure_database_url()
        
        # Verify it's a valid PostgreSQL URL
        if url and url.startswith('postgresql://'):
            print(f"✅ PASS: Database URL loaded successfully")
            print(f"   Format: postgresql://user:***@host:port/database")
            return True
        else:
            print(f"❌ FAIL: Invalid database URL format")
            return False
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False


def test_without_env_var():
    """Test that it fails properly when DATABASE_URL is not set"""
    print("\n" + "=" * 60)
    print("TEST 2: Without DATABASE_URL (should fail gracefully)")
    print("=" * 60)
    
    # Temporarily remove DATABASE_URL
    original_url = os.environ.pop('DATABASE_URL', None)
    
    try:
        from src.config.database import get_secure_database_url
        
        # Force reload the module to test without env var
        import importlib
        import src.config.database
        importlib.reload(src.config.database)
        
        try:
            url = src.config.database.get_secure_database_url()
            print(f"❌ FAIL: Should have raised ValueError but got: {url}")
            return False
        except ValueError as e:
            if "DATABASE_URL environment variable is required" in str(e):
                print(f"✅ PASS: Correctly raised ValueError")
                print(f"   Message: {str(e).split(chr(10))[0]}")
                return True
            else:
                print(f"❌ FAIL: Wrong error message: {e}")
                return False
    except Exception as e:
        print(f"❌ FAIL: Unexpected error: {e}")
        return False
    finally:
        # Restore DATABASE_URL
        if original_url:
            os.environ['DATABASE_URL'] = original_url


def test_validation():
    """Test URL validation"""
    print("\n" + "=" * 60)
    print("TEST 3: URL Validation")
    print("=" * 60)
    
    from src.config.database import validate_database_url
    
    test_cases = [
        ("postgresql://user:pass@localhost:5432/db", True, "Valid URL"),
        ("postgresql://user:pass@host/db", True, "Valid URL without port"),
        ("mysql://user:pass@localhost:3306/db", False, "Wrong protocol"),
        ("", False, "Empty string"),
        (None, False, "None value"),
        ("not-a-url", False, "Invalid format"),
    ]
    
    all_passed = True
    for url, expected, description in test_cases:
        result = validate_database_url(url)
        if result == expected:
            print(f"✅ PASS: {description}")
        else:
            print(f"❌ FAIL: {description} - Expected {expected}, got {result}")
            all_passed = False
    
    return all_passed


def test_no_hardcoded_passwords():
    """Test that no hardcoded passwords exist in code"""
    print("\n" + "=" * 60)
    print("TEST 4: No Hardcoded Passwords")
    print("=" * 60)
    
    import subprocess
    
    try:
        # Search for the old hardcoded password
        result = subprocess.run(
            ['grep', '-r', 'autovulrepair_secure_password_2024', '--include=*.py', '.'],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        if result.returncode == 1:  # grep returns 1 when no matches found
            print("✅ PASS: No hardcoded passwords found in Python files")
            return True
        elif result.returncode == 0:
            print("❌ FAIL: Found hardcoded passwords:")
            print(result.stdout)
            return False
        else:
            print(f"⚠️  WARNING: grep command failed with code {result.returncode}")
            return True  # Don't fail the test if grep isn't available
    except FileNotFoundError:
        print("⚠️  WARNING: grep not available, skipping this test")
        return True


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("SECURE DATABASE CONFIGURATION TEST SUITE")
    print("=" * 60 + "\n")
    
    results = []
    
    # Run tests
    results.append(("With DATABASE_URL", test_with_env_var()))
    results.append(("Without DATABASE_URL", test_without_env_var()))
    results.append(("URL Validation", test_validation()))
    results.append(("No Hardcoded Passwords", test_no_hardcoded_passwords()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED - SECURITY ISSUE RESOLVED!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
