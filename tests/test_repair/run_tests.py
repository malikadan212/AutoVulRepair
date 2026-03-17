"""
Test Runner for Repair Module
Run all repair module tests with proper configuration
"""
import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))


def main():
    """Run all repair module tests"""
    print("=" * 70)
    print("REPAIR MODULE TEST SUITE")
    print("=" * 70)
    
    # Check for API keys
    has_groq = bool(os.getenv('GROQ_API_KEY'))
    has_gemini = bool(os.getenv('GEMINI_API_KEY'))
    
    print(f"\nAPI Keys:")
    print(f"  GROQ_API_KEY: {'✓ Set' if has_groq else '✗ Not set'}")
    print(f"  GEMINI_API_KEY: {'✓ Set' if has_gemini else '✗ Not set'}")
    
    if not has_groq and not has_gemini:
        print("\n⚠️  WARNING: No API keys set. Some tests will be skipped.")
        print("   Set GROQ_API_KEY or GEMINI_API_KEY to run all tests.")
    
    print("\n" + "=" * 70)
    print("Running Tests...")
    print("=" * 70 + "\n")
    
    # Run tests
    test_dir = os.path.dirname(__file__)
    
    args = [
        test_dir,
        '-v',  # Verbose
        '-s',  # Show print statements
        '--tb=short',  # Short traceback format
        '--color=yes',  # Colored output
    ]
    
    # Add markers if needed
    if len(sys.argv) > 1:
        args.extend(sys.argv[1:])
    
    exit_code = pytest.main(args)
    
    print("\n" + "=" * 70)
    if exit_code == 0:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 70)
    
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
