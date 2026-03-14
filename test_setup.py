"""
Test Setup - Verify everything is working

This script checks:
1. Python version
2. Required packages
3. CVE database
4. Pinecone connection (if API key provided)
"""

import sys
import os


def check_python_version():
    """Check Python version"""
    print("Checking Python version...")
    version = sys.version_info
    
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor} is too old")
        print(f"    Please install Python 3.8 or higher")
        return False


def check_packages():
    """Check if required packages are installed"""
    print("\nChecking required packages...")
    
    packages = {
        'pinecone': 'pinecone-client',
        'sentence_transformers': 'sentence-transformers',
        'tqdm': 'tqdm',
        'torch': 'torch'
    }
    
    all_installed = True
    
    for module, package in packages.items():
        try:
            __import__(module)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} not installed")
            all_installed = False
    
    if not all_installed:
        print("\n  To install missing packages:")
        print("  pip install -r pinecone_requirements.txt")
    
    return all_installed


def check_database():
    """Check if CVE database exists"""
    print("\nChecking CVE database...")
    
    if not os.path.exists('cves.db'):
        print("  ✗ cves.db not found")
        print("    Please ensure cves.db is in the current directory")
        return False
    
    # Try to open and check
    try:
        import sqlite3
        conn = sqlite3.connect('cves.db')
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [t[0] for t in cursor.fetchall()]
        
        if 'cves' not in tables:
            print("  ✗ 'cves' table not found in database")
            conn.close()
            return False
        
        # Get count
        cursor.execute("SELECT COUNT(*) FROM cves")
        count = cursor.fetchone()[0]
        
        # Get size
        size_mb = os.path.getsize('cves.db') / (1024 * 1024)
        
        print(f"  ✓ cves.db found")
        print(f"    Records: {count:,}")
        print(f"    Size: {size_mb:.1f} MB")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"  ✗ Error reading database: {e}")
        return False


def check_pinecone(api_key):
    """Check Pinecone connection"""
    print("\nChecking Pinecone connection...")
    
    if not api_key:
        print("  ⊘ Skipped (no API key provided)")
        return None
    
    try:
        from pinecone import Pinecone
        
        pc = Pinecone(api_key=api_key)
        indexes = list(pc.list_indexes())
        
        print(f"  ✓ Connected to Pinecone")
        print(f"    Indexes: {len(indexes)}")
        
        if indexes:
            print("    Available indexes:")
            for idx in indexes:
                print(f"      - {idx.name} ({idx.dimension}D, {idx.metric})")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        print("    Check your API key")
        return False


def check_model():
    """Check if embedding model can be loaded"""
    print("\nChecking embedding model...")
    
    try:
        from sentence_transformers import SentenceTransformer
        
        print("  Loading model (this may take a moment)...")
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Test encoding
        test_text = "This is a test"
        embedding = model.encode([test_text])
        
        print(f"  ✓ Model loaded successfully")
        print(f"    Dimension: {len(embedding[0])}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Model loading failed: {e}")
        return False


def main():
    """Run all checks"""
    print("="*60)
    print("CVE to Pinecone - Setup Test")
    print("="*60)
    
    # Get API key if provided
    api_key = None
    if len(sys.argv) > 1:
        api_key = sys.argv[1]
    
    # Run checks
    results = {
        'Python': check_python_version(),
        'Packages': check_packages(),
        'Database': check_database(),
        'Model': check_model(),
        'Pinecone': check_pinecone(api_key)
    }
    
    # Summary
    print("\n" + "="*60)
    print("Summary")
    print("="*60)
    
    for check, result in results.items():
        if result is True:
            status = "✓ PASS"
        elif result is False:
            status = "✗ FAIL"
        else:
            status = "⊘ SKIP"
        
        print(f"  {status} - {check}")
    
    # Overall status
    print("\n" + "="*60)
    
    failed = [k for k, v in results.items() if v is False]
    
    if not failed:
        print("✓ All checks passed!")
        print("\nYou're ready to convert your CVE database!")
        print("\nNext steps:")
        print("  1. Double-click RUN_ME.bat")
        print("  2. Or run: python interactive_setup.py")
    else:
        print("✗ Some checks failed:")
        for check in failed:
            print(f"  - {check}")
        print("\nPlease fix the issues above before proceeding.")
    
    print("="*60)


if __name__ == '__main__':
    main()
