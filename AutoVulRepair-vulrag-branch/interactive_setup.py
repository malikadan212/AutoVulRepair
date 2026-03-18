"""
Interactive CVE to Pinecone Setup Wizard

This script guides you through the entire setup process.
"""

import os
import sys
import subprocess
import time


def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def print_step(step_num, total_steps, text):
    """Print a step indicator"""
    print(f"\n[Step {step_num}/{total_steps}] {text}")
    print("-" * 70)


def check_python():
    """Check if Python is installed"""
    try:
        version = sys.version_info
        if version.major >= 3 and version.minor >= 8:
            print(f"✓ Python {version.major}.{version.minor}.{version.micro} detected")
            return True
        else:
            print(f"✗ Python {version.major}.{version.minor} is too old")
            print("  Please install Python 3.8 or higher")
            return False
    except:
        print("✗ Python not found")
        return False


def check_database():
    """Check if CVE database exists"""
    if os.path.exists('cves.db'):
        # Get database size
        size_mb = os.path.getsize('cves.db') / (1024 * 1024)
        print(f"✓ CVE database found (cves.db, {size_mb:.1f} MB)")
        return True
    else:
        print("✗ CVE database not found (cves.db)")
        print("  Please ensure cves.db is in the current directory")
        return False


def install_packages():
    """Install required packages"""
    print("\nInstalling required packages...")
    print("This may take a few minutes...\n")
    
    try:
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'pinecone_requirements.txt'
        ], check=True)
        print("\n✓ All packages installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("\n✗ Failed to install packages")
        return False


def get_api_key():
    """Get Pinecone API key from user"""
    print("\nYou need a Pinecone API key to continue.")
    print("\nIf you don't have one:")
    print("  1. Go to https://www.pinecone.io/")
    print("  2. Sign up for a FREE account")
    print("  3. Get your API key from the console")
    print("  4. Come back here and paste it\n")
    
    api_key = input("Enter your Pinecone API key (or 'skip' to exit): ").strip()
    
    if api_key.lower() == 'skip':
        return None
    
    if not api_key:
        print("✗ API key cannot be empty")
        return None
    
    return api_key


def choose_conversion_size():
    """Let user choose how many CVEs to convert"""
    print("\nHow many CVEs do you want to convert?")
    print("\n  1. Quick Test (100 CVEs) - ~1 minute")
    print("  2. Small (1,000 CVEs) - ~5 minutes")
    print("  3. Medium (10,000 CVEs) - ~30 minutes")
    print("  4. Large (100,000 CVEs) - ~2 hours [FREE TIER MAX]")
    print("  5. Full Database (316,437 CVEs) - ~4 hours [REQUIRES PAID PLAN]")
    
    while True:
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            return 100, 'cve-demo'
        elif choice == '2':
            return 1000, 'cve-small'
        elif choice == '3':
            return 10000, 'cve-medium'
        elif choice == '4':
            return 100000, 'cve-large'
        elif choice == '5':
            return None, 'cve-full'
        else:
            print("Invalid choice. Please enter 1-5.")


def run_conversion(api_key, max_records, index_name):
    """Run the conversion script"""
    print(f"\nStarting conversion to index '{index_name}'...")
    
    cmd = [
        sys.executable,
        'cve_to_pinecone.py',
        '--api-key', api_key,
        '--index-name', index_name
    ]
    
    if max_records:
        cmd.extend(['--max-records', str(max_records)])
    
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        print("\n✗ Conversion failed")
        return False
    except KeyboardInterrupt:
        print("\n\n✗ Conversion cancelled by user")
        return False


def run_test_search(api_key, index_name):
    """Run a test search"""
    print("\nWould you like to test the search? (yes/no): ", end='')
    response = input().strip().lower()
    
    if response != 'yes':
        return
    
    print("\nEnter a search query (or press Enter for default): ", end='')
    query = input().strip()
    
    if not query:
        query = "SQL injection vulnerability"
    
    print(f"\nSearching for: '{query}'...\n")
    
    try:
        subprocess.run([
            sys.executable,
            'search_cve_vectors.py',
            '--api-key', api_key,
            '--index-name', index_name,
            '--query', query,
            '--top-k', '5'
        ], check=True)
    except subprocess.CalledProcessError:
        print("\n✗ Search failed")
    except KeyboardInterrupt:
        print("\n\n✗ Search cancelled")


def main():
    """Main interactive setup"""
    print_header("CVE to Pinecone - Interactive Setup Wizard")
    
    print("This wizard will guide you through:")
    print("  • Checking prerequisites")
    print("  • Installing required packages")
    print("  • Converting CVE database to Pinecone")
    print("  • Testing semantic search")
    
    input("\nPress Enter to continue...")
    
    # Step 1: Check Python
    print_step(1, 5, "Checking Python Installation")
    if not check_python():
        print("\n✗ Setup cannot continue without Python 3.8+")
        input("\nPress Enter to exit...")
        return
    
    # Step 2: Check database
    print_step(2, 5, "Checking CVE Database")
    if not check_database():
        print("\n✗ Setup cannot continue without cves.db")
        input("\nPress Enter to exit...")
        return
    
    # Step 3: Install packages
    print_step(3, 5, "Installing Required Packages")
    print("\nDo you want to install required packages? (yes/no): ", end='')
    response = input().strip().lower()
    
    if response == 'yes':
        if not install_packages():
            print("\n✗ Setup cannot continue without required packages")
            input("\nPress Enter to exit...")
            return
    else:
        print("\nSkipping package installation...")
        print("Make sure you have installed: pinecone-client, sentence-transformers, tqdm")
    
    # Step 4: Get API key
    print_step(4, 5, "Pinecone API Key")
    api_key = get_api_key()
    
    if not api_key:
        print("\n✗ Setup cancelled")
        input("\nPress Enter to exit...")
        return
    
    # Step 5: Convert database
    print_step(5, 5, "Converting CVE Database")
    max_records, index_name = choose_conversion_size()
    
    print("\nReady to convert!")
    print(f"  Index name: {index_name}")
    print(f"  Records: {max_records if max_records else 'ALL (316,437)'}")
    print("\nProceed with conversion? (yes/no): ", end='')
    response = input().strip().lower()
    
    if response != 'yes':
        print("\n✗ Conversion cancelled")
        input("\nPress Enter to exit...")
        return
    
    if run_conversion(api_key, max_records, index_name):
        print_header("✓ Conversion Complete!")
        
        # Test search
        run_test_search(api_key, index_name)
        
        # Final instructions
        print_header("Next Steps")
        print("You can now search your CVE database:")
        print(f"\n  python search_cve_vectors.py --api-key YOUR_KEY --index-name {index_name} --query \"YOUR_QUERY\"")
        print("\nExamples:")
        print(f"  python search_cve_vectors.py --api-key YOUR_KEY --index-name {index_name} --query \"SQL injection\"")
        print(f"  python search_cve_vectors.py --api-key YOUR_KEY --index-name {index_name} --query \"buffer overflow\" --severity HIGH")
        print("\nFor more information, see QUICKSTART.md")
    else:
        print("\n✗ Conversion failed")
    
    input("\nPress Enter to exit...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Setup cancelled by user")
        input("\nPress Enter to exit...")
