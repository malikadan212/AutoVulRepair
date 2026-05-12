#!/usr/bin/env python3
"""
Import VUL-RAG Data - Command-Line Tool

Imports VUL-RAG knowledge base entries from JSON files into the CVE database.
Handles validation, duplicate merging, and provides detailed import statistics.

Usage:
    python import_vulrag_data.py --file vulrag_data.json
    python import_vulrag_data.py --file vulrag_data.json --db-path custom_cves.db
    python import_vulrag_data.py --stats
    python import_vulrag_data.py --stats --db-path custom_cves.db

Requirements: 1.1, 1.2, 1.5
"""

import argparse
import sys
import os
from vulrag_importer import VulRagImporter


def print_banner():
    """Print application banner"""
    print("=" * 80)
    print("VUL-RAG Data Importer")
    print("Import enriched vulnerability knowledge into your CVE database")
    print("=" * 80)
    print()


def import_data(args):
    """
    Import VUL-RAG data from JSON file
    
    Args:
        args: Parsed command-line arguments
    """
    print(f"Database: {args.db_path}")
    print(f"Input file: {args.file}")
    print()
    
    # Check if file exists
    if not os.path.exists(args.file):
        print(f"✗ Error: File '{args.file}' not found")
        return 1
    
    # Check file size
    file_size = os.path.getsize(args.file)
    print(f"File size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
    print()
    
    try:
        # Initialize importer
        print("Initializing importer...")
        importer = VulRagImporter(db_path=args.db_path)
        print("✓ Importer initialized")
        print()
        
        # Import data
        print("Importing VUL-RAG data...")
        print("This may take a while for large files...")
        print()
        
        result = importer.import_from_json(args.file)
        
        # Display results
        print()
        print("=" * 80)
        print("Import Complete")
        print("=" * 80)
        print()
        print(f"Total entries processed: {result.total_entries:,}")
        print(f"Successfully imported:   {result.success_count:,}")
        print(f"Errors encountered:      {result.error_count:,}")
        print()
        
        if result.success_count > 0:
            success_rate = (result.success_count / result.total_entries * 100)
            print(f"Success rate: {success_rate:.1f}%")
            print()
        
        # Display errors if any
        if result.errors:
            print("Errors:")
            print("-" * 80)
            
            # Show first 20 errors
            for error in result.errors[:20]:
                print(f"  Entry {error['entry_index']} ({error['cve_id']})")
                print(f"    Error: {error['error']}")
                print()
            
            if len(result.errors) > 20:
                print(f"  ... and {len(result.errors) - 20} more errors")
                print()
            
            if args.verbose:
                # Save all errors to file
                error_file = args.file + '.errors.txt'
                with open(error_file, 'w') as f:
                    for error in result.errors:
                        f.write(f"Entry {error['entry_index']} ({error['cve_id']}): {error['error']}\n")
                print(f"All errors saved to: {error_file}")
                print()
        
        if result.success_count > 0:
            print("✓ Import completed successfully!")
            print()
            print("Next steps:")
            print("  1. Create enhanced FAISS index: python create_enhanced_index.py")
            print("  2. Search with enrichment: python search_enhanced_cve.py --query 'your query'")
        else:
            print("✗ No entries were imported successfully")
            return 1
        
        return 0
        
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        return 1
    except ValueError as e:
        print(f"✗ Error: {e}")
        print()
        print("Hint: Make sure the database schema has been migrated.")
        print("Run: python migrate_vulrag_schema.py")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def show_stats(args):
    """
    Display import statistics
    
    Args:
        args: Parsed command-line arguments
    """
    print(f"Database: {args.db_path}")
    print()
    
    try:
        # Initialize importer
        importer = VulRagImporter(db_path=args.db_path)
        
        # Get statistics
        stats = importer.get_import_stats()
        
        print("=" * 80)
        print("VUL-RAG Import Statistics")
        print("=" * 80)
        print()
        print(f"Total enrichments: {stats['total_enrichments']:,}")
        print()
        
        if stats['total_enrichments'] > 0:
            print("Field Coverage:")
            print("-" * 80)
            
            fields = [
                ('cwe_id', 'CWE ID'),
                ('vulnerability_type', 'Vulnerability Type'),
                ('root_cause', 'Root Cause'),
                ('attack_condition', 'Attack Condition'),
                ('fix_strategy', 'Fix Strategy'),
                ('code_pattern', 'Code Pattern')
            ]
            
            for field_name, field_label in fields:
                count = stats.get(f'{field_name}_populated', 0)
                percentage = (count / stats['total_enrichments'] * 100)
                bar_length = int(percentage / 2)  # Scale to 50 chars max
                bar = '█' * bar_length + '░' * (50 - bar_length)
                print(f"{field_label:20s} {bar} {count:6,} ({percentage:5.1f}%)")
            
            print()
        else:
            print("No enrichment data found in database.")
            print()
            print("To import VUL-RAG data:")
            print("  python import_vulrag_data.py --file vulrag_data.json")
        
        return 0
        
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        return 1
    except ValueError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Import VUL-RAG knowledge base data into CVE database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import VUL-RAG data from JSON file
  python import_vulrag_data.py --file vulrag_data.json
  
  # Import with custom database path
  python import_vulrag_data.py --file vulrag_data.json --db-path /path/to/cves.db
  
  # Show import statistics
  python import_vulrag_data.py --stats
  
  # Show statistics with verbose output
  python import_vulrag_data.py --stats --verbose

Requirements:
  - Database must exist with vulrag_enrichment table
  - Run migrate_vulrag_schema.py first if needed
  - JSON file must contain valid VUL-RAG entries

VUL-RAG JSON Format:
  {
    "cve_id": "CVE-2023-12345",
    "description": "Vulnerability description",
    "cwe_id": "CWE-79",
    "vulnerability_type": "Cross-Site Scripting",
    "root_cause": "Insufficient input validation",
    "attack_condition": "Attacker can inject scripts",
    "fix_strategy": "Implement input sanitization",
    "code_pattern": "Unescaped user input"
  }
        """
    )
    
    # Main arguments
    parser.add_argument(
        '--file',
        help='Path to VUL-RAG JSON file to import'
    )
    parser.add_argument(
        '--db-path',
        default='cves.db',
        help='Path to CVE database (default: cves.db)'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show import statistics instead of importing'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output with detailed error messages'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Validate arguments
    if not args.stats and not args.file:
        parser.print_help()
        return 1
    
    # Execute command
    if args.stats:
        return show_stats(args)
    else:
        return import_data(args)


if __name__ == '__main__':
    sys.exit(main())
