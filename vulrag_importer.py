"""
VUL-RAG Data Importer

Imports VUL-RAG knowledge base entries into the CVE database.
Handles JSON parsing, validation, duplicate merging, and statistics tracking.

Usage:
    from vulrag_importer import VulRagImporter
    
    importer = VulRagImporter(db_path='cves.db')
    result = importer.import_from_json('vulrag_data.json')
    print(f"Imported: {result.success_count}, Errors: {result.error_count}")
"""

import json
import sqlite3
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ImportResult:
    """Result of an import operation"""
    success_count: int
    error_count: int
    errors: List[Dict[str, str]]
    total_entries: int
    
    def __str__(self):
        return (f"Import Result: {self.success_count} successful, "
                f"{self.error_count} errors out of {self.total_entries} total entries")


class VulRagImporter:
    """Imports VUL-RAG knowledge base data into the CVE database"""
    
    REQUIRED_FIELDS = ['cve_id', 'description']
    OPTIONAL_FIELDS = ['cwe_id', 'vulnerability_type', 'root_cause', 
                       'attack_condition', 'fix_strategy', 'code_pattern']
    
    def __init__(self, db_path: str = 'cves.db'):
        """
        Initialize the importer
        
        Args:
            db_path: Path to the CVE database
        """
        self.db_path = db_path
        self._validate_database()
    
    def _validate_database(self):
        """Validate that the database exists and has required tables"""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(
                f"Database file '{self.db_path}' not found. "
                "Please ensure the CVE database exists."
            )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for vulrag_enrichment table
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='vulrag_enrichment'
        """)
        
        if not cursor.fetchone():
            conn.close()
            raise ValueError(
                "The 'vulrag_enrichment' table does not exist. "
                "Please run the migration script first: python migrate_vulrag_schema.py"
            )
        
        conn.close()
    
    def validate_entry(self, entry: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate that an entry contains required fields
        
        Args:
            entry: Dictionary containing VUL-RAG data
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in entry or not entry[field]:
                return False, f"Missing required field: {field}"
            
            # Check that required fields are not empty strings
            if isinstance(entry[field], str) and not entry[field].strip():
                return False, f"Required field '{field}' cannot be empty"
        
        # Validate CVE ID format (basic check)
        cve_id = entry['cve_id']
        if not isinstance(cve_id, str):
            return False, "cve_id must be a string"
        
        # CVE ID should match pattern CVE-YYYY-NNNNN
        if not cve_id.startswith('CVE-'):
            return False, f"Invalid CVE ID format: {cve_id}"
        
        return True, None
    
    def _cve_exists(self, cursor: sqlite3.Cursor, cve_id: str) -> bool:
        """Check if a CVE exists in the cves table"""
        cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
        return cursor.fetchone() is not None
    
    def _enrichment_exists(self, cursor: sqlite3.Cursor, cve_id: str) -> bool:
        """Check if enrichment data already exists for a CVE"""
        cursor.execute(
            "SELECT cve_id FROM vulrag_enrichment WHERE cve_id = ?", 
            (cve_id,)
        )
        return cursor.fetchone() is not None
    
    def merge_with_existing(self, cursor: sqlite3.Cursor, cve_id: str, 
                           vulrag_data: Dict[str, Any]) -> None:
        """
        Merge VUL-RAG data with existing CVE data
        
        Args:
            cursor: Database cursor
            cve_id: CVE identifier
            vulrag_data: VUL-RAG enrichment data
        """
        # Check if enrichment already exists
        if self._enrichment_exists(cursor, cve_id):
            # Update existing enrichment
            cursor.execute("""
                UPDATE vulrag_enrichment
                SET cwe_id = ?,
                    vulnerability_type = ?,
                    root_cause = ?,
                    attack_condition = ?,
                    fix_strategy = ?,
                    code_pattern = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE cve_id = ?
            """, (
                vulrag_data.get('cwe_id'),
                vulrag_data.get('vulnerability_type'),
                vulrag_data.get('root_cause'),
                vulrag_data.get('attack_condition'),
                vulrag_data.get('fix_strategy'),
                vulrag_data.get('code_pattern'),
                cve_id
            ))
        else:
            # Insert new enrichment
            cursor.execute("""
                INSERT INTO vulrag_enrichment 
                (cve_id, cwe_id, vulnerability_type, root_cause, 
                 attack_condition, fix_strategy, code_pattern)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                vulrag_data.get('cwe_id'),
                vulrag_data.get('vulnerability_type'),
                vulrag_data.get('root_cause'),
                vulrag_data.get('attack_condition'),
                vulrag_data.get('fix_strategy'),
                vulrag_data.get('code_pattern')
            ))
    
    def import_from_json(self, file_path: str) -> ImportResult:
        """
        Import VUL-RAG data from a JSON file
        
        Args:
            file_path: Path to JSON file containing VUL-RAG data
        
        Returns:
            ImportResult with statistics and errors
        
        Raises:
            FileNotFoundError: If the JSON file doesn't exist
            json.JSONDecodeError: If the file is not valid JSON
        """
        # Check file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"JSON file '{file_path}' not found")
        
        # Load JSON data
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Invalid JSON format in '{file_path}': {str(e)}",
                e.doc, e.pos
            )
        
        # Ensure data is a list
        if isinstance(data, dict):
            # If it's a single entry, wrap it in a list
            entries = [data]
        elif isinstance(data, list):
            entries = data
        else:
            raise ValueError(
                f"JSON data must be a list or dictionary, got {type(data)}"
            )
        
        # Import entries
        return self._import_entries(entries)
    
    def _import_entries(self, entries: List[Dict[str, Any]]) -> ImportResult:
        """
        Import a list of VUL-RAG entries
        
        Args:
            entries: List of VUL-RAG entry dictionaries
        
        Returns:
            ImportResult with statistics
        """
        success_count = 0
        error_count = 0
        errors = []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            for i, entry in enumerate(entries):
                try:
                    # Validate entry
                    is_valid, error_msg = self.validate_entry(entry)
                    if not is_valid:
                        error_count += 1
                        errors.append({
                            'entry_index': i,
                            'cve_id': entry.get('cve_id', 'UNKNOWN'),
                            'error': error_msg
                        })
                        continue
                    
                    cve_id = entry['cve_id']
                    
                    # Check if CVE exists in main table (optional check)
                    # We allow enrichment even if CVE doesn't exist yet
                    # The foreign key constraint will handle this
                    
                    # Merge with existing data
                    self.merge_with_existing(cursor, cve_id, entry)
                    success_count += 1
                    
                except sqlite3.IntegrityError as e:
                    error_count += 1
                    errors.append({
                        'entry_index': i,
                        'cve_id': entry.get('cve_id', 'UNKNOWN'),
                        'error': f"Database integrity error: {str(e)}"
                    })
                except Exception as e:
                    error_count += 1
                    errors.append({
                        'entry_index': i,
                        'cve_id': entry.get('cve_id', 'UNKNOWN'),
                        'error': f"Unexpected error: {str(e)}"
                    })
            
            # Commit all changes
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            raise RuntimeError(f"Import failed: {str(e)}")
        finally:
            conn.close()
        
        return ImportResult(
            success_count=success_count,
            error_count=error_count,
            errors=errors,
            total_entries=len(entries)
        )
    
    def get_import_stats(self) -> Dict[str, int]:
        """
        Get statistics about imported VUL-RAG data
        
        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Count total enrichments
            cursor.execute("SELECT COUNT(*) FROM vulrag_enrichment")
            total_enrichments = cursor.fetchone()[0]
            
            # Count enrichments with each field populated
            stats = {
                'total_enrichments': total_enrichments
            }
            
            for field in self.OPTIONAL_FIELDS:
                cursor.execute(
                    f"SELECT COUNT(*) FROM vulrag_enrichment WHERE {field} IS NOT NULL AND {field} != ''"
                )
                stats[f'{field}_populated'] = cursor.fetchone()[0]
            
            return stats
            
        finally:
            conn.close()


def main():
    """Command-line interface for the importer"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Import VUL-RAG knowledge base data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import from JSON file
  python vulrag_importer.py --file vulrag_data.json
  
  # Import with custom database
  python vulrag_importer.py --file vulrag_data.json --db-path custom_cves.db
  
  # Show import statistics
  python vulrag_importer.py --stats
        """
    )
    
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
        help='Show import statistics'
    )
    
    args = parser.parse_args()
    
    try:
        importer = VulRagImporter(db_path=args.db_path)
        
        if args.stats:
            # Show statistics
            stats = importer.get_import_stats()
            print("=" * 60)
            print("VUL-RAG Import Statistics")
            print("=" * 60)
            print(f"Total enrichments: {stats['total_enrichments']}")
            print()
            for field in VulRagImporter.OPTIONAL_FIELDS:
                count = stats.get(f'{field}_populated', 0)
                percentage = (count / stats['total_enrichments'] * 100) if stats['total_enrichments'] > 0 else 0
                print(f"{field}: {count} ({percentage:.1f}%)")
        
        elif args.file:
            # Import from file
            print(f"Importing VUL-RAG data from: {args.file}")
            print(f"Database: {args.db_path}\n")
            
            result = importer.import_from_json(args.file)
            
            print("=" * 60)
            print("Import Complete")
            print("=" * 60)
            print(f"Total entries: {result.total_entries}")
            print(f"Successfully imported: {result.success_count}")
            print(f"Errors: {result.error_count}")
            
            if result.errors:
                print("\nErrors:")
                for error in result.errors[:10]:  # Show first 10 errors
                    print(f"  Entry {error['entry_index']} ({error['cve_id']}): {error['error']}")
                
                if len(result.errors) > 10:
                    print(f"  ... and {len(result.errors) - 10} more errors")
        
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    main()
