"""
Index Manager for FAISS CVE Indexes

Manages multiple FAISS indexes, provides information about available indexes,
and verifies which indexes contain VUL-RAG enrichment data.

Usage:
    from index_manager import IndexManager
    
    manager = IndexManager()
    
    # List all available indexes
    indexes = manager.list_indexes()
    for idx in indexes:
        print(f"{idx['name']}: VUL-RAG={idx['has_vulrag_enrichment']}")
    
    # Get detailed info about a specific index
    info = manager.get_index_info('cve-vulrag')
    print(f"Total vectors: {info['total_vectors']}")
    
    # Verify if an index has VUL-RAG enrichment
    has_enrichment = manager.verify_index_schema('cve-vulrag')
"""

import os
import json
import pickle
from typing import List, Dict, Any, Optional


class IndexManager:
    """Manages FAISS indexes and provides metadata about them"""
    
    def __init__(self, index_dir: str = 'faiss_indexes'):
        """
        Initialize the index manager
        
        Args:
            index_dir: Directory containing FAISS indexes (default: faiss_indexes)
        """
        self.index_dir = index_dir
        
        if not os.path.exists(self.index_dir):
            raise FileNotFoundError(
                f"Index directory '{self.index_dir}' not found. "
                "Please create indexes first."
            )
    
    def list_indexes(self) -> List[Dict[str, Any]]:
        """
        List all available FAISS indexes with metadata
        
        Returns:
            List of dictionaries containing index information:
            - name: Index name
            - total_vectors: Number of vectors in the index
            - dimension: Vector dimension
            - model: Embedding model used
            - has_vulrag_enrichment: Boolean indicating if index contains VUL-RAG data
            - enrichment_stats: Statistics about enrichment coverage (if available)
            - index_file: Path to .index file
            - metadata_file: Path to .metadata file
            - info_file: Path to .info file
        """
        indexes = []
        
        # Find all .index files
        for filename in os.listdir(self.index_dir):
            if filename.endswith('.index'):
                index_name = filename[:-6]  # Remove .index extension
                
                try:
                    info = self.get_index_info(index_name)
                    indexes.append(info)
                except Exception as e:
                    # If we can't read the info, still list the index with minimal data
                    indexes.append({
                        'name': index_name,
                        'total_vectors': None,
                        'dimension': None,
                        'model': None,
                        'has_vulrag_enrichment': False,
                        'enrichment_stats': None,
                        'index_file': os.path.join(self.index_dir, filename),
                        'metadata_file': os.path.join(self.index_dir, f'{index_name}.metadata'),
                        'info_file': os.path.join(self.index_dir, f'{index_name}.info'),
                        'error': str(e)
                    })
        
        # Sort by name
        indexes.sort(key=lambda x: x['name'])
        
        return indexes
    
    def get_index_info(self, index_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific index
        
        Args:
            index_name: Name of the index (without file extension)
        
        Returns:
            Dictionary containing index information:
            - name: Index name
            - total_vectors: Number of vectors in the index
            - dimension: Vector dimension
            - model: Embedding model used
            - has_vulrag_enrichment: Boolean indicating if index contains VUL-RAG data
            - enrichment_stats: Statistics about enrichment coverage (if available)
            - index_file: Path to .index file
            - metadata_file: Path to .metadata file
            - info_file: Path to .info file
        
        Raises:
            FileNotFoundError: If the index files don't exist
        """
        index_file = os.path.join(self.index_dir, f'{index_name}.index')
        metadata_file = os.path.join(self.index_dir, f'{index_name}.metadata')
        info_file = os.path.join(self.index_dir, f'{index_name}.info')
        
        # Check if index file exists
        if not os.path.exists(index_file):
            raise FileNotFoundError(
                f"Index file not found: {index_file}. "
                f"Available indexes: {', '.join([f[:-6] for f in os.listdir(self.index_dir) if f.endswith('.index')])}"
            )
        
        # Read info file if it exists
        info_data = {}
        if os.path.exists(info_file):
            try:
                with open(info_file, 'r') as f:
                    info_data = json.load(f)
            except Exception as e:
                # Info file exists but couldn't be read
                pass
        
        # Determine if index has VUL-RAG enrichment
        has_vulrag = self.verify_index_schema(index_name)
        
        # Build result dictionary
        result = {
            'name': index_name,
            'total_vectors': info_data.get('total_vectors'),
            'dimension': info_data.get('dimension'),
            'model': info_data.get('model'),
            'has_vulrag_enrichment': has_vulrag,
            'enrichment_stats': info_data.get('enrichment_stats'),
            'index_file': index_file,
            'metadata_file': metadata_file,
            'info_file': info_file
        }
        
        # Add any additional fields from info file
        for key, value in info_data.items():
            if key not in result:
                result[key] = value
        
        return result
    
    def verify_index_schema(self, index_name: str) -> bool:
        """
        Verify if an index contains VUL-RAG enrichment fields
        
        Checks the index metadata to determine if it includes VUL-RAG fields
        (root_cause, fix_strategy, code_pattern, attack_condition, vulnerability_type).
        
        Args:
            index_name: Name of the index to verify
        
        Returns:
            True if the index contains VUL-RAG enrichment, False otherwise
        """
        # First check the .info file for explicit markers
        info_file = os.path.join(self.index_dir, f'{index_name}.info')
        if os.path.exists(info_file):
            try:
                with open(info_file, 'r') as f:
                    info_data = json.load(f)
                
                # Check for explicit enrichment markers
                if info_data.get('vulrag_enrichment') is True:
                    return True
                if info_data.get('enhanced') is True:
                    return True
            except Exception:
                pass
        
        # Check metadata file for VUL-RAG fields
        metadata_file = os.path.join(self.index_dir, f'{index_name}.metadata')
        if not os.path.exists(metadata_file):
            return False
        
        try:
            with open(metadata_file, 'rb') as f:
                metadata = pickle.load(f)
            
            # Check if metadata is a list and has entries
            if not isinstance(metadata, list) or len(metadata) == 0:
                return False
            
            # Check first few entries for VUL-RAG fields
            vulrag_fields = ['root_cause', 'fix_strategy', 'code_pattern', 
                           'attack_condition', 'vulnerability_type']
            
            # Sample up to 10 entries to check for VUL-RAG fields
            sample_size = min(10, len(metadata))
            for i in range(sample_size):
                entry = metadata[i]
                if not isinstance(entry, dict):
                    continue
                
                # Check if any VUL-RAG field exists in the entry
                for field in vulrag_fields:
                    if field in entry:
                        # Field exists - check if it's not just None for all entries
                        # If we find at least one non-None value, it's enriched
                        if entry[field] is not None:
                            return True
            
            # Check if the fields exist but are all None (still considered enriched schema)
            first_entry = metadata[0]
            if isinstance(first_entry, dict):
                for field in vulrag_fields:
                    if field in first_entry:
                        # Schema includes VUL-RAG fields even if values are None
                        return True
            
            return False
            
        except Exception:
            return False
    
    def get_enrichment_coverage(self, index_name: str) -> Optional[Dict[str, Any]]:
        """
        Get enrichment coverage statistics for an index
        
        Args:
            index_name: Name of the index
        
        Returns:
            Dictionary with enrichment statistics or None if not available:
            - total_cves: Total number of CVEs in the index
            - enriched_cves: Number of CVEs with VUL-RAG enrichment
            - enrichment_percentage: Percentage of CVEs with enrichment
        """
        info = self.get_index_info(index_name)
        return info.get('enrichment_stats')
    
    def print_index_summary(self):
        """Print a formatted summary of all available indexes"""
        indexes = self.list_indexes()
        
        if not indexes:
            print("No indexes found in directory:", self.index_dir)
            return
        
        print("=" * 80)
        print("FAISS Index Summary")
        print("=" * 80)
        print(f"Index Directory: {self.index_dir}")
        print(f"Total Indexes: {len(indexes)}\n")
        
        for idx in indexes:
            print(f"Index: {idx['name']}")
            print(f"  Location: {idx['index_file']}")
            
            if idx.get('error'):
                print(f"  Error: {idx['error']}")
                print()
                continue
            
            if idx['total_vectors'] is not None:
                print(f"  Total Vectors: {idx['total_vectors']:,}")
            
            if idx['dimension'] is not None:
                print(f"  Dimension: {idx['dimension']}")
            
            if idx['model']:
                print(f"  Model: {idx['model']}")
            
            # Highlight VUL-RAG enrichment
            if idx['has_vulrag_enrichment']:
                print(f"  VUL-RAG Enrichment: ✓ YES")
                
                if idx['enrichment_stats']:
                    stats = idx['enrichment_stats']
                    print(f"    - Total CVEs: {stats.get('total_cves', 'N/A'):,}")
                    print(f"    - Enriched CVEs: {stats.get('enriched_cves', 'N/A'):,}")
                    print(f"    - Coverage: {stats.get('enrichment_percentage', 0):.2f}%")
            else:
                print(f"  VUL-RAG Enrichment: ✗ NO (standard index)")
            
            print()


def main():
    """Command-line interface for index management"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Manage FAISS CVE indexes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all indexes
  python index_manager.py --list
  
  # Get info about a specific index
  python index_manager.py --info cve-vulrag
  
  # Verify if an index has VUL-RAG enrichment
  python index_manager.py --verify cve-vulrag
  
  # Print summary of all indexes
  python index_manager.py --summary
        """
    )
    
    parser.add_argument(
        '--index-dir',
        default='faiss_indexes',
        help='Directory containing FAISS indexes (default: faiss_indexes)'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all available indexes'
    )
    parser.add_argument(
        '--info',
        metavar='INDEX_NAME',
        help='Get detailed information about a specific index'
    )
    parser.add_argument(
        '--verify',
        metavar='INDEX_NAME',
        help='Verify if an index contains VUL-RAG enrichment'
    )
    parser.add_argument(
        '--summary',
        action='store_true',
        help='Print formatted summary of all indexes'
    )
    
    args = parser.parse_args()
    
    try:
        manager = IndexManager(index_dir=args.index_dir)
        
        if args.list:
            # List all indexes
            indexes = manager.list_indexes()
            print(f"\nAvailable indexes in '{args.index_dir}':")
            print("-" * 60)
            for idx in indexes:
                enrichment_marker = "✓" if idx['has_vulrag_enrichment'] else "✗"
                vectors = f"{idx['total_vectors']:,}" if idx['total_vectors'] else "N/A"
                print(f"{enrichment_marker} {idx['name']:<30} ({vectors} vectors)")
            print()
        
        elif args.info:
            # Get info about specific index
            info = manager.get_index_info(args.info)
            print(f"\nIndex Information: {args.info}")
            print("=" * 60)
            print(json.dumps(info, indent=2, default=str))
            print()
        
        elif args.verify:
            # Verify VUL-RAG enrichment
            has_enrichment = manager.verify_index_schema(args.verify)
            print(f"\nIndex: {args.verify}")
            if has_enrichment:
                print("✓ Contains VUL-RAG enrichment data")
                
                # Show coverage if available
                coverage = manager.get_enrichment_coverage(args.verify)
                if coverage:
                    print(f"  Total CVEs: {coverage['total_cves']:,}")
                    print(f"  Enriched CVEs: {coverage['enriched_cves']:,}")
                    print(f"  Coverage: {coverage['enrichment_percentage']:.2f}%")
            else:
                print("✗ Does not contain VUL-RAG enrichment (standard index)")
            print()
        
        elif args.summary:
            # Print formatted summary
            manager.print_index_summary()
        
        else:
            # Default: print summary
            manager.print_index_summary()
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    main()
