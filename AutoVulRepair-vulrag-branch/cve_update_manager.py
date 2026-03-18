"""
CVE Update Manager

Manages updates to VUL-RAG enrichment data for existing CVEs, including
database updates and FAISS index synchronization.

Usage:
    from cve_update_manager import CVEUpdateManager
    
    manager = CVEUpdateManager(index_name='cve-vulrag')
    
    # Update single CVE
    manager.update_vulrag_enrichment(
        'CVE-2023-12345',
        {'root_cause': 'Updated root cause', 'fix_strategy': 'New fix strategy'}
    )
    
    # Update multiple CVEs
    updates = {
        'CVE-2023-1': {'root_cause': 'New cause'},
        'CVE-2023-2': {'fix_strategy': 'New strategy'}
    }
    manager.update_bulk(updates)
"""

import sqlite3
import os
import pickle
from typing import Dict, List, Optional, Any
import numpy as np

try:
    import faiss
except ImportError:
    print("ERROR: FAISS not installed!")
    print("Please run: pip install faiss-cpu")
    exit(1)

from enhanced_embedding_generator import EnhancedEmbeddingGenerator


class CVEUpdateManager:
    """Manages updates to VUL-RAG enrichment data with index synchronization"""
    
    VULRAG_FIELDS = ['cwe_id', 'vulnerability_type', 'root_cause', 
                     'attack_condition', 'fix_strategy', 'code_pattern']
    
    def __init__(self, index_name: str = 'cve-vulrag', 
                 index_dir: str = 'faiss_indexes', 
                 db_path: str = 'cves.db'):
        """
        Initialize the CVE update manager
        
        Args:
            index_name: Name of the FAISS index to update
            index_dir: Directory containing FAISS indexes
            db_path: Path to SQLite database
        """
        self.index_name = index_name
        self.index_dir = index_dir
        self.db_path = db_path
        
        # Paths
        self.index_path = os.path.join(index_dir, f'{index_name}.index')
        self.metadata_path = os.path.join(index_dir, f'{index_name}.metadata')
        
        # Load index and metadata
        self._load_index()
        
        # Initialize embedding generator
        self.generator = EnhancedEmbeddingGenerator()
    
    def _load_index(self):
        """Load FAISS index and metadata from disk"""
        if not os.path.exists(self.index_path):
            raise FileNotFoundError(
                f"Index file not found: {self.index_path}. "
                f"Please create the index first using create_enhanced_index.py"
            )
        
        if not os.path.exists(self.metadata_path):
            raise FileNotFoundError(
                f"Metadata file not found: {self.metadata_path}"
            )
        
        # Load FAISS index
        self.index = faiss.read_index(self.index_path)
        
        # Load metadata
        with open(self.metadata_path, 'rb') as f:
            self.metadata = pickle.load(f)
        
        # Create CVE ID to index mapping for fast lookups
        self.cve_to_idx = {
            meta['cve_id']: idx 
            for idx, meta in enumerate(self.metadata)
        }
    
    def _save_index(self):
        """Save FAISS index and metadata to disk"""
        # Save FAISS index
        faiss.write_index(self.index, self.index_path)
        
        # Save metadata
        with open(self.metadata_path, 'wb') as f:
            pickle.dump(self.metadata, f)
    
    def _get_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CVE data from database
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary with CVE data or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT cve_id, description, published_date, last_modified
                FROM cves
                WHERE cve_id = ?
            """, (cve_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                'cve_id': row[0],
                'description': row[1],
                'published_date': row[2],
                'last_modified': row[3]
            }
        finally:
            conn.close()
    
    def _get_vulrag_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get VUL-RAG enrichment data from database
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary with VUL-RAG data or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT cwe_id, vulnerability_type, root_cause,
                       attack_condition, fix_strategy, code_pattern
                FROM vulrag_enrichment
                WHERE cve_id = ?
            """, (cve_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                'cwe_id': row[0],
                'vulnerability_type': row[1],
                'root_cause': row[2],
                'attack_condition': row[3],
                'fix_strategy': row[4],
                'code_pattern': row[5]
            }
        finally:
            conn.close()
    
    def _update_database(self, cve_id: str, vulrag_updates: Dict[str, Any]) -> None:
        """
        Update VUL-RAG enrichment in database
        
        Args:
            cve_id: CVE identifier
            vulrag_updates: Dictionary of fields to update
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if enrichment exists
            cursor.execute(
                "SELECT cve_id FROM vulrag_enrichment WHERE cve_id = ?",
                (cve_id,)
            )
            exists = cursor.fetchone() is not None
            
            if exists:
                # Build UPDATE query for only the fields being updated
                update_fields = []
                update_values = []
                
                for field in self.VULRAG_FIELDS:
                    if field in vulrag_updates:
                        update_fields.append(f"{field} = ?")
                        update_values.append(vulrag_updates[field])
                
                if update_fields:
                    # Add updated_at timestamp
                    update_fields.append("updated_at = CURRENT_TIMESTAMP")
                    
                    # Add cve_id for WHERE clause
                    update_values.append(cve_id)
                    
                    query = f"""
                        UPDATE vulrag_enrichment
                        SET {', '.join(update_fields)}
                        WHERE cve_id = ?
                    """
                    
                    cursor.execute(query, update_values)
            else:
                # Insert new enrichment
                fields = ['cve_id'] + [f for f in self.VULRAG_FIELDS if f in vulrag_updates]
                placeholders = ','.join(['?'] * len(fields))
                values = [cve_id] + [vulrag_updates[f] for f in fields[1:]]
                
                query = f"""
                    INSERT INTO vulrag_enrichment ({', '.join(fields)})
                    VALUES ({placeholders})
                """
                
                cursor.execute(query, values)
            
            conn.commit()
        finally:
            conn.close()
    
    def _regenerate_embedding(self, cve_id: str) -> np.ndarray:
        """
        Regenerate embedding for a CVE with updated enrichment
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            New normalized embedding vector
        """
        # Get CVE data
        cve_data = self._get_cve_data(cve_id)
        if not cve_data:
            raise ValueError(f"CVE not found in database: {cve_id}")
        
        # Get updated VUL-RAG data
        vulrag_data = self._get_vulrag_data(cve_id)
        
        # Generate new embedding
        embedding = self.generator.create_single_embedding(cve_data, vulrag_data)
        
        return embedding
    
    def _update_index_vector(self, cve_id: str, new_embedding: np.ndarray) -> None:
        """
        Replace vector in FAISS index at existing position
        
        Args:
            cve_id: CVE identifier
            new_embedding: New embedding vector to replace with
        """
        # Get index position
        if cve_id not in self.cve_to_idx:
            raise ValueError(f"CVE not found in index: {cve_id}")
        
        idx = self.cve_to_idx[cve_id]
        
        # FAISS doesn't support in-place updates, so we need to reconstruct
        # the index with the updated vector
        # For IndexFlatIP, we need to extract all vectors and rebuild
        
        # Get all vectors using reconstruct method
        n_vectors = self.index.ntotal
        d = self.index.d
        all_vectors = np.zeros((n_vectors, d), dtype=np.float32)
        
        for i in range(n_vectors):
            self.index.reconstruct(i, all_vectors[i])
        
        # Replace the vector at the specific index
        all_vectors[idx] = new_embedding.astype(np.float32)
        
        # Recreate index with updated vectors
        new_index = faiss.IndexFlatIP(self.index.d)
        new_index.add(all_vectors)
        
        self.index = new_index
    
    def _update_metadata(self, cve_id: str, vulrag_updates: Dict[str, Any]) -> None:
        """
        Update metadata with new VUL-RAG fields
        
        Args:
            cve_id: CVE identifier
            vulrag_updates: Dictionary of fields to update
        """
        if cve_id not in self.cve_to_idx:
            raise ValueError(f"CVE not found in metadata: {cve_id}")
        
        idx = self.cve_to_idx[cve_id]
        
        # Update metadata entry
        for field in self.VULRAG_FIELDS:
            if field in vulrag_updates:
                self.metadata[idx][field] = vulrag_updates[field]
    
    def update_vulrag_enrichment(self, cve_id: str, vulrag_updates: Dict[str, Any]) -> None:
        """
        Update VUL-RAG enrichment for a CVE
        
        This method performs a selective update of VUL-RAG fields while preserving
        standard CVE data. It updates the database, regenerates the embedding,
        and synchronizes the FAISS index.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2023-12345')
            vulrag_updates: Dictionary of VUL-RAG fields to update
                          Valid fields: cwe_id, vulnerability_type, root_cause,
                          attack_condition, fix_strategy, code_pattern
        
        Raises:
            ValueError: If CVE not found or invalid fields provided
        
        Example:
            manager.update_vulrag_enrichment(
                'CVE-2023-12345',
                {
                    'root_cause': 'Updated root cause analysis',
                    'fix_strategy': 'New recommended fix strategy'
                }
            )
        """
        # Validate CVE exists
        if cve_id not in self.cve_to_idx:
            raise ValueError(f"CVE not found in index: {cve_id}")
        
        # Validate fields
        invalid_fields = set(vulrag_updates.keys()) - set(self.VULRAG_FIELDS)
        if invalid_fields:
            raise ValueError(f"Invalid VUL-RAG fields: {invalid_fields}")
        
        # Update database
        self._update_database(cve_id, vulrag_updates)
        
        # Regenerate embedding with updated data
        new_embedding = self._regenerate_embedding(cve_id)
        
        # Update FAISS index
        self._update_index_vector(cve_id, new_embedding)
        
        # Update metadata
        self._update_metadata(cve_id, vulrag_updates)
        
        # Save changes to disk
        self._save_index()
    
    def update_bulk(self, updates: Dict[str, Dict[str, Any]], 
                   batch_size: int = 100) -> Dict[str, Any]:
        """
        Update multiple CVEs in batches
        
        Args:
            updates: Dictionary mapping CVE IDs to their update dictionaries
            batch_size: Number of updates to process before saving (for performance)
        
        Returns:
            Dictionary with statistics: success_count, error_count, errors
        
        Example:
            updates = {
                'CVE-2023-1': {'root_cause': 'New cause'},
                'CVE-2023-2': {'fix_strategy': 'New strategy'}
            }
            result = manager.update_bulk(updates)
        """
        success_count = 0
        error_count = 0
        errors = []
        
        cve_ids = list(updates.keys())
        
        for i, cve_id in enumerate(cve_ids):
            try:
                vulrag_updates = updates[cve_id]
                
                # Validate CVE exists
                if cve_id not in self.cve_to_idx:
                    raise ValueError(f"CVE not found in index: {cve_id}")
                
                # Validate fields
                invalid_fields = set(vulrag_updates.keys()) - set(self.VULRAG_FIELDS)
                if invalid_fields:
                    raise ValueError(f"Invalid VUL-RAG fields: {invalid_fields}")
                
                # Update database
                self._update_database(cve_id, vulrag_updates)
                
                # Regenerate embedding
                new_embedding = self._regenerate_embedding(cve_id)
                
                # Update FAISS index
                self._update_index_vector(cve_id, new_embedding)
                
                # Update metadata
                self._update_metadata(cve_id, vulrag_updates)
                
                success_count += 1
                
                # Save periodically for large batches
                if (i + 1) % batch_size == 0:
                    self._save_index()
                
            except Exception as e:
                error_count += 1
                errors.append({
                    'cve_id': cve_id,
                    'error': str(e)
                })
        
        # Final save
        self._save_index()
        
        return {
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors,
            'total': len(updates)
        }
    
    def get_index_size(self) -> int:
        """
        Get the number of vectors in the FAISS index
        
        Returns:
            Number of vectors in the index
        """
        return self.index.ntotal
    
    def verify_synchronization(self, cve_id: str) -> bool:
        """
        Verify that database and index are synchronized for a CVE
        
        Checks that the enrichment data in the database matches what's
        embedded in the FAISS index by comparing embeddings.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            True if synchronized, False otherwise
        """
        if cve_id not in self.cve_to_idx:
            return False
        
        # Get current embedding from index
        idx = self.cve_to_idx[cve_id]
        current_embedding = np.zeros(self.index.d, dtype=np.float32)
        self.index.reconstruct(idx, current_embedding)
        
        # Regenerate embedding from current database state
        expected_embedding = self._regenerate_embedding(cve_id)
        
        # Compare embeddings (should be very close, allowing for floating point errors)
        diff = np.linalg.norm(current_embedding - expected_embedding)
        
        # Threshold for considering embeddings equal (very small due to normalization)
        return diff < 1e-6


def main():
    """Command-line interface for CVE update manager"""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(
        description='Update VUL-RAG enrichment data for CVEs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update single CVE
  python cve_update_manager.py --cve CVE-2023-12345 --update '{"root_cause": "New cause"}'
  
  # Update from JSON file
  python cve_update_manager.py --bulk-file updates.json
  
  # Verify synchronization
  python cve_update_manager.py --verify CVE-2023-12345
        """
    )
    
    parser.add_argument(
        '--index-name',
        default='cve-vulrag',
        help='Name of the FAISS index (default: cve-vulrag)'
    )
    parser.add_argument(
        '--db-path',
        default='cves.db',
        help='Path to CVE database (default: cves.db)'
    )
    parser.add_argument(
        '--cve',
        help='CVE ID to update'
    )
    parser.add_argument(
        '--update',
        help='JSON string with fields to update'
    )
    parser.add_argument(
        '--bulk-file',
        help='JSON file with bulk updates (format: {"CVE-ID": {...}, ...})'
    )
    parser.add_argument(
        '--verify',
        help='Verify synchronization for a CVE ID'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize manager
        manager = CVEUpdateManager(
            index_name=args.index_name,
            db_path=args.db_path
        )
        
        print(f"✓ Loaded index: {args.index_name}")
        print(f"  Total vectors: {manager.get_index_size():,}")
        print()
        
        # Single CVE update
        if args.cve and args.update:
            print(f"Updating {args.cve}...")
            
            updates = json.loads(args.update)
            manager.update_vulrag_enrichment(args.cve, updates)
            
            print(f"✓ Successfully updated {args.cve}")
            print(f"  Updated fields: {', '.join(updates.keys())}")
        
        # Bulk update
        elif args.bulk_file:
            print(f"Loading bulk updates from: {args.bulk_file}")
            
            with open(args.bulk_file, 'r') as f:
                updates = json.load(f)
            
            print(f"Processing {len(updates)} CVE updates...")
            
            result = manager.update_bulk(updates)
            
            print(f"\n✓ Bulk update complete")
            print(f"  Successful: {result['success_count']}")
            print(f"  Errors: {result['error_count']}")
            
            if result['errors']:
                print(f"\nErrors:")
                for error in result['errors'][:10]:
                    print(f"  {error['cve_id']}: {error['error']}")
                
                if len(result['errors']) > 10:
                    print(f"  ... and {len(result['errors']) - 10} more errors")
        
        # Verify synchronization
        elif args.verify:
            print(f"Verifying synchronization for {args.verify}...")
            
            is_synced = manager.verify_synchronization(args.verify)
            
            if is_synced:
                print(f"✓ {args.verify} is synchronized")
            else:
                print(f"✗ {args.verify} is NOT synchronized")
                print(f"  Database and index may be out of sync")
        
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    main()
