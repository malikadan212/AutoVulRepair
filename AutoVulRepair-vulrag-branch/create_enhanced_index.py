"""
Enhanced FAISS Index Creation Tool

Creates a FAISS index with VUL-RAG enrichment data including root causes,
fix strategies, code patterns, and attack conditions for improved semantic search.

This tool generates the 'cve-vulrag' index that includes both standard CVE data
and VUL-RAG enrichment fields in the embeddings.

Usage:
    python create_enhanced_index.py
    python create_enhanced_index.py --index-name cve-vulrag --batch-size 100
    python create_enhanced_index.py --max-records 1000  # For testing
"""

import sqlite3
import json
import argparse
import os
import pickle
from typing import List, Dict, Any, Optional, Tuple
from tqdm import tqdm
import numpy as np

try:
    import faiss
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("ERROR: Required packages not installed!")
    print("Please run: pip install faiss-cpu sentence-transformers")
    exit(1)

from enhanced_embedding_generator import EnhancedEmbeddingGenerator


class EnhancedIndexCreator:
    """Creates enhanced FAISS indexes with VUL-RAG enrichment data"""
    
    def __init__(self, index_name: str = 'cve-vulrag', db_path: str = 'cves.db'):
        """
        Initialize the enhanced index creator
        
        Args:
            index_name: Name for the enhanced index (default: cve-vulrag)
            db_path: Path to the CVE database
        """
        self.db_path = db_path
        self.index_name = index_name
        self.index_dir = 'faiss_indexes'
        
        # Create index directory
        os.makedirs(self.index_dir, exist_ok=True)
        
        # Initialize embedding generator
        print("Loading embedding model (this may take a moment)...")
        self.generator = EnhancedEmbeddingGenerator()
        self.embedding_dim = self.generator.get_embedding_dimension()
        
        print(f"✓ Model loaded: {self.generator.get_model_name()} ({self.embedding_dim} dimensions)")
        
        # Initialize FAISS index and metadata
        self.index = None
        self.metadata = []
    
    def _validate_database(self):
        """Validate that the database has required tables"""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(
                f"Database file '{self.db_path}' not found. "
                "Please ensure the CVE database exists."
            )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for cves table
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='cves'
        """)
        if not cursor.fetchone():
            conn.close()
            raise ValueError("The 'cves' table does not exist in the database")
        
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
    
    def create_index(self):
        """Create FAISS index for enhanced embeddings"""
        print(f"Creating enhanced FAISS index...")
        
        # Use IndexFlatIP for cosine similarity (Inner Product after normalization)
        self.index = faiss.IndexFlatIP(self.embedding_dim)
        
        print(f"✓ FAISS index created (dimension: {self.embedding_dim})")
    
    def get_cve_count(self) -> int:
        """Get total number of CVEs in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_enrichment_stats(self) -> Dict[str, int]:
        """Get statistics about VUL-RAG enrichment coverage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count total CVEs
        cursor.execute("SELECT COUNT(*) FROM cves")
        total_cves = cursor.fetchone()[0]
        
        # Count enriched CVEs
        cursor.execute("SELECT COUNT(*) FROM vulrag_enrichment")
        enriched_cves = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_cves': total_cves,
            'enriched_cves': enriched_cves,
            'enrichment_percentage': (enriched_cves / total_cves * 100) if total_cves > 0 else 0
        }

    def fetch_cves_with_enrichment_batch(self, offset: int, batch_size: int) -> Tuple[List[Dict[str, Any]], List[Optional[Dict[str, Any]]]]:
        """
        Fetch a batch of CVEs with their VUL-RAG enrichment data
        
        Args:
            offset: Starting offset for batch
            batch_size: Number of CVEs to fetch
        
        Returns:
            Tuple of (cve_list, vulrag_list) where vulrag_list contains None for non-enriched CVEs
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Fetch CVEs with LEFT JOIN to include CVEs without enrichment
        cursor.execute("""
            SELECT 
                c.cve_id, 
                c.published_date, 
                c.last_modified, 
                c.description, 
                c.raw_json,
                v.cwe_id,
                v.vulnerability_type,
                v.root_cause,
                v.attack_condition,
                v.fix_strategy,
                v.code_pattern
            FROM cves c
            LEFT JOIN vulrag_enrichment v ON c.cve_id = v.cve_id
            LIMIT ? OFFSET ?
        """, (batch_size, offset))
        
        rows = cursor.fetchall()
        conn.close()
        
        cve_list = []
        vulrag_list = []
        
        for row in rows:
            (cve_id, published, modified, description, raw_json,
             cwe_id, vuln_type, root_cause, attack_cond, fix_strat, code_pat) = row
            
            # Parse raw JSON for additional metadata
            try:
                cve_data = json.loads(raw_json)
            except:
                cve_data = {}
            
            # Extract CVSS score if available
            cvss_score = None
            severity = "UNKNOWN"
            if 'metrics' in cve_data:
                if 'cvssMetricV31' in cve_data['metrics'] and cve_data['metrics']['cvssMetricV31']:
                    cvss_score = cve_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    severity = cve_data['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                elif 'cvssMetricV2' in cve_data['metrics'] and cve_data['metrics']['cvssMetricV2']:
                    cvss_score = cve_data['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                    severity = cve_data['metrics']['cvssMetricV2'][0]['baseSeverity']
            
            # Extract CWE information from raw JSON
            cwes = []
            if 'weaknesses' in cve_data:
                for weakness in cve_data['weaknesses']:
                    for desc in weakness.get('description', []):
                        cwes.append(desc.get('value', ''))
            
            # Build CVE data dictionary
            cve_dict = {
                'cve_id': cve_id,
                'description': description,
                'published_date': published,
                'last_modified': modified,
                'cvss_score': cvss_score,
                'severity': severity,
                'cwes': cwes
            }
            
            # Build VUL-RAG enrichment dictionary (None if no enrichment)
            vulrag_dict = None
            if cwe_id or vuln_type or root_cause or attack_cond or fix_strat or code_pat:
                vulrag_dict = {
                    'cwe_id': cwe_id,
                    'vulnerability_type': vuln_type,
                    'root_cause': root_cause,
                    'attack_condition': attack_cond,
                    'fix_strategy': fix_strat,
                    'code_pattern': code_pat
                }
            
            cve_list.append(cve_dict)
            vulrag_list.append(vulrag_dict)
        
        return cve_list, vulrag_list
    
    def add_batch(self, cve_list: List[Dict[str, Any]], vulrag_list: List[Optional[Dict[str, Any]]]):
        """
        Create embeddings and add batch to FAISS index
        
        Args:
            cve_list: List of CVE data dictionaries
            vulrag_list: List of VUL-RAG enrichment dictionaries (can contain None)
        """
        # Generate embeddings using EnhancedEmbeddingGenerator
        embeddings = self.generator.create_embeddings(cve_list, vulrag_list)
        
        # Add to FAISS index (embeddings are already normalized by the generator)
        self.index.add(embeddings)
        
        # Store metadata for each CVE
        for cve, vulrag in zip(cve_list, vulrag_list):
            metadata_entry = {
                'cve_id': cve['cve_id'],
                'description': cve['description'],
                'published_date': cve['published_date'],
                'severity': cve['severity'],
                'cvss_score': cve['cvss_score'],
                'cwe': cve['cwes'][0] if cve['cwes'] else None
            }
            
            # Add VUL-RAG fields to metadata
            if vulrag:
                metadata_entry.update({
                    'vulnerability_type': vulrag.get('vulnerability_type'),
                    'root_cause': vulrag.get('root_cause'),
                    'fix_strategy': vulrag.get('fix_strategy'),
                    'code_pattern': vulrag.get('code_pattern'),
                    'attack_condition': vulrag.get('attack_condition'),
                    'vulrag_cwe_id': vulrag.get('cwe_id')
                })
            else:
                # Set VUL-RAG fields to None for non-enriched CVEs
                metadata_entry.update({
                    'vulnerability_type': None,
                    'root_cause': None,
                    'fix_strategy': None,
                    'code_pattern': None,
                    'attack_condition': None,
                    'vulrag_cwe_id': None
                })
            
            self.metadata.append(metadata_entry)
    
    def save_index(self):
        """Save FAISS index and metadata to disk"""
        index_path = os.path.join(self.index_dir, f'{self.index_name}.index')
        metadata_path = os.path.join(self.index_dir, f'{self.index_name}.metadata')
        
        print(f"\nSaving enhanced index to disk...")
        
        # Save FAISS index
        faiss.write_index(self.index, index_path)
        
        # Save metadata
        with open(metadata_path, 'wb') as f:
            pickle.dump(self.metadata, f)
        
        # Save index info
        enrichment_stats = self.get_enrichment_stats()
        info = {
            'name': self.index_name,
            'total_vectors': self.index.ntotal,
            'dimension': self.embedding_dim,
            'model': self.generator.get_model_name(),
            'enhanced': True,
            'vulrag_enrichment': True,
            'enrichment_stats': enrichment_stats
        }
        
        info_path = os.path.join(self.index_dir, f'{self.index_name}.info')
        with open(info_path, 'w') as f:
            json.dump(info, f, indent=2)
        
        print(f"✓ Index saved: {index_path}")
        print(f"✓ Metadata saved: {metadata_path}")
        print(f"✓ Info saved: {info_path}")
    
    def build_index(self, batch_size: int = 100, max_records: int = None):
        """
        Build enhanced FAISS index from database
        
        Args:
            batch_size: Number of CVEs to process per batch
            max_records: Maximum number of records to process (None for all)
        """
        # Validate database
        print("Validating database...")
        self._validate_database()
        print("✓ Database validation passed")
        
        # Get enrichment statistics
        stats = self.get_enrichment_stats()
        print(f"\nEnrichment Statistics:")
        print(f"  Total CVEs: {stats['total_cves']:,}")
        print(f"  Enriched CVEs: {stats['enriched_cves']:,}")
        print(f"  Enrichment coverage: {stats['enrichment_percentage']:.1f}%")
        
        # Create index
        self.create_index()
        
        # Get total count
        total_cves = self.get_cve_count()
        if max_records:
            total_cves = min(total_cves, max_records)
        
        print(f"\nBuilding enhanced index with {total_cves:,} CVEs...")
        print(f"Batch size: {batch_size}")
        print(f"This may take a while...\n")
        
        # Process in batches with progress reporting
        offset = 0
        with tqdm(total=total_cves, desc="Processing CVEs", unit="CVE") as pbar:
            while offset < total_cves:
                # Fetch batch with enrichment data
                cve_list, vulrag_list = self.fetch_cves_with_enrichment_batch(offset, batch_size)
                
                if not cve_list:
                    break
                
                # Add to FAISS index
                self.add_batch(cve_list, vulrag_list)
                
                offset += len(cve_list)
                pbar.update(len(cve_list))
        
        # Save to disk
        self.save_index()
        
        print(f"\n✓ Enhanced index creation complete!")
        print(f"Total vectors: {self.index.ntotal:,}")
        print(f"Index dimension: {self.embedding_dim}")
        print(f"Index location: {self.index_dir}/{self.index_name}.index")
        print(f"\nThis index includes VUL-RAG enrichment data:")
        print(f"  - Root causes")
        print(f"  - Fix strategies")
        print(f"  - Code patterns")
        print(f"  - Attack conditions")
        print(f"  - Vulnerability types")
    
    def test_search(self, query: str, top_k: int = 5):
        """
        Test semantic search on the enhanced index
        
        Args:
            query: Search query string
            top_k: Number of results to return
        """
        print(f"\nTesting enhanced search with query: '{query}'")
        
        # Create query embedding (without enrichment)
        query_cve = {'cve_id': 'QUERY', 'description': query}
        query_embedding = self.generator.create_single_embedding(query_cve, None)
        query_embedding = query_embedding.reshape(1, -1)
        
        # Search
        distances, indices = self.index.search(query_embedding, top_k)
        
        print(f"\nTop {top_k} results:")
        print("=" * 80)
        
        for i, (idx, score) in enumerate(zip(indices[0], distances[0]), 1):
            if idx == -1:  # No result
                continue
            
            meta = self.metadata[idx]
            print(f"\n{i}. {meta['cve_id']} (Score: {score:.4f})")
            print(f"   Severity: {meta.get('severity', 'N/A')}")
            if meta.get('cvss_score'):
                print(f"   CVSS: {meta['cvss_score']}")
            print(f"   Description: {meta['description'][:150]}...")
            
            # Show VUL-RAG enrichment if available
            if meta.get('root_cause'):
                print(f"   Root Cause: {meta['root_cause'][:100]}...")
            if meta.get('fix_strategy'):
                print(f"   Fix Strategy: {meta['fix_strategy'][:100]}...")


def main():
    parser = argparse.ArgumentParser(
        description='Create enhanced FAISS index with VUL-RAG enrichment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create enhanced index with all CVEs
  python create_enhanced_index.py
  
  # Create with custom name
  python create_enhanced_index.py --index-name cve-vulrag-v2
  
  # Create test index with limited records
  python create_enhanced_index.py --index-name cve-test --max-records 1000
  
  # Test search after creation
  python create_enhanced_index.py --test-search "SQL injection fix" --skip-build
        """
    )
    
    parser.add_argument(
        '--index-name',
        default='cve-vulrag',
        help='Name for the enhanced index (default: cve-vulrag)'
    )
    parser.add_argument(
        '--db-path',
        default='cves.db',
        help='Path to CVE database (default: cves.db)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=100,
        help='Batch size for processing (default: 100)'
    )
    parser.add_argument(
        '--max-records',
        type=int,
        help='Maximum number of records to process (for testing)'
    )
    parser.add_argument(
        '--test-search',
        help='Test search query after index creation'
    )
    parser.add_argument(
        '--skip-build',
        action='store_true',
        help='Skip index building, only run test search'
    )
    
    args = parser.parse_args()
    
    # Create index creator
    creator = EnhancedIndexCreator(
        index_name=args.index_name,
        db_path=args.db_path
    )
    
    # Build index
    if not args.skip_build:
        try:
            creator.build_index(
                batch_size=args.batch_size,
                max_records=args.max_records
            )
        except Exception as e:
            print(f"\n✗ Error building index: {e}")
            import traceback
            traceback.print_exc()
            exit(1)
    else:
        # Load existing index for search
        print("Loading existing index for search test...")
        index_path = os.path.join(creator.index_dir, f'{args.index_name}.index')
        metadata_path = os.path.join(creator.index_dir, f'{args.index_name}.metadata')
        
        if not os.path.exists(index_path):
            print(f"✗ Index file not found: {index_path}")
            exit(1)
        
        creator.index = faiss.read_index(index_path)
        with open(metadata_path, 'rb') as f:
            creator.metadata = pickle.load(f)
        
        print(f"✓ Loaded index with {creator.index.ntotal:,} vectors")
    
    # Test search if requested
    if args.test_search:
        creator.test_search(args.test_search)


if __name__ == '__main__':
    main()
