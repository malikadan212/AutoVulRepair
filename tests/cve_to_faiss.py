"""
CVE Database to FAISS Vector Database Converter

FAISS (Facebook AI Similarity Search) - Local, Fast, FREE!

Advantages over Pinecone:
- ✅ Completely FREE (no limits)
- ✅ All 316,437 CVEs supported
- ✅ Runs locally (your data stays private)
- ✅ Faster (no network latency)
- ✅ No account or API key needed

Usage:
    python cve_to_faiss.py --index-name cve-vectors
    python cve_to_faiss.py --index-name cve-vectors --max-records 1000
"""

import sqlite3
import json
import argparse
import os
import pickle
from typing import List, Dict, Any
from tqdm import tqdm
import numpy as np

try:
    import faiss
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("ERROR: Required packages not installed!")
    print("Please run: pip install faiss-cpu sentence-transformers")
    exit(1)


class CVEToFAISSConverter:
    def __init__(self, index_name: str, db_path: str = 'cves.db'):
        """Initialize the converter"""
        self.db_path = db_path
        self.index_name = index_name
        self.index_dir = 'faiss_indexes'
        
        # Create index directory
        os.makedirs(self.index_dir, exist_ok=True)
        
        # Load embedding model
        print("Loading embedding model (this may take a moment)...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.embedding_dim = 384
        
        print(f"✓ Model loaded: all-MiniLM-L6-v2 ({self.embedding_dim} dimensions)")
        
        # Initialize FAISS index
        self.index = None
        self.metadata = []
    
    def create_index(self):
        """Create FAISS index"""
        print(f"Creating FAISS index...")
        
        # Use IndexFlatIP for cosine similarity (Inner Product after normalization)
        # This is equivalent to Pinecone's cosine metric
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
    
    def fetch_cves_batch(self, offset: int, batch_size: int) -> List[Dict[str, Any]]:
        """Fetch a batch of CVEs from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT cve_id, published_date, last_modified, description, raw_json
            FROM cves
            LIMIT ? OFFSET ?
        """, (batch_size, offset))
        
        rows = cursor.fetchall()
        conn.close()
        
        cves = []
        for row in rows:
            cve_id, published, modified, description, raw_json = row
            
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
            
            # Extract CWE information
            cwes = []
            if 'weaknesses' in cve_data:
                for weakness in cve_data['weaknesses']:
                    for desc in weakness.get('description', []):
                        cwes.append(desc.get('value', ''))
            
            cves.append({
                'cve_id': cve_id,
                'description': description,
                'published_date': published,
                'last_modified': modified,
                'cvss_score': cvss_score,
                'severity': severity,
                'cwes': cwes
            })
        
        return cves
    
    def create_embedding_text(self, cve: Dict[str, Any]) -> str:
        """Create text for embedding from CVE data"""
        parts = [
            f"CVE ID: {cve['cve_id']}",
            f"Description: {cve['description']}",
        ]
        
        if cve['severity'] != "UNKNOWN":
            parts.append(f"Severity: {cve['severity']}")
        
        if cve['cwes']:
            parts.append(f"Weaknesses: {', '.join(cve['cwes'][:3])}")
        
        return " | ".join(parts)
    
    def add_batch(self, cves: List[Dict[str, Any]]):
        """Create embeddings and add batch to FAISS"""
        # Create embedding texts
        texts = [self.create_embedding_text(cve) for cve in cves]
        
        # Generate embeddings
        embeddings = self.model.encode(texts, show_progress_bar=False)
        
        # Normalize for cosine similarity
        faiss.normalize_L2(embeddings)
        
        # Add to index
        self.index.add(embeddings)
        
        # Store metadata
        for cve in cves:
            self.metadata.append({
                'cve_id': cve['cve_id'],
                'description': cve['description'],
                'published_date': cve['published_date'],
                'severity': cve['severity'],
                'cvss_score': cve['cvss_score'],
                'cwe': cve['cwes'][0] if cve['cwes'] else None
            })
    
    def save_index(self):
        """Save FAISS index and metadata to disk"""
        index_path = os.path.join(self.index_dir, f'{self.index_name}.index')
        metadata_path = os.path.join(self.index_dir, f'{self.index_name}.metadata')
        
        print(f"\nSaving index to disk...")
        
        # Save FAISS index
        faiss.write_index(self.index, index_path)
        
        # Save metadata
        with open(metadata_path, 'wb') as f:
            pickle.dump(self.metadata, f)
        
        # Save index info
        info = {
            'name': self.index_name,
            'total_vectors': self.index.ntotal,
            'dimension': self.embedding_dim,
            'model': 'all-MiniLM-L6-v2'
        }
        
        info_path = os.path.join(self.index_dir, f'{self.index_name}.info')
        with open(info_path, 'w') as f:
            json.dump(info, f, indent=2)
        
        print(f"✓ Index saved: {index_path}")
        print(f"✓ Metadata saved: {metadata_path}")
        print(f"✓ Info saved: {info_path}")
    
    def convert(self, batch_size: int = 100, max_records: int = None):
        """Convert CVE database to FAISS vectors"""
        # Create index
        self.create_index()
        
        # Get total count
        total_cves = self.get_cve_count()
        if max_records:
            total_cves = min(total_cves, max_records)
        
        print(f"\nConverting {total_cves:,} CVEs to vector embeddings...")
        print(f"Batch size: {batch_size}")
        print(f"This may take a while...\n")
        
        # Process in batches
        offset = 0
        with tqdm(total=total_cves, desc="Processing CVEs") as pbar:
            while offset < total_cves:
                # Fetch batch
                cves = self.fetch_cves_batch(offset, batch_size)
                
                if not cves:
                    break
                
                # Add to FAISS
                self.add_batch(cves)
                
                offset += len(cves)
                pbar.update(len(cves))
        
        # Save to disk
        self.save_index()
        
        print(f"\n✓ Conversion complete!")
        print(f"Total vectors: {self.index.ntotal:,}")
        print(f"Index dimension: {self.embedding_dim}")
        print(f"Index location: {self.index_dir}/{self.index_name}.index")
    
    def test_search(self, query: str, top_k: int = 5):
        """Test semantic search on the index"""
        print(f"\nTesting search with query: '{query}'")
        
        # Create query embedding
        query_embedding = self.model.encode([query])
        faiss.normalize_L2(query_embedding)
        
        # Search
        distances, indices = self.index.search(query_embedding, top_k)
        
        print(f"\nTop {top_k} results:")
        print("-" * 80)
        
        for i, (idx, score) in enumerate(zip(indices[0], distances[0]), 1):
            if idx == -1:  # No result
                continue
            
            meta = self.metadata[idx]
            print(f"\n{i}. {meta['cve_id']} (Score: {score:.4f})")
            print(f"   Severity: {meta.get('severity', 'N/A')}")
            if meta.get('cvss_score'):
                print(f"   CVSS: {meta['cvss_score']}")
            print(f"   Description: {meta['description'][:200]}...")


def main():
    parser = argparse.ArgumentParser(
        description='Convert CVE database to FAISS vector database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert all CVEs (FREE - no limits!)
  python cve_to_faiss.py --index-name cve-vectors
  
  # Convert first 1000 CVEs (for testing)
  python cve_to_faiss.py --index-name cve-test --max-records 1000
  
  # Test search after conversion
  python cve_to_faiss.py --index-name cve-vectors --test-search "SQL injection vulnerability" --skip-conversion
        """
    )
    
    parser.add_argument('--index-name', required=True, help='Name for the FAISS index')
    parser.add_argument('--db-path', default='cves.db', help='Path to CVE database (default: cves.db)')
    parser.add_argument('--batch-size', type=int, default=100, help='Batch size for processing (default: 100)')
    parser.add_argument('--max-records', type=int, help='Maximum number of records to process (for testing)')
    parser.add_argument('--test-search', help='Test search query after conversion')
    parser.add_argument('--skip-conversion', action='store_true', help='Skip conversion, only run test search')
    
    args = parser.parse_args()
    
    # Check if database exists
    if not os.path.exists(args.db_path):
        print(f"ERROR: Database file '{args.db_path}' not found!")
        exit(1)
    
    # Create converter
    converter = CVEToFAISSConverter(
        index_name=args.index_name,
        db_path=args.db_path
    )
    
    # Convert database
    if not args.skip_conversion:
        converter.convert(
            batch_size=args.batch_size,
            max_records=args.max_records
        )
    else:
        # Load existing index for search
        from search_cve_faiss import FAISSCVESearch
        searcher = FAISSCVESearch(args.index_name)
        if args.test_search:
            searcher.search(args.test_search, top_k=5)
        return
    
    # Test search if requested
    if args.test_search:
        converter.test_search(args.test_search)


if __name__ == '__main__':
    main()
