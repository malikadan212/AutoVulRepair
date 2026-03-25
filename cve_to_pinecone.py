"""
CVE Database to Pinecone Vector Database Converter

Prerequisites:
1. Create a free Pinecone account at https://www.pinecone.io/
2. Get your API key from the Pinecone console
3. Install required packages: pip install pinecone-client sentence-transformers tqdm

Usage:
    python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-vectors
"""

import sqlite3
import json
import argparse
import os
from typing import List, Dict, Any
from tqdm import tqdm
import time

try:
    from pinecone import Pinecone, ServerlessSpec
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("ERROR: Required packages not installed!")
    print("Please run: pip install pinecone-client sentence-transformers tqdm")
    exit(1)


class CVEToPineconeConverter:
    def __init__(self, api_key: str, index_name: str, db_path: str = 'cves.db'):
        """Initialize the converter with Pinecone credentials"""
        self.db_path = db_path
        self.index_name = index_name
        
        # Initialize Pinecone
        print("Initializing Pinecone...")
        self.pc = Pinecone(api_key=api_key)
        
        # Load embedding model (using a lightweight model for free tier)
        print("Loading embedding model (this may take a moment)...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')  # 384 dimensions, fast and efficient
        self.embedding_dim = 384
        
        print(f"✓ Model loaded: all-MiniLM-L6-v2 ({self.embedding_dim} dimensions)")
    
    def create_index(self):
        """Create Pinecone index if it doesn't exist"""
        existing_indexes = [index.name for index in self.pc.list_indexes()]
        
        if self.index_name in existing_indexes:
            print(f"✓ Index '{self.index_name}' already exists")
            return
        
        print(f"Creating new index '{self.index_name}'...")
        
        # Create serverless index (free tier)
        self.pc.create_index(
            name=self.index_name,
            dimension=self.embedding_dim,
            metric='cosine',
            spec=ServerlessSpec(
                cloud='aws',
                region='us-east-1'  # Free tier region
            )
        )
        
        # Wait for index to be ready
        print("Waiting for index to be ready...")
        while not self.pc.describe_index(self.index_name).status['ready']:
            time.sleep(1)
        
        print(f"✓ Index '{self.index_name}' created successfully")
    
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
            
            # Extract references
            references = []
            if 'references' in cve_data:
                references = [ref.get('url', '') for ref in cve_data['references'][:5]]  # Limit to 5
            
            cves.append({
                'cve_id': cve_id,
                'description': description,
                'published_date': published,
                'last_modified': modified,
                'cvss_score': cvss_score,
                'severity': severity,
                'cwes': cwes,
                'references': references
            })
        
        return cves
    
    def create_embedding_text(self, cve: Dict[str, Any]) -> str:
        """Create text for embedding from CVE data"""
        # Combine relevant fields for better semantic search
        parts = [
            f"CVE ID: {cve['cve_id']}",
            f"Description: {cve['description']}",
        ]
        
        if cve['severity'] != "UNKNOWN":
            parts.append(f"Severity: {cve['severity']}")
        
        if cve['cwes']:
            parts.append(f"Weaknesses: {', '.join(cve['cwes'][:3])}")
        
        return " | ".join(parts)
    
    def upsert_batch(self, index, cves: List[Dict[str, Any]]):
        """Create embeddings and upsert batch to Pinecone"""
        # Create embedding texts
        texts = [self.create_embedding_text(cve) for cve in cves]
        
        # Generate embeddings
        embeddings = self.model.encode(texts, show_progress_bar=False)
        
        # Prepare vectors for upsert
        vectors = []
        for i, cve in enumerate(cves):
            vector_id = cve['cve_id']
            embedding = embeddings[i].tolist()
            
            # Metadata (Pinecone free tier has metadata limits)
            metadata = {
                'cve_id': cve['cve_id'],
                'description': cve['description'][:500],  # Truncate for metadata limits
                'published_date': cve['published_date'],
                'severity': cve['severity'],
            }
            
            # Add optional fields if available
            if cve['cvss_score']:
                metadata['cvss_score'] = float(cve['cvss_score'])
            
            if cve['cwes']:
                metadata['cwe'] = cve['cwes'][0][:100]  # First CWE only
            
            vectors.append({
                'id': vector_id,
                'values': embedding,
                'metadata': metadata
            })
        
        # Upsert to Pinecone
        index.upsert(vectors=vectors)
    
    def convert(self, batch_size: int = 100, max_records: int = None):
        """Convert CVE database to Pinecone vectors"""
        # Create index
        self.create_index()
        
        # Get index
        index = self.pc.Index(self.index_name)
        
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
                
                # Upsert to Pinecone
                try:
                    self.upsert_batch(index, cves)
                except Exception as e:
                    print(f"\nError upserting batch at offset {offset}: {e}")
                    print("Retrying in 5 seconds...")
                    time.sleep(5)
                    continue
                
                offset += len(cves)
                pbar.update(len(cves))
                
                # Rate limiting for free tier
                time.sleep(0.1)
        
        # Get final stats
        stats = index.describe_index_stats()
        print(f"\n✓ Conversion complete!")
        print(f"Total vectors in index: {stats['total_vector_count']:,}")
        print(f"Index dimension: {stats['dimension']}")
    
    def test_search(self, query: str, top_k: int = 5):
        """Test semantic search on the index"""
        print(f"\nTesting search with query: '{query}'")
        
        # Get index
        index = self.pc.Index(self.index_name)
        
        # Create query embedding
        query_embedding = self.model.encode([query])[0].tolist()
        
        # Search
        results = index.query(
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True
        )
        
        print(f"\nTop {top_k} results:")
        print("-" * 80)
        for i, match in enumerate(results['matches'], 1):
            print(f"\n{i}. {match['id']} (Score: {match['score']:.4f})")
            print(f"   Severity: {match['metadata'].get('severity', 'N/A')}")
            if 'cvss_score' in match['metadata']:
                print(f"   CVSS: {match['metadata']['cvss_score']}")
            print(f"   Description: {match['metadata']['description'][:200]}...")


def main():
    parser = argparse.ArgumentParser(
        description='Convert CVE database to Pinecone vector database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert all CVEs
  python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-vectors
  
  # Convert first 1000 CVEs (for testing)
  python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-test --max-records 1000
  
  # Test search after conversion
  python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-vectors --test-search "SQL injection vulnerability"
        """
    )
    
    parser.add_argument('--api-key', required=True, help='Pinecone API key')
    parser.add_argument('--index-name', required=True, help='Name for the Pinecone index')
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
    converter = CVEToPineconeConverter(
        api_key=args.api_key,
        index_name=args.index_name,
        db_path=args.db_path
    )
    
    # Convert database
    if not args.skip_conversion:
        converter.convert(
            batch_size=args.batch_size,
            max_records=args.max_records
        )
    
    # Test search if requested
    if args.test_search:
        converter.test_search(args.test_search)


if __name__ == '__main__':
    main()
