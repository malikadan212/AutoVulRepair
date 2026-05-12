"""
Search CVE FAISS Vector Database

Simple and fast semantic search for CVEs using FAISS.

Usage:
    python search_cve_faiss.py --index-name cve-vectors --query "SQL injection"
    python search_cve_faiss.py --index-name cve-vectors --query "buffer overflow" --severity HIGH
    
    
    
     python search_cve_faiss.py --index-name cve-full --query "SQL injection"
    
"""

import argparse
import os
import pickle
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


class FAISSCVESearch:
    """Search CVE vectors using FAISS"""
    
    def __init__(self, index_name: str, index_dir: str = 'faiss_indexes'):
        self.index_name = index_name
        self.index_dir = index_dir
        
        # Load index
        index_path = os.path.join(index_dir, f'{index_name}.index')
        metadata_path = os.path.join(index_dir, f'{index_name}.metadata')
        
        if not os.path.exists(index_path):
            raise FileNotFoundError(f"Index not found: {index_path}")
        
        print(f"Loading index: {index_name}")
        self.index = faiss.read_index(index_path)
        
        print(f"Loading metadata...")
        with open(metadata_path, 'rb') as f:
            self.metadata = pickle.load(f)
        
        print(f"Loading embedding model...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        print(f"Ready! Index has {self.index.ntotal:,} CVEs")
    
    def search(self, query: str, top_k: int = 10, severity_filter: str = None, min_cvss: float = None):
        """
        Search CVEs by semantic similarity
        
        Args:
            query: Natural language search query
            top_k: Number of results to return
            severity_filter: Filter by severity (HIGH, MEDIUM, LOW, CRITICAL)
            min_cvss: Minimum CVSS score
        
        Returns:
            List of matching CVEs with metadata
        """
        # Create query embedding
        query_embedding = self.model.encode([query])
        faiss.normalize_L2(query_embedding)
        
        # Search (get more results for filtering)
        search_k = top_k * 10 if (severity_filter or min_cvss) else top_k
        distances, indices = self.index.search(query_embedding, search_k)
        
        # Collect results
        results = []
        for idx, score in zip(indices[0], distances[0]):
            if idx == -1:  # No result
                continue
            
            meta = self.metadata[idx]
            
            # Apply filters
            if severity_filter and meta.get('severity') != severity_filter:
                continue
            
            if min_cvss and (not meta.get('cvss_score') or meta['cvss_score'] < min_cvss):
                continue
            
            results.append({
                'cve_id': meta['cve_id'],
                'score': float(score),
                'severity': meta.get('severity', 'N/A'),
                'cvss_score': meta.get('cvss_score'),
                'cwe': meta.get('cwe'),
                'published_date': meta.get('published_date'),
                'description': meta['description']
            })
            
            if len(results) >= top_k:
                break
        
        return results
    
    def find_similar_to_cve(self, cve_id: str, top_k: int = 10):
        """Find CVEs similar to a specific CVE"""
        # Find the CVE in metadata
        cve_idx = None
        for i, meta in enumerate(self.metadata):
            if meta['cve_id'] == cve_id:
                cve_idx = i
                break
        
        if cve_idx is None:
            return None
        
        # Get its vector
        vector = self.index.reconstruct(cve_idx).reshape(1, -1)
        
        # Search
        distances, indices = self.index.search(vector, top_k + 1)
        
        # Collect results (skip the original CVE)
        results = []
        for idx, score in zip(indices[0], distances[0]):
            if idx == cve_idx:  # Skip original
                continue
            
            meta = self.metadata[idx]
            results.append({
                'cve_id': meta['cve_id'],
                'score': float(score),
                'severity': meta.get('severity', 'N/A'),
                'cvss_score': meta.get('cvss_score'),
                'description': meta['description']
            })
            
            if len(results) >= top_k:
                break
        
        return results
    
    def get_stats(self):
        """Get index statistics"""
        return {
            'total_vectors': self.index.ntotal,
            'dimension': self.index.d,
            'index_name': self.index_name
        }


def main():
    parser = argparse.ArgumentParser(description='Search CVE vectors using FAISS')
    
    parser.add_argument('--index-name', required=True, help='Name of the FAISS index')
    parser.add_argument('--query', required=True, help='Search query')
    parser.add_argument('--top-k', type=int, default=10, help='Number of results (default: 10)')
    parser.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 
                       help='Filter by severity')
    parser.add_argument('--min-cvss', type=float, help='Minimum CVSS score')
    parser.add_argument('--similar-to', help='Find CVEs similar to this CVE ID')
    
    args = parser.parse_args()
    
    try:
        # Initialize searcher
        searcher = FAISSCVESearch(args.index_name)
        
        # Search
        if args.similar_to:
            print(f"\nFinding CVEs similar to: {args.similar_to}")
            results = searcher.find_similar_to_cve(args.similar_to, args.top_k)
            if not results:
                print(f"CVE {args.similar_to} not found in index")
                return
        else:
            print(f"\nSearching for: '{args.query}'")
            if args.severity:
                print(f"Filter: Severity = {args.severity}")
            if args.min_cvss:
                print(f"Filter: CVSS >= {args.min_cvss}")
            
            results = searcher.search(
                args.query,
                top_k=args.top_k,
                severity_filter=args.severity,
                min_cvss=args.min_cvss
            )
        
        # Display results
        print(f"\n{'='*80}")
        print(f"Found {len(results)} results")
        print(f"{'='*80}\n")
        
        for i, result in enumerate(results, 1):
            print(f"{i}. {result['cve_id']}")
            print(f"   Similarity Score: {result['score']:.4f}")
            print(f"   Severity: {result['severity']}")
            
            if result.get('cvss_score'):
                print(f"   CVSS Score: {result['cvss_score']}")
            
            if result.get('cwe'):
                print(f"   CWE: {result['cwe']}")
            
            print(f"   Published: {result.get('published_date', 'N/A')[:10]}")
            print(f"   Description: {result['description'][:200]}...")
            print()
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nMake sure you've run the conversion first:")
        print(f"  python cve_to_faiss.py --index-name {args.index_name}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()
