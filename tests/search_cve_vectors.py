"""
Simple CVE Vector Search Example

Usage:
    python search_cve_vectors.py --api-key YOUR_API_KEY --index-name cve-vectors --query "SQL injection"
"""

import argparse
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer


def search_cves(api_key: str, index_name: str, query: str, top_k: int = 10, filter_dict: dict = None):
    """
    Search CVE vectors using semantic similarity
    
    Args:
        api_key: Pinecone API key
        index_name: Name of the Pinecone index
        query: Search query (natural language)
        top_k: Number of results to return
        filter_dict: Optional metadata filters (e.g., {'severity': 'HIGH'})
    """
    # Initialize Pinecone
    pc = Pinecone(api_key=api_key)
    index = pc.Index(index_name)
    
    # Load embedding model
    print("Loading embedding model...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Create query embedding
    print(f"Searching for: '{query}'")
    query_embedding = model.encode([query])[0].tolist()
    
    # Search with optional filters
    results = index.query(
        vector=query_embedding,
        top_k=top_k,
        include_metadata=True,
        filter=filter_dict
    )
    
    # Display results
    print(f"\n{'='*80}")
    print(f"Found {len(results['matches'])} results")
    print(f"{'='*80}\n")
    
    for i, match in enumerate(results['matches'], 1):
        metadata = match['metadata']
        
        print(f"{i}. {match['id']}")
        print(f"   Similarity Score: {match['score']:.4f}")
        print(f"   Severity: {metadata.get('severity', 'N/A')}")
        
        if 'cvss_score' in metadata:
            print(f"   CVSS Score: {metadata['cvss_score']}")
        
        if 'cwe' in metadata:
            print(f"   CWE: {metadata['cwe']}")
        
        print(f"   Published: {metadata.get('published_date', 'N/A')[:10]}")
        print(f"   Description: {metadata['description']}")
        print()


def main():
    parser = argparse.ArgumentParser(description='Search CVE vectors using semantic similarity')
    
    parser.add_argument('--api-key', required=True, help='Pinecone API key')
    parser.add_argument('--index-name', required=True, help='Name of the Pinecone index')
    parser.add_argument('--query', required=True, help='Search query')
    parser.add_argument('--top-k', type=int, default=10, help='Number of results (default: 10)')
    parser.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 
                       help='Filter by severity')
    parser.add_argument('--min-cvss', type=float, help='Minimum CVSS score')
    
    args = parser.parse_args()
    
    # Build filter dictionary
    filter_dict = {}
    if args.severity:
        filter_dict['severity'] = args.severity
    if args.min_cvss:
        filter_dict['cvss_score'] = {'$gte': args.min_cvss}
    
    # Search
    search_cves(
        api_key=args.api_key,
        index_name=args.index_name,
        query=args.query,
        top_k=args.top_k,
        filter_dict=filter_dict if filter_dict else None
    )


if __name__ == '__main__':
    main()
