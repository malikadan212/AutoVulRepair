"""
Example: How to Use Your CVE Vector Database

This shows practical examples of searching and analyzing CVEs
using semantic similarity.
"""

from pinecone import Pinecone
from sentence_transformers import SentenceTransformer
import json


class CVEVectorSearch:
    """Simple wrapper for CVE vector search"""
    
    def __init__(self, api_key: str, index_name: str):
        self.pc = Pinecone(api_key=api_key)
        self.index = self.pc.Index(index_name)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
    
    def search(self, query: str, top_k: int = 10, filters: dict = None):
        """
        Search CVEs by semantic similarity
        
        Args:
            query: Natural language search query
            top_k: Number of results to return
            filters: Optional metadata filters
        
        Returns:
            List of matching CVEs with metadata
        """
        # Create embedding
        embedding = self.model.encode([query])[0].tolist()
        
        # Search
        results = self.index.query(
            vector=embedding,
            top_k=top_k,
            include_metadata=True,
            filter=filters
        )
        
        return results['matches']
    
    def find_similar_to_cve(self, cve_id: str, top_k: int = 10):
        """Find CVEs similar to a specific CVE"""
        # Fetch the CVE
        result = self.index.fetch(ids=[cve_id])
        
        if cve_id not in result['vectors']:
            return None
        
        # Get its vector
        vector = result['vectors'][cve_id]['values']
        
        # Find similar
        results = self.index.query(
            vector=vector,
            top_k=top_k + 1,  # +1 because it will include itself
            include_metadata=True
        )
        
        # Remove the original CVE from results
        matches = [m for m in results['matches'] if m['id'] != cve_id]
        return matches[:top_k]
    
    def get_stats(self):
        """Get index statistics"""
        return self.index.describe_index_stats()


def example_1_basic_search(searcher):
    """Example 1: Basic semantic search"""
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Semantic Search")
    print("="*80)
    
    query = "SQL injection vulnerabilities in web applications"
    print(f"\nQuery: '{query}'")
    print("\nTop 5 Results:")
    print("-" * 80)
    
    results = searcher.search(query, top_k=5)
    
    for i, match in enumerate(results, 1):
        print(f"\n{i}. {match['id']}")
        print(f"   Similarity: {match['score']:.4f}")
        print(f"   Severity: {match['metadata'].get('severity', 'N/A')}")
        if 'cvss_score' in match['metadata']:
            print(f"   CVSS: {match['metadata']['cvss_score']}")
        print(f"   Description: {match['metadata']['description'][:150]}...")


def example_2_filtered_search(searcher):
    """Example 2: Search with filters"""
    print("\n" + "="*80)
    print("EXAMPLE 2: Filtered Search (High Severity Only)")
    print("="*80)
    
    query = "buffer overflow"
    filters = {'severity': 'HIGH'}
    
    print(f"\nQuery: '{query}'")
    print(f"Filter: Severity = HIGH")
    print("\nTop 5 Results:")
    print("-" * 80)
    
    results = searcher.search(query, top_k=5, filters=filters)
    
    for i, match in enumerate(results, 1):
        print(f"\n{i}. {match['id']}")
        print(f"   Similarity: {match['score']:.4f}")
        print(f"   Severity: {match['metadata']['severity']}")
        print(f"   Description: {match['metadata']['description'][:150]}...")


def example_3_find_similar(searcher):
    """Example 3: Find similar CVEs to a specific CVE"""
    print("\n" + "="*80)
    print("EXAMPLE 3: Find Similar CVEs")
    print("="*80)
    
    # Use a well-known CVE (you can change this)
    cve_id = "CVE-1999-0095"  # From your database
    
    print(f"\nFinding CVEs similar to: {cve_id}")
    print("\nTop 5 Similar CVEs:")
    print("-" * 80)
    
    results = searcher.find_similar_to_cve(cve_id, top_k=5)
    
    if results:
        for i, match in enumerate(results, 1):
            print(f"\n{i}. {match['id']}")
            print(f"   Similarity: {match['score']:.4f}")
            print(f"   Severity: {match['metadata'].get('severity', 'N/A')}")
            print(f"   Description: {match['metadata']['description'][:150]}...")
    else:
        print(f"CVE {cve_id} not found in index")


def example_4_natural_language(searcher):
    """Example 4: Natural language queries"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Natural Language Queries")
    print("="*80)
    
    queries = [
        "vulnerabilities that allow remote attackers to execute arbitrary code",
        "security flaws in authentication mechanisms",
        "memory corruption issues in C programs"
    ]
    
    for query in queries:
        print(f"\nQuery: '{query}'")
        print("Top 3 Results:")
        print("-" * 40)
        
        results = searcher.search(query, top_k=3)
        
        for i, match in enumerate(results, 1):
            print(f"  {i}. {match['id']} (Score: {match['score']:.4f})")
            print(f"     {match['metadata']['description'][:100]}...")
        print()


def example_5_statistics(searcher):
    """Example 5: Get index statistics"""
    print("\n" + "="*80)
    print("EXAMPLE 5: Index Statistics")
    print("="*80)
    
    stats = searcher.get_stats()
    
    print(f"\nTotal CVEs in index: {stats['total_vector_count']:,}")
    print(f"Vector dimension: {stats['dimension']}")
    
    if 'namespaces' in stats and stats['namespaces']:
        print("\nNamespaces:")
        for ns_name, ns_stats in stats['namespaces'].items():
            print(f"  {ns_name}: {ns_stats['vector_count']:,} vectors")


def main():
    """Run all examples"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python example_usage.py YOUR_API_KEY YOUR_INDEX_NAME")
        print("\nExample:")
        print("  python example_usage.py pcsk_xxxxx cve-demo")
        sys.exit(1)
    
    api_key = sys.argv[1]
    index_name = sys.argv[2]
    
    print("="*80)
    print("CVE Vector Database - Usage Examples")
    print("="*80)
    print(f"\nConnecting to index: {index_name}")
    print("Loading model...")
    
    # Initialize searcher
    searcher = CVEVectorSearch(api_key, index_name)
    
    print("✓ Ready!\n")
    
    # Run examples
    try:
        example_1_basic_search(searcher)
        example_2_filtered_search(searcher)
        example_3_find_similar(searcher)
        example_4_natural_language(searcher)
        example_5_statistics(searcher)
        
        print("\n" + "="*80)
        print("All examples completed!")
        print("="*80)
        print("\nYou can now:")
        print("  1. Modify these examples for your use case")
        print("  2. Integrate into your security tools")
        print("  3. Build a CVE search API")
        print("  4. Create a vulnerability recommendation system")
        
    except Exception as e:
        print(f"\nError: {e}")
        print("\nMake sure:")
        print("  1. Your API key is correct")
        print("  2. The index exists and has data")
        print("  3. You've run the conversion script first")


if __name__ == '__main__':
    main()
