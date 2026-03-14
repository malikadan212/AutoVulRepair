"""
Demonstration of Enhanced CVE Search with VUL-RAG Enrichment

This script demonstrates the enhanced search functionality with real examples.
"""

from enhanced_cve_search import EnhancedFAISSCVESearch
import json


def demo_enriched_search():
    """Demonstrate search with enrichment data"""
    print("=" * 80)
    print("Enhanced CVE Search Demonstration")
    print("=" * 80)
    
    # Initialize searcher
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    
    # Example 1: Search for SQL injection
    print("\n1. Searching for 'SQL injection vulnerabilities'")
    print("-" * 80)
    results = searcher.search_with_enrichment("SQL injection", top_k=3)
    
    for i, result in enumerate(results, 1):
        print(f"\n{i}. {result['cve_id']} (Score: {result['score']:.4f})")
        print(f"   Severity: {result['severity']}")
        print(f"   Description: {result['description'][:100]}...")
        
        if result.get('vulnerability_type'):
            print(f"\n   📋 VUL-RAG Enrichment:")
            print(f"   Type: {result['vulnerability_type']}")
            if result.get('root_cause'):
                print(f"   Root Cause: {result['root_cause'][:80]}...")
            if result.get('fix_strategy'):
                print(f"   Fix Strategy: {result['fix_strategy'][:80]}...")
        else:
            print(f"   ℹ️  No VUL-RAG enrichment available")
    
    # Example 2: Compare standard vs enhanced search
    print("\n\n2. Comparing Standard vs Enhanced Search")
    print("-" * 80)
    
    query = "buffer overflow"
    print(f"Query: '{query}'")
    
    print("\nStandard Search (no enrichment):")
    standard_results = searcher.search(query, top_k=2)
    for result in standard_results:
        print(f"  - {result['cve_id']}: {len(result)} fields")
        print(f"    Fields: {list(result.keys())}")
    
    print("\nEnhanced Search (with enrichment):")
    enhanced_results = searcher.search_with_enrichment(query, top_k=2)
    for result in enhanced_results:
        print(f"  - {result['cve_id']}: {len(result)} fields")
        print(f"    Fields: {list(result.keys())}")
        enriched = "✓" if result.get('vulnerability_type') else "✗"
        print(f"    Has enrichment: {enriched}")
    
    # Example 3: Show JSON output
    print("\n\n3. JSON Output Format")
    print("-" * 80)
    results = searcher.search_with_enrichment("cross-site scripting", top_k=1)
    if results:
        print(json.dumps(results[0], indent=2, default=str))
    
    print("\n" + "=" * 80)
    print("Demonstration Complete")
    print("=" * 80)


if __name__ == '__main__':
    demo_enriched_search()
