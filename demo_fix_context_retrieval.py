"""
Demo: Fix Context Retrieval

Demonstrates the get_fix_context and get_fix_context_single methods
for retrieving formatted vulnerability information for LLM consumption.
"""

from enhanced_cve_search import EnhancedFAISSCVESearch


def demo_single_cve_context():
    """Demo: Get fix context for a single CVE"""
    print("=" * 80)
    print("Demo 1: Get Fix Context for Single CVE")
    print("=" * 80)
    print()
    
    # Initialize searcher
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    
    # Search for a CVE
    results = searcher.search_with_enrichment("buffer overflow", top_k=1)
    
    if results:
        cve_id = results[0]['cve_id']
        print(f"Getting fix context for: {cve_id}")
        print()
        
        # Get fix context using get_fix_context_single
        context = searcher.get_fix_context_single(cve_id)
        
        if context:
            print("Fix Context:")
            print("-" * 80)
            print(context)
            print()
        else:
            print("No context available")
    else:
        print("No search results found")
    
    print()


def demo_single_cve_string():
    """Demo: Get fix context using string parameter"""
    print("=" * 80)
    print("Demo 2: Get Fix Context with String Parameter")
    print("=" * 80)
    print()
    
    # Initialize searcher
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    
    # Search for a CVE
    results = searcher.search_with_enrichment("SQL injection", top_k=1)
    
    if results:
        cve_id = results[0]['cve_id']
        print(f"Getting fix context for: {cve_id}")
        print()
        
        # Get fix context using get_fix_context with string
        context = searcher.get_fix_context(cve_id)
        
        if context:
            print("Fix Context:")
            print("-" * 80)
            print(context)
            print()
        else:
            print("No context available")
    else:
        print("No search results found")
    
    print()


def demo_multiple_cves_context():
    """Demo: Get fix context for multiple CVEs"""
    print("=" * 80)
    print("Demo 3: Get Fix Context for Multiple CVEs")
    print("=" * 80)
    print()
    
    # Initialize searcher
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    
    # Search for CVEs
    results = searcher.search_with_enrichment("remote code execution", top_k=3)
    
    if results:
        cve_ids = [r['cve_id'] for r in results]
        print(f"Getting fix context for {len(cve_ids)} CVEs:")
        for cve_id in cve_ids:
            print(f"  - {cve_id}")
        print()
        
        # Get combined fix context
        context = searcher.get_fix_context(cve_ids)
        
        if context:
            print("Combined Fix Context:")
            print("-" * 80)
            print(context)
            print()
            
            # Show statistics
            print("Statistics:")
            print(f"  Total characters: {len(context)}")
            print(f"  Number of CVE sections: {context.count('===') // 2}")
        else:
            print("No context available")
    else:
        print("No search results found")
    
    print()


def demo_search_and_context_workflow():
    """Demo: Complete workflow - search and get fix context"""
    print("=" * 80)
    print("Demo 4: Complete Workflow - Search and Get Fix Context")
    print("=" * 80)
    print()
    
    # Initialize searcher
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    
    # Step 1: Search for vulnerabilities
    query = "authentication bypass"
    print(f"Step 1: Searching for '{query}'...")
    results = searcher.search_with_enrichment(query, top_k=2)
    
    if results:
        print(f"Found {len(results)} results:")
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result['cve_id']} (score: {result['score']:.4f})")
        print()
        
        # Step 2: Get fix context for top results
        print("Step 2: Retrieving fix context for top results...")
        cve_ids = [r['cve_id'] for r in results]
        context = searcher.get_fix_context(cve_ids)
        
        if context:
            print("Fix Context Retrieved:")
            print("-" * 80)
            print(context)
            print()
            
            # Step 3: Show how this would be used with an LLM
            print("Step 3: This context can now be passed to an LLM for:")
            print("  - Generating patches")
            print("  - Understanding vulnerability patterns")
            print("  - Creating security recommendations")
            print("  - Analyzing code for similar issues")
        else:
            print("No context available")
    else:
        print("No search results found")
    
    print()


def demo_context_with_enrichment():
    """Demo: Show difference between enriched and non-enriched CVEs"""
    print("=" * 80)
    print("Demo 5: Context with and without VUL-RAG Enrichment")
    print("=" * 80)
    print()
    
    # Initialize searcher
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    
    # Get some CVEs
    results = searcher.search_with_enrichment("vulnerability", top_k=2)
    
    if results:
        for i, result in enumerate(results, 1):
            cve_id = result['cve_id']
            has_enrichment = result.get('root_cause') or result.get('fix_strategy')
            
            print(f"CVE {i}: {cve_id}")
            print(f"Has VUL-RAG enrichment: {'Yes' if has_enrichment else 'No'}")
            print()
            
            # Get fix context
            context = searcher.get_fix_context_single(cve_id)
            
            if context:
                print("Fix Context:")
                print("-" * 80)
                print(context)
                print()
            
            if has_enrichment:
                print("✓ This CVE includes enrichment data:")
                if result.get('root_cause'):
                    print(f"  - Root Cause: {result['root_cause'][:80]}...")
                if result.get('fix_strategy'):
                    print(f"  - Fix Strategy: {result['fix_strategy'][:80]}...")
            else:
                print("⚠ This CVE uses fallback formatting (no enrichment)")
            
            print()
    else:
        print("No search results found")
    
    print()


def main():
    """Run all demos"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "Fix Context Retrieval Demo" + " " * 32 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    try:
        # Run demos
        demo_single_cve_context()
        demo_single_cve_string()
        demo_multiple_cves_context()
        demo_search_and_context_workflow()
        demo_context_with_enrichment()
        
        print("=" * 80)
        print("Demo Complete!")
        print("=" * 80)
        print()
        print("Key Features Demonstrated:")
        print("  ✓ get_fix_context_single() - Get context for one CVE")
        print("  ✓ get_fix_context(string) - Get context using string parameter")
        print("  ✓ get_fix_context(list) - Get context for multiple CVEs")
        print("  ✓ Integration with search workflow")
        print("  ✓ Handling of enriched and non-enriched CVEs")
        print()
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nMake sure you have:")
        print("  1. Created the enhanced index using create_enhanced_index.py")
        print("  2. The cves.db database with vulrag_enrichment table")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
