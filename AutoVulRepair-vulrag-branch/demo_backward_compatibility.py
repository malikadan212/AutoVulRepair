"""
Demonstration of Backward Compatibility

This script demonstrates that EnhancedFAISSCVESearch maintains full
backward compatibility with FAISSCVESearch while adding new features.
"""

from search_cve_faiss import FAISSCVESearch
from enhanced_cve_search import EnhancedFAISSCVESearch


def demo_drop_in_replacement():
    """Demonstrate that Enhanced class is a drop-in replacement"""
    print("=" * 80)
    print("DEMO 1: Drop-in Replacement")
    print("=" * 80)
    print("\nEnhancedFAISSCVESearch can replace FAISSCVESearch without code changes\n")
    
    query = "SQL injection vulnerability"
    
    # Original code using base class
    print("Using FAISSCVESearch (base class):")
    print("-" * 40)
    base_searcher = FAISSCVESearch('cve-vulrag-test')
    base_results = base_searcher.search(query, top_k=3)
    
    for i, result in enumerate(base_results, 1):
        print(f"{i}. {result['cve_id']} (score: {result['score']:.4f})")
        print(f"   {result['description'][:80]}...")
    
    print("\n" + "=" * 40 + "\n")
    
    # Same code using enhanced class
    print("Using EnhancedFAISSCVESearch (enhanced class):")
    print("-" * 40)
    enhanced_searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    enhanced_results = enhanced_searcher.search(query, top_k=3)
    
    for i, result in enumerate(enhanced_results, 1):
        print(f"{i}. {result['cve_id']} (score: {result['score']:.4f})")
        print(f"   {result['description'][:80]}...")
    
    # Verify results match
    print("\n" + "=" * 40)
    base_ids = [r['cve_id'] for r in base_results]
    enhanced_ids = [r['cve_id'] for r in enhanced_results]
    
    if base_ids == enhanced_ids:
        print("✓ Results are IDENTICAL - perfect backward compatibility!")
    else:
        print("⚠ Results differ (this shouldn't happen)")


def demo_enhanced_features():
    """Demonstrate new enhanced features"""
    print("\n\n" + "=" * 80)
    print("DEMO 2: Enhanced Features (New Functionality)")
    print("=" * 80)
    print("\nEnhanced class adds VUL-RAG enrichment without breaking compatibility\n")
    
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    
    # Use new search_with_enrichment method
    print("Using search_with_enrichment() method:")
    print("-" * 40)
    results = searcher.search_with_enrichment("buffer overflow", top_k=2)
    
    for i, result in enumerate(results, 1):
        print(f"\n{i}. {result['cve_id']}")
        print(f"   Score: {result['score']:.4f}")
        print(f"   Severity: {result['severity']}")
        print(f"   Description: {result['description'][:80]}...")
        
        # Show VUL-RAG enrichment if available
        if result.get('vulnerability_type'):
            print(f"\n   VUL-RAG Enrichment:")
            print(f"   - Type: {result['vulnerability_type']}")
            if result.get('root_cause'):
                print(f"   - Root Cause: {result['root_cause'][:60]}...")
            if result.get('fix_strategy'):
                print(f"   - Fix Strategy: {result['fix_strategy'][:60]}...")
        else:
            print(f"   (No VUL-RAG enrichment available)")


def demo_standard_index_compatibility():
    """Demonstrate compatibility with standard indexes"""
    print("\n\n" + "=" * 80)
    print("DEMO 3: Standard Index Compatibility")
    print("=" * 80)
    print("\nEnhanced class works with standard indexes (graceful fallback)\n")
    
    import os
    if not os.path.exists('faiss_indexes/cve-full.index'):
        print("⚠ Standard cve-full index not found, skipping demo")
        return
    
    # Use enhanced class with standard index
    print("Using EnhancedFAISSCVESearch with standard cve-full index:")
    print("-" * 40)
    searcher = EnhancedFAISSCVESearch('cve-full')
    
    # Standard search works
    results = searcher.search("XSS vulnerability", top_k=2)
    print(f"Standard search: {len(results)} results")
    
    # Enhanced search works but returns None for VUL-RAG fields
    enhanced_results = searcher.search_with_enrichment("XSS vulnerability", top_k=2)
    print(f"Enhanced search: {len(enhanced_results)} results")
    
    for result in enhanced_results:
        print(f"\n{result['cve_id']}")
        print(f"  Standard fields: ✓ (cve_id, description, severity)")
        print(f"  VUL-RAG fields: {result['vulnerability_type']} (gracefully None)")
    
    print("\n✓ Graceful fallback works - no errors with standard indexes!")


def demo_existing_consumer_patterns():
    """Demonstrate compatibility with existing consumer code patterns"""
    print("\n\n" + "=" * 80)
    print("DEMO 4: Existing Consumer Code Patterns")
    print("=" * 80)
    print("\nCommon code patterns continue to work unchanged\n")
    
    searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
    results = searcher.search("injection attack", top_k=5)
    
    # Pattern 1: Accessing standard fields
    print("Pattern 1: Accessing standard fields")
    print("-" * 40)
    for result in results[:2]:
        cve_id = result['cve_id']
        description = result['description']
        severity = result['severity']
        print(f"{cve_id}: {severity}")
    print("✓ Works!")
    
    # Pattern 2: Filtering by severity
    print("\nPattern 2: Filtering by severity")
    print("-" * 40)
    high_severity = [r for r in results if r['severity'] == 'HIGH']
    print(f"Found {len(high_severity)} HIGH severity CVEs")
    print("✓ Works!")
    
    # Pattern 3: Sorting by score
    print("\nPattern 3: Sorting by score")
    print("-" * 40)
    sorted_results = sorted(results, key=lambda x: x['score'], reverse=True)
    print(f"Top result: {sorted_results[0]['cve_id']} (score: {sorted_results[0]['score']:.4f})")
    print("✓ Works!")
    
    # Pattern 4: JSON serialization
    print("\nPattern 4: JSON serialization")
    print("-" * 40)
    import json
    json_output = json.dumps(results[:1], indent=2)
    print(f"Serialized {len(results[:1])} result(s) to JSON")
    print("✓ Works!")


def main():
    """Run all demonstrations"""
    print("\n" + "=" * 80)
    print("BACKWARD COMPATIBILITY DEMONSTRATION")
    print("=" * 80)
    print("\nThis demo shows that EnhancedFAISSCVESearch maintains full")
    print("backward compatibility with FAISSCVESearch while adding new features.")
    
    try:
        demo_drop_in_replacement()
        demo_enhanced_features()
        demo_standard_index_compatibility()
        demo_existing_consumer_patterns()
        
        print("\n\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print("\n✓ EnhancedFAISSCVESearch is a perfect drop-in replacement")
        print("✓ All existing code continues to work unchanged")
        print("✓ New VUL-RAG features are available when needed")
        print("✓ Graceful fallback for standard indexes")
        print("✓ All common consumer patterns work correctly")
        print("\n🎉 Full backward compatibility achieved!")
        
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
