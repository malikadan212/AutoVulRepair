"""
Demo: Index Manager Usage

Demonstrates how to use the IndexManager class to manage and query
information about FAISS indexes.
"""

from index_manager import IndexManager


def main():
    print("=" * 80)
    print("Index Manager Demo")
    print("=" * 80)
    print()
    
    # Initialize the index manager
    print("1. Initializing Index Manager...")
    manager = IndexManager(index_dir='faiss_indexes')
    print("   ✓ Index manager initialized\n")
    
    # List all available indexes
    print("2. Listing all available indexes...")
    indexes = manager.list_indexes()
    print(f"   Found {len(indexes)} indexes:\n")
    
    for idx in indexes:
        enrichment_marker = "✓" if idx['has_vulrag_enrichment'] else "✗"
        print(f"   {enrichment_marker} {idx['name']}")
        if idx['total_vectors']:
            print(f"      - Vectors: {idx['total_vectors']:,}")
        if idx['model']:
            print(f"      - Model: {idx['model']}")
        print()
    
    # Get detailed info about a specific index
    if indexes:
        print("3. Getting detailed information about first index...")
        first_index = indexes[0]['name']
        info = manager.get_index_info(first_index)
        
        print(f"   Index: {info['name']}")
        print(f"   - Total Vectors: {info['total_vectors']:,}")
        print(f"   - Dimension: {info['dimension']}")
        print(f"   - Model: {info['model']}")
        print(f"   - Has VUL-RAG Enrichment: {info['has_vulrag_enrichment']}")
        
        if info['enrichment_stats']:
            stats = info['enrichment_stats']
            print(f"   - Enrichment Coverage: {stats['enrichment_percentage']:.2f}%")
        print()
    
    # Verify which indexes have VUL-RAG enrichment
    print("4. Verifying VUL-RAG enrichment for each index...")
    for idx in indexes:
        has_enrichment = manager.verify_index_schema(idx['name'])
        status = "✓ HAS" if has_enrichment else "✗ NO"
        print(f"   {idx['name']}: {status} VUL-RAG enrichment")
    print()
    
    # Get enrichment coverage for enriched indexes
    print("5. Getting enrichment coverage statistics...")
    for idx in indexes:
        if idx['has_vulrag_enrichment']:
            coverage = manager.get_enrichment_coverage(idx['name'])
            if coverage:
                print(f"   {idx['name']}:")
                print(f"      - Total CVEs: {coverage['total_cves']:,}")
                print(f"      - Enriched CVEs: {coverage['enriched_cves']:,}")
                print(f"      - Coverage: {coverage['enrichment_percentage']:.2f}%")
    print()
    
    # Print formatted summary
    print("6. Printing formatted summary...")
    print()
    manager.print_index_summary()
    
    print("=" * 80)
    print("Demo Complete!")
    print("=" * 80)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
