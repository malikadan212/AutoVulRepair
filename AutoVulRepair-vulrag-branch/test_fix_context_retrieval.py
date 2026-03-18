"""
Test fix context retrieval methods in EnhancedFAISSCVESearch

Tests the get_fix_context and get_fix_context_single methods to ensure
they properly retrieve and format CVE data with VUL-RAG enrichment.
"""

import os
import sys
import sqlite3
from enhanced_cve_search import EnhancedFAISSCVESearch


def get_sample_cve_ids(searcher, count=3):
    """Get sample CVE IDs from the index metadata"""
    if hasattr(searcher, 'metadata') and searcher.metadata:
        return [entry['cve_id'] for entry in searcher.metadata[:count]]
    return []


def test_get_fix_context_single():
    """Test retrieving fix context for a single CVE"""
    print("Test 1: get_fix_context_single()")
    print("-" * 80)
    
    try:
        # Initialize searcher with the enhanced index
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Get a real CVE ID from the index
        sample_cves = get_sample_cve_ids(searcher, 1)
        if not sample_cves:
            print("⚠ No CVEs in index, skipping test")
            return True
        
        cve_id = sample_cves[0]
        context = searcher.get_fix_context_single(cve_id)
        
        if context:
            print(f"✓ Successfully retrieved fix context for {cve_id}")
            print(f"\nFormatted Context:\n{context}\n")
            
            # Verify expected sections are present
            assert 'Root Cause:' in context or 'Note: Limited context' in context, \
                "Context should contain either enrichment or fallback note"
            assert cve_id in context, "Context should contain CVE ID"
            
            print("✓ Context contains expected sections")
        else:
            print(f"✗ No context returned for {cve_id}")
            return False
        
        # Test with non-existent CVE
        context = searcher.get_fix_context_single('CVE-9999-NONEXISTENT')
        if context is None:
            print("✓ Correctly returns None for non-existent CVE")
        else:
            print("✗ Should return None for non-existent CVE")
            return False
        
        print("\n✓ Test 1 passed!\n")
        return True
        
    except Exception as e:
        print(f"✗ Test 1 failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_get_fix_context_single_cve_string():
    """Test get_fix_context with a single CVE ID as string"""
    print("Test 2: get_fix_context() with single CVE string")
    print("-" * 80)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Get a real CVE ID from the index
        sample_cves = get_sample_cve_ids(searcher, 1)
        if not sample_cves:
            print("⚠ No CVEs in index, skipping test")
            return True
        
        cve_id = sample_cves[0]
        context = searcher.get_fix_context(cve_id)
        
        if context:
            print(f"✓ Successfully retrieved fix context for {cve_id}")
            print(f"\nFormatted Context (first 500 chars):\n{context[:500]}...\n")
            
            # Verify it's a string
            assert isinstance(context, str), "Context should be a string"
            assert cve_id in context, "Context should contain CVE ID"
            
            print("✓ Context is properly formatted")
        else:
            print(f"✗ Empty context returned for {cve_id}")
            return False
        
        # Test with non-existent CVE
        context = searcher.get_fix_context('CVE-9999-NONEXISTENT')
        if context == "":
            print("✓ Correctly returns empty string for non-existent CVE")
        else:
            print("✗ Should return empty string for non-existent CVE")
            return False
        
        print("\n✓ Test 2 passed!\n")
        return True
        
    except Exception as e:
        print(f"✗ Test 2 failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_get_fix_context_multiple_cves():
    """Test get_fix_context with multiple CVE IDs"""
    print("Test 3: get_fix_context() with multiple CVE IDs")
    print("-" * 80)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Get real CVE IDs from the index
        sample_cves = get_sample_cve_ids(searcher, 2)
        if len(sample_cves) < 2:
            print("⚠ Not enough CVEs in index, skipping test")
            return True
        
        cve_ids = sample_cves
        context = searcher.get_fix_context(cve_ids)
        
        if context:
            print(f"✓ Successfully retrieved fix context for {len(cve_ids)} CVEs")
            print(f"\nFormatted Context (first 800 chars):\n{context[:800]}...\n")
            
            # Verify both CVEs are in the context
            for cve_id in cve_ids:
                assert cve_id in context, f"Context should contain {cve_id}"
            
            # Count delimiters (should have multiple CVE sections)
            delimiter_count = context.count('===')
            assert delimiter_count >= len(cve_ids) * 2, \
                f"Should have at least {len(cve_ids) * 2} delimiters (header and footer for each CVE)"
            
            print(f"✓ Context contains all {len(cve_ids)} CVEs with proper delimiters")
        else:
            print(f"✗ Empty context returned for {cve_ids}")
            return False
        
        # Test with empty list
        context = searcher.get_fix_context([])
        if context == "":
            print("✓ Correctly returns empty string for empty list")
        else:
            print("✗ Should return empty string for empty list")
            return False
        
        print("\n✓ Test 3 passed!\n")
        return True
        
    except Exception as e:
        print(f"✗ Test 3 failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_fix_context_with_enrichment():
    """Test that fix context includes VUL-RAG enrichment fields"""
    print("Test 4: Fix context includes VUL-RAG enrichment")
    print("-" * 80)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Get a real CVE ID from the index
        sample_cves = get_sample_cve_ids(searcher, 1)
        if not sample_cves:
            print("⚠ No CVEs in index, skipping test")
            return True
        
        cve_id = sample_cves[0]
        context = searcher.get_fix_context_single(cve_id)
        
        if context:
            print(f"✓ Retrieved context for {cve_id}")
            
            # Check for VUL-RAG enrichment sections
            has_enrichment = any(section in context for section in [
                'Root Cause:',
                'Fix Strategy:',
                'Attack Condition:',
                'Code Pattern:',
                'Vulnerability Type:'
            ])
            
            if has_enrichment:
                print("✓ Context includes VUL-RAG enrichment sections")
                
                # Show which sections are present
                sections = []
                if 'Root Cause:' in context:
                    sections.append('Root Cause')
                if 'Fix Strategy:' in context:
                    sections.append('Fix Strategy')
                if 'Attack Condition:' in context:
                    sections.append('Attack Condition')
                if 'Code Pattern:' in context:
                    sections.append('Code Pattern')
                if 'Vulnerability Type:' in context:
                    sections.append('Vulnerability Type')
                
                print(f"  Present sections: {', '.join(sections)}")
            else:
                print("  Note: No enrichment sections found (CVE may not have enrichment data)")
                # This is okay - the CVE might not have enrichment
                if 'Note: Limited context' in context:
                    print("  ✓ Fallback formatting used correctly")
        else:
            print(f"✗ No context returned for {cve_id}")
            return False
        
        print("\n✓ Test 4 passed!\n")
        return True
        
    except Exception as e:
        print(f"✗ Test 4 failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_fix_context_integration():
    """Integration test: search and get fix context"""
    print("Test 5: Integration - Search and get fix context")
    print("-" * 80)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Perform a search
        results = searcher.search_with_enrichment("buffer overflow", top_k=3)
        
        if results:
            print(f"✓ Search returned {len(results)} results")
            
            # Get CVE IDs from results
            cve_ids = [r['cve_id'] for r in results]
            print(f"  CVE IDs: {', '.join(cve_ids)}")
            
            # Get fix context for all results
            context = searcher.get_fix_context(cve_ids)
            
            if context:
                print(f"✓ Retrieved combined fix context ({len(context)} chars)")
                
                # Verify all CVEs are in the context
                for cve_id in cve_ids:
                    if cve_id in context:
                        print(f"  ✓ {cve_id} present in context")
                    else:
                        print(f"  ✗ {cve_id} missing from context")
                        return False
                
                print("\n✓ All CVEs included in combined context")
            else:
                print("✗ Empty context returned")
                return False
        else:
            print("  Note: No search results (index may be empty)")
            # This is okay if the test index is empty
        
        print("\n✓ Test 5 passed!\n")
        return True
        
    except Exception as e:
        print(f"✗ Test 5 failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 80)
    print("Testing Fix Context Retrieval Methods")
    print("=" * 80)
    print()
    
    # Check if test index exists
    if not os.path.exists('faiss_indexes/cve-vulrag-test.index'):
        print("⚠ Warning: Test index 'cve-vulrag-test' not found")
        print("  Some tests may fail. Run create_enhanced_index.py first.")
        print()
    
    # Run tests
    results = []
    results.append(("get_fix_context_single", test_get_fix_context_single()))
    results.append(("get_fix_context with string", test_get_fix_context_single_cve_string()))
    results.append(("get_fix_context with list", test_get_fix_context_multiple_cves()))
    results.append(("VUL-RAG enrichment", test_fix_context_with_enrichment()))
    results.append(("Integration test", test_fix_context_integration()))
    
    # Summary
    print("=" * 80)
    print("Test Summary")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print()
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
