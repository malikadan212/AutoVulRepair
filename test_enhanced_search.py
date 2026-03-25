"""
Test script for EnhancedFAISSCVESearch functionality

This script tests the enhanced search with VUL-RAG enrichment data.
"""

import sqlite3
from enhanced_cve_search import EnhancedFAISSCVESearch


def test_search_with_enrichment():
    """Test that search_with_enrichment returns results with VUL-RAG fields"""
    print("Test 1: Search with enrichment")
    print("-" * 60)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        results = searcher.search_with_enrichment("SQL injection", top_k=5)
        
        print(f"✓ Search returned {len(results)} results")
        
        # Verify all results have VUL-RAG fields (even if None)
        for result in results:
            assert 'vulnerability_type' in result, "Missing vulnerability_type field"
            assert 'root_cause' in result, "Missing root_cause field"
            assert 'fix_strategy' in result, "Missing fix_strategy field"
            assert 'code_pattern' in result, "Missing code_pattern field"
            assert 'attack_condition' in result, "Missing attack_condition field"
            
            # Also verify standard fields are present
            assert 'cve_id' in result, "Missing cve_id field"
            assert 'score' in result, "Missing score field"
            assert 'description' in result, "Missing description field"
        
        print("✓ All results have required VUL-RAG fields")
        print("✓ All results have standard CVE fields")
        
        # Check if any results have actual enrichment data
        enriched_count = sum(1 for r in results if r['vulnerability_type'] is not None)
        print(f"✓ {enriched_count} results have VUL-RAG enrichment data")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_load_vulrag_data():
    """Test that _load_vulrag_data correctly fetches enrichment"""
    print("\nTest 2: Load VUL-RAG data")
    print("-" * 60)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Get some CVE IDs from the enrichment table
        conn = sqlite3.connect('cves.db')
        cursor = conn.cursor()
        cursor.execute("SELECT cve_id FROM vulrag_enrichment LIMIT 3")
        enriched_cve_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        print(f"Testing with CVE IDs: {enriched_cve_ids}")
        
        # Load enrichment data
        enrichment = searcher._load_vulrag_data(enriched_cve_ids)
        
        print(f"✓ Loaded enrichment for {len(enrichment)} CVEs")
        
        # Verify structure
        for cve_id, data in enrichment.items():
            assert 'vulnerability_type' in data, f"Missing vulnerability_type for {cve_id}"
            assert 'root_cause' in data, f"Missing root_cause for {cve_id}"
            assert 'fix_strategy' in data, f"Missing fix_strategy for {cve_id}"
            assert 'code_pattern' in data, f"Missing code_pattern for {cve_id}"
            assert 'attack_condition' in data, f"Missing attack_condition for {cve_id}"
            
            print(f"✓ {cve_id}: {data['vulnerability_type']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_merge_results_with_enrichment():
    """Test that _merge_results_with_enrichment correctly combines data"""
    print("\nTest 3: Merge results with enrichment")
    print("-" * 60)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Create mock results
        mock_results = [
            {
                'cve_id': 'CVE-2023-12345',
                'score': 0.95,
                'severity': 'HIGH',
                'description': 'Test CVE 1'
            },
            {
                'cve_id': 'CVE-1999-0001',
                'score': 0.85,
                'severity': 'MEDIUM',
                'description': 'Test CVE 2'
            }
        ]
        
        # Create mock enrichment (only for first CVE)
        mock_enrichment = {
            'CVE-2023-12345': {
                'vulnerability_type': 'XSS',
                'root_cause': 'Bad input validation',
                'fix_strategy': 'Sanitize inputs',
                'code_pattern': 'Unescaped output',
                'attack_condition': 'User input'
            }
        }
        
        # Merge
        merged = searcher._merge_results_with_enrichment(mock_results, mock_enrichment)
        
        print(f"✓ Merged {len(merged)} results")
        
        # Verify first result has enrichment
        assert merged[0]['vulnerability_type'] == 'XSS', "First result should have enrichment"
        assert merged[0]['root_cause'] == 'Bad input validation', "First result enrichment incorrect"
        print("✓ First result has correct enrichment data")
        
        # Verify second result has None for enrichment fields
        assert merged[1]['vulnerability_type'] is None, "Second result should have None for enrichment"
        assert merged[1]['root_cause'] is None, "Second result should have None for enrichment"
        print("✓ Second result has None for missing enrichment")
        
        # Verify standard fields are preserved
        assert merged[0]['cve_id'] == 'CVE-2023-12345', "CVE ID should be preserved"
        assert merged[0]['score'] == 0.95, "Score should be preserved"
        print("✓ Standard fields preserved correctly")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_backward_compatibility():
    """Test that standard search method still works"""
    print("\nTest 4: Backward compatibility")
    print("-" * 60)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Use the parent class search method
        results = searcher.search("buffer overflow", top_k=3)
        
        print(f"✓ Standard search returned {len(results)} results")
        
        # Verify standard fields are present
        for result in results:
            assert 'cve_id' in result, "Missing cve_id"
            assert 'score' in result, "Missing score"
            assert 'description' in result, "Missing description"
        
        print("✓ Standard search works correctly")
        
        # Verify VUL-RAG fields are NOT in standard search results
        has_vulrag_fields = any('vulnerability_type' in r for r in results)
        assert not has_vulrag_fields, "Standard search should not include VUL-RAG fields"
        print("✓ Standard search does not include VUL-RAG fields")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Enhanced CVE Search Test Suite")
    print("=" * 60)
    
    tests = [
        test_search_with_enrichment,
        test_load_vulrag_data,
        test_merge_results_with_enrichment,
        test_backward_compatibility
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed!")
        return 0
    else:
        print(f"✗ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    exit(main())
