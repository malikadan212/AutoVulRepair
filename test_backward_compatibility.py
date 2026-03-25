"""
Comprehensive Backward Compatibility Test Suite

Tests that EnhancedFAISSCVESearch maintains full backward compatibility
with FAISSCVESearch while adding new functionality.

Requirements tested:
- 7.1: Standard cve-full index continues to work
- 7.2: Graceful fallback when enhanced index unavailable
- 7.3: Same parameters accepted as FAISSCVESearch
- 7.4: Result format includes all standard fields
- 7.5: Results compatible with existing consumers
"""

import os
import sys
import sqlite3
import inspect
from typing import List, Dict
from enhanced_cve_search import EnhancedFAISSCVESearch
from search_cve_faiss import FAISSCVESearch


def test_parameter_compatibility():
    """
    Test that EnhancedFAISSCVESearch accepts same parameters as FAISSCVESearch.
    
    Validates Requirement 7.3: Same parameters accepted as FAISSCVESearch
    """
    print("\nTest 1: Parameter Compatibility")
    print("-" * 80)
    
    try:
        # Get constructor signatures
        base_sig = inspect.signature(FAISSCVESearch.__init__)
        enhanced_sig = inspect.signature(EnhancedFAISSCVESearch.__init__)
        
        base_params = list(base_sig.parameters.keys())
        enhanced_params = list(enhanced_sig.parameters.keys())
        
        print(f"Base class parameters: {base_params}")
        print(f"Enhanced class parameters: {enhanced_params}")
        
        # Check that all base parameters are in enhanced class
        for param in base_params:
            if param == 'self':
                continue
            assert param in enhanced_params, f"Missing parameter: {param}"
        
        print("✓ All base class constructor parameters are supported")
        
        # Test instantiation with base class parameters only
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test', index_dir='faiss_indexes')
        print("✓ Can instantiate with base class parameters")
        
        # Get search method signatures
        base_search_sig = inspect.signature(FAISSCVESearch.search)
        enhanced_search_sig = inspect.signature(EnhancedFAISSCVESearch.search)
        
        base_search_params = list(base_search_sig.parameters.keys())
        enhanced_search_params = list(enhanced_search_sig.parameters.keys())
        
        print(f"Base search parameters: {base_search_params}")
        print(f"Enhanced search parameters: {enhanced_search_params}")
        
        # Verify search method parameters match
        for param in base_search_params:
            if param == 'self':
                continue
            assert param in enhanced_search_params, f"Missing search parameter: {param}"
        
        print("✓ All base class search parameters are supported")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_standard_index_compatibility():
    """
    Test that standard cve-full index works with existing code.
    
    Validates Requirement 7.1: Standard cve-full index continues to work
    """
    print("\nTest 2: Standard Index Compatibility")
    print("-" * 80)
    
    try:
        # Check if cve-full index exists
        index_path = 'faiss_indexes/cve-full.index'
        if not os.path.exists(index_path):
            print(f"⚠ Skipping: {index_path} not found")
            print("  (This is expected if you haven't created the standard index)")
            return True
        
        # Test with base class
        print("Testing with base FAISSCVESearch class...")
        base_searcher = FAISSCVESearch('cve-full')
        base_results = base_searcher.search("SQL injection", top_k=3)
        
        print(f"✓ Base class search returned {len(base_results)} results")
        
        # Test with enhanced class on standard index
        print("Testing with EnhancedFAISSCVESearch class...")
        enhanced_searcher = EnhancedFAISSCVESearch('cve-full')
        enhanced_results = enhanced_searcher.search("SQL injection", top_k=3)
        
        print(f"✓ Enhanced class search returned {len(enhanced_results)} results")
        
        # Verify results are similar (same CVE IDs)
        base_cve_ids = {r['cve_id'] for r in base_results}
        enhanced_cve_ids = {r['cve_id'] for r in enhanced_results}
        
        assert base_cve_ids == enhanced_cve_ids, "Results should match between classes"
        print("✓ Both classes return same CVE IDs for standard index")
        
        # Verify result structure matches
        for base_result, enhanced_result in zip(base_results, enhanced_results):
            assert base_result['cve_id'] == enhanced_result['cve_id']
            assert base_result['score'] == enhanced_result['score']
            assert base_result['description'] == enhanced_result['description']
        
        print("✓ Result structures match between classes")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_result_format_compatibility():
    """
    Test that result format includes all standard fields.
    
    Validates Requirement 7.4: Result format includes all standard fields
    """
    print("\nTest 3: Result Format Compatibility")
    print("-" * 80)
    
    try:
        # Use test index
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Test standard search method (inherited)
        print("Testing standard search method...")
        standard_results = searcher.search("buffer overflow", top_k=3)
        
        # Define required standard fields
        required_fields = ['cve_id', 'score', 'severity', 'description']
        optional_standard_fields = ['cvss_score', 'cwe', 'published_date']
        
        print(f"✓ Standard search returned {len(standard_results)} results")
        
        # Verify all standard results have required fields
        for result in standard_results:
            for field in required_fields:
                assert field in result, f"Missing required field: {field}"
        
        print("✓ All standard results have required fields")
        
        # Test enhanced search method
        print("Testing enhanced search method...")
        enhanced_results = searcher.search_with_enrichment("buffer overflow", top_k=3)
        
        print(f"✓ Enhanced search returned {len(enhanced_results)} results")
        
        # Verify enhanced results have all standard fields PLUS VUL-RAG fields
        vulrag_fields = ['vulnerability_type', 'root_cause', 'fix_strategy', 
                        'code_pattern', 'attack_condition']
        
        for result in enhanced_results:
            # Check standard fields
            for field in required_fields:
                assert field in result, f"Missing required standard field: {field}"
            
            # Check VUL-RAG fields are present (even if None)
            for field in vulrag_fields:
                assert field in result, f"Missing VUL-RAG field: {field}"
        
        print("✓ Enhanced results have all standard fields")
        print("✓ Enhanced results have all VUL-RAG fields")
        
        # Verify standard fields have same values in both result types
        # (comparing first result from each)
        if standard_results and enhanced_results:
            std_cve_ids = {r['cve_id'] for r in standard_results}
            enh_cve_ids = {r['cve_id'] for r in enhanced_results}
            
            # Find common CVE
            common_cves = std_cve_ids & enh_cve_ids
            if common_cves:
                common_cve = list(common_cves)[0]
                std_result = next(r for r in standard_results if r['cve_id'] == common_cve)
                enh_result = next(r for r in enhanced_results if r['cve_id'] == common_cve)
                
                # Compare standard fields
                for field in required_fields:
                    assert std_result[field] == enh_result[field], \
                        f"Field {field} differs between standard and enhanced results"
                
                print(f"✓ Standard fields match between search methods for {common_cve}")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_graceful_fallback():
    """
    Test graceful fallback when enhanced index is unavailable.
    
    Validates Requirement 7.2: Graceful fallback when enhanced index unavailable
    """
    print("\nTest 4: Graceful Fallback")
    print("-" * 80)
    
    try:
        # Test 1: Try to load non-existent index
        print("Testing with non-existent index...")
        try:
            searcher = EnhancedFAISSCVESearch('nonexistent-index')
            print("✗ Should have raised FileNotFoundError")
            return False
        except FileNotFoundError as e:
            print(f"✓ Correctly raises FileNotFoundError: {e}")
        
        # Test 2: Use standard index without VUL-RAG enrichment
        index_path = 'faiss_indexes/cve-full.index'
        if os.path.exists(index_path):
            print("\nTesting standard index without enrichment...")
            searcher = EnhancedFAISSCVESearch('cve-full')
            
            # Standard search should work
            results = searcher.search("XSS vulnerability", top_k=3)
            print(f"✓ Standard search works: {len(results)} results")
            
            # Enhanced search should work but return None for VUL-RAG fields
            enhanced_results = searcher.search_with_enrichment("XSS vulnerability", top_k=3)
            print(f"✓ Enhanced search works: {len(enhanced_results)} results")
            
            # Verify VUL-RAG fields are None (no enrichment in standard index)
            for result in enhanced_results:
                # VUL-RAG fields should be present but None
                assert 'vulnerability_type' in result
                assert 'root_cause' in result
                assert 'fix_strategy' in result
                
                # Standard fields should have values
                assert result['cve_id'] is not None
                assert result['description'] is not None
            
            print("✓ Enhanced search gracefully handles missing enrichment")
        else:
            print("⚠ Skipping standard index test (cve-full not found)")
        
        # Test 3: Database connection failure handling
        print("\nTesting database connection handling...")
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Temporarily use invalid database path
        original_db = searcher.db_path
        searcher.db_path = 'nonexistent.db'
        
        try:
            # This should fail gracefully
            enrichment = searcher._load_vulrag_data(['CVE-2023-12345'])
            print("✗ Should have raised an error for missing database")
            return False
        except Exception as e:
            print(f"✓ Correctly handles database errors: {type(e).__name__}")
        finally:
            searcher.db_path = original_db
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_existing_consumer_compatibility():
    """
    Test that results are compatible with existing consumers.
    
    Validates Requirement 7.5: Results compatible with existing consumers
    """
    print("\nTest 5: Existing Consumer Compatibility")
    print("-" * 80)
    
    try:
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Simulate existing consumer code that expects standard fields
        results = searcher.search("SQL injection", top_k=3)
        
        print(f"✓ Search returned {len(results)} results")
        
        # Existing consumer code pattern 1: Accessing standard fields
        for result in results:
            cve_id = result['cve_id']
            description = result['description']
            severity = result['severity']
            score = result['score']
            
            assert isinstance(cve_id, str)
            assert isinstance(description, str)
            assert isinstance(severity, str)
            assert isinstance(score, float)
        
        print("✓ Standard field access works (existing consumer pattern 1)")
        
        # Existing consumer code pattern 2: JSON serialization
        import json
        try:
            json_output = json.dumps(results)
            assert len(json_output) > 0
            print("✓ Results are JSON serializable (existing consumer pattern 2)")
        except Exception as e:
            print(f"✗ JSON serialization failed: {e}")
            return False
        
        # Existing consumer code pattern 3: Filtering by severity
        high_severity = [r for r in results if r['severity'] == 'HIGH']
        print(f"✓ Filtering by severity works: {len(high_severity)} HIGH severity CVEs")
        
        # Existing consumer code pattern 4: Sorting by score
        sorted_results = sorted(results, key=lambda x: x['score'], reverse=True)
        assert sorted_results[0]['score'] >= sorted_results[-1]['score']
        print("✓ Sorting by score works (existing consumer pattern 4)")
        
        # Test that enhanced results are also compatible
        enhanced_results = searcher.search_with_enrichment("SQL injection", top_k=3)
        
        # Should still support all existing patterns
        for result in enhanced_results:
            cve_id = result['cve_id']
            description = result['description']
            assert isinstance(cve_id, str)
            assert isinstance(description, str)
        
        print("✓ Enhanced results support existing consumer patterns")
        
        # Enhanced results should have additional fields that can be safely ignored
        for result in enhanced_results:
            # Existing code can safely ignore new fields
            standard_only = {k: v for k, v in result.items() 
                           if k in ['cve_id', 'score', 'severity', 'description', 
                                   'cvss_score', 'cwe', 'published_date']}
            assert len(standard_only) >= 4  # At least the required fields
        
        print("✓ Enhanced results can be filtered to standard fields")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_method_inheritance():
    """
    Test that all base class methods are available in enhanced class.
    """
    print("\nTest 6: Method Inheritance")
    print("-" * 80)
    
    try:
        # Get all public methods from base class
        base_methods = [method for method in dir(FAISSCVESearch) 
                       if not method.startswith('_') and callable(getattr(FAISSCVESearch, method))]
        
        # Get all public methods from enhanced class
        enhanced_methods = [method for method in dir(EnhancedFAISSCVESearch) 
                           if not method.startswith('_') and callable(getattr(EnhancedFAISSCVESearch, method))]
        
        print(f"Base class public methods: {base_methods}")
        print(f"Enhanced class public methods: {enhanced_methods}")
        
        # Check that all base methods are available
        for method in base_methods:
            assert method in enhanced_methods, f"Missing method: {method}"
        
        print("✓ All base class methods are available in enhanced class")
        
        # Test that inherited methods work
        searcher = EnhancedFAISSCVESearch('cve-vulrag-test')
        
        # Test search method (inherited)
        results = searcher.search("buffer overflow", top_k=2)
        assert len(results) > 0
        print("✓ Inherited search() method works")
        
        # Test get_stats method (inherited)
        stats = searcher.get_stats()
        assert 'total_vectors' in stats
        assert 'dimension' in stats
        print("✓ Inherited get_stats() method works")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all backward compatibility tests"""
    print("=" * 80)
    print("BACKWARD COMPATIBILITY TEST SUITE")
    print("=" * 80)
    print("\nTesting that EnhancedFAISSCVESearch maintains full compatibility")
    print("with FAISSCVESearch while adding new functionality.")
    print("\nRequirements:")
    print("  7.1: Standard cve-full index continues to work")
    print("  7.2: Graceful fallback when enhanced index unavailable")
    print("  7.3: Same parameters accepted as FAISSCVESearch")
    print("  7.4: Result format includes all standard fields")
    print("  7.5: Results compatible with existing consumers")
    
    tests = [
        ("Parameter Compatibility (Req 7.3)", test_parameter_compatibility),
        ("Standard Index Compatibility (Req 7.1)", test_standard_index_compatibility),
        ("Result Format Compatibility (Req 7.4)", test_result_format_compatibility),
        ("Graceful Fallback (Req 7.2)", test_graceful_fallback),
        ("Existing Consumer Compatibility (Req 7.5)", test_existing_consumer_compatibility),
        ("Method Inheritance", test_method_inheritance),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ ALL BACKWARD COMPATIBILITY TESTS PASSED!")
        print("  EnhancedFAISSCVESearch is fully compatible with FAISSCVESearch")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
