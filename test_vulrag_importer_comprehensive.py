"""
Comprehensive test for VUL-RAG Importer

Tests all requirements:
- 1.1: JSON parsing functionality
- 1.2: Validation for required fields (cve_id, description)
- 1.4: Merge logic to handle duplicate CVE entries
- 1.5: Import statistics tracking (success count, error count)
- Error handling for invalid JSON and missing files
"""

import os
import json
import sqlite3
import tempfile
from vulrag_importer import VulRagImporter, ImportResult


def test_json_parsing():
    """Test 1.1: JSON parsing functionality"""
    print("Test 1.1: JSON parsing functionality")
    
    # Create a temporary JSON file
    test_data = [
        {
            "cve_id": "CVE-2024-TEST1",
            "cwe_id": "CWE-79",
            "vulnerability_type": "XSS",
            "root_cause": "Input validation",
            "attack_condition": "User input",
            "fix_strategy": "Sanitize input",
            "code_pattern": "Unescaped output",
            "description": "Test XSS vulnerability"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_data, f)
        temp_file = f.name
    
    try:
        importer = VulRagImporter()
        result = importer.import_from_json(temp_file)
        
        assert result.success_count == 1, "Should import 1 entry"
        assert result.error_count == 0, "Should have no errors"
        print("✓ JSON parsing works correctly")
        
        # Verify all fields were parsed
        conn = sqlite3.connect('cves.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, cwe_id, vulnerability_type, root_cause, 
                   attack_condition, fix_strategy, code_pattern
            FROM vulrag_enrichment WHERE cve_id = ?
        """, ("CVE-2024-TEST1",))
        row = cursor.fetchone()
        conn.close()
        
        assert row is not None, "Entry should exist in database"
        assert row[0] == "CVE-2024-TEST1"
        assert row[1] == "CWE-79"
        assert row[2] == "XSS"
        print("✓ All fields parsed correctly")
        
    finally:
        os.unlink(temp_file)


def test_required_field_validation():
    """Test 1.2: Validation for required fields"""
    print("\nTest 1.2: Required field validation")
    
    importer = VulRagImporter()
    
    # Test valid entry
    valid_entry = {
        "cve_id": "CVE-2024-VALID",
        "description": "Valid description"
    }
    is_valid, error = importer.validate_entry(valid_entry)
    assert is_valid, "Valid entry should pass validation"
    print("✓ Valid entry passes validation")
    
    # Test missing cve_id
    missing_cve = {
        "description": "Missing CVE ID"
    }
    is_valid, error = importer.validate_entry(missing_cve)
    assert not is_valid, "Entry without cve_id should fail"
    assert "cve_id" in error, "Error should mention cve_id"
    print("✓ Missing cve_id detected")
    
    # Test missing description
    missing_desc = {
        "cve_id": "CVE-2024-TEST"
    }
    is_valid, error = importer.validate_entry(missing_desc)
    assert not is_valid, "Entry without description should fail"
    assert "description" in error, "Error should mention description"
    print("✓ Missing description detected")
    
    # Test empty cve_id
    empty_cve = {
        "cve_id": "",
        "description": "Empty CVE ID"
    }
    is_valid, error = importer.validate_entry(empty_cve)
    assert not is_valid, "Empty cve_id should fail"
    print("✓ Empty cve_id detected")
    
    # Test invalid CVE format
    invalid_format = {
        "cve_id": "INVALID-2024-123",
        "description": "Invalid format"
    }
    is_valid, error = importer.validate_entry(invalid_format)
    assert not is_valid, "Invalid CVE format should fail"
    assert "Invalid CVE ID format" in error
    print("✓ Invalid CVE format detected")


def test_duplicate_handling():
    """Test 1.4: Merge logic to handle duplicate CVE entries"""
    print("\nTest 1.4: Duplicate handling")
    
    # Create test data
    test_data = [
        {
            "cve_id": "CVE-2024-DUP1",
            "description": "First version",
            "fix_strategy": "Original fix"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_data, f)
        temp_file = f.name
    
    try:
        importer = VulRagImporter()
        
        # Import first time
        result1 = importer.import_from_json(temp_file)
        assert result1.success_count == 1
        
        # Check count
        conn = sqlite3.connect('cves.db')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vulrag_enrichment WHERE cve_id = ?", 
                      ("CVE-2024-DUP1",))
        count1 = cursor.fetchone()[0]
        assert count1 == 1, "Should have 1 entry"
        
        # Import again with updated data
        test_data[0]["fix_strategy"] = "Updated fix"
        with open(temp_file, 'w') as f:
            json.dump(test_data, f)
        
        result2 = importer.import_from_json(temp_file)
        assert result2.success_count == 1
        
        # Check count is still 1 (not 2)
        cursor.execute("SELECT COUNT(*) FROM vulrag_enrichment WHERE cve_id = ?", 
                      ("CVE-2024-DUP1",))
        count2 = cursor.fetchone()[0]
        assert count2 == 1, "Should still have 1 entry (merged, not duplicated)"
        print("✓ Duplicate entries are merged, not duplicated")
        
        # Check that data was updated
        cursor.execute("SELECT fix_strategy FROM vulrag_enrichment WHERE cve_id = ?",
                      ("CVE-2024-DUP1",))
        fix_strategy = cursor.fetchone()[0]
        assert fix_strategy == "Updated fix", "Data should be updated"
        print("✓ Duplicate entry data is updated correctly")
        
        conn.close()
        
    finally:
        os.unlink(temp_file)


def test_import_statistics():
    """Test 1.5: Import statistics tracking"""
    print("\nTest 1.5: Import statistics tracking")
    
    # Create mixed valid/invalid data
    test_data = [
        {
            "cve_id": "CVE-2024-STAT1",
            "description": "Valid entry 1"
        },
        {
            "cve_id": "CVE-2024-STAT2",
            "description": "Valid entry 2"
        },
        {
            "cve_id": "",  # Invalid: empty cve_id
            "description": "Invalid entry"
        },
        {
            "cve_id": "CVE-2024-STAT3"
            # Invalid: missing description
        },
        {
            "cve_id": "CVE-2024-STAT4",
            "description": "Valid entry 3"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_data, f)
        temp_file = f.name
    
    try:
        importer = VulRagImporter()
        result = importer.import_from_json(temp_file)
        
        # Check statistics
        assert result.total_entries == 5, "Should have 5 total entries"
        assert result.success_count == 3, "Should have 3 successful imports"
        assert result.error_count == 2, "Should have 2 errors"
        print(f"✓ Statistics correct: {result.success_count} success, {result.error_count} errors")
        
        # Check that errors are tracked
        assert len(result.errors) == 2, "Should have 2 error records"
        assert all('cve_id' in err for err in result.errors), "Errors should include cve_id"
        assert all('error' in err for err in result.errors), "Errors should include error message"
        print("✓ Error details tracked correctly")
        
        # Verify success + error = total
        assert result.success_count + result.error_count == result.total_entries
        print("✓ Success count + error count = total entries")
        
    finally:
        os.unlink(temp_file)


def test_error_handling():
    """Test error handling for invalid JSON and missing files"""
    print("\nTest: Error handling")
    
    importer = VulRagImporter()
    
    # Test missing file
    try:
        importer.import_from_json("nonexistent_file.json")
        assert False, "Should raise FileNotFoundError"
    except FileNotFoundError as e:
        assert "not found" in str(e)
        print("✓ Missing file error handled correctly")
    
    # Test invalid JSON
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("{ invalid json }")
        temp_file = f.name
    
    try:
        try:
            importer.import_from_json(temp_file)
            assert False, "Should raise JSONDecodeError"
        except json.JSONDecodeError as e:
            assert "Invalid JSON format" in str(e)
            print("✓ Invalid JSON error handled correctly")
    finally:
        os.unlink(temp_file)


def test_get_import_stats():
    """Test get_import_stats method"""
    print("\nTest: Get import statistics")
    
    importer = VulRagImporter()
    stats = importer.get_import_stats()
    
    assert 'total_enrichments' in stats
    assert stats['total_enrichments'] >= 0
    print(f"✓ Total enrichments: {stats['total_enrichments']}")
    
    # Check that all optional fields are tracked
    for field in VulRagImporter.OPTIONAL_FIELDS:
        key = f'{field}_populated'
        assert key in stats, f"Stats should include {key}"
    print("✓ All field statistics tracked")


def main():
    """Run all tests"""
    print("=" * 70)
    print("VUL-RAG Importer Comprehensive Test Suite")
    print("=" * 70)
    
    try:
        test_json_parsing()
        test_required_field_validation()
        test_duplicate_handling()
        test_import_statistics()
        test_error_handling()
        test_get_import_stats()
        
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED")
        print("=" * 70)
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    main()
