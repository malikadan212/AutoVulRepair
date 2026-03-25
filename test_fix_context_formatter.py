"""
Test Fix Context Formatter

Tests the FixContextFormatter class to ensure it correctly formats
CVE data for LLM consumption.
"""

from fix_context_formatter import FixContextFormatter


def test_format_single_cve_with_complete_enrichment():
    """Test formatting a CVE with complete VUL-RAG enrichment"""
    formatter = FixContextFormatter()
    
    cve_data = {
        'cve_id': 'CVE-2023-12345',
        'severity': 'HIGH',
        'cvss_score': 7.5,
        'cwe': 'CWE-79',
        'description': 'XSS vulnerability in web application',
        'vulnerability_type': 'Cross-Site Scripting',
        'root_cause': 'Insufficient input validation',
        'attack_condition': 'Attacker can inject scripts',
        'fix_strategy': 'Implement input sanitization',
        'code_pattern': 'Unescaped user input'
    }
    
    result = formatter.format_single_cve(cve_data)
    
    # Verify all fields are present
    assert 'CVE-2023-12345' in result
    assert 'Cross-Site Scripting' in result
    assert 'HIGH' in result
    assert '7.5' in result
    assert 'CWE-79' in result
    assert 'XSS vulnerability' in result
    assert 'Insufficient input validation' in result
    assert 'Attacker can inject scripts' in result
    assert 'Implement input sanitization' in result
    assert 'Unescaped user input' in result
    
    # Verify section headers
    assert 'Description:' in result
    assert 'Root Cause:' in result
    assert 'Attack Condition:' in result
    assert 'Fix Strategy:' in result
    assert 'Code Pattern:' in result


def test_format_single_cve_with_partial_enrichment():
    """Test formatting a CVE with partial VUL-RAG data"""
    formatter = FixContextFormatter()
    
    cve_data = {
        'cve_id': 'CVE-2023-67890',
        'description': 'Buffer overflow vulnerability',
        'root_cause': 'Lack of bounds checking',
        'fix_strategy': 'Implement bounds checking'
        # Missing: vulnerability_type, attack_condition, code_pattern
    }
    
    result = formatter.format_single_cve(cve_data)
    
    # Verify present fields are included
    assert 'CVE-2023-67890' in result
    assert 'Buffer overflow vulnerability' in result
    assert 'Lack of bounds checking' in result
    assert 'Implement bounds checking' in result
    
    # Verify section headers for present fields
    assert 'Root Cause:' in result
    assert 'Fix Strategy:' in result


def test_format_single_cve_without_enrichment():
    """Test fallback formatting for CVE without VUL-RAG enrichment"""
    formatter = FixContextFormatter()
    
    cve_data = {
        'cve_id': 'CVE-2023-11111',
        'severity': 'MEDIUM',
        'cvss_score': 5.3,
        'description': 'Improper input validation'
    }
    
    result = formatter.format_single_cve(cve_data)
    
    # Verify basic fields are present
    assert 'CVE-2023-11111' in result
    assert 'MEDIUM' in result
    assert '5.3' in result
    assert 'Improper input validation' in result
    
    # Verify fallback note is present
    assert 'Limited context available' in result
    assert 'VUL-RAG enrichment data not found' in result


def test_format_multiple_cves():
    """Test formatting multiple CVEs with clear delimiters"""
    formatter = FixContextFormatter()
    
    cve_list = [
        {
            'cve_id': 'CVE-2023-AAA',
            'description': 'SQL injection vulnerability',
            'root_cause': 'Unparameterized queries',
            'fix_strategy': 'Use prepared statements'
        },
        {
            'cve_id': 'CVE-2023-BBB',
            'description': 'Path traversal vulnerability',
            'root_cause': 'Insufficient path validation',
            'fix_strategy': 'Validate file paths'
        }
    ]
    
    result = formatter.format_multiple_cves(cve_list)
    
    # Verify both CVEs are present
    assert 'CVE-2023-AAA' in result
    assert 'CVE-2023-BBB' in result
    assert 'SQL injection' in result
    assert 'Path traversal' in result
    
    # Verify they are separated
    assert result.count('===') >= 4  # At least 2 headers and 2 footers


def test_format_multiple_cves_empty_list():
    """Test formatting empty CVE list"""
    formatter = FixContextFormatter()
    
    result = formatter.format_multiple_cves([])
    
    assert result == ""


def test_format_for_patch_generation():
    """Test patch generation format with CVE context and code"""
    formatter = FixContextFormatter()
    
    cve_data = {
        'cve_id': 'CVE-2023-SQL',
        'description': 'SQL injection in search function',
        'root_cause': 'String concatenation in SQL query',
        'fix_strategy': 'Use parameterized queries',
        'vulnerability_type': 'SQL Injection'
    }
    
    code = "SELECT * FROM users WHERE id = '" + "user_id" + "'"
    
    result = formatter.format_for_patch_generation(cve_data, code)
    
    # Verify structure
    assert 'VULNERABILITY CONTEXT:' in result
    assert 'VULNERABLE CODE:' in result
    assert 'TASK:' in result
    
    # Verify CVE data is present
    assert 'CVE-2023-SQL' in result
    assert 'SQL injection' in result
    assert 'Use parameterized queries' in result
    
    # Verify code is present
    assert 'user_id' in result
    assert '```' in result


def test_field_inclusion_property():
    """
    Property test: For any CVE with complete VUL-RAG data,
    the fix context should contain all specified fields
    
    Validates: Requirements 4.1
    """
    formatter = FixContextFormatter()
    
    # Test with various complete CVE data
    test_cases = [
        {
            'cve_id': 'CVE-2023-TEST1',
            'description': 'Test vulnerability 1',
            'root_cause': 'Test root cause 1',
            'fix_strategy': 'Test fix strategy 1',
            'code_pattern': 'Test code pattern 1',
            'attack_condition': 'Test attack condition 1'
        },
        {
            'cve_id': 'CVE-2023-TEST2',
            'description': 'Test vulnerability 2',
            'root_cause': 'Test root cause 2',
            'fix_strategy': 'Test fix strategy 2',
            'code_pattern': 'Test code pattern 2',
            'attack_condition': 'Test attack condition 2'
        }
    ]
    
    for cve_data in test_cases:
        result = formatter.format_single_cve(cve_data)
        
        # All fields should be present as substrings
        assert cve_data['description'] in result
        assert cve_data['root_cause'] in result
        assert cve_data['fix_strategy'] in result
        assert cve_data['code_pattern'] in result
        assert cve_data['attack_condition'] in result


def test_partial_data_handling_property():
    """
    Property test: For any CVE with partial enrichment,
    the fix context should include only non-null fields
    
    Validates: Requirements 4.3
    """
    formatter = FixContextFormatter()
    
    # Test with various partial data combinations
    test_cases = [
        {
            'cve_id': 'CVE-2023-PARTIAL1',
            'description': 'Test vulnerability',
            'root_cause': 'Test root cause'
            # Missing: fix_strategy, code_pattern, attack_condition
        },
        {
            'cve_id': 'CVE-2023-PARTIAL2',
            'description': 'Test vulnerability',
            'fix_strategy': 'Test fix strategy'
            # Missing: root_cause, code_pattern, attack_condition
        }
    ]
    
    for cve_data in test_cases:
        result = formatter.format_single_cve(cve_data)
        
        # Present fields should be included
        for key, value in cve_data.items():
            if value:
                assert value in result
        
        # Should not contain placeholder text for missing fields
        assert 'None' not in result
        assert 'null' not in result.lower()


def test_multi_cve_concatenation_property():
    """
    Property test: For any list of N CVEs (N > 1),
    the combined fix context should contain N delimiter strings
    
    Validates: Requirements 4.2
    """
    formatter = FixContextFormatter()
    
    # Test with different list sizes
    for n in [2, 3, 5]:
        cve_list = [
            {
                'cve_id': f'CVE-2023-{i:04d}',
                'description': f'Test vulnerability {i}',
                'root_cause': f'Test root cause {i}',
                'fix_strategy': f'Test fix strategy {i}'
            }
            for i in range(n)
        ]
        
        result = formatter.format_multiple_cves(cve_list)
        
        # Should contain N CVE IDs
        for i in range(n):
            assert f'CVE-2023-{i:04d}' in result
        
        # Should contain at least N*2 delimiter strings (header and footer for each)
        delimiter_count = result.count('===')
        assert delimiter_count >= n * 2


if __name__ == '__main__':
    # Run all tests
    print("Running Fix Context Formatter Tests")
    print("=" * 80)
    
    tests = [
        ("Format single CVE with complete enrichment", test_format_single_cve_with_complete_enrichment),
        ("Format single CVE with partial enrichment", test_format_single_cve_with_partial_enrichment),
        ("Format single CVE without enrichment", test_format_single_cve_without_enrichment),
        ("Format multiple CVEs", test_format_multiple_cves),
        ("Format multiple CVEs empty list", test_format_multiple_cves_empty_list),
        ("Format for patch generation", test_format_for_patch_generation),
        ("Field inclusion property", test_field_inclusion_property),
        ("Partial data handling property", test_partial_data_handling_property),
        ("Multi-CVE concatenation property", test_multi_cve_concatenation_property),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            print(f"✓ {test_name}")
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_name}: Unexpected error: {e}")
            failed += 1
    
    print()
    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    
    if failed == 0:
        print("✓ All tests passed!")
    else:
        print(f"✗ {failed} test(s) failed")
        exit(1)
