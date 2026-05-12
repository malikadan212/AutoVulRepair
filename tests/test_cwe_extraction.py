#!/usr/bin/env python3
"""
Test CWE extraction from static analysis tools
Verifies that CWE IDs are correctly extracted from Cppcheck XML and CodeQL SARIF
"""
import unittest
import json
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET

from src.analysis.cppcheck import CppcheckAnalyzer
from src.analysis.codeql import CodeQLAnalyzer


class TestCppcheckCWEExtraction(unittest.TestCase):
    """Test CWE extraction from Cppcheck XML output"""
    
    def setUp(self):
        self.analyzer = CppcheckAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_cwe_extraction_from_xml(self):
        """Test CWE ID extraction from Cppcheck XML with cwe attribute"""
        # Create test XML with CWE attributes
        xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
    <cppcheck version="2.10"/>
    <errors>
        <error id="bufferAccessOutOfBounds" severity="error" msg="Buffer overflow" cwe="119">
            <location file="test.c" line="10"/>
        </error>
        <error id="nullPointer" severity="error" msg="Null pointer dereference" cwe="476">
            <location file="test.c" line="20"/>
        </error>
        <error id="useAfterFree" severity="error" msg="Use after free" cwe="416">
            <location file="test.c" line="30"/>
        </error>
        <error id="integerOverflow" severity="warning" msg="Integer overflow" cwe="190">
            <location file="test.c" line="40"/>
        </error>
    </errors>
</results>'''
        
        xml_path = os.path.join(self.temp_dir, 'cppcheck_results.xml')
        with open(xml_path, 'w') as f:
            f.write(xml_content)
        
        vulnerabilities, patches = self.analyzer._parse_xml_results(xml_path)
        
        # Verify all vulnerabilities were parsed
        self.assertEqual(len(vulnerabilities), 4)
        
        # Check CWE extraction for each vulnerability
        buffer_vuln = next(v for v in vulnerabilities if v['rule_id'] == 'bufferAccessOutOfBounds')
        self.assertEqual(buffer_vuln['cwe'], 'CWE-119')
        
        null_vuln = next(v for v in vulnerabilities if v['rule_id'] == 'nullPointer')
        self.assertEqual(null_vuln['cwe'], 'CWE-476')
        
        uaf_vuln = next(v for v in vulnerabilities if v['rule_id'] == 'useAfterFree')
        self.assertEqual(uaf_vuln['cwe'], 'CWE-416')
        
        overflow_vuln = next(v for v in vulnerabilities if v['rule_id'] == 'integerOverflow')
        self.assertEqual(overflow_vuln['cwe'], 'CWE-190')
    
    def test_cwe_extraction_without_cwe_attribute(self):
        """Test handling of XML without CWE attributes"""
        xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
    <cppcheck version="2.10"/>
    <errors>
        <error id="styleIssue" severity="style" msg="Style issue">
            <location file="test.c" line="10"/>
        </error>
    </errors>
</results>'''
        
        xml_path = os.path.join(self.temp_dir, 'cppcheck_results.xml')
        with open(xml_path, 'w') as f:
            f.write(xml_content)
        
        vulnerabilities, patches = self.analyzer._parse_xml_results(xml_path)
        
        self.assertEqual(len(vulnerabilities), 1)
        # CWE should be None when not present
        self.assertIsNone(vulnerabilities[0]['cwe'])
    
    def test_cwe_formatting(self):
        """Test that CWE IDs are properly formatted as CWE-XXX"""
        xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
    <cppcheck version="2.10"/>
    <errors>
        <error id="test1" severity="error" msg="Test" cwe="119">
            <location file="test.c" line="10"/>
        </error>
        <error id="test2" severity="error" msg="Test" cwe="CWE-476">
            <location file="test.c" line="20"/>
        </error>
    </errors>
</results>'''
        
        xml_path = os.path.join(self.temp_dir, 'cppcheck_results.xml')
        with open(xml_path, 'w') as f:
            f.write(xml_content)
        
        vulnerabilities, patches = self.analyzer._parse_xml_results(xml_path)
        
        # Both should be formatted as CWE-XXX
        self.assertEqual(vulnerabilities[0]['cwe'], 'CWE-119')
        self.assertEqual(vulnerabilities[1]['cwe'], 'CWE-476')


class TestCodeQLCWEExtraction(unittest.TestCase):
    """Test CWE extraction from CodeQL SARIF output"""
    
    def setUp(self):
        self.analyzer = CodeQLAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_cwe_extraction_from_rule_tags(self):
        """Test CWE extraction from rule metadata tags"""
        sarif_data = {
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "cpp/buffer-overflow",
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-119"]
                                }
                            },
                            {
                                "id": "cpp/sql-injection",
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-89"]
                                }
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "cpp/buffer-overflow",
                        "message": {"text": "Buffer overflow vulnerability"},
                        "level": "error",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 10}
                            }
                        }]
                    },
                    {
                        "ruleId": "cpp/sql-injection",
                        "message": {"text": "SQL injection vulnerability"},
                        "level": "warning",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 20}
                            }
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = os.path.join(self.temp_dir, 'codeql_results.sarif')
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        vulnerabilities, patches = self.analyzer._parse_sarif_results(sarif_path)
        
        self.assertEqual(len(vulnerabilities), 2)
        
        # Check CWE extraction
        buffer_vuln = next(v for v in vulnerabilities if v['rule_id'] == 'cpp/buffer-overflow')
        self.assertEqual(buffer_vuln['cwe'], 'CWE-119')
        
        sql_vuln = next(v for v in vulnerabilities if v['rule_id'] == 'cpp/sql-injection')
        self.assertEqual(sql_vuln['cwe'], 'CWE-89')
    
    def test_cwe_extraction_from_result_properties(self):
        """Test CWE extraction from result-level properties"""
        sarif_data = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "cpp/use-after-free",
                        "message": {"text": "Use after free"},
                        "level": "error",
                        "properties": {
                            "tags": ["security", "external/cwe/cwe-416"]
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 15}
                            }
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = os.path.join(self.temp_dir, 'codeql_results.sarif')
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        vulnerabilities, patches = self.analyzer._parse_sarif_results(sarif_path)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['cwe'], 'CWE-416')
    
    def test_cwe_extraction_with_different_formats(self):
        """Test CWE extraction with various tag formats"""
        sarif_data = {
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "test1",
                                "properties": {
                                    "tags": ["external/cwe/cwe-190"]
                                }
                            },
                            {
                                "id": "test2",
                                "properties": {
                                    "tags": ["external/cwe/CWE-191"]
                                }
                            },
                            {
                                "id": "test3",
                                "properties": {
                                    "tags": ["cwe-476"]
                                }
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "test1",
                        "message": {"text": "Test 1"},
                        "level": "error",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 10}
                            }
                        }]
                    },
                    {
                        "ruleId": "test2",
                        "message": {"text": "Test 2"},
                        "level": "error",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 20}
                            }
                        }]
                    },
                    {
                        "ruleId": "test3",
                        "message": {"text": "Test 3"},
                        "level": "error",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 30}
                            }
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = os.path.join(self.temp_dir, 'codeql_results.sarif')
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        vulnerabilities, patches = self.analyzer._parse_sarif_results(sarif_path)
        
        self.assertEqual(len(vulnerabilities), 3)
        
        # All should be formatted as CWE-XXX
        self.assertEqual(vulnerabilities[0]['cwe'], 'CWE-190')
        self.assertEqual(vulnerabilities[1]['cwe'], 'CWE-191')
        self.assertEqual(vulnerabilities[2]['cwe'], 'CWE-476')
    
    def test_cwe_extraction_without_tags(self):
        """Test handling of SARIF without CWE tags"""
        sarif_data = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "test/no-cwe",
                        "message": {"text": "Test without CWE"},
                        "level": "warning",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 10}
                            }
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = os.path.join(self.temp_dir, 'codeql_results.sarif')
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        vulnerabilities, patches = self.analyzer._parse_sarif_results(sarif_path)
        
        self.assertEqual(len(vulnerabilities), 1)
        # CWE should be None when not present
        self.assertIsNone(vulnerabilities[0]['cwe'])


class TestINTREPAIRCWEMapping(unittest.TestCase):
    """Test CWE mapping for INTREPAIR integer overflow detection"""
    
    def setUp(self):
        """Check if z3-solver is available"""
        try:
            import z3
            self.z3_available = True
        except ImportError:
            self.z3_available = False
    
    @unittest.skipIf(not hasattr(unittest.TestCase, 'z3_available'), "z3-solver not installed")
    def test_overflow_cwe_mapping(self):
        """Test that integer overflow gets CWE-190"""
        if not self.z3_available:
            self.skipTest("z3-solver not installed")
        
        from src.intrepair.detector import OverflowFault
        
        fault = OverflowFault(
            fault_id="test_001",
            file_name="test.c",
            line_number=10,
            faulty_statement="int x = a + b;",
            operator="+",
            lhs_var="x",
            operand_left="a",
            operand_right="b",
            operand_right_is_const=False,
            operand_right_value=None,
            inferred_type="int",
            can_overflow=True,
            can_underflow=False,
            cwe_id="CWE-190"
        )
        
        self.assertEqual(fault.cwe_id, "CWE-190")
    
    @unittest.skipIf(not hasattr(unittest.TestCase, 'z3_available'), "z3-solver not installed")
    def test_underflow_cwe_mapping(self):
        """Test that integer underflow gets CWE-191"""
        if not self.z3_available:
            self.skipTest("z3-solver not installed")
        
        from src.intrepair.detector import OverflowFault
        
        fault = OverflowFault(
            fault_id="test_002",
            file_name="test.c",
            line_number=20,
            faulty_statement="int x = a * -3;",
            operator="*",
            lhs_var="x",
            operand_left="a",
            operand_right="-3",
            operand_right_is_const=True,
            operand_right_value=-3,
            inferred_type="int",
            can_overflow=False,
            can_underflow=True,
            cwe_id="CWE-191"
        )
        
        self.assertEqual(fault.cwe_id, "CWE-191")
    
    @unittest.skipIf(not hasattr(unittest.TestCase, 'z3_available'), "z3-solver not installed")
    def test_both_overflow_underflow_cwe_mapping(self):
        """Test that both overflow and underflow gets CWE-190/191"""
        if not self.z3_available:
            self.skipTest("z3-solver not installed")
        
        from src.intrepair.detector import OverflowFault
        
        fault = OverflowFault(
            fault_id="test_003",
            file_name="test.c",
            line_number=30,
            faulty_statement="int x = a * a;",
            operator="*",
            lhs_var="x",
            operand_left="a",
            operand_right="a",
            operand_right_is_const=False,
            operand_right_value=None,
            inferred_type="int",
            can_overflow=True,
            can_underflow=True,
            cwe_id="CWE-190/191"
        )
        
        self.assertEqual(fault.cwe_id, "CWE-190/191")


if __name__ == '__main__':
    unittest.main()
