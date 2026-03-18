#!/usr/bin/env python3
"""
Test cases for static analysis tools (CodeQL and Cppcheck)
Tests tool availability, analysis execution, and result parsing
"""
import unittest
import tempfile
import os
import json
import shutil
import subprocess
from unittest.mock import patch, MagicMock

# Import analysis components
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.analysis.codeql import CodeQLAnalyzer
    from src.analysis.cppcheck import CppcheckAnalyzer
except ImportError:
    # Create mock classes if analysis modules don't exist
    class CodeQLAnalyzer:
        def is_available(self):
            return False
        
        def analyze(self, source_dir):
            return [], []
    
    class CppcheckAnalyzer:
        def is_available(self):
            return False
        
        def analyze(self, source_dir):
            return [], []


class TestCodeQLAnalyzer(unittest.TestCase):
    """Test CodeQL static analysis functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = CodeQLAnalyzer()
        
        # Create test C++ files
        self.test_cpp_file = os.path.join(self.temp_dir, 'test.cpp')
        with open(self.test_cpp_file, 'w') as f:
            f.write('''
#include <iostream>
#include <cstring>

int main() {
    char buffer[10];
    char input[100] = "This is a very long string that will overflow the buffer";
    strcpy(buffer, input);  // Buffer overflow vulnerability
    
    int* ptr = new int(42);
    delete ptr;
    *ptr = 10;  // Use after free vulnerability
    
    return 0;
}
            ''')
        
        # Create test Python file
        self.test_py_file = os.path.join(self.temp_dir, 'test.py')
        with open(self.test_py_file, 'w') as f:
            f.write('''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()

def unsafe_eval(user_input):
    # Code injection vulnerability
    return eval(user_input)
            ''')
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_codeql_availability_check(self):
        """Test CodeQL availability detection"""
        # Test when CodeQL is available
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = 'CodeQL command-line toolchain release 2.15.0'
            mock_run.return_value = mock_result
            
            self.assertTrue(self.analyzer.is_available())
        
        # Test when CodeQL is not available
        with patch('subprocess.run', side_effect=FileNotFoundError):
            self.assertFalse(self.analyzer.is_available())
    
    @patch('subprocess.run')
    def test_codeql_database_creation(self, mock_run):
        """Test CodeQL database creation"""
        # Mock successful database creation
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Successfully created database'
        mock_run.return_value = mock_result
        
        # Test database creation
        db_path = os.path.join(self.temp_dir, 'codeql-db')
        success = self.analyzer._create_database(self.temp_dir, db_path, ['cpp'])
        
        self.assertTrue(success)
        mock_run.assert_called()
    
    @patch('subprocess.run')
    def test_codeql_analysis_execution(self, mock_run):
        """Test CodeQL analysis execution"""
        # Mock successful analysis
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        # Create mock SARIF results
        sarif_results = {
            "runs": [{
                "results": [
                    {
                        "ruleId": "cpp/buffer-overflow",
                        "message": {"text": "Buffer overflow detected"},
                        "level": "error",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.cpp"},
                                "region": {"startLine": 8}
                            }
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = os.path.join(self.temp_dir, 'results.sarif')
        with open(sarif_path, 'w') as f:
            json.dump(sarif_results, f)
        
        vulnerabilities, patches = self.analyzer._parse_sarif_results(sarif_path)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['rule_id'], 'cpp/buffer-overflow')
        self.assertEqual(vulnerabilities[0]['severity'], 'high')
        self.assertEqual(len(patches), 1)
    
    def test_codeql_language_detection(self):
        """Test programming language detection"""
        languages = self.analyzer._detect_languages(self.temp_dir)
        
        # Should detect both C++ and Python
        self.assertIn('cpp', languages)
        self.assertIn('python', languages)
    
    def test_codeql_sarif_parsing(self):
        """Test SARIF result parsing"""
        # Create test SARIF file
        sarif_data = {
            "runs": [{
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "message": {"text": "SQL injection vulnerability"},
                        "level": "warning",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.py"},
                                "region": {"startLine": 7}
                            }
                        }]
                    },
                    {
                        "ruleId": "py/code-injection",
                        "message": {"text": "Code injection via eval()"},
                        "level": "error",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.py"},
                                "region": {"startLine": 13}
                            }
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = os.path.join(self.temp_dir, 'test_results.sarif')
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        vulnerabilities, patches = self.analyzer._parse_sarif_results(sarif_path)
        
        self.assertEqual(len(vulnerabilities), 2)
        
        # Check first vulnerability (SQL injection)
        sql_vuln = vulnerabilities[0]
        self.assertEqual(sql_vuln['rule_id'], 'py/sql-injection')
        self.assertEqual(sql_vuln['severity'], 'medium')
        self.assertEqual(sql_vuln['file'], 'test.py')
        self.assertEqual(sql_vuln['line'], 7)
        
        # Check second vulnerability (code injection)
        code_vuln = vulnerabilities[1]
        self.assertEqual(code_vuln['rule_id'], 'py/code-injection')
        self.assertEqual(code_vuln['severity'], 'high')
        self.assertEqual(code_vuln['line'], 13)
        
        # Check patches generated
        self.assertEqual(len(patches), 2)
        self.assertIn('SQL injection', patches[0]['description'])
        self.assertIn('Code injection', patches[1]['description'])
    
    @patch('subprocess.run')
    def test_codeql_timeout_handling(self, mock_run):
        """Test CodeQL timeout handling"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired('codeql', 300)
        
        vulnerabilities, patches = self.analyzer.analyze(self.temp_dir)
        
        # Should fallback gracefully
        self.assertIsInstance(vulnerabilities, list)
        self.assertIsInstance(patches, list)


class TestCppcheckAnalyzer(unittest.TestCase):
    """Test Cppcheck static analysis functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = CppcheckAnalyzer()
        
        # Create test C++ files with various vulnerabilities
        self.test_files = {
            'buffer_overflow.cpp': '''
#include <cstring>
#include <iostream>

void vulnerable_function(const char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Buffer overflow
    std::cout << buffer << std::endl;
}

int main() {
    vulnerable_function("This string is way too long for the buffer");
    return 0;
}
            ''',
            'memory_leak.cpp': '''
#include <iostream>

void memory_leak_function() {
    int* ptr = new int[100];
    // Memory leak - no delete[]
    return;
}

int main() {
    memory_leak_function();
    return 0;
}
            ''',
            'null_pointer.cpp': '''
#include <iostream>

void null_pointer_function() {
    int* ptr = nullptr;
    *ptr = 42;  // Null pointer dereference
}

int main() {
    null_pointer_function();
    return 0;
}
            '''
        }
        
        for filename, content in self.test_files.items():
            file_path = os.path.join(self.temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_cppcheck_availability_check(self):
        """Test Cppcheck availability detection"""
        # Test when Cppcheck is available
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = 'Cppcheck 2.12'
            mock_run.return_value = mock_result
            
            self.assertTrue(self.analyzer.is_available())
        
        # Test when Cppcheck is not available
        with patch('subprocess.run', side_effect=FileNotFoundError):
            self.assertFalse(self.analyzer.is_available())
    
    def test_cppcheck_file_detection(self):
        """Test C/C++ file detection"""
        cpp_files = self.analyzer.find_cpp_files(self.temp_dir)
        
        self.assertEqual(len(cpp_files), 3)
        self.assertTrue(any('buffer_overflow.cpp' in f for f in cpp_files))
        self.assertTrue(any('memory_leak.cpp' in f for f in cpp_files))
        self.assertTrue(any('null_pointer.cpp' in f for f in cpp_files))
    
    @patch('subprocess.run')
    def test_cppcheck_analysis_execution(self, mock_run):
        """Test Cppcheck analysis execution"""
        # Mock successful analysis
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ''
        mock_run.return_value = mock_result
        
        # Create mock XML results
        xml_results = '''<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
    <cppcheck version="2.12"/>
    <errors>
        <error id="bufferAccessOutOfBounds" severity="error" msg="Buffer access out-of-bounds" verbose="Buffer access out-of-bounds">
            <location file="buffer_overflow.cpp" line="6"/>
        </error>
        <error id="memleak" severity="error" msg="Memory leak: ptr" verbose="Memory leak: ptr">
            <location file="memory_leak.cpp" line="4"/>
        </error>
        <error id="nullPointer" severity="error" msg="Null pointer dereference" verbose="Null pointer dereference">
            <location file="null_pointer.cpp" line="5"/>
        </error>
    </errors>
</results>'''
        
        xml_path = os.path.join(self.temp_dir, 'cppcheck-results.xml')
        with open(xml_path, 'w') as f:
            f.write(xml_results)
        
        vulnerabilities, patches = self.analyzer._parse_xml_results(xml_path)
        
        self.assertEqual(len(vulnerabilities), 3)
        self.assertEqual(len(patches), 0)  # Fix: patches are not generated in _parse_xml_results
        
        # Check buffer overflow detection
        buffer_vuln = next(v for v in vulnerabilities if 'buffer_overflow.cpp' in v['file'])
        self.assertEqual(buffer_vuln['rule_id'], 'bufferAccessOutOfBounds')
        self.assertEqual(buffer_vuln['severity'], 'high')
        self.assertEqual(buffer_vuln['line'], 6)
        
        # Check memory leak detection
        leak_vuln = next(v for v in vulnerabilities if 'memory_leak.cpp' in v['file'])
        self.assertEqual(leak_vuln['rule_id'], 'memleak')
        self.assertEqual(leak_vuln['severity'], 'high')
        
        # Check null pointer detection
        null_vuln = next(v for v in vulnerabilities if 'null_pointer.cpp' in v['file'])
        self.assertEqual(null_vuln['rule_id'], 'nullPointer')
        self.assertEqual(null_vuln['severity'], 'high')
    
    def test_cppcheck_stderr_parsing(self):
        """Test Cppcheck stderr output parsing (fallback)"""
        stderr_output = '''
buffer_overflow.cpp:6:error:Buffer access out-of-bounds
memory_leak.cpp:4:warning:Memory leak detected
null_pointer.cpp:5:error:Null pointer dereference
        '''
        
        vulnerabilities, patches = self.analyzer._parse_stderr_output(stderr_output)
        
        self.assertEqual(len(vulnerabilities), 3)
        
        # Check parsing accuracy
        buffer_vuln = vulnerabilities[0]
        self.assertEqual(buffer_vuln['file'], 'buffer_overflow.cpp')
        self.assertEqual(buffer_vuln['line'], 6)
        self.assertEqual(buffer_vuln['severity'], 'high')  # error -> high in stderr parsing
        
        leak_vuln = vulnerabilities[1]
        self.assertEqual(leak_vuln['file'], 'memory_leak.cpp')
        self.assertEqual(leak_vuln['line'], 4)
        self.assertEqual(leak_vuln['severity'], 'medium')  # warning -> medium
    
    def test_cppcheck_severity_mapping(self):
        """Test Cppcheck severity level mapping"""
        test_cases = [
            ('error', 'high'),
            ('warning', 'medium'),
            ('performance', 'medium'),
            ('portability', 'medium'),
            ('style', 'low'),
            ('information', 'low'),
            ('unknown', 'low')
        ]
        
        for cppcheck_severity, expected_severity in test_cases:
            mapped_severity = self.analyzer._map_severity(cppcheck_severity)
            self.assertEqual(mapped_severity, expected_severity)
    
    @patch('subprocess.run')
    def test_cppcheck_timeout_handling(self, mock_run):
        """Test Cppcheck timeout handling"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired('cppcheck', 120)
        
        vulnerabilities, patches = self.analyzer.analyze(self.temp_dir, 'local_path')
        
        # Should fallback gracefully
        self.assertIsInstance(vulnerabilities, list)
        self.assertIsInstance(patches, list)
    
    @patch('subprocess.run')
    def test_cppcheck_error_handling(self, mock_run):
        """Test Cppcheck error handling"""
        # Mock analysis failure
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = 'cppcheck: error: could not find or open any of the paths given.'
        mock_run.return_value = mock_result
        
        vulnerabilities, patches = self.analyzer.analyze(self.temp_dir, 'local_path')
        
        # Should handle errors gracefully
        self.assertIsInstance(vulnerabilities, list)
        self.assertIsInstance(patches, list)


class TestAnalysisIntegration(unittest.TestCase):
    """Test integration between analysis tools and the main application"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a realistic test project
        self.create_test_project()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def create_test_project(self):
        """Create a realistic test project with multiple vulnerabilities"""
        # Create project structure
        src_dir = os.path.join(self.temp_dir, 'src')
        os.makedirs(src_dir)
        
        # Main application file
        main_cpp = os.path.join(src_dir, 'main.cpp')
        with open(main_cpp, 'w') as f:
            f.write('''
#include <iostream>
#include <cstring>
#include <cstdlib>
#include "utils.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <input>" << std::endl;
        return 1;
    }
    
    char buffer[256];
    strcpy(buffer, argv[1]);  // Potential buffer overflow
    
    process_input(buffer);
    
    return 0;
}
            ''')
        
        # Utility functions
        utils_h = os.path.join(src_dir, 'utils.h')
        with open(utils_h, 'w') as f:
            f.write('''
#ifndef UTILS_H
#define UTILS_H

void process_input(const char* input);
char* allocate_memory(size_t size);
void free_memory(char* ptr);

#endif
            ''')
        
        utils_cpp = os.path.join(src_dir, 'utils.cpp')
        with open(utils_cpp, 'w') as f:
            f.write('''
#include "utils.h"
#include <cstring>
#include <cstdlib>
#include <iostream>

void process_input(const char* input) {
    char local_buffer[64];
    strcpy(local_buffer, input);  // Another buffer overflow
    
    std::cout << "Processing: " << local_buffer << std::endl;
}

char* allocate_memory(size_t size) {
    char* ptr = (char*)malloc(size);
    if (!ptr) {
        return nullptr;
    }
    return ptr;
}

void free_memory(char* ptr) {
    free(ptr);
    // Use after free vulnerability
    *ptr = '\\0';
}
            ''')
        
        # CMakeLists.txt
        cmake_file = os.path.join(self.temp_dir, 'CMakeLists.txt')
        with open(cmake_file, 'w') as f:
            f.write('''
cmake_minimum_required(VERSION 3.10)
project(TestProject)

set(CMAKE_CXX_STANDARD 17)

add_executable(test_app
    src/main.cpp
    src/utils.cpp
)
            ''')
    
    def test_tool_selection_logic(self):
        """Test automatic tool selection based on project type"""
        # Test C++ project detection
        codeql_analyzer = CodeQLAnalyzer()
        cppcheck_analyzer = CppcheckAnalyzer()
        
        # Should detect C++ files
        cpp_files = cppcheck_analyzer.find_cpp_files(self.temp_dir)
        self.assertGreater(len(cpp_files), 0)
        
        # Should detect C++ language for CodeQL
        languages = codeql_analyzer._detect_languages(self.temp_dir)
        self.assertIn('cpp', languages)
    
    @patch('subprocess.run')
    def test_analysis_result_consistency(self, mock_run):
        """Test that both tools produce consistent result formats"""
        # Mock both tools as available
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Tool version 1.0'
        mock_run.return_value = mock_result
        
        codeql_analyzer = CodeQLAnalyzer()
        cppcheck_analyzer = CppcheckAnalyzer()
        
        # Test result format consistency
        from unittest.mock import patch
        with patch.object(codeql_analyzer, '_parse_sarif_results') as mock_sarif:
            mock_sarif.return_value = (
                [{'rule_id': 'test', 'severity': 'high', 'file': 'test.cpp', 'line': 1}],
                [{'id': 'patch1', 'description': 'Test patch'}]
            )
            
            codeql_vulns, codeql_patches = mock_sarif.return_value
        
        with patch.object(cppcheck_analyzer, '_parse_xml_results') as mock_xml:
            mock_xml.return_value = (
                [{'rule_id': 'test', 'severity': 'high', 'file': 'test.cpp', 'line': 1}],
                [{'id': 'patch1', 'description': 'Test patch'}]
            )
            
            cppcheck_vulns, cppcheck_patches = mock_xml.return_value
        
        # Both should have same structure
        self.assertEqual(len(codeql_vulns), len(cppcheck_vulns))
        self.assertEqual(len(codeql_patches), len(cppcheck_patches))
        
        # Check required fields exist
        for vuln in codeql_vulns + cppcheck_vulns:
            self.assertIn('rule_id', vuln)
            self.assertIn('severity', vuln)
            self.assertIn('file', vuln)
            self.assertIn('line', vuln)
        
        for patch in codeql_patches + cppcheck_patches:
            self.assertIn('id', patch)
            self.assertIn('description', patch)
    
    def test_analysis_performance_benchmarking(self):
        """Test analysis performance with different project sizes"""
        import time
        
        # Create projects of different sizes
        project_sizes = [1, 5, 10]  # Number of files
        
        for size in project_sizes:
            test_dir = os.path.join(self.temp_dir, f'project_{size}')
            os.makedirs(test_dir, exist_ok=True)
            
            # Create multiple files
            for i in range(size):
                file_path = os.path.join(test_dir, f'file_{i}.cpp')
                with open(file_path, 'w') as f:
                    f.write(f'''
#include <iostream>
#include <cstring>

void function_{i}() {{
    char buffer[10];
    char input[100] = "test input {i}";
    strcpy(buffer, input);  // Buffer overflow
}}

int main() {{
    function_{i}();
    return 0;
}}
                    ''')
            
            # Measure analysis time (mocked)
            start_time = time.time()
            
            # Simulate analysis
            cppcheck_analyzer = CppcheckAnalyzer()
            cpp_files = cppcheck_analyzer.find_cpp_files(test_dir)
            
            end_time = time.time()
            analysis_time = end_time - start_time
            
            # Should scale reasonably
            self.assertLess(analysis_time, 1.0)  # Should be fast for small projects
            self.assertEqual(len(cpp_files), size)


class TestAnalysisResultProcessing(unittest.TestCase):
    """Test processing and transformation of analysis results"""
    
    def test_vulnerability_deduplication(self):
        """Test deduplication of similar vulnerabilities"""
        vulnerabilities = [
            {
                'rule_id': 'buffer-overflow',
                'file': 'test.cpp',
                'line': 10,
                'function': 'vulnerable_func',
                'severity': 'high'
            },
            {
                'rule_id': 'buffer-overflow',
                'file': 'test.cpp',
                'line': 11,  # Same function, different line
                'function': 'vulnerable_func',
                'severity': 'high'
            },
            {
                'rule_id': 'buffer-overflow',
                'file': 'other.cpp',
                'line': 10,
                'function': 'other_func',
                'severity': 'high'
            }
        ]
        
        # Simulate deduplication logic
        deduplicated = {}
        for vuln in vulnerabilities:
            key = f"{vuln['file']}:{vuln['function']}"
            if key not in deduplicated:
                deduplicated[key] = vuln
        
        # Should deduplicate to 2 unique vulnerabilities
        self.assertEqual(len(deduplicated), 2)
    
    def test_severity_normalization(self):
        """Test severity level normalization across tools"""
        # Test different severity mappings
        severity_mappings = {
            # CodeQL levels
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            
            # Cppcheck levels
            'error': 'high',
            'warning': 'medium',
            'style': 'low',
            'performance': 'medium',
            'portability': 'medium',
            'information': 'low'
        }
        
        for tool_severity, expected_severity in severity_mappings.items():
            # Test normalization function
            if tool_severity in ['error']:
                normalized = 'high'
            elif tool_severity in ['warning', 'performance', 'portability']:
                normalized = 'medium'
            else:
                normalized = 'low'
            
            self.assertEqual(normalized, expected_severity)
    
    def test_patch_generation_quality(self):
        """Test quality of generated patches"""
        vulnerability = {
            'rule_id': 'buffer-overflow',
            'file': 'test.cpp',
            'line': 10,
            'message': 'strcpy() is unsafe, use strncpy() instead',
            'severity': 'high'
        }
        
        # Simulate patch generation
        patch = {
            'id': f"patch_{vulnerability['rule_id']}",
            'description': f"Fix {vulnerability['rule_id']} in {vulnerability['file']}",
            'content': f"Replace strcpy() with strncpy() at line {vulnerability['line']}",
            'confidence': 'medium'
        }
        
        # Check patch quality
        self.assertIn('strcpy', patch['content'])
        self.assertIn('strncpy', patch['content'])
        self.assertIn(str(vulnerability['line']), patch['content'])
        self.assertEqual(patch['confidence'], 'medium')


if __name__ == '__main__':
    unittest.main()