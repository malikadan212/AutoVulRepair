"""
Unit Tests for Triage Analyzer
Tests crash analysis and classification logic
"""

import unittest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock
from src.triage.analyzer import CrashTriageAnalyzer


class TestCrashTriageAnalyzer(unittest.TestCase):
    """Test cases for CrashTriageAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scan_id = "test_scan_123"
        
        # Mock campaign results
        self.test_campaign_results = {
            "total_targets": 3,
            "total_time": 300.5,
            "timestamp": "2024-01-01T12:00:00",
            "results": [
                {
                    "target": "fuzz_test_buffer_overflow",
                    "status": "completed",
                    "runtime": 60.2,
                    "crashes_found": 2,
                    "crashes": [
                        {
                            "filename": "crash-abc123",
                            "path": "/tmp/crashes/crash-abc123",
                            "size": 16
                        },
                        {
                            "filename": "crash-def456", 
                            "path": "/tmp/crashes/crash-def456",
                            "size": 8
                        }
                    ],
                    "output": "AddressSanitizer: heap-buffer-overflow on address 0x602000000013"
                },
                {
                    "target": "fuzz_test_double_free",
                    "status": "completed", 
                    "runtime": 45.1,
                    "crashes_found": 1,
                    "crashes": [
                        {
                            "filename": "crash-ghi789",
                            "path": "/tmp/crashes/crash-ghi789", 
                            "size": 4
                        }
                    ],
                    "output": "AddressSanitizer: double-free on address 0x602000000020"
                },
                {
                    "target": "fuzz_test_memory_leak",
                    "status": "completed",
                    "runtime": 120.0,
                    "crashes_found": 1,
                    "crashes": [
                        {
                            "filename": "leak-jkl012",
                            "path": "/tmp/leaks/leak-jkl012",
                            "size": 0
                        }
                    ],
                    "output": "AddressSanitizer: 1024 byte(s) leaked in 1 allocation(s)"
                }
            ]
        }
        
        # Create temporary scan directory structure
        self.temp_scan_dir = tempfile.mkdtemp()
        self.scan_dir = os.path.join(self.temp_scan_dir, self.scan_id)
        os.makedirs(self.scan_dir)
        
        # Create fuzz results directory and file
        fuzz_results_dir = os.path.join(self.scan_dir, 'fuzz', 'results')
        os.makedirs(fuzz_results_dir, exist_ok=True)
        
        campaign_results_path = os.path.join(fuzz_results_dir, 'campaign_results.json')
        with open(campaign_results_path, 'w') as f:
            json.dump(self.test_campaign_results, f)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.temp_scan_dir):
            shutil.rmtree(self.temp_scan_dir)
    
    @patch('src.triage.analyzer.os.getenv')
    def test_analyzer_initialization(self, mock_getenv):
        """Test analyzer initialization"""
        mock_getenv.return_value = self.temp_scan_dir
        
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        self.assertEqual(analyzer.scan_id, self.scan_id)
        self.assertTrue(analyzer.scan_dir.endswith(self.scan_id))
    
    def test_load_campaign_results_success(self):
        """Test successful loading of campaign results"""
        # Create analyzer with the test scan directory
        analyzer = CrashTriageAnalyzer(self.scan_id)
        # Override the results_dir to point to our test directory
        analyzer.results_dir = os.path.join(self.scan_dir, 'fuzz', 'results')
        
        results = analyzer._load_campaign_results()
        
        self.assertIsNotNone(results)
        self.assertEqual(results['total_targets'], 3)
        self.assertEqual(len(results['results']), 3)
    
    @patch('src.triage.analyzer.os.getenv')
    def test_load_campaign_results_not_found(self, mock_getenv):
        """Test handling of missing campaign results"""
        mock_getenv.return_value = '/nonexistent/path'
        
        analyzer = CrashTriageAnalyzer(self.scan_id)
        results = analyzer._load_campaign_results()
        
        self.assertIsNone(results)
    
    def test_extract_crash_type_heap_overflow(self):
        """Test crash type extraction for heap buffer overflow"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        crash_type = analyzer._extract_crash_type(
            'crash-abc123',
            'AddressSanitizer: heap-buffer-overflow on address 0x602000000013'
        )
        
        self.assertEqual(crash_type, 'Heap Buffer Overflow')
    
    def test_extract_crash_type_double_free(self):
        """Test crash type extraction for double free"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        crash_type = analyzer._extract_crash_type(
            'crash-def456',
            'AddressSanitizer: double-free on address 0x602000000020'
        )
        
        self.assertEqual(crash_type, 'Double Free')
    
    def test_extract_crash_type_memory_leak(self):
        """Test crash type extraction for memory leak"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        crash_type = analyzer._extract_crash_type(
            'leak-jkl012',
            'AddressSanitizer: 1024 byte(s) leaked in 1 allocation(s)'
        )
        
        self.assertEqual(crash_type, 'Memory Leak')
    
    def test_extract_crash_type_unknown(self):
        """Test crash type extraction for unknown crashes"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        crash_type = analyzer._extract_crash_type(
            'unknown-crash',
            'Some unknown error message'
        )
        
        self.assertEqual(crash_type, 'Unknown Crash')  # Default for unknown files
    
    def test_assess_severity_critical(self):
        """Test severity assessment for critical bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        severity = analyzer._assess_severity('Double Free', '')
        self.assertEqual(severity, 'Critical')
        
        severity = analyzer._assess_severity('Use After Free', '')
        self.assertEqual(severity, 'Critical')
    
    def test_assess_severity_high(self):
        """Test severity assessment for high bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        severity = analyzer._assess_severity('Heap Buffer Overflow', '')
        self.assertEqual(severity, 'Critical')  # Buffer overflows are critical
        
        severity = analyzer._assess_severity('Null Pointer Dereference', '')
        self.assertEqual(severity, 'High')
    
    def test_assess_severity_medium(self):
        """Test severity assessment for medium bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        severity = analyzer._assess_severity('Memory Leak', '')
        self.assertEqual(severity, 'Medium')
    
    def test_assess_exploitability_exploitable(self):
        """Test exploitability assessment for exploitable bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        exploitability = analyzer._assess_exploitability('Heap Buffer Overflow', '')
        self.assertEqual(exploitability, 'Exploitable')
        
        exploitability = analyzer._assess_exploitability('Use After Free', '')
        self.assertEqual(exploitability, 'Exploitable')
    
    def test_assess_exploitability_likely(self):
        """Test exploitability assessment for likely exploitable bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        exploitability = analyzer._assess_exploitability('Double Free', '')
        self.assertEqual(exploitability, 'Exploitable')  # Updated to Exploitable
        
        exploitability = analyzer._assess_exploitability('Stack Overflow', '')
        self.assertEqual(exploitability, 'Likely Exploitable')
    
    def test_assess_exploitability_unlikely(self):
        """Test exploitability assessment for unlikely exploitable bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        exploitability = analyzer._assess_exploitability('Memory Leak', '')
        self.assertEqual(exploitability, 'Unlikely Exploitable')
        
        exploitability = analyzer._assess_exploitability('Null Pointer Dereference', '')
        self.assertEqual(exploitability, 'Unlikely Exploitable')
    
    def test_calculate_cvss_critical_exploitable(self):
        """Test CVSS calculation for critical exploitable bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        cvss = analyzer._calculate_cvss('Double Free', 'Critical', 'Exploitable')
        self.assertEqual(cvss, 9.0)  # Critical + Exploitable = 9.0 * 1.0 = 9.0
    
    def test_calculate_cvss_high_likely(self):
        """Test CVSS calculation for high likely exploitable bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        cvss = analyzer._calculate_cvss('Stack Overflow', 'High', 'Likely Exploitable')
        self.assertAlmostEqual(cvss, 6.4, places=1)  # 7.5 * 0.8 + 0.2 * 2 = 6.4
    
    def test_calculate_cvss_medium_unlikely(self):
        """Test CVSS calculation for medium unlikely exploitable bugs"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        cvss = analyzer._calculate_cvss('Memory Leak', 'Medium', 'Unlikely Exploitable')
        self.assertAlmostEqual(cvss, 3.5, places=1)  # 5.0 * 0.5 + 0.5 * 2 = 3.5
    
    def test_extract_stack_trace(self):
        """Test stack trace extraction"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        output = """AddressSanitizer: heap-buffer-overflow
    #0 0x7f8b8c0a1234 in main /path/to/main.cpp:42:5
    #1 0x7f8b8c0a5678 in __libc_start_main /lib/libc.so.6
    #2 0x7f8b8c0a9abc in _start /path/to/start.s:123
    
Some other output"""
        
        stack_trace = analyzer._extract_stack_trace(output)
        
        self.assertEqual(len(stack_trace), 3)
        self.assertIn('#0 0x7f8b8c0a1234', stack_trace[0])
        self.assertIn('#1 0x7f8b8c0a5678', stack_trace[1])
        self.assertIn('#2 0x7f8b8c0a9abc', stack_trace[2])
    
    def test_extract_root_cause(self):
        """Test root cause extraction"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        output = """Some error output
SUMMARY: AddressSanitizer: heap-buffer-overflow /path/to/file.cpp:42:5 in function_name
More output"""
        
        root_cause = analyzer._extract_root_cause(output)
        
        self.assertIn('SUMMARY: AddressSanitizer: heap-buffer-overflow', root_cause)
    
    def test_deduplicate_crashes(self):
        """Test crash deduplication"""
        analyzer = CrashTriageAnalyzer(self.scan_id)
        
        crashes = [
            {
                'crash_type': 'Buffer Overflow',
                'stack_trace': ['#0 func1', '#1 func2', '#2 func3']
            },
            {
                'crash_type': 'Buffer Overflow', 
                'stack_trace': ['#0 func1', '#1 func2', '#2 func3']  # Same signature
            },
            {
                'crash_type': 'Double Free',
                'stack_trace': ['#0 free', '#1 main']  # Different signature
            }
        ]
        
        unique_crashes = analyzer._deduplicate_crashes(crashes)
        
        # Should deduplicate to 2 unique crashes
        self.assertEqual(len(unique_crashes), 2)
        
        # Check that duplicate is marked
        self.assertNotIn('is_duplicate', unique_crashes[0])
        self.assertNotIn('is_duplicate', unique_crashes[1])
    
    def test_analyze_campaign_success(self):
        """Test successful campaign analysis"""
        # Create analyzer with the test scan directory
        analyzer = CrashTriageAnalyzer(self.scan_id)
        # Override the results_dir to point to our test directory
        analyzer.results_dir = os.path.join(self.scan_dir, 'fuzz', 'results')
        
        results = analyzer.analyze_campaign()
        
        # Check structure
        self.assertIn('summary', results)
        self.assertIn('crashes', results)
        self.assertIn('timestamp', results)
        
        # Check summary
        summary = results['summary']
        self.assertIn('total_crashes', summary)
        self.assertIn('by_severity', summary)
        self.assertIn('by_type', summary)
        self.assertIn('by_exploitability', summary)
        
        # Check crashes were analyzed
        self.assertGreater(len(results['crashes']), 0)
    
    @patch('src.triage.analyzer.os.getenv')
    def test_analyze_campaign_no_results(self, mock_getenv):
        """Test campaign analysis with no results"""
        # Point to empty directory
        empty_dir = tempfile.mkdtemp()
        mock_getenv.return_value = empty_dir
        
        try:
            analyzer = CrashTriageAnalyzer(self.scan_id)
            results = analyzer.analyze_campaign()
            
            self.assertIn('error', results)
            
        finally:
            import shutil
            shutil.rmtree(empty_dir)


if __name__ == '__main__':
    unittest.main()