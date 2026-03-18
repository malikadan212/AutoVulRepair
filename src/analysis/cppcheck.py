#!/usr/bin/env python3
"""
Cppcheck Static Analysis Integration
Runs Cppcheck and converts results to standardized format
"""
import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class CppcheckAnalyzer:
    """Cppcheck static analysis integration"""
    
    def __init__(self):
        """Initialize Cppcheck analyzer"""
        # Severity mapping to our standard levels
        self.severity_map = {
            'error': 'high',
            'warning': 'medium', 
            'style': 'low',
            'performance': 'medium',
            'portability': 'medium',
            'information': 'low',
            'unknown': 'low'
        }
        
        # Try to use Docker if available
        try:
            from src.utils.docker_helper import DockerToolRunner
            self.docker_runner = DockerToolRunner()
            self.use_docker = self.docker_runner.is_docker_available()
            if self.use_docker:
                logger.info("[CPPCHECK] Docker is available, will use Docker for analysis")
        except Exception as e:
            logger.warning(f"[CPPCHECK] Failed to initialize Docker: {e}")
            self.docker_runner = None
            self.use_docker = False
    
    def is_available(self) -> bool:
        """Check if Cppcheck is available in PATH"""
        try:
            result = subprocess.run(['cppcheck', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def find_cpp_files(self, source_dir: str) -> List[str]:
        """Find C/C++ files in the source directory"""
        cpp_extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']
        cpp_files = []
        
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                if any(file.endswith(ext) for ext in cpp_extensions):
                    cpp_files.append(os.path.join(root, file))
        
        return cpp_files
    
    def _map_severity(self, cppcheck_severity: str) -> str:
        """Map Cppcheck severity to our standard levels"""
        return self.severity_map.get(cppcheck_severity, 'low')
    
    def _parse_xml_results(self, xml_file: str) -> Tuple[List[Dict], List[Dict]]:
        """Parse Cppcheck XML output into standardized format"""
        vulnerabilities = []
        patches = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Parse errors/warnings
            for error in root.findall('.//error'):
                # Get error attributes
                error_id = error.get('id', 'unknown')
                severity = error.get('severity', 'warning')
                msg = error.get('msg', 'No message')
                
                # Get location information
                locations = error.findall('location')
                if not locations:
                    continue  # Skip errors without location
                
                # Process first location
                location = locations[0]
                file_path = location.get('file', '')
                line = int(location.get('line', 0))
                
                # Skip if no file path
                if not file_path:
                    continue
                
                vulnerability = {
                    'id': f'cppcheck_{error_id}_{line}',
                    'severity': self._map_severity(severity),
                    'description': msg,
                    'file': file_path,
                    'line': line,
                    'tool': 'cppcheck',
                    'rule_id': error_id
                }
                
                vulnerabilities.append(vulnerability)
        
        except ET.ParseError as e:
            logger.error(f"Failed to parse Cppcheck XML output: {e}")
        
        return vulnerabilities, patches
    
    def _parse_stderr_output(self, stderr_output: str) -> Tuple[List[Dict], List[Dict]]:
        """Parse Cppcheck stderr output as fallback"""
        vulnerabilities = []
        patches = []
        
        lines = stderr_output.strip().split('\n')
        for line in lines:
            if ':' in line and ('error' in line or 'warning' in line):
                parts = line.split(':')
                if len(parts) >= 4:
                    file_path = parts[0]
                    try:
                        line_num = int(parts[1])
                    except ValueError:
                        line_num = 0
                    
                    # Determine severity from message
                    severity = 'high' if 'error' in line else 'medium'
                    
                    vulnerability = {
                        'id': f'cppcheck_stderr_{line_num}',
                        'severity': severity,
                        'description': ':'.join(parts[3:]).strip(),
                        'file': file_path,
                        'line': line_num,
                        'tool': 'cppcheck',
                        'rule_id': 'stderr_parse'
                    }
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities, patches
    
    def analyze(self, source_dir: str, source_type: str, repo_url: Optional[str] = None) -> Tuple[List[Dict], List[Dict]]:
        """Run Cppcheck analysis on source directory
        
        Args:
            source_dir: Directory containing source code to analyze
            source_type: Type of source (local_path, repo_url, etc.)
            repo_url: Optional repository URL
            
        Returns:
            Tuple of (vulnerabilities, patches)
        """
        logger.info(f"Starting Cppcheck analysis on {source_dir}")
        
        # Try Docker first if available
        if self.use_docker and self.docker_runner:
            logger.info("[CPPCHECK] Using Docker for analysis")
            try:
                # Create output file path
                output_file = os.path.join(os.path.dirname(source_dir), 'artifacts', 'cppcheck-report.xml')
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                
                # Run Cppcheck via Docker
                stdout, stderr, returncode = self.docker_runner.run_cppcheck(source_dir, output_file, timeout=300)
                
                # Cppcheck returns 0 for no issues, 1 for issues found - both are success
                # Only fail if return code is > 1 (actual error) or output file doesn't exist
                if returncode <= 1 and os.path.exists(output_file):
                    logger.info(f"[CPPCHECK] Docker analysis completed (return code: {returncode}), parsing results from {output_file}")
                    vulnerabilities, patches = self._parse_xml_results(output_file)
                    logger.info(f"[CPPCHECK] Found {len(vulnerabilities)} vulnerabilities via Docker")
                    return vulnerabilities, patches
                else:
                    error_msg = f"Cppcheck Docker analysis failed with return code {returncode}"
                    if not os.path.exists(output_file):
                        error_msg += f" and output file not found: {output_file}"
                    logger.error(f"[CPPCHECK] {error_msg}")
                    raise RuntimeError(error_msg)
            except Exception as e:
                logger.error(f"[CPPCHECK] Docker analysis error: {e}")
                raise RuntimeError(f"Cppcheck analysis failed: {e}")
        
        # Try local Cppcheck
        if self.is_available():
            logger.info("[CPPCHECK] Using local Cppcheck installation")
            # Create temporary XML output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
                xml_output = temp_file.name
            
            try:
                # Build Cppcheck command
                cmd = [
                    'cppcheck',
                    '--xml',
                    '--xml-version=2',
                    f'--output-file={xml_output}',
                    '--enable=all',
                    '--inconclusive',
                    '--force',
                    '--quiet',
                    '--suppress=missingIncludeSystem',
                    '--suppress=unmatchedSuppression',
                    source_dir
                ]
                
                logger.info(f"Running: {' '.join(cmd)}")
                
                # Run Cppcheck
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                # Parse XML results
                vulnerabilities, patches = self._parse_xml_results(xml_output)
                
                # If no XML results, try parsing stderr
                if not vulnerabilities and result.stderr:
                    vulnerabilities, patches = self._parse_stderr_output(result.stderr)
                
                return vulnerabilities, patches
                
            except subprocess.TimeoutExpired:
                logger.error("Cppcheck analysis timed out")
                raise RuntimeError("Cppcheck analysis timed out after 300 seconds")
            except Exception as e:
                logger.error(f"Cppcheck analysis failed: {e}")
                raise RuntimeError(f"Cppcheck analysis failed: {e}")
            finally:
                # Clean up temporary file
                if os.path.exists(xml_output):
                    os.unlink(xml_output)
        
        # No analysis tool available - fail hard
        error_msg = "Cppcheck is not available. Docker is not running or Cppcheck is not installed."
        logger.error(f"[CPPCHECK] {error_msg}")
        raise RuntimeError(error_msg)
    


def main():
    """Main entry point for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Cppcheck analysis')
    parser.add_argument('source_dir', help='Source directory to analyze')
    parser.add_argument('--source-type', default='local_path',
                       help='Source type (local_path, repo_url)')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Run analysis
    analyzer = CppcheckAnalyzer()
    vulnerabilities, patches = analyzer.analyze(args.source_dir, args.source_type)
    
    print(f"Analysis complete. Found {len(vulnerabilities)} vulnerabilities and {len(patches)} patches.")


if __name__ == '__main__':
    main()