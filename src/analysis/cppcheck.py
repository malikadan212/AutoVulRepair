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
        
        # CWE mapping for Cppcheck rule IDs
        # Based on Cppcheck documentation and CPPCHECK_CWE_MAPPING.md
        self.cwe_map = {
            # Buffer overflows and memory access
            'bufferAccessOutOfBounds': 'CWE-788',
            'arrayIndexOutOfBounds': 'CWE-788',
            'arrayIndexThenCheck': 'CWE-119',
            'outOfBounds': 'CWE-119',
            'negativeIndex': 'CWE-119',
            'pointerOutOfBounds': 'CWE-119',
            
            # Null pointer dereference
            'nullPointer': 'CWE-476',
            'nullPointerArithmetic': 'CWE-476',
            'nullPointerRedundantCheck': 'CWE-476',
            
            # Memory leaks
            'memleak': 'CWE-401',
            'memleakOnRealloc': 'CWE-401',
            'resourceLeak': 'CWE-404',
            'leakReturnValNotUsed': 'CWE-401',
            
            # Use after free
            'useAfterFree': 'CWE-416',
            'deallocuse': 'CWE-416',
            'deallocDealloc': 'CWE-415',
            'doubleFree': 'CWE-415',
            
            # Integer overflows
            'integerOverflow': 'CWE-190',
            'signConversion': 'CWE-195',
            'negativeArraySize': 'CWE-129',
            
            # Uninitialized variables
            'uninitvar': 'CWE-457',
            'uninitdata': 'CWE-457',
            'uninitstring': 'CWE-457',
            'uninitStructMember': 'CWE-457',
            
            # Format string vulnerabilities
            'wrongPrintfScanfArgNum': 'CWE-685',
            'invalidPrintfArgType_sint': 'CWE-686',
            'invalidPrintfArgType_uint': 'CWE-686',
            
            # Division by zero
            'zerodiv': 'CWE-369',
            'zerodivcond': 'CWE-369',
            
            # Race conditions
            'raceAfterInterlockedDecrement': 'CWE-362',
            
            # Dangerous functions
            'bufferNotZeroTerminated': 'CWE-170',
            'terminateStrncpy': 'CWE-170',
            
            # Other common issues
            'invalidPointerCast': 'CWE-704',
            'va_list_usedBeforeStarted': 'CWE-664',
            'va_start_wrongParameter': 'CWE-664',
        }
        
        # CWE ID to human-readable name mapping
        self.cwe_names = {
            'CWE-119': 'Buffer Overflow',
            'CWE-120': 'Buffer Copy without Checking Size',
            'CWE-121': 'Stack-based Buffer Overflow',
            'CWE-122': 'Heap-based Buffer Overflow',
            'CWE-125': 'Out-of-bounds Read',
            'CWE-129': 'Improper Validation of Array Index',
            'CWE-170': 'Improper Null Termination',
            'CWE-190': 'Integer Overflow',
            'CWE-195': 'Signed to Unsigned Conversion Error',
            'CWE-362': 'Race Condition',
            'CWE-369': 'Divide By Zero',
            'CWE-398': 'Code Quality Issue',
            'CWE-401': 'Memory Leak',
            'CWE-404': 'Resource Leak',
            'CWE-415': 'Double Free',
            'CWE-416': 'Use After Free',
            'CWE-457': 'Uninitialized Variable',
            'CWE-476': 'NULL Pointer Dereference',
            'CWE-477': 'Use of Obsolete Function',
            'CWE-561': 'Dead Code',
            'CWE-563': 'Unused Variable',
            'CWE-570': 'Expression Always False',
            'CWE-571': 'Expression Always True',
            'CWE-664': 'Improper Control of Resource',
            'CWE-685': 'Function Call With Incorrect Number of Arguments',
            'CWE-686': 'Function Call With Incorrect Argument Type',
            'CWE-704': 'Incorrect Type Conversion',
            'CWE-775': 'Missing Release of File Descriptor',
            'CWE-788': 'Access of Memory Location After End of Buffer',
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
        """Check if Cppcheck is available (Docker or local)"""
        # Check Docker first
        if self.use_docker and self.docker_runner:
            if self.docker_runner.image_exists('vuln-scanner/cppcheck:latest'):
                return True
        
        # Fallback to local installation
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
    
    def _calculate_priority_score(self, rule_id: str, severity: str, cwe_id: str = None) -> float:
        """Calculate priority score based on rule, severity, and CWE
        
        Returns a score from 1.0 to 10.0 where:
        - 9.0-10.0: Critical (buffer overflows, use-after-free, double free)
        - 7.0-8.9: High (null pointer, memory leaks, integer overflow)
        - 4.0-6.9: Medium (resource leaks, uninitialized vars, obsolete functions)
        - 1.0-3.9: Low (style issues, dead code, unused variables)
        """
        # Base scores from Cppcheck severity
        base_scores = {
            'error': 8.0,      # Cppcheck 'error' = serious issues
            'warning': 6.0,    # Cppcheck 'warning' = potential issues
            'style': 2.0,      # Code style issues
            'performance': 3.0,
            'portability': 2.5,
            'information': 1.5,
            'unknown': 4.0
        }
        
        score = base_scores.get(severity, 4.0)
        
        # Critical vulnerabilities (memory corruption, exploitable)
        critical_rules = [
            'arrayIndexOutOfBounds',      # CWE-788: Out-of-bounds access
            'bufferAccessOutOfBounds',    # CWE-788: Buffer overflow
            'useAfterFree',               # CWE-416: Use after free
            'doubleFree',                 # CWE-415: Double free
            'deallocDealloc',             # CWE-415: Double free variant
        ]
        
        # High-risk vulnerabilities (crashes, data corruption)
        high_risk_rules = [
            'nullPointer',                # CWE-476: NULL deref (crash)
            'nullPointerArithmetic',      # CWE-476: NULL pointer math
            'memleak',                    # CWE-401: Memory leak
            'memleakOnRealloc',           # CWE-401: Memory leak variant
            'resourceLeak',               # CWE-404: Resource leak
            'integerOverflow',            # CWE-190: Integer overflow
            'signConversion',             # CWE-195: Sign conversion
            'zerodiv',                    # CWE-369: Division by zero
            'uninitvar',                  # CWE-457: Uninitialized variable
            'uninitdata',                 # CWE-457: Uninitialized data
        ]
        
        # Medium-risk vulnerabilities (quality issues, potential problems)
        medium_risk_rules = [
            'getsCalled',                 # CWE-477: Obsolete function
            'bufferNotZeroTerminated',    # CWE-170: String termination
            'invalidPointerCast',         # CWE-704: Type conversion
            'wrongPrintfScanfArgNum',     # CWE-685: Wrong arg count
        ]
        
        # Adjust score based on rule criticality
        if rule_id in critical_rules:
            score = max(score, 9.0)  # Critical: 9.0-10.0
        elif rule_id in high_risk_rules:
            score = max(score, 7.0)  # High: 7.0-8.9
        elif rule_id in medium_risk_rules:
            score = max(score, 5.0)  # Medium: 5.0-6.9
        
        # CWE-based adjustments (if CWE is available)
        if cwe_id:
            critical_cwes = ['CWE-788', 'CWE-787', 'CWE-416', 'CWE-415', 'CWE-119', 'CWE-120']
            high_cwes = ['CWE-476', 'CWE-401', 'CWE-404', 'CWE-190', 'CWE-369']
            
            if cwe_id in critical_cwes:
                score = max(score, 9.0)
            elif cwe_id in high_cwes:
                score = max(score, 7.0)
        
        # Style/quality issues should stay low
        if severity in ['style', 'information', 'performance', 'portability']:
            score = min(score, 4.0)
        
        # Dead code and unused variables are low priority
        if rule_id in ['unusedFunction', 'unusedVariable', 'unreadVariable', 'unusedAllocatedMemory']:
            score = min(score, 3.0)
            
        return min(score, 10.0)  # Cap at 10.0

    def _map_severity(self, cppcheck_severity: str) -> str:
        """Map Cppcheck severity to our standard levels"""
        return self.severity_map.get(cppcheck_severity, 'low')
    
    def _parse_xml_results(self, xml_file: str) -> Tuple[List[Dict], List[Dict]]:
        """Parse Cppcheck XML output into standardized format"""
        vulnerabilities = []
        patches = []
        seen_vulnerabilities = set()  # Track unique vulnerabilities to prevent duplicates
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Parse errors/warnings
            for error in root.findall('.//error'):
                # Get error attributes
                error_id = error.get('id', 'unknown')
                severity = error.get('severity', 'warning')
                msg = error.get('msg', 'No message')
                
                # Extract CWE ID from XML attribute or map from rule ID
                cwe_id = error.get('cwe')
                if cwe_id:
                    # Format as CWE-XXX if it's just a number
                    if cwe_id.isdigit():
                        cwe_id = f'CWE-{cwe_id}'
                    elif not cwe_id.startswith('CWE-'):
                        cwe_id = f'CWE-{cwe_id}'
                else:
                    # Map from rule ID if CWE not in XML
                    cwe_id = self.cwe_map.get(error_id)
                
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
                
                # Create unique identifier to prevent duplicates
                # Use only error_id, file, and line (not message) to avoid duplicates with different messages
                unique_id = f"{error_id}:{file_path}:{line}"
                if unique_id in seen_vulnerabilities:
                    continue  # Skip duplicate
                seen_vulnerabilities.add(unique_id)
                
                # Calculate priority score
                mapped_severity = self._map_severity(severity)
                priority_score = self._calculate_priority_score(error_id, severity, cwe_id)
                
                # Get human-readable CWE name
                cwe_name = self.cwe_names.get(cwe_id, 'Security Vulnerability') if cwe_id else 'Security Issue'
                
                vulnerability = {
                    'id': f'cppcheck_{error_id}_{line}',
                    'severity': mapped_severity,
                    'description': msg,
                    'file': file_path,
                    'line': line,
                    'tool': 'cppcheck',
                    'rule_id': error_id,
                    'priority_score': priority_score,
                    'cwe': cwe_id,  # CWE ID (e.g., CWE-788)
                    'cwe_name': cwe_name  # Human-readable name (e.g., "Buffer Overflow")
                }
                
                vulnerabilities.append(vulnerability)
        
        except ET.ParseError as e:
            logger.error(f"Failed to parse Cppcheck XML output: {e}")
        
        logger.info(f"[CPPCHECK] Parsed {len(vulnerabilities)} unique vulnerabilities from XML")
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
                    priority_score = self._calculate_priority_score('stderr_parse', severity)
                    
                    vulnerability = {
                        'id': f'cppcheck_stderr_{line_num}',
                        'severity': severity,
                        'description': ':'.join(parts[3:]).strip(),
                        'file': file_path,
                        'line': line_num,
                        'tool': 'cppcheck',
                        'rule_id': 'stderr_parse',
                        'priority_score': priority_score
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
                
                # Only use stderr parsing if XML parsing found no results
                if not vulnerabilities and result.stderr:
                    logger.info("[CPPCHECK] No XML results found, trying stderr parsing as fallback")
                    vulnerabilities, patches = self._parse_stderr_output(result.stderr)
                
                logger.info(f"[CPPCHECK] Local analysis found {len(vulnerabilities)} vulnerabilities")
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