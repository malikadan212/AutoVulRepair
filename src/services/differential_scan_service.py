"""
Differential Scan Service
Handles scanning only changed files in pull requests for faster, targeted analysis
"""

import os
import tempfile
import shutil
import logging
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

from .github_service import GitHubService

logger = logging.getLogger(__name__)

class DifferentialScanService:
    """Service for scanning only changed files in pull requests"""
    
    def __init__(self, github_service: GitHubService):
        """Initialize with GitHub service for API access"""
        self.github_service = github_service
    
    def prepare_pr_scan(self, repo_full_name: str, pr_number: int, base_dir: str) -> Dict[str, Any]:
        """
        Prepare a pull request for differential scanning
        
        Args:
            repo_full_name: Repository name (owner/repo)
            pr_number: Pull request number
            base_dir: Base directory for scan preparation
            
        Returns:
            Dict with scan preparation results
        """
        try:
            logger.info(f"Preparing PR scan for {repo_full_name} PR #{pr_number}")
            
            # Get PR files
            pr_files = self.github_service.get_pull_request_files(repo_full_name, pr_number)
            
            if not pr_files:
                return {
                    'success': False,
                    'error': 'No files found in pull request or access denied',
                    'files': []
                }
            
            # Filter files for analysis
            scannable_files = self._filter_scannable_files(pr_files)
            
            if not scannable_files:
                return {
                    'success': False,
                    'error': 'No scannable source code files found in pull request',
                    'files': pr_files
                }
            
            # Clone repository and checkout PR
            repo_dir = self._clone_and_checkout_pr(repo_full_name, pr_number, base_dir)
            
            if not repo_dir:
                return {
                    'success': False,
                    'error': 'Failed to clone repository or checkout pull request',
                    'files': scannable_files
                }
            
            # Prepare file list for scanning
            scan_files = self._prepare_scan_files(repo_dir, scannable_files)
            
            return {
                'success': True,
                'repo_dir': repo_dir,
                'files': scan_files,
                'pr_files': pr_files,
                'scannable_count': len(scannable_files),
                'total_count': len(pr_files)
            }
            
        except Exception as e:
            logger.error(f"Error preparing PR scan: {e}")
            return {
                'success': False,
                'error': f'Failed to prepare PR scan: {str(e)}',
                'files': []
            }
    
    def _filter_scannable_files(self, pr_files: List[Dict]) -> List[Dict]:
        """Filter PR files to only include scannable source code files"""
        scannable_extensions = {
            '.c', '.cpp', '.cc', '.cxx', '.c++',
            '.h', '.hpp', '.hh', '.hxx', '.h++',
            '.py', '.js', '.ts', '.jsx', '.tsx',
            '.java', '.go', '.rs', '.php', '.rb',
            '.cs', '.swift', '.kt', '.scala'
        }
        
        scannable_files = []
        
        for file_info in pr_files:
            filename = file_info.get('filename', '')
            status = file_info.get('status', '')
            
            # Skip deleted files
            if status == 'removed':
                continue
            
            # Check file extension
            file_path = Path(filename)
            if file_path.suffix.lower() in scannable_extensions:
                scannable_files.append(file_info)
                logger.debug(f"Including scannable file: {filename}")
            else:
                logger.debug(f"Skipping non-scannable file: {filename}")
        
        logger.info(f"Filtered {len(scannable_files)} scannable files from {len(pr_files)} total files")
        return scannable_files
    
    def _clone_and_checkout_pr(self, repo_full_name: str, pr_number: int, base_dir: str) -> Optional[str]:
        """Clone repository and checkout the pull request"""
        try:
            # Create temporary directory for repo
            repo_dir = os.path.join(base_dir, f"pr_{pr_number}")
            os.makedirs(repo_dir, exist_ok=True)
            
            # Construct clone URL
            clone_url = f"https://github.com/{repo_full_name}.git"
            
            logger.info(f"Cloning repository {repo_full_name}")
            
            # Clone repository
            clone_cmd = [
                'git', 'clone', 
                '--depth', '50',  # Shallow clone for speed
                clone_url, 
                repo_dir
            ]
            
            result = subprocess.run(
                clone_cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Git clone failed: {result.stderr}")
                return None
            
            # Fetch PR
            logger.info(f"Fetching PR #{pr_number}")
            
            fetch_cmd = [
                'git', 'fetch', 'origin', 
                f'pull/{pr_number}/head:pr-{pr_number}'
            ]
            
            result = subprocess.run(
                fetch_cmd,
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.warning(f"Failed to fetch PR branch, using default branch: {result.stderr}")
                # Continue with default branch - still useful for scanning
            else:
                # Checkout PR branch
                checkout_cmd = ['git', 'checkout', f'pr-{pr_number}']
                
                result = subprocess.run(
                    checkout_cmd,
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    logger.warning(f"Failed to checkout PR branch: {result.stderr}")
                    # Continue with default branch
            
            logger.info(f"Repository prepared at: {repo_dir}")
            return repo_dir
            
        except subprocess.TimeoutExpired:
            logger.error("Git operation timed out")
            return None
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            return None
    
    def _prepare_scan_files(self, repo_dir: str, scannable_files: List[Dict]) -> List[Dict]:
        """Prepare list of files for scanning with full paths"""
        scan_files = []
        
        for file_info in scannable_files:
            filename = file_info.get('filename', '')
            full_path = os.path.join(repo_dir, filename)
            
            # Check if file exists (might be renamed/moved)
            if os.path.exists(full_path):
                scan_files.append({
                    'filename': filename,
                    'full_path': full_path,
                    'status': file_info.get('status', ''),
                    'additions': file_info.get('additions', 0),
                    'deletions': file_info.get('deletions', 0),
                    'changes': file_info.get('changes', 0)
                })
                logger.debug(f"Prepared scan file: {filename}")
            else:
                logger.warning(f"File not found in repository: {filename}")
        
        logger.info(f"Prepared {len(scan_files)} files for scanning")
        return scan_files
    
    def run_differential_analysis(self, scan_files: List[Dict], analysis_tool: str = 'cppcheck') -> Dict[str, Any]:
        """
        Run analysis only on the changed files
        
        Args:
            scan_files: List of files to scan with full paths
            analysis_tool: Analysis tool to use
            
        Returns:
            Analysis results
        """
        try:
            logger.info(f"Running differential analysis on {len(scan_files)} files with {analysis_tool}")
            
            if not scan_files:
                return {
                    'success': False,
                    'error': 'No files to scan',
                    'vulnerabilities': []
                }
            
            # Extract file paths for analysis
            file_paths = [f['full_path'] for f in scan_files]
            
            # Run analysis based on tool
            if analysis_tool == 'cppcheck':
                return self._run_cppcheck_differential(file_paths, scan_files)
            elif analysis_tool == 'codeql':
                return self._run_codeql_differential(file_paths, scan_files)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported analysis tool: {analysis_tool}',
                    'vulnerabilities': []
                }
                
        except Exception as e:
            logger.error(f"Error running differential analysis: {e}")
            return {
                'success': False,
                'error': f'Analysis failed: {str(e)}',
                'vulnerabilities': []
            }
    
    def _run_cppcheck_differential(self, file_paths: List[str], scan_files: List[Dict]) -> Dict[str, Any]:
        """Run Cppcheck analysis on specific files"""
        try:
            # Filter C/C++ files
            cpp_files = [
                path for path in file_paths 
                if any(path.lower().endswith(ext) for ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'])
            ]
            
            if not cpp_files:
                return {
                    'success': True,
                    'vulnerabilities': [],
                    'message': 'No C/C++ files found for Cppcheck analysis'
                }
            
            logger.info(f"Running Cppcheck on {len(cpp_files)} C/C++ files")
            
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
                output_file = temp_file.name
            
            try:
                # Run Cppcheck
                cmd = [
                    'cppcheck',
                    '--xml',
                    '--xml-version=2',
                    '--enable=all',
                    '--suppress=missingIncludeSystem',
                    '--suppress=unmatchedSuppression',
                    f'--output-file={output_file}'
                ] + cpp_files
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                # Parse results
                vulnerabilities = self._parse_cppcheck_results(output_file, scan_files)
                
                return {
                    'success': True,
                    'vulnerabilities': vulnerabilities,
                    'files_scanned': len(cpp_files),
                    'tool': 'cppcheck'
                }
                
            finally:
                # Clean up temp file
                if os.path.exists(output_file):
                    os.unlink(output_file)
                    
        except subprocess.TimeoutExpired:
            logger.error("Cppcheck analysis timed out")
            return {
                'success': False,
                'error': 'Analysis timed out',
                'vulnerabilities': []
            }
        except Exception as e:
            logger.error(f"Cppcheck analysis failed: {e}")
            return {
                'success': False,
                'error': f'Cppcheck failed: {str(e)}',
                'vulnerabilities': []
            }
    
    def _run_codeql_differential(self, file_paths: List[str], scan_files: List[Dict]) -> Dict[str, Any]:
        """Run CodeQL analysis on specific files"""
        # For now, return placeholder - CodeQL differential scanning is more complex
        return {
            'success': False,
            'error': 'CodeQL differential scanning not yet implemented',
            'vulnerabilities': []
        }
    
    def _parse_cppcheck_results(self, xml_file: str, scan_files: List[Dict]) -> List[Dict]:
        """Parse Cppcheck XML results and filter for scanned files"""
        vulnerabilities = []
        
        try:
            import xml.etree.ElementTree as ET
            
            if not os.path.exists(xml_file) or os.path.getsize(xml_file) == 0:
                logger.info("No Cppcheck results found")
                return []
            
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Get list of scanned file names for filtering
            scanned_filenames = {f['filename'] for f in scan_files}
            
            for error in root.findall('.//error'):
                # Get error details
                error_id = error.get('id', '')
                severity = error.get('severity', 'style')
                msg = error.get('msg', '')
                
                # Map Cppcheck severity to our severity levels
                if severity in ['error']:
                    our_severity = 'high'
                elif severity in ['warning', 'performance', 'portability']:
                    our_severity = 'medium'
                else:
                    our_severity = 'low'
                
                # Get location information
                for location in error.findall('location'):
                    file_path = location.get('file', '')
                    line = location.get('line', '0')
                    
                    # Check if this file is in our PR changes
                    relative_path = None
                    for filename in scanned_filenames:
                        if file_path.endswith(filename):
                            relative_path = filename
                            break
                    
                    if relative_path:
                        vulnerability = {
                            'id': f"cppcheck_{error_id}_{line}",
                            'tool': 'Cppcheck',
                            'severity': our_severity,
                            'type': error_id,
                            'description': msg,
                            'file': relative_path,
                            'line': int(line) if line.isdigit() else 0,
                            'cwe': self._get_cwe_for_cppcheck_error(error_id),
                            'cwe_description': self._get_cwe_description(error_id),
                            'cvss_score': self._get_cvss_score(our_severity),
                            'impact': self._get_impact_description(error_id),
                            'recommendation': self._get_recommendation(error_id),
                            'pr_context': True  # Mark as PR-specific finding
                        }
                        vulnerabilities.append(vulnerability)
            
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities in PR changes")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error parsing Cppcheck results: {e}")
            return []
    
    def _get_cwe_for_cppcheck_error(self, error_id: str) -> str:
        """Map Cppcheck error IDs to CWE numbers"""
        cwe_mapping = {
            'bufferAccessOutOfBounds': 'CWE-119',
            'arrayIndexOutOfBounds': 'CWE-125',
            'nullPointer': 'CWE-476',
            'memoryLeak': 'CWE-401',
            'uninitvar': 'CWE-457',
            'doubleFree': 'CWE-415',
            'useAfterFree': 'CWE-416',
            'integerOverflow': 'CWE-190',
            'divisionByZero': 'CWE-369'
        }
        return cwe_mapping.get(error_id, 'CWE-Other')
    
    def _get_cwe_description(self, error_id: str) -> str:
        """Get CWE description for error"""
        descriptions = {
            'bufferAccessOutOfBounds': 'Buffer Access with Incorrect Length Value',
            'arrayIndexOutOfBounds': 'Out-of-bounds Read',
            'nullPointer': 'NULL Pointer Dereference',
            'memoryLeak': 'Missing Release of Memory after Effective Lifetime',
            'uninitvar': 'Use of Uninitialized Variable'
        }
        return descriptions.get(error_id, 'Security Vulnerability')
    
    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score based on severity"""
        scores = {
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }
        return scores.get(severity, 3.0)
    
    def _get_impact_description(self, error_id: str) -> str:
        """Get impact description for error type"""
        impacts = {
            'bufferAccessOutOfBounds': 'Could lead to memory corruption, crashes, or code execution',
            'nullPointer': 'Application crash or denial of service',
            'memoryLeak': 'Resource exhaustion and performance degradation',
            'uninitvar': 'Unpredictable behavior or information disclosure'
        }
        return impacts.get(error_id, 'Potential security vulnerability')
    
    def _get_recommendation(self, error_id: str) -> str:
        """Get recommendation for fixing the error"""
        recommendations = {
            'bufferAccessOutOfBounds': 'Validate array bounds before access',
            'nullPointer': 'Check for null before dereferencing pointers',
            'memoryLeak': 'Ensure proper memory deallocation',
            'uninitvar': 'Initialize variables before use'
        }
        return recommendations.get(error_id, 'Review and fix the identified issue')
    
    def cleanup_scan_directory(self, repo_dir: str):
        """Clean up temporary scan directory"""
        try:
            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir)
                logger.info(f"Cleaned up scan directory: {repo_dir}")
        except Exception as e:
            logger.error(f"Error cleaning up scan directory: {e}")