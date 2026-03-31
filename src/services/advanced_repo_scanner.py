"""
Advanced Repository Scanner
Comprehensive repository and PR scanning with intelligent analysis
"""

import os
import subprocess
import tempfile
import shutil
import logging
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from datetime import datetime
import json

# Try to import git, fallback to subprocess if not available
try:
    import git
    HAS_GITPYTHON = True
except ImportError:
    HAS_GITPYTHON = False
    logging.warning("GitPython not available, using subprocess for git operations")

from .github_service import GitHubService
from .differential_scan_service import DifferentialScanService
from src.analysis.cppcheck import CppcheckAnalyzer
from src.analysis.codeql import CodeQLAnalyzer

logger = logging.getLogger(__name__)

class AdvancedRepoScanner:
    """Advanced repository scanning with comprehensive analysis"""
    
    def __init__(self, github_service: GitHubService = None):
        self.github_service = github_service
        self.differential_service = DifferentialScanService(github_service) if github_service else None
        
        # Initialize analyzers
        self.cppcheck = CppcheckAnalyzer()
        self.codeql = CodeQLAnalyzer()
        
        # Scan configuration
        self.max_file_size = 10 * 1024 * 1024  # 10MB
        self.max_repo_size = 500 * 1024 * 1024  # 500MB
        self.timeout_seconds = 1800  # 30 minutes
        
    def scan_full_repository(self, repo_url: str, scan_id: str, 
                           analysis_tools: List[str] = None) -> Dict[str, Any]:
        """
        Comprehensive full repository scan
        
        Args:
            repo_url: Git repository URL
            scan_id: Unique scan identifier
            analysis_tools: List of tools to use ['cppcheck', 'codeql', 'semgrep']
        
        Returns:
            Comprehensive scan results
        """
        logger.info(f"Starting full repository scan: {repo_url}")
        
        if not analysis_tools:
            analysis_tools = ['cppcheck', 'codeql']
        
        results = {
            'scan_id': scan_id,
            'repo_url': repo_url,
            'scan_type': 'full_repository',
            'started_at': datetime.now().isoformat(),
            'status': 'processing',
            'analysis_tools': analysis_tools,
            'findings': [],
            'statistics': {},
            'metadata': {}
        }
        
        temp_dir = None
        try:
            # Clone repository
            temp_dir = tempfile.mkdtemp(prefix=f'repo_scan_{scan_id}_')
            repo_dir = self._clone_repository(repo_url, temp_dir)
            
            if not repo_dir:
                results['status'] = 'failed'
                results['error'] = 'Failed to clone repository'
                return results
            
            # Analyze repository structure
            repo_stats = self._analyze_repository_structure(repo_dir)
            results['statistics'] = repo_stats
            
            # Check repository size
            if repo_stats['total_size_mb'] > self.max_repo_size / (1024 * 1024):
                logger.warning(f"Repository size ({repo_stats['total_size_mb']:.1f}MB) exceeds limit")
                results['status'] = 'failed'
                results['error'] = f"Repository too large: {repo_stats['total_size_mb']:.1f}MB"
                return results
            
            # Run analysis tools
            all_findings = []
            tool_results = {}
            
            for tool in analysis_tools:
                logger.info(f"Running {tool} analysis...")
                tool_findings = self._run_analysis_tool(tool, repo_dir, repo_stats)
                
                if tool_findings:
                    all_findings.extend(tool_findings)
                    tool_results[tool] = {
                        'findings_count': len(tool_findings),
                        'status': 'completed'
                    }
                else:
                    tool_results[tool] = {
                        'findings_count': 0,
                        'status': 'failed'
                    }
            
            # Process and deduplicate findings
            processed_findings = self._process_findings(all_findings, repo_dir)
            
            results.update({
                'status': 'completed',
                'completed_at': datetime.now().isoformat(),
                'findings': processed_findings,
                'tool_results': tool_results,
                'total_findings': len(processed_findings),
                'analysis_summary': self._generate_analysis_summary(processed_findings, tool_results)
            })
            
            logger.info(f"Repository scan completed: {len(processed_findings)} findings")
            return results
            
        except Exception as e:
            logger.error(f"Repository scan failed: {e}")
            results.update({
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.now().isoformat()
            })
            return results
            
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def scan_pull_request(self, repo_full_name: str, pr_number: int, 
                         scan_id: str, analysis_tools: List[str] = None) -> Dict[str, Any]:
        """
        Comprehensive pull request differential scan
        
        Args:
            repo_full_name: Repository name (owner/repo)
            pr_number: Pull request number
            scan_id: Unique scan identifier
            analysis_tools: List of tools to use
        
        Returns:
            PR scan results with differential analysis
        """
        logger.info(f"Starting PR scan: {repo_full_name} PR #{pr_number}")
        
        if not self.github_service:
            return {
                'scan_id': scan_id,
                'status': 'failed',
                'error': 'GitHub service not configured'
            }
        
        if not analysis_tools:
            analysis_tools = ['cppcheck', 'codeql']
        
        results = {
            'scan_id': scan_id,
            'repo_full_name': repo_full_name,
            'pr_number': pr_number,
            'scan_type': 'pull_request',
            'started_at': datetime.now().isoformat(),
            'status': 'processing',
            'analysis_tools': analysis_tools,
            'findings': [],
            'pr_info': {},
            'changed_files': []
        }
        
        temp_dir = None
        try:
            # Get PR information
            pr_info = self._get_pr_info(repo_full_name, pr_number)
            results['pr_info'] = pr_info
            
            # Prepare PR scan
            temp_dir = tempfile.mkdtemp(prefix=f'pr_scan_{scan_id}_')
            pr_prep = self.differential_service.prepare_pr_scan(
                repo_full_name, pr_number, temp_dir
            )
            
            if not pr_prep['success']:
                results['status'] = 'failed'
                results['error'] = pr_prep['error']
                return results
            
            results['changed_files'] = pr_prep['files']
            
            # Run differential analysis
            all_findings = []
            tool_results = {}
            
            for tool in analysis_tools:
                logger.info(f"Running {tool} differential analysis...")
                tool_findings = self._run_differential_analysis(
                    tool, pr_prep['repo_dir'], pr_prep['files']
                )
                
                if tool_findings:
                    all_findings.extend(tool_findings)
                    tool_results[tool] = {
                        'findings_count': len(tool_findings),
                        'status': 'completed'
                    }
                else:
                    tool_results[tool] = {
                        'findings_count': 0,
                        'status': 'completed'
                    }
            
            # Process findings with PR context
            processed_findings = self._process_pr_findings(
                all_findings, pr_prep['files'], pr_prep['repo_dir']
            )
            
            results.update({
                'status': 'completed',
                'completed_at': datetime.now().isoformat(),
                'findings': processed_findings,
                'tool_results': tool_results,
                'total_findings': len(processed_findings),
                'files_analyzed': len(pr_prep['files'])
            })
            
            logger.info(f"PR scan completed: {len(processed_findings)} findings in {len(pr_prep['files'])} files")
            return results
            
        except Exception as e:
            logger.error(f"PR scan failed: {e}")
            results.update({
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.now().isoformat()
            })
            return results
            
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _clone_repository(self, repo_url: str, temp_dir: str) -> Optional[str]:
        """Clone repository with optimizations"""
        try:
            repo_dir = os.path.join(temp_dir, 'repo')
            
            # Use subprocess for git operations (more reliable in containers)
            logger.info(f"Cloning repository: {repo_url}")
            
            clone_cmd = [
                'git', 'clone',
                '--depth', '1',  # Shallow clone
                '--single-branch',  # Only default branch
                '--no-tags',  # Skip tags
                repo_url,
                repo_dir
            ]
            
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Repository cloned successfully to: {repo_dir}")
                return repo_dir
            else:
                logger.error(f"Git clone failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Repository clone timed out")
            return None
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            return None
    
    def _analyze_repository_structure(self, repo_dir: str) -> Dict[str, Any]:
        """Analyze repository structure and statistics"""
        stats = {
            'total_files': 0,
            'source_files': 0,
            'total_size_mb': 0,
            'languages': {},
            'file_extensions': {},
            'largest_files': [],
            'directory_structure': {}
        }
        
        # Language extensions mapping
        language_map = {
            '.c': 'C', '.h': 'C',
            '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++', '.hpp': 'C++', '.hxx': 'C++',
            '.py': 'Python',
            '.js': 'JavaScript', '.jsx': 'JavaScript',
            '.ts': 'TypeScript', '.tsx': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.cs': 'C#',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala'
        }
        
        source_extensions = set(language_map.keys())
        large_files = []
        
        try:
            for root, dirs, files in os.walk(repo_dir):
                # Skip .git directory
                if '.git' in dirs:
                    dirs.remove('.git')
                
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, repo_dir)
                    
                    try:
                        file_size = os.path.getsize(file_path)
                        stats['total_files'] += 1
                        stats['total_size_mb'] += file_size / (1024 * 1024)
                        
                        # Track file extensions
                        ext = Path(file).suffix.lower()
                        stats['file_extensions'][ext] = stats['file_extensions'].get(ext, 0) + 1
                        
                        # Track languages
                        if ext in language_map:
                            lang = language_map[ext]
                            stats['languages'][lang] = stats['languages'].get(lang, 0) + 1
                            stats['source_files'] += 1
                        
                        # Track large files
                        if file_size > 1024 * 1024:  # > 1MB
                            large_files.append({
                                'path': rel_path,
                                'size_mb': file_size / (1024 * 1024)
                            })
                            
                    except (OSError, IOError):
                        continue
            
            # Sort and limit large files
            large_files.sort(key=lambda x: x['size_mb'], reverse=True)
            stats['largest_files'] = large_files[:10]
            
            logger.info(f"Repository analysis: {stats['total_files']} files, "
                       f"{stats['source_files']} source files, "
                       f"{stats['total_size_mb']:.1f}MB")
            
        except Exception as e:
            logger.error(f"Error analyzing repository structure: {e}")
        
        return stats
    
    def _run_analysis_tool(self, tool: str, repo_dir: str, repo_stats: Dict) -> List[Dict]:
        """Run specific analysis tool on repository"""
        try:
            if tool == 'cppcheck' and self.cppcheck.is_available():
                return self._run_cppcheck_analysis(repo_dir, repo_stats)
            elif tool == 'codeql' and self.codeql.is_available():
                return self._run_codeql_analysis(repo_dir, repo_stats)
            else:
                logger.warning(f"Analysis tool '{tool}' not available")
                return []
                
        except Exception as e:
            logger.error(f"Error running {tool} analysis: {e}")
            return []
    
    def _run_cppcheck_analysis(self, repo_dir: str, repo_stats: Dict) -> List[Dict]:
        """Run Cppcheck analysis on repository"""
        if 'C' not in repo_stats['languages'] and 'C++' not in repo_stats['languages']:
            logger.info("No C/C++ files found, skipping Cppcheck")
            return []
        
        try:
            vulnerabilities, patches = self.cppcheck.analyze(repo_dir, 'repository')
            
            # Convert to standardized format with analysis method tracking
            findings = []
            for vuln in vulnerabilities:
                finding = {
                    'tool': 'cppcheck',
                    'analysis_method': 'docker' if self.cppcheck.use_docker else 'local',
                    'type': 'vulnerability',
                    'rule_id': vuln.get('rule_id', 'unknown'),
                    'severity': vuln.get('severity', 'medium'),
                    'message': vuln.get('message', ''),
                    'file_path': vuln.get('file', ''),
                    'line_number': vuln.get('line', 0),
                    'cwe': vuln.get('cwe'),
                    'confidence': vuln.get('confidence', 'medium')
                }
                
                # Check if this is from pattern-based fallback analysis
                if 'finding_id' in vuln and 'bufferoverflow' in vuln.get('finding_id', ''):
                    finding['analysis_method'] = 'pattern_fallback'
                    finding['message'] = f"[PATTERN-BASED DETECTION] {finding['message']}"
                    finding['confidence'] = 'low'  # Lower confidence for pattern-based
                    finding['tool_note'] = 'Generated by pattern matching (Docker/local tools unavailable)'
                
                findings.append(finding)
            
            analysis_method = findings[0]['analysis_method'] if findings else ('docker' if self.cppcheck.use_docker else 'local')
            logger.info(f"Cppcheck found {len(findings)} findings using {analysis_method} analysis")
            return findings
            
        except Exception as e:
            logger.error(f"Cppcheck analysis failed: {e}")
            return []
    
    def _run_codeql_analysis(self, repo_dir: str, repo_stats: Dict) -> List[Dict]:
        """Run CodeQL analysis on repository"""
        try:
            vulnerabilities, patches = self.codeql.analyze(repo_dir)
            
            # Convert to standardized format
            findings = []
            for vuln in vulnerabilities:
                findings.append({
                    'tool': 'codeql',
                    'type': 'vulnerability',
                    'rule_id': vuln.get('rule_id', 'unknown'),
                    'severity': vuln.get('severity', 'medium'),
                    'message': vuln.get('message', ''),
                    'file_path': vuln.get('file', ''),
                    'line_number': vuln.get('line', 0),
                    'cwe': vuln.get('cwe'),
                    'confidence': vuln.get('confidence', 'high')
                })
            
            logger.info(f"CodeQL found {len(findings)} findings")
            return findings
            
        except Exception as e:
            logger.error(f"CodeQL analysis failed: {e}")
            return []
    
    def _run_differential_analysis(self, tool: str, repo_dir: str, 
                                 changed_files: List[Dict]) -> List[Dict]:
        """Run analysis only on changed files"""
        try:
            # Create temporary directory with only changed files
            temp_analysis_dir = tempfile.mkdtemp(prefix='diff_analysis_')
            
            try:
                # Copy only changed files
                for file_info in changed_files:
                    src_path = os.path.join(repo_dir, file_info['filename'])
                    dst_path = os.path.join(temp_analysis_dir, file_info['filename'])
                    
                    if os.path.exists(src_path):
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)
                
                # Run analysis on filtered files
                if tool == 'cppcheck':
                    return self._run_cppcheck_analysis(temp_analysis_dir, {})
                elif tool == 'codeql':
                    return self._run_codeql_analysis(temp_analysis_dir, {})
                else:
                    return []
                    
            finally:
                shutil.rmtree(temp_analysis_dir, ignore_errors=True)
                
        except Exception as e:
            logger.error(f"Differential analysis failed: {e}")
            return []
    
    def _get_pr_info(self, repo_full_name: str, pr_number: int) -> Dict[str, Any]:
        """Get pull request information"""
        try:
            # Get PR details from GitHub API
            pulls = self.github_service.get_repository_pulls(repo_full_name, limit=100)
            
            for pr in pulls:
                if pr['number'] == pr_number:
                    return {
                        'title': pr['title'],
                        'state': pr['state'],
                        'created_at': pr['created_at'],
                        'updated_at': pr['updated_at'],
                        'head_sha': pr['head']['sha'],
                        'base_sha': pr['base']['sha'],
                        'author': pr['user']['login']
                    }
            
            return {'error': 'Pull request not found'}
            
        except Exception as e:
            logger.error(f"Error getting PR info: {e}")
            return {'error': str(e)}
    
    def _process_findings(self, findings: List[Dict], repo_dir: str) -> List[Dict]:
        """Process and deduplicate findings"""
        processed = []
        seen_findings = set()
        
        for finding in findings:
            # Create unique key for deduplication
            key = (
                finding.get('file_path', ''),
                finding.get('line_number', 0),
                finding.get('rule_id', ''),
                finding.get('message', '')
            )
            
            if key not in seen_findings:
                seen_findings.add(key)
                
                # Enhance finding with additional context
                enhanced_finding = finding.copy()
                enhanced_finding.update({
                    'finding_id': f"{finding.get('tool', 'unknown')}_{len(processed)}",
                    'detected_at': datetime.now().isoformat(),
                    'file_exists': os.path.exists(
                        os.path.join(repo_dir, finding.get('file_path', ''))
                    ) if repo_dir else False
                })
                
                processed.append(enhanced_finding)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        processed.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 3))
        
        return processed
    
    def _process_pr_findings(self, findings: List[Dict], changed_files: List[Dict], 
                           repo_dir: str) -> List[Dict]:
        """Process findings with PR context"""
        # Create mapping of changed files
        changed_file_map = {f['filename']: f for f in changed_files}
        
        processed = []
        for finding in findings:
            file_path = finding.get('file_path', '')
            
            # Only include findings in changed files
            if file_path in changed_file_map:
                enhanced_finding = finding.copy()
                file_info = changed_file_map[file_path]
                
                enhanced_finding.update({
                    'finding_id': f"pr_{finding.get('tool', 'unknown')}_{len(processed)}",
                    'detected_at': datetime.now().isoformat(),
                    'pr_context': {
                        'file_status': file_info.get('status', 'unknown'),
                        'additions': file_info.get('additions', 0),
                        'deletions': file_info.get('deletions', 0),
                        'changes': file_info.get('changes', 0)
                    }
                })
                
                processed.append(enhanced_finding)
        
        return self._process_findings(processed, repo_dir)
    
    def get_scan_capabilities(self) -> Dict[str, Any]:
        """Get scanner capabilities and tool availability"""
        # Get actual supported languages from available tools
        all_supported_languages = set()
        available_tools = {}
        
        # Cppcheck
        cppcheck_available = self.cppcheck.is_available()
        cppcheck_languages = ['C', 'C++']
        available_tools['cppcheck'] = {
            'available': cppcheck_available,
            'version': getattr(self.cppcheck, 'get_version', lambda: 'Unknown')(),
            'languages': cppcheck_languages
        }
        if cppcheck_available:
            all_supported_languages.update(cppcheck_languages)
        
        # CodeQL
        codeql_available = self.codeql.is_available()
        codeql_languages = ['C', 'C++', 'Python', 'JavaScript', 'TypeScript', 'Java', 'C#', 'Go']
        available_tools['codeql'] = {
            'available': codeql_available,
            'version': getattr(self.codeql, 'get_version', lambda: 'Unknown')(),
            'languages': codeql_languages
        }
        if codeql_available:
            all_supported_languages.update(codeql_languages)
        
        return {
            'tools': available_tools,
            'scan_types': ['full_repository', 'pull_request', 'differential'],
            'supported_languages': sorted(list(all_supported_languages)),  # Only languages actually supported by available tools
            'limits': {
                'max_file_size_mb': self.max_file_size / (1024 * 1024),
                'max_repo_size_mb': self.max_repo_size / (1024 * 1024),
                'timeout_minutes': self.timeout_seconds / 60
            }
        }
    
    def _generate_analysis_summary(self, findings: List[Dict], tool_results: Dict) -> Dict[str, Any]:
        """Generate summary of analysis methods used"""
        summary = {
            'tools_used': [],
            'analysis_methods': {},
            'fallback_used': False,
            'docker_used': False,
            'local_used': False
        }
        
        # Count analysis methods
        method_counts = {}
        for finding in findings:
            method = finding.get('analysis_method', 'unknown')
            method_counts[method] = method_counts.get(method, 0) + 1
            
            if method == 'pattern_fallback':
                summary['fallback_used'] = True
            elif method == 'docker':
                summary['docker_used'] = True
            elif method == 'local':
                summary['local_used'] = True
        
        summary['analysis_methods'] = method_counts
        summary['tools_used'] = list(tool_results.keys())
        
        # Generate user-friendly message
        if summary['fallback_used']:
            if summary['docker_used'] or summary['local_used']:
                summary['message'] = "Mixed analysis: Some findings from real tools, some from pattern matching"
                summary['warning'] = "Some vulnerabilities detected using pattern matching (lower confidence)"
            else:
                summary['message'] = "Pattern-based analysis only (Docker/local tools unavailable)"
                summary['warning'] = "All findings are from pattern matching - install tools for better accuracy"
        elif summary['docker_used']:
            summary['message'] = "Full Docker-based static analysis completed"
        elif summary['local_used']:
            summary['message'] = "Local tool-based static analysis completed"
        else:
            summary['message'] = "No analysis performed"
        
        return summary