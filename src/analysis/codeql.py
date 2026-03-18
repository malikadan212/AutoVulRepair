#!/usr/bin/env python3
"""
CodeQL Static Analysis Integration
Provides deep semantic analysis for multiple programming languages
"""
import os
import json
import subprocess
import tempfile
import shutil
from typing import List, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)


class CodeQLAnalyzer:
    """CodeQL static analysis tool integration"""
    
    def __init__(self):
        self.tool_name = 'codeql'
        self.timeout = 300  # 5 minutes default timeout
        
        # Try to use Docker if available
        try:
            from src.utils.docker_helper import DockerToolRunner
            self.docker_runner = DockerToolRunner()
            self.use_docker = self.docker_runner.is_docker_available()
            if self.use_docker:
                logger.info("[CODEQL] Docker is available, will use Docker for analysis")
        except Exception as e:
            logger.warning(f"[CODEQL] Failed to initialize Docker: {e}")
            self.docker_runner = None
            self.use_docker = False
    
    def is_available(self) -> bool:
        """Check if CodeQL is available on the system"""
        try:
            result = subprocess.run([self.tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def get_version(self) -> str:
        """Get CodeQL version information"""
        try:
            result = subprocess.run([self.tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return "Not available"
    
    def analyze(self, source_dir: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Run CodeQL analysis on source directory
        
        Args:
            source_dir: Path to source code directory
            
        Returns:
            Tuple of (vulnerabilities, patches)
        """
        # Detect languages first
        languages = self._detect_languages(source_dir)
        if not languages:
            logger.warning("No supported languages detected for CodeQL")
            return [], []
        
        logger.info(f"[CODEQL] Detected languages: {', '.join(languages)}")
        
        # Try Docker first if available
        if self.use_docker and self.docker_runner:
            logger.info("[CODEQL] Using Docker for analysis")
            try:
                # Create artifacts directory for output
                artifacts_dir = os.path.join(os.path.dirname(source_dir), 'artifacts')
                os.makedirs(artifacts_dir, exist_ok=True)
                
                # Create database directory
                db_path = os.path.join(artifacts_dir, 'codeql-db')
                os.makedirs(db_path, exist_ok=True)
                
                # Create SARIF output path
                sarif_path = os.path.join(artifacts_dir, 'codeql-results.sarif')
                
                # Create database via Docker
                logger.info(f"[CODEQL] Creating database for languages: {', '.join(languages)}")
                stdout, stderr, returncode = self.docker_runner.run_codeql_database_create(
                    source_dir, db_path, languages, timeout=600
                )
                
                if returncode != 0:
                    error_msg = f"CodeQL database creation failed with return code {returncode}: {stderr[:200]}"
                    logger.error(f"[CODEQL] {error_msg}")
                    raise RuntimeError(error_msg)
                
                logger.info("[CODEQL] Database created successfully")
                
                # Run analysis via Docker
                logger.info("[CODEQL] Running analysis queries")
                # Use the first detected language for query pack selection
                primary_language = languages[0]
                stdout, stderr, returncode = self.docker_runner.run_codeql_analyze(
                    db_path, sarif_path, language=primary_language, timeout=600
                )
                
                if returncode == 0 and os.path.exists(sarif_path):
                    logger.info(f"[CODEQL] Docker analysis completed, parsing results from {sarif_path}")
                    vulnerabilities, patches = self._parse_sarif_results(sarif_path)
                    logger.info(f"[CODEQL] Found {len(vulnerabilities)} vulnerabilities via Docker")
                    return vulnerabilities, patches
                else:
                    error_msg = f"CodeQL analysis failed with return code {returncode}"
                    logger.error(f"[CODEQL] {error_msg}")
                    raise RuntimeError(error_msg)
            except Exception as e:
                logger.error(f"[CODEQL] Docker analysis error: {e}")
                raise RuntimeError(f"CodeQL analysis failed: {e}")
        
        # Try local CodeQL
        if self.is_available():
            logger.info("[CODEQL] Using local CodeQL installation")
            try:
                # Create temporary database
                with tempfile.TemporaryDirectory() as temp_dir:
                    db_path = os.path.join(temp_dir, 'codeql-db')
                    sarif_path = os.path.join(temp_dir, 'results.sarif')
                    
                    # Create database
                    if not self._create_database(source_dir, db_path, languages):
                        raise RuntimeError("Failed to create CodeQL database")
                    
                    # Run analysis
                    if not self._run_analysis(db_path, sarif_path):
                        raise RuntimeError("Failed to run CodeQL analysis")
                    
                    # Parse results
                    return self._parse_sarif_results(sarif_path)
                    
            except Exception as e:
                logger.error(f"CodeQL analysis failed: {e}")
                raise RuntimeError(f"CodeQL analysis failed: {e}")
        
        # No analysis tool available - fail hard
        error_msg = "CodeQL is not available. Docker is not running or CodeQL is not installed."
        logger.error(f"[CODEQL] {error_msg}")
        raise RuntimeError(error_msg)
    
    def _detect_languages(self, source_dir: str) -> List[str]:
        """Detect programming languages in the source directory"""
        languages = []
        
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                
                if ext in ['.py'] and 'python' not in languages:
                    languages.append('python')
                elif ext in ['.js', '.ts', '.jsx', '.tsx'] and 'javascript' not in languages:
                    languages.append('javascript')
                elif ext in ['.java'] and 'java' not in languages:
                    languages.append('java')
                elif ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'] and 'cpp' not in languages:
                    languages.append('cpp')
                elif ext in ['.cs'] and 'csharp' not in languages:
                    languages.append('csharp')
                elif ext in ['.go'] and 'go' not in languages:
                    languages.append('go')
        
        return languages
    
    def _create_database(self, source_dir: str, db_path: str, languages: List[str]) -> bool:
        """Create CodeQL database"""
        try:
            language_str = ','.join(languages)
            logger.info(f"Creating CodeQL database for languages: {language_str}")
            
            result = subprocess.run([
                self.tool_name, 'database', 'create', db_path,
                f'--language={language_str}',
                '--source-root', source_dir
            ], capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode != 0:
                logger.error(f"Database creation failed: {result.stderr}")
                return False
            
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("Database creation timed out")
            return False
        except Exception as e:
            logger.error(f"Database creation error: {e}")
            return False
    
    def _run_analysis(self, db_path: str, sarif_path: str) -> bool:
        """Run CodeQL analysis queries"""
        try:
            logger.info("Running CodeQL analysis")
            
            result = subprocess.run([
                self.tool_name, 'database', 'analyze', db_path,
                '--format=sarif-latest',
                f'--output={sarif_path}',
                '--download'  # Download standard query packs
            ], capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode != 0:
                logger.error(f"Analysis failed: {result.stderr}")
                return False
            
            return os.path.exists(sarif_path)
            
        except subprocess.TimeoutExpired:
            logger.error("Analysis timed out")
            return False
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return False
    
    def _parse_sarif_results(self, sarif_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse SARIF results from CodeQL"""
        vulnerabilities = []
        patches = []
        
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', 'No description')
                    
                    # Get location info
                    locations = result.get('locations', [])
                    file_path = 'unknown'
                    line_num = 0
                    
                    if locations:
                        physical_location = locations[0].get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        file_path = artifact_location.get('uri', 'unknown')
                        region = physical_location.get('region', {})
                        line_num = region.get('startLine', 0)
                    
                    # Determine severity
                    level = result.get('level', 'note')
                    severity = self._map_severity(level)
                    
                    # Extract file stem
                    file_stem = os.path.splitext(os.path.basename(file_path))[0]
                    
                    vulnerability = {
                        'rule_id': rule_id,
                        'type': self._map_rule_to_type(rule_id),
                        'severity': severity,
                        'confidence': 'high',
                        'file': file_path,
                        'file_stem': file_stem,
                        'line': line_num,
                        'message': message,
                        'function': 'unknown',  # CodeQL doesn't always provide function names
                        'tool': 'CodeQL'
                    }
                    
                    vulnerabilities.append(vulnerability)
            
            # Generate patches
            for i, vuln in enumerate(vulnerabilities):
                patch = {
                    'id': f'codeql_patch_{i}',
                    'description': f'Fix CodeQL issue: {vuln["message"]}',
                    'content': self._generate_patch_content(vuln),
                    'confidence': 'medium'
                }
                patches.append(patch)
        
        except Exception as e:
            logger.error(f"Error parsing SARIF: {e}")
            return [], []
        
        return vulnerabilities, patches
    
    def _map_severity(self, level: str) -> str:
        """Map CodeQL severity levels to our standard levels"""
        mapping = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            'info': 'low'
        }
        return mapping.get(level, 'medium')
    
    def _map_rule_to_type(self, rule_id: str) -> str:
        """Map CodeQL rule IDs to vulnerability types"""
        if 'sql-injection' in rule_id:
            return 'SQL Injection'
        elif 'xss' in rule_id or 'cross-site-scripting' in rule_id:
            return 'Cross-Site Scripting'
        elif 'buffer-overflow' in rule_id:
            return 'Buffer Overflow'
        elif 'use-after-free' in rule_id:
            return 'Use After Free'
        elif 'null-pointer' in rule_id:
            return 'Null Pointer Dereference'
        elif 'code-injection' in rule_id:
            return 'Code Injection'
        elif 'path-traversal' in rule_id:
            return 'Path Traversal'
        else:
            return 'Security Issue'
    
    def _generate_patch_content(self, vulnerability: Dict[str, Any]) -> str:
        """Generate patch content based on vulnerability type"""
        rule_id = vulnerability['rule_id']
        file_path = vulnerability['file']
        line_num = vulnerability['line']
        
        if 'sql-injection' in rule_id:
            return f'''# Fix SQL Injection in {file_path}:{line_num}
# Replace string formatting with parameterized queries
# Before: cursor.execute(f"SELECT * FROM users WHERE id = {{user_id}}")
# After:  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'''
        
        elif 'buffer-overflow' in rule_id:
            return f'''# Fix Buffer Overflow in {file_path}:{line_num}
# Replace unsafe string functions with safe alternatives
# Before: strcpy(dest, src)
# After:  strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest) - 1] = '\\0';'''
        
        elif 'code-injection' in rule_id:
            return f'''# Fix Code Injection in {file_path}:{line_num}
# Avoid using eval() or exec() with user input
# Use safer alternatives like ast.literal_eval() for data parsing'''
        
        else:
            return f'''# Security Issue in {file_path}:{line_num}
# {vulnerability["message"]}
# Manual review and fix required'''