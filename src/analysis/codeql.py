import os
import json
import shutil
import subprocess
import tempfile
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class CodeQLAnalyzer:
    """CodeQL static analysis implementation"""
    
    def __init__(self):
        self.tool_name = 'codeql'
        self.timeout = 300  # 5 minutes
    
    def is_available(self):
        """Check if CodeQL is available"""
        try:
            result = subprocess.run([self.tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def detect_languages(self, source_path):
        """Detect programming languages in the source directory"""
        languages = set()
        
        for root, dirs, files in os.walk(source_path):
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in ['.py']:
                    languages.add('python')
                elif ext in ['.js', '.ts', '.jsx', '.tsx']:
                    languages.add('javascript')
                elif ext in ['.java']:
                    languages.add('java')
                elif ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']:
                    languages.add('cpp')
                elif ext in ['.cs']:
                    languages.add('csharp')
                elif ext in ['.go']:
                    languages.add('go')
        
        return list(languages)
    
    def analyze(self, source_path, source_type, repo_url=None):
        """Run CodeQL analysis on the source code"""
        if not self.is_available():
            logger.warning("CodeQL not available, using simulation")
            return self._simulate_analysis()
        
        # Handle different source types
        if source_type == 'repo_url' and repo_url:
            return self._analyze_repo(repo_url)
        else:
            return self._analyze_local(source_path)
    
    def _analyze_repo(self, repo_url):
        """Analyze a GitHub repository"""
        temp_dir = None
        try:
            # Clone repository
            temp_dir = tempfile.mkdtemp(prefix='codeql_repo_')
            clone_result = subprocess.run([
                'git', 'clone', '--depth', '1', repo_url, temp_dir
            ], capture_output=True, text=True, timeout=60)
            
            if clone_result.returncode != 0:
                logger.error(f"Failed to clone repository: {clone_result.stderr}")
                return self._simulate_analysis()
            
            return self._analyze_local(temp_dir)
            
        except Exception as e:
            logger.error(f"Repository analysis failed: {e}")
            return self._simulate_analysis()
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _analyze_local(self, source_path):
        """Analyze local source code"""
        db_path = None
        try:
            # Detect languages
            languages = self.detect_languages(source_path)
            if not languages:
                logger.info("No supported languages detected")
                return self._simulate_analysis()
            
            # Create CodeQL database
            db_path = tempfile.mkdtemp(prefix='codeql_db_')
            language_str = ','.join(languages)
            
            logger.info(f"Creating CodeQL database for languages: {language_str}")
            create_result = subprocess.run([
                self.tool_name, 'database', 'create', db_path,
                f'--language={language_str}',
                '--source-root', source_path
            ], capture_output=True, text=True, timeout=self.timeout)
            
            if create_result.returncode != 0:
                logger.error(f"Database creation failed: {create_result.stderr}")
                return self._simulate_analysis()
            
            # Run analysis
            return self._run_queries(db_path)
            
        except Exception as e:
            logger.error(f"Local analysis failed: {e}")
            return self._simulate_analysis()
        finally:
            if db_path and os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)
    
    def _run_queries(self, db_path):
        """Run CodeQL queries and parse results"""
        sarif_path = None
        try:
            # Create temporary SARIF output file
            sarif_fd, sarif_path = tempfile.mkstemp(suffix='.sarif')
            os.close(sarif_fd)
            
            # Run CodeQL analysis with security queries
            query_result = subprocess.run([
                self.tool_name, 'database', 'analyze', db_path,
                '--format=sarif-latest',
                f'--output={sarif_path}',
                '--download'  # Download standard query packs
            ], capture_output=True, text=True, timeout=self.timeout)
            
            if query_result.returncode == 0 and os.path.exists(sarif_path):
                return self._parse_sarif_results(sarif_path)
            else:
                logger.error(f"Query execution failed: {query_result.stderr}")
                return self._simulate_analysis()
                
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            return self._simulate_analysis()
        finally:
            if sarif_path and os.path.exists(sarif_path):
                os.unlink(sarif_path)
    
    def _parse_sarif_results(self, sarif_path):
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
                    
                    vuln_id = f'codeql_{rule_id}_{len(vulnerabilities)}'
                    vulnerabilities.append({
                        'id': vuln_id,
                        'severity': severity,
                        'description': f'CodeQL: {message}',
                        'file': os.path.basename(file_path),
                        'line': line_num,
                        'tool': 'CodeQL',
                        'rule_id': rule_id
                    })
                    
                    # Generate patch suggestion
                    patches.append({
                        'id': f'patch_{vuln_id}',
                        'description': f'Review and fix CodeQL finding: {rule_id}',
                        'content': self._generate_patch_content(rule_id, message, file_path, line_num)
                    })
            
            logger.info(f"CodeQL found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities, patches
            
        except Exception as e:
            logger.error(f"Error parsing SARIF results: {e}")
            return self._simulate_analysis()
    
    def _map_severity(self, level):
        """Map CodeQL severity levels to our standard levels"""
        mapping = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            'info': 'low'
        }
        return mapping.get(level, 'medium')
    
    def _generate_patch_content(self, rule_id, message, file_path, line_num):
        """Generate patch content based on rule type"""
        return f"""# CodeQL Security Finding
# Rule: {rule_id}
# File: {file_path}:{line_num}
# Description: {message}
#
# Manual review required. Common fixes:
# - Validate and sanitize all user inputs
# - Use parameterized queries for database operations
# - Implement proper authentication and authorization
# - Use secure cryptographic functions
# - Handle exceptions properly
#
# Please review the specific finding and apply appropriate security measures."""
    
    def _simulate_analysis(self):
        """Simulate CodeQL analysis when tool is not available"""
        vulnerabilities = [
            {
                'id': 'codeql_sim_1',
                'severity': 'high',
                'description': 'CodeQL Simulation: Potential SQL injection vulnerability',
                'file': 'database.py',
                'line': 42,
                'tool': 'CodeQL (Simulated)',
                'rule_id': 'sql-injection'
            },
            {
                'id': 'codeql_sim_2',
                'severity': 'medium',
                'description': 'CodeQL Simulation: Unvalidated user input',
                'file': 'api.py',
                'line': 15,
                'tool': 'CodeQL (Simulated)',
                'rule_id': 'unvalidated-input'
            }
        ]
        
        patches = [
            {
                'id': 'patch_codeql_sim_1',
                'description': 'Fix SQL injection by using parameterized queries',
                'content': '''# SQL Injection Fix
# Use parameterized queries instead of string concatenation
# Before: query = f"SELECT * FROM users WHERE id = {user_id}"
# After: query = "SELECT * FROM users WHERE id = %s"
#        cursor.execute(query, (user_id,))'''
            },
            {
                'id': 'patch_codeql_sim_2',
                'description': 'Add input validation',
                'content': '''# Input Validation Fix
# Validate and sanitize all user inputs
# Example:
# if not isinstance(user_input, str) or len(user_input) > 100:
#     raise ValueError("Invalid input")
# sanitized_input = html.escape(user_input)'''
            }
        ]
        
        return vulnerabilities, patches