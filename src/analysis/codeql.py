import os
import json
import shutil
import subprocess
import tempfile
import logging
from pathlib import Path

# Try to import Docker helper, fall back to direct execution if unavailable
try:
    from src.utils.docker_helper import DockerToolRunner
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

logger = logging.getLogger(__name__)

class CodeQLAnalyzer:
    """CodeQL static analysis implementation"""
    
    def __init__(self):
        self.tool_name = 'codeql'
        self.timeout = 1100  # 15 minutes - CodeQL analysis can take a while
        self.docker_runner = None
        
        # Try to initialize Docker runner
        if DOCKER_AVAILABLE:
            try:
                self.docker_runner = DockerToolRunner()
                if self.docker_runner.is_docker_available():
                    logger.info("[CODEQL_INIT] Docker-based CodeQL available")
                logger.debug(f"[CODEQL_INIT] Docker runner initialized: {self.docker_runner is not None}")
            except Exception as e:
                logger.warning(f"[CODEQL_INIT] Failed to initialize Docker runner: {e}")
                self.docker_runner = None
        else:
            logger.debug("[CODEQL_INIT] Docker helper not available")
    
    def is_available(self):
        """Check if CodeQL is available (via Docker or direct)"""
        logger.debug(f"[CODEQL_AVAIL] Starting availability check, docker_runner: {self.docker_runner is not None}")
        
        # Try Docker first (preferred) - just check if image exists, don't test every time
        if self.docker_runner:
            try:
                logger.debug("[CODEQL_AVAIL] Checking Docker availability...")
                docker_avail = self.docker_runner.is_docker_available()
                logger.debug(f"[CODEQL_AVAIL] Docker available: {docker_avail}")
                
                if docker_avail:
                    logger.debug("[CODEQL_AVAIL] Checking if Docker image exists...")
                    # Check for our tagged image first
                    image_exists = self.docker_runner.image_exists('vuln-scanner/codeql:latest')
                    if not image_exists:
                        # Also check for Microsoft container
                        image_exists = self.docker_runner.image_exists('mcr.microsoft.com/cstsectools/codeql-container:latest')
                    
                    logger.debug(f"[CODEQL_AVAIL] Image exists: {image_exists}")
                    
                    if image_exists:
                        logger.info("[CODEQL_AVAIL] Docker image found - CodeQL available via Docker")
                        return True
                    else:
                        logger.warning("[CODEQL_AVAIL] Docker image 'vuln-scanner/codeql:latest' or 'mcr.microsoft.com/cstsectools/codeql-container:latest' not found")
                else:
                    logger.warning("[CODEQL_AVAIL] Docker is not available")
            except Exception as e:
                logger.error(f"[CODEQL_AVAIL] Docker check error: {e}", exc_info=True)
        else:
            logger.warning("[CODEQL_AVAIL] docker_runner is None - Docker not initialized")
        
        # Fallback to direct execution
        logger.debug("[CODEQL_AVAIL] Checking direct installation...")
        try:
            result = subprocess.run([self.tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("[CODEQL_AVAIL] Direct installation found")
                return True
            else:
                logger.debug(f"[CODEQL_AVAIL] Direct check failed with returncode: {result.returncode}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"[CODEQL_AVAIL] Direct installation not found: {type(e).__name__}")
        
        logger.warning("[CODEQL_AVAIL] CodeQL not available (neither Docker nor direct)")
        return False
    
    def detect_languages(self, source_path):
        """Detect programming languages in the source directory"""
        languages = set()
        
        for root, dirs, files in os.walk(source_path):
            # Skip common dependency/build directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'vendor', 'venv', 'dist', 'build']]
            
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
        
        detected = list(languages)
        if detected:
            logger.info(f"[LANGUAGE_DETECT] Detected languages: {', '.join(detected)}")
        return detected
    
    def analyze(self, source_path, source_type, repo_url=None, artifacts_dir=None):
        """Run CodeQL analysis on the source code
        
        Args:
            source_path: Path to source directory (used as clone destination for repos)
            source_type: Type of source ('repo_url', 'zip', 'code_snippet')
            repo_url: GitHub repository URL (if source_type is 'repo_url')
            artifacts_dir: Directory to store analysis artifacts
        """
        if not self.is_available():
            logger.warning("CodeQL not available, using simulation")
            return self._simulate_analysis()
        
        # Handle different source types
        if source_type == 'repo_url' and repo_url:
            # Clone to source_path to preserve the repository for signature extraction
            return self._analyze_repo(repo_url, artifacts_dir=artifacts_dir, clone_dir=source_path)
        else:
            return self._analyze_local(source_path, artifacts_dir=artifacts_dir)
    
    def _analyze_repo(self, repo_url, artifacts_dir=None, clone_dir=None):
        """Analyze a GitHub repository
        
        Args:
            repo_url: GitHub repository URL
            artifacts_dir: Directory to store analysis artifacts
            clone_dir: Directory to clone repository to (if None, uses temp directory)
        """
        logger.info(f"[CODEQL_REPO] Starting repository analysis for: {repo_url}")
        temp_dir = None
        cleanup_needed = False
        
        try:
            # Determine clone directory
            if clone_dir:
                # Use provided directory (persistent)
                target_dir = clone_dir
                
                # Ensure parent directory exists
                parent_dir = os.path.dirname(target_dir)
                os.makedirs(parent_dir, exist_ok=True)
                
                # If directory already exists with content, use it (already cloned)
                if os.path.exists(target_dir) and os.listdir(target_dir):
                    logger.info(f"[CODEQL_REPO] Directory already contains files, using existing: {target_dir}")
                else:
                    # Remove empty directory if it exists (git clone fails with existing dir)
                    if os.path.exists(target_dir):
                        try:
                            os.rmdir(target_dir)
                        except OSError:
                            pass  # Directory not empty, that's fine
                    
                    logger.info(f"[CODEQL_REPO] Cloning repository to persistent directory: {target_dir}")
                    
                    # Clone repository
                    clone_result = subprocess.run([
                        'git', 'clone', '--depth', '1', repo_url, target_dir
                    ], capture_output=True, text=True, timeout=60)
                    
                    if clone_result.returncode != 0:
                        logger.error(f"[CODEQL_REPO] Failed to clone repository: {clone_result.stderr}")
                        return self._simulate_analysis()
                    
                    logger.info(f"[CODEQL_REPO] Repository cloned successfully")
            else:
                # Use temporary directory (will be cleaned up)
                target_dir = tempfile.mkdtemp(prefix='codeql_repo_')
                temp_dir = target_dir
                cleanup_needed = True
                logger.info(f"[CODEQL_REPO] Cloning repository to temporary directory: {target_dir}")
                
                # Clone repository
                clone_result = subprocess.run([
                    'git', 'clone', '--depth', '1', repo_url, target_dir
                ], capture_output=True, text=True, timeout=60)
                
                if clone_result.returncode != 0:
                    logger.error(f"[CODEQL_REPO] Failed to clone repository: {clone_result.stderr}")
                    return self._simulate_analysis()
            
            logger.info(f"[CODEQL_REPO] Repository cloned successfully, starting local analysis")
            return self._analyze_local(target_dir, artifacts_dir=artifacts_dir)
            
        except Exception as e:
            logger.error(f"[CODEQL_REPO] Repository analysis failed: {e}")
            return self._simulate_analysis()
        finally:
            # Only cleanup if we used a temporary directory
            if cleanup_needed and temp_dir and os.path.exists(temp_dir):
                logger.info(f"[CODEQL_REPO] Cleaning up temporary directory: {temp_dir}")
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _analyze_local(self, source_path, artifacts_dir=None):
        """Analyze local source code"""
        logger.info(f"[CODEQL_LOCAL] Starting local analysis for path: {source_path}")
        db_path = None
        try:
            # Detect languages
            logger.info(f"[CODEQL_LOCAL] Detecting languages in source code...")
            languages = self.detect_languages(source_path)
            if not languages:
                logger.warning(f"[CODEQL_LOCAL] No supported languages detected in {source_path}")
                return self._simulate_analysis()
            
            language_str = ','.join(languages)
            logger.info(f"[CODEQL_LOCAL] Detected languages: {language_str}")
            
            # Create CodeQL database
            db_path = tempfile.mkdtemp(prefix='codeql_db_')
            logger.info(f"[CODEQL_LOCAL] Creating CodeQL database at: {db_path}")
            logger.info(f"[CODEQL_LOCAL] This step may take 2-5 minutes for large repositories...")
            
            # Try Docker first (preferred method)
            db_created = False
            if self.docker_runner and self.docker_runner.is_docker_available():
                # Check for our tagged image or Microsoft container
                image_exists = self.docker_runner.image_exists('vuln-scanner/codeql:latest')
                if not image_exists:
                    image_exists = self.docker_runner.image_exists('mcr.microsoft.com/cstsectools/codeql-container:latest')
                
                if image_exists:
                    logger.info("[CODEQL_LOCAL] Creating CodeQL database via Docker container (this may take several minutes)...")
                    try:
                        stdout, stderr, return_code = self.docker_runner.run_codeql_database_create(
                            source_path,
                            db_path,
                            languages,
                            timeout=self.timeout
                        )
                        if return_code == 0:
                            db_created = True
                            logger.info("Successfully created CodeQL database via Docker")
                        else:
                            logger.warning(f"CodeQL database creation via Docker failed: {stderr}")
                    except Exception as e:
                        logger.warning(f"Docker database creation failed, falling back to direct: {e}")
            
            # Fallback to direct execution
            if not db_created:
                logger.info("Creating CodeQL database directly (not via Docker)")
                
                # Build command arguments - let autobuild detect build system
                cmd_args = [
                    self.tool_name, 'database', 'create', db_path,
                    f'--language={language_str}',
                    '--source-root', source_path
                ]
                
                logger.info(f"[CODEQL_DIRECT] Letting autobuild detect build system for {language_str}")
                
                create_result = subprocess.run(
                    cmd_args,
                    capture_output=True, 
                    text=True, 
                    timeout=self.timeout
                )
                
                if create_result.returncode != 0:
                    logger.error(f"Database creation failed: {create_result.stderr}")
                    return self._simulate_analysis()
            
            # Run analysis
            return self._run_queries(db_path, languages, artifacts_dir=artifacts_dir)
            
        except Exception as e:
            logger.error(f"Local analysis failed: {e}")
            return self._simulate_analysis()
        finally:
            if db_path and os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)
    
    def _run_queries(self, db_path, languages, artifacts_dir=None):
        """Run CodeQL queries and parse results"""
        sarif_path = None
        try:
            # Create temporary SARIF output file
            if artifacts_dir:
                os.makedirs(artifacts_dir, exist_ok=True)
                sarif_path = os.path.join(artifacts_dir, 'codeql-results.sarif')
            else:
                sarif_fd, sarif_path = tempfile.mkstemp(suffix='.sarif')
                os.close(sarif_fd)
            
            # Try Docker first (preferred method)
            analysis_success = False
            if self.docker_runner and self.docker_runner.is_docker_available():
                # Check for either our tagged image or Microsoft container
                has_image = (self.docker_runner.image_exists('vuln-scanner/codeql:latest') or 
                           self.docker_runner.image_exists('mcr.microsoft.com/cstsectools/codeql-container:latest'))
                if has_image:
                    logger.info("Running CodeQL analysis via Docker container")
                    try:
                        # Get primary language from detected languages
                        primary_language = languages[0] if languages else 'javascript'
                        stdout, stderr, return_code = self.docker_runner.run_codeql_analyze(
                            db_path,
                            sarif_path,
                            language=primary_language,
                            timeout=self.timeout
                        )
                        if return_code == 0 and os.path.exists(sarif_path):
                            analysis_success = True
                            logger.info("Successfully ran CodeQL analysis via Docker")
                        else:
                            logger.warning(f"CodeQL analysis via Docker failed: {stderr}")
                    except Exception as e:
                        logger.warning(f"Docker analysis failed, falling back to direct: {e}")
            
            # Fallback to direct execution
            if not analysis_success:
                logger.info("Running CodeQL analysis directly (not via Docker)")
                query_result = subprocess.run([
                    self.tool_name, 'database', 'analyze', db_path,
                    '--format=sarif-latest',
                    f'--output={sarif_path}',
                    '--download'  # Download standard query packs
                ], capture_output=True, text=True, timeout=self.timeout)
                
                if query_result.returncode == 0 and os.path.exists(sarif_path):
                    analysis_success = True
                else:
                    logger.error(f"Query execution failed: {query_result.stderr}")
            
            if analysis_success and os.path.exists(sarif_path):
                return self._parse_sarif_results(sarif_path)
            else:
                return self._simulate_analysis()
                
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            return self._simulate_analysis()
        finally:
            if (not artifacts_dir) and sarif_path and os.path.exists(sarif_path):
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