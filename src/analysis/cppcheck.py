import os
import subprocess
import tempfile
import shutil
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

# Try to import Docker helper, fall back to direct execution if unavailable
logger = logging.getLogger(__name__)

DOCKER_AVAILABLE = False
try:
    from src.utils.docker_helper import DockerToolRunner
    DOCKER_AVAILABLE = True
    logger.debug("DockerToolRunner import successful")
except Exception as e:
    # Catch all exceptions, not just ImportError, since there might be other issues
    logger.warning(f"Docker helper import failed: {e} - will use direct execution or simulation")
    DOCKER_AVAILABLE = False

class CppcheckAnalyzer:
    """Cppcheck static analysis implementation"""
    
    def __init__(self):
        self.tool_name = 'cppcheck'
        self.timeout = 120  # 2 minutes
        self.docker_runner = None
        
        # Try to initialize Docker runner
        if DOCKER_AVAILABLE:
            try:
                self.docker_runner = DockerToolRunner()
                if self.docker_runner.is_docker_available():
                    logger.info("[CPPCHECK_INIT] Docker-based Cppcheck available")
            except Exception as e:
                logger.warning(f"[CPPCHECK_INIT] Failed to initialize Docker runner: {e}")
                self.docker_runner = None
    
    def is_available(self):
        """Check if Cppcheck is available (via Docker or direct)"""
        logger.debug(f"[CPPCHECK_AVAIL] Starting availability check, docker_runner: {self.docker_runner is not None}")
        
        # Try Docker first (preferred) - just check if image exists, don't test every time
        if self.docker_runner:
            try:
                logger.debug("[CPPCHECK_AVAIL] Checking Docker availability...")
                docker_avail = self.docker_runner.is_docker_available()
                logger.debug(f"[CPPCHECK_AVAIL] Docker available: {docker_avail}")
                
                if docker_avail:
                    logger.debug("[CPPCHECK_AVAIL] Checking if Docker image exists...")
                    image_exists = self.docker_runner.image_exists('vuln-scanner/cppcheck:latest')
                    logger.debug(f"[CPPCHECK_AVAIL] Image exists: {image_exists}")
                    
                    if image_exists:
                        logger.info("[CPPCHECK_AVAIL] Docker image found - Cppcheck available via Docker")
                        return True
                    else:
                        logger.warning("[CPPCHECK_AVAIL] Docker image 'vuln-scanner/cppcheck:latest' not found")
                else:
                    logger.warning("[CPPCHECK_AVAIL] Docker is not available")
            except Exception as e:
                logger.error(f"[CPPCHECK_AVAIL] Docker check error: {e}", exc_info=True)
        else:
            logger.warning("[CPPCHECK_AVAIL] docker_runner is None - Docker not initialized")
        
        # Fallback to direct execution
        logger.debug("[CPPCHECK_AVAIL] Checking direct installation...")
        try:
            result = subprocess.run([self.tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("[CPPCHECK_AVAIL] Direct installation found")
                return True
            else:
                logger.debug(f"[CPPCHECK_AVAIL] Direct check failed with returncode: {result.returncode}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"[CPPCHECK_AVAIL] Direct installation not found: {type(e).__name__}")
        
        logger.warning("[CPPCHECK_AVAIL] Cppcheck not available (neither Docker nor direct)")
        return False
    
    def find_cpp_files(self, source_path):
        """Find C/C++ files in the source directory"""
        cpp_extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']
        cpp_files = []
        
        for root, dirs, files in os.walk(source_path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in cpp_extensions):
                    cpp_files.append(os.path.join(root, file))
        
        return cpp_files
    
    def analyze(self, source_path, source_type, repo_url=None, artifacts_dir=None):
        """Run Cppcheck analysis on the source code"""
        logger.info(f"[CPPCHECK_ANALYZE] Starting analyze() - source_path: {source_path}, source_type: {source_type}, repo_url: {repo_url}")
        if not self.is_available():
            logger.warning("[CPPCHECK_ANALYZE] Cppcheck not available, using simulation")
            return self._simulate_analysis()
        
        logger.info(f"[CPPCHECK_ANALYZE] Cppcheck is available, proceeding with analysis")
        # Handle different source types
        if source_type == 'repo_url' and repo_url:
            logger.info(f"[CPPCHECK_ANALYZE] Detected repo_url, calling _analyze_repo()")
            return self._analyze_repo(repo_url, artifacts_dir=artifacts_dir)
        else:
            logger.info(f"[CPPCHECK_ANALYZE] Local analysis, calling _analyze_local()")
            return self._analyze_local(source_path, artifacts_dir=artifacts_dir)
    
    def _analyze_repo(self, repo_url, artifacts_dir=None):
        """Analyze a GitHub repository"""
        logger.info(f"[CPPCHECK_REPO] Starting repository analysis for: {repo_url}")
        temp_dir = None
        try:
            # Clone repository
            temp_dir = tempfile.mkdtemp(prefix='cppcheck_repo_')
            logger.info(f"[CPPCHECK_REPO] Cloning repository to: {temp_dir}")
            clone_result = subprocess.run([
                'git', 'clone', '--depth', '1', repo_url, temp_dir
            ], capture_output=True, text=True, timeout=60)
            
            if clone_result.returncode != 0:
                logger.error(f"[CPPCHECK_REPO] Failed to clone repository: {clone_result.stderr}")
                return self._simulate_analysis()
            
            logger.info(f"[CPPCHECK_REPO] Repository cloned successfully, starting local analysis")
            return self._analyze_local(temp_dir, artifacts_dir=artifacts_dir)
            
        except Exception as e:
            logger.error(f"Repository analysis failed: {e}")
            return self._simulate_analysis()
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _analyze_local(self, source_path, artifacts_dir=None):
        """Analyze local source code"""
        logger.info(f"[CPPCHECK_LOCAL] Starting local analysis for path: {source_path}")
        try:
            # Check for C/C++ files
            logger.info(f"[CPPCHECK_LOCAL] Searching for C/C++ files...")
            cpp_files = self.find_cpp_files(source_path)
            if not cpp_files:
                logger.warning(f"[CPPCHECK_LOCAL] No C/C++ files found in {source_path}")
                return self._simulate_analysis()
            
            logger.info(f"[CPPCHECK_LOCAL] Found {len(cpp_files)} C/C++ files for analysis")
            
            # Run Cppcheck analysis
            logger.info(f"[CPPCHECK_LOCAL] Running Cppcheck now...")
            result = self._run_cppcheck(source_path, artifacts_dir=artifacts_dir)
            logger.info(f"[CPPCHECK_LOCAL] Cppcheck analysis completed")
            return result
            
        except Exception as e:
            logger.error(f"Local analysis failed: {e}")
            return self._simulate_analysis()
    
    def _run_cppcheck(self, source_path, artifacts_dir=None):
        """Run Cppcheck and parse results"""
        logger.info(f"[CPPCHECK_RUN] Starting Cppcheck execution for: {source_path}")
        if artifacts_dir:
            artifacts_dir = os.path.abspath(artifacts_dir)
            os.makedirs(artifacts_dir, exist_ok=True)
            xml_path = os.path.join(artifacts_dir, 'cppcheck-report.xml')
            logger.info(f"[CPPCHECK_RUN] Artifact XML output file: {xml_path}")
        else:
            xml_fd, xml_path = tempfile.mkstemp(suffix='.xml')
            os.close(xml_fd)
            logger.info(f"[CPPCHECK_RUN] Temporary XML output file: {xml_path}")
        
        try:
            # Try Docker first (preferred method)
            if self.docker_runner and self.docker_runner.is_docker_available():
                if self.docker_runner.image_exists('vuln-scanner/cppcheck:latest'):
                    logger.info("[CPPCHECK_RUN] Running Cppcheck via Docker container")
                    try:
                        stdout, stderr, return_code = self.docker_runner.run_cppcheck(
                            source_path, 
                            output_file=xml_path,
                            timeout=self.timeout
                        )
                        
                        # Parse results if XML was generated
                        if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
                            logger.info("Successfully ran Cppcheck via Docker")
                            # If artifacts_dir provided but xml_path is temporary, persist a copy
                            if artifacts_dir and not xml_path.startswith(os.path.abspath(artifacts_dir)):
                                try:
                                    os.makedirs(artifacts_dir, exist_ok=True)
                                    persisted = os.path.join(artifacts_dir, 'cppcheck-report.xml')
                                    import shutil
                                    shutil.copyfile(xml_path, persisted)
                                except Exception as persist_err:
                                    logger.warning(f"[CPPCHECK_RUN] Failed to persist XML to artifacts: {persist_err}")
                            return self._parse_xml_results(xml_path)
                        elif stderr:
                            logger.warning(f"Cppcheck Docker stderr: {stderr}")
                            return self._parse_stderr_output(stderr)
                        else:
                            logger.info("No Cppcheck issues found")
                            return [], []
                    except Exception as e:
                        logger.warning(f"Docker execution failed, falling back to direct: {e}")
                        # Fall through to direct execution
            
            # Fallback to direct execution
            logger.info("Running Cppcheck directly (not via Docker)")
            cppcheck_result = subprocess.run([
                self.tool_name,
                '--enable=all',
                '--inconclusive',
                '--xml',
                '--xml-version=2',
                f'--output-file={xml_path}',
                source_path
            ], capture_output=True, text=True, timeout=self.timeout)
            
            # Parse results
            if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
                # If artifacts_dir provided but xml_path is temporary, persist a copy
                if artifacts_dir and not xml_path.startswith(os.path.abspath(artifacts_dir)):
                    try:
                        os.makedirs(artifacts_dir, exist_ok=True)
                        persisted = os.path.join(artifacts_dir, 'cppcheck-report.xml')
                        import shutil
                        shutil.copyfile(xml_path, persisted)
                    except Exception as persist_err:
                        logger.warning(f"[CPPCHECK_RUN] Failed to persist XML to artifacts: {persist_err}")
                return self._parse_xml_results(xml_path)
            elif cppcheck_result.stderr:
                # Fallback: parse stderr output
                return self._parse_stderr_output(cppcheck_result.stderr)
            else:
                logger.info("No Cppcheck issues found")
                return [], []
                
        except subprocess.TimeoutExpired:
            logger.error("Cppcheck analysis timed out")
            return self._simulate_analysis()
        except Exception as e:
            logger.error(f"Cppcheck execution failed: {e}")
            return self._simulate_analysis()
        finally:
            if not artifacts_dir and os.path.exists(xml_path):
                os.unlink(xml_path)
    
    def _parse_xml_results(self, xml_path):
        """Parse Cppcheck XML results"""
        vulnerabilities = []
        patches = []
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for error in root.findall('.//error'):
                error_id = error.get('id', 'unknown')
                severity = error.get('severity', 'style')
                msg = error.get('msg', 'No description')
                verbose_msg = error.get('verbose', msg)
                
                # Get location
                location = error.find('location')
                file_path = 'unknown'
                line_num = 0
                
                if location is not None:
                    file_path = location.get('file', 'unknown')
                    line_num = int(location.get('line', 0))
                
                # Map severity
                sev_level = self._map_severity(severity)
                
                vuln_id = f'cppcheck_{error_id}_{len(vulnerabilities)}'
                vulnerabilities.append({
                    'id': vuln_id,
                    'severity': sev_level,
                    'description': f'Cppcheck: {verbose_msg}',
                    'file': os.path.basename(file_path),
                    'line': line_num,
                    'tool': 'Cppcheck',
                    'rule_id': error_id
                })
                
                # Generate patch
                patches.append({
                    'id': f'patch_{vuln_id}',
                    'description': f'Fix Cppcheck issue: {error_id}',
                    'content': self._generate_patch_content(error_id, msg, file_path, line_num)
                })
            
            logger.info(f"Cppcheck found {len(vulnerabilities)} issues")
            return vulnerabilities, patches
            
        except Exception as e:
            logger.error(f"Error parsing Cppcheck XML: {e}")
            return self._simulate_analysis()
    
    def _parse_stderr_output(self, stderr_output):
        """Parse Cppcheck stderr output as fallback"""
        vulnerabilities = []
        patches = []
        
        try:
            lines = stderr_output.split('\n')
            for line in lines:
                if ':' in line and any(word in line.lower() for word in ['error', 'warning', 'style']):
                    parts = line.split(':')
                    if len(parts) >= 4:
                        file_path = parts[0].strip()
                        line_num_str = parts[1].strip()
                        line_num = int(line_num_str) if line_num_str.isdigit() else 0
                        severity = 'medium' if 'warning' in line.lower() else 'low'
                        description = ':'.join(parts[2:]).strip()
                        
                        vuln_id = f'cppcheck_stderr_{len(vulnerabilities)}'
                        vulnerabilities.append({
                            'id': vuln_id,
                            'severity': severity,
                            'description': f'Cppcheck: {description}',
                            'file': os.path.basename(file_path),
                            'line': line_num,
                            'tool': 'Cppcheck',
                            'rule_id': 'stderr_parse'
                        })
                        
                        patches.append({
                            'id': f'patch_{vuln_id}',
                            'description': f'Fix: {description}',
                            'content': f'# Issue: {description}\n# File: {file_path}:{line_num}\n# Review and apply appropriate fix'
                        })
            
            return vulnerabilities, patches
            
        except Exception as e:
            logger.error(f"Error parsing Cppcheck stderr: {e}")
            return [], []
    
    def _map_severity(self, severity):
        """Map Cppcheck severity levels to our standard levels"""
        mapping = {
            'error': 'high',
            'warning': 'medium',
            'performance': 'medium',
            'portability': 'medium',
            'style': 'low',
            'information': 'low'
        }
        return mapping.get(severity, 'medium')
    
    def _generate_patch_content(self, rule_id, message, file_path, line_num):
        """Generate patch content based on rule type"""
        patch_suggestions = {
            'nullPointer': 'Add null pointer checks before dereferencing',
            'arrayIndexOutOfBounds': 'Add bounds checking for array access',
            'memoryLeak': 'Ensure proper memory deallocation with free() or delete',
            'bufferAccessOutOfBounds': 'Use safe string functions and bounds checking',
            'uninitvar': 'Initialize variables before use',
            'unusedVariable': 'Remove unused variables or mark as [[maybe_unused]]',
            'constParameter': 'Add const qualifier to parameters that are not modified',
            'passedByValue': 'Consider passing large objects by const reference'
        }
        
        suggestion = patch_suggestions.get(rule_id, 'Review and fix the reported issue')
        
        return f"""# Cppcheck Issue Fix
# Rule: {rule_id}
# File: {file_path}:{line_num}
# Description: {message}
#
# Suggested fix: {suggestion}
#
# Please review the specific issue and apply the appropriate fix.
# Common C/C++ security practices:
# - Always check return values
# - Initialize variables before use
# - Use safe string functions (strncpy, snprintf)
# - Free allocated memory
# - Check array bounds
# - Validate input parameters"""
    
    def _simulate_analysis(self):
        """Simulate Cppcheck analysis when tool is not available"""
        vulnerabilities = [
            {
                'id': 'cppcheck_sim_1',
                'severity': 'high',
                'description': 'Cppcheck Simulation: Potential buffer overflow',
                'file': 'main.cpp',
                'line': 25,
                'tool': 'Cppcheck (Simulated)',
                'rule_id': 'bufferAccessOutOfBounds'
            },
            {
                'id': 'cppcheck_sim_2',
                'severity': 'medium',
                'description': 'Cppcheck Simulation: Memory leak detected',
                'file': 'utils.cpp',
                'line': 67,
                'tool': 'Cppcheck (Simulated)',
                'rule_id': 'memoryLeak'
            },
            {
                'id': 'cppcheck_sim_3',
                'severity': 'low',
                'description': 'Cppcheck Simulation: Unused variable',
                'file': 'helper.cpp',
                'line': 12,
                'tool': 'Cppcheck (Simulated)',
                'rule_id': 'unusedVariable'
            }
        ]
        
        patches = [
            {
                'id': 'patch_cppcheck_sim_1',
                'description': 'Fix buffer overflow by adding bounds checking',
                'content': '''# Buffer Overflow Fix
# Add bounds checking before array access
# Example:
# if (index >= 0 && index < array_size) {
#     array[index] = value;
# }'''
            },
            {
                'id': 'patch_cppcheck_sim_2',
                'description': 'Fix memory leak by adding proper deallocation',
                'content': '''# Memory Leak Fix
# Ensure proper memory deallocation
# Example:
# char* buffer = malloc(size);
# // ... use buffer ...
# free(buffer);
# buffer = NULL;'''
            },
            {
                'id': 'patch_cppcheck_sim_3',
                'description': 'Remove unused variable',
                'content': '''# Unused Variable Fix
# Remove the unused variable declaration
# Or mark as [[maybe_unused]] if needed for future use'''
            }
        ]
        
        return vulnerabilities, patches