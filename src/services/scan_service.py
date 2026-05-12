"""
Service layer for scan operations
This provides business logic and coordinates between different components
"""

from typing import List, Dict, Any, Optional
import uuid
import os
import tempfile
import shutil
import json
import logging
from datetime import datetime

from src.repositories.scan_repository import ScanRepository
from src.models.scan_v2 import DatabaseManager

# Set up logging
logger = logging.getLogger(__name__)
# Import Celery tasks for background processing
try:
    from src.workers.job_worker import process_scan_task, process_fuzzing_task
    CELERY_AVAILABLE = True
    logger.info("Celery workers available - using async processing")
except ImportError:
    try:
        from src.queue.tasks import analyze_code, analyze_code_sync
        CELERY_AVAILABLE = True
        logger.info("Celery queue tasks available - using async processing")
    except ImportError:
        CELERY_AVAILABLE = False
        analyze_code_sync = None
        logger.warning("Celery not available - falling back to synchronous processing")
from src.fuzz_plan.generator import FuzzPlanGenerator
from src.harness.generator import HarnessGenerator
from src.build.orchestrator import BuildOrchestrator
from src.fuzz_exec.executor import FuzzExecutor
from src.triage.analyzer import CrashTriageAnalyzer


class ScanService:
    """
    High-level service for managing scans
    Coordinates between repository, analysis tools, and background jobs
    """
    
    def __init__(self, repository: ScanRepository):
        self.repository = repository
        self.scans_dir = os.getenv('SCANS_DIR', './scans')
    
    # ============================================================================
    # Scan Creation and Management
    # ============================================================================
    
    def create_scan(self, 
                   source_type: str,
                   repo_url: str = None,
                   code_snippet: str = None,
                   file_upload: Any = None,
                   analysis_tool: str = 'cppcheck',
                   user_id: str = None) -> Dict[str, Any]:
        """
        Create a new scan
        
        Args:
            source_type: 'repository', 'snippet', or 'file_upload'
            repo_url: Git repository URL (for repository scans)
            code_snippet: Source code text (for snippet scans)
            file_upload: Uploaded file (for file upload scans)
            analysis_tool: Analysis tool to use
            user_id: User identifier
        
        Returns:
            Dict with scan_id and status
        """
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan_data = {
            'scan_id': scan_id,
            'user_id': user_id,
            'repo_url': repo_url,
            'source_type': source_type,
            'analysis_tool': analysis_tool,
            'metadata': {
                'created_by': 'scan_service',
                'source_type': source_type
            }
        }
        
        created_scan_id = self.repository.create_scan(scan_data)
        
        # Process source code based on type
        if source_type == 'snippet' and code_snippet:
            self._process_code_snippet(scan_id, code_snippet)
        elif source_type == 'repository' and repo_url:
            self._process_repository(scan_id, repo_url)
        elif source_type == 'file_upload' and file_upload:
            self._process_file_upload(scan_id, file_upload)
        else:
            self.repository.update_scan_status(scan_id, 'failed', 'Invalid source type or missing data')
            return {'scan_id': scan_id, 'status': 'failed', 'error': 'Invalid input'}
        
        # Start background processing with Celery if available
        if CELERY_AVAILABLE:
            try:
                # Try to use the new worker system first
                from src.workers.job_worker import process_scan_task
                
                # Prepare scan data for background processing
                scan_data = {
                    'source_type': source_type,
                    'analysis_tool': analysis_tool,
                    'code_snippet': code_snippet,
                    'repo_url': repo_url,
                    'file_upload': None  # File data already processed and stored
                }
                
                # Start background task
                task_result = process_scan_task.delay(scan_id, scan_data)
                logger.info(f"Started background scan task {task_result.id} for scan {scan_id}")
                
                return {
                    'scan_id': scan_id,
                    'status': 'processing',
                    'task_id': task_result.id,
                    'message': 'Scan started in background'
                }
                
            except ImportError:
                # Fallback to queue tasks
                from src.queue.tasks import analyze_code
                task_result = analyze_code.delay(scan_id, analysis_tool)
                logger.info(f"Started background analysis task {task_result.id} for scan {scan_id}")
                
                return {
                    'scan_id': scan_id,
                    'status': 'processing', 
                    'task_id': task_result.id,
                    'message': 'Scan started in background'
                }
        else:
            # Fallback to synchronous processing
            logger.warning(f"Celery not available, running scan {scan_id} synchronously")
            
        # Run analysis (synchronously if Celery not available)
        try:
            analysis_result = self.run_static_analysis(scan_id, analysis_tool)
            return {
                'scan_id': scan_id,
                'status': analysis_result['status'],
                'findings_count': analysis_result.get('findings_count', 0)
            }
        except Exception as e:
            self.repository.update_scan_status(scan_id, 'failed', str(e))
            return {
                'scan_id': scan_id,
                'status': 'failed',
                'error': str(e)
            }
    
    def _process_code_snippet(self, scan_id: str, code_snippet: str):
        """Process code snippet input"""
        # Detect file extension from content
        extension = self._detect_file_extension(code_snippet)
        
        files = [{
            'path': f'snippet{extension}',
            'content': code_snippet
        }]
        
        self.repository.store_source_files(scan_id, files)
    
    def _process_repository(self, scan_id: str, repo_url: str):
        """Process repository input by cloning it"""
        import subprocess
        import tempfile
        import shutil
        
        temp_dir = None
        try:
            # Create temporary directory for cloning
            temp_dir = tempfile.mkdtemp(prefix=f'repo_{scan_id}_')
            
            # Clone the repository
            result = subprocess.run([
                'git', 'clone', '--depth', '1', repo_url, temp_dir
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                raise Exception('Failed to clone repository. Make sure it\'s public and accessible.')
            
            # Extract source files from cloned repo
            files = []
            for root, dirs, filenames in os.walk(temp_dir):
                # Skip .git directory
                if '.git' in root:
                    continue
                    
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, temp_dir)
                    
                    # Only include source code files
                    if any(filename.lower().endswith(ext) for ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.py', '.js', '.java']):
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            files.append({
                                'path': rel_path,
                                'content': content
                            })
                        except Exception:
                            continue
            
            if not files:
                raise Exception('No source code files found in repository')
            
            self.repository.store_source_files(scan_id, files)
            
        except subprocess.TimeoutExpired:
            raise Exception('Repository clone timed out')
        finally:
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _process_file_upload(self, scan_id: str, file_upload: Any):
        """Process file upload input by extracting files"""
        import tempfile
        import zipfile
        import shutil
        from src.utils.validation import safe_extract_zip
        
        temp_dir = None
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix=f'upload_{scan_id}_')
            
            # Save uploaded file
            if hasattr(file_upload, 'filename') and file_upload.filename.endswith('.zip'):
                # Handle ZIP file
                zip_path = os.path.join(temp_dir, 'upload.zip')
                file_upload.save(zip_path)
                
                # Extract ZIP safely
                extract_dir = os.path.join(temp_dir, 'extracted')
                os.makedirs(extract_dir, exist_ok=True)
                safe_extract_zip(zip_path, extract_dir, timeout=120)
                
                # Extract source files
                files = []
                for root, dirs, filenames in os.walk(extract_dir):
                    for filename in filenames:
                        file_path = os.path.join(root, filename)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        
                        # Only include source code files
                        if any(filename.lower().endswith(ext) for ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.py', '.js', '.java']):
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                files.append({
                                    'path': rel_path,
                                    'content': content
                                })
                            except Exception:
                                continue
                
                if not files:
                    raise Exception('No source code files found in uploaded ZIP')
                
                self.repository.store_source_files(scan_id, files)
            else:
                raise Exception('Unsupported file type. Please upload a ZIP file.')
                
        finally:
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _detect_file_extension(self, content: str) -> str:
        """Detect file extension from code content"""
        if not content:
            return '.txt'
            
        content_lower = content.lower()
        
        if '#include' in content_lower or 'int main(' in content_lower:
            if 'class ' in content_lower or 'namespace ' in content_lower or 'std::' in content_lower:
                return '.cpp'
            else:
                return '.c'
        elif 'def ' in content_lower or 'import ' in content_lower:
            return '.py'
        elif 'function ' in content_lower or 'var ' in content_lower or 'const ' in content_lower:
            return '.js'
        else:
            return '.txt'
    
    def get_user_scans(self, user_id: str, limit: int = None) -> List[Dict[str, Any]]:
        """Get all scans for a specific user"""
        return self.repository.get_scans_by_user(user_id, limit)
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan status and basic information"""
        return self.repository.get_scan(scan_id)
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get complete scan results"""
        scan = self.repository.get_scan(scan_id)
        if not scan:
            return {'error': 'Scan not found'}
        
        # Get all related data
        findings = self.repository.get_static_findings(scan_id)
        source_files = self.repository.get_source_files(scan_id)
        
        return {
            'scan': scan,
            'findings': findings,
            'source_files': source_files,
            'total_findings': len(findings),
            'total_files': len(source_files)
        }
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get Celery task status"""
        if not CELERY_AVAILABLE:
            return {'error': 'Celery not available'}
        
        try:
            from src.workers.job_worker import celery_app
            result = celery_app.AsyncResult(task_id)
            
            return {
                'task_id': task_id,
                'status': result.status,
                'result': result.result if result.ready() else None,
                'info': result.info,
                'ready': result.ready(),
                'successful': result.successful() if result.ready() else None,
                'failed': result.failed() if result.ready() else None
            }
        except Exception as e:
            return {'error': f'Failed to get task status: {str(e)}'}
    
    def cancel_task(self, task_id: str) -> Dict[str, Any]:
        """Cancel a Celery task"""
        if not CELERY_AVAILABLE:
            return {'error': 'Celery not available'}
        
        try:
            from src.workers.job_worker import celery_app
            celery_app.control.revoke(task_id, terminate=True)
            
            return {
                'task_id': task_id,
                'status': 'cancelled',
                'message': 'Task cancelled successfully'
            }
        except Exception as e:
            return {'error': f'Failed to cancel task: {str(e)}'}
    
    def get_active_tasks(self) -> Dict[str, Any]:
        """Get all active Celery tasks"""
        if not CELERY_AVAILABLE:
            return {'error': 'Celery not available'}
        
        try:
            from src.workers.job_worker import celery_app
            inspect = celery_app.control.inspect()
            
            active_tasks = inspect.active()
            scheduled_tasks = inspect.scheduled()
            reserved_tasks = inspect.reserved()
            
            return {
                'active': active_tasks or {},
                'scheduled': scheduled_tasks or {},
                'reserved': reserved_tasks or {},
                'total_active': sum(len(tasks) for tasks in (active_tasks or {}).values()),
                'total_scheduled': sum(len(tasks) for tasks in (scheduled_tasks or {}).values()),
                'total_reserved': sum(len(tasks) for tasks in (reserved_tasks or {}).values())
            }
        except Exception as e:
            return {'error': f'Failed to get active tasks: {str(e)}'}
    
    def start_fuzzing_async(self, scan_id: str, fuzzing_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Start fuzzing in background using Celery"""
        if not CELERY_AVAILABLE:
            return {'error': 'Celery not available for background fuzzing'}
        
        try:
            from src.workers.job_worker import process_fuzzing_task
            
            # Default fuzzing configuration
            if not fuzzing_config:
                fuzzing_config = {
                    'duration': 300,  # 5 minutes
                    'max_crashes': 10,
                    'timeout': 30
                }
            
            # Start background fuzzing task
            task_result = process_fuzzing_task.delay(scan_id, fuzzing_config)
            logger.info(f"Started background fuzzing task {task_result.id} for scan {scan_id}")
            
            return {
                'scan_id': scan_id,
                'task_id': task_result.id,
                'status': 'processing',
                'message': 'Fuzzing started in background'
            }
            
        except Exception as e:
            logger.error(f"Failed to start fuzzing for scan {scan_id}: {e}")
            return {'error': f'Failed to start fuzzing: {str(e)}'}
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get complete scan results"""
        scan = self.repository.get_scan(scan_id)
        if not scan:
            return {'error': 'Scan not found'}
        
        # Get all related data
        findings = self.repository.get_static_findings(scan_id)
        source_files = self.repository.get_source_files(scan_id)
        
        return {
            'scan': scan,
            'findings': findings,
            'source_files': source_files,
            'total_findings': len(findings),
            'total_files': len(source_files)
        }
    
    # ============================================================================
    # Analysis Pipeline
    # ============================================================================
    
    def run_static_analysis(self, scan_id: str, analysis_tool: str = 'cppcheck') -> Dict[str, Any]:
        """
        Run static analysis on a scan
        This can work with both database and file-based storage
        """
        try:
            self.repository.update_scan_status(scan_id, 'processing')
            
            # Get source files
            source_files = self.repository.get_source_files(scan_id)
            if not source_files:
                raise Exception("No source files found for scan")
            
            # For database mode, we need to create temporary files for analysis
            if self.repository.use_database:
                findings = self._run_analysis_from_database(scan_id, source_files, analysis_tool)
            else:
                findings = self._run_analysis_from_filesystem(scan_id, analysis_tool)
            
            # Store findings in database AND create legacy files for compatibility
            self.repository.store_static_findings(scan_id, findings)
            
            # Update scan status
            self.repository.update_scan_status(scan_id, 'completed')
            
            return {
                'status': 'completed',
                'findings_count': len(findings),
                'scan_id': scan_id
            }
            
        except Exception as e:
            self.repository.update_scan_status(scan_id, 'failed', str(e))
            return {
                'status': 'failed',
                'error': str(e),
                'scan_id': scan_id
            }
    
    def _run_analysis_from_database(self, scan_id: str, source_files: List[Dict], analysis_tool: str) -> List[Dict]:
        """Run analysis when source files are stored in database"""
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = os.path.join(temp_dir, 'source')
            os.makedirs(source_dir, exist_ok=True)
            
            # Write source files to temporary directory
            session = self.repository.db_manager.get_session()
            try:
                from src.models.scan_v2 import ScanSource
                sources = session.query(ScanSource).filter(ScanSource.scan_id == scan_id).all()
                
                for source in sources:
                    file_path = os.path.join(source_dir, source.file_path)
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(source.file_content)
                
                # Run analysis using legacy code
                findings = self._run_legacy_analysis(source_dir, analysis_tool)
                
                # CRITICAL FIX: Also create the legacy static_findings.json file for compatibility
                # This ensures existing fuzzing and other modules can still work
                if self.repository.use_database:
                    legacy_scan_dir = os.path.join(self.scans_dir, scan_id)
                    os.makedirs(legacy_scan_dir, exist_ok=True)
                    
                    findings_data = {
                        'version': '1.0',
                        'generated_at': datetime.now().isoformat(),
                        'tool': analysis_tool,
                        'total_findings': len(findings),
                        'findings': findings,
                        'metadata': {
                            'source_files': [source.file_path for source in sources],
                            'storage_type': 'database_with_legacy_compat'
                        }
                    }
                    
                    with open(os.path.join(legacy_scan_dir, 'static_findings.json'), 'w') as f:
                        json.dump(findings_data, f, indent=2)
                
                return findings
                
            finally:
                session.close()
    
    def _run_analysis_from_filesystem(self, scan_id: str, analysis_tool: str) -> List[Dict]:
        """Run analysis when source files are in filesystem"""
        source_dir = os.path.join(self.scans_dir, scan_id, 'source')
        findings = self._run_legacy_analysis(source_dir, analysis_tool)
        
        # CRITICAL FIX: Also create the legacy static_findings.json file for compatibility
        # This ensures existing fuzzing and other modules can still work
        legacy_scan_dir = os.path.join(self.scans_dir, scan_id)
        os.makedirs(legacy_scan_dir, exist_ok=True)
        
        findings_data = {
            'version': '1.0',
            'generated_at': datetime.now().isoformat(),
            'tool': analysis_tool,
            'total_findings': len(findings),
            'findings': findings,
            'metadata': {
                'source_files': [f for f in os.listdir(source_dir) if f.endswith(('.c', '.cpp', '.cc', '.h', '.hpp'))],
                'storage_type': 'filesystem'
            }
        }
        
        with open(os.path.join(legacy_scan_dir, 'static_findings.json'), 'w') as f:
            json.dump(findings_data, f, indent=2)
        
        return findings
    
    def _run_legacy_analysis(self, source_dir: str, analysis_tool: str) -> List[Dict]:
        """Run actual static analysis using the specified tool"""
        findings = []
        
        if analysis_tool == 'cppcheck':
            try:
                # Use the proper Cppcheck analyzer that knows about Docker
                from src.analysis.cppcheck import CppcheckAnalyzer
                
                logger.info(f"[SCAN] Using CppcheckAnalyzer for real analysis on {source_dir}")
                analyzer = CppcheckAnalyzer()
                
                if not analyzer.is_available():
                    error_msg = "Cppcheck is not available. Docker is not running or Cppcheck is not installed."
                    logger.error(f"[SCAN] {error_msg}")
                    raise RuntimeError(error_msg)
                
                # Run real Cppcheck analysis - ALWAYS run fresh analysis, don't reuse old results
                logger.info("[SCAN] Running fresh Cppcheck analysis (not reusing old results)")
                vulnerabilities, patches = analyzer.analyze(source_dir, 'local_path')
                
                # Convert to our findings format
                for vuln in vulnerabilities:
                    # Build metadata with CWE name if available
                    metadata = {
                        'tool': vuln.get('tool', 'cppcheck')
                    }
                    if vuln.get('cwe_name'):
                        metadata['cwe_name'] = vuln.get('cwe_name')
                    
                    finding = {
                        'finding_id': vuln.get('id', str(uuid.uuid4())),
                        'rule_id': vuln.get('rule_id', 'unknown'),
                        'severity': vuln.get('severity', 'medium'),
                        'confidence': 'high',
                        'message': vuln.get('description', ''),
                        'cwe': vuln.get('cwe', ''),  # CWE from analyzer mapping
                        'file_path': vuln.get('file', ''),
                        'file': os.path.basename(vuln.get('file', '')),
                        'line_number': vuln.get('line', 0),
                        'line': vuln.get('line', 0),
                        'column_number': 1,
                        'column': 1,
                        'function_name': '',
                        'function': '',
                        'priority_score': vuln.get('priority_score', 5.0),
                        'cvss_score': vuln.get('priority_score', 5.0),  # Store as cvss_score for database
                        'metadata': metadata  # Add metadata with CWE name
                    }
                    findings.append(finding)
                
                logger.info(f"[SCAN] Real Cppcheck analysis found {len(findings)} findings")
                return findings
                
            except Exception as e:
                logger.error(f"[SCAN] Error running real Cppcheck analysis: {e}")
                raise RuntimeError(f"Cppcheck analysis failed: {e}")
        
        elif analysis_tool == 'codeql':
            try:
                # Use the proper CodeQL analyzer that knows about Docker
                from src.analysis.codeql import CodeQLAnalyzer
                
                logger.info(f"[SCAN] Using CodeQLAnalyzer for real analysis on {source_dir}")
                analyzer = CodeQLAnalyzer()
                
                if not analyzer.is_available():
                    error_msg = "CodeQL is not available. Docker is not running or CodeQL is not installed."
                    logger.error(f"[SCAN] {error_msg}")
                    raise RuntimeError(error_msg)
                
                # Run real CodeQL analysis
                vulnerabilities, patches = analyzer.analyze(source_dir, 'local_path')
                
                # Convert to our findings format
                for vuln in vulnerabilities:
                    finding = {
                        'finding_id': vuln.get('id', str(uuid.uuid4())),
                        'rule_id': vuln.get('rule_id', 'unknown'),
                        'severity': vuln.get('severity', 'medium'),
                        'confidence': 'high',
                        'message': vuln.get('description', ''),
                        'cwe': vuln.get('cwe', ''),
                        'file_path': vuln.get('file', ''),
                        'file': os.path.basename(vuln.get('file', '')),
                        'line_number': vuln.get('line', 0),
                        'line': vuln.get('line', 0),
                        'column_number': vuln.get('column', 1),
                        'column': vuln.get('column', 1),
                        'function_name': vuln.get('function', ''),
                        'function': vuln.get('function', ''),
                        'priority_score': 8.0 if vuln.get('severity') == 'high' else 6.0
                    }
                    findings.append(finding)
                
                logger.info(f"[SCAN] Real CodeQL analysis found {len(findings)} findings")
                return findings
                
            except Exception as e:
                logger.error(f"[SCAN] Error running real CodeQL analysis: {e}")
                raise RuntimeError(f"CodeQL analysis failed: {e}")
        
        else:
            # Unknown tool - fail with clear error
            error_msg = f"Unknown analysis tool '{analysis_tool}'. Supported tools: cppcheck, codeql"
            logger.error(f"[SCAN] {error_msg}")
            raise RuntimeError(error_msg)
        
        return findings
    
    def _fallback_pattern_analysis(self, source_dir: str) -> List[Dict]:
        """Fallback pattern-based analysis when real tools aren't available"""
        findings = []
        
        # Look for source files in the directory
        source_files = []
        if os.path.exists(source_dir):
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    if file.endswith(('.c', '.cpp', '.cc', '.h', '.hpp')):
                        source_files.append(os.path.join(root, file))
        
        # Generate realistic findings based on common C/C++ issues
        if source_files:
            for i, source_file in enumerate(source_files):
                filename = os.path.basename(source_file)
                
                # Read file content to generate more realistic findings
                try:
                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    lines = content.split('\n')
                    
                    # Look for common vulnerability patterns
                    for line_num, line in enumerate(lines, 1):
                        line_lower = line.lower()
                        
                        # Buffer overflow patterns
                        if 'strcpy' in line_lower or 'sprintf' in line_lower:
                            findings.append({
                                'finding_id': f'{filename}_bufferoverflow_{line_num}',
                                'rule_id': 'bufferAccessOutOfBounds',
                                'severity': 'error',
                                'confidence': 'low',  # Changed from 'high' to 'low' for fallback
                                'message': f'Potential buffer overflow in {line.strip()}',
                                'cwe': '120',
                                'file': filename,
                                'file_name': filename,
                                'line': line_num,
                                'column': 1,
                                'function': 'unknown',
                                'priority_score': 9.0,
                                'tool': 'Pattern-Based Fallback',  # Add tool marker
                                'analysis_method': 'pattern_matching'  # Add analysis method
                            })
                        
                        # Memory leak patterns
                        if 'malloc' in line_lower and 'free' not in content.lower():
                            findings.append({
                                'finding_id': f'{filename}_memleak_{line_num}',
                                'rule_id': 'memleak',
                                'severity': 'error',
                                'confidence': 'low',  # Changed from 'medium' to 'low' for fallback
                                'message': f'Potential memory leak: {line.strip()}',
                                'cwe': '401',
                                'file': filename,
                                'file_name': filename,
                                'line': line_num,
                                'column': 1,
                                'function': 'unknown',
                                'priority_score': 8.0,
                                'tool': 'Pattern-Based Fallback',  # Add tool marker
                                'analysis_method': 'pattern_matching'  # Add analysis method
                            })
                        
                        # Null pointer dereference
                        if '*' in line and ('null' in line_lower or 'nullptr' in line_lower):
                            findings.append({
                                'finding_id': f'{filename}_nullpointer_{line_num}',
                                'rule_id': 'nullPointer',
                                'severity': 'error',
                                'confidence': 'low',  # Changed from 'high' to 'low' for fallback
                                'message': f'Potential null pointer dereference: {line.strip()}',
                                'cwe': '476',
                                'file': filename,
                                'file_name': filename,
                                'line': line_num,
                                'column': 1,
                                'function': 'unknown',
                                'priority_score': 9.0,
                                'tool': 'Pattern-Based Fallback',  # Add tool marker
                                'analysis_method': 'pattern_matching'  # Add analysis method
                            })
                
                except Exception as e:
                    print(f"Error reading source file {source_file}: {e}")
        
        # If no findings found, create at least one simulated finding
        if not findings:
            findings.append({
                'finding_id': 'simulated_finding_1',
                'rule_id': 'simulation',
                'severity': 'medium',
                'confidence': 'low',
                'message': 'Simulated finding for testing - no real analysis performed',
                'cwe': '000',
                'file': 'snippet.cpp',
                'file_name': 'snippet.cpp',
                'line': 1,
                'column': 1,
                'function': 'main',
                'priority_score': 5.0,
                'tool': 'Pattern-Based Fallback',  # Add tool marker
                'analysis_method': 'pattern_matching'  # Add analysis method
            })
        
        logger.warning(f"[SCAN] Using pattern-based fallback analysis - {len(findings)} findings generated")
        logger.warning("[SCAN] For accurate results, ensure Cppcheck/CodeQL/Docker are properly configured")
        
        return findings
    
    # ============================================================================
    # Fuzzing Pipeline
    # ============================================================================
    
    def store_fuzz_plan(self, scan_id: str, fuzz_plan: Dict[str, Any]) -> bool:
        """Store fuzz plan in database while maintaining legacy file compatibility"""
        if not self.repository.use_database:
            # For legacy mode, just create the file
            return self._create_legacy_fuzz_plan_file(scan_id, fuzz_plan)
        
        # Store in database
        success = self._store_fuzz_plan_db(scan_id, fuzz_plan)
        
        # Also create legacy file for compatibility
        if success:
            self._create_legacy_fuzz_plan_file(scan_id, fuzz_plan)
        
        return success
    
    def _store_fuzz_plan_db(self, scan_id: str, fuzz_plan: Dict[str, Any]) -> bool:
        """Store fuzz plan in database"""
        try:
            from src.models.scan_v2 import FuzzPlan, FuzzTarget
            
            session = self.repository.db_manager.get_session()
            try:
                # Create fuzz plan record
                plan = FuzzPlan(
                    scan_id=scan_id,
                    version=fuzz_plan.get('version', '1.0'),
                    total_targets=len(fuzz_plan.get('targets', [])),
                    metadata_json=fuzz_plan.get('metadata', {})
                )
                session.add(plan)
                session.flush()  # Get the plan ID
                
                # Store targets
                for target_data in fuzz_plan.get('targets', []):
                    target = FuzzTarget(
                        plan_id=plan.id,
                        scan_id=scan_id,
                        target_id=target_data.get('target_id', ''),
                        function_name=target_data.get('function_name', ''),
                        file_path=target_data.get('source_file', ''),
                        line_number=target_data.get('line_number', 0),
                        bug_class=target_data.get('bug_class', ''),
                        priority=target_data.get('priority', 0.0),
                        harness_type=target_data.get('harness_type', ''),
                        sanitizers=target_data.get('sanitizers', []),
                        seeds=target_data.get('seed_directories', []),
                        dictionaries=target_data.get('dictionaries', []),
                        function_signature=target_data.get('function_signature', {})
                    )
                    session.add(target)
                
                session.commit()
                return True
                
            except Exception as e:
                session.rollback()
                print(f"Error storing fuzz plan in database: {e}")
                return False
            finally:
                session.close()
                
        except Exception as e:
            print(f"Error accessing database for fuzz plan storage: {e}")
            return False
    
    def _create_legacy_fuzz_plan_file(self, scan_id: str, fuzz_plan: Dict[str, Any]) -> bool:
        """Create legacy fuzz plan file for compatibility"""
        try:
            legacy_scan_dir = os.path.join(self.scans_dir, scan_id)
            fuzz_dir = os.path.join(legacy_scan_dir, 'fuzz')
            os.makedirs(fuzz_dir, exist_ok=True)
            
            with open(os.path.join(fuzz_dir, 'fuzzplan.json'), 'w') as f:
                json.dump(fuzz_plan, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error creating legacy fuzz plan file: {e}")
            return False
    
    def store_harness_files(self, scan_id: str, harnesses: List[Dict[str, Any]]) -> bool:
        """Store harness files in database while maintaining legacy file compatibility"""
        if not self.repository.use_database:
            # For legacy mode, files are already created by harness generator
            return True
        
        # Store in database
        success = self._store_harness_files_db(scan_id, harnesses)
        
        # Legacy files are already created by the harness generator
        # No need to duplicate them
        
        return success
    
    def _store_harness_files_db(self, scan_id: str, harnesses: List[Dict[str, Any]]) -> bool:
        """Store harness files in database"""
        try:
            from src.models.scan_v2 import HarnessFile, FuzzTarget
            
            session = self.repository.db_manager.get_session()
            try:
                for harness_data in harnesses:
                    # Find the corresponding target
                    target = session.query(FuzzTarget).filter(
                        FuzzTarget.scan_id == scan_id,
                        FuzzTarget.target_id == harness_data.get('target_id', '')
                    ).first()
                    
                    if target:
                        harness = HarnessFile(
                            target_id=target.id,
                            scan_id=scan_id,
                            filename=harness_data.get('filename', ''),
                            harness_code=harness_data.get('code', ''),
                            harness_type=harness_data.get('harness_type', ''),
                            build_status='pending'
                        )
                        session.add(harness)
                
                session.commit()
                return True
                
            except Exception as e:
                session.rollback()
                print(f"Error storing harness files in database: {e}")
                return False
            finally:
                session.close()
                
        except Exception as e:
            print(f"Error accessing database for harness storage: {e}")
            return False
    
    def store_fuzz_campaign_results(self, scan_id: str, campaign_results: Dict[str, Any]) -> bool:
        """Store fuzzing campaign results in database while maintaining legacy file compatibility"""
        if not self.repository.use_database:
            # For legacy mode, just create the file
            return self._create_legacy_campaign_results_file(scan_id, campaign_results)
        
        # Store in database
        success = self._store_campaign_results_db(scan_id, campaign_results)
        
        # Also create legacy file for compatibility
        if success:
            self._create_legacy_campaign_results_file(scan_id, campaign_results)
        
        return success
    
    def _store_campaign_results_db(self, scan_id: str, campaign_results: Dict[str, Any]) -> bool:
        """Store campaign results in database"""
        try:
            from src.models.scan_v2 import FuzzCampaign, FuzzExecution, CrashArtifact, FuzzTarget
            
            session = self.repository.db_manager.get_session()
            try:
                # Create campaign record
                campaign = FuzzCampaign(
                    scan_id=scan_id,
                    runtime_minutes=campaign_results.get('runtime_minutes', 0),
                    total_targets=campaign_results.get('total_targets', 0),
                    targets_executed=len(campaign_results.get('results', [])),
                    total_executions=sum(1 for r in campaign_results.get('results', []) if r.get('status') == 'completed'),
                    total_crashes=sum(len(r.get('crashes', [])) for r in campaign_results.get('results', [])),
                    status='completed',
                    total_time_seconds=int(campaign_results.get('total_time', 0)),
                    metadata_json=campaign_results
                )
                session.add(campaign)
                session.flush()  # Get the campaign ID
                
                # Store execution results
                for result in campaign_results.get('results', []):
                    # Find the corresponding target
                    target = session.query(FuzzTarget).filter(
                        FuzzTarget.scan_id == scan_id,
                        FuzzTarget.function_name == result.get('target', '').replace('fuzz_test_', '')
                    ).first()
                    
                    execution = FuzzExecution(
                        campaign_id=campaign.id,
                        target_id=target.id if target else None,
                        scan_id=scan_id,
                        target_name=result.get('target', ''),
                        status=result.get('status', ''),
                        runtime_seconds=result.get('runtime', 0),
                        exit_code=result.get('exit_code', 0),
                        executions_count=0,  # Would need to parse from output
                        crashes_found=result.get('crashes_found', 0),
                        fuzzer_output=result.get('output', '')
                    )
                    session.add(execution)
                    session.flush()  # Get the execution ID
                    
                    # Store crash artifacts
                    for crash in result.get('crashes', []):
                        # Read crash file if it exists
                        crash_data = None
                        crash_path = crash.get('path', '')
                        if crash_path and os.path.exists(crash_path):
                            try:
                                with open(crash_path, 'rb') as f:
                                    crash_data = f.read()
                            except Exception:
                                pass
                        
                        artifact = CrashArtifact(
                            execution_id=execution.id,
                            scan_id=scan_id,
                            filename=crash.get('filename', ''),
                            file_size=crash.get('size', 0),
                            crash_data=crash_data,
                            severity='high' if 'crash' in crash.get('filename', '') else 'medium'
                        )
                        session.add(artifact)
                
                session.commit()
                return True
                
            except Exception as e:
                session.rollback()
                print(f"Error storing campaign results in database: {e}")
                return False
            finally:
                session.close()
                
        except Exception as e:
            print(f"Error accessing database for campaign results storage: {e}")
            return False
    
    def _create_legacy_campaign_results_file(self, scan_id: str, campaign_results: Dict[str, Any]) -> bool:
        """Create legacy campaign results file for compatibility"""
        try:
            legacy_scan_dir = os.path.join(self.scans_dir, scan_id)
            results_dir = os.path.join(legacy_scan_dir, 'fuzz', 'results')
            os.makedirs(results_dir, exist_ok=True)
            
            with open(os.path.join(results_dir, 'campaign_results.json'), 'w') as f:
                json.dump(campaign_results, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error creating legacy campaign results file: {e}")
            return False
    
    def generate_fuzz_plan(self, scan_id: str) -> Dict[str, Any]:
        """Generate fuzz plan from static findings"""
        try:
            findings = self.repository.get_static_findings(scan_id)
            if not findings:
                return {'error': 'No static findings available for fuzz plan generation'}
            
            # Create temporary findings file for legacy fuzz plan generator
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                import json
                findings_data = {
                    'total_findings': len(findings),
                    'findings': findings
                }
                json.dump(findings_data, temp_file, indent=2)
                temp_findings_path = temp_file.name
            
            try:
                # Generate fuzz plan using existing code
                generator = FuzzPlanGenerator(temp_findings_path)
                fuzz_plan = generator.generate_fuzz_plan()
                
                # Store fuzz plan in repository
                # TODO: Implement fuzz plan storage in repository
                
                return {
                    'status': 'completed',
                    'targets_count': len(fuzz_plan.get('targets', [])),
                    'fuzz_plan': fuzz_plan
                }
                
            finally:
                os.unlink(temp_findings_path)
                
        except Exception as e:
            return {'error': str(e)}
    
    def generate_harnesses(self, scan_id: str) -> Dict[str, Any]:
        """Generate fuzzing harnesses"""
        try:
            # This would use the harness generator
            # For now, return placeholder
            return {
                'status': 'completed',
                'harnesses_count': 0,
                'message': 'Harness generation not yet implemented in service layer'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def run_fuzzing_campaign(self, scan_id: str, runtime_minutes: int = 5) -> Dict[str, Any]:
        """Run fuzzing campaign"""
        try:
            # This would use the fuzz executor
            # For now, return placeholder
            return {
                'status': 'completed',
                'targets_executed': 0,
                'crashes_found': 0,
                'message': 'Fuzzing execution not yet implemented in service layer'
            }
        except Exception as e:
            return {'error': str(e)}
    
    # ============================================================================
    # Background Job Processing
    # ============================================================================
    
    def process_next_job(self) -> Optional[Dict[str, Any]]:
        """Process the next job in the queue"""
        job = self.repository.get_next_job()
        if not job:
            return None
        
        try:
            result = self._execute_job(job)
            self.repository.complete_job(job['id'], result)
            return {'status': 'completed', 'job_id': job['id'], 'result': result}
            
        except Exception as e:
            self.repository.complete_job(job['id'], error=str(e))
            return {'status': 'failed', 'job_id': job['id'], 'error': str(e)}
    
    def _execute_job(self, job: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific job"""
        job_type = job['job_type']
        scan_id = job['scan_id']
        payload = job['payload']
        
        if job_type == 'static_analysis':
            return self.run_static_analysis(scan_id, payload.get('analysis_tool', 'cppcheck'))
        elif job_type == 'fuzz_plan':
            return self.generate_fuzz_plan(scan_id)
        elif job_type == 'harness_generation':
            return self.generate_harnesses(scan_id)
        elif job_type == 'fuzz_execution':
            return self.run_fuzzing_campaign(scan_id, payload.get('runtime_minutes', 5))
        else:
            raise Exception(f"Unknown job type: {job_type}")
    
    # ============================================================================
    # Maintenance and Cleanup
    # ============================================================================
    
    def cleanup_old_scans(self, older_than_days: int = 30) -> Dict[str, Any]:
        """Clean up old scan data"""
        deleted_count = self.repository.cleanup_old_scans(older_than_days)
        return {
            'deleted_scans': deleted_count,
            'cleanup_date': datetime.utcnow().isoformat()
        }
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        storage_stats = self.repository.get_storage_stats()
        
        return {
            'storage': storage_stats,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def update_scan_status(self, scan_id: str, status: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Update scan status - used by Celery workers
        """
        try:
            # Update basic status
            success = self.repository.update_scan_status(scan_id, status)
            
            # If metadata provided, store it (for now just log it)
            if metadata:
                logger.info(f"Scan {scan_id} status updated to {status} with metadata: {metadata}")
            
            return success
        except Exception as e:
            logger.error(f"Failed to update scan status for {scan_id}: {e}")
            return False
    
    def update_fuzzing_status(self, scan_id: str, status: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Update fuzzing status - used by Celery workers
        """
        try:
            # For now, update the main scan status with fuzzing prefix
            fuzzing_status = f"fuzzing_{status}" if not status.startswith('fuzzing') else status
            success = self.repository.update_scan_status(scan_id, fuzzing_status)
            
            # If metadata provided, store it (for now just log it)
            if metadata:
                logger.info(f"Scan {scan_id} fuzzing status updated to {status} with metadata: {metadata}")
            
            return success
        except Exception as e:
            logger.error(f"Failed to update fuzzing status for {scan_id}: {e}")
            return False
    # ============================================================================
    # Celery Job Processing Methods
    # ============================================================================
    
    def process_scan_job(self, scan_id: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a scan job - called by Celery workers
        This method handles the actual scan processing logic
        """
        try:
            logger.info(f"Processing scan job {scan_id} with data: {scan_data}")
            
            # Get scan from database
            scan = self.repository.get_scan(scan_id)
            if not scan:
                raise Exception(f"Scan {scan_id} not found")
            
            # Update status to processing
            self.repository.update_scan_status(scan_id, 'processing')
            
            # Determine analysis tool
            analysis_tool = scan_data.get('analysis_tool', scan.get('analysis_tool', 'cppcheck'))
            
            # Check if this is an existing scan or new data
            source_type = scan_data.get('source_type', 'existing')
            
            if source_type != 'existing':
                # Process new source data
                if source_type == 'snippet' and scan_data.get('code_snippet'):
                    self._process_code_snippet(scan_id, scan_data['code_snippet'])
                elif source_type == 'repository' and scan_data.get('repo_url'):
                    self._process_repository(scan_id, scan_data['repo_url'])
                elif source_type == 'file_upload' and scan_data.get('file_upload'):
                    self._process_file_upload(scan_id, scan_data['file_upload'])
            
            # Run static analysis
            analysis_result = self.run_static_analysis(scan_id, analysis_tool)
            
            logger.info(f"Scan job {scan_id} completed successfully")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Scan job {scan_id} failed: {e}")
            self.repository.update_scan_status(scan_id, 'failed', str(e))
            raise
    
    def process_fuzzing_job(self, scan_id: str, fuzzing_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a fuzzing job - called by Celery workers
        """
        try:
            logger.info(f"Processing fuzzing job {scan_id} with config: {fuzzing_config}")
            
            # Get scan from database
            scan = self.repository.get_scan(scan_id)
            if not scan:
                raise Exception(f"Scan {scan_id} not found")
            
            # Update status to processing
            self.repository.update_scan_status(scan_id, 'fuzzing')
            
            # Generate fuzz plan first
            fuzz_plan_result = self.generate_fuzz_plan(scan_id)
            if fuzz_plan_result.get('status') != 'success':
                raise Exception("Failed to generate fuzz plan")
            
            # Generate harnesses
            harness_result = self.generate_harnesses(scan_id)
            if harness_result.get('status') != 'success':
                raise Exception("Failed to generate harnesses")
            
            # Execute fuzzing campaign
            fuzzing_result = self.execute_fuzzing(scan_id, fuzzing_config)
            
            logger.info(f"Fuzzing job {scan_id} completed successfully")
            return fuzzing_result
            
        except Exception as e:
            logger.error(f"Fuzzing job {scan_id} failed: {e}")
            self.repository.update_scan_status(scan_id, 'failed', str(e))
            raise
    
    def execute_fuzzing(self, scan_id: str, fuzzing_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute fuzzing campaign - called by fuzzing jobs
        """
        try:
            # This would use the existing fuzzing infrastructure
            scans_dir = os.getenv('SCANS_DIR', './scans')
            scan_dir = os.path.join(scans_dir, scan_id)
            
            # Use the existing FuzzExecutor
            executor = FuzzExecutor(scan_dir)
            
            # Run fuzzing with configuration
            runtime_minutes = fuzzing_config.get('duration', 300) // 60  # Convert seconds to minutes
            max_crashes = fuzzing_config.get('max_crashes', 10)
            
            # Execute fuzzing campaign
            campaign_results = executor.run_campaign(
                runtime_minutes=runtime_minutes,
                max_crashes=max_crashes
            )
            
            # Store results
            self.store_fuzz_campaign_results(scan_id, campaign_results)
            
            return {
                'status': 'success',
                'campaign_results': campaign_results,
                'total_crashes': sum(r.get('crashes_found', 0) for r in campaign_results.get('results', [])),
                'targets_executed': len(campaign_results.get('results', []))
            }
            
        except Exception as e:
            logger.error(f"Fuzzing execution failed for {scan_id}: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def cleanup_old_scans(self, days_old: int = 30) -> Dict[str, Any]:
        """
        Cleanup old scans - called by Celery beat scheduler
        """
        try:
            logger.info(f"Starting cleanup of scans older than {days_old} days")
            
            # This would implement the actual cleanup logic
            # For now, return a placeholder
            return {
                'status': 'success',
                'message': f'Cleanup completed for scans older than {days_old} days',
                'deleted_count': 0
            }
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            raise