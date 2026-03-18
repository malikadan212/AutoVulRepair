import os
import json
import logging
# Suppress noisy Celery Redis connection warnings
import warnings
warnings.filterwarnings('ignore', category=UserWarning, module='celery')

from celery import Celery
from src.models.scan import get_session, Scan
from src.analysis.codeql import CodeQLAnalyzer
from src.analysis.cppcheck import CppcheckAnalyzer

# Configure logging with timestamps
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Suppress Celery Redis connection errors - we fall back to sync if Redis is unavailable
import logging as std_logging
celery_logger = std_logging.getLogger('celery')
celery_logger.setLevel(std_logging.CRITICAL)  # Suppress all Celery messages below CRITICAL
# Suppress Redis backend connection retry messages completely
redis_logger = std_logging.getLogger('celery.backends.redis')
redis_logger.setLevel(std_logging.CRITICAL)  # Suppress all Redis connection retry messages
redis_connection_logger = std_logging.getLogger('celery.backends.redis.connection')
redis_connection_logger.setLevel(std_logging.CRITICAL)

# Initialize Celery with connection retry disabled for graceful fallback
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
celery_app = Celery(
    'vulnerability_scanner', 
    broker=redis_url, 
    backend=redis_url,
    broker_connection_retry_on_startup=False  # Don't retry connection on startup
)
celery_app.conf.broker_connection_retry = False  # Disable connection retries
celery_app.conf.broker_connection_max_retries = 0  # Don't retry at all
celery_app.conf.task_always_eager = False  # Keep async by default
# Suppress connection errors in Celery logs
celery_app.conf.broker_logging_level = 'CRITICAL'  # Only log critical broker errors
celery_app.conf.worker_logging_level = 'INFO'  # Keep worker logs at INFO

def _analyze_with_codeql_impl(scan_id):
    """Internal implementation of CodeQL analysis"""
    session = get_session()
    try:
        # Get scan record
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return {'status': 'failed', 'error': 'Scan not found'}
        
        # Update status to running
        scan.status = 'running'
        session.commit()
        
        # Initialize analyzer
        analyzer = CodeQLAnalyzer()
        
        # Determine source path
        scans_dir = os.getenv('SCANS_DIR', './scans')
        source_path = os.path.join(scans_dir, scan_id, 'source')
        
        # Ensure artifacts directory exists and pass it through
        scans_dir = os.path.abspath(os.getenv('SCANS_DIR', './scans'))
        artifacts_dir = os.path.join(scans_dir, scan_id, 'artifacts')
        os.makedirs(artifacts_dir, exist_ok=True)

        # Clone repository if source_type is repo_url
        if scan.source_type == 'repo_url' and scan.repo_url:
            logger.info(f"[CODEQL] Cloning repository: {scan.repo_url}")
            try:
                import subprocess
                clone_result = subprocess.run(
                    ['git', 'clone', '--depth', '1', scan.repo_url, source_path],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if clone_result.returncode != 0:
                    error_msg = f"Git clone failed: {clone_result.stderr}"
                    logger.error(f"[CODEQL] {error_msg}")
                    scan.status = 'failed'
                    session.commit()
                    return {'status': 'failed', 'error': error_msg}
                logger.info(f"[CODEQL] Repository cloned successfully")
            except subprocess.TimeoutExpired:
                error_msg = "Git clone timed out after 300 seconds"
                logger.error(f"[CODEQL] {error_msg}")
                scan.status = 'failed'
                session.commit()
                return {'status': 'failed', 'error': error_msg}
            except Exception as clone_error:
                error_msg = f"Failed to clone repository: {str(clone_error)}"
                logger.error(f"[CODEQL] {error_msg}")
                scan.status = 'failed'
                session.commit()
                return {'status': 'failed', 'error': error_msg}

        # Run analysis
        logger.info(f"[CODEQL] Starting analysis for scan {scan_id}")
        logger.info(f"[CODEQL] Source path: {source_path}, Source type: {scan.source_type}")
        import time
        start_time = time.time()
        vulnerabilities, patches = analyzer.analyze(source_path)
        elapsed = time.time() - start_time
        
        # Convert CodeQL results to static_findings.json for Module 2 (if converter exists)
        try:
            from src.module1.codeql_to_findings import convert_codeql_to_findings
            static_findings_path = os.path.join(scans_dir, scan_id, 'static_findings.json')
            logger.info(f"[CODEQL] Converting results to static_findings.json: {static_findings_path}")
            # CodeQL converter would need to be implemented
            logger.info(f"[CODEQL] Conversion complete - ready for Module 2 fuzz plan generation")
        except ImportError:
            logger.info(f"[CODEQL] CodeQL to findings converter not yet implemented")
        except Exception as conv_error:
            logger.warning(f"[CODEQL] Failed to convert to static_findings.json: {conv_error}")
        
        # Update scan with results
        scan.status = 'completed'
        scan.vulnerabilities_json = vulnerabilities
        scan.patches_json = patches
        scan.artifacts_path = os.path.join(scans_dir, scan_id, 'artifacts')
        session.commit()
        
        logger.info(f"[CODEQL] Analysis completed for scan {scan_id} in {elapsed:.2f} seconds")
        logger.info(f"[CODEQL] Found {len(vulnerabilities)} vulnerabilities and {len(patches)} patches")
        return {'status': 'completed', 'vulnerabilities': len(vulnerabilities), 'patches': len(patches)}
        
    except Exception as e:
        logger.error(f"CodeQL analysis failed for scan {scan_id}: {str(e)}")
        scan.status = 'failed'
        session.commit()
        return {'status': 'failed', 'error': str(e)}
    finally:
        session.close()

def _analyze_with_cppcheck_impl(scan_id):
    """Internal implementation of Cppcheck analysis"""
    session = get_session()
    try:
        # Get scan record
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return {'status': 'failed', 'error': 'Scan not found'}
        
        # Update status to running
        scan.status = 'running'
        session.commit()
        
        # Initialize analyzer
        analyzer = CppcheckAnalyzer()
        
        # Determine source path
        scans_dir = os.path.abspath(os.getenv('SCANS_DIR', './scans'))
        source_path = os.path.join(scans_dir, scan_id, 'source')
        
        # Ensure artifacts directory exists and pass it through
        scans_dir = os.path.abspath(os.getenv('SCANS_DIR', './scans'))
        artifacts_dir = os.path.join(scans_dir, scan_id, 'artifacts')
        os.makedirs(artifacts_dir, exist_ok=True)

        # Clone repository if source_type is repo_url
        logger.info(f"[CPPCHECK] DEBUG: source_type={scan.source_type}, repo_url={scan.repo_url}")
        if scan.source_type == 'repo_url' and scan.repo_url:
            logger.info(f"[CPPCHECK] Cloning repository: {scan.repo_url}")
            try:
                import subprocess
                clone_result = subprocess.run(
                    ['git', 'clone', '--depth', '1', scan.repo_url, source_path],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if clone_result.returncode != 0:
                    error_msg = f"Git clone failed: {clone_result.stderr}"
                    logger.error(f"[CPPCHECK] {error_msg}")
                    scan.status = 'failed'
                    session.commit()
                    return {'status': 'failed', 'error': error_msg}
                logger.info(f"[CPPCHECK] Repository cloned successfully")
            except subprocess.TimeoutExpired:
                error_msg = "Git clone timed out after 300 seconds"
                logger.error(f"[CPPCHECK] {error_msg}")
                scan.status = 'failed'
                session.commit()
                return {'status': 'failed', 'error': error_msg}
            except Exception as clone_error:
                error_msg = f"Failed to clone repository: {str(clone_error)}"
                logger.error(f"[CPPCHECK] {error_msg}")
                scan.status = 'failed'
                session.commit()
                return {'status': 'failed', 'error': error_msg}

        # Run analysis
        logger.info(f"[CPPCHECK] Starting analysis for scan {scan_id}")
        logger.info(f"[CPPCHECK] Source path: {source_path}, Source type: {scan.source_type}, Repo URL: {scan.repo_url}")
        logger.info(f"[CPPCHECK] Calling analyzer.analyze() now...")
        import time
        start_time = time.time()
        try:
            vulnerabilities, patches = analyzer.analyze(source_path, scan.source_type, scan.repo_url)
            elapsed = time.time() - start_time
            logger.info(f"[CPPCHECK] analyzer.analyze() returned - vulnerabilities: {len(vulnerabilities)}, patches: {len(patches)}")
        except Exception as analyze_error:
            elapsed = time.time() - start_time
            logger.error(f"[CPPCHECK] analyzer.analyze() failed after {elapsed:.2f} seconds: {analyze_error}", exc_info=True)
            raise
        
        # Convert cppcheck XML to static_findings.json for Module 2
        cppcheck_xml = os.path.join(artifacts_dir, 'cppcheck-report.xml')
        if os.path.exists(cppcheck_xml):
            try:
                from src.module1.cppcheck_to_findings import convert_cppcheck_to_findings
                static_findings_path = os.path.join(scans_dir, scan_id, 'static_findings.json')
                logger.info(f"[CPPCHECK] Converting XML to static_findings.json: {static_findings_path}")
                convert_cppcheck_to_findings(cppcheck_xml, static_findings_path)
                logger.info(f"[CPPCHECK] Conversion complete - ready for Module 2 fuzz plan generation")
            except Exception as conv_error:
                logger.warning(f"[CPPCHECK] Failed to convert to static_findings.json: {conv_error}")
                # Don't fail the scan if conversion fails
        
        # Update scan with results
        scan.status = 'completed'
        scan.vulnerabilities_json = vulnerabilities
        scan.patches_json = patches
        scan.artifacts_path = os.path.join(scans_dir, scan_id, 'artifacts')
        session.commit()
        
        logger.info(f"[CPPCHECK] Analysis completed for scan {scan_id} in {elapsed:.2f} seconds")
        logger.info(f"[CPPCHECK] Found {len(vulnerabilities)} vulnerabilities and {len(patches)} patches")
        return {'status': 'completed', 'vulnerabilities': len(vulnerabilities), 'patches': len(patches)}
        
    except Exception as e:
        logger.error(f"Cppcheck analysis failed for scan {scan_id}: {str(e)}")
        scan.status = 'failed'
        session.commit()
        return {'status': 'failed', 'error': str(e)}
    finally:
        session.close()

@celery_app.task(bind=True)
def analyze_with_codeql(self, scan_id):
    """Celery task wrapper for CodeQL analysis"""
    return _analyze_with_codeql_impl(scan_id)

@celery_app.task(bind=True)
def analyze_with_cppcheck(self, scan_id):
    """Celery task wrapper for Cppcheck analysis"""
    return _analyze_with_cppcheck_impl(scan_id)

# Task routing
@celery_app.task(bind=True)
def analyze_code(self, scan_id, analysis_tool):
    """Route analysis to appropriate tool (Celery async)"""
    if analysis_tool == 'codeql':
        return _analyze_with_codeql_impl(scan_id)
    elif analysis_tool == 'cppcheck':
        return _analyze_with_cppcheck_impl(scan_id)
    else:
        logger.error(f"Unknown analysis tool: {analysis_tool}")
        session = get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status = 'failed'
                session.commit()
        finally:
            session.close()
        return {'status': 'failed', 'error': f'Unknown analysis tool: {analysis_tool}'}

# Synchronous version for testing without Redis
def analyze_code_sync(scan_id, analysis_tool):
    """Synchronous version for testing without Redis"""
    logger.info(f"[SYNC_ANALYSIS] Starting synchronous analysis for scan {scan_id}, tool: {analysis_tool}")
    try:
        if analysis_tool == 'codeql':
            # Call the implementation directly (not as Celery task)
            result = _analyze_with_codeql_impl(scan_id)
            return result
        elif analysis_tool == 'cppcheck':
            # Call the implementation directly (not as Celery task)
            result = _analyze_with_cppcheck_impl(scan_id)
            return result
        else:
            logger.error(f"[SYNC_ANALYSIS] Unknown analysis tool: {analysis_tool}")
            session = get_session()
            try:
                scan = session.query(Scan).filter_by(id=scan_id).first()
                if scan:
                    scan.status = 'failed'
                    session.commit()
            finally:
                session.close()
            return {'status': 'failed', 'error': f'Unknown analysis tool: {analysis_tool}'}
    except Exception as e:
        logger.error(f"[SYNC_ANALYSIS] Error in synchronous analysis: {e}", exc_info=True)
        session = get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status = 'failed'
                session.commit()
        finally:
            session.close()
        raise