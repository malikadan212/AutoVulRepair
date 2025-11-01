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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress Celery Redis connection errors
import logging as std_logging
celery_logger = std_logging.getLogger('celery')
celery_logger.setLevel(std_logging.WARNING)  # Only show warnings/errors, not connection retries
# Suppress Redis backend connection retry messages
redis_logger = std_logging.getLogger('celery.backends.redis')
redis_logger.setLevel(std_logging.ERROR)  # Only show actual errors

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

@celery_app.task(bind=True)
def analyze_with_codeql(self, scan_id):
    """Celery task for CodeQL analysis"""
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
        
        # Run analysis
        logger.info(f"Starting CodeQL analysis for scan {scan_id}")
        vulnerabilities, patches = analyzer.analyze(source_path, scan.source_type, scan.repo_url)
        
        # Update scan with results
        scan.status = 'completed'
        scan.vulnerabilities_json = vulnerabilities
        scan.patches_json = patches
        scan.artifacts_path = os.path.join(scans_dir, scan_id, 'artifacts')
        session.commit()
        
        logger.info(f"CodeQL analysis completed for scan {scan_id}")
        return {'status': 'completed', 'vulnerabilities': len(vulnerabilities), 'patches': len(patches)}
        
    except Exception as e:
        logger.error(f"CodeQL analysis failed for scan {scan_id}: {str(e)}")
        scan.status = 'failed'
        session.commit()
        return {'status': 'failed', 'error': str(e)}
    finally:
        session.close()

@celery_app.task(bind=True)
def analyze_with_cppcheck(self, scan_id):
    """Celery task for Cppcheck analysis"""
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
        scans_dir = os.getenv('SCANS_DIR', './scans')
        source_path = os.path.join(scans_dir, scan_id, 'source')
        
        # Run analysis
        logger.info(f"Starting Cppcheck analysis for scan {scan_id}")
        vulnerabilities, patches = analyzer.analyze(source_path, scan.source_type, scan.repo_url)
        
        # Update scan with results
        scan.status = 'completed'
        scan.vulnerabilities_json = vulnerabilities
        scan.patches_json = patches
        scan.artifacts_path = os.path.join(scans_dir, scan_id, 'artifacts')
        session.commit()
        
        logger.info(f"Cppcheck analysis completed for scan {scan_id}")
        return {'status': 'completed', 'vulnerabilities': len(vulnerabilities), 'patches': len(patches)}
        
    except Exception as e:
        logger.error(f"Cppcheck analysis failed for scan {scan_id}: {str(e)}")
        scan.status = 'failed'
        session.commit()
        return {'status': 'failed', 'error': str(e)}
    finally:
        session.close()

# Task routing
@celery_app.task(bind=True)
def analyze_code(self, scan_id, analysis_tool):
    """Route analysis to appropriate tool (Celery async)"""
    if analysis_tool == 'codeql':
        return analyze_with_codeql(scan_id)
    elif analysis_tool == 'cppcheck':
        return analyze_with_cppcheck(scan_id)
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
    if analysis_tool == 'codeql':
        return analyze_with_codeql(scan_id)
    elif analysis_tool == 'cppcheck':
        return analyze_with_cppcheck(scan_id)
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