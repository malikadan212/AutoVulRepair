import os
import json
import logging
from celery import Celery
from src.models.scan import get_session, Scan
from src.analysis.codeql import CodeQLAnalyzer
from src.analysis.cppcheck import CppcheckAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Celery
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
celery_app = Celery('vulnerability_scanner', broker=redis_url, backend=redis_url)

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
    """Route analysis to appropriate tool"""
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