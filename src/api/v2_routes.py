"""
API v2 routes - Production-ready endpoints using database storage
These routes will gradually replace the existing file-based endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from typing import Dict, Any
import os
import logging

from src.services.scan_service import ScanService
from src.repositories.scan_repository import ScanRepository
from src.models.scan_v2 import DatabaseManager

# Create blueprint for v2 API
api_v2 = Blueprint('api_v2', __name__, url_prefix='/api/v2')

logger = logging.getLogger(__name__)

# Global service instance (will be initialized in app factory)
scan_service: ScanService = None

def init_v2_api(app):
    """Initialize v2 API with database connection"""
    global scan_service
    
    # Get database URL from config
    database_url = app.config.get('DATABASE_URL') or os.getenv('DATABASE_URL')
    if not database_url:
        logger.warning("No DATABASE_URL configured, v2 API will use legacy mode")
        use_database = False
    else:
        use_database = True
    
    # Initialize database manager
    if use_database:
        db_manager = DatabaseManager(database_url)
        # Create tables if they don't exist
        try:
            db_manager.create_tables()
            logger.info("Database tables created/verified")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            use_database = False
    else:
        db_manager = None
    
    # Initialize repository and service
    repository = ScanRepository(db_manager, use_database=use_database)
    scan_service = ScanService(repository)
    
    logger.info(f"V2 API initialized with {'database' if use_database else 'legacy'} storage")

# ============================================================================
# Health and Status Endpoints
# ============================================================================

@api_v2.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database connectivity if using database
        if scan_service.repository.use_database:
            db_healthy = scan_service.repository.db_manager.health_check()
        else:
            db_healthy = True  # Legacy mode doesn't need DB
        
        return jsonify({
            'status': 'healthy' if db_healthy else 'degraded',
            'database': 'connected' if db_healthy else 'disconnected',
            'storage_mode': 'database' if scan_service.repository.use_database else 'filesystem',
            'version': '2.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'version': '2.0'
        }), 500

@api_v2.route('/stats', methods=['GET'])
def system_stats():
    """Get system statistics"""
    try:
        stats = scan_service.get_system_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Scan Management Endpoints
# ============================================================================

@api_v2.route('/scans', methods=['POST'])
def create_scan():
    """
    Create a new scan
    
    Body:
    {
        "source_type": "snippet|repository|file_upload",
        "repo_url": "https://github.com/user/repo",  // for repository
        "code_snippet": "int main() { ... }",        // for snippet
        "analysis_tool": "cppcheck",                  // optional
        "user_id": "user123"                          // optional
    }
    """
    try:
        data = request.get_json() or {}
        
        # Validate required fields
        source_type = data.get('source_type')
        if not source_type or source_type not in ['snippet', 'repository', 'file_upload']:
            return jsonify({
                'error': 'Invalid or missing source_type. Must be: snippet, repository, or file_upload'
            }), 400
        
        # Validate source-specific fields
        if source_type == 'snippet' and not data.get('code_snippet'):
            return jsonify({'error': 'code_snippet is required for snippet scans'}), 400
        elif source_type == 'repository' and not data.get('repo_url'):
            return jsonify({'error': 'repo_url is required for repository scans'}), 400
        
        # Create scan
        result = scan_service.create_scan(
            source_type=source_type,
            repo_url=data.get('repo_url'),
            code_snippet=data.get('code_snippet'),
            file_upload=request.files.get('file') if source_type == 'file_upload' else None,
            analysis_tool=data.get('analysis_tool', 'cppcheck'),
            user_id=data.get('user_id')
        )
        
        return jsonify(result), 201 if result.get('status') != 'failed' else 400
        
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        return jsonify({'error': str(e)}), 500

@api_v2.route('/scans/<scan_id>', methods=['GET'])
def get_scan(scan_id: str):
    """Get scan information"""
    try:
        scan = scan_service.get_scan_status(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(scan)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_v2.route('/scans/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id: str):
    """Get complete scan results"""
    try:
        results = scan_service.get_scan_results(scan_id)
        if 'error' in results:
            return jsonify(results), 404
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_v2.route('/scans/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id: str):
    """Get scan status (lightweight endpoint)"""
    try:
        scan = scan_service.get_scan_status(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Return only status-related fields
        return jsonify({
            'scan_id': scan['scan_id'],
            'status': scan['status'],
            'created_at': scan.get('created_at'),
            'started_at': scan.get('started_at'),
            'completed_at': scan.get('completed_at'),
            'error_message': scan.get('error_message')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Analysis Pipeline Endpoints
# ============================================================================

@api_v2.route('/scans/<scan_id>/analyze', methods=['POST'])
def run_analysis(scan_id: str):
    """
    Run static analysis on a scan
    
    Body:
    {
        "analysis_tool": "cppcheck"  // optional
    }
    """
    try:
        data = request.get_json() or {}
        analysis_tool = data.get('analysis_tool', 'cppcheck')
        
        result = scan_service.run_static_analysis(scan_id, analysis_tool)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_v2.route('/scans/<scan_id>/fuzz-plan', methods=['POST'])
def generate_fuzz_plan(scan_id: str):
    """Generate fuzz plan from static findings"""
    try:
        result = scan_service.generate_fuzz_plan(scan_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_v2.route('/scans/<scan_id>/harnesses', methods=['POST'])
def generate_harnesses(scan_id: str):
    """Generate fuzzing harnesses"""
    try:
        result = scan_service.generate_harnesses(scan_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_v2.route('/scans/<scan_id>/fuzz', methods=['POST'])
def run_fuzzing(scan_id: str):
    """
    Run fuzzing campaign
    
    Body:
    {
        "runtime_minutes": 5,  // optional
        "max_targets": 10      // optional
    }
    """
    try:
        data = request.get_json() or {}
        runtime_minutes = data.get('runtime_minutes', 5)
        
        result = scan_service.run_fuzzing_campaign(scan_id, runtime_minutes)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Background Job Endpoints
# ============================================================================

@api_v2.route('/jobs/next', methods=['POST'])
def process_next_job():
    """Process the next job in the queue (for worker processes)"""
    try:
        result = scan_service.process_next_job()
        if result:
            return jsonify(result)
        else:
            return jsonify({'message': 'No jobs available'}), 204
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Maintenance Endpoints
# ============================================================================

@api_v2.route('/maintenance/cleanup', methods=['POST'])
def cleanup_old_scans():
    """
    Clean up old scan data
    
    Body:
    {
        "older_than_days": 30  // optional, default 30
    }
    """
    try:
        data = request.get_json() or {}
        older_than_days = data.get('older_than_days', 30)
        
        result = scan_service.cleanup_old_scans(older_than_days)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Migration Endpoints (for transitioning from v1 to v2)
# ============================================================================

@api_v2.route('/migration/status', methods=['GET'])
def migration_status():
    """Get migration status"""
    return jsonify({
        'storage_mode': 'database' if scan_service.repository.use_database else 'filesystem',
        'v1_compatible': True,
        'migration_complete': scan_service.repository.use_database
    })

@api_v2.route('/migration/migrate-scan/<scan_id>', methods=['POST'])
def migrate_scan(scan_id: str):
    """Migrate a specific scan from filesystem to database"""
    if scan_service.repository.use_database:
        return jsonify({'error': 'Already using database storage'}), 400
    
    # TODO: Implement scan migration logic
    return jsonify({'error': 'Migration not yet implemented'}), 501

# ============================================================================
# Error Handlers
# ============================================================================

@api_v2.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@api_v2.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@api_v2.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500