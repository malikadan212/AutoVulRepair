"""
Background Job Worker
Processes scan jobs asynchronously using Celery
"""

import os
import sys
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional

from celery import Celery
from celery.signals import worker_ready, worker_shutdown

# Set up logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set Celery worker environment flag
os.environ['CELERY_WORKER'] = 'true'

try:
    from src.config.settings import get_settings
    settings = get_settings()
except Exception as e:
    logger.warning(f"Could not load settings: {e}. Using environment variables directly.")
    # Fallback to direct environment variable access
    class FallbackSettings:
        def __init__(self):
            self.REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self.DATABASE_URL = os.getenv('DATABASE_URL')
    settings = FallbackSettings()

# Initialize Celery
celery_app = Celery(
    'autovulrepair',
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=['src.workers.job_worker']
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes max per task
    task_soft_time_limit=25 * 60,  # 25 minutes soft limit
    worker_prefetch_multiplier=1,  # Process one task at a time
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks
)


@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Called when worker is ready to receive tasks"""
    logger.info("Worker is ready to process tasks")


@worker_shutdown.connect
def worker_shutdown_handler(sender=None, **kwargs):
    """Called when worker is shutting down"""
    logger.info("Worker is shutting down")


@celery_app.task(bind=True, name='process_scan')
def process_scan_task(self, scan_id: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a scan job in the background
    
    Args:
        scan_id: Unique scan identifier
        scan_data: Scan configuration and source code
        
    Returns:
        Dict with scan results
    """
    logger.info(f"Starting scan processing for scan_id: {scan_id}")
    
    try:
        # Import dependencies here to avoid import errors during module loading
        from src.services.scan_service import ScanService
        from src.repositories.scan_repository import ScanRepository
        from src.models.scan_v2 import DatabaseManager
        
        # Initialize database manager with correct connection
        DATABASE_URL = os.getenv('DATABASE_URL')
        db_manager = DatabaseManager(DATABASE_URL)
        scan_repository = ScanRepository(db_manager, use_database=True)
        scan_service = ScanService(scan_repository)
        
        # Update scan status to processing
        scan_service.update_scan_status(scan_id, 'processing', {
            'started_at': datetime.utcnow().isoformat(),
            'worker_id': self.request.id
        })
        
        # Process the scan
        result = scan_service.process_scan_job(scan_id, scan_data)
        
        # Update scan status to completed
        scan_service.update_scan_status(scan_id, 'completed', {
            'completed_at': datetime.utcnow().isoformat(),
            'processing_time': result.get('processing_time', 0)
        })
        
        # Trigger patch generation after scan completes
        try:
            from src.services.patch_generation_service import PatchGenerationService
            patch_gen_service = PatchGenerationService()
            patch_result = patch_gen_service.generate_all_patches(scan_id)
            logger.info(f"Patch generation initiated for scan {scan_id}: {patch_result}")
        except Exception as patch_error:
            logger.error(f"Failed to initiate patch generation for scan {scan_id}: {patch_error}")
            # Don't fail the scan if patch generation fails
        
        logger.info(f"Scan processing completed for scan_id: {scan_id}")
        return result
        
    except Exception as e:
        logger.error(f"Scan processing failed for scan_id: {scan_id}, error: {str(e)}")
        logger.error(traceback.format_exc())
        
        try:
            # Try to update scan status to failed
            scan_service.update_scan_status(scan_id, 'failed', {
                'failed_at': datetime.utcnow().isoformat(),
                'error': str(e),
                'traceback': traceback.format_exc()
            })
        except:
            pass  # Ignore errors when updating status
        
        # Re-raise the exception so Celery can handle retries
        raise
    finally:
        # No need to close session - DatabaseManager handles this
        pass


@celery_app.task(bind=True, name='process_fuzzing')
def process_fuzzing_task(self, scan_id: str, fuzzing_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process fuzzing job in the background
    
    Args:
        scan_id: Unique scan identifier
        fuzzing_config: Fuzzing configuration
        
    Returns:
        Dict with fuzzing results
    """
    logger.info(f"Starting fuzzing processing for scan_id: {scan_id}")
    
    try:
        # Import dependencies here to avoid import errors during module loading
        from src.services.scan_service import ScanService
        from src.repositories.scan_repository import ScanRepository
        from src.models.scan_v2 import DatabaseManager
        
        # Initialize database manager with correct connection
        DATABASE_URL = os.getenv('DATABASE_URL')
        db_manager = DatabaseManager(DATABASE_URL)
        scan_repository = ScanRepository(db_manager, use_database=True)
        scan_service = ScanService(scan_repository)
        
        # Update fuzzing status to processing
        scan_service.update_fuzzing_status(scan_id, 'processing', {
            'started_at': datetime.utcnow().isoformat(),
            'worker_id': self.request.id
        })
        
        # Process fuzzing
        result = scan_service.process_fuzzing_job(scan_id, fuzzing_config)
        
        # Update fuzzing status to completed
        scan_service.update_fuzzing_status(scan_id, 'completed', {
            'completed_at': datetime.utcnow().isoformat(),
            'processing_time': result.get('processing_time', 0)
        })
        
        logger.info(f"Fuzzing processing completed for scan_id: {scan_id}")
        return result
        
    except Exception as e:
        logger.error(f"Fuzzing processing failed for scan_id: {scan_id}, error: {str(e)}")
        logger.error(traceback.format_exc())
        
        try:
            # Try to update fuzzing status to failed
            scan_service.update_fuzzing_status(scan_id, 'failed', {
                'failed_at': datetime.utcnow().isoformat(),
                'error': str(e),
                'traceback': traceback.format_exc()
            })
        except:
            pass  # Ignore errors when updating status
        
        raise
    finally:
        try:
            session.close()
        except:
            pass


@celery_app.task(name='cleanup_old_scans')
def cleanup_old_scans_task(days_old: int = 30) -> Dict[str, Any]:
    """
    Cleanup old scan data
    
    Args:
        days_old: Delete scans older than this many days
        
    Returns:
        Dict with cleanup statistics
    """
    logger.info(f"Starting cleanup of scans older than {days_old} days")
    
    try:
        # Import dependencies here to avoid import errors during module loading
        from src.services.scan_service import ScanService
        from src.repositories.scan_repository import ScanRepository
        from src.models.scan_v2 import DatabaseManager
        
        # Initialize database manager with correct connection
        DATABASE_URL = os.getenv('DATABASE_URL')
        db_manager = DatabaseManager(DATABASE_URL)
        scan_repository = ScanRepository(db_manager, use_database=True)
        scan_service = ScanService(scan_repository)
        
        result = scan_service.cleanup_old_scans(days_old)
        logger.info(f"Cleanup completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise
    finally:
        try:
            session.close()
        except:
            pass


@celery_app.task(name='health_check')
def health_check_task() -> Dict[str, Any]:
    """
    Health check task for monitoring
    
    Returns:
        Dict with health status
    """
    try:
        # Import dependencies here to avoid import errors during module loading
        from src.models.scan_v2 import DatabaseManager
        
        # Initialize database manager with correct connection
        DATABASE_URL = os.getenv('DATABASE_URL')
        db_manager = DatabaseManager(DATABASE_URL)
        
        # Simple database connectivity check
        health = db_manager.health_check()
        
        return {
            'status': 'healthy' if health else 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'worker_id': health_check_task.request.id
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }


# Task routing configuration
celery_app.conf.task_routes = {
    'process_scan': {'queue': 'scan_queue'},
    'process_fuzzing': {'queue': 'fuzzing_queue'},
    'cleanup_old_scans': {'queue': 'maintenance_queue'},
    'health_check': {'queue': 'health_queue'},
}

# Periodic tasks configuration
celery_app.conf.beat_schedule = {
    'cleanup-old-scans': {
        'task': 'cleanup_old_scans',
        'schedule': 24 * 60 * 60,  # Run daily
        'args': (30,)  # Delete scans older than 30 days
    },
    'health-check': {
        'task': 'health_check',
        'schedule': 60,  # Run every minute
    },
}