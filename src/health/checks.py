"""
Health check endpoints for Kubernetes probes
"""
import time
import logging
from flask import jsonify

logger = logging.getLogger(__name__)

class HealthChecker:
    """Health check utilities for Kubernetes"""
    
    @staticmethod
    def check_database():
        """Check database connectivity"""
        try:
            from src.database.connection import DatabaseConfig
            return DatabaseConfig.test_connection()
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    @staticmethod
    def check_redis():
        """Check Redis connectivity"""
        try:
            # Import here to avoid circular imports
            try:
                from src.workers.job_worker import celery_app
            except ImportError:
                from src.queue.tasks import celery_app
            
            # Use Celery's Redis connection
            result = celery_app.control.ping(timeout=5)
            return len(result) > 0 if result else False
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False
    
    @staticmethod
    def check_disk_space():
        """Check available disk space"""
        try:
            import shutil
            import os
            scans_dir = os.getenv('SCANS_DIR', '/app/scans')
            
            # Create directory if it doesn't exist
            if not os.path.exists(scans_dir):
                os.makedirs(scans_dir, exist_ok=True)
            
            total, used, free = shutil.disk_usage(scans_dir)
            
            # Alert if less than 1GB free
            free_gb = free // (1024**3)
            return free_gb > 1
        except Exception as e:
            logger.error(f"Disk space check failed: {e}")
            return False
    
    @staticmethod
    def liveness_probe():
        """
        Kubernetes liveness probe
        Returns 200 if the application is alive (basic functionality)
        """
        try:
            # Basic application health
            status = {
                'status': 'alive',
                'timestamp': time.time(),
                'service': 'autovulrepair'
            }
            return jsonify(status), 200
        except Exception as e:
            logger.error(f"Liveness probe failed: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    @staticmethod
    def readiness_probe():
        """
        Kubernetes readiness probe
        Returns 200 only if the application is ready to serve traffic
        """
        try:
            checks = {
                'database': HealthChecker.check_database(),
                'redis': HealthChecker.check_redis(),
                'disk_space': HealthChecker.check_disk_space()
            }
            
            all_healthy = all(checks.values())
            
            status = {
                'status': 'ready' if all_healthy else 'not_ready',
                'timestamp': time.time(),
                'checks': checks,
                'service': 'autovulrepair'
            }
            
            return jsonify(status), 200 if all_healthy else 503
            
        except Exception as e:
            logger.error(f"Readiness probe failed: {e}")
            return jsonify({
                'status': 'error', 
                'message': str(e),
                'timestamp': time.time()
            }), 500
    
    @staticmethod
    def startup_probe():
        """
        Kubernetes startup probe
        Returns 200 when the application has finished starting up
        """
        try:
            # Check if critical services are available
            db_ready = HealthChecker.check_database()
            
            if db_ready:
                status = {
                    'status': 'started',
                    'timestamp': time.time(),
                    'service': 'autovulrepair'
                }
                return jsonify(status), 200
            else:
                return jsonify({
                    'status': 'starting',
                    'message': 'Database not ready',
                    'timestamp': time.time()
                }), 503
                
        except Exception as e:
            logger.error(f"Startup probe failed: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'timestamp': time.time()
            }), 500

def register_health_routes(app):
    """Register health check routes with Flask app"""
    
    @app.route('/health')
    @app.route('/health/live')
    def health_live():
        """Liveness probe endpoint"""
        return HealthChecker.liveness_probe()
    
    @app.route('/health/ready')
    def health_ready():
        """Readiness probe endpoint"""
        return HealthChecker.readiness_probe()
    
    @app.route('/health/startup')
    def health_startup():
        """Startup probe endpoint"""
        return HealthChecker.startup_probe()
    
    @app.route('/metrics')
    def metrics():
        """Basic metrics endpoint for monitoring"""
        try:
            # Import here to avoid circular imports
            # Try new database system first
            from src.models.scan_v2 import DatabaseManager
            from src.repositories.scan_repository import ScanRepository
            import os
            
            DATABASE_URL = os.getenv('DATABASE_URL')
            if DATABASE_URL:
                try:
                    db_manager = DatabaseManager(DATABASE_URL)
                    if db_manager.health_check():
                        scan_repository = ScanRepository(db_manager, use_database=True)
                        stats = scan_repository.get_storage_stats()
                        
                        metrics_data = {
                            'autovulrepair_scans_total': stats.get('total_scans', 0),
                            'autovulrepair_scans_completed': stats.get('completed_scans', 0),
                            'autovulrepair_scans_failed': stats.get('failed_scans', 0),
                            'autovulrepair_scans_running': stats.get('active_scans', 0),
                            'autovulrepair_database_type': 'postgresql'
                        }
                        
                        # Format as Prometheus metrics
                        prometheus_metrics = []
                        for metric_name, value in metrics_data.items():
                            if metric_name == 'autovulrepair_database_type':
                                prometheus_metrics.append(f'{metric_name}{{type="{value}"}} 1')
                            else:
                                prometheus_metrics.append(f'{metric_name} {value}')
                        
                        return '\n'.join(prometheus_metrics)
                        
                except Exception as e:
                    logger.warning(f"New database system failed for metrics: {e}")
            
            # Fallback to legacy system
            from src.models.scan import get_session, Scan
            
            session = get_session()
            try:
                # Get basic metrics
                total_scans = session.query(Scan).count()
                completed_scans = session.query(Scan).filter(Scan.status == 'completed').count()
                failed_scans = session.query(Scan).filter(Scan.status == 'failed').count()
                running_scans = session.query(Scan).filter(Scan.status == 'running').count()
                
                metrics_data = {
                    'autovulrepair_scans_total': total_scans,
                    'autovulrepair_scans_completed': completed_scans,
                    'autovulrepair_scans_failed': failed_scans,
                    'autovulrepair_scans_running': running_scans,
                    'autovulrepair_success_rate': (completed_scans / total_scans * 100) if total_scans > 0 else 0
                }
                
                return jsonify(metrics_data), 200
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Metrics endpoint failed: {e}")
            return jsonify({'error': str(e)}), 500