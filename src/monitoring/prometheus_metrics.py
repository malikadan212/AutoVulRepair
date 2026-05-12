"""
Prometheus Metrics for Enterprise Monitoring
Comprehensive metrics collection for observability
"""

import time
import logging
from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest
from functools import wraps
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Application metrics
scan_requests_total = Counter(
    'autovulrepair_scan_requests_total',
    'Total number of scan requests',
    ['source_type', 'analysis_tool', 'user_type']
)

scan_duration_seconds = Histogram(
    'autovulrepair_scan_duration_seconds',
    'Time spent processing scans',
    ['analysis_tool', 'status'],
    buckets=[30, 60, 120, 300, 600, 1200, 3600]
)

vulnerabilities_found_total = Counter(
    'autovulrepair_vulnerabilities_found_total',
    'Total vulnerabilities found',
    ['severity', 'bug_class', 'analysis_tool']
)

active_scans_gauge = Gauge(
    'autovulrepair_active_scans',
    'Number of currently active scans'
)

user_sessions_gauge = Gauge(
    'autovulrepair_active_user_sessions',
    'Number of active user sessions'
)

github_api_requests_total = Counter(
    'autovulrepair_github_api_requests_total',
    'Total GitHub API requests',
    ['endpoint', 'status_code']
)

github_rate_limit_remaining = Gauge(
    'autovulrepair_github_rate_limit_remaining',
    'Remaining GitHub API rate limit'
)

database_connections_active = Gauge(
    'autovulrepair_database_connections_active',
    'Active database connections'
)

celery_tasks_total = Counter(
    'autovulrepair_celery_tasks_total',
    'Total Celery tasks',
    ['task_name', 'status']
)

celery_task_duration_seconds = Histogram(
    'autovulrepair_celery_task_duration_seconds',
    'Celery task execution time',
    ['task_name'],
    buckets=[1, 5, 10, 30, 60, 300, 600, 1800]
)

# System info
app_info = Info(
    'autovulrepair_app_info',
    'Application information'
)

class MetricsCollector:
    """Centralized metrics collection"""
    
    @staticmethod
    def record_scan_request(source_type: str, analysis_tool: str, user_type: str = 'authenticated'):
        """Record a scan request"""
        scan_requests_total.labels(
            source_type=source_type,
            analysis_tool=analysis_tool,
            user_type=user_type
        ).inc()
    
    @staticmethod
    def record_scan_duration(analysis_tool: str, status: str, duration: float):
        """Record scan completion time"""
        scan_duration_seconds.labels(
            analysis_tool=analysis_tool,
            status=status
        ).observe(duration)
    
    @staticmethod
    def record_vulnerabilities(findings: list, analysis_tool: str):
        """Record vulnerability findings"""
        for finding in findings:
            vulnerabilities_found_total.labels(
                severity=finding.get('severity', 'unknown'),
                bug_class=finding.get('bug_class', 'unknown'),
                analysis_tool=analysis_tool
            ).inc()
    
    @staticmethod
    def update_active_scans(count: int):
        """Update active scans gauge"""
        active_scans_gauge.set(count)
    
    @staticmethod
    def update_user_sessions(count: int):
        """Update active user sessions"""
        user_sessions_gauge.set(count)
    
    @staticmethod
    def record_github_api_call(endpoint: str, status_code: int):
        """Record GitHub API usage"""
        github_api_requests_total.labels(
            endpoint=endpoint,
            status_code=status_code
        ).inc()
    
    @staticmethod
    def update_github_rate_limit(remaining: int):
        """Update GitHub rate limit"""
        github_rate_limit_remaining.set(remaining)
    
    @staticmethod
    def record_celery_task(task_name: str, status: str, duration: float = None):
        """Record Celery task metrics"""
        celery_tasks_total.labels(
            task_name=task_name,
            status=status
        ).inc()
        
        if duration is not None:
            celery_task_duration_seconds.labels(
                task_name=task_name
            ).observe(duration)

def monitor_scan_performance(analysis_tool: str):
    """Decorator to monitor scan performance"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            status = 'success'
            
            try:
                result = func(*args, **kwargs)
                
                # Record vulnerabilities if found
                if isinstance(result, tuple) and len(result) >= 2:
                    vulnerabilities, _ = result
                    MetricsCollector.record_vulnerabilities(vulnerabilities, analysis_tool)
                
                return result
            except Exception as e:
                status = 'error'
                raise
            finally:
                duration = time.time() - start_time
                MetricsCollector.record_scan_duration(analysis_tool, status, duration)
        
        return wrapper
    return decorator

def monitor_github_api():
    """Decorator to monitor GitHub API calls"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = func.__name__
            status_code = 200
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status_code = 500
                raise
            finally:
                MetricsCollector.record_github_api_call(endpoint, status_code)
        
        return wrapper
    return decorator

def get_prometheus_metrics() -> str:
    """Generate Prometheus metrics output"""
    try:
        # Update system metrics
        from src.services.scan_service import scan_service
        
        # Get active scans count
        try:
            stats = scan_service.get_system_stats()
            MetricsCollector.update_active_scans(stats.get('storage', {}).get('active_scans', 0))
        except Exception as e:
            logger.warning(f"Failed to update scan metrics: {e}")
        
        # Set application info
        app_info.info({
            'version': '2.0.0',
            'environment': 'production',
            'build_date': '2024-04-10'
        })
        
        return generate_latest()
    except Exception as e:
        logger.error(f"Failed to generate Prometheus metrics: {e}")
        return "# Error generating metrics\n"