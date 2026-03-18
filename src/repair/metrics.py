"""
Repair Metrics Tracking
Track success rates, timing, and performance metrics
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class RepairMetrics:
    """Track and save repair metrics"""
    
    def __init__(self, scan_id: str):
        """
        Initialize metrics tracker
        
        Args:
            scan_id: Scan ID
        """
        self.scan_id = scan_id
        self.metrics = {
            'scan_id': scan_id,
            'started_at': datetime.now().isoformat(),
            'completed_at': None,
            'total_time_seconds': None,
            'agents': [],
            'repairs': [],
            'summary': {
                'total_vulnerabilities': 0,
                'successful_repairs': 0,
                'failed_repairs': 0,
                'success_rate': 0.0,
                'average_time_per_repair': 0.0
            }
        }
        self._current_repair = None
        self._repair_start_time = None
    
    def start_repair(self, crash_id: str):
        """
        Start tracking a repair
        
        Args:
            crash_id: Crash/vulnerability ID
        """
        import time
        self._current_repair = crash_id
        self._repair_start_time = time.time()
        logger.info(f"Started tracking repair for {crash_id}")
    
    def end_repair(
        self,
        crash_id: str,
        success: bool,
        patches_generated: int = 0,
        best_score: float = 0.0
    ):
        """
        End tracking a repair
        
        Args:
            crash_id: Crash/vulnerability ID
            success: Whether repair succeeded
            patches_generated: Number of patches generated
            best_score: Best patch score (0.0-1.0)
        """
        import time
        
        if self._repair_start_time is None:
            logger.warning(f"end_repair called without start_repair for {crash_id}")
            duration = 0.0
        else:
            duration = time.time() - self._repair_start_time
        
        # Track the repair
        self.track_repair(
            vulnerability_id=crash_id,
            status='complete' if success else 'failed',
            duration=duration,
            patch_score=int(best_score * 100) if best_score else None,
            error=None if success else 'Repair failed'
        )
        
        # Reset tracking
        self._current_repair = None
        self._repair_start_time = None
        
        logger.info(f"Ended tracking repair for {crash_id}: success={success}, duration={duration:.2f}s")
    
    def track_agent(
        self,
        agent_name: str,
        duration: float,
        success: bool,
        details: Dict = None
    ):
        """
        Track agent execution
        
        Args:
            agent_name: Name of the agent
            duration: Execution time in seconds
            success: Whether agent succeeded
            details: Additional details (optional)
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'agent': agent_name,
            'duration': round(duration, 2),
            'success': success
        }
        
        if details:
            entry['details'] = details
        
        self.metrics['agents'].append(entry)
        logger.info(f"Tracked {agent_name}: {duration:.2f}s, success={success}")
    
    def track_repair(
        self,
        vulnerability_id: str,
        status: str,
        duration: float,
        patch_score: Optional[int] = None,
        error: Optional[str] = None
    ):
        """
        Track repair attempt
        
        Args:
            vulnerability_id: ID of vulnerability
            status: 'complete', 'failed', etc.
            duration: Time taken in seconds
            patch_score: Score of best patch (0-100)
            error: Error message if failed
        """
        entry = {
            'vulnerability_id': vulnerability_id,
            'status': status,
            'duration': round(duration, 2),
            'patch_score': patch_score,
            'timestamp': datetime.now().isoformat()
        }
        
        if error:
            entry['error'] = error
        
        self.metrics['repairs'].append(entry)
        
        # Update summary
        self.metrics['summary']['total_vulnerabilities'] += 1
        if status == 'complete':
            self.metrics['summary']['successful_repairs'] += 1
        else:
            self.metrics['summary']['failed_repairs'] += 1
        
        logger.info(f"Tracked repair {vulnerability_id}: {status}, {duration:.2f}s")
    
    def finalize(self):
        """Finalize metrics and calculate summary statistics"""
        self.metrics['completed_at'] = datetime.now().isoformat()
        
        # Calculate total time
        started = datetime.fromisoformat(self.metrics['started_at'])
        completed = datetime.fromisoformat(self.metrics['completed_at'])
        self.metrics['total_time_seconds'] = round((completed - started).total_seconds(), 2)
        
        # Calculate success rate
        total = self.metrics['summary']['total_vulnerabilities']
        successful = self.metrics['summary']['successful_repairs']
        
        if total > 0:
            self.metrics['summary']['success_rate'] = round((successful / total) * 100, 1)
            
            # Calculate average time
            total_time = sum(r['duration'] for r in self.metrics['repairs'])
            self.metrics['summary']['average_time_per_repair'] = round(total_time / total, 2)
        
        logger.info(f"Finalized metrics: {successful}/{total} successful ({self.metrics['summary']['success_rate']}%)")
    
    def save(self):
        """Save metrics to file"""
        try:
            scans_dir = os.getenv('SCANS_DIR', './scans')
            metrics_dir = os.path.join(scans_dir, self.scan_id, 'repair')
            os.makedirs(metrics_dir, exist_ok=True)
            
            metrics_path = os.path.join(metrics_dir, 'metrics.json')
            
            with open(metrics_path, 'w', encoding='utf-8') as f:
                json.dump(self.metrics, f, indent=2)
            
            logger.info(f"Saved metrics to {metrics_path}")
            
        except Exception as e:
            logger.error(f"Failed to save metrics: {e}")
    
    def get_summary(self) -> Dict:
        """Get summary statistics"""
        return self.metrics['summary']
    
    def get_agent_stats(self) -> Dict:
        """Get per-agent statistics"""
        stats = {}
        
        for entry in self.metrics['agents']:
            agent = entry['agent']
            if agent not in stats:
                stats[agent] = {
                    'total_calls': 0,
                    'successful_calls': 0,
                    'failed_calls': 0,
                    'total_time': 0.0,
                    'average_time': 0.0
                }
            
            stats[agent]['total_calls'] += 1
            stats[agent]['total_time'] += entry['duration']
            
            if entry['success']:
                stats[agent]['successful_calls'] += 1
            else:
                stats[agent]['failed_calls'] += 1
        
        # Calculate averages
        for agent, data in stats.items():
            if data['total_calls'] > 0:
                data['average_time'] = round(data['total_time'] / data['total_calls'], 2)
        
        return stats
    
    @staticmethod
    def load(scan_id: str) -> Optional['RepairMetrics']:
        """
        Load metrics from file
        
        Args:
            scan_id: Scan ID
            
        Returns:
            RepairMetrics instance or None if not found
        """
        try:
            scans_dir = os.getenv('SCANS_DIR', './scans')
            metrics_path = os.path.join(scans_dir, scan_id, 'repair', 'metrics.json')
            
            if not os.path.exists(metrics_path):
                return None
            
            with open(metrics_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            metrics = RepairMetrics(scan_id)
            metrics.metrics = data
            
            logger.info(f"Loaded metrics from {metrics_path}")
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to load metrics: {e}")
            return None


def format_metrics_report(metrics: RepairMetrics) -> str:
    """
    Format metrics as human-readable report
    
    Args:
        metrics: RepairMetrics instance
        
    Returns:
        Formatted report string
    """
    summary = metrics.get_summary()
    agent_stats = metrics.get_agent_stats()
    
    report = f"""
Repair Metrics Report
=====================
Scan ID: {metrics.scan_id}
Started: {metrics.metrics['started_at']}
Completed: {metrics.metrics['completed_at']}
Total Time: {metrics.metrics['total_time_seconds']}s

Summary
-------
Total Vulnerabilities: {summary['total_vulnerabilities']}
Successful Repairs: {summary['successful_repairs']}
Failed Repairs: {summary['failed_repairs']}
Success Rate: {summary['success_rate']}%
Average Time per Repair: {summary['average_time_per_repair']}s

Agent Performance
-----------------
"""
    
    for agent, stats in agent_stats.items():
        report += f"""
{agent}:
  Total Calls: {stats['total_calls']}
  Successful: {stats['successful_calls']}
  Failed: {stats['failed_calls']}
  Average Time: {stats['average_time']}s
"""
    
    return report
