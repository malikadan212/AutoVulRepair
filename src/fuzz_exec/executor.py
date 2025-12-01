"""
Fuzz Execution Module
Runs fuzz targets and monitors for crashes
"""

import os
import json
import subprocess
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class FuzzExecutor:
    """Execute fuzz targets and collect results"""
    
    def __init__(self, scan_dir: str):
        self.scan_dir = scan_dir
        self.build_dir = os.path.join(scan_dir, 'build')
        self.fuzz_dir = os.path.join(scan_dir, 'fuzz')
        self.results_dir = os.path.join(self.fuzz_dir, 'results')
        self.crashes_dir = os.path.join(self.fuzz_dir, 'crashes')
        
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.crashes_dir, exist_ok=True)
    
    def run_campaign(self, runtime_minutes: int = 5, max_targets: Optional[int] = None) -> Dict:
        """
        Run fuzzing campaign on all built targets
        
        Args:
            runtime_minutes: How long to fuzz each target
            max_targets: Maximum number of targets to run (None = all)
        
        Returns:
            Campaign results dictionary
        """
        logger.info(f"Starting fuzzing campaign for {self.scan_dir}")
        
        # Find all built fuzz targets
        if not os.path.exists(self.build_dir):
            return {'error': 'Build directory not found'}
        
        targets = [f for f in os.listdir(self.build_dir) 
                  if f.startswith('fuzz_') and os.access(os.path.join(self.build_dir, f), os.X_OK)]
        
        if not targets:
            return {'error': 'No fuzz targets found'}
        
        if max_targets:
            targets = targets[:max_targets]
        
        logger.info(f"Found {len(targets)} fuzz targets")
        
        # Run each target
        results = []
        start_time = time.time()
        
        for i, target in enumerate(targets, 1):
            logger.info(f"Running target {i}/{len(targets)}: {target}")
            result = self._run_single_target(target, runtime_minutes)
            results.append(result)
        
        total_time = time.time() - start_time
        
        # Save campaign results
        campaign_data = {
            'timestamp': datetime.now().isoformat(),
            'scan_dir': self.scan_dir,
            'runtime_minutes': runtime_minutes,
            'total_targets': len(targets),
            'total_time': round(total_time, 2),
            'results': results
        }
        
        self._save_campaign_results(campaign_data)
        
        return campaign_data
    
    def _run_single_target(self, target_name: str, runtime_minutes: int) -> Dict:
        """Run a single fuzz target"""
        target_path = os.path.join(self.build_dir, target_name)
        crash_dir = os.path.join(self.crashes_dir, target_name)
        os.makedirs(crash_dir, exist_ok=True)
        
        # Check if running in Docker or on host
        in_docker = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')
        
        if in_docker:
            # Running inside Docker - execute directly
            cmd = [
                target_path,
                f'-max_total_time={runtime_minutes * 60}',
                f'-artifact_prefix={crash_dir}/',
                '-print_final_stats=1'
            ]
        else:
            # Running on host (Windows) - execute via Docker
            # Convert Windows paths to Docker paths
            scan_id = os.path.basename(self.scan_dir)
            docker_target_path = f'/app/scans/{scan_id}/build/{target_name}'
            docker_crash_dir = f'/app/scans/{scan_id}/fuzz/crashes/{target_name}'
            
            cmd = [
                'docker', 'run', '--rm',
                '-v', f'{os.path.abspath(self.scan_dir)}:/app/scans/{scan_id}',
                'autovulrepair-app:latest',
                docker_target_path,
                f'-max_total_time={runtime_minutes * 60}',
                f'-artifact_prefix={docker_crash_dir}/',
                '-print_final_stats=1'
            ]
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=(runtime_minutes * 60) + 30
            )
            
            elapsed = time.time() - start_time
            
            # Parse output for stats
            output = result.stdout + result.stderr
            stats = self._parse_fuzzer_stats(output)
            
            # Check for crashes
            crashes = self._find_crashes(crash_dir)
            
            return {
                'target': target_name,
                'status': 'completed',
                'runtime': round(elapsed, 2),
                'exit_code': result.returncode,
                'crashes_found': len(crashes),
                'crashes': crashes,
                'stats': stats,
                'output': output[-1000:]  # Last 1000 chars
            }
            
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            crashes = self._find_crashes(crash_dir)
            
            return {
                'target': target_name,
                'status': 'timeout',
                'runtime': round(elapsed, 2),
                'crashes_found': len(crashes),
                'crashes': crashes
            }
        except Exception as e:
            return {
                'target': target_name,
                'status': 'error',
                'error': str(e)
            }
    
    def _parse_fuzzer_stats(self, output: str) -> Dict:
        """Extract statistics from fuzzer output"""
        stats = {}
        
        # Look for common LibFuzzer stats
        for line in output.split('\n'):
            if 'cov:' in line:
                # Example: #12345  DONE   cov: 123 ft: 456 corp: 78/9876b
                parts = line.split()
                for part in parts:
                    if part.startswith('cov:'):
                        stats['coverage'] = part.split(':')[1]
                    elif part.startswith('corp:'):
                        stats['corpus'] = part.split(':')[1]
                    elif part.startswith('exec/s:'):
                        stats['exec_per_sec'] = part.split(':')[1]
        
        return stats
    
    def _find_crashes(self, crash_dir: str) -> List[Dict]:
        """Find crash artifacts in directory"""
        crashes = []
        
        if not os.path.exists(crash_dir):
            return crashes
        
        for filename in os.listdir(crash_dir):
            if filename.startswith('crash-') or filename.startswith('leak-') or filename.startswith('timeout-'):
                filepath = os.path.join(crash_dir, filename)
                crashes.append({
                    'filename': filename,
                    'size': os.path.getsize(filepath),
                    'path': filepath
                })
        
        return crashes
    
    def _save_campaign_results(self, data: Dict):
        """Save campaign results to JSON"""
        results_file = os.path.join(self.results_dir, 'campaign_results.json')
        
        with open(results_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Campaign results saved: {results_file}")
    
    def get_campaign_results(self) -> Optional[Dict]:
        """Load existing campaign results"""
        results_file = os.path.join(self.results_dir, 'campaign_results.json')
        
        if not os.path.exists(results_file):
            return None
        
        try:
            with open(results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load campaign results: {e}")
            return None
