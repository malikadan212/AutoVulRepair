"""
Crash Triage Module
Analyzes and classifies crashes to prioritize security impact
"""

import os
import json
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class CrashTriageAnalyzer:
    """Analyze and classify fuzzing crashes"""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.scan_dir = f"scans/{scan_id}"
        self.fuzz_dir = os.path.join(self.scan_dir, 'fuzz')
        self.results_dir = os.path.join(self.fuzz_dir, 'results')
        self.triage_dir = os.path.join(self.fuzz_dir, 'triage')
        
        os.makedirs(self.triage_dir, exist_ok=True)
    
    def analyze_campaign(self) -> Dict:
        """
        Analyze all crashes from fuzzing campaign
        
        Returns:
            Triage results dictionary
        """
        logger.info(f"Starting crash triage for {self.scan_dir}")
        
        # Load campaign results
        campaign_results = self._load_campaign_results()
        if not campaign_results:
            return {'error': 'No campaign results found'}
        
        # Analyze each crash
        triaged_crashes = []
        
        for result in campaign_results.get('results', []):
            if result.get('crashes_found', 0) > 0:
                target_name = result['target']
                crashes = result.get('crashes', [])
                output = result.get('output', '')
                
                for crash in crashes:
                    # Analyze crash
                    analysis = self._analyze_crash(
                        target_name=target_name,
                        crash_file=crash,
                        sanitizer_output=output
                    )
                    
                    triaged_crashes.append(analysis)
        
        # Deduplicate crashes first
        unique_crashes = self._deduplicate_crashes(triaged_crashes)
        
        # Now count stats from unique crashes only
        crash_stats = {
            'total_crashes': len(unique_crashes),
            'unique_crashes': len(unique_crashes),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'exploitable': 0,
            'likely_exploitable': 0,
            'unlikely_exploitable': 0
        }
        
        for crash in unique_crashes:
            # Update severity stats
            severity = crash['severity'].lower()
            if severity in crash_stats:
                crash_stats[severity] += 1
            
            # Update exploitability stats
            exploitability = crash['exploitability'].lower().replace(' ', '_')
            if exploitability in crash_stats:
                crash_stats[exploitability] += 1
        
        # Build summary for template
        summary = {
            'total_crashes': len(unique_crashes),
            'by_severity': {
                'Critical': crash_stats['critical'],
                'High': crash_stats['high'],
                'Medium': crash_stats['medium'],
                'Low': crash_stats['low']
            },
            'by_type': {},
            'by_exploitability': {
                'High': crash_stats['exploitable'],
                'Medium': crash_stats['likely_exploitable'],
                'Low': crash_stats['unlikely_exploitable']
            }
        }
        
        # Count by crash type
        for crash in unique_crashes:
            crash_type = crash['crash_type']
            summary['by_type'][crash_type] = summary['by_type'].get(crash_type, 0) + 1
        
        # Save triage results
        triage_data = {
            'timestamp': datetime.now().isoformat(),
            'scan_dir': self.scan_dir,
            'summary': summary,
            'crashes': unique_crashes
        }
        
        self._save_triage_results(triage_data)
        
        return triage_data
    
    def _analyze_crash(self, target_name: str, crash_file: Dict, sanitizer_output: str) -> Dict:
        """Analyze a single crash"""
        crash_type = self._extract_crash_type(crash_file['filename'], sanitizer_output)
        severity = self._assess_severity(crash_type, sanitizer_output)
        exploitability = self._assess_exploitability(crash_type, sanitizer_output)
        stack_trace = self._extract_stack_trace(sanitizer_output)
        root_cause = self._extract_root_cause(sanitizer_output)
        cvss_score = self._calculate_cvss(crash_type, severity, exploitability)
        
        return {
            'id': f"crash_{target_name}_{crash_file['filename'][:16]}",
            'target': target_name,
            'crash_file': crash_file['filename'],
            'crash_path': crash_file['path'],
            'crash_size': crash_file['size'],
            'crash_type': crash_type,
            'severity': severity,
            'exploitability': exploitability,
            'cvss_score': cvss_score,
            'stack_trace': stack_trace,
            'root_cause': root_cause,
            'sanitizer_output': sanitizer_output[-500:]  # Last 500 chars
        }
    
    def _extract_crash_type(self, filename: str, output: str) -> str:
        """Extract crash type from filename and sanitizer output"""
        # Check filename prefix
        if filename.startswith('crash-'):
            # Parse sanitizer output for crash type
            if 'heap-buffer-overflow' in output.lower():
                return 'Heap Buffer Overflow'
            elif 'stack-buffer-overflow' in output.lower():
                return 'Stack Buffer Overflow'
            elif 'double-free' in output.lower():
                return 'Double Free'
            elif 'use-after-free' in output.lower():
                return 'Use After Free'
            elif 'null pointer' in output.lower() or 'segv' in output.lower():
                return 'Null Pointer Dereference'
            elif 'stack-overflow' in output.lower():
                return 'Stack Overflow'
            else:
                return 'Memory Corruption'
        elif filename.startswith('leak-'):
            return 'Memory Leak'
        elif filename.startswith('timeout-'):
            return 'Timeout / Infinite Loop'
        else:
            return 'Unknown Crash'
    
    def _assess_severity(self, crash_type: str, output: str) -> str:
        """Assess crash severity"""
        critical_types = ['Heap Buffer Overflow', 'Stack Buffer Overflow', 'Use After Free', 'Double Free']
        high_types = ['Stack Overflow', 'Null Pointer Dereference', 'Memory Corruption']
        medium_types = ['Memory Leak', 'Timeout / Infinite Loop']
        
        if crash_type in critical_types:
            return 'Critical'
        elif crash_type in high_types:
            return 'High'
        elif crash_type in medium_types:
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_exploitability(self, crash_type: str, output: str) -> str:
        """Assess exploitability"""
        exploitable_types = ['Heap Buffer Overflow', 'Stack Buffer Overflow', 'Use After Free', 'Double Free']
        likely_types = ['Stack Overflow', 'Memory Corruption']
        
        if crash_type in exploitable_types:
            return 'Exploitable'
        elif crash_type in likely_types:
            return 'Likely Exploitable'
        else:
            return 'Unlikely Exploitable'
    
    def _extract_stack_trace(self, output: str) -> List[str]:
        """Extract stack trace from sanitizer output"""
        stack_trace = []
        lines = output.split('\n')
        
        in_stack = False
        for line in lines:
            # Look for stack trace markers
            if re.match(r'\s*#\d+\s+0x[0-9a-f]+', line):
                in_stack = True
                stack_trace.append(line.strip())
            elif in_stack and not line.strip():
                break
        
        return stack_trace[:10]  # Top 10 frames
    
    def _extract_root_cause(self, output: str) -> str:
        """Extract root cause from sanitizer output"""
        lines = output.split('\n')
        
        for line in lines:
            if 'SUMMARY:' in line:
                return line.strip()
        
        return 'Root cause not identified'
    
    def _calculate_cvss(self, crash_type: str, severity: str, exploitability: str) -> float:
        """Calculate CVSS score"""
        base_scores = {
            'Critical': 9.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 3.0
        }
        
        exploit_modifiers = {
            'Exploitable': 1.0,
            'Likely Exploitable': 0.8,
            'Unlikely Exploitable': 0.5
        }
        
        base = base_scores.get(severity, 5.0)
        modifier = exploit_modifiers.get(exploitability, 0.5)
        
        return round(min(10.0, base * modifier + (1 - modifier) * 2), 1)
    
    def _deduplicate_crashes(self, crashes: List[Dict]) -> List[Dict]:
        """Deduplicate similar crashes by stack trace similarity"""
        unique = []
        seen_signatures = set()
        
        for crash in crashes:
            # Create signature from crash type + top 3 stack frames
            stack_top = crash['stack_trace'][:3] if crash['stack_trace'] else []
            signature = f"{crash['crash_type']}:{'|'.join(stack_top)}"
            
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique.append(crash)
            else:
                # Mark as duplicate
                crash['is_duplicate'] = True
        
        return unique
    
    def _load_campaign_results(self) -> Optional[Dict]:
        """Load campaign results"""
        results_file = os.path.join(self.results_dir, 'campaign_results.json')
        
        if not os.path.exists(results_file):
            return None
        
        try:
            with open(results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load campaign results: {e}")
            return None
    
    def _save_triage_results(self, data: Dict):
        """Save triage results to JSON"""
        results_file = os.path.join(self.triage_dir, 'triage_results.json')
        
        with open(results_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Triage results saved: {results_file}")
    
    def get_triage_results(self) -> Optional[Dict]:
        """Load existing triage results"""
        results_file = os.path.join(self.triage_dir, 'triage_results.json')
        
        if not os.path.exists(results_file):
            return None
        
        try:
            with open(results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load triage results: {e}")
            return None

    def get_results(self) -> Optional[Dict]:
        """Alias for get_triage_results for consistency with other modules"""
        return self.get_triage_results()
    
    def analyze_all_crashes(self) -> Dict:
        """Alias for analyze_campaign for consistency with API"""
        return self.analyze_campaign()
