"""
Advanced Scan API Endpoints
Enhanced repository and PR scanning endpoints
"""

from flask import Blueprint, request, jsonify, session
from flask_login import login_required, current_user
import uuid
import os
import logging
from typing import Dict, Any

from src.services.advanced_repo_scanner import AdvancedRepoScanner
from src.services.github_service import GitHubService
from src.services.scan_service import ScanService
from src.repositories.scan_repository import ScanRepository
from src.models.scan_v2 import DatabaseManager
from src.utils.validation import is_valid_github_url

logger = logging.getLogger(__name__)

# Create blueprint
advanced_scan_bp = Blueprint('advanced_scan', __name__, url_prefix='/api/v2/scan')

def get_scanner_service():
    """Get scanner service with GitHub integration"""
    github_token = session.get('github_token')
    github_service = GitHubService(github_token) if github_token else None
    return AdvancedRepoScanner(github_service)

def get_scan_service():
    """Get scan service instance"""
    # Initialize database manager
    DATABASE_URL = os.getenv('DATABASE_URL')
    if DATABASE_URL:
        try:
            db_manager = DatabaseManager(DATABASE_URL)
            scan_repository = ScanRepository(db_manager, use_database=True)
        except Exception:
            scan_repository = ScanRepository(None, use_database=False)
    else:
        scan_repository = ScanRepository(None, use_database=False)
    
    return ScanService(scan_repository)

@advanced_scan_bp.route('/capabilities', methods=['GET'])
def get_scan_capabilities():
    """Get scanner capabilities and available tools"""
    try:
        scanner = get_scanner_service()
        capabilities = scanner.get_scan_capabilities()
        
        return jsonify({
            'success': True,
            'capabilities': capabilities
        })
        
    except Exception as e:
        logger.error(f"Error getting scan capabilities: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@advanced_scan_bp.route('/repository', methods=['POST'])
@login_required
def scan_full_repository():
    """Start a comprehensive repository scan"""
    try:
        data = request.get_json()
        
        # Validate input
        repo_url = data.get('repo_url', '').strip()
        if not repo_url or not is_valid_github_url(repo_url):
            return jsonify({
                'success': False,
                'error': 'Valid GitHub repository URL required'
            }), 400
        
        analysis_tools = data.get('analysis_tools', ['cppcheck', 'codeql'])
        if not isinstance(analysis_tools, list):
            analysis_tools = ['cppcheck', 'codeql']
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan_service = get_scan_service()
        scan_result = scan_service.create_scan(
            source_type='repository',
            repo_url=repo_url,
            analysis_tool=','.join(analysis_tools),
            user_id=current_user.id
        )
        
        if not scan_result.get('success', True):
            return jsonify({
                'success': False,
                'error': scan_result.get('error', 'Failed to create scan')
            }), 400
        
        # Start repository scan
        scanner = get_scanner_service()
        scan_results = scanner.scan_full_repository(
            repo_url=repo_url,
            scan_id=scan_id,
            analysis_tools=analysis_tools
        )
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': scan_results['status'],
            'message': f'Repository scan {"completed" if scan_results["status"] == "completed" else "started"}',
            'results': scan_results
        })
        
    except Exception as e:
        logger.error(f"Error starting repository scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@advanced_scan_bp.route('/pull-request', methods=['POST'])
@login_required
def scan_pull_request():
    """Start a pull request differential scan"""
    try:
        data = request.get_json()
        
        # Validate input
        repo_full_name = data.get('repo_full_name', '').strip()
        pr_number = data.get('pr_number')
        
        if not repo_full_name or '/' not in repo_full_name:
            return jsonify({
                'success': False,
                'error': 'Valid repository name (owner/repo) required'
            }), 400
        
        if not isinstance(pr_number, int) or pr_number <= 0:
            return jsonify({
                'success': False,
                'error': 'Valid pull request number required'
            }), 400
        
        analysis_tools = data.get('analysis_tools', ['cppcheck', 'codeql'])
        if not isinstance(analysis_tools, list):
            analysis_tools = ['cppcheck', 'codeql']
        
        # Check GitHub authentication
        if not session.get('github_token'):
            return jsonify({
                'success': False,
                'error': 'GitHub authentication required for PR scanning'
            }), 401
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan_service = get_scan_service()
        repo_url = f"https://github.com/{repo_full_name}"
        scan_result = scan_service.create_scan(
            source_type='pull_request',
            repo_url=repo_url,
            analysis_tool=','.join(analysis_tools),
            user_id=current_user.id
        )
        
        # Start PR scan
        scanner = get_scanner_service()
        scan_results = scanner.scan_pull_request(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            scan_id=scan_id,
            analysis_tools=analysis_tools
        )
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': scan_results['status'],
            'message': f'PR scan {"completed" if scan_results["status"] == "completed" else "started"}',
            'results': scan_results
        })
        
    except Exception as e:
        logger.error(f"Error starting PR scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
@advanced_scan_bp.route('/batch', methods=['POST'])
@login_required
def batch_scan_repositories():
    """Scan multiple repositories in batch"""
    try:
        data = request.get_json()
        
        # Validate input
        repositories = data.get('repositories', [])
        if not isinstance(repositories, list) or len(repositories) == 0:
            return jsonify({
                'success': False,
                'error': 'List of repositories required'
            }), 400
        
        if len(repositories) > 10:  # Limit batch size
            return jsonify({
                'success': False,
                'error': 'Maximum 10 repositories per batch'
            }), 400
        
        analysis_tools = data.get('analysis_tools', ['cppcheck'])
        
        # Start batch scans
        scanner = get_scanner_service()
        scan_service = get_scan_service()
        
        batch_results = []
        
        for repo_url in repositories:
            if not is_valid_github_url(repo_url):
                batch_results.append({
                    'repo_url': repo_url,
                    'success': False,
                    'error': 'Invalid GitHub URL'
                })
                continue
            
            try:
                scan_id = str(uuid.uuid4())
                
                # Create scan record
                scan_service.create_scan(
                    source_type='repository',
                    repo_url=repo_url,
                    analysis_tool=','.join(analysis_tools),
                    user_id=current_user.id
                )
                
                # Start scan
                scan_results = scanner.scan_full_repository(
                    repo_url=repo_url,
                    scan_id=scan_id,
                    analysis_tools=analysis_tools
                )
                
                batch_results.append({
                    'repo_url': repo_url,
                    'scan_id': scan_id,
                    'success': True,
                    'status': scan_results['status'],
                    'findings_count': scan_results.get('total_findings', 0)
                })
                
            except Exception as e:
                batch_results.append({
                    'repo_url': repo_url,
                    'success': False,
                    'error': str(e)
                })
        
        return jsonify({
            'success': True,
            'batch_results': batch_results,
            'total_scans': len(repositories),
            'successful_scans': sum(1 for r in batch_results if r['success'])
        })
        
    except Exception as e:
        logger.error(f"Error in batch scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@advanced_scan_bp.route('/compare', methods=['POST'])
@login_required
def compare_scans():
    """Compare two scan results"""
    try:
        data = request.get_json()
        
        scan_id_1 = data.get('scan_id_1')
        scan_id_2 = data.get('scan_id_2')
        
        if not scan_id_1 or not scan_id_2:
            return jsonify({
                'success': False,
                'error': 'Two scan IDs required for comparison'
            }), 400
        
        scan_service = get_scan_service()
        
        # Get scan results
        scan_1 = scan_service.get_scan_results(scan_id_1)
        scan_2 = scan_service.get_scan_results(scan_id_2)
        
        if 'error' in scan_1 or 'error' in scan_2:
            return jsonify({
                'success': False,
                'error': 'One or both scans not found'
            }), 404
        
        # Compare findings
        comparison = _compare_scan_findings(scan_1, scan_2)
        
        return jsonify({
            'success': True,
            'comparison': comparison
        })
        
    except Exception as e:
        logger.error(f"Error comparing scans: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@advanced_scan_bp.route('/trends/<user_id>', methods=['GET'])
@login_required
def get_scan_trends(user_id: str):
    """Get scanning trends for a user"""
    try:
        # Validate user access
        if current_user.id != user_id:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        scan_service = get_scan_service()
        
        # Get user's recent scans (last 30 days)
        from datetime import datetime, timedelta
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        # This would need to be implemented in scan_service
        trends = {
            'total_scans': 0,
            'vulnerability_trends': [],
            'tool_usage': {},
            'scan_types': {},
            'top_vulnerabilities': []
        }
        
        return jsonify({
            'success': True,
            'trends': trends,
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting scan trends: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def _compare_scan_findings(scan_1: Dict, scan_2: Dict) -> Dict[str, Any]:
    """Compare findings between two scans"""
    findings_1 = scan_1.get('findings', [])
    findings_2 = scan_2.get('findings', [])
    
    # Create finding signatures for comparison
    def create_signature(finding):
        return (
            finding.get('file_path', ''),
            finding.get('line_number', 0),
            finding.get('rule_id', ''),
            finding.get('message', '')
        )
    
    sigs_1 = {create_signature(f): f for f in findings_1}
    sigs_2 = {create_signature(f): f for f in findings_2}
    
    # Find differences
    only_in_1 = [sigs_1[sig] for sig in sigs_1 if sig not in sigs_2]
    only_in_2 = [sigs_2[sig] for sig in sigs_2 if sig not in sigs_1]
    common = [sigs_1[sig] for sig in sigs_1 if sig in sigs_2]
    
    return {
        'scan_1': {
            'scan_id': scan_1['scan']['scan_id'],
            'total_findings': len(findings_1)
        },
        'scan_2': {
            'scan_id': scan_2['scan']['scan_id'],
            'total_findings': len(findings_2)
        },
        'comparison': {
            'new_findings': only_in_2,
            'resolved_findings': only_in_1,
            'common_findings': common,
            'new_count': len(only_in_2),
            'resolved_count': len(only_in_1),
            'common_count': len(common)
        }
    }