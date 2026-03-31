#!/usr/bin/env python3
"""
Minimal Flask App for Testing Advanced Scanner
Bypasses the import issues in the main app
"""

import os
import uuid
import tempfile
import shutil
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'dev-secret-key'

# Simple user management
login_manager = LoginManager()
login_manager.login_view = 'home'
login_manager.init_app(app)

USERS = {}

class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    return USERS.get(user_id)

@app.route('/')
def home():
    return '''
    <h1>AutoVulRepair - Minimal Test Version</h1>
    <p>This is a minimal version to test the advanced scanner.</p>
    <a href="/login-demo">Login (Demo)</a> | 
    <a href="/advanced-scan">Advanced Scanner</a> |
    <a href="/api/v2/scan/capabilities">API Test</a>
    '''

@app.route('/login-demo')
def login_demo():
    """Demo login for testing"""
    user = User('demo-user', 'demo')
    USERS['demo-user'] = user
    login_user(user)
    flash('Logged in as demo user')
    return redirect(url_for('advanced_scan_dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/advanced-scan')
@login_required
def advanced_scan_dashboard():
    """Advanced repository and PR scanning dashboard"""
    return render_template('advanced_scan_dashboard.html')

# Minimal API endpoints
@app.route('/api/v2/scan/capabilities', methods=['GET'])
def get_scan_capabilities():
    """Get scanner capabilities - minimal version"""
    try:
        # Test Docker availability
        import subprocess
        docker_available = False
        try:
            result = subprocess.run(['docker', '--version'], capture_output=True, timeout=5)
            docker_available = result.returncode == 0
        except:
            pass
        
        # Test Docker images
        cppcheck_available = False
        codeql_available = False
        
        if docker_available:
            try:
                result = subprocess.run(['docker', 'images', '-q', 'vuln-scanner/cppcheck:latest'], 
                                      capture_output=True, timeout=5)
                cppcheck_available = bool(result.stdout.strip())
                
                result = subprocess.run(['docker', 'images', '-q', 'vuln-scanner/codeql:latest'], 
                                      capture_output=True, timeout=5)
                codeql_available = bool(result.stdout.strip())
            except:
                pass
        
        # Calculate actually supported languages based on available tools
        supported_languages = set()
        if cppcheck_available:
            supported_languages.update(['C', 'C++'])
        if codeql_available:
            supported_languages.update(['C', 'C++', 'Python', 'JavaScript', 'TypeScript', 'Java', 'C#', 'Go'])
        
        capabilities = {
            'tools': {
                'cppcheck': {
                    'available': cppcheck_available,
                    'languages': ['C', 'C++']
                },
                'codeql': {
                    'available': codeql_available,
                    'languages': ['C', 'C++', 'Python', 'JavaScript', 'TypeScript', 'Java', 'C#', 'Go']
                }
            },
            'scan_types': ['full_repository', 'pull_request'],
            'supported_languages': sorted(list(supported_languages)),  # Only actually supported languages
            'limits': {
                'max_file_size_mb': 10,
                'max_repo_size_mb': 500,
                'timeout_minutes': 30
            }
        }
        
        return jsonify({
            'success': True,
            'capabilities': capabilities
        })
        
    except Exception as e:
        logger.error(f"Error getting capabilities: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/v2/scan/repository', methods=['POST'])
@login_required
def scan_repository_minimal():
    """Minimal repository scan for testing"""
    try:
        data = request.get_json()
        repo_url = data.get('repo_url', '').strip()
        
        if not repo_url:
            return jsonify({
                'success': False,
                'error': 'Repository URL required'
            }), 400
        
        scan_id = str(uuid.uuid4())
        
        # Simulate scan results
        results = {
            'scan_id': scan_id,
            'repo_url': repo_url,
            'scan_type': 'full_repository',
            'started_at': datetime.now().isoformat(),
            'status': 'completed',
            'completed_at': datetime.now().isoformat(),
            'findings': [
                {
                    'tool': 'cppcheck',
                    'analysis_method': 'docker',
                    'type': 'vulnerability',
                    'rule_id': 'bufferAccessOutOfBounds',
                    'severity': 'high',
                    'message': 'Potential buffer overflow detected',
                    'file_path': 'src/main.cpp',
                    'line_number': 42,
                    'confidence': 'high'
                }
            ],
            'tool_results': {
                'cppcheck': {
                    'findings_count': 1,
                    'status': 'completed'
                }
            },
            'total_findings': 1,
            'analysis_summary': {
                'message': 'Full Docker-based static analysis completed',
                'docker_used': True,
                'fallback_used': False,
                'tools_used': ['cppcheck']
            }
        }
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': 'completed',
            'message': 'Repository scan completed',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error in repository scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    print("🚀 Starting Minimal AutoVulRepair Server")
    print("🌐 Visit: http://localhost:5000")
    print("🔧 Advanced Scanner: http://localhost:5000/advanced-scan")
    print("📊 API Test: http://localhost:5000/api/v2/scan/capabilities")
    
    app.run(host='127.0.0.1', port=5000, debug=True)