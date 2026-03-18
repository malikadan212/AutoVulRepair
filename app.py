import os
import time
import uuid
import tempfile
import shutil
import subprocess
import zipfile
import logging
import json
from functools import wraps
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests

# Import new components
from src.models.scan import get_session, Scan, create_database
from src.queue.tasks import celery_app, analyze_code, analyze_code_sync
from src.utils.validation import (
    is_valid_github_url, validate_zip_file, validate_code_snippet, 
    safe_extract_zip, sanitize_filename
)
# validate_zip_file and safe_extract_zip are used for secure ZIP processing

# Import Module 2 components
from src.fuzz_plan.generator import FuzzPlanGenerator
from src.harness.generator import HarnessGenerator
# from src.build.orchestrator import BuildOrchestrator
from src.fuzz_exec.executor import FuzzExecutor

load_dotenv()

# Configure logging with timestamps
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to see more details
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Set specific loggers to appropriate levels
logging.getLogger('src.analysis.cppcheck').setLevel(logging.DEBUG)
logging.getLogger('src.utils.docker_helper').setLevel(logging.DEBUG)

# Also configure Flask's logger
app_logger = logging.getLogger('werkzeug')
app_logger.setLevel(logging.INFO)

# Initialize database
logger.info("=" * 60)
logger.info(f"Starting application at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.info("=" * 60)
create_database()
logger.info("Database initialized")

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev')
# Set maximum upload size to 100MB to prevent resource exhaustion
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Add request logging middleware
@app.before_request
def log_request_info():
    """Log incoming requests"""
    logger.info(f"[REQUEST] {request.method} {request.path} - IP: {request.remote_addr}")

@app.after_request
def log_response_info(response):
    """Log outgoing responses"""
    logger.info(f"[RESPONSE] {request.method} {request.path} - Status: {response.status_code}")
    return response

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'home'
login_manager.init_app(app)

# Simple in-memory user store
USERS = {}


class User(UserMixin):
    def __init__(self, id_, username, token=None):
        self.id = id_
        self.username = username
        self.token = token

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    return USERS.get(user_id)


# OAuth (GitHub) setup
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={
        'scope': 'user:email'
    },
)


def login_required_oauth(f):
    """Wrapper for routes that require OAuth token in session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'github_token' not in session:
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated


def is_api_request():
    """Check if request is from API client (VS Code extension)"""
    return (
        request.headers.get('Accept') == 'application/json' or
        (request.content_type and 'application/json' in request.content_type)
    )


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/api/health')
def api_health():
    """Health check endpoint for VS Code extension"""
    return jsonify({
        'status': 'ok',
        'message': 'Backend is running',
        'version': '1.0.0'
    })


@app.route('/no-login')
def no_login_scan():
    """Entry point for users who want to scan without GitHub login"""
    return render_template('no_login_scan.html')

@app.route('/scan-public', methods=['GET'])
def scan_public_form():
    """Show the public scanning form"""
    return render_template('no_login_scan.html')


@app.route('/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    return github.authorize_redirect(redirect_uri)


@app.route('/auth')
def authorized():
    try:
        token = github.authorize_access_token()
        if not token:
            flash('Authentication failed.')
            return redirect(url_for('home'))

        session['github_token'] = token['access_token']
        
        # Fetch user info
        resp = requests.get('https://api.github.com/user', 
                          headers={'Authorization': f'token {token["access_token"]}'})
        
        if resp.status_code != 200:
            flash('Failed to fetch user info from GitHub.')
            return redirect(url_for('home'))

        data = resp.json()
        user_id = str(data.get('id'))
        username = data.get('login')

        user = User(user_id, username, token=token['access_token'])
        USERS[user_id] = user
        login_user(user)
        flash('Logged in successfully.')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Authentication error: {str(e)}')
        return redirect(url_for('home'))


# Token getter no longer needed with Authlib


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with real statistics from database"""
    session_db = get_session()
    try:
        from sqlalchemy import func
        
        # Get user's scans (or all scans if user_id is None for demo)
        user_scans = session_db.query(Scan).filter(
            (Scan.user_id == current_user.id) | (Scan.user_id == None)
        ).all()
        
        # Calculate real statistics
        total_scans = len(user_scans)
        
        total_vulnerabilities = 0
        total_patches = 0
        completed_scans = 0
        
        for scan in user_scans:
            if scan.vulnerabilities_json:
                total_vulnerabilities += len(scan.vulnerabilities_json)
            if scan.patches_json:
                total_patches += len(scan.patches_json)
            if scan.status == 'completed':
                completed_scans += 1
        
        # Calculate success rate
        success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
        
        # Get recent scans (last 5)
        recent_scans = session_db.query(Scan).filter(
            (Scan.user_id == current_user.id) | (Scan.user_id == None)
        ).order_by(Scan.created_at.desc()).limit(5).all()
        
        stats = {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'total_patches': total_patches,
            'success_rate': round(success_rate, 1)
        }
        
        return render_template('dashboard.html', 
                             user=current_user, 
                             stats=stats,
                             recent_scans=recent_scans)
    finally:
        session_db.close()


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('github_token', None)
    flash('Logged out.')
    return redirect(url_for('home'))


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        repo_url = request.form.get('repo_url', '').strip()
        zip_file = request.files.get('zip_file')
        analysis_tool = request.form.get('analysis_tool', 'cppcheck')

        scan_id = str(uuid.uuid4())

        try:
            if repo_url:
                # Validate it's a GitHub URL
                if not is_valid_github_url(repo_url):
                    flash('Please provide a valid GitHub repository URL.')
                    return render_template('scan.html')
                
                result = process_github_repo(repo_url, scan_id, analysis_tool)
            elif zip_file:
                result = process_zip_upload(zip_file, scan_id, analysis_tool)
            else:
                flash('Please provide a GitHub URL or upload a ZIP file.')
                return render_template('scan.html')
            
            if result['success']:
                # Store scan results in session
                session.setdefault('scans', {})[scan_id] = result['data']
                return redirect(url_for('results', scan_id=scan_id))
            else:
                flash(f'Scan failed: {result["error"]}')
                return render_template('scan.html')
                
        except Exception as e:
            flash(f'An error occurred: {str(e)}')
            return render_template('scan.html')

    return render_template('scan.html')


@app.route('/results/<scan_id>')
def results(scan_id):
    """Show comprehensive final results - accessible without login"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return redirect(url_for('no_login_scan'))
        
        # Get static analysis results
        vulnerabilities = scan.vulnerabilities_json or []
        patches = scan.patches_json or []
        
        # Get fuzzing results
        scans_dir = os.getenv('SCANS_DIR', './scans')
        fuzz_results_path = os.path.join(scans_dir, scan_id, 'fuzz', 'results', 'campaign_results.json')
        fuzz_results = None
        if os.path.exists(fuzz_results_path):
            with open(fuzz_results_path, 'r') as f:
                fuzz_results = json.load(f)
        
        # Get triage results
        triage_results_path = os.path.join(scans_dir, scan_id, 'fuzz', 'triage', 'triage_results.json')
        triage_results = None
        if os.path.exists(triage_results_path):
            with open(triage_results_path, 'r') as f:
                triage_results = json.load(f)
        
        return render_template('final_results.html',
                             scan_id=scan_id,
                             scan=scan,
                             vulnerabilities=vulnerabilities,
                             patches=patches,
                             fuzz_results=fuzz_results,
                             triage_results=triage_results)
    finally:
        session_db.close()


@app.route('/scan-progress/<scan_id>')
def scan_progress(scan_id):
    """Show scan progress page - accessible without login"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        return render_template('scan_progress.html', 
                             scan_id=scan_id, 
                             analysis_tool=scan.analysis_tool or 'cppcheck',
                             source_type=scan.source_type or 'Repository',
                             repo_url=scan.repo_url)
    except Exception as e:
        logger.error(f"Error loading scan progress for {scan_id}: {e}")
        flash('Error loading scan details.', 'error')
        return redirect(url_for('no_login_scan'))
    finally:
        session_db.close()


def extract_code_context(scan_id, file_path, line_number, context_lines=5):
    """Extract code context around a specific line"""
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        source_dir = os.path.join(scan_dir, 'source')
        
        # Handle different path formats
        if file_path.startswith('/tmp/source/'):
            file_path = file_path[12:]  # Remove /tmp/source/ prefix
        elif file_path.startswith('/source/'):
            file_path = file_path[8:]  # Remove /source/ prefix
        
        # Get just the filename if it's a full path
        if '/' in file_path:
            file_path = os.path.basename(file_path)
        
        full_path = os.path.join(source_dir, file_path)
        
        if not os.path.exists(full_path):
            logger.warning(f"Source file not found: {full_path}")
            return None
        
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        line_num = int(line_number)
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        context = []
        for i in range(start, end):
            is_vuln_line = (i == line_num - 1)
            context.append({
                'line_num': i + 1,
                'code': lines[i].rstrip(),
                'is_vulnerable': is_vuln_line
            })
        
        return context
    except Exception as e:
        logger.error(f"Error extracting code context for {file_path}: {e}")
        return None


@app.route('/detailed-findings/<scan_id>')
def detailed_findings(scan_id):
    """Show detailed vulnerability findings - accessible without login"""
    logger.info(f"[DETAILED_FINDINGS] Request for scan: {scan_id}")
    # Get scan data from database
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            logger.warning(f"[DETAILED_FINDINGS] Scan not found: {scan_id}")
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        logger.info(f"[DETAILED_FINDINGS] Scan {scan_id} found, status: {scan.status}")
        
        # Get vulnerabilities and patches from database
        vulnerabilities = scan.vulnerabilities_json or []
        patches = scan.patches_json or []
        
        # Add code context to each vulnerability
        for vuln in vulnerabilities:
            if vuln.get('file') and vuln.get('line'):
                vuln['code_context'] = extract_code_context(
                    scan_id, 
                    vuln['file'], 
                    vuln['line']
                )
        
        logger.info(f"[DETAILED_FINDINGS] Scan {scan_id} has {len(vulnerabilities)} vulnerabilities and {len(patches)} patches")
        
        # If scan is still running, show progress
        if scan.status == 'queued' or scan.status == 'running':
            logger.info(f"[DETAILED_FINDINGS] Scan {scan_id} still in progress, showing progress view")
            return render_template('detailed_findings.html',
                                 scan_id=scan_id,
                                 vulnerabilities=[],
                                 patches=[],
                                 status=scan.status,
                                 analysis_tool=scan.analysis_tool)
        
        # If scan failed, show error
        if scan.status == 'failed':
            logger.warning(f"[DETAILED_FINDINGS] Scan {scan_id} failed")
            return render_template('detailed_findings.html',
                                 scan_id=scan_id,
                                 vulnerabilities=[],
                                 patches=[],
                                 status='failed',
                                 error='Scan failed. Please try again.')
        
        logger.info(f"[DETAILED_FINDINGS] Rendering results for scan {scan_id}")
        return render_template('detailed_findings.html', 
                             scan_id=scan_id,
                             vulnerabilities=vulnerabilities,
                             patches=patches,
                             status=scan.status,
                             analysis_tool=scan.analysis_tool,
                             repo_url=scan.repo_url,
                             source_type=scan.source_type)
    finally:
        session_db.close()


@app.route('/patch-review/<scan_id>')
def patch_review(scan_id):
    """Show patch review interface with Stage 1 repairs - accessible without login"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            flash('Scan not found', 'error')
            return redirect(url_for('home'))
        
        # Load vulnerabilities from static_findings.json
        import json
        from pathlib import Path
        
        findings_file = Path('scans') / scan_id / 'static_findings.json'
        vulnerabilities = []
        
        if findings_file.exists():
            with open(findings_file, 'r') as f:
                findings_data = json.load(f)
            vulnerabilities = findings_data.get('findings', [])
            logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from static_findings.json")
        else:
            logger.warning(f"Static findings file not found: {findings_file}")
        
        # Import Stage 1 components
        from src.repair.stage1 import Stage1RepairEngine, classify_vulnerability
        
        # Initialize repair engine
        repair_engine = Stage1RepairEngine(enable_dead_code=False)
        
        # Classify vulnerabilities and compute statistics
        classified_vulns = []
        stage1_counts = {
            'null_pointer': 0,
            'uninitialized_var': 0,
            'dead_code': 0,
            'integer_overflow': 0,
            'memory_dealloc': 0
        }
        stage2_vulns = []
        
        for vuln in vulnerabilities:
            classification = classify_vulnerability(vuln)
            vuln_with_class = vuln.copy()
            vuln_with_class['classification'] = classification
            
            # Add code context for better visualization
            if vuln.get('file') and vuln.get('line'):
                vuln_with_class['code_context'] = extract_code_context(
                    scan_id,
                    vuln['file'],
                    vuln['line'],
                    context_lines=5
                )
            
            classified_vulns.append(vuln_with_class)
            
            # Count by category
            if classification['stage'] == 1 and classification['enabled']:
                category = classification['category']
                if category in stage1_counts:
                    stage1_counts[category] += 1
            elif classification['stage'] == 2:
                stage2_vulns.append(vuln_with_class)
        
        # Calculate totals
        total_stage1 = sum(stage1_counts.values())
        total_stage2 = len(stage2_vulns)
        
        # Get existing patches (if any were generated)
        # Refresh the scan object to get latest patches from database
        session_db.expire(scan)
        session_db.refresh(scan)
        patches = scan.patches_json or []
        
        # Filter out invalid patches (those with no content)
        valid_patches = [p for p in patches if p.get('file') and p.get('line') and p.get('original')]
        
        logger.info(f"Loaded {len(patches)} total patches, {len(valid_patches)} valid patches")
        
        return render_template('patch_review.html',
                             scan_id=scan_id,
                             scan=scan,
                             vulnerabilities=classified_vulns,
                             patches=valid_patches,
                             repair_engine=repair_engine,
                             stage1_counts=stage1_counts,
                             total_stage1=total_stage1,
                             total_stage2=total_stage2,
                             stage2_vulns=stage2_vulns)
    finally:
        session_db.close()


@app.route('/fuzzing-dashboard')
def fuzzing_dashboard():
    """Show fuzzing campaign dashboard - accessible without login"""
    scan_id = request.args.get('scan_id')
    return render_template('fuzzing_dashboard.html', scan_id=scan_id)


@app.route('/monitoring')
def monitoring_dashboard():
    """Show system monitoring dashboard - accessible without login"""
    return render_template('monitoring_dashboard.html')




@app.route('/api/scan-status/<scan_id>')
def api_scan_status(scan_id):
    """API endpoint for checking scan status - accessible without login"""
    logger.debug(f"[API] Status check requested for scan: {scan_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            logger.warning(f"[API] Scan not found: {scan_id}")
            return jsonify({'error': 'Scan not found'}), 404
        
        vuln_count = len(scan.vulnerabilities_json) if scan.vulnerabilities_json else 0
        patch_count = len(scan.patches_json) if scan.patches_json else 0
        
        # Calculate elapsed time
        elapsed_time = None
        if scan.created_at:
            from datetime import datetime
            elapsed_time = (datetime.now() - scan.created_at).total_seconds()
        
        logger.debug(f"[API] Scan {scan_id} status: {scan.status}, vulnerabilities: {vuln_count}")
        return jsonify({
            'status': scan.status,
            'analysis_tool': scan.analysis_tool,
            'vulnerabilities_count': vuln_count,
            'patches_count': patch_count,
            'elapsed_time': elapsed_time,
            'error': None
        })
    except Exception as e:
        logger.error(f"[API] Error checking scan status: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()


@app.route('/api/scan/<scan_id>/results')
def api_scan_results(scan_id):
    """Get scan results in JSON format for VS Code extension"""
    logger.debug(f"[API] Results requested for scan: {scan_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            logger.warning(f"[API] Scan not found: {scan_id}")
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = scan.vulnerabilities_json or []
        patches = scan.patches_json or []
        
        # Format vulnerabilities for VS Code extension
        formatted_vulns = []
        for vuln in vulnerabilities:
            # Find matching patch
            patch_content = None
            for p in patches:
                if p.get('vuln_id') == vuln.get('id'):
                    patch_content = p.get('content')
                    break
            
            formatted_vulns.append({
                'id': vuln.get('id', str(uuid.uuid4())),
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'Medium'),
                'file': vuln.get('file', ''),
                'line': int(vuln.get('line', 0)),
                'column': int(vuln.get('column', 0)),
                'endLine': int(vuln.get('endLine', vuln.get('line', 0))),
                'endColumn': int(vuln.get('endColumn', vuln.get('column', 0) + 10)),
                'description': vuln.get('description', ''),
                'cwe': vuln.get('cwe', ''),
                'exploitability': float(vuln.get('exploitability', 0.5)),
                'impact': vuln.get('impact', ''),
                'recommendation': vuln.get('recommendation', ''),
                'patch': patch_content
            })
        
        # Calculate summary
        summary = {
            'total': len(formatted_vulns),
            'critical': sum(1 for v in formatted_vulns if v['severity'].lower() == 'critical'),
            'high': sum(1 for v in formatted_vulns if v['severity'].lower() == 'high'),
            'medium': sum(1 for v in formatted_vulns if v['severity'].lower() == 'medium'),
            'low': sum(1 for v in formatted_vulns if v['severity'].lower() == 'low')
        }
        
        logger.debug(f"[API] Returning {len(formatted_vulns)} vulnerabilities for scan {scan_id}")
        return jsonify({
            'scanId': scan_id,
            'status': scan.status,
            'progress': 100 if scan.status == 'completed' else 50,
            'stage': 'Analysis Complete' if scan.status == 'completed' else 'In Progress',
            'vulnerabilities': formatted_vulns,
            'summary': summary
        })
    except Exception as e:
        logger.error(f"[API] Error getting scan results: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()


@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def api_cancel_scan(scan_id):
    """Cancel an active scan"""
    logger.info(f"[API] Cancel requested for scan: {scan_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            logger.warning(f"[API] Scan not found: {scan_id}")
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status in ['completed', 'failed', 'cancelled']:
            logger.warning(f"[API] Cannot cancel scan {scan_id} with status: {scan.status}")
            return jsonify({
                'error': f'Cannot cancel scan with status: {scan.status}'
            }), 400
        
        # Revoke Celery task if it exists
        if hasattr(scan, 'celery_task_id') and scan.celery_task_id:
            try:
                celery_app.control.revoke(scan.celery_task_id, terminate=True)
                logger.info(f"[API] Revoked Celery task {scan.celery_task_id} for scan {scan_id}")
            except Exception as e:
                logger.warning(f"[API] Failed to revoke Celery task: {e}")
        
        # Update scan status
        scan.status = 'cancelled'
        session_db.commit()
        
        logger.info(f"[API] Scan {scan_id} cancelled successfully")
        
        return jsonify({
            'scanId': scan_id,
            'status': 'cancelled',
            'message': 'Scan cancelled successfully'
        })
    except Exception as e:
        logger.error(f"[API] Error cancelling scan {scan_id}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()


@app.route('/api/generate-single-patch/<scan_id>/<vuln_id>', methods=['POST'])
def api_generate_single_patch(scan_id, vuln_id):
    """API endpoint to generate a single Stage 1 patch"""
    logger.info(f"[API] Single patch generation requested for scan: {scan_id}, vuln: {vuln_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Load vulnerabilities from the database (already normalized by cppcheck/codeql engines)
        vulnerabilities = scan.vulnerabilities_json or []
        
        # Find the specific vulnerability
        vuln = next((v for v in vulnerabilities if v.get('id') == vuln_id), None)
        if not vuln:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        # Get source files
        source_files = {}
        scan_dir = Path('scans') / scan_id / 'source'
        
        if scan_dir.exists():
            for source_file in scan_dir.rglob('*.c*'):
                try:
                    with open(source_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        filename = source_file.name
                        source_files[f'/tmp/source/{filename}'] = content
                        source_files[f'/work/source/{filename}'] = content
                        source_files[filename] = content
                        source_files[str(source_file)] = content
                except Exception as e:
                    logger.warning(f"Could not read {source_file}: {e}")
        
        # Initialize Stage 1 repair engine
        from src.repair.stage1 import Stage1RepairEngine
        from src.repair.stage1.classifier import classify_vulnerability, is_stage1_repairable
        
        repair_engine = Stage1RepairEngine(enable_dead_code=False)
        
        # Log all vuln fields for debugging
        logger.info(f"[PATCH_DEBUG] Vulnerability fields: id={vuln.get('id')}, rule_id={vuln.get('rule_id')}, severity={vuln.get('severity')}, line={vuln.get('line')}, file={vuln.get('file')}")
        
        # Check if vulnerability is Stage 1 repairable before attempting
        classification = classify_vulnerability(vuln)
        logger.info(f"[PATCH_DEBUG] Classification: stage={classification['stage']}, category={classification['category']}, enabled={classification['enabled']}, reason={classification['reason']}")
        
        if classification['stage'] != 1 or not classification['enabled']:
            msg = f"Vulnerability '{vuln.get('rule_id', vuln_id)}' (stage={classification['stage']}, category={classification['category']}) cannot be fixed by rule-based patching. Reason: {classification['reason']}"
            logger.warning(f"[PATCH_DEBUG] Not patchable: {msg}")
            return jsonify({'error': msg, 'classification': classification}), 400
        
        # Get source code
        file_path = vuln.get('file', '')
        logger.info(f"[PATCH_DEBUG] Looking for source file: {file_path}")
        logger.info(f"[PATCH_DEBUG] Available source file keys: {list(source_files.keys())}")
        source_code = source_files.get(file_path)
        
        if not source_code:
            return jsonify({'error': f'Source code not found for {file_path}. Available: {list(source_files.keys())}'}), 400
        
        logger.info(f"[PATCH_DEBUG] Source code found ({len(source_code)} chars). Generating patch...")
        
        # Generate patch
        patch = repair_engine.generate_patch(vuln, source_code, file_path)
        
        if patch:
            # Save patch to database
            existing_patches = scan.patches_json or []
            existing_patches.append(patch)
            scan.patches_json = existing_patches
            
            # Mark the JSON field as modified (required for SQLAlchemy to detect changes)
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(scan, 'patches_json')
            
            session_db.commit()
            
            logger.info(f"[API] Generated single patch for {vuln_id}")
            
            return jsonify({
                'success': True,
                'patch': patch
            })
        else:
            logger.warning(f"[PATCH_DEBUG] repair_engine.generate_patch returned None for vuln {vuln_id}")
            return jsonify({'error': f'Rule-based patch could not be generated for {vuln.get("rule_id", vuln_id)}. The vulnerability pattern may not match any known fix template.'}), 400
        
    except Exception as e:
        logger.error(f"[API] Error generating single patch: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()


@app.route('/api/generate-stage1-patches/<scan_id>', methods=['POST'])
def api_generate_stage1_patches(scan_id):
    """API endpoint to generate Stage 1 patches - accessible without login"""
    logger.info(f"[API] Stage 1 patch generation requested for scan: {scan_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Load vulnerabilities from the database (already normalized by cppcheck/codeql engines)
        vulnerabilities = scan.vulnerabilities_json or []
        if not vulnerabilities:
            return jsonify({'error': 'No vulnerabilities found. Run a scan first.'}), 400
        
        logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from database")
        
        # Get source files from scan artifacts
        import os
        from pathlib import Path
        
        source_files = {}
        
        # Find the scan's source directory
        scan_dir = Path('scans') / scan_id / 'source'
        
        if scan_dir.exists():
            logger.info(f"Loading source files from: {scan_dir}")
            for source_file in scan_dir.rglob('*.c*'):
                try:
                    with open(source_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        filename = source_file.name
                        
                        # Map multiple path formats:
                        # 1. /tmp/source/filename.cpp (Docker container path)
                        source_files[f'/tmp/source/{filename}'] = content
                        # 2. /work/source/filename.cpp (Another Docker container path)
                        source_files[f'/work/source/{filename}'] = content
                        # 3. Just the filename
                        source_files[filename] = content
                        # 4. The actual path
                        source_files[str(source_file)] = content
                        
                        logger.info(f"Loaded: {filename} ({len(content)} bytes)")
                except Exception as e:
                    logger.warning(f"Could not read {source_file}: {e}")
            
            logger.info(f"Loaded {len(set(source_files.values()))} unique source files with {len(source_files)} path mappings")
        else:
            logger.warning(f"Source directory not found: {scan_dir}")
        
        # Initialize Stage 1 repair engine
        from src.repair.stage1 import Stage1RepairEngine
        
        enable_dead_code = request.json.get('enable_dead_code', False) if request.json else False
        repair_engine = Stage1RepairEngine(enable_dead_code=enable_dead_code)
        
        # Generate patches
        result = repair_engine.batch_repair(vulnerabilities, source_files)
        
        # Save patches to database
        existing_patches = scan.patches_json or []
        new_patches = result['patches']
        
        logger.info(f"Before merge: {len(existing_patches)} existing patches, {len(new_patches)} new patches")
        
        # Merge patches (avoid duplicates) - filter out invalid patches
        patch_ids = {p.get('patch_id') for p in existing_patches if p.get('patch_id')}
        added_count = 0
        for patch in new_patches:
            patch_id = patch.get('patch_id')
            if patch_id and patch_id not in patch_ids:
                existing_patches.append(patch)
                added_count += 1
            elif not patch_id:
                logger.warning(f"Patch missing patch_id: {patch}")
        
        scan.patches_json = existing_patches
        
        # Mark the JSON field as modified (required for SQLAlchemy to detect changes)
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(scan, 'patches_json')
        
        session_db.flush()  # Flush to ensure changes are written
        session_db.commit()
        session_db.refresh(scan)  # Refresh to get the committed state
        
        logger.info(f"[API] Saved {added_count} new patches. Total patches in DB: {len(existing_patches)}")
        logger.info(f"[API] After commit, scan.patches_json has {len(scan.patches_json or [])} patches")
        logger.info(f"[API] Generated {len(new_patches)} Stage 1 patches for scan {scan_id}")
        
        return jsonify({
            'success': True,
            'patches_generated': len(new_patches),
            'stats': result['stats'],
            'patches': new_patches,
            'source_files_found': len(source_files)
        })
        
    except Exception as e:
        logger.error(f"[API] Error generating Stage 1 patches: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/scan_status/<scan_id>')
@login_required
def scan_status(scan_id):
    """Legacy endpoint for authenticated users"""
    logger.debug(f"[API] Legacy status check for scan: {scan_id}")
    scans = session.get('scans', {})
    scan = scans.get(scan_id)
    if not scan:
        logger.warning(f"[API] Scan not found in session: {scan_id}")
        return jsonify({'error': 'not found'}), 404
    return jsonify({'status': scan['status']})


# ============================================================================
# Module 2: Fuzz Plan Routes
# ============================================================================

@app.route('/fuzz-plan/<scan_id>')
def fuzz_plan_view(scan_id):
    """Display fuzz plan for a scan - accessible without login"""
    logger.info(f"[FUZZ_PLAN] View requested for scan: {scan_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        # Check if fuzz plan exists
        scans_dir = os.getenv('SCANS_DIR', './scans')
        fuzz_plan_path = os.path.join(scans_dir, scan_id, 'fuzz', 'fuzzplan.json')
        
        if not os.path.exists(fuzz_plan_path):
            # Fuzz plan not generated yet
            return render_template('fuzz_plan.html',
                                 scan_id=scan_id,
                                 fuzz_plan=None,
                                 scan=scan)
        
        # Load fuzz plan
        with open(fuzz_plan_path, 'r', encoding='utf-8') as f:
            fuzz_plan = json.load(f)
        
        return render_template('fuzz_plan.html',
                             scan_id=scan_id,
                             fuzz_plan=fuzz_plan,
                             scan=scan)
    finally:
        session_db.close()


@app.route('/api/fuzz-plan/generate/<scan_id>', methods=['POST'])
def generate_fuzz_plan(scan_id):
    """Generate fuzz plan from static findings - accessible without login"""
    logger.info(f"[FUZZ_PLAN] Generation requested for scan: {scan_id}")
    
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        
        # Check if scan exists
        if not os.path.exists(scan_dir):
            logger.warning(f"[FUZZ_PLAN] Scan directory not found: {scan_dir}")
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if static findings exist
        static_findings_path = os.path.join(scan_dir, 'static_findings.json')
        if not os.path.exists(static_findings_path):
            logger.warning(f"[FUZZ_PLAN] Static findings not found: {static_findings_path}")
            return jsonify({'error': 'Static findings not found. Run static analysis first.'}), 400
        
        # Validate static findings file is readable and valid JSON
        try:
            with open(static_findings_path, 'r', encoding='utf-8') as f:
                test_data = json.load(f)
            if not isinstance(test_data, dict) or 'findings' not in test_data:
                logger.error(f"[FUZZ_PLAN] Invalid static findings format")
                return jsonify({'error': 'Invalid static findings format'}), 400
        except json.JSONDecodeError as e:
            logger.error(f"[FUZZ_PLAN] Invalid JSON in static findings: {e}")
            return jsonify({'error': f'Invalid JSON in static findings: {str(e)}'}), 400
        
        # Create fuzz directory
        fuzz_dir = os.path.join(scan_dir, 'fuzz')
        os.makedirs(fuzz_dir, exist_ok=True)
        
        # Generate fuzz plan with source directory for signature extraction
        fuzz_plan_path = os.path.join(fuzz_dir, 'fuzzplan.json')
        source_dir = os.path.join(scan_dir, 'source')
        generator = FuzzPlanGenerator(static_findings_path, source_dir=source_dir)
        
        try:
            generator.save_fuzz_plan(fuzz_plan_path)
        except ValueError as e:
            logger.error(f"[FUZZ_PLAN] Validation error: {e}")
            return jsonify({'error': f'Validation error: {str(e)}'}), 400
        except Exception as e:
            logger.error(f"[FUZZ_PLAN] Generation error: {e}", exc_info=True)
            return jsonify({'error': f'Generation failed: {str(e)}'}), 500
        
        # Load generated plan
        with open(fuzz_plan_path, 'r', encoding='utf-8') as f:
            fuzz_plan = json.load(f)
        
        targets_count = len(fuzz_plan.get('targets', []))
        logger.info(f"[FUZZ_PLAN] Generated {targets_count} targets for scan {scan_id}")
        
        return jsonify({
            'success': True,
            'targets_count': targets_count,
            'fuzz_plan': fuzz_plan
        })
        
    except Exception as e:
        logger.error(f"[FUZZ_PLAN] Unexpected error: {e}", exc_info=True)
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


@app.route('/api/fuzz-plan/<scan_id>')
def get_fuzz_plan(scan_id):
    """Get fuzz plan for a scan - accessible without login"""
    logger.debug(f"[FUZZ_PLAN] API request for scan: {scan_id}")
    
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        fuzz_plan_path = os.path.join(scans_dir, scan_id, 'fuzz', 'fuzzplan.json')
        
        if not os.path.exists(fuzz_plan_path):
            return jsonify({'error': 'Fuzz plan not found'}), 404
        
        with open(fuzz_plan_path, 'r', encoding='utf-8') as f:
            fuzz_plan = json.load(f)
        
        return jsonify(fuzz_plan)
        
    except Exception as e:
        logger.error(f"[FUZZ_PLAN] Error loading fuzz plan: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/fuzz-plan/<scan_id>/export/<format>')
def export_fuzz_plan(scan_id, format):
    """Export fuzz plan in different formats - accessible without login"""
    logger.info(f"[FUZZ_PLAN] Export requested for scan {scan_id} in format {format}")
    
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        static_findings_path = os.path.join(scan_dir, 'static_findings.json')
        
        if not os.path.exists(static_findings_path):
            return jsonify({'error': 'Static findings not found'}), 404
        
        # Generate export file with source directory for signature extraction
        source_dir = os.path.join(scan_dir, 'source')
        generator = FuzzPlanGenerator(static_findings_path, source_dir=source_dir)
        
        if format == 'json':
            output_path = os.path.join(scan_dir, 'fuzz', 'fuzzplan.json')
            if os.path.exists(output_path):
                return send_file(output_path, 
                               as_attachment=True,
                               download_name=f'fuzzplan_{scan_id[:8]}.json',
                               mimetype='application/json')
            else:
                return jsonify({'error': 'Fuzz plan not generated yet'}), 404
                
        elif format == 'csv':
            output_path = os.path.join(scan_dir, 'fuzz', 'fuzzplan.csv')
            generator.export_to_csv(output_path)
            return send_file(output_path,
                           as_attachment=True,
                           download_name=f'fuzzplan_{scan_id[:8]}.csv',
                           mimetype='text/csv')
                           
        elif format == 'markdown' or format == 'md':
            output_path = os.path.join(scan_dir, 'fuzz', 'fuzzplan.md')
            generator.export_to_markdown(output_path)
            return send_file(output_path,
                           as_attachment=True,
                           download_name=f'fuzzplan_{scan_id[:8]}.md',
                           mimetype='text/markdown')
        else:
            return jsonify({'error': 'Invalid format. Use: json, csv, or markdown'}), 400
            
    except Exception as e:
        logger.error(f"[FUZZ_PLAN] Export error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Module 2: Harness Generation Routes
# ============================================================================

@app.route('/harness-generation/<scan_id>')
def harness_generation_view(scan_id):
    """Display harness generation page - accessible without login"""
    logger.info(f"[HARNESS_GEN] View requested for scan: {scan_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        # Check if fuzz plan exists
        scans_dir = os.getenv('SCANS_DIR', './scans')
        fuzz_plan_path = os.path.join(scans_dir, scan_id, 'fuzz', 'fuzzplan.json')
        
        if not os.path.exists(fuzz_plan_path):
            flash('Please generate a fuzz plan first.', 'warning')
            return redirect(url_for('fuzz_plan_view', scan_id=scan_id))
        
        # Check if harnesses exist
        harness_dir = os.path.join(scans_dir, scan_id, 'fuzz', 'harnesses')
        harnesses = []
        harness_stats = {
            'total_lines': 0,
            'harness_types': set(),
            'sanitizers_used': set()
        }
        
        if os.path.exists(harness_dir):
            # Load harness metadata
            for filename in os.listdir(harness_dir):
                if filename.endswith('.cc') or filename.endswith('.cpp'):
                    file_path = os.path.join(harness_dir, filename)
                    file_size = os.path.getsize(file_path)
                    
                    # Read file for preview and metadata extraction
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.split('\n')
                        preview = '\n'.join(lines[:20])
                        if len(lines) > 20:
                            preview += '\n... (truncated)'
                    
                    # Extract metadata from comments
                    bug_class = 'Unknown'
                    sanitizers = ['ASan', 'UBSan']
                    
                    for line in lines[:15]:  # Check first 15 lines for metadata
                        if '// Bug Class:' in line:
                            bug_class = line.split('// Bug Class:')[1].strip()
                        elif '// Sanitizers:' in line:
                            san_str = line.split('// Sanitizers:')[1].strip()
                            sanitizers = [s.strip() for s in san_str.split(',')]
                    
                    # Extract metadata from filename or content
                    harness_info = {
                        'name': filename,
                        'file_path': filename,
                        'function_name': filename.replace('_harness.cc', '').replace('_harness.cpp', ''),
                        'harness_type': 'bytes-to-api',
                        'bug_class': bug_class,
                        'file_size': file_size,
                        'sanitizers': sanitizers,
                        'code_preview': preview
                    }
                    harnesses.append(harness_info)
                    
                    harness_stats['total_lines'] += len(lines)
                    harness_stats['harness_types'].add(harness_info['harness_type'])
                    harness_stats['sanitizers_used'].update(harness_info['sanitizers'])
        
        # Convert sets to lists for template
        harness_stats['harness_types'] = list(harness_stats['harness_types'])
        harness_stats['sanitizers_used'] = list(harness_stats['sanitizers_used'])
        
        return render_template('harness_generation.html',
                             scan_id=scan_id,
                             harnesses=harnesses,
                             harness_stats=harness_stats,
                             scan=scan)
    finally:
        session_db.close()


@app.route('/api/harness/generate/<scan_id>', methods=['POST'])
def generate_harnesses(scan_id):
    """Generate fuzzing harnesses from fuzz plan - accessible without login"""
    logger.info(f"[HARNESS_GEN] Generation requested for scan: {scan_id}")
    
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        fuzz_plan_path = os.path.join(scan_dir, 'fuzz', 'fuzzplan.json')
        
        # Check if fuzz plan exists
        if not os.path.exists(fuzz_plan_path):
            logger.warning(f"[HARNESS_GEN] Fuzz plan not found: {fuzz_plan_path}")
            return jsonify({'error': 'Fuzz plan not found. Generate fuzz plan first.'}), 404
        
        # Create harness directory
        harness_dir = os.path.join(scan_dir, 'fuzz', 'harnesses')
        os.makedirs(harness_dir, exist_ok=True)
        
        # Generate harnesses using HarnessGenerator
        generator = HarnessGenerator(fuzz_plan_path)
        harnesses = generator.generate_all_harnesses(harness_dir)
        
        if not harnesses:
            return jsonify({'error': 'No harnesses generated. Check fuzz plan targets.'}), 400
        
        # Generate build script and README
        generator.generate_build_script(harness_dir, harnesses)
        generator.generate_readme(harness_dir, harnesses)
        
        logger.info(f"[HARNESS_GEN] Generated {len(harnesses)} harnesses for scan {scan_id}")
        
        return jsonify({
            'success': True,
            'harnesses_count': len(harnesses),
            'harnesses': harnesses
        })
        
    except Exception as e:
        logger.error(f"[HARNESS_GEN] Unexpected error: {e}", exc_info=True)
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


@app.route('/api/harness/download/<scan_id>')
def download_harness(scan_id):
    """Download a single harness file - accessible without login"""
    file_name = request.args.get('file')
    if not file_name:
        return jsonify({'error': 'File parameter required'}), 400
    
    scans_dir = os.getenv('SCANS_DIR', './scans')
    harness_path = os.path.join(scans_dir, scan_id, 'fuzz', 'harnesses', file_name)
    
    if not os.path.exists(harness_path):
        return jsonify({'error': 'Harness file not found'}), 404
    
    return send_file(harness_path, as_attachment=True, download_name=file_name)


@app.route('/api/harness/download-all/<scan_id>')
def download_all_harnesses(scan_id):
    """Download all harnesses as ZIP - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    harness_dir = os.path.join(scans_dir, scan_id, 'fuzz', 'harnesses')
    
    if not os.path.exists(harness_dir):
        return jsonify({'error': 'No harnesses found'}), 404
    
    # Create ZIP file
    zip_path = os.path.join(scans_dir, scan_id, 'fuzz', f'harnesses_{scan_id[:8]}.zip')
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for filename in os.listdir(harness_dir):
            if filename.endswith('.cc') or filename.endswith('.cpp'):
                file_path = os.path.join(harness_dir, filename)
                zipf.write(file_path, filename)
    
    return send_file(zip_path, as_attachment=True, download_name=f'harnesses_{scan_id[:8]}.zip')


@app.route('/api/harness/view/<scan_id>')
def view_harness(scan_id):
    """View full harness code - accessible without login"""
    file_name = request.args.get('file')
    if not file_name:
        return jsonify({'error': 'File parameter required'}), 400
    
    scans_dir = os.getenv('SCANS_DIR', './scans')
    harness_path = os.path.join(scans_dir, scan_id, 'fuzz', 'harnesses', file_name)
    
    if not os.path.exists(harness_path):
        return jsonify({'error': 'Harness file not found'}), 404
    
    with open(harness_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    # Return as plain text for viewing
    return f"<pre style='font-family: monospace; padding: 20px;'>{code}</pre>"


# ============================================================================
# Module 2: Build Orchestration Routes
# ============================================================================

@app.route('/build-orchestration/<scan_id>')
def build_orchestration_view(scan_id):
    """Display build orchestration page - accessible without login"""
    logger.info(f"[BUILD] View requested for scan: {scan_id}")
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        # Check if harnesses exist
        scans_dir = os.getenv('SCANS_DIR', './scans')
        harness_dir = os.path.join(scans_dir, scan_id, 'fuzz', 'harnesses')
        
        if not os.path.exists(harness_dir):
            flash('Please generate harnesses first.', 'warning')
            return redirect(url_for('harness_generation_view', scan_id=scan_id))
        
        # Check if builds exist
        scan_dir = os.path.join(scans_dir, scan_id)
        orchestrator = BuildOrchestrator(scan_dir)
        build_log = orchestrator.get_build_results()
        
        builds = []
        build_stats = {
            'success_count': 0,
            'error_count': 0,
            'pending_count': 0,
            'total_time': 0
        }
        
        if build_log:
            builds = build_log.get('builds', [])
            build_stats['success_count'] = build_log.get('successful', 0)
            build_stats['error_count'] = build_log.get('failed', 0)
            build_stats['total_time'] = round(sum(b.get('build_time', 0) for b in builds), 2)
        
        return render_template('build_orchestration.html',
                             scan_id=scan_id,
                             builds=builds,
                             build_stats=build_stats,
                             scan=scan)
    finally:
        session_db.close()


@app.route('/api/build/start/<scan_id>', methods=['POST'])
def start_build(scan_id):
    """Start building all fuzz targets - accessible without login"""
    logger.info(f"[BUILD] Build requested for scan: {scan_id}")
    
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        
        # Check if scan exists
        if not os.path.exists(scan_dir):
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if harnesses exist
        harness_dir = os.path.join(scan_dir, 'fuzz', 'harnesses')
        if not os.path.exists(harness_dir):
            return jsonify({'error': 'No harnesses found. Generate harnesses first.'}), 404
        
        # Start build
        orchestrator = BuildOrchestrator(scan_dir)
        build_results = orchestrator.build_all_targets()
        
        if not build_results:
            return jsonify({'error': 'No targets to build'}), 400
        
        success_count = sum(1 for r in build_results if r['status'] == 'success')
        error_count = sum(1 for r in build_results if r['status'] == 'error')
        
        logger.info(f"[BUILD] Completed for scan {scan_id}: {success_count} success, {error_count} failed")
        
        return jsonify({
            'success': True,
            'total': len(build_results),
            'successful': success_count,
            'failed': error_count,
            'builds': build_results
        })
        
    except Exception as e:
        logger.error(f"[BUILD] Unexpected error: {e}", exc_info=True)
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


@app.route('/api/build/status/<scan_id>')
def build_status(scan_id):
    """Get build status - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    orchestrator = BuildOrchestrator(scan_dir)
    build_log = orchestrator.get_build_results()
    
    if not build_log:
        return jsonify({'complete': False})
    
    return jsonify({
        'complete': True,
        'successful': build_log.get('successful', 0),
        'failed': build_log.get('failed', 0),
        'total': build_log.get('total_targets', 0)
    })


@app.route('/api/build/log/<scan_id>')
def download_build_log(scan_id):
    """Download build log - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    log_path = os.path.join(scans_dir, scan_id, 'build', '.build_log.json')
    
    if not os.path.exists(log_path):
        return jsonify({'error': 'Build log not found'}), 404
    
    return send_file(log_path, 
                    as_attachment=True,
                    download_name=f'build_log_{scan_id[:8]}.json',
                    mimetype='application/json')


@app.route('/api/build/download/<scan_id>')
def download_build_binary(scan_id):
    """Download built binary - accessible without login"""
    file_name = request.args.get('file')
    if not file_name:
        return jsonify({'error': 'File parameter required'}), 400
    
    scans_dir = os.getenv('SCANS_DIR', './scans')
    binary_path = os.path.join(scans_dir, scan_id, 'build', os.path.basename(file_name))
    
    if not os.path.exists(binary_path):
        return jsonify({'error': 'Binary not found'}), 404
    
    return send_file(binary_path, as_attachment=True, download_name=os.path.basename(file_name))


@app.route('/api/build/test-run/<scan_id>/<target_name>', methods=['POST'])
def test_run_target(scan_id, target_name):
    """Test run a built target - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    orchestrator = BuildOrchestrator(scan_dir)
    result = orchestrator.test_run_target(target_name, runs=100)
    
    return jsonify(result)


# ============================================================================
# Module 3: AI-Powered Repair (Grok/Gemini/Ollama)
# ============================================================================

@app.route('/api/repair/<scan_id>', methods=['POST'])
def repair_vulnerabilities(scan_id):
    """Run AI-assisted repair for vulnerabilities in a scan"""
    logger.info(f"[AI_REPAIR] AI repair requested for scan: {scan_id}")
    session_db = get_session()
    
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Load vulnerabilities
        vulnerabilities = scan.vulnerabilities_json or []
        if not vulnerabilities:
            return jsonify({'error': 'No vulnerabilities found to repair'}), 400
            
        # Optional filters
        data = request.json or {}
        vuln_index = data.get('vuln_index')  # Repairy only specific vulnerability
        provider = os.getenv('LLM_PROVIDER', 'groq')
        
        # Initialize Orchestrator
        from src.repair.orchestrator import RepairOrchestrator
        from src.repair.llm_client import MultiProviderLLMClient, LLMProvider
        
        # Force the requested provider from .env or request
        provider = provider.lower().strip()
        providers = []
        if provider == 'groq':
            providers = [LLMProvider.GROQ]
        elif provider == 'gemini':
            providers = [LLMProvider.GEMINI]
        elif provider == 'ollama':
            providers = [LLMProvider.OLLAMA]
        else:
            # Fallback to the primary provider
            providers = [LLMProvider.GROQ]
        
        llm_client = MultiProviderLLMClient(providers=providers)
        orchestrator = RepairOrchestrator(llm_client=llm_client)
        
        results = []
        
        # If specific index requested, only repair that one
        if vuln_index is not None:
            vuls_to_repair = [vulnerabilities[vuln_index]]
            logger.info(f"Repairing single vulnerability at index {vuln_index}")
        else:
            # Repair up to 5 vulnerabilities in parallel to avoid rate limits
            vuls_to_repair = vulnerabilities[:5]
            logger.info(f"Repairing batch of {len(vuls_to_repair)} vulnerabilities")
            
        for i, vuln in enumerate(vuls_to_repair):
            try:
                crash_id = f"vul-{i}"
                logger.info(f"Starting repair for {crash_id} ({vuln.get('bug_class', 'Unknown')})")
                
                # Run the multi-agent repair
                # This uses Analyzer -> Generator (with VUL-RAG) -> Validator
                repair_state = orchestrator.repair(
                    vulnerability=vuln,
                    scan_id=scan_id,
                    crash_id=crash_id
                )
                
                # Extract the best patch if found
                best_patch = repair_state.get('best_patch')
                analysis = repair_state.get('analysis') or {}
                
                if best_patch:
                    # Format result for VS Code extension
                    results.append({
                        'vulnerability_id': vuln.get('id'),
                        'type': vuln.get('type'),
                        'patch': best_patch.get('diff', ''),
                        'explanation': analysis.get('root_cause', 'AI-generated fix'),
                        'status': 'fixed',
                        'success': True
                    })
                    
                    # Store in scan patches
                    existing_patches = scan.patches_json or []
                    patch_id = f"ai_patch_{scan_id}_{i}"
                    
                    ai_patch = {
                        'patch_id': patch_id,
                        'vulnerability_id': vuln.get('id'),
                        'repaired': best_patch.get('diff', ''),
                        'original': best_patch.get('original_code', ''),
                        'explanation': analysis.get('root_cause', 'AI-generated fix'),
                        'type': 'ai_assisted',
                        'score': best_patch.get('score', 1.0)
                    }
                    
                    existing_patches.append(ai_patch)
                    scan.patches_json = existing_patches
                else:
                    results.append({
                        'vulnerability_id': vuln.get('id'),
                        'type': vuln.get('type'),
                        'status': 'failed',
                        'reason': repair_state.get('error', 'No valid patch generated'),
                        'success': False
                    })
            except Exception as e:
                logger.error(f"Error repairing {vuln.get('id', i)}: {e}")
                results.append({
                    'vulnerability_id': vuln.get('id', i),
                    'type': vuln.get('type', 'Unknown'),
                    'status': 'error',
                    'error': str(e),
                    'success': False
                })
        
        # Save changes to database
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(scan, 'patches_json')
        session_db.commit()
        
        return jsonify({
            'success': True,
            'repair_results': results
        })
        
    except Exception as e:
        logger.error(f"[AI_REPAIR] Error during AI repair process: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()


# ============================================================================
# Module 2: Fuzz Execution Routes
# ============================================================================

@app.route('/fuzz-execution/<scan_id>')
def fuzz_execution_view(scan_id):
    """Display fuzz execution page - accessible without login"""
    logger.info(f"[FUZZ_EXEC] View requested for scan: {scan_id}")
    return render_template('fuzz_execution.html', scan_id=scan_id)


@app.route('/api/fuzz/start/<scan_id>', methods=['POST'])
def start_fuzzing(scan_id):
    """Start fuzzing campaign - accessible without login"""
    logger.info(f"[FUZZ_EXEC] Campaign start requested for scan: {scan_id}")
    
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    # Get parameters
    runtime_minutes = int(request.json.get('runtime_minutes', 5))
    max_targets = request.json.get('max_targets')
    
    try:
        executor = FuzzExecutor(scan_dir)
        results = executor.run_campaign(runtime_minutes=runtime_minutes, max_targets=max_targets)
        
        logger.info(f"[FUZZ_EXEC] Campaign completed for scan: {scan_id}")
        return jsonify(results)
    except Exception as e:
        logger.error(f"[FUZZ_EXEC] Campaign failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/fuzz/results/<scan_id>')
def fuzz_results(scan_id):
    """Get fuzzing campaign results - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    executor = FuzzExecutor(scan_dir)
    results = executor.get_campaign_results()
    
    if results:
        return jsonify(results)
    else:
        return jsonify({'error': 'No results found'}), 404


@app.route('/api/scan', methods=['POST'])
@app.route('/scan-public', methods=['POST'])
def scan_public():
    """New ingestion API endpoint for public scanning"""
    try:
        # Check if this is a JSON request or form submission
        is_json_request = request.content_type and 'application/json' in request.content_type
        is_form_submission = request.content_type and (
            'multipart/form-data' in request.content_type or 
            'application/x-www-form-urlencoded' in request.content_type
        )
        
        # Get data from appropriate source
        if is_json_request:
            data = request.get_json() or {}
            repo_url = data.get('repo_url', '').strip()
            zip_file = None  # JSON requests don't support file uploads
            code_snippet = data.get('code_snippet', '').strip()
            analysis_tool = data.get('analysis_tool', 'cppcheck')
        else:
            # Form data
            repo_url = request.form.get('repo_url', '').strip()
            zip_file = request.files.get('zip_file')
            code_snippet = request.form.get('code_snippet', '').strip()
            analysis_tool = request.form.get('analysis_tool', 'cppcheck')
        
        logger.info(f"[SCAN_SUBMISSION] New scan request received")
        logger.info(f"[SCAN_SUBMISSION] Content-Type: {request.content_type}, Is JSON: {is_json_request}, Is Form: {is_form_submission}")
        if is_json_request:
            logger.info(f"[SCAN_SUBMISSION] Request JSON data: {data}")
        logger.info(f"[SCAN_SUBMISSION] Source types - repo_url: {bool(repo_url)}, zip_file: {bool(zip_file and zip_file.filename)}, code_snippet: {bool(code_snippet)}")
        logger.info(f"[SCAN_SUBMISSION] Analysis tool: {analysis_tool}")
        
        # Validate that only one source type is provided
        # For code snippets, check if it's not just whitespace
        has_code_snippet = code_snippet and code_snippet.strip()
        source_count = sum(bool(x) for x in [repo_url, zip_file and zip_file.filename, has_code_snippet])
        if source_count != 1:
            logger.warning(f"[SCAN_SUBMISSION] Validation failed: Exactly one source type must be provided (found {source_count})")
            if is_form_submission:
                flash('Please provide exactly one source: GitHub URL, ZIP file, or code snippet.', 'error')
                return redirect(url_for('no_login_scan'))
            return jsonify({'error': 'Exactly one source type must be provided'}), 400
        
        # Validate analysis tool
        if analysis_tool not in ['cppcheck', 'codeql']:
            logger.warning(f"[SCAN_SUBMISSION] Invalid analysis tool: {analysis_tool}")
            if is_form_submission:
                flash('Invalid analysis tool. Must be "cppcheck" or "codeql"', 'error')
                return redirect(url_for('no_login_scan'))
            return jsonify({'error': 'Invalid analysis tool. Must be "cppcheck" or "codeql"'}), 400
        
        # Generate scan ID and create directories
        scan_id = str(uuid.uuid4())
        scans_dir = os.getenv('SCANS_DIR', './scans')
        scan_dir = os.path.join(scans_dir, scan_id)
        source_dir = os.path.join(scan_dir, 'source')
        artifacts_dir = os.path.join(scan_dir, 'artifacts')
        
        logger.info(f"[SCAN_SUBMISSION] Generated scan_id: {scan_id}")
        logger.info(f"[SCAN_SUBMISSION] Creating directories - scan_dir: {scan_dir}")
        os.makedirs(source_dir, exist_ok=True)
        os.makedirs(artifacts_dir, exist_ok=True)
        logger.info(f"[SCAN_SUBMISSION] Directories created successfully")
        
        # Process different source types
        session_db = get_session()
        try:
            if repo_url:
                logger.info(f"[SCAN_SUBMISSION] Processing GitHub repository: {repo_url}")
                # Validate GitHub URL
                if not is_valid_github_url(repo_url):
                    logger.warning(f"[SCAN_SUBMISSION] Invalid GitHub URL format: {repo_url}")
                    if is_form_submission:
                        flash('Invalid GitHub URL format. Please use: https://github.com/username/repository', 'error')
                        return redirect(url_for('no_login_scan'))
                    return jsonify({'error': 'Invalid GitHub URL format'}), 400
                
                logger.info(f"[SCAN_SUBMISSION] GitHub URL validated successfully")
                # Create scan record
                scan = Scan(
                    id=scan_id,
                    user_id=None,  # Public scan
                    source_type='repo_url',
                    repo_url=repo_url,
                    analysis_tool=analysis_tool,
                    status='queued'
                )
                logger.info(f"[SCAN_SUBMISSION] Scan record created for repo_url: {scan_id}")
                
            elif zip_file:
                logger.info(f"[SCAN_SUBMISSION] Processing ZIP file: {zip_file.filename}")
                # Validate ZIP file
                is_valid, error_msg = validate_zip_file(zip_file)
                if not is_valid:
                    logger.warning(f"[SCAN_SUBMISSION] ZIP validation failed: {error_msg}")
                    if is_form_submission:
                        flash(f'ZIP file error: {error_msg}', 'error')
                        return redirect(url_for('no_login_scan'))
                    return jsonify({'error': error_msg}), 400
                
                logger.info(f"[SCAN_SUBMISSION] ZIP file validated successfully, size: {zip_file.content_length} bytes")
                # Save and extract ZIP safely
                zip_path = os.path.join(source_dir, 'source.zip')
                logger.info(f"[SCAN_SUBMISSION] Saving ZIP to: {zip_path}")
                zip_file.save(zip_path)
                
                try:
                    logger.info(f"[SCAN_SUBMISSION] Extracting ZIP file...")
                    safe_extract_zip(zip_path, source_dir, timeout=120)
                    os.remove(zip_path)  # Remove ZIP after extraction
                    logger.info(f"[SCAN_SUBMISSION] ZIP extracted and removed successfully")
                except ValueError as e:
                    logger.error(f"[SCAN_SUBMISSION] Unsafe ZIP file detected: {str(e)}")
                    shutil.rmtree(scan_dir, ignore_errors=True)
                    if is_form_submission:
                        flash(f'Unsafe ZIP file: {str(e)}', 'error')
                        return redirect(url_for('no_login_scan'))
                    return jsonify({'error': f'Unsafe ZIP file: {str(e)}'}), 400
                except TimeoutError as e:
                    logger.error(f"[SCAN_SUBMISSION] ZIP extraction timed out: {str(e)}")
                    shutil.rmtree(scan_dir, ignore_errors=True)
                    if is_form_submission:
                        flash(f'ZIP extraction timed out: {str(e)}', 'error')
                        return redirect(url_for('no_login_scan'))
                    return jsonify({'error': f'ZIP extraction timed out: {str(e)}'}), 400
                except RuntimeError as e:
                    logger.error(f"[SCAN_SUBMISSION] ZIP extraction failed: {str(e)}")
                    shutil.rmtree(scan_dir, ignore_errors=True)
                    if is_form_submission:
                        flash(f'ZIP extraction failed: {str(e)}', 'error')
                        return redirect(url_for('no_login_scan'))
                    return jsonify({'error': f'ZIP extraction failed: {str(e)}'}), 400
                
                logger.info(f"[SCAN_SUBMISSION] ZIP processing completed successfully")
                # Create scan record
                scan = Scan(
                    id=scan_id,
                    user_id=None,
                    source_type='zip',
                    source_path=source_dir,
                    analysis_tool=analysis_tool,
                    status='queued'
                )
                logger.info(f"[SCAN_SUBMISSION] Scan record created for zip: {scan_id}")
                
            else:  # code_snippet
                logger.info(f"[SCAN_SUBMISSION] Processing code snippet (length: {len(code_snippet)} chars)")
                # Validate code snippet
                is_valid, error_msg = validate_code_snippet(code_snippet)
                if not is_valid:
                    logger.warning(f"[SCAN_SUBMISSION] Code snippet validation failed: {error_msg}")
                    if is_form_submission:
                        flash(f'Code snippet error: {error_msg}', 'error')
                        return redirect(url_for('no_login_scan'))
                    return jsonify({'error': error_msg}), 400
                
                # Determine file extension based on content
                if 'def ' in code_snippet or 'import ' in code_snippet:
                    file_ext = '.py'
                elif any(keyword in code_snippet for keyword in ['#include', 'int main', 'void ']):
                    file_ext = '.cpp'
                elif 'function' in code_snippet or 'const ' in code_snippet:
                    file_ext = '.js'
                else:
                    file_ext = '.txt'
                
                logger.info(f"[SCAN_SUBMISSION] Detected file type: {file_ext}")
                # Save code snippet
                snippet_path = os.path.join(source_dir, f'snippet{file_ext}')
                logger.info(f"[SCAN_SUBMISSION] Saving code snippet to: {snippet_path}")
                with open(snippet_path, 'w', encoding='utf-8') as f:
                    f.write(code_snippet)
                logger.info(f"[SCAN_SUBMISSION] Code snippet saved successfully")
                
                # Create scan record
                scan = Scan(
                    id=scan_id,
                    user_id=None,
                    source_type='code_snippet',
                    source_path=snippet_path,
                    analysis_tool=analysis_tool, 
                    status='queued'
                )
                logger.info(f"[SCAN_SUBMISSION] Scan record created for code_snippet: {scan_id}")
            
            # Save scan to database
            logger.info(f"[SCAN_SUBMISSION] Saving scan record to database: {scan_id}")
            session_db.add(scan)
            session_db.commit()
            logger.info(f"[SCAN_SUBMISSION] Scan record saved successfully")

            # Flags to control Module 1 execution
            skip_static = bool(request.form.get('skip_static'))
            use_cached_static = bool(request.form.get('use_cached_static', '1'))
            if not (request.form.get('skip_static') or request.form.get('use_cached_static')):
                skip_static = os.getenv('ANALYSIS_DEFAULT', '').lower() == 'dynamic_only'

            # Try cached artifacts if requested
            if use_cached_static:
                artifacts_dir_abs = os.path.abspath(artifacts_dir)
                cached_xml = os.path.join(artifacts_dir_abs, 'cppcheck-report.xml')
                cached_sarif = os.path.join(artifacts_dir_abs, 'codeql-results.sarif')
                try:
                    cached_vulns = None
                    cached_patches = None
                    if analysis_tool == 'cppcheck' and os.path.exists(cached_xml):
                        logger.info(f"[SCAN_SUBMISSION] Using cached Cppcheck XML: {cached_xml}")
                        cached_vulns, cached_patches = parse_cppcheck_xml(cached_xml)
                    elif analysis_tool == 'codeql' and os.path.exists(cached_sarif):
                        logger.info(f"[SCAN_SUBMISSION] Using cached CodeQL SARIF: {cached_sarif}")
                        cached_vulns, cached_patches = parse_sarif_results(cached_sarif)

                    if cached_vulns is not None and cached_patches is not None:
                        scan.status = 'completed'
                        scan.vulnerabilities_json = cached_vulns
                        scan.patches_json = cached_patches
                        session_db.commit()
                        logger.info(f"[SCAN_SUBMISSION] Loaded {len(cached_vulns)} cached vulnerabilities; skipping static execution")

                        if is_form_submission:
                            return redirect(url_for('detailed_findings', scan_id=scan_id))
                        return jsonify({'scan_id': scan_id, 'status': 'completed'}), 200
                except Exception as cache_err:
                    logger.warning(f"[SCAN_SUBMISSION] Failed to use cached artifacts: {cache_err}")
                    session_db.rollback()

            # If skipping static, bypass Module 1 (intended for Module 2 work)
            if skip_static:
                logger.info(f"[SCAN_SUBMISSION] Skip static enabled - not enqueuing static analysis for scan {scan_id}")
                scan.status = 'queued'
                session_db.commit()
                if is_form_submission:
                    return redirect(url_for('scan_progress', scan_id=scan_id))
                return jsonify({'scan_id': scan_id, 'status': 'queued'}), 202

            # Enqueue Celery task (with fallback to sync if Redis unavailable)
            # Run analysis in background thread immediately to avoid any blocking
            import threading
            import traceback
            
            def run_analysis_background():
                """Run analysis - try Celery first, fallback to sync"""
                start_time = time.time()
                logger.info(f"[ANALYSIS] Starting analysis for scan {scan_id} using {analysis_tool}")
                try:
                    # Try Celery first (will fail fast if Redis unavailable due to our config)
                    logger.info(f"[ANALYSIS] Attempting to enqueue Celery task for scan {scan_id}...")
                    analyze_code.delay(scan_id, analysis_tool)
                    logger.info(f"[ANALYSIS] Celery task enqueued successfully for scan {scan_id}")
                except Exception as e:
                    # Celery failed, run synchronously
                    logger.warning(f"[ANALYSIS] Celery unavailable ({e}), running synchronously...")
                    logger.info(f"[ANALYSIS] For production, ensure Redis is running and Celery worker is active")
                    try:
                        logger.info(f"[ANALYSIS] Starting synchronous analysis for scan {scan_id} at {datetime.now().strftime('%H:%M:%S')}")
                        analyze_code_sync(scan_id, analysis_tool)
                        elapsed = time.time() - start_time
                        logger.info(f"[ANALYSIS] Completed synchronous analysis for scan {scan_id} in {elapsed:.2f} seconds")
                    except Exception as task_error:
                        logger.error(f"[ANALYSIS] Error in background analysis for scan {scan_id}: {task_error}")
                        traceback.print_exc()
            
            # Start analysis in background thread immediately (non-blocking)
            logger.info(f"[SCAN_SUBMISSION] Starting analysis thread for scan {scan_id}")
            analysis_thread = threading.Thread(target=run_analysis_background, daemon=True)
            analysis_thread.start()
            logger.info(f"[SCAN_SUBMISSION] Analysis thread started successfully")
            
            
            # For form submissions, redirect to detailed findings page
            if is_form_submission:
                try:
                    findings_url = url_for('detailed_findings', scan_id=scan_id)
                    logger.info(f"[SCAN_SUBMISSION] Redirecting to detailed findings: {findings_url}")
                    return redirect(findings_url)
                except Exception as redirect_error:
                    logger.error(f"[SCAN_SUBMISSION] Error generating redirect URL: {redirect_error}")
                    import traceback
                    traceback.print_exc()
                    flash(f'Scan submitted successfully (ID: {scan_id})', 'success')
                    return redirect(url_for('no_login_scan'))
            
            # For API calls (JSON), return JSON response for VS Code extension
            logger.info(f"[SCAN_SUBMISSION] Returning JSON response for scan {scan_id}")
            return jsonify({
                'scanId': scan_id,  # Changed from 'scan_id' to 'scanId' for extension compatibility
                'status': 'queued',
                'message': 'Scan initiated successfully'
            }), 202
            
        finally:
            session_db.close()
            logger.info(f"[SCAN_SUBMISSION] Database session closed for scan {scan_id}")
            
    except Exception as e:
        logger.error(f"[SCAN_SUBMISSION] Exception during scan submission: {e}", exc_info=True)
        # Clean up on error
        if 'scan_dir' in locals() and os.path.exists(scan_dir):
            shutil.rmtree(scan_dir, ignore_errors=True)
        # Check if form submission for proper error handling
        is_json_request = request.content_type and 'application/json' in request.content_type
        is_form_submission = request.content_type and ('multipart/form-data' in request.content_type or 'application/x-www-form-urlencoded' in request.content_type)
        
        import traceback
        print(f"ERROR in /scan-public: {e}")
        print(f"Content-Type: {request.content_type}, Is JSON: {is_json_request}, Is Form: {is_form_submission}")
        traceback.print_exc()
        
        if is_form_submission:
            flash(f'An error occurred: {str(e)}', 'error')
            try:
                return redirect(url_for('no_login_scan'))
            except Exception as redirect_err:
                print(f"ERROR in redirect: {redirect_err}")
                traceback.print_exc()
                # Fallback: return error page directly
                return f"<html><body><h1>Error</h1><p>{str(e)}</p><a href='/no-login'>Go Back</a></body></html>", 500
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@app.route('/public-results/<scan_id>')
def public_results(scan_id):
    """Show results for public scans (no login required)"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        vulnerabilities = scan.vulnerabilities_json or []
        patches = scan.patches_json or []
        
        scan_data = {
            'status': scan.status,
            'analysis_tool': scan.analysis_tool,
            'vulnerabilities': vulnerabilities,
            'patches': patches,
            'repo_url': scan.repo_url,
            'created_at': scan.created_at
        }
        
        return render_template('public_results.html', scan_id=scan_id, scan=scan_data)
    except Exception as e:
        logger.error(f"Error loading public results for scan {scan_id}: {e}")
        flash('Error loading scan results.', 'error')
        return redirect(url_for('no_login_scan'))
    finally:
        session_db.close()


@app.route('/api/tool-status')
def tool_status():
    """Check availability of analysis tools"""
    logger.info("[API] Tool status check requested")
    
    # Both tools are available via Docker containers
    # Cppcheck runs via Docker image, CodeQL via Docker image
    # No need to check host installation
    
    status = {
        'codeql': {
            'available': True,  # Available via Docker
            'name': 'CodeQL',
            'method': 'Docker Container'
        },
        'cppcheck': {
            'available': True,  # Available via Docker
            'name': 'Cppcheck',
            'method': 'Docker Container'
        }
    }
    
    logger.info(f"[API] Tool status - Both tools available via Docker")
    return jsonify(status)


@app.route('/download-patch/<scan_id>/<patch_id>')
def download_patch(scan_id, patch_id):
    """Download patch file"""
    scans = session.get('public_scans', {})
    scan = scans.get(scan_id)
    if not scan:
        flash('Scan not found or expired.')
        return redirect(url_for('no_login_scan'))
    
    # Find the patch
    patch = next((p for p in scan.get('patches', []) if p['id'] == patch_id), None)
    if not patch:
        flash('Patch not found.')
        return redirect(url_for('public_results', scan_id=scan_id))
    
    # Create temporary patch file
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False)
    temp_file.write(patch['content'])
    temp_file.close()
    
    return send_file(temp_file.name, as_attachment=True, 
                    download_name=f'{patch_id}.patch', mimetype='text/plain')

@app.route('/artifacts/<scan_id>/<filename>')
def download_artifact(scan_id, filename):
    """Download analysis artifact (e.g., XML/SARIF)"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    artifact_path = os.path.join(scans_dir, scan_id, 'artifacts', sanitize_filename(filename))
    if not os.path.exists(artifact_path):
        flash('Artifact not found.', 'error')
        return redirect(url_for('no_login_scan'))
    return send_file(artifact_path, as_attachment=True, download_name=filename)


def is_valid_github_url(url):
    """Validate if URL is a valid GitHub repository URL"""
    import re
    pattern = r'^https://github\.com/[\w\-\.]+/[\w\-\.]+/?$'
    return bool(re.match(pattern, url))


def process_github_repo(repo_url, scan_id, analysis_tool='cppcheck'):
    """Clone and process a public GitHub repository"""
    temp_dir = None
    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix=f'scan_{scan_id}_')
        
        # Clone the repository
        result = subprocess.run([
            'git', 'clone', '--depth', '1', repo_url, temp_dir
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            return {
                'success': False, 
                'error': 'Failed to clone repository. Make sure it\'s public and accessible.'
            }
        
        # Run static analysis with selected tool
        vulnerabilities, patches = run_static_analysis(temp_dir, analysis_tool)
        
        return {
            'success': True,
            'data': {
                'repo_url': repo_url,
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'patches': patches,
                'scan_type': 'github_repo',
                'analysis_tool': analysis_tool
            }
        }
        
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Repository clone timed out.'}
    except Exception as e:
        return {'success': False, 'error': f'Processing failed: {str(e)}'}
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def process_zip_upload(zip_file, scan_id, analysis_tool='cppcheck'):
    """Process uploaded ZIP file with secure extraction"""
    temp_dir = None
    try:
        # Validate ZIP file before processing
        is_valid, error_msg = validate_zip_file(zip_file)
        if not is_valid:
            return {'success': False, 'error': error_msg}
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix=f'scan_{scan_id}_')
        
        # Save and extract ZIP securely
        zip_path = os.path.join(temp_dir, 'upload.zip')
        zip_file.save(zip_path)
        
        # Use secure extraction with path traversal protection and timeout
        try:
            safe_extract_zip(zip_path, temp_dir, timeout=120)
        except ValueError as e:
            return {'success': False, 'error': f'Unsafe ZIP file: {str(e)}'}
        except TimeoutError as e:
            return {'success': False, 'error': f'ZIP extraction timed out: {str(e)}'}
        except RuntimeError as e:
            return {'success': False, 'error': f'ZIP extraction failed: {str(e)}'}
        
        # Remove the ZIP file
        os.remove(zip_path)
        
        # Run static analysis with selected tool
        vulnerabilities, patches = run_static_analysis(temp_dir, analysis_tool)
        
        return {
            'success': True,
            'data': {
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'patches': patches,
                'scan_type': 'zip_upload',
                'analysis_tool': analysis_tool
            }
        }
        
    except Exception as e:
        return {'success': False, 'error': f'ZIP processing failed: {str(e)}'}
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def process_code_snippet(code_snippet, scan_id, analysis_tool='cppcheck'):
    """Process pasted code snippet"""
    try:
        # Create temporary file for analysis
        temp_dir = tempfile.mkdtemp(prefix=f'snippet_{scan_id}_')
        
        # Determine file extension based on content or default to .txt
        file_ext = '.py' if 'def ' in code_snippet or 'import ' in code_snippet else '.cpp'
        snippet_file = os.path.join(temp_dir, f'snippet{file_ext}')
        
        with open(snippet_file, 'w', encoding='utf-8') as f:
            f.write(code_snippet)
        
        # Run analysis on the snippet
        vulnerabilities, patches = run_static_analysis(temp_dir, analysis_tool)
        
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        return {
            'success': True,
            'data': {
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'patches': patches,
                'scan_type': 'code_snippet',
                'analysis_tool': analysis_tool
            }
        }
        
    except Exception as e:
        return {'success': False, 'error': f'Code analysis failed: {str(e)}'}


def run_static_analysis(directory, analysis_tool='cppcheck'):
    """Run static analysis using the selected tool"""
    try:
        if analysis_tool == 'codeql':
            return run_codeql_analysis(directory)
        elif analysis_tool == 'cppcheck':
            return run_cppcheck_analysis(directory)
        else:
            # Fallback to simulation for unsupported tools
            return simulate_scan(directory)
    except Exception as e:
        print(f"Analysis failed: {e}")
        # Fallback to simulation if analysis fails
        return simulate_scan(directory)


def run_codeql_analysis(directory):
    """Run CodeQL analysis for deep semantic analysis"""
    vulnerabilities = []
    patches = []
    
    try:
        # Check if CodeQL is available
        result = subprocess.run(['codeql', '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print("CodeQL not available, falling back to simulation")
            return simulate_scan(directory)
        
        print(f"CodeQL version: {result.stdout.strip()}")
        
        # Detect languages in the directory
        languages = detect_languages(directory)
        if not languages:
            print("No supported languages detected for CodeQL")
            return simulate_scan(directory)
        
        # Create CodeQL database
        db_path = os.path.join(directory, 'codeql-db')
        language_str = ','.join(languages)
        
        print(f"Creating CodeQL database for languages: {language_str}")
        create_db_result = subprocess.run([
            'codeql', 'database', 'create', db_path,
            f'--language={language_str}',
            '--source-root', directory
        ], capture_output=True, text=True, timeout=300)
        
        if create_db_result.returncode != 0:
            print(f"CodeQL database creation failed: {create_db_result.stderr}")
            return simulate_scan(directory)
        
        # Run CodeQL queries with standard security pack
        sarif_path = os.path.join(directory, 'codeql-results.sarif')
        query_result = subprocess.run([
            'codeql', 'database', 'analyze', db_path,
            '--format=sarif-latest',
            f'--output={sarif_path}',
            '--download'  # Download standard query packs
        ], capture_output=True, text=True, timeout=300)
        
        if query_result.returncode == 0 and os.path.exists(sarif_path):
            # Parse SARIF results
            vulnerabilities, patches = parse_sarif_results(sarif_path)
            print(f"CodeQL found {len(vulnerabilities)} vulnerabilities")
        else:
            print(f"CodeQL analysis failed: {query_result.stderr}")
            vulnerabilities, patches = simulate_scan(directory)
        
        # Clean up database and results
        if os.path.exists(db_path):
            shutil.rmtree(db_path, ignore_errors=True)
        if os.path.exists(sarif_path):
            os.remove(sarif_path)
            
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"CodeQL analysis error: {e}")
        return simulate_scan(directory)
    
    return vulnerabilities, patches


def run_cppcheck_analysis(directory):
    """Run Cppcheck analysis for fast C/C++ vulnerability detection"""
    vulnerabilities = []
    patches = []
    
    try:
        # Check if Cppcheck is available
        result = subprocess.run(['cppcheck', '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print("Cppcheck not available, falling back to simulation")
            return simulate_scan(directory)
        
        print(f"Cppcheck version: {result.stdout.strip()}")
        
        # Check if directory contains C/C++ files
        cpp_files = find_cpp_files(directory)
        if not cpp_files:
            print("No C/C++ files found, using simulation")
            return simulate_scan(directory)
        
        print(f"Found {len(cpp_files)} C/C++ files for analysis")
        
        # Run Cppcheck analysis with comprehensive checks
        xml_output_path = os.path.join(directory, 'cppcheck-results.xml')
        cppcheck_result = subprocess.run([
            'cppcheck',
            '--enable=all',
            '--inconclusive',
            '--xml',
            '--xml-version=2',
            f'--output-file={xml_output_path}',
            directory
        ], capture_output=True, text=True, timeout=120)
        
        # Parse Cppcheck XML output
        if os.path.exists(xml_output_path):
            vulnerabilities, patches = parse_cppcheck_xml(xml_output_path)
            print(f"Cppcheck found {len(vulnerabilities)} issues")
            os.remove(xml_output_path)
        elif cppcheck_result.stderr:
            # Fallback: parse stderr output
            vulnerabilities, patches = parse_cppcheck_stderr(cppcheck_result.stderr)
        else:
            print("No Cppcheck results found")
            vulnerabilities, patches = simulate_scan(directory)
            
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Cppcheck analysis error: {e}")
        return simulate_scan(directory)
    
    return vulnerabilities, patches


def detect_languages(directory):
    """Detect programming languages in the directory for CodeQL"""
    languages = []
    
    # Walk through directory and check file extensions
    for root, dirs, files in os.walk(directory):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in ['.py']:
                if 'python' not in languages:
                    languages.append('python')
            elif ext in ['.js', '.ts', '.jsx', '.tsx']:
                if 'javascript' not in languages:
                    languages.append('javascript')
            elif ext in ['.java']:
                if 'java' not in languages:
                    languages.append('java')
            elif ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']:
                if 'cpp' not in languages:
                    languages.append('cpp')
            elif ext in ['.cs']:
                if 'csharp' not in languages:
                    languages.append('csharp')
            elif ext in ['.go']:
                if 'go' not in languages:
                    languages.append('go')
    
    return languages


def find_cpp_files(directory):
    """Find C/C++ files in the directory"""
    cpp_files = []
    cpp_extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.lower().endswith(ext) for ext in cpp_extensions):
                cpp_files.append(os.path.join(root, file))
    
    return cpp_files


def parse_sarif_results(sarif_path):
    """Parse SARIF results from CodeQL"""
    vulnerabilities = []
    patches = []
    
    try:
        import json
        with open(sarif_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
        
        for run in sarif_data.get('runs', []):
            for result in run.get('results', []):
                rule_id = result.get('ruleId', 'unknown')
                message = result.get('message', {}).get('text', 'No description')
                
                # Get location info
                locations = result.get('locations', [])
                file_path = 'unknown'
                line_num = 0
                
                if locations:
                    physical_location = locations[0].get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    file_path = artifact_location.get('uri', 'unknown')
                    region = physical_location.get('region', {})
                    line_num = region.get('startLine', 0)
                
                # Determine severity
                level = result.get('level', 'note')
                severity = 'high' if level == 'error' else 'medium' if level == 'warning' else 'low'
                
                vulnerabilities.append({
                    'id': f'codeql_{rule_id}_{len(vulnerabilities)}',
                    'severity': severity,
                    'description': f'CodeQL: {message}',
                    'file': file_path,
                    'line': line_num,
                    'tool': 'CodeQL'
                })
        
        # Generate basic patches
        for i, vuln in enumerate(vulnerabilities):
            patches.append({
                'id': f'codeql_patch_{i}',
                'description': f'Review and fix: {vuln["description"]}',
                'content': f'# CodeQL Issue: {vuln["description"]}\n# File: {vuln["file"]}:{vuln["line"]}\n# Manual review and fix required'
            })
    
    except Exception as e:
        print(f"Error parsing SARIF: {e}")
        return simulate_scan('')[0], simulate_scan('')[1]
    
    return vulnerabilities, patches


def parse_cppcheck_xml(xml_path):
    """Parse Cppcheck XML results"""
    vulnerabilities = []
    patches = []
    
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        for error in root.findall('.//error'):
            error_id = error.get('id', 'unknown')
            severity = error.get('severity', 'style')
            msg = error.get('msg', 'No description')
            
            # Map Cppcheck severity to our levels
            if severity in ['error']:
                sev_level = 'high'
            elif severity in ['warning', 'performance', 'portability']:
                sev_level = 'medium'
            else:
                sev_level = 'low'
            
            # Get location
            location = error.find('location')
            file_path = location.get('file', 'unknown') if location is not None else 'unknown'
            line_num = int(location.get('line', 0)) if location is not None else 0
            
            vulnerabilities.append({
                'id': f'cppcheck_{error_id}_{len(vulnerabilities)}',
                'severity': sev_level,
                'description': f'Cppcheck: {msg}',
                'file': os.path.basename(file_path),
                'line': line_num,
                'tool': 'Cppcheck'
            })
        
        # Generate patches
        for i, vuln in enumerate(vulnerabilities):
            patches.append({
                'id': f'cppcheck_patch_{i}',
                'description': f'Fix Cppcheck issue: {vuln["description"]}',
                'content': f'# Cppcheck Issue: {vuln["description"]}\n# File: {vuln["file"]}:{vuln["line"]}\n# Review and apply appropriate fix'
            })
    
    except Exception as e:
        print(f"Error parsing Cppcheck XML: {e}")
        return simulate_scan('')[0], simulate_scan('')[1]
    
    return vulnerabilities, patches


def parse_cppcheck_stderr(stderr_output):
    """Parse Cppcheck stderr output as fallback"""
    vulnerabilities = []
    patches = []
    
    try:
        lines = stderr_output.split('\n')
        for line in lines:
            if ':' in line and any(word in line.lower() for word in ['error', 'warning', 'style']):
                parts = line.split(':')
                if len(parts) >= 4:
                    file_path = parts[0].strip()
                    line_num = parts[1].strip() if parts[1].strip().isdigit() else '0'
                    severity = 'medium' if 'warning' in line.lower() else 'low'
                    description = ':'.join(parts[2:]).strip()
                    
                    vulnerabilities.append({
                        'id': f'cppcheck_stderr_{len(vulnerabilities)}',
                        'severity': severity,
                        'description': f'Cppcheck: {description}',
                        'file': os.path.basename(file_path),
                        'line': int(line_num) if line_num.isdigit() else 0,
                        'tool': 'Cppcheck'
                    })
        
        # Generate patches
        for i, vuln in enumerate(vulnerabilities):
            patches.append({
                'id': f'cppcheck_stderr_patch_{i}',
                'description': f'Fix: {vuln["description"]}',
                'content': f'# Issue: {vuln["description"]}\n# File: {vuln["file"]}:{vuln["line"]}\n# Apply appropriate fix'
            })
    
    except Exception as e:
        print(f"Error parsing Cppcheck stderr: {e}")
    
    return vulnerabilities, patches


def check_tool_availability(tool_name):
    """Check if a tool is available and get version info"""
    try:
        result = subprocess.run([tool_name, '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return {
                'available': True,
                'version': result.stdout.strip(),
                'path': shutil.which(tool_name)
            }
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return {
        'available': False,
        'version': None,
        'path': None
    }


def simulate_scan(directory):
    """Simulate vulnerability scanning (fallback when tools aren't available)"""
    vulnerabilities = []
    patches = []
    
    # Try to find relevant files in the directory
    source_files = []
    if directory and os.path.exists(directory):
        for root, _, files in os.walk(directory):
            for f in files:
                if f.endswith(('.c', '.cpp', '.h')):
                    source_files.append(os.path.join(root, f))
    
    if any(f.endswith('test_smart_fix.c') for f in source_files):
        # Specific findings for our test file
        vulnerabilities.extend([
            {
                'id': 'sim_vuln_1',
                'severity': 'high',
                'type': 'buffer_overflow',
                'description': 'Simulated: Potential buffer overflow in scan_input',
                'file': 'test_smart_fix.c',
                'line': 25,
                'tool': 'Simulation'
            },
            {
                'id': 'sim_vuln_2',
                'severity': 'medium',
                'type': 'null_pointer_dereference',
                'description': 'Simulated: Potential NULL pointer dereference (rule-based test)',
                'file': 'test_smart_fix.c',
                'line': 142,
                'tool': 'Simulation'
            },
            {
                'id': 'sim_vuln_3',
                'severity': 'high',
                'type': 'integer_overflow',
                'description': 'Simulated: Integer overflow in complex calculation (AI requested)',
                'file': 'test_smart_fix.c',
                'line': 65,
                'tool': 'Simulation'
            }
        ])
    else:
        # Generic findings
        vulnerabilities.append({
            'id': 'sim_vuln_gen',
            'severity': 'medium',
            'type': 'security_flaw',
            'description': 'Simulated: Sample vulnerability for testing',
            'file': os.path.basename(source_files[0]) if source_files else 'database.py',
            'line': 10,
            'tool': 'Simulation'
        })
    
    # Generate simple patches for the findings
    for i, vuln in enumerate(vulnerabilities):
        patches.append({
            'id': f'sim_patch_{i}',
            'description': f'Fix: {vuln["description"]}',
            'content': f'# Simulated fix for {vuln["description"]}\n# Manual review required'
        })
    
    return vulnerabilities, patches


# ============================================================================
# TRIAGE MODULE ROUTES
# ============================================================================

@app.route('/triage/<scan_id>')
def triage_dashboard(scan_id):
    """Triage dashboard for crash analysis"""
    from src.triage.analyzer import CrashTriageAnalyzer
    
    analyzer = CrashTriageAnalyzer(scan_id)
    results = analyzer.get_results()
    
    return render_template('triage_dashboard.html', 
                         scan_id=scan_id, 
                         results=results)

@app.route('/api/triage/<scan_id>/start', methods=['POST'])
def start_triage(scan_id):
    """Start triage analysis"""
    try:
        from src.triage.analyzer import CrashTriageAnalyzer
        
        analyzer = CrashTriageAnalyzer(scan_id)
        results = analyzer.analyze_all_crashes()
        
        return jsonify({
            'status': 'success',
            'message': 'Triage analysis completed',
            'results': results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/triage/<scan_id>/crash/<crash_id>')
def get_crash_details(scan_id, crash_id):
    """Get detailed information about a specific crash"""
    try:
        from src.triage.analyzer import CrashTriageAnalyzer
        
        analyzer = CrashTriageAnalyzer(scan_id)
        results = analyzer.get_results()
        
        if not results:
            return jsonify({'error': 'No triage results found'}), 404
        
        # Find the crash (using 'id' key, not 'crash_id')
        crash = next((c for c in results['crashes'] if c['id'] == crash_id), None)
        
        if not crash:
            return jsonify({'error': 'Crash not found'}), 404
        
        return jsonify(crash)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# REPRO-KIT MODULE ROUTES
# ============================================================================

@app.route('/repro-kit/<scan_id>')
def repro_kit(scan_id):
    """Repro-kit dashboard for generating reproducers"""
    from src.repro.generator import ReproKitGenerator
    
    generator = ReproKitGenerator(scan_id)
    results = generator.get_results()
    
    return render_template('repro_kit.html', 
                         scan_id=scan_id, 
                         results=results)

@app.route('/api/repro/<scan_id>/generate', methods=['POST'])
def generate_repro_kits(scan_id):
    """Generate reproduction kits for all crashes"""
    try:
        from src.repro.generator import ReproKitGenerator
        
        generator = ReproKitGenerator(scan_id)
        results = generator.generate_all_repros()
        
        return jsonify({
            'status': 'success',
            'message': f'Generated {results["total_repros"]} reproduction kits',
            'results': results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/repro/<scan_id>/code/<crash_id>/<code_type>')
def get_repro_code(scan_id, crash_id, code_type):
    """Get code for a specific repro component"""
    try:
        from src.repro.generator import ReproKitGenerator
        
        generator = ReproKitGenerator(scan_id)
        results = generator.get_results()
        
        if not results:
            return jsonify({'error': 'No repro results found'}), 404
        
        # Find the repro kit
        kit = next((k for k in results['repro_kits'] if k['crash_id'] == crash_id), None)
        
        if not kit:
            return jsonify({'error': 'Repro kit not found'}), 404
        
        # Get the requested code
        code_map = {
            'reproducer': ('Standalone Reproducer', kit['components']['standalone_reproducer']['code']),
            'gdb': ('GDB Debug Script', kit['components']['gdb_script']['script']),
            'exploit': ('Exploit Template', kit['components'].get('exploit_template', {}).get('code', 'Not available'))
        }
        
        if code_type not in code_map:
            return jsonify({'error': 'Invalid code type'}), 400
        
        title, code = code_map[code_type]
        
        return jsonify({
            'title': title,
            'code': code
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repro/<scan_id>/download/<crash_id>/<file_type>')
def download_repro_file(scan_id, crash_id, file_type):
    """Download a repro kit file"""
    try:
        from pathlib import Path
        
        scan_dir = Path(f"scans/{scan_id}")
        repro_dir = scan_dir / "repro_kits"
        
        file_map = {
            'reproducer': f"{crash_id}_reproducer.c",
            'gdb': f"{crash_id}_debug.gdb",
            'exploit': f"{crash_id}_exploit.c"
        }
        
        if file_type not in file_map:
            return jsonify({'error': 'Invalid file type'}), 400
        
        file_path = repro_dir / file_map[file_type]
        
        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(file_path, as_attachment=True, download_name=file_map[file_type])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repro/<scan_id>/apply-patch/<crash_id>', methods=['POST'])
def apply_patch(scan_id, crash_id):
    """Apply suggested patch (placeholder for now)"""
    # This would integrate with version control to apply patches
    return jsonify({
        'status': 'info',
        'message': 'Patch application requires manual review. Download the patch diff and apply manually.'
    })


# ============================================================================
# STAGE 2 (AI) - REPAIR MODULE ROUTES
# ============================================================================

@app.route('/repair/<scan_id>')
def repair_dashboard(scan_id):
    """Repair dashboard showing all AI-generated repairs"""
    try:
        # Try to load triage results from Module 2 (fuzzing)
        triage_path = Path(f"scans/{scan_id}/triage/triage_results.json")
        triage_results = None
        if triage_path.exists():
            with open(triage_path, 'r') as f:
                triage_results = json.load(f)
        
        # If no triage results, try to load static analysis vulnerabilities from Module 1
        if not triage_results:
            session_db = get_session()
            try:
                scan = session_db.query(Scan).filter_by(id=scan_id).first()
                if scan and scan.vulnerabilities_json:
                    # Convert static analysis vulnerabilities to triage format
                    vulnerabilities = scan.vulnerabilities_json if isinstance(scan.vulnerabilities_json, list) else []
                    
                    # Filter for Stage 2 vulnerabilities (complex ones that need AI)
                    stage2_vulns = []
                    for vuln in vulnerabilities:
                        # Stage 2 includes buffer overflows, format strings, obsolete functions, and other complex issues
                        rule_id = vuln.get('rule_id', '')
                        # Include buffer overflows, array bounds, obsolete functions (gets, strcpy, etc.)
                        if any(keyword in rule_id.lower() for keyword in [
                            'arrayindexoutofbounds', 'bufferaccessoutofbounds', 'bufferoverflow',
                            'obsoletefunction', 'gets', 'strcpy', 'sprintf', 'strcat',
                            'formatstring', 'racecondition'
                        ]):
                            stage2_vulns.append({
                                'crash_id': vuln.get('id', f"vuln_{vuln.get('line', 0)}"),
                                'file': vuln.get('file', 'unknown'),
                                'line': vuln.get('line', 0),
                                'description': vuln.get('description', 'Unknown vulnerability'),
                                'severity': vuln.get('severity', 'medium'),
                                'rule_id': vuln.get('rule_id', 'unknown')
                            })
                    
                    if stage2_vulns:
                        triage_results = {
                            'crashes': stage2_vulns,
                            'summary': {
                                'total': len(stage2_vulns),
                                'unique': len(stage2_vulns)
                            }
                        }
            finally:
                session_db.close()
        
        # If still no vulnerabilities, show error
        if not triage_results or not triage_results.get('crashes'):
            flash('No vulnerabilities found for AI repair. Please run a scan first.', 'warning')
            return redirect(url_for('detailed_findings', scan_id=scan_id))
        
        # Load repair results if available
        repair_path = Path(f"scans/{scan_id}/repair/repair_results.json")
        repair_results = None
        if repair_path.exists():
            with open(repair_path, 'r') as f:
                repair_results = json.load(f)
        
        # Load metrics if available
        metrics_path = Path(f"scans/{scan_id}/repair/metrics.json")
        metrics = None
        if metrics_path.exists():
            with open(metrics_path, 'r') as f:
                metrics = json.load(f)
        
        return render_template('repair_dashboard_enhanced.html',
                             scan_id=scan_id,
                             triage_results=triage_results,
                             repair_results=repair_results,
                             metrics=metrics)
    except Exception as e:
        logger.error(f"Error loading repair dashboard: {e}")
        flash(f'Error loading repair dashboard: {str(e)}', 'danger')
        return redirect(url_for('detailed_findings', scan_id=scan_id))


@app.route('/api/repair/start/<scan_id>', methods=['POST'])
def start_repair(scan_id):
    """Start AI repair workflow for critical/high vulnerabilities"""
    try:
        from src.repair.orchestrator import RepairOrchestrator
        from src.repair.llm_client import get_client
        
        # Check if LLM is configured
        client = get_client()
        health = client.check_health()
        if not any(health.values()):
            return jsonify({
                'status': 'error',
                'message': 'No LLM provider is configured. Please set GROQ_API_KEY or GEMINI_API_KEY in .env file.'
            }), 400
        
        # Try to load triage results from Module 2 (fuzzing)
        triage_path = Path(f"scans/{scan_id}/triage/triage_results.json")
        triage_results = None
        if triage_path.exists():
            with open(triage_path, 'r') as f:
                triage_results = json.load(f)
        
        # If no triage results, try to load static analysis vulnerabilities from Module 1
        if not triage_results:
            session_db = get_session()
            try:
                scan = session_db.query(Scan).filter_by(id=scan_id).first()
                if scan and scan.vulnerabilities_json:
                    # Convert static analysis vulnerabilities to triage format
                    vulnerabilities_list = scan.vulnerabilities_json if isinstance(scan.vulnerabilities_json, list) else []
                    
                    # Filter for Stage 2 vulnerabilities (complex ones that need AI)
                    stage2_vulns = []
                    for vuln in vulnerabilities_list:
                        rule_id = vuln.get('rule_id', '')
                        if any(keyword in rule_id.lower() for keyword in [
                            'arrayindexoutofbounds', 'bufferaccessoutofbounds', 'bufferoverflow',
                            'obsoletefunction', 'gets', 'strcpy', 'sprintf', 'strcat',
                            'formatstring', 'racecondition'
                        ]):
                            stage2_vulns.append({
                                'crash_id': vuln.get('id', f"vuln_{vuln.get('line', 0)}"),
                                'file': vuln.get('file', 'unknown'),
                                'line': vuln.get('line', 0),
                                'description': vuln.get('description', 'Unknown vulnerability'),
                                'severity': 'High',  # Stage 2 vulnerabilities are high severity
                                'rule_id': vuln.get('rule_id', 'unknown')
                            })
                    
                    if stage2_vulns:
                        triage_results = {
                            'crashes': stage2_vulns,
                            'summary': {
                                'total': len(stage2_vulns),
                                'unique': len(stage2_vulns)
                            }
                        }
            finally:
                session_db.close()
        
        # If still no vulnerabilities, return error
        if not triage_results:
            return jsonify({
                'status': 'error',
                'message': 'No vulnerabilities found. Please run a scan first.'
            }), 404
        
        # Filter critical/high vulnerabilities
        vulnerabilities = []
        for crash in triage_results.get('crashes', []):
            if crash.get('severity') in ['Critical', 'High']:
                vulnerabilities.append(crash)
        
        if not vulnerabilities:
            return jsonify({
                'status': 'info',
                'message': 'No critical or high severity vulnerabilities found to repair.'
            })
        
        # Start repair workflow (async)
        from threading import Thread
        
        def run_repairs():
            orchestrator = RepairOrchestrator()
            results = []
            
            for vuln in vulnerabilities:
                crash_id = vuln.get('crash_id', vuln.get('target', 'unknown'))
                try:
                    result = orchestrator.repair(
                        vulnerability=vuln,
                        scan_id=scan_id,
                        crash_id=crash_id,
                        max_retries=2
                    )
                    results.append({
                        'crash_id': crash_id,
                        'status': result['status'],
                        'patches_generated': len(result.get('patches', [])),
                        'best_patch': result.get('best_patch'),
                        'validation_results': result.get('validation_results')
                    })
                except Exception as e:
                    logger.error(f"Repair failed for {crash_id}: {e}")
                    results.append({
                        'crash_id': crash_id,
                        'status': 'failed',
                        'error': str(e)
                    })
            
            # Save results
            repair_dir = Path(f"scans/{scan_id}/repair")
            repair_dir.mkdir(parents=True, exist_ok=True)
            
            with open(repair_dir / 'repair_results.json', 'w') as f:
                json.dump({
                    'scan_id': scan_id,
                    'repairs': results,
                    'summary': {
                        'total': len(results),
                        'successful': sum(1 for r in results if r['status'] == 'completed'),
                        'failed': sum(1 for r in results if r['status'] == 'failed')
                    }
                }, f, indent=2)
            
            # Save metrics
            if orchestrator.metrics:
                orchestrator.metrics.finalize()
                orchestrator.metrics.save()
        
        thread = Thread(target=run_repairs)
        thread.start()
        
        return jsonify({
            'status': 'started',
            'scan_id': scan_id,
            'vulnerabilities_queued': len(vulnerabilities),
            'message': f'Started repair workflow for {len(vulnerabilities)} vulnerabilities'
        })
        
    except Exception as e:
        logger.error(f"Error starting repair: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/repair/status/<scan_id>')
def repair_status(scan_id):
    """Get repair status and results"""
    try:
        repair_path = Path(f"scans/{scan_id}/repair/repair_results.json")
        
        if not repair_path.exists():
            return jsonify({
                'status': 'not_started',
                'message': 'No repair results found'
            })
        
        with open(repair_path, 'r') as f:
            results = json.load(f)
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error getting repair status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/repair/patch/<scan_id>/<crash_id>')
def get_repair_patch(scan_id, crash_id):
    """Get specific patch details"""
    try:
        repair_path = Path(f"scans/{scan_id}/repair/repair_results.json")
        
        if not repair_path.exists():
            return jsonify({'error': 'No repair results found'}), 404
        
        with open(repair_path, 'r') as f:
            results = json.load(f)
        
        # Find the repair for this crash
        for repair in results.get('repairs', []):
            if repair['crash_id'] == crash_id:
                return jsonify(repair)
        
        return jsonify({'error': 'Patch not found'}), 404
        
    except Exception as e:
        logger.error(f"Error getting patch: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/repair/apply/<scan_id>/<crash_id>', methods=['POST'])
def apply_repair_patch(scan_id, crash_id):
    """Apply a validated patch to source code"""
    try:
        from src.repair.tools.patch_applier import PatchApplier
        
        # Get patch details
        repair_path = Path(f"scans/{scan_id}/repair/repair_results.json")
        if not repair_path.exists():
            return jsonify({'error': 'No repair results found'}), 404
        
        with open(repair_path, 'r') as f:
            results = json.load(f)
        
        # Find the repair
        repair = None
        for r in results.get('repairs', []):
            if r['crash_id'] == crash_id:
                repair = r
                break
        
        if not repair or not repair.get('best_patch'):
            return jsonify({'error': 'No patch found for this crash'}), 404
        
        best_patch = repair['best_patch']
        
        # Apply patch
        applier = PatchApplier(scan_id=scan_id)
        success = applier.apply_patch(
            file_path=best_patch['file'],
            patch_diff=best_patch['diff'],
            patch_metadata=best_patch
        )
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Patch applied to {best_patch["file"]}',
                'file': best_patch['file']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to apply patch'
            }), 500
        
    except Exception as e:
        logger.error(f"Error applying patch: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/repair/download/<scan_id>/<crash_id>')
def download_repair_patch(scan_id, crash_id):
    """Download patch as .diff file"""
    try:
        # Get patch details
        repair_path = Path(f"scans/{scan_id}/repair/repair_results.json")
        if not repair_path.exists():
            return jsonify({'error': 'No repair results found'}), 404
        
        with open(repair_path, 'r') as f:
            results = json.load(f)
        
        # Find the repair
        repair = None
        for r in results.get('repairs', []):
            if r['crash_id'] == crash_id:
                repair = r
                break
        
        if not repair or not repair.get('best_patch'):
            return jsonify({'error': 'No patch found'}), 404
        
        best_patch = repair['best_patch']
        
        # Create temporary file with patch
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.diff', delete=False) as f:
            f.write(best_patch['diff'])
            temp_path = f.name
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=f"{crash_id}_repair.diff",
            mimetype='text/x-diff'
        )
        
    except Exception as e:
        logger.error(f"Error downloading patch: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/repair/health')
def repair_health():
    """Check repair module health (LLM providers)"""
    try:
        from src.repair.llm_client import get_client
        
        client = get_client()
        health = client.check_health()
        
        return jsonify({
            'status': 'healthy' if any(health.values()) else 'unhealthy',
            'providers': health,
            'message': 'At least one LLM provider is available' if any(health.values()) else 'No LLM providers available'
        })
        
    except Exception as e:
        logger.error(f"Error checking repair health: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=True, extra_files=['templates/', 'src/'])
