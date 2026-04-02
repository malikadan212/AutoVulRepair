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
from collections import defaultdict
import time

# Simple rate limiting storage
rate_limit_storage = defaultdict(list)

def rate_limit(max_requests=10, window_seconds=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier (IP address)
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
            current_time = time.time()
            
            # Clean old requests
            rate_limit_storage[client_ip] = [
                req_time for req_time in rate_limit_storage[client_ip] 
                if current_time - req_time < window_seconds
            ]
            
            # Check rate limit
            if len(rate_limit_storage[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
            
            # Add current request
            rate_limit_storage[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests

# Import legacy components (for backward compatibility)
from src.models.scan import Scan
from src.database.connection import get_session, create_database
# Import new Celery workers instead of old queue tasks
try:
    from src.workers.job_worker import celery_app
    CELERY_AVAILABLE = True
except ImportError:
    # Fallback for development environments
    try:
        from src.queue.tasks import celery_app, analyze_code, analyze_code_sync
        CELERY_AVAILABLE = True
    except ImportError:
        CELERY_AVAILABLE = False
        celery_app = None

from src.utils.validation import (
    is_valid_github_url, validate_zip_file, validate_code_snippet, 
    safe_extract_zip, sanitize_filename
)
# validate_zip_file and safe_extract_zip are used for secure ZIP processing

# Import new database components
from src.models.scan_v2 import DatabaseManager
from src.repositories.scan_repository import ScanRepository
from src.services.scan_service import ScanService

# Import new GitHub service
from src.services.github_service import GitHubService
from src.services.differential_scan_service import DifferentialScanService

# Import user service for database-backed user management
from src.services.user_service import user_service
from src.models.user import User

# Import Module 2 components
from src.fuzz_plan.generator import FuzzPlanGenerator
from src.harness.generator import HarnessGenerator
from src.build.orchestrator import BuildOrchestrator
from src.fuzz_exec.executor import FuzzExecutor
from src.fuzz_exec.repair_integration import FuzzingRepairIntegration

# Import health checks for Kubernetes
from src.health.checks import register_health_routes

# Import advanced scanning endpoints
from src.api.advanced_scan_endpoints import advanced_scan_bp

load_dotenv()

# ---------------------------------------------------------------------------
# Temporary development helper: skip static/dynamic analysis when testing new
# AI patch module.  This flag is NOT intended for production and can be

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

# Initialize database and services
logger.info("=" * 60)
logger.info(f"Starting application at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.info("=" * 60)

# Initialize legacy database for backward compatibility
create_database()
logger.info("Legacy database initialized")

# Initialize new database system
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL:
    try:
        db_manager = DatabaseManager(DATABASE_URL)
        db_manager.create_tables()
        
        # Test connection
        if db_manager.health_check():
            logger.info("New database system initialized and connected")
            USE_DATABASE = True
        else:
            logger.warning("Database connection failed, using legacy file system")
            USE_DATABASE = False
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}, using legacy file system")
        USE_DATABASE = False
        db_manager = None
else:
    logger.info("No DATABASE_URL configured, using legacy file system")
    USE_DATABASE = False
    db_manager = None

# Initialize repository and service layers
if USE_DATABASE and db_manager:
    scan_repository = ScanRepository(db_manager, use_database=True)
    scan_service = ScanService(scan_repository)
    logger.info("Using database-backed scan service")
else:
    scan_repository = ScanRepository(None, use_database=False)
    scan_service = ScanService(scan_repository)
    logger.info("Using file system-backed scan service")

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev')

# Session configuration for better persistence
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours
app.config['SESSION_COOKIE_NAME'] = 'autovulrepair_session'

# Set maximum upload size to 100MB to prevent resource exhaustion
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Add custom JSON filter for templates
import json
@app.template_filter('tojson')
def to_json_filter(obj):
    return json.dumps(obj)

# Register health check routes for Kubernetes
register_health_routes(app)

# Register advanced scanning endpoints
app.register_blueprint(advanced_scan_bp)

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

# Database-backed user management (no more in-memory storage)
# Users are now stored in the database via user_service


# User class is now imported from src.models.user
# No need for in-app User class definition

@login_manager.user_loader
def load_user(user_id):
    """Load user from database"""
    return user_service.get_user_by_id(user_id)


# OAuth (GitHub) setup
oauth = OAuth(app)

# Check if GitHub OAuth credentials are configured
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_OAUTH_ENABLED = (
    GITHUB_CLIENT_ID and 
    GITHUB_CLIENT_SECRET and 
    GITHUB_CLIENT_ID != 'your_github_client_id_here' and
    GITHUB_CLIENT_SECRET != 'your_github_client_secret_here'
)

if GITHUB_OAUTH_ENABLED:
    github = oauth.register(
        name='github',
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={
            'scope': 'user:email'
        },
    )
    logger.info("GitHub OAuth enabled")
else:
    github = None
    logger.warning("GitHub OAuth disabled - credentials not configured")


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
    return render_template('home.html', github_oauth_enabled=GITHUB_OAUTH_ENABLED)


@app.route('/api/health')
def api_health():
    """Health check endpoint for VS Code extension - now includes database status"""
    try:
        health_status = {
            'status': 'ok',
            'message': 'Backend is running',
            'version': '2.0.0',
            'database': {
                'enabled': USE_DATABASE,
                'connected': False,
                'type': 'postgresql' if USE_DATABASE else 'legacy_sqlite'
            },
            'storage': {
                'type': 'database' if USE_DATABASE else 'filesystem',
                'stats': {}
            }
        }
        
        # Check database connectivity
        if USE_DATABASE and db_manager:
            health_status['database']['connected'] = db_manager.health_check()
            if health_status['database']['connected']:
                # Get storage stats
                stats = scan_service.get_system_stats()
                health_status['storage']['stats'] = stats['storage']
        
        return jsonify(health_status)
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Health check failed: {str(e)}',
            'version': '2.0.0',
            'database': {'enabled': False, 'connected': False},
            'storage': {'type': 'error'}
        }), 500


@app.route('/api/system/stats')
def api_system_stats():
    """Get system statistics - new endpoint for monitoring"""
    try:
        stats = scan_service.get_system_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/migrate', methods=['POST'])
def api_migrate_to_database():
    """Migrate existing file-based scans to database - admin endpoint"""
    if not USE_DATABASE:
        return jsonify({'error': 'Database not enabled'}), 400
    
    try:
        # This would implement migration logic
        # For now, return placeholder
        return jsonify({
            'status': 'not_implemented',
            'message': 'Migration functionality not yet implemented'
        })
    except Exception as e:
        logger.error(f"Migration error: {e}")
        return jsonify({'error': str(e)}), 500


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
    if not GITHUB_OAUTH_ENABLED:
        flash('GitHub OAuth is not configured. Please set up GitHub OAuth credentials or use the no-login option.', 'warning')
        return redirect(url_for('no_login_scan'))
    
    redirect_uri = url_for('authorized', _external=True)
    return github.authorize_redirect(redirect_uri)


@app.route('/auth')
def authorized():
    if not GITHUB_OAUTH_ENABLED:
        flash('GitHub OAuth is not configured.', 'error')
        return redirect(url_for('home'))
    
    try:
        logger.info("[AUTH] GitHub OAuth callback initiated")
        
        token = github.authorize_access_token()
        if not token:
            logger.warning("[AUTH] GitHub OAuth token not received")
            flash('Authentication failed.')
            return redirect(url_for('home'))

        logger.info("[AUTH] GitHub OAuth token received successfully")
        session['github_token'] = token['access_token']
        session.permanent = True  # Make session permanent
        
        # Fetch user info
        logger.info("[AUTH] Fetching user info from GitHub API")
        resp = requests.get('https://api.github.com/user', 
                          headers={'Authorization': f'token {token["access_token"]}'})
        
        if resp.status_code != 200:
            logger.error(f"[AUTH] Failed to fetch user info from GitHub: {resp.status_code}")
            flash('Failed to fetch user info from GitHub.')
            return redirect(url_for('home'))

        data = resp.json()
        user_id = str(data.get('id'))
        username = data.get('login')
        email = data.get('email')
        avatar_url = data.get('avatar_url')

        logger.info(f"[AUTH] GitHub user info received: {username} (ID: {user_id})")

        # Create or update user in database
        logger.info(f"[AUTH] Creating/updating user in database: {username}")
        user = user_service.create_or_update_user(
            user_id=user_id,
            username=username,
            email=email,
            avatar_url=avatar_url,
            token=token['access_token']
        )
        
        logger.info(f"[AUTH] User successfully saved to database: {username} (ID: {user_id})")
        
        login_user(user, remember=True)  # Remember the user
        logger.info(f"[AUTH] User logged in successfully: {username}")
        
        flash('Logged in successfully.')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"[AUTH] Authentication error: {e}", exc_info=True)
        flash(f'Authentication error: {str(e)}')
        return redirect(url_for('home'))


# Token getter no longer needed with Authlib


@app.route('/dashboard')
@login_required
def dashboard():
    """Enhanced user dashboard with personalized scan management"""
    try:
        # Get user's scans from NEW database system
        logger.info(f"[DASHBOARD] Loading dashboard for user {current_user.username} (ID: {current_user.id})")
        user_scans_data = scan_service.get_user_scans(current_user.id)
        
        logger.info(f"[DASHBOARD] Found {len(user_scans_data)} scans for user {current_user.username}")
        
        # Convert scan data to format expected by template
        recent_scans = []
        for scan_data in user_scans_data[:10]:
            # Convert ISO string to datetime object for template
            created_at = None
            if scan_data.get('created_at'):
                try:
                    from datetime import datetime
                    created_at = datetime.fromisoformat(scan_data['created_at'].replace('Z', '+00:00'))
                    created_at = created_at.replace(tzinfo=None)  # Remove timezone for template
                except:
                    created_at = None
            
            # Create scan object that matches template expectations
            scan_obj = type('Scan', (), {
                'id': scan_data['scan_id'],
                'repo_url': scan_data.get('repo_url', 'Code snippet/ZIP'),
                'status': scan_data['status'],
                'analysis_tool': scan_data['analysis_tool'],
                'created_at': created_at,
                'source_type': scan_data.get('source_type', 'repository')
            })()
            
            recent_scans.append(scan_obj)
        
        # Calculate user-specific statistics from new data format
        stats = calculate_user_stats_v2(user_scans_data)
        
        # Get scan status breakdown
        status_breakdown = get_status_breakdown_v2(user_scans_data)
        
        # Get vulnerability trends (last 30 days)
        vulnerability_trends = get_vulnerability_trends_v2(user_scans_data)
        
        # Ensure vulnerability_trends is not None
        if vulnerability_trends is None:
            vulnerability_trends = []
        
        # Get user preferences/settings
        user_settings = get_user_settings(current_user.id)
        
        logger.info(f"[DASHBOARD] Rendering dashboard with {len(recent_scans)} recent scans")
        
        return render_template('single_page_dashboard.html',
                             user=current_user,
                             stats=stats,
                             recent_scans=recent_scans,
                             status_breakdown=status_breakdown,
                             vulnerability_trends=vulnerability_trends,
                             user_settings=user_settings)
            
    except Exception as e:
        logger.error(f"Error loading enhanced dashboard: {e}", exc_info=True)
        # Fallback to basic stats
        stats = {
            'total_scans': 0,
            'completed_scans': 0,
            'failed_scans': 0,
            'running_scans': 0,
            'success_rate': 0,
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'avg_scan_time': 0
        }
        return render_template('single_page_dashboard.html', 
                             user=current_user, 
                             stats=stats,
                             recent_scans=[],
                             status_breakdown={},
                             vulnerability_trends=[],
                             user_settings=get_user_settings(current_user.id))


def calculate_user_stats_v2(user_scans_data):
    """Calculate personalized statistics for user using new data format"""
    total_scans = len(user_scans_data)
    
    # Count by status
    completed_scans = sum(1 for scan in user_scans_data if scan.get('status') == 'completed')
    failed_scans = sum(1 for scan in user_scans_data if scan.get('status') == 'failed')
    running_scans = sum(1 for scan in user_scans_data if scan.get('status') in ['queued', 'processing'])
    
    # Count vulnerabilities by getting findings for each completed scan
    total_vulnerabilities = 0
    critical_vulnerabilities = 0
    high_vulnerabilities = 0
    
    # Use the global scan_service that's already initialized
    global scan_service
    
    logger.info(f"[DASHBOARD] Calculating stats for {len(user_scans_data)} scans ({completed_scans} completed)")
    
    # Count vulnerabilities from completed scans
    for scan_data in user_scans_data:
        if scan_data.get('status') == 'completed':
            scan_id = scan_data['scan_id']
            try:
                logger.debug(f"[DASHBOARD] Getting results for scan {scan_id[:8]}...")
                results = scan_service.get_scan_results(scan_id)
                if 'error' not in results:
                    findings = results['findings']
                    scan_vuln_count = len(findings)
                    total_vulnerabilities += scan_vuln_count
                    
                    logger.debug(f"[DASHBOARD] Scan {scan_id[:8]}: {scan_vuln_count} vulnerabilities")
                    
                    # Count by severity (using Cppcheck severity mapping)
                    for finding in findings:
                        severity = finding.get('severity', '').lower()
                        if severity == 'error':  # Cppcheck 'error' = high severity
                            high_vulnerabilities += 1
                        # Note: Cppcheck doesn't have 'critical', so we don't count those
                else:
                    logger.warning(f"[DASHBOARD] Error getting results for scan {scan_id[:8]}: {results.get('error', 'Unknown error')}")
            except Exception as e:
                logger.error(f"[DASHBOARD] Exception getting results for scan {scan_id[:8]}: {e}")
                continue
    
    logger.info(f"[DASHBOARD] Final vulnerability counts: {total_vulnerabilities} total, {high_vulnerabilities} high")
    
    # Calculate success rate
    success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
    
    # Calculate average scan time (simplified for now)
    avg_scan_time = 0  # TODO: Implement based on new timestamp fields
    
    return {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'running_scans': running_scans,
        'success_rate': round(success_rate, 1),
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulnerabilities': critical_vulnerabilities,
        'high_vulnerabilities': high_vulnerabilities,
        'avg_scan_time': avg_scan_time
    }

def get_status_breakdown_v2(user_scans_data):
    """Get scan status breakdown for charts using new data format"""
    status_counts = {}
    for scan in user_scans_data:
        status = scan.get('status', 'unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
    
    return status_counts

def get_vulnerability_trends_v2(user_scans_data):
    """Get vulnerability trends over last 30 days using new data format"""
    from datetime import timedelta, datetime
    thirty_days_ago = datetime.now() - timedelta(days=30)
    
    # Filter recent scans
    recent_scans = []
    for scan in user_scans_data:
        created_at_str = scan.get('created_at')
        if created_at_str:
            try:
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                if created_at.replace(tzinfo=None) >= thirty_days_ago:
                    recent_scans.append(scan)
            except:
                continue
    
    # For now, return empty trends since we need to implement vulnerability counting
    trends = []
    for i in range(30):
        date = (datetime.now() - timedelta(days=29-i)).date()
        trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'vulnerabilities': 0  # TODO: Implement vulnerability counting from findings
        })
    
    return trends

def calculate_user_stats(user_scans):
    """Calculate personalized statistics for user"""
    total_scans = len(user_scans)
    
    # Count by status
    completed_scans = sum(1 for scan in user_scans if scan.status == 'completed')
    failed_scans = sum(1 for scan in user_scans if scan.status == 'failed')
    running_scans = sum(1 for scan in user_scans if scan.status in ['queued', 'processing'])
    
    # Count vulnerabilities
    total_vulnerabilities = 0
    critical_vulnerabilities = 0
    high_vulnerabilities = 0
    
    for scan in user_scans:
        if scan.vulnerabilities_json:
            vulns = scan.vulnerabilities_json
            total_vulnerabilities += len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    critical_vulnerabilities += 1
                elif severity == 'high':
                    high_vulnerabilities += 1
    
    # Calculate success rate
    success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
    
    # Calculate average scan time
    avg_scan_time = calculate_average_scan_time(user_scans)
    
    return {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'running_scans': running_scans,
        'success_rate': round(success_rate, 1),
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulnerabilities': critical_vulnerabilities,
        'high_vulnerabilities': high_vulnerabilities,
        'avg_scan_time': avg_scan_time
    }

def get_status_breakdown(user_scans):
    """Get scan status breakdown for charts"""
    status_counts = {}
    for scan in user_scans:
        status = scan.status
        status_counts[status] = status_counts.get(status, 0) + 1
    
    return status_counts

def get_vulnerability_trends(user_scans):
    """Get vulnerability trends over last 30 days"""
    from datetime import timedelta
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_scans = [scan for scan in user_scans if scan.created_at and scan.created_at >= thirty_days_ago]
    
    # Group by day
    daily_vulns = {}
    for scan in recent_scans:
        day = scan.created_at.date()
        if scan.vulnerabilities_json:
            vuln_count = len(scan.vulnerabilities_json)
            daily_vulns[day] = daily_vulns.get(day, 0) + vuln_count
    
    # Convert to chart format
    trends = []
    for i in range(30):
        date = (datetime.now() - timedelta(days=29-i)).date()
        trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'vulnerabilities': daily_vulns.get(date, 0)
        })
    
    return trends

def get_user_settings(user_id):
    """Get user preferences and settings"""
    # For now, return default settings
    # Later this will come from a user_settings table
    return {
        'default_analysis_tool': 'cppcheck',
        'email_notifications': True,
        'auto_patch_generation': False,
        'preferred_severity_filter': 'all',
        'dashboard_refresh_interval': 30  # seconds
    }

def calculate_average_scan_time(user_scans):
    """Calculate average scan completion time"""
    completed_scans = [scan for scan in user_scans if scan.status == 'completed' and hasattr(scan, 'completed_at') and scan.completed_at]
    
    if not completed_scans:
        return 0
    
    total_time = 0
    for scan in completed_scans:
        if scan.created_at and scan.completed_at:
            duration = (scan.completed_at - scan.created_at).total_seconds()
            total_time += duration
    
    if len(completed_scans) == 0:
        return 0
        
    avg_seconds = total_time / len(completed_scans)
    return round(avg_seconds / 60, 1)  # Return in minutes


# API endpoints for enhanced dashboard
@app.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    """Get real-time dashboard statistics"""
    try:
        session_db = get_session()
        try:
            user_scans = session_db.query(Scan).filter(
                Scan.user_id == current_user.id
            ).all()
            
            stats = calculate_user_stats(user_scans)
            return jsonify(stats)
        finally:
            session_db.close()
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/recent-scans')
@login_required
def api_recent_scans():
    """Get recent scans for dashboard"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        session_db = get_session()
        try:
            recent_scans = session_db.query(Scan).filter(
                Scan.user_id == current_user.id
            ).order_by(Scan.created_at.desc()).limit(limit).all()
            
            scans_data = []
            for scan in recent_scans:
                scans_data.append({
                    'id': scan.id,
                    'repo_url': scan.repo_url or 'ZIP Upload',
                    'status': scan.status,
                    'created_at': scan.created_at.isoformat() if scan.created_at else None,
                    'analysis_tool': scan.analysis_tool,
                    'vulnerability_count': len(scan.vulnerabilities_json) if scan.vulnerabilities_json else 0
                })
            
            return jsonify({'scans': scans_data})
        finally:
            session_db.close()
    except Exception as e:
        logger.error(f"Error getting recent scans: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/running-scans')
@login_required
def api_running_scans():
    """Get currently running scans"""
    try:
        session_db = get_session()
        try:
            running_scans = session_db.query(Scan).filter(
                Scan.user_id == current_user.id,
                Scan.status.in_(['queued', 'processing'])
            ).order_by(Scan.created_at.desc()).all()
            
            scans_data = []
            for scan in running_scans:
                # Calculate estimated completion time
                elapsed_time = (datetime.now() - scan.created_at).total_seconds() if scan.created_at else 0
                estimated_remaining = max(0, 300 - elapsed_time)  # Assume 5 min average
                
                scans_data.append({
                    'id': scan.id,
                    'repo_url': scan.repo_url or 'ZIP Upload',
                    'status': scan.status,
                    'created_at': scan.created_at.isoformat() if scan.created_at else None,
                    'elapsed_time': elapsed_time,
                    'estimated_remaining': estimated_remaining,
                    'analysis_tool': scan.analysis_tool
                })
            
            return jsonify({'scans': scans_data})
        finally:
            session_db.close()
    except Exception as e:
        logger.error(f"Error getting running scans: {e}")
        return jsonify({'error': str(e)}), 500

# User settings management
@app.route('/api/user/settings', methods=['GET'])
@login_required
def api_get_user_settings():
    """Get user settings"""
    try:
        settings = get_user_settings(current_user.id)
        return jsonify(settings)
    except Exception as e:
        logger.error(f"Error getting user settings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/settings', methods=['PUT'])
@login_required
def api_update_user_settings():
    """Update user settings"""
    try:
        try:
            data = request.get_json()
        except Exception as e:
            return jsonify({'error': 'Invalid JSON format'}), 400
        
        # Validate settings
        valid_tools = ['cppcheck', 'clang-static-analyzer', 'semgrep']
        if data.get('default_analysis_tool') not in valid_tools:
            return jsonify({'error': 'Invalid analysis tool'}), 400
        
        # For now, store in session (later move to database)
        session['user_settings'] = data
        
        logger.info(f"Updated settings for user {current_user.username}")
        return jsonify({'message': 'Settings updated successfully'})
        
    except Exception as e:
        logger.error(f"Error updating user settings: {e}")
        return jsonify({'error': str(e)}), 500


# GitHub Integration API Endpoints
@app.route('/api/github/repositories')
@login_required
def api_get_user_repositories():
    """Get user's GitHub repositories"""
    try:
        # Check if user has GitHub token
        github_token = session.get('github_token')
        if not github_token:
            return jsonify({'error': 'GitHub authentication required'}), 401
        
        # Initialize GitHub service
        github_service = GitHubService(github_token)
        
        # Get repositories
        repositories = github_service.get_user_repositories(limit=50)
        
        # Get rate limit status
        rate_limit = github_service.get_rate_limit_status()
        
        return jsonify({
            'repositories': repositories,
            'rate_limit': rate_limit,
            'count': len(repositories)
        })
        
    except Exception as e:
        logger.error(f"Error getting user repositories: {e}")
        return jsonify({'error': 'Failed to fetch repositories'}), 500


@app.route('/api/github/repository/<path:repo_full_name>/pulls')
@login_required
def api_get_repository_pulls(repo_full_name):
    """Get pull requests for a specific repository"""
    try:
        # Validate repository name
        if not repo_full_name or '/' not in repo_full_name:
            return jsonify({'error': 'Invalid repository name'}), 400
        
        # Check GitHub token
        github_token = session.get('github_token')
        if not github_token:
            return jsonify({'error': 'GitHub authentication required'}), 401
        
        # Initialize GitHub service
        github_service = GitHubService(github_token)
        
        # Validate user has access to repository
        if not github_service.validate_repository_access(repo_full_name):
            return jsonify({'error': 'Repository not found or access denied'}), 403
        
        # Get pull requests
        pulls = github_service.get_repository_pulls(repo_full_name, limit=20)
        
        return jsonify({
            'pulls': pulls,
            'repository': repo_full_name,
            'count': len(pulls)
        })
        
    except Exception as e:
        logger.error(f"Error getting repository pulls: {e}")
        return jsonify({'error': 'Failed to fetch pull requests'}), 500


@app.route('/api/github/repository/<path:repo_full_name>/pulls/<int:pr_number>/files')
@login_required
def api_get_pull_request_files(repo_full_name, pr_number):
    """Get files changed in a pull request"""
    try:
        # Validate inputs
        if not repo_full_name or '/' not in repo_full_name:
            return jsonify({'error': 'Invalid repository name'}), 400
        
        if pr_number <= 0:
            return jsonify({'error': 'Invalid pull request number'}), 400
        
        # Check GitHub token
        github_token = session.get('github_token')
        if not github_token:
            return jsonify({'error': 'GitHub authentication required'}), 401
        
        # Initialize GitHub service
        github_service = GitHubService(github_token)
        
        # Validate repository access
        if not github_service.validate_repository_access(repo_full_name):
            return jsonify({'error': 'Repository not found or access denied'}), 403
        
        # Get PR files
        files = github_service.get_pull_request_files(repo_full_name, pr_number)
        
        return jsonify({
            'files': files,
            'repository': repo_full_name,
            'pr_number': pr_number,
            'count': len(files)
        })
        
    except Exception as e:
        logger.error(f"Error getting PR files: {e}")
        return jsonify({'error': 'Failed to fetch pull request files'}), 500

# Quick actions for dashboard
@app.route('/api/dashboard/quick-scan', methods=['POST'])
@login_required
def api_quick_scan():
    """Start a quick scan from dashboard"""
    try:
        try:
            data = request.get_json()
        except Exception as e:
            return jsonify({'error': 'Invalid JSON format'}), 400
        repo_url = data.get('repo_url', '').strip()
        
        if not repo_url:
            return jsonify({'error': 'Repository URL required'}), 400
        
        if not is_valid_github_url(repo_url):
            return jsonify({'error': 'Invalid GitHub URL'}), 400
        
        # Get user's default settings
        user_settings = get_user_settings(current_user.id)
        analysis_tool = user_settings.get('default_analysis_tool', 'cppcheck')
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan record in database
        session_db = get_session()
        try:
            new_scan = Scan(
                id=scan_id,
                user_id=current_user.id,
                source_type='repo_url',
                repo_url=repo_url,
                analysis_tool=analysis_tool,
                status='processing'
            )
            session_db.add(new_scan)
            session_db.commit()
            logger.info(f"Created quick scan {scan_id} for user {current_user.username}")
        finally:
            session_db.close()
        
        # Start scan processing using Celery
        result = scan_service.create_scan(
            user_id=current_user.id,
            source_type='repository',
            analysis_tool=analysis_tool,
            repo_url=repo_url
        )
        
        if result['status'] == 'processing':
            # Scan started in background
            return jsonify({
                'scan_id': result['scan_id'],
                'task_id': result.get('task_id'),
                'message': 'Scan started in background',
                'status': 'processing',
                'redirect_url': url_for('scan_status', scan_id=result['scan_id'])
            })
        elif result['status'] == 'completed':
            # Scan completed synchronously (Celery not available)
            return jsonify({
                'scan_id': result['scan_id'],
                'message': 'Scan completed successfully',
                'redirect_url': url_for('detailed_findings', scan_id=result['scan_id'])
            })
        else:
            # Scan failed
            return jsonify({'error': result.get('error', 'Scan failed')}), 400
            
    except Exception as e:
        logger.error(f"Error starting quick scan: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tasks/<task_id>/status')
@login_required
def api_task_status(task_id):
    """Get Celery task status"""
    try:
        result = scan_service.get_task_status(task_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting task status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tasks/<task_id>/cancel', methods=['POST'])
@login_required
def api_cancel_task(task_id):
    """Cancel a Celery task"""
    try:
        result = scan_service.cancel_task(task_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error cancelling task: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tasks/active')
@login_required
def api_active_tasks():
    """Get all active Celery tasks"""
    try:
        result = scan_service.get_active_tasks()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting active tasks: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>/fuzzing/start', methods=['POST'])
@login_required
def api_start_fuzzing(scan_id):
    """Start fuzzing for a scan"""
    try:
        data = request.get_json() or {}
        fuzzing_config = data.get('config', {})
        
        result = scan_service.start_fuzzing_async(scan_id, fuzzing_config)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting fuzzing: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/scan/<scan_id>/status')
@login_required
def scan_status(scan_id):
    """Show scan status page with real-time updates"""
    try:
        scan = scan_service.get_scan_status(scan_id)
        if not scan:
            flash('Scan not found')
            return redirect(url_for('dashboard'))
        
        # Check if user owns this scan
        if scan.get('user_id') != current_user.id:
            flash('Access denied')
            return redirect(url_for('dashboard'))
        
        return render_template('scan_status.html', scan=scan, scan_id=scan_id)
    except Exception as e:
        logger.error(f"Error loading scan status: {e}")
        flash('Error loading scan status')
        return redirect(url_for('dashboard'))


@app.route('/debug/session')
def debug_session():
    """Debug endpoint to check session state"""
    if not app.debug and os.getenv('FLASK_ENV') != 'development':
        return "Debug endpoint disabled", 404
    
    session_info = {
        'session_keys': list(session.keys()),
        'has_github_token': 'github_token' in session,
        'current_user_authenticated': current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else False,
        'current_user_id': getattr(current_user, 'id', None),
        'session_permanent': session.permanent
    }
    
    return jsonify(session_info)


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
        code_snippet = request.form.get('code_snippet', '').strip()
        analysis_tool = request.form.get('analysis_tool', 'cppcheck')
        
        # New PR scanning parameters
        scan_type = request.form.get('scan_type', 'full')  # 'full' or 'pr'
        pr_number = request.form.get('pr_number')

        logger.info(f"[SCAN] New authenticated scan initiated by user {current_user.username} (ID: {current_user.id})")
        logger.info(f"[SCAN] Source types - repo_url: {bool(repo_url)}, zip_file: {bool(zip_file and zip_file.filename)}, code_snippet: {bool(code_snippet)}")
        logger.info(f"[SCAN] Analysis tool: {analysis_tool}")

        try:
            # Validate that only one source type is provided
            has_code_snippet = code_snippet and str(code_snippet).strip()
            source_count = sum(bool(x) for x in [repo_url, zip_file and zip_file.filename, has_code_snippet])
            if source_count != 1:
                logger.warning(f"[SCAN] Validation failed: Exactly one source type must be provided (found {source_count})")
                flash('Please provide exactly one source: GitHub URL, ZIP file, or code snippet.', 'error')
                return render_template('unified_scan.html')
            
            # Validate analysis tool
            if analysis_tool not in ['cppcheck', 'codeql']:
                logger.warning(f"[SCAN] Invalid analysis tool: {analysis_tool}")
                flash('Invalid analysis tool. Must be "cppcheck" or "codeql"', 'error')
                return render_template('unified_scan.html')
            
            # Use the new scan service (same as no-login but with user_id)
            if repo_url:
                if not is_valid_github_url(repo_url):
                    logger.warning(f"[SCAN] Invalid GitHub URL format: {repo_url}")
                    flash('Invalid GitHub URL format. Please use: https://github.com/username/repository', 'error')
                    return render_template('unified_scan.html')
                
                logger.info(f"[SCAN] Processing GitHub repository: {repo_url}")
                result = scan_service.create_scan(
                    source_type='repository',
                    repo_url=repo_url,
                    analysis_tool=analysis_tool,
                    user_id=current_user.id  # Associate with logged-in user
                )
                
            elif zip_file:
                # Validate ZIP file
                is_valid, error_msg = validate_zip_file(zip_file)
                if not is_valid:
                    logger.warning(f"[SCAN] ZIP validation failed: {error_msg}")
                    flash(f'ZIP file error: {error_msg}', 'error')
                    return render_template('unified_scan.html')
                
                logger.info(f"[SCAN] Processing ZIP file: {zip_file.filename}")
                result = scan_service.create_scan(
                    source_type='file_upload',
                    file_upload=zip_file,
                    analysis_tool=analysis_tool,
                    user_id=current_user.id  # Associate with logged-in user
                )
                
            else:  # code_snippet
                # Validate code snippet
                is_valid, error_msg = validate_code_snippet(code_snippet)
                if not is_valid:
                    logger.warning(f"[SCAN] Code snippet validation failed: {error_msg}")
                    flash(f'Code snippet error: {error_msg}', 'error')
                    return render_template('unified_scan.html')
                
                logger.info(f"[SCAN] Processing code snippet (length: {len(code_snippet)} chars)")
                result = scan_service.create_scan(
                    source_type='snippet',
                    code_snippet=code_snippet,
                    analysis_tool=analysis_tool,
                    user_id=current_user.id  # Associate with logged-in user
                )
            
            scan_id = result['scan_id']
            logger.info(f"[SCAN] ✅ Authenticated scan created successfully: {scan_id} for user {current_user.username}")
            logger.info(f"[SCAN] 💾 Scan saved to NEW database system with user association")
            
            # Redirect to detailed findings page
            return redirect(url_for('detailed_findings', scan_id=scan_id))
                
        except Exception as e:
            logger.error(f"[SCAN] Error creating authenticated scan: {e}", exc_info=True)
            flash(f'An error occurred: {str(e)}')
            return render_template('unified_scan.html')

    return render_template('unified_scan.html')


# Advanced scan functionality is now integrated into the main /scan route


@app.route('/scan-progress/<scan_id>')
def scan_progress(scan_id):
    """Show scan progress page - accessible without login"""
    try:
        # Use the global scan_service that was initialized with the correct database configuration
        global scan_service
        logger.info(f"[SCAN_PROGRESS] Request for scan: {scan_id}")
        
        # Use the database service to get scan results
        results = scan_service.get_scan_results(scan_id)
        
        if 'error' in results:
            logger.warning(f"[SCAN_PROGRESS] Scan not found: {scan_id}")
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        scan = results['scan']
        logger.info(f"[SCAN_PROGRESS] Scan {scan_id} found, status: {scan.get('status', 'unknown')}")
        
        return render_template('scan_progress.html', 
                             scan_id=scan_id, 
                             analysis_tool=scan.get('analysis_tool', 'cppcheck'),
                             source_type=scan.get('source_type', 'Repository'),
                             repo_url=scan.get('repo_url', ''))
    except Exception as e:
        logger.error(f"Error loading scan progress for {scan_id}: {e}")
        flash('Error loading scan details.', 'error')
        return redirect(url_for('no_login_scan'))


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


@app.route('/api/debug-scan/<scan_id>')
def debug_scan_retrieval(scan_id):
    """Debug endpoint to test scan retrieval"""
    try:
        logger.info(f"[DEBUG] Testing scan retrieval for: {scan_id}")
        
        # Test the same approach as my working test script
        DATABASE_URL = os.getenv('DATABASE_URL')
        logger.info(f"[DEBUG] DATABASE_URL: {DATABASE_URL[:50] if DATABASE_URL else 'None'}...")
        
        if DATABASE_URL:
            from src.models.scan_v2 import DatabaseManager
            from src.repositories.scan_repository import ScanRepository
            from src.services.scan_service import ScanService
            
            db_manager = DatabaseManager(DATABASE_URL)
            logger.info(f"[DEBUG] DatabaseManager created")
            
            # Test health check
            health = db_manager.health_check()
            logger.info(f"[DEBUG] Database health check: {health}")
            
            scan_repository = ScanRepository(db_manager, use_database=True)
            service = ScanService(scan_repository)
            logger.info(f"[DEBUG] Service created")
            
            # Test repository method
            repo_result = scan_repository.get_scan(scan_id)
            logger.info(f"[DEBUG] Repository result: {repo_result is not None}")
            
            # Test service method
            service_result = service.get_scan_results(scan_id)
            logger.info(f"[DEBUG] Service result: {'error' not in service_result}")
            
            return jsonify({
                'scan_id': scan_id,
                'database_url_configured': bool(DATABASE_URL),
                'health_check': health,
                'repository_found': repo_result is not None,
                'service_found': 'error' not in service_result,
                'repository_result': repo_result,
                'service_result': service_result if 'error' not in service_result else service_result
            })
        else:
            return jsonify({'error': 'No DATABASE_URL configured'}), 500
            
    except Exception as e:
        logger.error(f"[DEBUG] Error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

def get_fuzzing_status(scan_id):
    """Get fuzzing status and results for integration with detailed findings"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    # Check if fuzzing results exist
    executor = FuzzExecutor(scan_dir)
    fuzz_results = executor.get_campaign_results()
    
    if not fuzz_results:
        return {
            'available': False,
            'status': 'not_run',
            'message': 'Fuzzing has not been run for this scan'
        }
    
    # Calculate fuzzing summary
    total_crashes = sum(r.get('crashes_found', 0) for r in fuzz_results.get('results', []))
    total_targets = fuzz_results.get('total_targets', 0)
    
    # Determine vulnerability confirmation status
    confirmed_vulns = []
    if total_crashes > 0:
        for result in fuzz_results.get('results', []):
            if result.get('crashes_found', 0) > 0:
                vuln_type = result.get('target', '').replace('fuzz_test_', '').replace('_', ' ').title()
                confirmed_vulns.append({
                    'type': vuln_type,
                    'crashes': result.get('crashes_found', 0),
                    'target': result.get('target', '')
                })
    
    return {
        'available': True,
        'status': 'completed',
        'total_targets': total_targets,
        'total_crashes': total_crashes,
        'confirmed_vulnerabilities': confirmed_vulns,
        'runtime': fuzz_results.get('total_time', 0),
        'timestamp': fuzz_results.get('timestamp', ''),
        'message': f'Fuzzing confirmed {len(confirmed_vulns)} vulnerability types with {total_crashes} crashes'
    }


def determine_vulnerability_type(rule_id, message, severity):
    """
    Determine vulnerability type, CWE, risk score, and recommendations based on rule_id and message
    """
    rule_id = rule_id.lower()
    message = message.lower() if message else ''
    
    # Analyze context to determine actual severity
    # Some "error" level findings should be downgraded based on context
    actual_severity = severity
    
    # Buffer overflow vulnerabilities
    if ('buffer' in rule_id or 'overflow' in rule_id or 
        'strcpy' in message or 'sprintf' in message or 'strcat' in message or 'gets' in message):
        
        # Adjust severity and risk score based on context
        if ('printf(' in message and ('buffer overflows' in message or 'gets' in message)):
            # This is just a printf statement, not an actual buffer overflow
            actual_severity = 'low'
            risk_score = 2.5
        elif ('test_' in message and '()' in message):
            # Function calls to test functions - medium risk
            actual_severity = 'medium'
            risk_score = 5.2
        elif ('function' in message and '()' in message):
            # General function calls - medium risk unless clearly dangerous
            actual_severity = 'medium'
            risk_score = 6.2
        elif ('void ' in message and '()' in message):
            # Function declarations - medium risk
            actual_severity = 'medium'
            risk_score = 5.8
        elif 'strcpy(' in message and ('user_input' in message or 'buffer' in message):
            # Direct dangerous strcpy calls - keep high
            risk_score = 8.8 if actual_severity == 'high' else 6.5
        elif 'sprintf(' in message and ('user_input' in message or '%' in message):
            # Direct dangerous sprintf calls - keep high  
            risk_score = 8.5 if actual_severity == 'high' else 6.2
        else:
            # Other buffer overflow patterns - high risk by default
            actual_severity = 'high'
            risk_score = 8.0
            
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-787',
            'cwe_description': 'Buffer Overflow',
            'risk_score': risk_score,
            'description': 'Buffer overflow vulnerability detected',
            'impact': 'This vulnerability could allow an attacker to execute arbitrary code, cause denial of service, or corrupt memory.',
            'recommendation': 'Use safe string functions (strncpy, snprintf) or implement proper bounds checking. Consider using memory-safe languages or libraries.'
        }
    
    # Null pointer dereference
    elif ('null' in rule_id or 'pointer' in rule_id or 
          'null pointer' in message or 'nullptr' in message):
        
        # Analyze context for null pointer issues
        if ('= nullptr' in message or '= null' in message):
            # Variable declaration - lower risk
            actual_severity = 'medium'
            risk_score = 4.2
        elif 'dereference' in message:
            # Actual dereference - higher risk
            risk_score = 6.8 if actual_severity == 'high' else 4.5
        else:
            # General null pointer issue
            actual_severity = 'medium'
            risk_score = 5.1
            
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-476',
            'cwe_description': 'NULL Pointer Dereference',
            'risk_score': risk_score,
            'description': 'Null pointer dereference vulnerability',
            'impact': 'This issue may lead to application crashes, denial of service, or unexpected behavior.',
            'recommendation': 'Add null pointer checks before dereferencing. Initialize pointers properly and validate input parameters.'
        }
    
    # Memory leak
    elif ('leak' in rule_id or 'memory' in rule_id or 
          'malloc' in message or 'new' in message or 'leak' in message):
        actual_severity = 'medium'
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-401',
            'cwe_description': 'Memory Leak',
            'risk_score': 4.8 if actual_severity == 'high' else 3.2,
            'description': 'Memory leak detected',
            'impact': 'This issue can lead to resource exhaustion, performance degradation, and potential denial of service.',
            'recommendation': 'Ensure all allocated memory is properly freed. Use RAII patterns or smart pointers in C++.'
        }
    
    # Use after free
    elif ('use' in rule_id and 'free' in rule_id or 
          'use after free' in message or 'freed' in message):
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-416',
            'cwe_description': 'Use After Free',
            'risk_score': 8.2 if actual_severity == 'high' else 6.1,
            'description': 'Use-after-free vulnerability detected',
            'impact': 'This vulnerability could allow an attacker to execute arbitrary code or cause memory corruption.',
            'recommendation': 'Set pointers to NULL after freeing. Use memory-safe programming practices and consider static analysis tools.'
        }
    
    # Format string vulnerability
    elif ('format' in rule_id or 'string' in rule_id or 
          'printf' in message or '%n' in message or 'format string' in message):
        
        # Check if it's actually a format string vuln or just a printf call
        if '%n' in message:
            # Actual format string attack
            risk_score = 7.8
        elif 'printf(' in message and not any(x in message for x in ['%s', '%d', '%n']):
            # Simple printf call - lower risk
            actual_severity = 'low'
            risk_score = 2.8
        else:
            risk_score = 6.5
            
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-134',
            'cwe_description': 'Format String Vulnerability',
            'risk_score': risk_score,
            'description': 'Format string vulnerability detected',
            'impact': 'This vulnerability could allow an attacker to read/write arbitrary memory locations or execute code.',
            'recommendation': 'Use format strings with proper format specifiers. Never use user input directly as format strings.'
        }
    
    # Integer overflow
    elif ('integer' in rule_id or 'overflow' in rule_id or 
          'int overflow' in message or 'integer overflow' in message):
        actual_severity = 'medium'
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-190',
            'cwe_description': 'Integer Overflow',
            'risk_score': 5.5 if actual_severity == 'high' else 3.8,
            'description': 'Integer overflow vulnerability detected',
            'impact': 'This issue can lead to unexpected behavior, buffer overflows, or security bypasses.',
            'recommendation': 'Validate input ranges and use safe integer arithmetic. Consider using libraries that detect overflow.'
        }
    
    # Uninitialized variable
    elif ('uninitialized' in rule_id or 'variable' in rule_id or 
          'uninitialized' in message):
        actual_severity = 'medium'
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-457',
            'cwe_description': 'Uninitialized Variable',
            'risk_score': 4.1 if actual_severity == 'high' else 2.6,
            'description': 'Uninitialized variable detected',
            'impact': 'This issue can lead to unpredictable behavior, information disclosure, or security vulnerabilities.',
            'recommendation': 'Initialize all variables before use. Use compiler warnings to detect uninitialized variables.'
        }
    
    # Unused variable (code quality)
    elif ('unused' in rule_id or 'variable' in rule_id or 
          'unused variable' in message):
        actual_severity = 'low'
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-563',
            'cwe_description': 'Unused Variable',
            'risk_score': 1.8,
            'description': 'Unused variable detected',
            'impact': 'This is a code quality issue that should be addressed to improve maintainability and reduce confusion.',
            'recommendation': 'Remove unused variables or add appropriate comments if they are intentionally unused for future use.'
        }
    
    # Resource leak (file handles, etc.)
    elif ('resource' in rule_id or 'leak' in rule_id or 
          'file' in message or 'handle' in message):
        actual_severity = 'medium'
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-404',
            'cwe_description': 'Resource Leak',
            'risk_score': 4.7 if actual_severity == 'high' else 3.1,
            'description': 'Resource leak detected',
            'impact': 'This issue can lead to resource exhaustion and potential denial of service.',
            'recommendation': 'Ensure all opened resources (files, handles) are properly closed. Use RAII patterns.'
        }
    
    # Default case for unknown vulnerabilities
    else:
        # Analyze message content to determine severity
        if any(dangerous in message for dangerous in ['overflow', 'crash', 'exploit', 'attack']):
            actual_severity = 'high'
            risk_score = 7.2
        elif any(medium_risk in message for medium_risk in ['leak', 'null', 'uninitialized']):
            actual_severity = 'medium'
            risk_score = 4.5
        else:
            actual_severity = 'low'
            risk_score = 2.9
            
        return {
            'actual_severity': actual_severity,
            'cwe': 'CWE-693',
            'cwe_description': 'Protection Mechanism Failure',
            'risk_score': risk_score,
            'description': f'Security issue detected: {rule_id}',
            'impact': 'This issue may lead to security vulnerabilities or unexpected behavior.',
            'recommendation': 'Review the code and apply appropriate security measures based on the specific vulnerability type.'
        }


@app.route('/detailed-findings/<scan_id>')
def detailed_findings(scan_id):
    """Show detailed vulnerability findings - accessible without login"""
    logger.info(f"[DETAILED_FINDINGS] Request for scan: {scan_id}")
    
    try:
        # Use ONLY the new scan_service (no more legacy fallback)
        logger.info(f"[DETAILED_FINDINGS] Using new scan_service for scan lookup")
        
        # Get scan results from the new database system
        results = scan_service.get_scan_results(scan_id)
        
        if 'error' in results:
            logger.warning(f"[DETAILED_FINDINGS] Scan not found: {scan_id}")
            logger.warning(f"[DETAILED_FINDINGS] Error details: {results}")
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        scan = results['scan']
        findings = results['findings']
        
        logger.info(f"[DETAILED_FINDINGS] Scan {scan_id} found in NEW database system, status: {scan.get('status', 'unknown')}")
        
        # Convert findings to the format expected by the template
        vulnerabilities = []
        for i, finding in enumerate(findings):
            logger.debug(f"[DETAILED_FINDINGS] Processing finding {i}: {finding}")
            
            # Map severity from cppcheck format to template format
            severity_mapping = {
                'error': 'high',
                'warning': 'medium', 
                'style': 'low',
                'performance': 'medium',
                'portability': 'medium',
                'information': 'low',
                'info': 'low',
                'unknown': 'low'
            }
            
            # Get severity from finding, default to 'low' if not found
            raw_severity = finding.get('severity', 'info').lower()
            logger.debug(f"[DETAILED_FINDINGS] Raw severity for finding {i}: '{raw_severity}'")
            severity = severity_mapping.get(raw_severity, 'low')
            logger.debug(f"[DETAILED_FINDINGS] Mapped severity for finding {i}: '{severity}'")
            
            # Get message and description - prioritize description if available
            message = finding.get('message', '')
            description = finding.get('description')
            rule_id = finding.get('rule_id', '').lower()
            
            # Use actual Cppcheck CWE code if available, otherwise determine from rule
            actual_cwe = finding.get('cwe', '')
            if actual_cwe:
                # Use the real Cppcheck CWE code
                cwe_code = f"CWE-{actual_cwe}"
                # Get CWE description from a mapping
                cwe_descriptions = {
                    '788': 'Access of Memory Location After End of Buffer',
                    '787': 'Out-of-bounds Write', 
                    '401': 'Missing Release of Memory after Effective Lifetime',
                    '415': 'Double Free',
                    '775': 'Missing Release of File Descriptor or Handle after Effective Lifetime',
                    '476': 'NULL Pointer Dereference',
                    '571': 'Expression is Always True',
                    '570': 'Expression is Always False',
                    '398': 'Indicator of Poor Code Quality',
                    '190': 'Integer Overflow or Wraparound',
                    '457': 'Use of Uninitialized Variable',
                    '477': 'Use of Obsolete Function'
                }
                cwe_description = cwe_descriptions.get(actual_cwe, 'Security Vulnerability')
                
                # Use actual Cppcheck priority score if available, otherwise calculate
                risk_score = finding.get('priority_score')
                if risk_score is None:
                    # Fallback calculation based on CWE severity
                    if actual_cwe in ['788', '787', '415', '476']:  # Critical vulnerabilities
                        risk_score = 8.5 if severity == 'high' else 7.0
                    elif actual_cwe in ['401', '775', '190', '457']:  # High-risk vulnerabilities  
                        risk_score = 7.0 if severity == 'high' else 5.5
                    else:  # Medium/low risk
                        risk_score = 5.0 if severity == 'high' else 3.5
                
            else:
                # Fallback to determine_vulnerability_type for findings without CWE
                vuln_type_info = determine_vulnerability_type(rule_id, message, severity)
                cwe_code = vuln_type_info['cwe']
                cwe_description = vuln_type_info['cwe_description']
                risk_score = vuln_type_info['risk_score']
                severity = vuln_type_info.get('actual_severity', severity)
            
            # If no description, use message; if no message either, create a meaningful description
            if not description:
                if message:
                    description = message
                else:
                    description = f"Static analysis finding: {rule_id}"
            
            # Clean up the description to remove technical details for display
            if description and ' - CVE-' in description:
                description = description.split(' - CVE-')[0]
            
            # Ensure we have a meaningful description
            if not description or description.lower() in ['none', 'null', '']:
                description = f"Static analysis finding in {finding.get('file_path', 'unknown file')}"
            
            vuln = {
                'id': str(i),  # Template needs string ID for toggles
                'rule': finding.get('rule_id', 'Unknown'),
                'severity': severity,
                'confidence': finding.get('confidence', 'medium'),
                'file': finding.get('file_path', finding.get('file', '')),
                'line': finding.get('line_number', finding.get('line', 0)),
                'column': finding.get('column_number', finding.get('column', 0)),
                'function': finding.get('function_name', finding.get('function', '')),
                'message': message,
                'description': description,
                'cwe': cwe_code,
                'cwe_description': cwe_description,
                'cvss_score': risk_score,
                'exploitability_score': finding.get('exploitability_score'),
                'tool': scan.get('analysis_tool', 'cppcheck').title(),  # Template expects tool name
                'impact': f'This {severity}-severity vulnerability may impact system security and stability.',
                'recommendation': f'Review and address this {rule_id} issue in the code.'
            }
            
            # Add code context if available
            if vuln.get('file') and vuln.get('line'):
                vuln['code_context'] = extract_code_context(
                    scan_id, 
                    vuln['file'], 
                    vuln['line']
                )
            
            vulnerabilities.append(vuln)
            logger.debug(f"[DETAILED_FINDINGS] Mapped vulnerability {i}: severity={severity}, description='{description[:50]}...'")
        
        logger.info(f"[DETAILED_FINDINGS] Mapped {len(vulnerabilities)} vulnerabilities")
        
        # Check if fuzzing results are available for this scan
        fuzzing_status = get_fuzzing_status(scan_id)
        
        # Get patches (for now, empty - will be implemented later)
        patches = []
        
        logger.info(f"[DETAILED_FINDINGS] Scan {scan_id} has {len(vulnerabilities)} vulnerabilities and {len(patches)} patches")
        
        # If scan is still running, show progress
        status = scan.get('status', 'unknown')
        if status in ['queued', 'processing']:
            logger.info(f"[DETAILED_FINDINGS] Scan {scan_id} still in progress, showing progress view")
            return render_template('detailed_findings.html',
                                 scan_id=scan_id,
                                 vulnerabilities=[],
                                 patches=[],
                                 status=status,
                                 analysis_tool=scan.get('analysis_tool', 'cppcheck'))
        
        # If scan failed, show error
        if status == 'failed':
            logger.warning(f"[DETAILED_FINDINGS] Scan {scan_id} failed")
            return render_template('detailed_findings.html',
                                 scan_id=scan_id,
                                 vulnerabilities=[],
                                 patches=[],
                                 status='failed',
                                 error=scan.get('error_message', 'Scan failed. Please try again.'))
        
        logger.info(f"[DETAILED_FINDINGS] Rendering results for scan {scan_id}")
        logger.info(f"[DETAILED_FINDINGS] About to render template with status: {status}")
        try:
            return render_template('detailed_findings.html', 
                                 scan_id=scan_id,
                                 vulnerabilities=vulnerabilities,
                                 patches=patches,
                                 status=status,
                                 analysis_tool=scan.get('analysis_tool', 'cppcheck'),
                                 repo_url=scan.get('repo_url', ''),
                                 source_type=scan.get('source_type', ''),
                                 fuzzing_status=fuzzing_status)
        except Exception as template_error:
            logger.error(f"[DETAILED_FINDINGS] Template error: {template_error}")
            raise
                             
    except Exception as e:
        logger.error(f"[DETAILED_FINDINGS] Error retrieving scan {scan_id}: {e}", exc_info=True)
        flash('Error retrieving scan results.', 'error')
        return redirect(url_for('no_login_scan'))


@app.route('/debug-test')
def debug_test():
    """Simple debug test route"""
    return "<h1>Debug Test Route Working!</h1>"


def classify_vulnerability_for_patching(rule_id, message, cwe):
    """Classify vulnerability for patch generation stages"""
    rule_id = rule_id.lower() if rule_id else ''
    message = message.lower() if message else ''
    cwe = str(cwe) if cwe else ''
    
    # Stage 1: Rule-based repairs (deterministic)
    
    # Null pointer dereference (CWE-476)
    if (cwe == '476' or 
        any(keyword in rule_id or keyword in message for keyword in [
            'nullpointer', 'null pointer', 'dereference', 'null_ptr'
        ])):
        return {
            'stage': 1,
            'category': 'null_pointer_dereference',
            'enabled': True,
            'reason': 'Null pointer dereference - deterministic repair available'
        }
    
    # Memory management issues (CWE-401, CWE-415, CWE-416)
    if (cwe in ['401', '415', '416'] or 
        any(keyword in rule_id or keyword in message for keyword in [
            'memleak', 'memory leak', 'doublefree', 'double free', 'memory pointed', 'freed twice'
        ])):
        return {
            'stage': 1,
            'category': 'memory_deallocation',
            'enabled': True,
            'reason': 'Memory management issue - MemFix repair available'
        }
    
    # Integer overflow (CWE-190, CWE-191)
    if (cwe in ['190', '191'] or 
        any(keyword in rule_id or keyword in message for keyword in [
            'overflow', 'integer overflow', 'signed integer overflow'
        ])):
        return {
            'stage': 1,
            'category': 'integer_overflow',
            'enabled': True,
            'reason': 'Integer overflow - IntRepair available'
        }
    
    # Uninitialized variables (CWE-457, CWE-398, CWE-908)
    if (cwe in ['457', '398', '908'] or 
        any(keyword in rule_id or keyword in message for keyword in [
            'uninitialized', 'uninit', 'scope of the variable', 'variable can be reduced'
        ])):
        return {
            'stage': 1,
            'category': 'uninitialized_variable',
            'enabled': True,
            'reason': 'Uninitialized variable - deterministic repair available'
        }
    
    # Dead code (CWE-561) - disabled by default
    if (cwe == '561' or 
        any(keyword in rule_id or keyword in message for keyword in [
            'dead', 'unused', 'unreachable'
        ])):
        return {
            'stage': 1,
            'category': 'dead_code',
            'enabled': False,  # Disabled due to low success rate
            'reason': 'Dead code - disabled due to low success rate (20-40%)'
        }
    
    # Stage 2: AI-assisted repairs (complex cases)
    
    # Buffer overflow (CWE-121, CWE-122, CWE-788)
    if (cwe in ['121', '122', '788'] or 
        any(keyword in rule_id or keyword in message for keyword in [
            'buffer', 'array', 'bounds', 'buffer overflow'
        ])):
        return {
            'stage': 2,
            'category': 'buffer_overflow',
            'enabled': True,
            'reason': 'Buffer overflow requires contextual analysis'
        }
    
    # Format string (CWE-134)
    if (cwe == '134' or 
        any(keyword in rule_id or keyword in message for keyword in [
            'format', 'printf', 'sprintf'
        ])):
        return {
            'stage': 2,
            'category': 'format_string',
            'enabled': True,
            'reason': 'Format string vulnerability requires calling convention understanding'
        }
    
    # Default to Stage 2 for unknown vulnerabilities
    return {
        'stage': 2,
        'category': 'other',
        'enabled': True,
        'reason': 'Complex vulnerability requiring AI analysis'
    }

def get_existing_patches(scan_id):
    """Get existing patches for a scan"""
    try:
        # Try to get patches directly from database using the new schema
        from src.models.scan_v2 import RepairPatch, DatabaseManager
        import os
        
        DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://autovulrepair:autovulrepair_secure_password_2024@localhost:5432/autovulrepair')
        db_manager = DatabaseManager(DATABASE_URL)
        session_db = db_manager.get_session()
        
        repair_patches = session_db.query(RepairPatch).filter_by(scan_id=scan_id).all()
        
        if repair_patches:
            # Convert RepairPatch objects to legacy format
            patches = []
            for repair_patch in repair_patches:
                patch_dict = {
                    'patch_id': str(repair_patch.id),
                    'finding_id': str(repair_patch.finding_id) if repair_patch.finding_id else None,
                    'file': repair_patch.file_path,
                    'original': repair_patch.original_code,
                    'repaired': repair_patch.patched_code,
                    'diff': repair_patch.patch_diff,
                    'category': repair_patch.repair_method,
                    'confidence': float(repair_patch.confidence_score) if repair_patch.confidence_score else None,
                    'stage': 1,  # Assume Stage 1 for now
                    'description': f"Automated repair using {repair_patch.repair_method}",
                    'created_at': repair_patch.created_at.isoformat() if repair_patch.created_at else None
                }
                patches.append(patch_dict)
            
            session_db.close()
            logger.info(f"[GET_PATCHES] Loaded {len(patches)} patches from database for scan {scan_id}")
            return patches
        
        session_db.close()
        logger.info(f"[GET_PATCHES] No patches found in database for scan {scan_id}")
        
    except Exception as db_error:
        logger.warning(f"[GET_PATCHES] Database error for scan {scan_id}: {db_error}")
    
    # Fallback: try to load from file system
    try:
        import json
        import os
        scan_dir = os.path.join('scans', scan_id)
        patches_file = os.path.join(scan_dir, 'patches.json')
        
        if os.path.exists(patches_file):
            with open(patches_file, 'r') as f:
                patches_data = json.load(f)
                # Convert from dict format to list format if needed
                if isinstance(patches_data, dict):
                    patches = list(patches_data.values())
                else:
                    patches = patches_data
                logger.info(f"[GET_PATCHES] Loaded {len(patches)} patches from file system for scan {scan_id}")
                return patches
    except Exception as file_error:
        logger.warning(f"[GET_PATCHES] File system error for scan {scan_id}: {file_error}")
    
    logger.info(f"[GET_PATCHES] No patches found for scan {scan_id}")
    return []



@app.route('/patch-review/<scan_id>')
def patch_review(scan_id):
    """Show patch generation interface for vulnerabilities"""
    logger.info(f"[PATCH_REVIEW] Request for scan: {scan_id}")
    
    try:
        # Try to get scan results from the database
        try:
            results = scan_service.get_scan_results(scan_id)
            if 'error' not in results:
                scan = results['scan']
                findings = results['findings']
                logger.info(f"[PATCH_REVIEW] Loaded scan from database with {len(findings)} findings")
            else:
                raise Exception("Scan not found in database")
        except Exception as db_error:
            logger.warning(f"[PATCH_REVIEW] Database error for scan {scan_id}: {db_error}")
            # Try to load from file system as fallback
            import json
            import os
            scan_dir = os.path.join('scans', scan_id)
            findings_file = os.path.join(scan_dir, 'static_findings.json')
            
            if os.path.exists(findings_file):
                logger.info(f"[PATCH_REVIEW] Loading scan data from file system: {findings_file}")
                with open(findings_file, 'r') as f:
                    file_data = json.load(f)
                
                # Create mock scan data
                scan = {
                    'id': scan_id,
                    'status': 'completed',
                    'analysis_tool': 'cppcheck',
                    'repo_url': 'https://github.com/malikadan212/Test-Repo.git'
                }
                findings = file_data.get('findings', [])
                
                logger.info(f"[PATCH_REVIEW] Loaded {len(findings)} findings from file system")
            else:
                logger.warning(f"[PATCH_REVIEW] No file system data found for scan: {scan_id}")
                flash('Scan not found.', 'error')
                return redirect(url_for('no_login_scan'))
        
        logger.info(f"[PATCH_REVIEW] Processing {len(findings)} findings for patch generation")
        
        # Convert findings to vulnerability format and classify for patching
        vulnerabilities = []
        seen_vulnerabilities = set()  # Track duplicates by (file, line, message)
        
        for i, finding in enumerate(findings):
            # Map severity
            severity_mapping = {
                'error': 'high',
                'warning': 'medium', 
                'style': 'low',
                'performance': 'medium',
                'portability': 'medium',
                'information': 'low',
                'info': 'low',
                'unknown': 'low'
            }
            
            raw_severity = finding.get('severity', 'info').lower()
            severity = severity_mapping.get(raw_severity, 'low')
            
            # Get CWE and vulnerability type
            actual_cwe = finding.get('cwe', '')
            rule_id = finding.get('rule_id', '').lower()
            message = finding.get('message', '')
            
            # Get file and line for deduplication
            file_path = finding.get('file', finding.get('file_path', ''))
            line_num = finding.get('line', finding.get('line_number', 0))
            
            # Create deduplication key
            dedup_key = (file_path, line_num, message.strip())
            if dedup_key in seen_vulnerabilities:
                logger.debug(f"Skipping duplicate vulnerability: {file_path}:{line_num} - {message[:50]}")
                continue
            seen_vulnerabilities.add(dedup_key)
            
            # Get the finding ID - database uses 'id', file system uses 'finding_id'
            finding_id = finding.get('finding_id') or str(finding.get('id', f"vuln_{i}"))
            
            # Classify vulnerability for patch generation
            classification = classify_vulnerability_for_patching(rule_id, message, actual_cwe)
            
            vuln = {
                'finding_id': finding_id,  # Use the finding_id we extracted
                'file_name': finding.get('file_name', file_path.split('/')[-1] if file_path else 'unknown'),
                'file': file_path,
                'line': line_num,
                'column': finding.get('column', finding.get('column_number', 0)),
                'function': finding.get('function', finding.get('function_name', '')),
                'message': message,
                'cwe': actual_cwe or '476',  # Default to null pointer if no CWE
                'severity': severity,
                'classification': classification,
                'code_context': extract_code_context(scan_id, file_path, line_num, context_lines=2)
            }
            
            vulnerabilities.append(vuln)
        
        # Get existing patches (if any)
        patches = get_existing_patches(scan_id)
        
        logger.info(f"[PATCH_REVIEW] Loaded {len(patches)} existing patches for scan {scan_id}")
        if patches:
            logger.info(f"[PATCH_REVIEW] Sample patch IDs: {[p.get('patch_id', 'NO_ID')[:8] for p in patches[:3]]}")
        
        # Calculate stage counts
        stage1_vulns = [v for v in vulnerabilities if v['classification']['stage'] == 1 and v['classification']['enabled']]
        stage2_vulns = [v for v in vulnerabilities if v['classification']['stage'] == 2]
        
        stage1_counts = {
            'null_pointer': len([v for v in stage1_vulns if 'null' in v['classification']['category']]),
            'memory_dealloc': len([v for v in stage1_vulns if 'memory' in v['classification']['category']]),
            'integer_overflow': len([v for v in stage1_vulns if 'integer' in v['classification']['category']]),
            'uninitialized_var': len([v for v in stage1_vulns if 'uninitialized' in v['classification']['category']]),
            'dead_code': len([v for v in stage1_vulns if 'dead_code' in v['classification']['category']])
        }
        
        logger.info(f"[PATCH_REVIEW] Rendering patch review with {len(stage1_vulns)} Stage 1 and {len(stage2_vulns)} Stage 2 vulnerabilities")
        
        return render_template('patch_review.html',
                             scan_id=scan_id,
                             vulnerabilities=vulnerabilities,
                             patches=patches,
                             total_stage1=len(stage1_vulns),
                             total_stage2=len(stage2_vulns),
                             stage1_counts=stage1_counts,
                             stage2_vulns=stage2_vulns)
                             
    except Exception as e:
        logger.error(f"[PATCH_REVIEW] Error processing scan {scan_id}: {e}", exc_info=True)
        flash('Error loading patch review interface.', 'error')
        return redirect(url_for('detailed_findings', scan_id=scan_id))


# Patch review route temporarily disabled due to technical issues
# Users can access vulnerability details through the detailed findings page

# Temporary redirect for patch_dashboard to repair_dashboard
@app.route('/patch/<scan_id>')
def patch_dashboard(scan_id):
    """Temporary redirect to repair_dashboard"""
    return redirect(url_for('repair_dashboard', scan_id=scan_id))


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
    """API endpoint for checking scan status - now using database service"""
    logger.debug(f"[API] Status check requested for scan: {scan_id}")
    
    try:
        # Try new service first
        scan_data = scan_service.get_scan_status(scan_id)
        if scan_data:
            # Get additional data for response
            results = scan_service.get_scan_results(scan_id)
            vuln_count = len(results.get('findings', []))
            
            # Calculate elapsed time
            elapsed_time = None
            if scan_data.get('created_at'):
                from datetime import datetime
                try:
                    if isinstance(scan_data['created_at'], str):
                        created_at = datetime.fromisoformat(scan_data['created_at'].replace('Z', '+00:00'))
                    else:
                        created_at = scan_data['created_at']
                    elapsed_time = (datetime.now() - created_at.replace(tzinfo=None)).total_seconds()
                except Exception:
                    pass
            
            logger.debug(f"[API] Scan {scan_id} status: {scan_data['status']}, vulnerabilities: {vuln_count}")
            return jsonify({
                'status': scan_data['status'],
                'analysis_tool': scan_data.get('analysis_tool', 'cppcheck'),
                'vulnerabilities_count': vuln_count,
                'patches_count': 0,  # TODO: Implement patch counting in service
                'elapsed_time': elapsed_time,
                'error': scan_data.get('error_message')
            })
        
        # Fallback to legacy system
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
                elapsed_time = (datetime.now() - scan.created_at).total_seconds()
            
            logger.debug(f"[API] Legacy scan {scan_id} status: {scan.status}, vulnerabilities: {vuln_count}")
            return jsonify({
                'status': scan.status,
                'analysis_tool': scan.analysis_tool,
                'vulnerabilities_count': vuln_count,
                'patches_count': patch_count,
                'elapsed_time': elapsed_time,
                'error': None
            })
        finally:
            session_db.close()
            
    except Exception as e:
        logger.error(f"[API] Error checking scan status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<scan_id>/results')
@login_required
def api_scan_results(scan_id):
    """Get scan results in JSON format for VS Code extension - now using database service"""
    logger.debug(f"[API] Results requested for scan: {scan_id}")
    
    try:
        # Verify user owns this scan
        current_user_id = session.get('user_id')
        if not current_user_id:
            return jsonify({'error': 'Authentication required'}), 401
        # Try new service first
        results = scan_service.get_scan_results(scan_id)
        if results and not results.get('error'):
            scan_data = results['scan']
            
            # Verify ownership
            if scan_data.get('user_id') != current_user_id:
                return jsonify({'error': 'Access denied'}), 403
            findings = results['findings']
            
            # Format vulnerabilities for VS Code extension
            formatted_vulns = []
            for finding in findings:
                formatted_vulns.append({
                    'id': finding.get('id', str(uuid.uuid4())),
                    'type': finding.get('rule_id', 'Unknown'),
                    'severity': finding.get('severity', 'Medium').title(),
                    'file': finding.get('file_path', ''),
                    'line': int(finding.get('line_number', 0)),
                    'column': int(finding.get('column_number', 0)),
                    'endLine': int(finding.get('line_number', 0)),
                    'endColumn': int(finding.get('column_number', 0) + 10),
                    'description': finding.get('message', ''),
                    'cwe': finding.get('cwe', ''),
                    'exploitability': float(finding.get('exploitability_score', 0.5) or 0.5),
                    'impact': finding.get('description', ''),
                    'recommendation': 'Review and fix this issue',
                    'patch': None  # TODO: Link patches to findings
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
                'status': scan_data['status'],
                'progress': 100 if scan_data['status'] == 'completed' else 50,
                'stage': 'Analysis Complete' if scan_data['status'] == 'completed' else 'In Progress',
                'vulnerabilities': formatted_vulns,
                'summary': summary
            })
        
        # Fallback to legacy system
        session_db = get_session()
        try:
            scan = session_db.query(Scan).filter_by(id=scan_id).first()
            if not scan:
                logger.warning(f"[API] Scan not found: {scan_id}")
                return jsonify({'error': 'Scan not found'}), 404
            
            # Verify ownership for legacy scans
            if scan.user_id != current_user_id:
                return jsonify({'error': 'Access denied'}), 403
            
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
            
            logger.debug(f"[API] Legacy returning {len(formatted_vulns)} vulnerabilities for scan {scan_id}")
            return jsonify({
                'scanId': scan_id,
                'status': scan.status,
                'progress': 100 if scan.status == 'completed' else 50,
                'stage': 'Analysis Complete' if scan.status == 'completed' else 'In Progress',
                'vulnerabilities': formatted_vulns,
                'summary': summary
            })
        finally:
            session_db.close()
            
    except Exception as e:
        logger.error(f"[API] Error getting scan results: {e}")
        return jsonify({'error': str(e)}), 500


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
    
    try:
        # Check if patch already exists for this vulnerability
        existing_patches = get_existing_patches(scan_id)
        for patch in existing_patches:
            if patch.get('finding_id') == vuln_id:
                logger.info(f"[API] Patch already exists for vulnerability {vuln_id}")
                return jsonify({
                    'success': True,
                    'patch': patch,
                    'message': 'Patch already exists'
                })
        
        # Try to get scan results from the database first
        try:
            results = scan_service.get_scan_results(scan_id)
            if 'error' not in results:
                scan = results['scan']
                findings = results['findings']
                logger.info(f"[API] Loaded {len(findings)} findings from database")
            else:
                raise Exception("Scan not found in database")
        except Exception as db_error:
            logger.warning(f"[API] Database error for scan {scan_id}: {db_error}")
            # Try to load from file system as fallback
            import json
            import os
            scan_dir = os.path.join('scans', scan_id)
            findings_file = os.path.join(scan_dir, 'static_findings.json')
            
            if os.path.exists(findings_file):
                logger.info(f"[API] Loading scan data from file system: {findings_file}")
                with open(findings_file, 'r') as f:
                    file_data = json.load(f)
                
                # Create mock scan data
                scan = {
                    'id': scan_id,
                    'status': 'completed',
                    'analysis_tool': 'cppcheck',
                    'repo_url': 'https://github.com/malikadan212/Test-Repo.git'
                }
                findings = file_data.get('findings', [])
                
                logger.info(f"[API] Loaded {len(findings)} findings from file system")
            else:
                logger.warning(f"[API] No file system data found for scan: {scan_id}")
                return jsonify({'error': 'Scan not found'}), 404
        
        # Find the specific vulnerability by database ID or finding_id
        vuln = None
        for finding in findings:
            # Try both 'id' (database) and 'finding_id' (file system) fields
            finding_id = str(finding.get('id', ''))
            finding_id_alt = str(finding.get('finding_id', ''))
            
            if finding_id == vuln_id or finding_id_alt == vuln_id:
                vuln = finding
                break
        
        if not vuln:
            logger.warning(f"[API] Vulnerability {vuln_id} not found in {len(findings)} findings")
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        # Get source files from database using scan service
        results = scan_service.get_scan_results(scan_id)
        if 'error' in results:
            return jsonify({'error': 'Scan not found'}), 404
        
        source_files = {}
        for source_file in results.get('source_files', []):
            file_path = source_file.get('file_path', '')
            
            # Get content from database
            try:
                from src.models.scan_v2 import ScanSource, DatabaseManager
                import os
                
                DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://autovulrepair:autovulrepair_secure_password_2024@localhost:5432/autovulrepair')
                db_manager = DatabaseManager(DATABASE_URL)
                session = db_manager.get_session()
                
                try:
                    source = session.query(ScanSource).filter(ScanSource.id == source_file.get('id')).first()
                    if source:
                        content = source.file_content
                        filename = os.path.basename(file_path)
                        # Map multiple path formats for compatibility
                        source_files[f'/tmp/source/{filename}'] = content
                        source_files[filename] = content
                        source_files[file_path] = content
                finally:
                    session.close()
                    
            except Exception as e:
                logger.warning(f"Could not read source file {file_path}: {e}")
        
        logger.info(f"Loaded {len(source_files)} source file mappings from database")
        
        # Initialize Stage 1 repair engine
        from src.repair.stage1 import Stage1RepairEngine
        
        repair_engine = Stage1RepairEngine(enable_dead_code=False)
        
        # Get source code - handle both database and file system field names
        file_path = vuln.get('file_path') or vuln.get('file', '')
        source_code = source_files.get(file_path)
        
        if not source_code:
            return jsonify({'error': f'Source code not found for {file_path}'}), 400
        
        # Convert finding to format expected by repair engine - handle both database and file system field names
        vuln_for_repair = {
            'finding_id': str(vuln.get('id') or vuln.get('finding_id', '')),
            'rule_id': vuln.get('rule_id', ''),
            'severity': vuln.get('severity', ''),
            'message': vuln.get('message', ''),
            'cwe': vuln.get('cwe', ''),
            'file': vuln.get('file_path') or vuln.get('file', ''),
            'line': vuln.get('line_number') or vuln.get('line', 0),
            'column': vuln.get('column_number') or vuln.get('column', 0),
            'function': vuln.get('function_name') or vuln.get('function', '')
        }
        
        # Generate patch
        patch = repair_engine.generate_patch(vuln_for_repair, source_code, file_path)
        
        if patch:
            # Try to save patch (detect if we loaded from database or file system)
            loaded_from_database = hasattr(scan, 'patches_json')  # Database objects have this attribute
            
            try:
                if loaded_from_database:
                    # Save to database
                    session_db = get_session()
                    existing_patches = scan.patches_json or []
                    existing_patches.append(patch)
                    scan.patches_json = existing_patches
                    
                    # Mark the JSON field as modified (required for SQLAlchemy to detect changes)
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(scan, 'patches_json')
                    
                    session_db.commit()
                    session_db.close()
                    logger.info(f"[API] Saved patch to database for vulnerability {vuln_id}")
                else:
                    # Save to file system
                    import json
                    import os
                    scan_dir = os.path.join('scans', scan_id)
                    os.makedirs(scan_dir, exist_ok=True)
                    patches_file = os.path.join(scan_dir, 'patches.json')
                    
                    # Load existing patches
                    existing_patches = []
                    if os.path.exists(patches_file):
                        try:
                            with open(patches_file, 'r') as f:
                                patches_data = json.load(f)
                                if isinstance(patches_data, dict):
                                    existing_patches = list(patches_data.values())
                                else:
                                    existing_patches = patches_data
                        except Exception as e:
                            logger.warning(f"Could not load existing patches: {e}")
                    
                    # Add new patch
                    existing_patches.append(patch)
                    
                    # Save to file
                    with open(patches_file, 'w') as f:
                        json.dump(existing_patches, f, indent=2)
                    
                    logger.info(f"[API] Saved patch to file system for vulnerability {vuln_id}")
            except Exception as save_error:
                logger.warning(f"[API] Could not save patch: {save_error}")
            
            logger.info(f"[API] Generated single patch for {vuln_id}")
            
            return jsonify({
                'success': True,
                'patch': patch
            })
        else:
            return jsonify({'error': 'Failed to generate patch'}), 400
        
    except Exception as e:
        logger.error(f"[API] Error generating single patch: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-stage1-patches/<scan_id>', methods=['POST'])
def api_generate_stage1_patches(scan_id):
    """API endpoint to generate Stage 1 patches - accessible without login"""
    logger.info(f"[API] Stage 1 patch generation requested for scan: {scan_id} - UPDATED CODE VERSION 2")
    
    try:
        # Check existing patches first to avoid duplicates
        existing_patches = get_existing_patches(scan_id)
        existing_patch_finding_ids = {patch.get('finding_id') for patch in existing_patches if patch.get('finding_id')}
        logger.info(f"[API] Found {len(existing_patches)} existing patches for {len(existing_patch_finding_ids)} vulnerabilities")
        
        # Try to get scan results from the database first
        try:
            results = scan_service.get_scan_results(scan_id)
            if 'error' not in results:
                scan = results['scan']
                findings = results['findings']
                logger.info(f"[API] Loaded {len(findings)} findings from database")
            else:
                raise Exception("Scan not found in database")
        except Exception as db_error:
            logger.warning(f"[API] Database error for scan {scan_id}: {db_error}")
            # Try to load from file system as fallback
            import json
            import os
            scan_dir = os.path.join('scans', scan_id)
            findings_file = os.path.join(scan_dir, 'static_findings.json')
            
            if os.path.exists(findings_file):
                logger.info(f"[API] Loading scan data from file system: {findings_file}")
                with open(findings_file, 'r') as f:
                    file_data = json.load(f)
                
                # Create mock scan data
                scan = {
                    'id': scan_id,
                    'status': 'completed',
                    'analysis_tool': 'cppcheck',
                    'repo_url': 'https://github.com/malikadan212/Test-Repo.git'
                }
                findings = file_data.get('findings', [])
                
                logger.info(f"[API] Loaded {len(findings)} findings from file system")
            else:
                logger.warning(f"[API] No file system data found for scan: {scan_id}")
                return jsonify({'error': 'Scan not found'}), 404
        
        if not findings:
            return jsonify({'error': 'No vulnerabilities found'}), 400
        
        logger.info(f"[API] Loaded {len(findings)} vulnerabilities from database")
        
        # Convert findings to format expected by repair engine - handle both database and file system field names
        # Filter out vulnerabilities that already have patches
        vulnerabilities = []
        skipped_count = 0
        for finding in findings:
            finding_id = str(finding.get('id') or finding.get('finding_id', ''))
            
            # Skip if patch already exists
            if finding_id in existing_patch_finding_ids:
                skipped_count += 1
                logger.debug(f"[API] Skipping vulnerability {finding_id} - patch already exists")
                continue
            
            vuln = {
                'finding_id': finding_id,
                'rule_id': finding.get('rule_id', ''),
                'severity': finding.get('severity', ''),
                'message': finding.get('message', ''),
                'cwe': finding.get('cwe', ''),
                'file': finding.get('file_path') or finding.get('file', ''),
                'line': finding.get('line_number') or finding.get('line', 0),
                'column': finding.get('column_number') or finding.get('column', 0),
                'function': finding.get('function_name') or finding.get('function', '')
            }
            vulnerabilities.append(vuln)
        
        logger.info(f"[API] Processing {len(vulnerabilities)} vulnerabilities (skipped {skipped_count} with existing patches)")
        
        # If no vulnerabilities need patches, return early
        if not vulnerabilities:
            logger.info(f"[API] All vulnerabilities already have patches")
            return jsonify({
                'success': True,
                'patches_generated': 0,
                'message': 'All vulnerabilities already have patches',
                'existing_patches': len(existing_patches),
                'skipped_count': skipped_count
            })
        
        # Get source files from database using scan service
        results = scan_service.get_scan_results(scan_id)
        if 'error' in results:
            return jsonify({'error': 'Scan not found'}), 404
        
        source_files = {}
        for source_file in results.get('source_files', []):
            file_path = source_file.get('file_path', '')
            
            # Get content from database
            try:
                from src.models.scan_v2 import ScanSource, DatabaseManager
                import os
                
                DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://autovulrepair:autovulrepair_secure_password_2024@localhost:5432/autovulrepair')
                db_manager = DatabaseManager(DATABASE_URL)
                session = db_manager.get_session()
                
                try:
                    source = session.query(ScanSource).filter(ScanSource.id == source_file.get('id')).first()
                    if source:
                        content = source.file_content
                        filename = os.path.basename(file_path)
                        # Map multiple path formats for compatibility
                        source_files[f'/tmp/source/{filename}'] = content
                        source_files[filename] = content
                        source_files[file_path] = content
                        
                        logger.info(f"Loaded: {filename} ({len(content)} bytes)")
                finally:
                    session.close()
                    
            except Exception as e:
                logger.warning(f"Could not read source file {file_path}: {e}")
        
        logger.info(f"Loaded {len(set(source_files.values()))} unique source files with {len(source_files)} path mappings from database")
        
        # Initialize Stage 1 repair engine
        from src.repair.stage1 import Stage1RepairEngine
        
        enable_dead_code = request.json.get('enable_dead_code', False) if request.json else False
        repair_engine = Stage1RepairEngine(enable_dead_code=enable_dead_code)
        
        # Generate patches
        result = repair_engine.batch_repair(vulnerabilities, source_files)
        
        # Try to save patches (detect if we loaded from database or file system)
        loaded_from_database = False
        
        try:
            results = scan_service.get_scan_results(scan_id)
            if 'error' not in results:
                loaded_from_database = True
                logger.info(f"[API] Detected database loading: {loaded_from_database}")
        except Exception as detect_error:
            logger.warning(f"[API] Error detecting database loading: {detect_error}")
        
        logger.info(f"[API] Will save patches to: {'database' if loaded_from_database else 'file system'}")
        
        try:
            if loaded_from_database:
                # Save to new database schema using RepairPatch table
                from src.models.scan_v2 import RepairPatch, DatabaseManager
                import os
                
                DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://autovulrepair:autovulrepair_secure_password_2024@localhost:5432/autovulrepair')
                db_manager = DatabaseManager(DATABASE_URL)
                session_db = db_manager.get_session()
                
                new_patches = result['patches']
                
                logger.info(f"[API] Saving {len(new_patches)} patches to new database schema")
                
                # Get existing patch IDs to avoid duplicates
                existing_patches = session_db.query(RepairPatch).filter_by(scan_id=scan_id).all()
                existing_patch_ids = {str(p.id) for p in existing_patches}
                
                logger.info(f"[API] Found {len(existing_patches)} existing patches")
                
                added_count = 0
                for patch in new_patches:
                    patch_id = patch.get('patch_id')
                    if not patch_id:
                        logger.warning(f"[API] Patch missing patch_id: {patch}")
                        continue
                    
                    if patch_id in existing_patch_ids:
                        logger.debug(f"[API] Patch {patch_id} already exists, skipping")
                        continue
                    
                    # Create RepairPatch object
                    repair_patch = RepairPatch(
                        scan_id=scan_id,
                        finding_id=patch.get('finding_id'),  # May be None
                        file_path=patch.get('file', ''),
                        original_code=patch.get('original', ''),
                        patched_code=patch.get('repaired', '') or patch.get('patched', ''),
                        patch_diff=patch.get('diff', ''),
                        repair_method=patch.get('category', 'unknown'),
                        confidence_score=patch.get('confidence', 0.8)
                    )
                    
                    session_db.add(repair_patch)
                    added_count += 1
                    logger.debug(f"[API] Added patch {patch_id} to session")
                
                logger.info(f"[API] Committing {added_count} patches to database...")
                session_db.commit()
                logger.info(f"[API] Database commit successful!")
                
                session_db.close()
                
                logger.info(f"[API] Saved {added_count} new patches to database. Total patches: {len(existing_patches) + added_count}")
            else:
                # Save to file system
                import json
                import os
                scan_dir = os.path.join('scans', scan_id)
                os.makedirs(scan_dir, exist_ok=True)
                patches_file = os.path.join(scan_dir, 'patches.json')
                
                # Load existing patches from file
                existing_patches = []
                if os.path.exists(patches_file):
                    try:
                        with open(patches_file, 'r') as f:
                            patches_data = json.load(f)
                            if isinstance(patches_data, dict):
                                existing_patches = list(patches_data.values())
                            else:
                                existing_patches = patches_data
                    except Exception as e:
                        logger.warning(f"Could not load existing patches file: {e}")
                
                # Merge new patches
                patch_ids = {p.get('patch_id') for p in existing_patches if p.get('patch_id')}
                added_count = 0
                for patch in result['patches']:
                    patch_id = patch.get('patch_id')
                    if patch_id and patch_id not in patch_ids:
                        existing_patches.append(patch)
                        added_count += 1
                
                # Save to file
                with open(patches_file, 'w') as f:
                    json.dump(existing_patches, f, indent=2)
                
                logger.info(f"[API] Saved {added_count} new patches to file system. Total patches: {len(existing_patches)}")
        except Exception as save_error:
            logger.error(f"[API] Could not save patches: {save_error}")
            import traceback
            traceback.print_exc()
        
        logger.info(f"[API] Generated {len(result['patches'])} Stage 1 patches for scan {scan_id}")
        
        return jsonify({
            'success': True,
            'patches_generated': len(result['patches']),
            'stats': result['stats'],
            'patches': result['patches'],
            'source_files_found': len(source_files),
            'code_version': 'UPDATED_VERSION_2'  # Added to verify code is updated
        })
        
    except Exception as e:
        logger.error(f"[API] Error generating Stage 1 patches: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan_status/<scan_id>')
@login_required
def api_legacy_scan_status(scan_id):
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
    
    try:
        # Use the global scan_service that was initialized with the correct database configuration
        global scan_service
        
        # Check if scan exists using the new database service
        scan_status = scan_service.get_scan_status(scan_id)
        if not scan_status or 'error' in scan_status:
            logger.warning(f"[FUZZ_PLAN] Scan not found: {scan_id}")
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
                                 scan=scan_status)
        
        # Load fuzz plan
        with open(fuzz_plan_path, 'r', encoding='utf-8') as f:
            fuzz_plan = json.load(f)
        
        return render_template('fuzz_plan.html',
                             scan_id=scan_id,
                             fuzz_plan=fuzz_plan,
                             scan=scan_status)
                             
    except Exception as e:
        logger.error(f"[FUZZ_PLAN] Error loading fuzz plan view: {e}")
        flash('Error loading fuzz plan.', 'error')
        return redirect(url_for('no_login_scan'))


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
        
        # Check if integration fuzzing should be enabled
        enable_integration = request.json.get('enable_integration', False) if request.is_json else False
        
        # Check if race condition fuzzing should be enabled
        enable_race_condition = request.json.get('enable_race_condition', False) if request.is_json else False
        
        generator = FuzzPlanGenerator(
            static_findings_path, 
            source_dir=source_dir,
            enable_integration=enable_integration,  # New parameter
            enable_race_condition=enable_race_condition  # New parameter
        )
        
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
            'integration_enabled': fuzz_plan['metadata'].get('integration_enabled', False),
            'integration_targets': fuzz_plan['metadata'].get('integration_targets', 0),
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


@app.route('/api/scan/<scan_id>/export/<format>')
@login_required
def export_scan_results(scan_id, format):
    """Export scan results in different formats for authenticated users"""
    try:
        # Validate scan ID format (should be UUID)
        import re
        if not re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', scan_id):
            return jsonify({'error': 'Invalid scan ID format'}), 400
        
        # Validate format
        if format not in ['json', 'csv', 'sarif']:
            return jsonify({'error': 'Unsupported format. Use json, csv, or sarif'}), 400
        # Get scan and verify ownership
        scan = scan_service.get_scan_status(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Verify user owns this scan
        if scan.get('user_id') != session.get('user_id'):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get complete scan results
        results = scan_service.get_scan_results(scan_id)
        findings = results.get('findings', [])
        
        if format == 'json':
            # Export as JSON
            export_data = {
                'scan_id': scan_id,
                'scan_info': {
                    'created_at': scan.get('created_at'),
                    'status': scan.get('status'),
                    'analysis_tool': scan.get('analysis_tool'),
                    'source_type': scan.get('source_type')
                },
                'summary': {
                    'total_findings': len(findings),
                    'severity_breakdown': {},
                    'rule_breakdown': {}
                },
                'findings': findings
            }
            
            # Calculate summaries
            for finding in findings:
                severity = finding.get('severity', 'unknown')
                rule_id = finding.get('rule_id', 'unknown')
                export_data['summary']['severity_breakdown'][severity] = \
                    export_data['summary']['severity_breakdown'].get(severity, 0) + 1
                export_data['summary']['rule_breakdown'][rule_id] = \
                    export_data['summary']['rule_breakdown'].get(rule_id, 0) + 1
            
            response = make_response(json.dumps(export_data, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=scan_results_{scan_id[:8]}.json'
            return response
            
        elif format == 'csv':
            # Export as CSV
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'Finding ID', 'Rule ID', 'Severity', 'Confidence', 'Message',
                'File', 'Line', 'Column', 'Function', 'CWE', 'Priority Score'
            ])
            
            # Write findings
            for finding in findings:
                writer.writerow([
                    finding.get('finding_id', ''),
                    finding.get('rule_id', ''),
                    finding.get('severity', ''),
                    finding.get('confidence', ''),
                    finding.get('message', ''),
                    finding.get('file', ''),
                    finding.get('line', ''),
                    finding.get('column', ''),
                    finding.get('function', ''),
                    finding.get('cwe', ''),
                    finding.get('priority_score', '')
                ])
            
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=scan_results_{scan_id[:8]}.csv'
            return response
            
        elif format == 'sarif':
            # Export as SARIF (Static Analysis Results Interchange Format)
            sarif_data = {
                "version": "2.1.0",
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "AutoVulRepair",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-org/autovulrepair"
                        }
                    },
                    "results": []
                }]
            }
            
            # Convert findings to SARIF format
            for finding in findings:
                sarif_result = {
                    "ruleId": finding.get('rule_id', ''),
                    "level": "error" if finding.get('severity') == 'error' else "warning",
                    "message": {
                        "text": finding.get('message', '')
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('file', '')
                            },
                            "region": {
                                "startLine": finding.get('line', 1),
                                "startColumn": finding.get('column', 1)
                            }
                        }
                    }]
                }
                
                if finding.get('cwe'):
                    sarif_result["properties"] = {
                        "cwe": finding.get('cwe'),
                        "priority_score": finding.get('priority_score', 0)
                    }
                
                sarif_data["runs"][0]["results"].append(sarif_result)
            
            response = make_response(json.dumps(sarif_data, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=scan_results_{scan_id[:8]}.sarif'
            return response
            
        else:
            return jsonify({'error': 'Unsupported format. Use json, csv, or sarif'}), 400
            
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({'error': 'Export failed'}), 500
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
    
    try:
        # Use the global scan_service that was initialized with the correct database configuration
        global scan_service
        
        # Check if scan exists using the new database service
        scan_status = scan_service.get_scan_status(scan_id)
        if not scan_status or 'error' in scan_status:
            logger.warning(f"[HARNESS_GEN] Scan not found: {scan_id}")
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
                             scan=scan_status)
                             
    except Exception as e:
        logger.error(f"[HARNESS_GEN] Error loading harness generation view: {e}")
        flash('Error loading harness generation page.', 'error')
        return redirect(url_for('no_login_scan'))


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
    
    try:
        # Use the global scan_service that was initialized with the correct database configuration
        global scan_service
        
        # Check if scan exists using the new database service
        scan_status = scan_service.get_scan_status(scan_id)
        if not scan_status or 'error' in scan_status:
            logger.warning(f"[BUILD] Scan not found: {scan_id}")
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
                             scan=scan_status)
                             
    except Exception as e:
        logger.error(f"[BUILD] Error loading build orchestration view: {e}")
        flash('Error loading build orchestration page.', 'error')
        return redirect(url_for('no_login_scan'))


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
    # Special handling for integration demo
    if scan_id == '169a84b7-demo-integration':
        demo_results_file = 'demo_fuzz_execution_results.json'
        if os.path.exists(demo_results_file):
            try:
                with open(demo_results_file, 'r') as f:
                    demo_results = json.load(f)
                return jsonify(demo_results)
            except Exception as e:
                logger.error(f"Failed to load demo results: {e}")
        
        # Fallback demo data if file doesn't exist
        return jsonify({
            "scan_id": "169a84b7-demo-integration",
            "timestamp": "2024-03-30T10:30:45.123Z",
            "total_time": 324.44,
            "total_targets": 12,
            "status": "completed",
            "results": [
                {
                    "target": "integration_auth_login_chain_0",
                    "status": "completed",
                    "runtime": 15.67,
                    "crashes_found": 3,
                    "is_integration": True,
                    "integration_chain": {
                        "components": [
                            {"name": "handle_login_request", "is_auth": True},
                            {"name": "validate_credentials", "is_auth": True, "is_validation": True},
                            {"name": "check_user_permissions", "is_auth": True, "is_database": True}
                        ],
                        "vulnerability_surface": ["authentication_bypass", "component_interaction_bug"],
                        "endpoint_type": "http"
                    },
                    "crashes": [
                        {"filename": "auth-bypass-a1b2c3d4e5f6789012345678", "size": 64},
                        {"filename": "auth-bypass-f6e5d4c3b2a1987654321098", "size": 128}
                    ]
                }
            ]
        })
    
    
    # Special handling for race condition demo
    if scan_id == '169a84b7-race-condition-demo':
        demo_results_file = 'demo_race_condition_execution_results.json'
        if os.path.exists(demo_results_file):
            try:
                with open(demo_results_file, 'r') as f:
                    demo_results = json.load(f)
                return jsonify(demo_results)
            except Exception as e:
                logger.error(f"Failed to load race condition demo results: {e}")
        
        # Fallback race condition demo data
        return jsonify({
            "scan_id": "169a84b7-race-condition-demo",
            "timestamp": "2024-03-30T14:30:45.123Z",
            "total_time": 456.78,
            "total_targets": 15,
            "status": "completed",
            "results": [
                {
                    "target": "race_unsafe_memory_management_9096",
                    "status": "completed",
                    "runtime": 23.45,
                    "crashes_found": 4,
                    "is_race_condition": True,
                    "race_condition_config": {
                        "thread_count": 8,
                        "execution_count": 200,
                        "timing_variation": 0.02,
                        "vulnerability_types": ["double_free", "use_after_free"]
                    },
                    "crashes": [
                        {"filename": "race-double-free-abc123def456789", "size": 32}
                    ]
                }
            ]
        })
    
    # Regular handling for other scans
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    executor = FuzzExecutor(scan_dir)
    results = executor.get_campaign_results()
    
    if results:
        return jsonify(results)
    else:
        return jsonify({'error': 'No results found'}), 404


@app.route('/api/fuzz/crashes/<scan_id>/<target_name>/analyze')
def analyze_crashes(scan_id, target_name):
    """Analyze crashes for a specific target - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    crashes_dir = os.path.join(scan_dir, 'fuzz', 'crashes', target_name)
    
    if not os.path.exists(crashes_dir):
        return jsonify({'error': 'No crashes found for this target'}), 404
    
    # Analyze crash files
    crash_files = [f for f in os.listdir(crashes_dir) 
                  if f.startswith('crash-') or f.startswith('leak-')]
    
    if not crash_files:
        return jsonify({'error': 'No crash files found'}), 404
    
    # Extract vulnerability type from target name
    vuln_type = target_name.replace('fuzz_test_', '').replace('_', ' ').title()
    
    analysis = f"""Crash Analysis for {vuln_type}:

🔥 Found {len(crash_files)} crash-inducing inputs
📍 Vulnerability Type: {vuln_type}
⚠️ Security Impact: These inputs can crash your program and potentially be exploited

Crash Files:
"""
    
    for crash_file in crash_files[:5]:  # Show first 5
        crash_path = os.path.join(crashes_dir, crash_file)
        size = os.path.getsize(crash_path)
        analysis += f"• {crash_file} ({size} bytes)\n"
    
    if len(crash_files) > 5:
        analysis += f"... and {len(crash_files) - 5} more crash files\n"
    
    analysis += f"""
🛡️ Next Steps:
1. Use these inputs to reproduce the vulnerability
2. Develop and test a patch
3. Validate the patch using these exact inputs
4. Add regression tests to prevent this bug from returning

💡 These crash inputs are proof-of-concept exploits that demonstrate the vulnerability is real and exploitable."""
    
    return jsonify({
        'analysis': analysis,
        'crash_count': len(crash_files),
        'vulnerability_type': vuln_type,
        'crash_files': crash_files
    })


@app.route('/api/fuzz/crashes/<scan_id>/<target_name>/download')
def download_crash_inputs(scan_id, target_name):
    """Download crash inputs as a zip file - accessible without login"""
    import zipfile
    import io
    from flask import send_file
    
    scans_dir = os.getenv('SCANS_DIR', './scans')
    crashes_dir = os.path.join(scans_dir, scan_id, 'fuzz', 'crashes', target_name)
    
    if not os.path.exists(crashes_dir):
        return jsonify({'error': 'No crashes found for this target'}), 404
    
    # Create zip file in memory
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for crash_file in os.listdir(crashes_dir):
            if crash_file.startswith('crash-') or crash_file.startswith('leak-'):
                crash_path = os.path.join(crashes_dir, crash_file)
                zip_file.write(crash_path, crash_file)
    
    zip_buffer.seek(0)
    
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{target_name}_crash_inputs.zip'
    )


@app.route('/api/fuzz/advanced/<scan_id>', methods=['POST'])
def start_advanced_fuzzing(scan_id):
    """Start advanced fuzzing campaign to find vulnerabilities static analysis misses - accessible without login"""
    logger.info(f"[ADVANCED_FUZZ] Campaign start requested for scan: {scan_id}")
    
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    # Get parameters
    runtime_minutes = int(request.json.get('runtime_minutes', 10))
    
    try:
        from src.fuzz_exec.advanced_fuzzer import AdvancedFuzzExecutor
        
        executor = AdvancedFuzzExecutor(scan_dir)
        results = executor.run_advanced_campaign(runtime_minutes=runtime_minutes)
        
        logger.info(f"[ADVANCED_FUZZ] Campaign completed for scan: {scan_id}")
        return jsonify(results)
    except Exception as e:
        logger.error(f"[ADVANCED_FUZZ] Campaign failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/fuzz/advanced/<scan_id>/results')
def advanced_fuzz_results(scan_id):
    """Get advanced fuzzing campaign results - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    advanced_results_dir = os.path.join(scan_dir, 'fuzz', 'advanced_results')
    results_file = os.path.join(advanced_results_dir, 'advanced_campaign_results.json')
    
    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            return jsonify(results)
        except Exception as e:
            return jsonify({'error': f'Failed to load results: {str(e)}'}), 500
    else:
        return jsonify({'error': 'No advanced fuzzing results found'}), 404


@app.route('/api/repair/validate-patch/<scan_id>', methods=['POST'])
def validate_patch_with_fuzzing(scan_id):
    """Validate a patch using fuzzing crash inputs - accessible without login"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    scan_dir = os.path.join(scans_dir, scan_id)
    
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({'error': 'Invalid JSON format'}), 400
    vulnerability_id = data.get('vulnerability_id')
    patched_code_path = data.get('patched_code_path')
    
    if not vulnerability_id or not patched_code_path:
        return jsonify({'error': 'Missing vulnerability_id or patched_code_path'}), 400
    
    # Use fuzzing integration to validate patch
    integration = FuzzingRepairIntegration(scan_dir)
    validation_result = integration.validate_patch(vulnerability_id, patched_code_path)
    
    return jsonify(validation_result)


@app.route('/api/scan', methods=['POST'])
@app.route('/scan-public', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=60)  # 5 scans per minute
def scan_public():
    """New ingestion API endpoint for public scanning - now using database service"""
    try:
        # Check if this is a JSON request or form submission
        is_json_request = request.content_type and 'application/json' in request.content_type
        is_form_submission = request.content_type and (
            'multipart/form-data' in request.content_type or 
            'application/x-www-form-urlencoded' in request.content_type
        )
        
        # Get data from appropriate source
        if is_json_request:
            try:
                data = request.get_json() or {}
            except Exception as e:
                logger.warning(f"[SCAN_SUBMISSION] Malformed JSON: {e}")
                return jsonify({'error': 'Invalid JSON format'}), 400
            repo_url = (data.get('repo_url') or '').strip()
            zip_file = None  # JSON requests don't support file uploads
            code_snippet = (data.get('code_snippet') or '').strip()
            analysis_tool = data.get('analysis_tool', 'cppcheck')
        else:
            # Form data
            repo_url = (request.form.get('repo_url') or '').strip()
            zip_file = request.files.get('zip_file')
            code_snippet = (request.form.get('code_snippet') or '').strip()
            analysis_tool = request.form.get('analysis_tool', 'cppcheck')
        
        logger.info(f"[SCAN_SUBMISSION] New scan request received")
        logger.info(f"[SCAN_SUBMISSION] Content-Type: {request.content_type}, Is JSON: {is_json_request}, Is Form: {is_form_submission}")
        if is_json_request:
            logger.info(f"[SCAN_SUBMISSION] Request JSON data: {data}")
        logger.info(f"[SCAN_SUBMISSION] Source types - repo_url: {bool(repo_url)}, zip_file: {bool(zip_file and zip_file.filename)}, code_snippet: {bool(code_snippet)}")
        logger.info(f"[SCAN_SUBMISSION] Analysis tool: {analysis_tool}")
        
        # Validate that only one source type is provided
        has_code_snippet = code_snippet and str(code_snippet).strip()
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
        
        # Determine source type and create scan using service layer
        if repo_url:
            if not is_valid_github_url(repo_url):
                logger.warning(f"[SCAN_SUBMISSION] Invalid GitHub URL format: {repo_url}")
                if is_form_submission:
                    flash('Invalid GitHub URL format. Please use: https://github.com/username/repository', 'error')
                    return redirect(url_for('no_login_scan'))
                return jsonify({'error': 'Invalid GitHub URL format'}), 400
            
            logger.info(f"[SCAN_SUBMISSION] Processing GitHub repository: {repo_url}")
            result = scan_service.create_scan(
                source_type='repository',
                repo_url=repo_url,
                analysis_tool=analysis_tool,
                user_id=None  # Public scan
            )
            
        elif zip_file:
            # Validate ZIP file
            is_valid, error_msg = validate_zip_file(zip_file)
            if not is_valid:
                logger.warning(f"[SCAN_SUBMISSION] ZIP validation failed: {error_msg}")
                if is_form_submission:
                    flash(f'ZIP file error: {error_msg}', 'error')
                    return redirect(url_for('no_login_scan'))
                return jsonify({'error': error_msg}), 400
            
            logger.info(f"[SCAN_SUBMISSION] Processing ZIP file: {zip_file.filename}")
            result = scan_service.create_scan(
                source_type='file_upload',
                file_upload=zip_file,
                analysis_tool=analysis_tool,
                user_id=None  # Public scan
            )
            
        else:  # code_snippet
            # Validate code snippet
            is_valid, error_msg = validate_code_snippet(code_snippet)
            if not is_valid:
                logger.warning(f"[SCAN_SUBMISSION] Code snippet validation failed: {error_msg}")
                if is_form_submission:
                    flash(f'Code snippet error: {error_msg}', 'error')
                    return redirect(url_for('no_login_scan'))
                return jsonify({'error': error_msg}), 400
            
            logger.info(f"[SCAN_SUBMISSION] Processing code snippet (length: {len(code_snippet)} chars)")
            result = scan_service.create_scan(
                source_type='snippet',
                code_snippet=code_snippet,
                analysis_tool=analysis_tool,
                user_id=None  # Public scan
            )
        
        scan_id = result['scan_id']
        logger.info(f"[SCAN_SUBMISSION] Scan created successfully: {scan_id}")
        
        # For form submissions, redirect to detailed findings page
        if is_form_submission:
            try:
                findings_url = url_for('detailed_findings', scan_id=scan_id)
                logger.info(f"[SCAN_SUBMISSION] Redirecting to detailed findings: {findings_url}")
                return redirect(findings_url)
            except Exception as redirect_error:
                logger.error(f"[SCAN_SUBMISSION] Error generating redirect URL: {redirect_error}")
                flash(f'Scan submitted successfully (ID: {scan_id})', 'success')
                return redirect(url_for('no_login_scan'))
        
        # For API calls (JSON), return JSON response for VS Code extension
        logger.info(f"[SCAN_SUBMISSION] Returning JSON response for scan {scan_id}")
        return jsonify({
            'scanId': scan_id,  # Changed from 'scan_id' to 'scanId' for extension compatibility
            'status': result['status'],
            'message': 'Scan initiated successfully'
        }), 202
            
    except Exception as e:
        logger.error(f"[SCAN_SUBMISSION] Exception during scan submission: {e}", exc_info=True)
        
        # Check if form submission for proper error handling
        is_json_request = request.content_type and 'application/json' in request.content_type
        is_form_submission = request.content_type and ('multipart/form-data' in request.content_type or 'application/x-www-form-urlencoded' in request.content_type)
        
        if is_form_submission:
            flash(f'An error occurred: {str(e)}', 'error')
            try:
                return redirect(url_for('no_login_scan'))
            except Exception as redirect_err:
                logger.error(f"ERROR in redirect: {redirect_err}")
                return f"<html><body><h1>Error</h1><p>{str(e)}</p><a href='/no-login'>Go Back</a></body></html>", 500
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


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


def process_github_pr_scan(repo_url, scan_id, analysis_tool, pr_number):
    """Process a GitHub pull request with differential scanning"""
    temp_dir = None
    try:
        logger.info(f"Starting PR scan for {repo_url} PR #{pr_number} with {analysis_tool}")
        
        # Check if user has GitHub token
        github_token = session.get('github_token')
        if not github_token:
            return {
                'success': False,
                'error': 'GitHub authentication required for PR scanning'
            }
        
        # Initialize GitHub service
        github_service = GitHubService(github_token)
        
        # Extract repository name from URL
        repo_full_name = repo_url.replace('https://github.com/', '').replace('.git', '').strip('/')
        
        # Validate repository access
        if not github_service.validate_repository_access(repo_full_name):
            return {
                'success': False,
                'error': 'Repository not found or access denied'
            }
        
        # Initialize differential scan service
        differential_service = DifferentialScanService(github_service)
        
        # Create temporary directory for scan
        temp_dir = tempfile.mkdtemp(prefix=f'pr_scan_{scan_id}_')
        
        # Prepare PR for scanning
        logger.info(f"Preparing PR #{pr_number} for differential scanning")
        prep_result = differential_service.prepare_pr_scan(repo_full_name, pr_number, temp_dir)
        
        if not prep_result['success']:
            return {
                'success': False,
                'error': prep_result['error']
            }
        
        # Get scan files
        scan_files = prep_result['files']
        repo_dir = prep_result['repo_dir']
        
        logger.info(f"Found {len(scan_files)} files to scan in PR #{pr_number}")
        
        if not scan_files:
            return {
                'success': True,
                'data': {
                    'repo_url': repo_url,
                    'pr_number': pr_number,
                    'status': 'completed',
                    'vulnerabilities': [],
                    'patches': [],
                    'scan_type': 'github_pr',
                    'analysis_tool': analysis_tool,
                    'message': 'No scannable files found in pull request changes'
                }
            }
        
        # Run differential analysis
        logger.info(f"Running {analysis_tool} analysis on PR changes")
        analysis_result = differential_service.run_differential_analysis(scan_files, analysis_tool)
        
        if not analysis_result['success']:
            return {
                'success': False,
                'error': analysis_result['error']
            }
        
        vulnerabilities = analysis_result['vulnerabilities']
        
        # Generate patches for found vulnerabilities (if any)
        patches = []
        if vulnerabilities:
            logger.info(f"Generating patches for {len(vulnerabilities)} vulnerabilities")
            patches = generate_patches_for_vulnerabilities(vulnerabilities, repo_dir)
        
        # Clean up repository directory
        differential_service.cleanup_scan_directory(repo_dir)
        
        logger.info(f"PR scan completed: {len(vulnerabilities)} vulnerabilities, {len(patches)} patches")
        
        return {
            'success': True,
            'data': {
                'repo_url': repo_url,
                'pr_number': pr_number,
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'patches': patches,
                'scan_type': 'github_pr',
                'analysis_tool': analysis_tool,
                'files_scanned': len(scan_files),
                'total_pr_files': prep_result.get('total_count', 0),
                'scannable_files': prep_result.get('scannable_count', 0)
            }
        }
        
    except Exception as e:
        logger.error(f"PR scan failed: {e}")
        return {
            'success': False,
            'error': f'PR scan failed: {str(e)}'
        }
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def generate_patches_for_vulnerabilities(vulnerabilities, repo_dir):
    """Generate patches for vulnerabilities found in PR scan"""
    patches = []
    
    try:
        for vuln in vulnerabilities:
            if not vuln.get('pr_context'):
                continue  # Skip non-PR vulnerabilities
            
            file_path = vuln.get('file', '')
            line_number = vuln.get('line', 0)
            vuln_type = vuln.get('type', '')
            description = vuln.get('description', '')
            
            # Generate patch based on vulnerability type
            patch_content = generate_patch_for_vulnerability_type(
                vuln_type, file_path, line_number, description, repo_dir
            )
            
            if patch_content:
                patch_id = f"patch_{len(patches) + 1}"
                patches.append({
                    'id': patch_id,
                    'vulnerability_id': vuln.get('id', ''),
                    'file': file_path,
                    'line': line_number,
                    'type': vuln_type,
                    'description': f"Fix for {vuln_type} in {file_path}",
                    'content': patch_content,
                    'confidence': 'medium',  # PR patches are generally medium confidence
                    'pr_context': True
                })
    
    except Exception as e:
        logger.error(f"Error generating patches: {e}")
    
    return patches


def generate_patch_for_vulnerability_type(vuln_type, file_path, line_number, description, repo_dir):
    """Generate a patch for a specific vulnerability type"""
    try:
        full_file_path = os.path.join(repo_dir, file_path)
        
        if not os.path.exists(full_file_path):
            return None
        
        with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        if line_number <= 0 or line_number > len(lines):
            return None
        
        # Get the problematic line
        problem_line = lines[line_number - 1].strip()
        
        # Generate patch based on vulnerability type
        if 'bufferAccessOutOfBounds' in vuln_type or 'arrayIndexOutOfBounds' in vuln_type:
            return generate_buffer_overflow_patch(problem_line, line_number)
        elif 'nullPointer' in vuln_type:
            return generate_null_pointer_patch(problem_line, line_number)
        elif 'memoryLeak' in vuln_type:
            return generate_memory_leak_patch(problem_line, line_number)
        elif 'uninitvar' in vuln_type:
            return generate_uninitialized_var_patch(problem_line, line_number)
        else:
            # Generic patch
            return generate_generic_patch(problem_line, line_number, description)
    
    except Exception as e:
        logger.error(f"Error generating patch for {vuln_type}: {e}")
        return None


def generate_buffer_overflow_patch(problem_line, line_number):
    """Generate patch for buffer overflow vulnerabilities"""
    patch = f"""--- a/file.c
+++ b/file.c
@@ -{line_number},1 +{line_number},3 @@
-{problem_line}
+    // TODO: Add bounds checking before buffer access
+    // Verify buffer size and input length
+{problem_line}"""
    return patch


def generate_null_pointer_patch(problem_line, line_number):
    """Generate patch for null pointer vulnerabilities"""
    patch = f"""--- a/file.c
+++ b/file.c
@@ -{line_number},1 +{line_number},4 @@
-{problem_line}
+    // Add null pointer check
+    if (ptr != NULL) {{
+{problem_line}
+    }}"""
    return patch


def generate_memory_leak_patch(problem_line, line_number):
    """Generate patch for memory leak vulnerabilities"""
    patch = f"""--- a/file.c
+++ b/file.c
@@ -{line_number},1 +{line_number},2 @@
 {problem_line}
+    // TODO: Add corresponding free() call for allocated memory"""
    return patch


def generate_uninitialized_var_patch(problem_line, line_number):
    """Generate patch for uninitialized variable vulnerabilities"""
    patch = f"""--- a/file.c
+++ b/file.c
@@ -{line_number},1 +{line_number},2 @@
+    // Initialize variable before use
 {problem_line}"""
    return patch


def generate_generic_patch(problem_line, line_number, description):
    """Generate generic patch with security comment"""
    patch = f"""--- a/file.c
+++ b/file.c
@@ -{line_number},1 +{line_number},2 @@
+    // Security fix needed: {description}
 {problem_line}"""
    return patch


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
    vulnerabilities = [
        {
            'id': 'sim_vuln_1',
            'severity': 'high',
            'description': 'Simulated: SQL Injection vulnerability detected',
            'file': 'src/database.py',
            'line': 42,
            'tool': 'Simulation'
        },
        {
            'id': 'sim_vuln_2',
            'severity': 'medium',
            'description': 'Simulated: Outdated dependency with known vulnerabilities',
            'file': 'requirements.txt',
            'line': 5,
            'tool': 'Simulation'
        }
    ]
    
    patches = [
        {
            'id': 'sim_patch_1',
            'description': 'Fix SQL injection by using parameterized queries',
            'content': '''--- a/src/database.py
+++ b/src/database.py
@@ -39,7 +39,7 @@ def get_user(user_id):
     """Get user by ID"""
-    query = f"SELECT * FROM users WHERE id = {user_id}"
+    query = "SELECT * FROM users WHERE id = %s"
-    cursor.execute(query)
+    cursor.execute(query, (user_id,))
     return cursor.fetchone()'''
        },
        {
            'id': 'sim_patch_2',
            'description': 'Update vulnerable dependency',
            'content': '''--- a/requirements.txt
+++ b/requirements.txt
@@ -2,7 +2,7 @@ flask==2.0.1
 requests==2.25.1
-urllib3==1.26.4
+urllib3==1.26.18
 jinja2==3.0.1'''
        }
    ]
    
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
        # Use scan service to get vulnerabilities from database
        results = scan_service.get_scan_results(scan_id)
        if 'error' in results:
            flash('Scan not found.', 'error')
            return redirect(url_for('no_login_scan'))
        
        scan = results['scan']
        findings = results['findings']
        
        logger.info(f"[REPAIR_DASHBOARD] Loaded {len(findings)} findings from database")
        
        # Filter for Stage 2 vulnerabilities (complex ones that need AI)
        stage2_vulns = []
        for finding in findings:
            rule_id = finding.get('rule_id', '')
            # Include buffer overflows, array bounds, obsolete functions (gets, strcpy, etc.)
            if any(keyword in rule_id.lower() for keyword in [
                'arrayindexoutofbounds', 'bufferaccessoutofbounds', 'bufferoverflow',
                'obsoletefunction', 'gets', 'strcpy', 'sprintf', 'strcat',
                'formatstring', 'racecondition'
            ]):
                stage2_vulns.append({
                    'crash_id': str(finding.get('id', f"vuln_{finding.get('line_number', 0)}")),
                    'file': finding.get('file_path', 'unknown'),
                    'line': finding.get('line_number', 0),
                    'description': finding.get('message', 'Unknown vulnerability'),
                    'severity': 'High',  # Stage 2 vulnerabilities are high severity
                    'rule_id': finding.get('rule_id', 'unknown'),
                    'cwe': finding.get('cwe', ''),
                    'function': finding.get('function_name', '')
                })
        
        if not stage2_vulns:
            flash('No Stage 2 vulnerabilities found for AI repair. These vulnerabilities may be handled by Stage 1 (rule-based) repair.', 'info')
            return redirect(url_for('patch_review', scan_id=scan_id))
        
        # Create triage results format
        triage_results = {
            'crashes': stage2_vulns,
            'summary': {
                'total': len(stage2_vulns),
                'unique': len(stage2_vulns)
            }
        }
        
        logger.info(f"[REPAIR_DASHBOARD] Found {len(stage2_vulns)} Stage 2 vulnerabilities")
        
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
        logger.error(f"[REPAIR_DASHBOARD] Error loading repair dashboard: {e}", exc_info=True)
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
        
        # Use scan service to get vulnerabilities from database
        results = scan_service.get_scan_results(scan_id)
        if 'error' in results:
            return jsonify({
                'status': 'error',
                'message': 'No vulnerabilities found. Please run a scan first.'
            }), 404
        
        scan = results['scan']
        findings = results['findings']
        
        logger.info(f"[START_REPAIR] Loaded {len(findings)} findings from database")
        
        # Filter for Stage 2 vulnerabilities (complex ones that need AI)
        stage2_vulns = []
        for finding in findings:
            rule_id = finding.get('rule_id', '')
            if any(keyword in rule_id.lower() for keyword in [
                'arrayindexoutofbounds', 'bufferaccessoutofbounds', 'bufferoverflow',
                'obsoletefunction', 'gets', 'strcpy', 'sprintf', 'strcat',
                'formatstring', 'racecondition'
            ]):
                stage2_vulns.append({
                    'crash_id': str(finding.get('id', f"vuln_{finding.get('line_number', 0)}")),
                    'file': finding.get('file_path', 'unknown'),
                    'line': finding.get('line_number', 0),
                    'description': finding.get('message', 'Unknown vulnerability'),
                    'severity': 'High',  # Stage 2 vulnerabilities are high severity
                    'rule_id': finding.get('rule_id', 'unknown'),
                    'cwe': finding.get('cwe', ''),
                    'function': finding.get('function_name', '')
                })
        
        if not stage2_vulns:
            return jsonify({
                'status': 'info',
                'message': 'No Stage 2 vulnerabilities found. These may be handled by Stage 1 (rule-based) repair.'
            })
        
        logger.info(f"[START_REPAIR] Found {len(stage2_vulns)} Stage 2 vulnerabilities")
        
        # Filter critical/high vulnerabilities
        vulnerabilities = []
        for vuln in stage2_vulns:
            if vuln.get('severity') in ['Critical', 'High']:
                vulnerabilities.append(vuln)
        
        if not vulnerabilities:
            return jsonify({
                'status': 'info',
                'message': 'No critical or high severity vulnerabilities found to repair.'
            })
        
        # Start repair workflow (async) with proper error handling and context
        from threading import Thread
        import traceback
        
        def run_repairs():
            try:
                logger.info(f"[REPAIR_THREAD] Starting repair thread for scan {scan_id}")
                logger.info(f"[REPAIR_THREAD] Processing {len(vulnerabilities)} vulnerabilities")
                
                # Initialize orchestrator in thread context
                orchestrator = RepairOrchestrator()
                logger.info(f"[REPAIR_THREAD] RepairOrchestrator initialized successfully")
                
                results = []
                
                for i, vuln in enumerate(vulnerabilities):
                    crash_id = vuln.get('crash_id', vuln.get('target', 'unknown'))
                    logger.info(f"[REPAIR_THREAD] Processing vulnerability {i+1}/{len(vulnerabilities)}: {crash_id}")
                    
                    try:
                        # Log vulnerability details
                        logger.info(f"[REPAIR_THREAD] Vulnerability: {vuln.get('rule_id', 'unknown')} in {vuln.get('file', 'unknown')}:{vuln.get('line', 0)}")
                        
                        result = orchestrator.repair(
                            vulnerability=vuln,
                            scan_id=scan_id,
                            crash_id=crash_id,
                            max_retries=2
                        )
                        
                        logger.info(f"[REPAIR_THREAD] Repair completed for {crash_id}: status={result.get('status', 'unknown')}")
                        
                        # Extract patches properly
                        patches = result.get('patches', [])
                        best_patch = result.get('best_patch')
                        
                        results.append({
                            'crash_id': crash_id,
                            'file': vuln.get('file', 'unknown'),
                            'line': vuln.get('line', 0),
                            'rule_id': vuln.get('rule_id', 'unknown'),
                            'status': result.get('status', 'unknown'),
                            'patches_generated': len(patches),
                            'patches': patches,  # Include actual patches
                            'best_patch': best_patch,
                            'patch': best_patch.get('patch_content', '') if best_patch else '',  # For compatibility
                            'validation_results': result.get('validation_results', {}),
                            'analysis': result.get('analysis', ''),
                            'error': result.get('error')
                        })
                        
                        logger.info(f"[REPAIR_THREAD] Successfully processed {crash_id}: {len(patches)} patches generated")
                        
                    except Exception as e:
                        logger.error(f"[REPAIR_THREAD] Repair failed for {crash_id}: {e}")
                        logger.error(f"[REPAIR_THREAD] Traceback: {traceback.format_exc()}")
                        results.append({
                            'crash_id': crash_id,
                            'file': vuln.get('file', 'unknown'),
                            'line': vuln.get('line', 0),
                            'rule_id': vuln.get('rule_id', 'unknown'),
                            'status': 'failed',
                            'patches_generated': 0,
                            'patches': [],
                            'best_patch': None,
                            'patch': '',
                            'validation_results': {},
                            'analysis': '',
                            'error': str(e)
                        })
                
                # Save results
                repair_dir = Path(f"scans/{scan_id}/repair")
                repair_dir.mkdir(parents=True, exist_ok=True)
                
                final_results = {
                    'scan_id': scan_id,
                    'status': 'completed',
                    'repairs': results,
                    'summary': {
                        'total': len(results),
                        'successful': sum(1 for r in results if r['status'] == 'completed'),
                        'failed': sum(1 for r in results if r['status'] == 'failed'),
                        'total_patches': sum(r.get('patches_generated', 0) for r in results)
                    },
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(repair_dir / 'repair_results.json', 'w') as f:
                    json.dump(final_results, f, indent=2)
                
                logger.info(f"[REPAIR_THREAD] Repair thread completed successfully")
                logger.info(f"[REPAIR_THREAD] Results: {final_results['summary']}")
                
                # Save metrics
                if hasattr(orchestrator, 'metrics') and orchestrator.metrics:
                    try:
                        orchestrator.metrics.finalize()
                        orchestrator.metrics.save()
                        logger.info(f"[REPAIR_THREAD] Metrics saved successfully")
                    except Exception as e:
                        logger.error(f"[REPAIR_THREAD] Failed to save metrics: {e}")
                        
            except Exception as e:
                logger.error(f"[REPAIR_THREAD] Critical error in repair thread: {e}")
                logger.error(f"[REPAIR_THREAD] Full traceback: {traceback.format_exc()}")
                
                # Save error results
                try:
                    repair_dir = Path(f"scans/{scan_id}/repair")
                    repair_dir.mkdir(parents=True, exist_ok=True)
                    
                    error_results = {
                        'scan_id': scan_id,
                        'status': 'failed',
                        'error': str(e),
                        'traceback': traceback.format_exc(),
                        'repairs': [],
                        'summary': {'total': 0, 'successful': 0, 'failed': 0},
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    with open(repair_dir / 'repair_results.json', 'w') as f:
                        json.dump(error_results, f, indent=2)
                        
                except Exception as save_error:
                    logger.error(f"[REPAIR_THREAD] Failed to save error results: {save_error}")
        
        thread = Thread(target=run_repairs, name=f"RepairThread-{scan_id}")
        thread.daemon = True  # Make thread daemon so it doesn't block shutdown
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
    # Initialize database tables
    try:
        create_database()  # Create scan tables
        user_service.create_tables()  # Create user tables
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
    
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True, extra_files=['templates/', 'src/'])
