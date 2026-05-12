"""
GitHub App Routes
Handles GitHub App installation, callbacks, and management
"""

import os
import logging
import secrets
from flask import Blueprint, request, redirect, url_for, session, flash, jsonify, render_template
from flask_login import login_required, current_user

from src.services.github_app_service import GitHubAppService
from src.services.installation_service import InstallationService
from src.database.connection import get_session

logger = logging.getLogger(__name__)

# Create blueprint
github_app_bp = Blueprint('github_app', __name__)

# Initialize services (will be done in app.py)
github_app_service = None
installation_service = None

def init_github_app_services(app_id: str, private_key: str):
    """Initialize GitHub App services"""
    global github_app_service, installation_service
    
    db_session = get_session()
    github_app_service = GitHubAppService(app_id, private_key, db_session)
    installation_service = InstallationService(db_session, github_app_service)

@github_app_bp.route('/install-github-app')
@login_required
def install_github_app():
    """Redirect user to GitHub App installation page"""
    try:
        # Generate state token to track this user's installation
        state_token = secrets.token_urlsafe(32)
        session['github_app_state'] = state_token
        session['github_app_user_id'] = current_user.id
        
        # GitHub App installation URL
        app_name = os.getenv('GITHUB_APP_NAME', 'autovulrepair')
        github_install_url = f"https://github.com/apps/{app_name}/installations/new?state={state_token}"
        
        logger.info(f"Redirecting user {current_user.username} to GitHub App installation")
        
        return redirect(github_install_url)
        
    except Exception as e:
        logger.error(f"Error initiating GitHub App installation: {e}")
        flash('Failed to initiate GitHub App installation. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@github_app_bp.route('/github/installation/callback')
@github_app_bp.route('/github/installation/success')  # Handle both URLs for compatibility
def github_installation_callback():
    """Handle GitHub App installation callback"""
    try:
        # Ensure services are initialized (fallback for development server issues)
        global github_app_service, installation_service
        if not github_app_service or not installation_service:
            GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')
            GITHUB_APP_PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
            if GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY:
                init_github_app_services(GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY)
                logger.info("GitHub App services initialized in callback (fallback)")
        
        installation_id = request.args.get('installation_id')
        setup_action = request.args.get('setup_action')
        state = request.args.get('state')
        
        logger.info(f"GitHub App installation callback: installation_id={installation_id}, "
                   f"setup_action={setup_action}, state={state}")
        
        # Verify state token
        if state != session.get('github_app_state'):
            logger.warning("Invalid state token in GitHub App callback")
            flash('Invalid installation state. Please try again.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get user ID from session
        user_id = session.get('github_app_user_id')
        if not user_id:
            logger.warning("No user ID in session for GitHub App callback")
            flash('Session expired. Please try again.', 'error')
            return redirect(url_for('dashboard'))
        
        if setup_action == 'install' and installation_id:
            # Handle new installation
            result = installation_service.handle_new_installation(
                int(installation_id), 
                user_id, 
                setup_action
            )
            
            if result['success']:
                # Clear session tokens
                session.pop('github_app_state', None)
                session.pop('github_app_user_id', None)
                
                # Store installation result for success page
                session['installation_result'] = result
                
                logger.info(f"GitHub App installation successful for user {user_id}: "
                           f"{result['enabled_repositories']} repos enabled")
                
                return redirect(url_for('github_app.installation_success'))
            else:
                logger.error(f"GitHub App installation failed: {result.get('error')}")
                flash(f'Installation failed: {result.get("error")}', 'error')
                return redirect(url_for('dashboard'))
        
        elif setup_action == 'update' and installation_id:
            # Handle installation update (repository selection changed)
            logger.info(f"GitHub App installation updated: {installation_id}")
            flash('GitHub App installation updated successfully.', 'success')
            return redirect(url_for('dashboard'))
        
        else:
            logger.warning(f"Unknown setup action or missing installation ID: {setup_action}")
            flash('Installation was not completed.', 'warning')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Error in GitHub App installation callback: {e}")
        flash('Installation failed due to an error. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@github_app_bp.route('/github/installation/success')
@login_required
def installation_success():
    """Show installation success page"""
    try:
        result = session.pop('installation_result', None)
        
        if not result:
            flash('No installation result found.', 'warning')
            return redirect(url_for('dashboard'))
        
        return render_template('github_app/installation_success.html', result=result)
        
    except Exception as e:
        logger.error(f"Error showing installation success: {e}")
        flash('Error displaying installation results.', 'error')
        return redirect(url_for('dashboard'))

# API Routes for GitHub App management

@github_app_bp.route('/api/github-app/installations')
@login_required
def api_get_installations():
    """Get user's GitHub App installations"""
    try:
        # Ensure services are initialized (fallback for development server issues)
        global github_app_service, installation_service
        if not installation_service:
            GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')
            GITHUB_APP_PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
            if GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY:
                init_github_app_services(GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY)
                logger.info("GitHub App services initialized in API endpoint (fallback)")
        
        if not installation_service:
            return jsonify({
                'success': False,
                'error': 'GitHub App not configured'
            }), 503
            
        installations = installation_service.get_user_installations(current_user.id)
        return jsonify({
            'success': True,
            'installations': installations
        })
        
    except Exception as e:
        logger.error(f"Error getting installations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@github_app_bp.route('/api/github-app/repositories')
@login_required
def api_get_repositories():
    """Get user's repositories accessible through GitHub App"""
    try:
        # Ensure services are initialized (fallback for development server issues)
        global github_app_service, installation_service
        if not installation_service:
            GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')
            GITHUB_APP_PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
            if GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY:
                init_github_app_services(GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY)
                logger.info("GitHub App services initialized in repositories API (fallback)")
        
        if not installation_service:
            return jsonify({
                'success': False,
                'error': 'GitHub App not configured'
            }), 503
            
        repositories = installation_service.get_user_repositories(current_user.id)
        return jsonify({
            'success': True,
            'repositories': repositories,
            'total': len(repositories),
            'enabled': len([r for r in repositories if r['automation_enabled']])
        })
        
    except Exception as e:
        logger.error(f"Error getting repositories: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@github_app_bp.route('/api/github-app/pull-requests')
@login_required
def api_get_pull_requests():
    """Get pull requests created by AutoVulRepair"""
    try:
        # Ensure services are initialized
        global github_app_service, installation_service
        if not installation_service:
            GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')
            GITHUB_APP_PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
            if GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY:
                init_github_app_services(GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY)
                logger.info("GitHub App services initialized in PR API (fallback)")
        
        if not installation_service:
            return jsonify({
                'success': False,
                'error': 'GitHub App not configured'
            }), 503
        
        # Get user's repositories
        repositories = installation_service.get_user_repositories(current_user.id)
        
        # For now, return empty list (PRs will be tracked in future)
        # TODO: Query database for PRs created by AutoVulRepair
        pull_requests = []
        
        return jsonify({
            'success': True,
            'pull_requests': pull_requests,
            'total': len(pull_requests)
        })
        
    except Exception as e:
        logger.error(f"Error getting pull requests: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@github_app_bp.route('/api/github-app/repository/<path:repo_full_name>/automation', methods=['POST'])
@login_required
def api_toggle_repository_automation(repo_full_name):
    """Toggle automation for a specific repository"""
    try:
        data = request.get_json() or {}
        enabled = data.get('enabled', True)
        
        result = installation_service.toggle_repository_automation(
            current_user.id, 
            repo_full_name, 
            enabled
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Error toggling repository automation: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@github_app_bp.route('/api/github-app/repository/<path:repo_full_name>/settings', methods=['PUT'])
@login_required
def api_update_repository_settings(repo_full_name):
    """Update automation settings for a repository"""
    try:
        settings = request.get_json() or {}
        
        result = installation_service.update_repository_settings(
            current_user.id,
            repo_full_name,
            settings
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Error updating repository settings: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@github_app_bp.route('/api/github-app/repository/<path:repo_full_name>/scan', methods=['POST'])
@login_required
def api_trigger_repository_scan(repo_full_name):
    """Manually trigger scan for a repository"""
    try:
        # Get repository info
        repositories = installation_service.get_user_repositories(current_user.id)
        repo = next((r for r in repositories if r['full_name'] == repo_full_name), None)
        
        if not repo:
            return jsonify({
                'success': False,
                'error': 'Repository not found'
            }), 404
        
        # Import scan service
        from src.services.scan_service import scan_service
        
        # Create scan using GitHub App token
        result = scan_service.create_scan(
            source_type='repository',
            repo_url=f"https://github.com/{repo_full_name}",
            analysis_tool='cppcheck',
            user_id=current_user.id,
            automated=False,
            github_installation_id=repo['installation_id']
        )
        
        return jsonify({
            'success': True,
            'scan_id': result['scan_id'],
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Error triggering repository scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Webhook handler (will be enhanced in webhook routes)
@github_app_bp.route('/webhook/github/app', methods=['POST'])
def github_app_webhook():
    """Handle GitHub App webhooks"""
    try:
        # This will be implemented in the webhook handler
        # For now, just acknowledge receipt
        return jsonify({'status': 'received'}), 200
        
    except Exception as e:
        logger.error(f"Error handling GitHub App webhook: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500