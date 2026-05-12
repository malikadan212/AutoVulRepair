"""
Development Routes
Mock endpoints for testing GitHub App functionality locally
"""

import json
import logging
from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required

logger = logging.getLogger(__name__)

dev_bp = Blueprint('dev', __name__)

@dev_bp.route('/dev/webhook-test')
@login_required
def webhook_test_page():
    """Test page for simulating GitHub webhooks"""
    return render_template('dev/webhook_test.html')

@dev_bp.route('/dev/simulate-webhook', methods=['POST'])
@login_required
def simulate_webhook():
    """Simulate a GitHub webhook for testing"""
    try:
        data = request.get_json()
        event_type = data.get('event_type', 'push')
        repo_name = data.get('repo_name', 'test/repo')
        
        # Create mock webhook payload
        if event_type == 'push':
            mock_payload = {
                'ref': 'refs/heads/main',
                'after': 'abc123def456',
                'repository': {
                    'full_name': repo_name,
                    'clone_url': f'https://github.com/{repo_name}.git',
                    'name': repo_name.split('/')[-1]
                },
                'pusher': {
                    'name': 'test-user'
                }
            }
        elif event_type == 'pull_request':
            mock_payload = {
                'action': 'opened',
                'number': 42,
                'repository': {
                    'full_name': repo_name,
                    'clone_url': f'https://github.com/{repo_name}.git'
                },
                'pull_request': {
                    'number': 42,
                    'title': 'Test PR',
                    'user': {'login': 'test-user'},
                    'base': {'ref': 'main'},
                    'head': {'ref': 'feature-branch', 'sha': 'def456abc123'}
                }
            }
        else:
            return jsonify({'error': 'Unsupported event type'}), 400
        
        # Import webhook handler
        from src.webhooks.github_webhooks import webhook_handler
        
        if not webhook_handler:
            return jsonify({'error': 'Webhook handler not initialized'}), 500
        
        # Process the mock webhook
        if event_type == 'push':
            result = webhook_handler.handle_push_event(mock_payload)
        elif event_type == 'pull_request':
            result = webhook_handler.handle_pull_request_event(mock_payload)
        
        return jsonify({
            'success': True,
            'event_type': event_type,
            'payload': mock_payload,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error simulating webhook: {e}")
        return jsonify({'error': str(e)}), 500

@dev_bp.route('/dev/test-installation')
@login_required
def test_installation():
    """Test GitHub App installation flow"""
    try:
        from src.services.installation_service import installation_service
        
        if not installation_service:
            return jsonify({'error': 'Installation service not available'}), 500
        
        # Mock installation data
        mock_installation_result = installation_service.handle_new_installation(
            installation_id=999999,  # Mock installation ID
            user_id=current_user.id,
            setup_action='install'
        )
        
        return jsonify({
            'success': True,
            'installation_result': mock_installation_result
        })
        
    except Exception as e:
        logger.error(f"Error testing installation: {e}")
        return jsonify({'error': str(e)}), 500