"""
GitHub Webhook Handlers for Real-time Integration
Automatically triggers scans on push, PR creation, etc.
Enhanced for GitHub App integration
"""

import hmac
import hashlib
import json
import logging
from typing import Dict, Optional
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

github_webhooks_bp = Blueprint('github_webhooks', __name__)

class GitHubWebhookHandler:
    """Handle GitHub webhook events for automated scanning"""
    
    def __init__(self, webhook_secret: str):
        self.webhook_secret = webhook_secret
    
    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature"""
        if not signature or not signature.startswith('sha256='):
            return False
        
        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(f'sha256={expected_signature}', signature)
    
    def handle_installation_event(self, payload: Dict) -> Dict:
        """Handle GitHub App installation events"""
        try:
            action = payload.get('action')
            installation = payload.get('installation', {})
            installation_id = installation.get('id')
            
            logger.info(f"GitHub App installation event: {action}, installation_id: {installation_id}")
            
            if action == 'created':
                # New installation - this is handled by the callback URL
                return {'status': 'acknowledged', 'action': action}
            
            elif action == 'deleted':
                # Installation deleted - deactivate in our system
                from src.routes.github_app_routes import installation_service
                if installation_service:
                    result = installation_service.handle_installation_deleted(installation_id)
                    return {'status': 'processed', 'action': action, 'result': result}
                
            elif action in ['suspend', 'unsuspend']:
                # Installation suspended/unsuspended
                logger.info(f"Installation {installation_id} {action}")
                return {'status': 'acknowledged', 'action': action}
            
            return {'status': 'ignored', 'action': action}
            
        except Exception as e:
            logger.error(f"Error handling installation event: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def handle_push_event(self, payload: Dict) -> Dict:
        """Handle repository push events"""
        try:
            repo_full_name = payload['repository']['full_name']
            branch = payload['ref'].split('/')[-1]
            commit_sha = payload['after']
            
            logger.info(f"Push event: {repo_full_name}, branch: {branch}, commit: {commit_sha[:8]}")
            
            # Get repository from installation service
            from src.routes.github_app_routes import installation_service
            if not installation_service:
                return {'status': 'error', 'error': 'Installation service not available'}
            
            repo = installation_service.get_repository_for_webhook(repo_full_name)
            if not repo:
                return {'status': 'skipped', 'reason': 'Repository not found or automation disabled'}
            
            # Check if we should scan this branch
            if not repo.auto_scan_on_push:
                return {'status': 'skipped', 'reason': 'Auto-scan on push disabled'}
            
            # Only scan main/master branches by default (configurable)
            main_branches = ['main', 'master', 'develop']
            if branch not in main_branches:
                return {'status': 'skipped', 'reason': f'Branch {branch} not in scan list'}
            
            # Create automated scan
            from src.services.scan_service import scan_service
            result = scan_service.create_scan(
                source_type='repository',
                repo_url=payload['repository']['clone_url'],
                analysis_tool='cppcheck',
                automated=True,
                trigger='push_event',
                github_installation_id=repo.installation.installation_id,
                metadata={
                    'branch': branch,
                    'commit_sha': commit_sha,
                    'pusher': payload.get('pusher', {}).get('name', 'unknown'),
                    'repository_full_name': repo_full_name
                }
            )
            
            # Update repository last scan info
            from datetime import datetime
            repo.last_scanned_at = datetime.utcnow()
            repo.last_scan_status = 'running'
            
            # Commit the update
            from src.database.connection import get_session
            db = get_session()
            db.commit()
            
            logger.info(f"Started automated scan for {repo_full_name}: {result.get('scan_id')}")
            
            return {
                'status': 'scan_started',
                'scan_id': result.get('scan_id'),
                'repository': repo_full_name,
                'branch': branch,
                'commit': commit_sha[:8]
            }
            
        except Exception as e:
            logger.error(f"Error handling push event: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def handle_pull_request_event(self, payload: Dict) -> Dict:
        """Handle pull request events"""
        try:
            action = payload.get('action')
            if action not in ['opened', 'synchronize', 'reopened']:
                return {'status': 'skipped', 'reason': f'PR action {action} not triggering scan'}
            
            repo_full_name = payload['repository']['full_name']
            pr_number = payload['pull_request']['number']
            
            logger.info(f"PR event: {repo_full_name}, PR #{pr_number}, action: {action}")
            
            # Get repository from installation service
            from src.routes.github_app_routes import installation_service
            if not installation_service:
                return {'status': 'error', 'error': 'Installation service not available'}
            
            repo = installation_service.get_repository_for_webhook(repo_full_name)
            if not repo:
                return {'status': 'skipped', 'reason': 'Repository not found or automation disabled'}
            
            # Check if we should scan PRs
            if not repo.auto_scan_on_pr:
                return {'status': 'skipped', 'reason': 'Auto-scan on PR disabled'}
            
            # Create PR-specific scan
            from src.services.scan_service import scan_service
            result = scan_service.create_scan(
                source_type='pull_request',
                repo_url=payload['repository']['clone_url'],
                analysis_tool='cppcheck',
                automated=True,
                trigger='pull_request',
                github_installation_id=repo.installation.installation_id,
                metadata={
                    'pr_number': pr_number,
                    'pr_title': payload['pull_request']['title'],
                    'author': payload['pull_request']['user']['login'],
                    'base_branch': payload['pull_request']['base']['ref'],
                    'head_branch': payload['pull_request']['head']['ref'],
                    'head_sha': payload['pull_request']['head']['sha'],
                    'repository_full_name': repo_full_name
                }
            )
            
            logger.info(f"Started PR scan for {repo_full_name} PR #{pr_number}: {result.get('scan_id')}")
            
            return {
                'status': 'scan_started',
                'scan_id': result.get('scan_id'),
                'repository': repo_full_name,
                'pr_number': pr_number,
                'action': action
            }
            
        except Exception as e:
            logger.error(f"Error handling pull request event: {e}")
            return {'status': 'error', 'error': str(e)}

# Global webhook handler instance
webhook_handler = None

def init_webhook_handler(webhook_secret: str):
    """Initialize webhook handler"""
    global webhook_handler
    webhook_handler = GitHubWebhookHandler(webhook_secret)

@github_webhooks_bp.route('/webhook/github', methods=['POST'])
def handle_github_webhook():
    """Main GitHub webhook endpoint"""
    from datetime import datetime
    from src.models.webhook_event import WebhookEvent
    from src.database.connection import get_session
    
    webhook_event = None
    db = None
    
    try:
        if not webhook_handler:
            logger.error("Webhook handler not initialized")
            return jsonify({'error': 'Webhook handler not available'}), 500
        
        # Get event info
        event_type = request.headers.get('X-GitHub-Event')
        delivery_id = request.headers.get('X-GitHub-Delivery')
        signature = request.headers.get('X-Hub-Signature-256')
        
        logger.info(f"Webhook received: event={event_type}, delivery={delivery_id}")
        
        # Get payload
        payload = request.get_data()
        
        # Verify signature
        if not webhook_handler.verify_signature(payload, signature):
            logger.warning(f"Invalid webhook signature for delivery {delivery_id}")
            return jsonify({'error': 'Invalid signature'}), 403
        
        # Parse JSON
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in webhook payload: {e}")
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Create webhook event record
        try:
            db = get_session()
            webhook_event = WebhookEvent(
                delivery_id=delivery_id,
                event_type=event_type,
                action=data.get('action'),
                repository_full_name=data.get('repository', {}).get('full_name'),
                installation_id=data.get('installation', {}).get('id'),
                sender_login=data.get('sender', {}).get('login'),
                status='received',
                payload_summary={
                    'ref': data.get('ref'),
                    'before': data.get('before', '')[:8] if data.get('before') else None,
                    'after': data.get('after', '')[:8] if data.get('after') else None,
                    'pr_number': data.get('pull_request', {}).get('number'),
                    'pr_title': data.get('pull_request', {}).get('title')
                }
            )
            db.add(webhook_event)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create webhook event record: {e}")
            if db:
                db.rollback()
        
        # Route to appropriate handler
        if event_type == 'installation':
            result = webhook_handler.handle_installation_event(data)
        elif event_type == 'push':
            result = webhook_handler.handle_push_event(data)
        elif event_type == 'pull_request':
            result = webhook_handler.handle_pull_request_event(data)
        else:
            logger.info(f"Ignoring webhook event: {event_type}")
            result = {'status': 'ignored', 'event': event_type}
        
        # Update webhook event with result
        if webhook_event and db:
            try:
                webhook_event.status = result.get('status', 'processed')
                webhook_event.scan_id = result.get('scan_id')
                webhook_event.error_message = result.get('error') or result.get('reason')
                webhook_event.processed_at = datetime.utcnow()
                db.commit()
            except Exception as e:
                logger.warning(f"Failed to update webhook event: {e}")
                db.rollback()
        
        logger.info(f"Webhook processed: {result.get('status')} for {event_type}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Webhook handling error: {e}")
        
        # Mark webhook as failed
        if webhook_event and db:
            try:
                webhook_event.status = 'failed'
                webhook_event.error_message = str(e)
                webhook_event.processed_at = datetime.utcnow()
                db.commit()
            except:
                pass
        
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        if db:
            db.close()