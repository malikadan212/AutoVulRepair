"""
Enterprise Authentication Integration
SAML, OIDC, and multi-provider SSO support
"""

import logging
from typing import Dict, Optional, Any
from flask import Blueprint, request, redirect, url_for, session, flash
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client import OAuthError

logger = logging.getLogger(__name__)

enterprise_auth_bp = Blueprint('enterprise_auth', __name__)

class EnterpriseAuthProvider:
    """Enterprise authentication provider manager"""
    
    def __init__(self, app=None):
        self.app = app
        self.oauth = OAuth()
        self.providers = {}
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
        self.oauth.init_app(app)
        
        # Register configured providers
        self._register_github_enterprise()
        self._register_azure_ad()
        self._register_okta()
        self._register_google_workspace()
    
    def _register_github_enterprise(self):
        """Register GitHub Enterprise Server"""
        github_config = self.app.config.get('GITHUB_ENTERPRISE', {})
        
        if github_config.get('enabled'):
            self.providers['github_enterprise'] = self.oauth.register(
                name='github_enterprise',
                client_id=github_config['client_id'],
                client_secret=github_config['client_secret'],
                server_metadata_url=f"{github_config['base_url']}/.well-known/openid_configuration",
                client_kwargs={
                    'scope': 'openid email profile'
                }
            )
    
    def _register_azure_ad(self):
        """Register Azure Active Directory"""
        azure_config = self.app.config.get('AZURE_AD', {})
        
        if azure_config.get('enabled'):
            self.providers['azure_ad'] = self.oauth.register(
                name='azure_ad',
                client_id=azure_config['client_id'],
                client_secret=azure_config['client_secret'],
                server_metadata_url=f"https://login.microsoftonline.com/{azure_config['tenant_id']}/v2.0/.well-known/openid_configuration",
                client_kwargs={
                    'scope': 'openid email profile'
                }
            )
    
    def _register_okta(self):
        """Register Okta OIDC"""
        okta_config = self.app.config.get('OKTA', {})
        
        if okta_config.get('enabled'):
            self.providers['okta'] = self.oauth.register(
                name='okta',
                client_id=okta_config['client_id'],
                client_secret=okta_config['client_secret'],
                server_metadata_url=f"{okta_config['domain']}/.well-known/openid_configuration",
                client_kwargs={
                    'scope': 'openid email profile groups'
                }
            )
    
    def _register_google_workspace(self):
        """Register Google Workspace"""
        google_config = self.app.config.get('GOOGLE_WORKSPACE', {})
        
        if google_config.get('enabled'):
            self.providers['google_workspace'] = self.oauth.register(
                name='google_workspace',
                client_id=google_config['client_id'],
                client_secret=google_config['client_secret'],
                server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
                client_kwargs={
                    'scope': 'openid email profile',
                    'hd': google_config.get('hosted_domain')  # Restrict to organization domain
                }
            )
    
    def get_available_providers(self) -> Dict[str, Dict[str, Any]]:
        """Get list of available authentication providers"""
        available = {}
        
        for name, provider in self.providers.items():
            config_key = name.upper().replace('_', '_')
            config = self.app.config.get(config_key, {})
            
            available[name] = {
                'name': name,
                'display_name': config.get('display_name', name.replace('_', ' ').title()),
                'icon': config.get('icon', 'key'),
                'enabled': config.get('enabled', False),
                'login_url': url_for('enterprise_auth.login', provider=name)
            }
        
        return available
    
    def authenticate_user(self, provider_name: str, user_info: Dict) -> Dict[str, Any]:
        """Process user authentication from provider"""
        try:
            # Extract standard user information
            user_data = {
                'provider': provider_name,
                'provider_id': user_info.get('sub') or user_info.get('id'),
                'email': user_info.get('email'),
                'name': user_info.get('name'),
                'username': user_info.get('preferred_username') or user_info.get('login'),
                'avatar_url': user_info.get('picture') or user_info.get('avatar_url'),
                'groups': user_info.get('groups', []),
                'organization': self._extract_organization(provider_name, user_info)
            }
            
            # Validate required fields
            if not user_data['provider_id'] or not user_data['email']:
                raise ValueError("Missing required user information")
            
            return user_data
            
        except Exception as e:
            logger.error(f"Failed to authenticate user from {provider_name}: {e}")
            raise
    
    def _extract_organization(self, provider_name: str, user_info: Dict) -> Optional[str]:
        """Extract organization information from user data"""
        if provider_name == 'github_enterprise':
            return user_info.get('company')
        elif provider_name == 'azure_ad':
            return user_info.get('tid')  # Tenant ID
        elif provider_name == 'okta':
            return user_info.get('org')
        elif provider_name == 'google_workspace':
            return user_info.get('hd')  # Hosted domain
        
        return None

# Initialize global provider manager
auth_provider = EnterpriseAuthProvider()

@enterprise_auth_bp.route('/auth/login/<provider>')
def login(provider):
    """Initiate login with specified provider"""
    try:
        if provider not in auth_provider.providers:
            flash(f'Authentication provider "{provider}" not available', 'error')
            return redirect(url_for('home'))
        
        oauth_provider = auth_provider.providers[provider]
        redirect_uri = url_for('enterprise_auth.callback', provider=provider, _external=True)
        
        return oauth_provider.authorize_redirect(redirect_uri)
        
    except Exception as e:
        logger.error(f"Login initiation failed for {provider}: {e}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('home'))

@enterprise_auth_bp.route('/auth/callback/<provider>')
def callback(provider):
    """Handle authentication callback"""
    try:
        if provider not in auth_provider.providers:
            flash('Invalid authentication provider', 'error')
            return redirect(url_for('home'))
        
        oauth_provider = auth_provider.providers[provider]
        
        # Get access token
        token = oauth_provider.authorize_access_token()
        
        # Get user info
        user_info = oauth_provider.parse_id_token(token)
        
        # Process authentication
        user_data = auth_provider.authenticate_user(provider, user_info)
        
        # Create or update user in database
        from src.services.user_service import user_service
        user = user_service.create_or_update_enterprise_user(user_data)
        
        # Log in user
        from flask_login import login_user
        login_user(user, remember=True)
        
        # Store provider info in session
        session['auth_provider'] = provider
        session['provider_token'] = token
        
        flash('Successfully logged in', 'success')
        return redirect(url_for('dashboard'))
        
    except OAuthError as e:
        logger.error(f"OAuth error for {provider}: {e}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"Authentication callback failed for {provider}: {e}")
        flash('Authentication failed. Please contact support.', 'error')
        return redirect(url_for('home'))

@enterprise_auth_bp.route('/auth/providers')
def list_providers():
    """API endpoint to list available providers"""
    return auth_provider.get_available_providers()