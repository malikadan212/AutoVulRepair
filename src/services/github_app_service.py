"""
GitHub App Service
Handles GitHub App authentication, installation management, and API calls
"""

import jwt
import time
import requests
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session

from src.models.github_installation import GitHubInstallation, InstallationRepository, GitHubAppToken

logger = logging.getLogger(__name__)

class GitHubAppService:
    """Service for GitHub App integration"""
    
    def __init__(self, app_id: str, private_key: str, db_session: Session):
        self.app_id = app_id
        self.private_key = private_key
        self.db = db_session
        self.base_url = "https://api.github.com"
        
    def generate_jwt_token(self) -> str:
        """Generate JWT token for GitHub App authentication"""
        try:
            now = int(time.time())
            payload = {
                'iat': now - 60,  # Issued 60 seconds ago
                'exp': now + 300,  # Expires in 5 minutes (GitHub limit is 10 minutes max)
                'iss': self.app_id
            }
            
            return jwt.encode(payload, self.private_key, algorithm='RS256')
        except Exception as e:
            logger.error(f"Failed to generate JWT token: {e}")
            raise
    
    def get_installation_token(self, installation_id: int) -> Optional[str]:
        """Get installation access token (cached)"""
        try:
            # Check if we have a valid cached token
            cached_token = self.db.query(GitHubAppToken).filter(
                GitHubAppToken.installation_id == installation_id,
                GitHubAppToken.expires_at > datetime.utcnow() + timedelta(minutes=5)
            ).first()
            
            if cached_token:
                return cached_token.access_token
            
            # Generate new token
            jwt_token = self.generate_jwt_token()
            
            headers = {
                'Authorization': f'Bearer {jwt_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'AutoVulRepair/1.0'
            }
            
            response = requests.post(
                f"{self.base_url}/app/installations/{installation_id}/access_tokens",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 201:
                token_data = response.json()
                access_token = token_data['token']
                expires_at = datetime.fromisoformat(token_data['expires_at'].replace('Z', '+00:00'))
                
                # Cache the token
                self.cache_installation_token(installation_id, access_token, expires_at)
                
                return access_token
            else:
                logger.error(f"Failed to get installation token: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting installation token: {e}")
            return None
    
    def cache_installation_token(self, installation_id: int, token: str, expires_at: datetime):
        """Cache installation token in database"""
        try:
            # Remove old token
            self.db.query(GitHubAppToken).filter(
                GitHubAppToken.installation_id == installation_id
            ).delete()
            
            # Add new token
            cached_token = GitHubAppToken(
                installation_id=installation_id,
                access_token=token,
                expires_at=expires_at
            )
            
            self.db.add(cached_token)
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Failed to cache installation token: {e}")
            self.db.rollback()
    
    def get_installation_info(self, installation_id: int) -> Optional[Dict]:
        """Get installation details from GitHub"""
        try:
            jwt_token = self.generate_jwt_token()
            
            headers = {
                'Authorization': f'Bearer {jwt_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'AutoVulRepair/1.0'
            }
            
            response = requests.get(
                f"{self.base_url}/app/installations/{installation_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get installation info: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting installation info: {e}")
            return None
    
    def get_installation_repositories(self, installation_id: int) -> List[Dict]:
        """Get repositories accessible through installation"""
        try:
            installation_token = self.get_installation_token(installation_id)
            if not installation_token:
                return []
            
            headers = {
                'Authorization': f'token {installation_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'AutoVulRepair/1.0'
            }
            
            repositories = []
            page = 1
            
            while True:
                response = requests.get(
                    f"{self.base_url}/installation/repositories",
                    headers=headers,
                    params={'page': page, 'per_page': 100},
                    timeout=10
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to get repositories: {response.status_code}")
                    break
                
                data = response.json()
                repositories.extend(data.get('repositories', []))
                
                # Check if there are more pages
                if len(data.get('repositories', [])) < 100:
                    break
                
                page += 1
            
            return repositories
            
        except Exception as e:
            logger.error(f"Error getting installation repositories: {e}")
            return []
    
    def should_auto_enable_repository(self, repo: Dict) -> bool:
        """Determine if repository should have automation enabled automatically"""
        try:
            # Skip archived repositories
            if repo.get('archived', False):
                return False
            
            # Skip forks (unless user specifically wants them)
            if repo.get('fork', False):
                return False
            
            # Check if repository has been updated recently (within 6 months)
            updated_at = repo.get('updated_at')
            if updated_at:
                updated_date = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                six_months_ago = datetime.now() - timedelta(days=180)
                if updated_date < six_months_ago:
                    return False
            
            # Check for C/C++ code (our specialty)
            language = repo.get('language', '').lower()
            cpp_languages = ['c', 'c++', 'cpp', 'objective-c', 'objective-c++']
            
            if language in cpp_languages:
                return True
            
            # For other languages, be more selective
            # Only enable if repository has significant activity
            if repo.get('size', 0) > 100:  # More than 100KB
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error determining auto-enable for repo: {e}")
            return False
    
    def create_pull_request(self, repo_full_name: str, installation_id: int, 
                          title: str, body: str, head_branch: str, base_branch: str = 'main') -> Optional[Dict]:
        """Create pull request using GitHub App token"""
        try:
            installation_token = self.get_installation_token(installation_id)
            if not installation_token:
                return None
            
            headers = {
                'Authorization': f'token {installation_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'AutoVulRepair/1.0'
            }
            
            data = {
                'title': title,
                'body': body,
                'head': head_branch,
                'base': base_branch
            }
            
            response = requests.post(
                f"{self.base_url}/repos/{repo_full_name}/pulls",
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 201:
                return response.json()
            else:
                logger.error(f"Failed to create PR: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating pull request: {e}")
            return None
    
    def create_branch_and_files(self, repo_full_name: str, installation_id: int,
                               branch_name: str, files: List[Dict], base_branch: str = 'main') -> bool:
        """Create branch and add/update files"""
        try:
            installation_token = self.get_installation_token(installation_id)
            if not installation_token:
                return False
            
            headers = {
                'Authorization': f'token {installation_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'AutoVulRepair/1.0'
            }
            
            # Get base branch SHA
            response = requests.get(
                f"{self.base_url}/repos/{repo_full_name}/git/refs/heads/{base_branch}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get base branch SHA: {response.status_code}")
                return False
            
            base_sha = response.json()['object']['sha']
            
            # Create new branch
            branch_data = {
                'ref': f'refs/heads/{branch_name}',
                'sha': base_sha
            }
            
            response = requests.post(
                f"{self.base_url}/repos/{repo_full_name}/git/refs",
                headers=headers,
                json=branch_data,
                timeout=10
            )
            
            if response.status_code != 201:
                logger.error(f"Failed to create branch: {response.status_code}")
                return False
            
            # Add/update files
            for file_info in files:
                file_data = {
                    'message': file_info.get('commit_message', f'Update {file_info["path"]}'),
                    'content': file_info['content'],  # Base64 encoded
                    'branch': branch_name
                }
                
                # Check if file exists
                file_response = requests.get(
                    f"{self.base_url}/repos/{repo_full_name}/contents/{file_info['path']}",
                    headers=headers,
                    params={'ref': branch_name},
                    timeout=10
                )
                
                if file_response.status_code == 200:
                    # File exists, include SHA for update
                    file_data['sha'] = file_response.json()['sha']
                
                # Create/update file
                response = requests.put(
                    f"{self.base_url}/repos/{repo_full_name}/contents/{file_info['path']}",
                    headers=headers,
                    json=file_data,
                    timeout=10
                )
                
                if response.status_code not in [200, 201]:
                    logger.error(f"Failed to update file {file_info['path']}: {response.status_code}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating branch and files: {e}")
            return False