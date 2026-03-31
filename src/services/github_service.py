"""
GitHub API Service
Secure integration with GitHub API for repository and PR management
"""

import requests
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class GitHubService:
    """Secure GitHub API integration service"""
    
    def __init__(self, access_token: str):
        """Initialize with user's GitHub access token"""
        if not access_token:
            raise ValueError("GitHub access token is required")
        
        self.access_token = access_token
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {access_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AutoVulRepair-DevSecOps/1.0'
        })
        
        # Rate limiting tracking
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make secure API request with error handling and rate limiting"""
        try:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            
            # Check rate limiting
            if self.rate_limit_remaining is not None and self.rate_limit_remaining < 10:
                logger.warning("GitHub API rate limit low, skipping request")
                return None
            
            response = self.session.get(url, params=params, timeout=10)
            
            # Update rate limit info
            self.rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            self.rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                logger.warning("GitHub API rate limit exceeded")
                return None
            elif response.status_code == 401:
                logger.error("GitHub API authentication failed")
                return None
            else:
                logger.error(f"GitHub API error: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in GitHub API request: {e}")
            return None
    
    def get_user_repositories(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's repositories with security filtering"""
        try:
            # Get user's own repositories
            repos_data = self._make_request('/user/repos', {
                'type': 'owner',  # Only repos owned by user
                'sort': 'updated',
                'per_page': min(limit, 100),  # GitHub max is 100
                'page': 1
            })
            
            if not repos_data:
                return []
            
            # Filter and sanitize repository data
            filtered_repos = []
            for repo in repos_data:
                # Security checks
                if not repo.get('owner', {}).get('login'):
                    continue
                
                # Only include repositories with safe data
                safe_repo = {
                    'id': repo.get('id'),
                    'name': repo.get('name', ''),
                    'full_name': repo.get('full_name', ''),
                    'description': repo.get('description', '')[:200] if repo.get('description') else '',
                    'private': repo.get('private', True),
                    'html_url': repo.get('html_url', ''),
                    'clone_url': repo.get('clone_url', ''),
                    'updated_at': repo.get('updated_at', ''),
                    'language': repo.get('language', ''),
                    'size': repo.get('size', 0),
                    'default_branch': repo.get('default_branch', 'main')
                }
                
                # Validate required fields
                if safe_repo['id'] and safe_repo['name'] and safe_repo['full_name']:
                    filtered_repos.append(safe_repo)
            
            logger.info(f"Retrieved {len(filtered_repos)} repositories for user")
            return filtered_repos
            
        except Exception as e:
            logger.error(f"Error getting user repositories: {e}")
            return []
    
    def get_repository_pulls(self, repo_full_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent pull requests for a repository"""
        try:
            # Validate repository name format
            if not repo_full_name or '/' not in repo_full_name:
                logger.error("Invalid repository name format")
                return []
            
            # Split and validate owner/repo
            parts = repo_full_name.split('/')
            if len(parts) != 2 or not all(parts):
                logger.error("Invalid repository name format")
                return []
            
            owner, repo = parts
            
            # Get pull requests
            pulls_data = self._make_request(f'/repos/{owner}/{repo}/pulls', {
                'state': 'open',
                'sort': 'updated',
                'per_page': min(limit, 30),
                'page': 1
            })
            
            if not pulls_data:
                return []
            
            # Filter and sanitize PR data
            filtered_pulls = []
            for pr in pulls_data:
                safe_pr = {
                    'id': pr.get('id'),
                    'number': pr.get('number'),
                    'title': pr.get('title', '')[:100] if pr.get('title') else '',
                    'state': pr.get('state', ''),
                    'created_at': pr.get('created_at', ''),
                    'updated_at': pr.get('updated_at', ''),
                    'html_url': pr.get('html_url', ''),
                    'head': {
                        'sha': pr.get('head', {}).get('sha', ''),
                        'ref': pr.get('head', {}).get('ref', '')
                    },
                    'base': {
                        'sha': pr.get('base', {}).get('sha', ''),
                        'ref': pr.get('base', {}).get('ref', '')
                    },
                    'user': {
                        'login': pr.get('user', {}).get('login', '')
                    }
                }
                
                # Validate required fields
                if safe_pr['id'] and safe_pr['number'] and safe_pr['title']:
                    filtered_pulls.append(safe_pr)
            
            logger.info(f"Retrieved {len(filtered_pulls)} pull requests for {repo_full_name}")
            return filtered_pulls
            
        except Exception as e:
            logger.error(f"Error getting repository pulls: {e}")
            return []
    
    def get_pull_request_files(self, repo_full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get files changed in a pull request"""
        try:
            # Validate inputs
            if not repo_full_name or '/' not in repo_full_name:
                return []
            
            if not isinstance(pr_number, int) or pr_number <= 0:
                return []
            
            parts = repo_full_name.split('/')
            if len(parts) != 2:
                return []
            
            owner, repo = parts
            
            # Get PR files
            files_data = self._make_request(f'/repos/{owner}/{repo}/pulls/{pr_number}/files')
            
            if not files_data:
                return []
            
            # Filter and sanitize file data
            filtered_files = []
            for file_info in files_data:
                # Only include files that are likely source code
                filename = file_info.get('filename', '')
                if not filename:
                    continue
                
                # Security: Filter file types
                allowed_extensions = {'.c', '.cpp', '.h', '.hpp', '.py', '.js', '.ts', '.java', '.go', '.rs'}
                if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
                    continue
                
                safe_file = {
                    'filename': filename,
                    'status': file_info.get('status', ''),
                    'additions': file_info.get('additions', 0),
                    'deletions': file_info.get('deletions', 0),
                    'changes': file_info.get('changes', 0),
                    'patch': file_info.get('patch', '')[:5000]  # Limit patch size
                }
                
                filtered_files.append(safe_file)
            
            logger.info(f"Retrieved {len(filtered_files)} changed files for PR #{pr_number}")
            return filtered_files
            
        except Exception as e:
            logger.error(f"Error getting PR files: {e}")
            return []
    
    def validate_repository_access(self, repo_full_name: str) -> bool:
        """Validate that user has access to repository"""
        try:
            if not repo_full_name or '/' not in repo_full_name:
                return False
            
            parts = repo_full_name.split('/')
            if len(parts) != 2:
                return False
            
            owner, repo = parts
            
            # Check if user has access to repository
            repo_data = self._make_request(f'/repos/{owner}/{repo}')
            
            return repo_data is not None
            
        except Exception as e:
            logger.error(f"Error validating repository access: {e}")
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get current rate limit status"""
        return {
            'remaining': self.rate_limit_remaining,
            'reset_time': datetime.fromtimestamp(self.rate_limit_reset) if self.rate_limit_reset else None
        }