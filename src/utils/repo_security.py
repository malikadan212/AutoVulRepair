"""
Repository Security Utilities
Provides security functions for safely handling cloned repositories
"""

import os
import shutil
import logging
import requests
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class RepoSecurityManager:
    """Manages security for cloned repositories"""
    
    # Maximum repository size in MB
    MAX_REPO_SIZE_MB = 100
    
    # Allowed file extensions for analysis
    ALLOWED_EXTENSIONS = {
        '.c', '.cpp', '.cc', '.cxx', '.c++',
        '.h', '.hpp', '.hxx', '.h++', '.hh',
        '.C', '.H'  # Some projects use uppercase
    }
    
    # Dangerous files/directories to remove
    DANGEROUS_PATTERNS = {
        '.git/hooks',  # Git hooks can execute code
        'Makefile',    # Build scripts
        'CMakeLists.txt',
        '*.sh',        # Shell scripts
        '*.bat',       # Batch scripts
        '*.ps1',       # PowerShell scripts
        '*.exe',       # Executables
        '*.dll',       # Libraries
        '*.so',        # Shared objects
        '*.dylib',     # macOS libraries
    }
    
    def check_repo_size(self, repo_url: str) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Check repository size via GitHub API before cloning
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Tuple of (is_safe, size_kb, error_message)
        """
        try:
            # Parse GitHub URL
            # Expected format: https://github.com/owner/repo or https://github.com/owner/repo/
            parts = repo_url.rstrip('/').split('/')
            if len(parts) < 5 or 'github.com' not in repo_url:
                return True, None, None  # Not a GitHub URL, skip check
            
            owner = parts[-2]
            repo = parts[-1].replace('.git', '')
            
            # Call GitHub API
            api_url = f'https://api.github.com/repos/{owner}/{repo}'
            response = requests.get(api_url, timeout=10)
            
            if response.status_code != 200:
                logger.warning(f"[REPO_SECURITY] Could not check repo size: {response.status_code}")
                return True, None, None  # Allow if API fails
            
            data = response.json()
            size_kb = data.get('size', 0)  # Size in KB
            size_mb = size_kb / 1024
            
            if size_mb > self.MAX_REPO_SIZE_MB:
                error_msg = f"Repository too large: {size_mb:.1f}MB (max: {self.MAX_REPO_SIZE_MB}MB)"
                logger.warning(f"[REPO_SECURITY] {error_msg}")
                return False, size_kb, error_msg
            
            logger.info(f"[REPO_SECURITY] Repository size: {size_mb:.1f}MB - OK")
            return True, size_kb, None
            
        except Exception as e:
            logger.warning(f"[REPO_SECURITY] Error checking repo size: {e}")
            return True, None, None  # Allow if check fails
    
    def sanitize_cloned_repo(self, repo_dir: str) -> int:
        """
        Remove dangerous files and keep only source files
        
        Args:
            repo_dir: Path to cloned repository
            
        Returns:
            Number of files removed
        """
        removed_count = 0
        
        try:
            # Remove git hooks
            hooks_dir = os.path.join(repo_dir, '.git', 'hooks')
            if os.path.exists(hooks_dir):
                shutil.rmtree(hooks_dir, ignore_errors=True)
                logger.info(f"[REPO_SECURITY] Removed git hooks directory")
                removed_count += 1
            
            # Walk through repository and remove non-source files
            for root, dirs, files in os.walk(repo_dir):
                # Skip .git directory
                if '.git' in root:
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    file_ext = Path(file).suffix.lower()
                    
                    # Keep only allowed source files
                    if file_ext not in self.ALLOWED_EXTENSIONS:
                        try:
                            os.remove(file_path)
                            removed_count += 1
                        except Exception as e:
                            logger.debug(f"[REPO_SECURITY] Could not remove {file}: {e}")
            
            logger.info(f"[REPO_SECURITY] Sanitized repository: removed {removed_count} non-source files")
            return removed_count
            
        except Exception as e:
            logger.error(f"[REPO_SECURITY] Error sanitizing repository: {e}")
            return removed_count
    
    def set_readonly_permissions(self, repo_dir: str) -> bool:
        """
        Set directory to read-only to prevent modifications
        
        Args:
            repo_dir: Path to repository
            
        Returns:
            True if successful
        """
        try:
            # On Unix systems, set to read + execute only
            if os.name != 'nt':  # Not Windows
                os.chmod(repo_dir, 0o555)
                logger.info(f"[REPO_SECURITY] Set read-only permissions on {repo_dir}")
            return True
        except Exception as e:
            logger.warning(f"[REPO_SECURITY] Could not set read-only permissions: {e}")
            return False
    
    def schedule_cleanup(self, repo_dir: str, hours: int = 24) -> None:
        """
        Schedule repository cleanup after specified hours
        
        Args:
            repo_dir: Path to repository
            hours: Hours until cleanup (default: 24)
        """
        # This would integrate with a cleanup scheduler
        # For now, just log the intent
        logger.info(f"[REPO_SECURITY] Repository {repo_dir} scheduled for cleanup in {hours} hours")
        # TODO: Implement actual scheduling (Celery task, cron, etc.)
