"""
GitHub App Installation Management Service
Handles installation lifecycle, repository management, and automation settings
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session

from src.models.github_installation import GitHubInstallation, InstallationRepository
from src.services.github_app_service import GitHubAppService

logger = logging.getLogger(__name__)

class InstallationService:
    """Service for managing GitHub App installations"""
    
    def __init__(self, db_session: Session, github_app_service: GitHubAppService):
        self.db = db_session
        self.github_app = github_app_service
    
    def handle_new_installation(self, installation_id: int, user_id: str, 
                               setup_action: str = 'install') -> Dict[str, Any]:
        """Handle new GitHub App installation"""
        try:
            logger.info(f"Processing new installation {installation_id} for user {user_id}")
            
            # Get installation details from GitHub
            installation_info = self.github_app.get_installation_info(installation_id)
            if not installation_info:
                return {'success': False, 'error': 'Failed to get installation info'}
            
            # Create installation record
            installation = GitHubInstallation(
                installation_id=installation_id,
                user_id=user_id,
                github_account_login=installation_info['account']['login'],
                github_account_id=installation_info['account']['id'],
                github_account_type=installation_info['account']['type'],
                repository_selection=installation_info.get('repository_selection', 'all'),
                permissions=installation_info.get('permissions', {})
            )
            
            self.db.add(installation)
            self.db.flush()  # Get the ID
            
            # Get repositories and set up automation
            repositories = self.github_app.get_installation_repositories(installation_id)
            enabled_repos = []
            skipped_repos = []
            
            for repo in repositories:
                repo_record = InstallationRepository(
                    installation_id=installation.id,
                    repository_full_name=repo['full_name'],
                    repository_id=repo['id'],
                    repository_name=repo['name'],
                    repository_private=repo['private'],
                    repository_language=repo.get('language'),
                    automation_enabled=False  # Start disabled, enable selectively
                )
                
                # Determine if we should auto-enable automation
                if self.github_app.should_auto_enable_repository(repo):
                    repo_record.automation_enabled = True
                    enabled_repos.append(repo['full_name'])
                    logger.info(f"Auto-enabled automation for {repo['full_name']}")
                else:
                    skipped_repos.append(repo['full_name'])
                    logger.info(f"Skipped automation for {repo['full_name']}")
                
                self.db.add(repo_record)
            
            self.db.commit()
            
            logger.info(f"Installation {installation_id} processed successfully: "
                       f"{len(enabled_repos)} enabled, {len(skipped_repos)} skipped")
            
            return {
                'success': True,
                'installation_id': installation_id,
                'total_repositories': len(repositories),
                'enabled_repositories': len(enabled_repos),
                'skipped_repositories': len(skipped_repos),
                'enabled_repos': enabled_repos,
                'skipped_repos': skipped_repos
            }
            
        except Exception as e:
            logger.error(f"Error handling new installation: {e}")
            self.db.rollback()
            return {'success': False, 'error': str(e)}
    
    def get_user_installations(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all GitHub App installations for a user"""
        try:
            logger.info(f"[INSTALLATION_SERVICE] Getting installations for user_id: {user_id}")
            
            # Use text() to avoid type casting issues
            from sqlalchemy import text
            
            # Query using raw SQL to avoid UUID casting issue
            query = text("""
                SELECT installation_id, user_id, github_account_login, github_account_id,
                       github_account_type, repository_selection, permissions, is_active,
                       installed_at, updated_at
                FROM github_installations
                WHERE user_id = :user_id AND is_active = true
            """)
            
            installations_raw = self.db.execute(query, {'user_id': user_id}).fetchall()
            
            logger.info(f"[INSTALLATION_SERVICE] Found {len(installations_raw)} installations")
            
            result = []
            for inst in installations_raw:
                # Count repositories for this installation
                repo_query = text("""
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN automation_enabled THEN 1 ELSE 0 END) as enabled
                    FROM installation_repositories ir
                    JOIN github_installations gi ON ir.installation_id = gi.id
                    WHERE gi.installation_id = :installation_id AND ir.is_active = true
                """)
                
                repo_counts = self.db.execute(repo_query, {'installation_id': inst[0]}).fetchone()
                total_repos = repo_counts[0] if repo_counts else 0
                enabled_repos = repo_counts[1] if repo_counts else 0
                
                logger.info(f"[INSTALLATION_SERVICE] Installation {inst[0]}: {total_repos} repos, {enabled_repos} enabled")
                
                result.append({
                    'installation_id': inst[0],
                    'github_account': inst[2],
                    'account_type': inst[4],
                    'repository_selection': inst[5],
                    'total_repositories': total_repos,
                    'enabled_repositories': enabled_repos,
                    'installed_at': inst[8].isoformat() if inst[8] else None,
                    'permissions': inst[6]
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting user installations: {e}", exc_info=True)
            return []
    
    def get_user_repositories(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all repositories accessible through user's installations"""
        try:
            from sqlalchemy import text
            
            logger.info(f"[INSTALLATION_SERVICE] Getting repositories for user_id: {user_id}")
            
            # Simpler query without complex joins
            query = text("""
                SELECT ir.repository_id, ir.repository_full_name, ir.repository_name,
                       ir.repository_private, ir.repository_language, ir.automation_enabled,
                       ir.auto_scan_on_push, ir.auto_create_prs, ir.auto_scan_on_pr,
                       ir.last_scanned_at, ir.last_scan_status, ir.settings,
                       gi.installation_id, gi.github_account_login
                FROM installation_repositories ir
                JOIN github_installations gi ON ir.installation_id = gi.id
                WHERE gi.user_id = :user_id 
                  AND gi.is_active = true 
                  AND ir.is_active = true
            """)
            
            repositories = self.db.execute(query, {'user_id': user_id}).fetchall()
            
            logger.info(f"[INSTALLATION_SERVICE] Found {len(repositories)} repositories")
            
            result = []
            for repo in repositories:
                # Get last scan from scans table
                scan_query = text("""
                    SELECT created_at, status 
                    FROM scans 
                    WHERE repo_url LIKE :repo_pattern 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """)
                last_scan = self.db.execute(scan_query, {'repo_pattern': f'%{repo[1]}%'}).fetchone()
                
                last_scan_date = last_scan[0] if last_scan else repo[9]
                last_scan_status = last_scan[1] if last_scan else repo[10]
                
                result.append({
                    'repository_id': repo[0],
                    'full_name': repo[1],
                    'name': repo[2],
                    'private': repo[3],
                    'language': repo[4],
                    'automation_enabled': repo[5],
                    'auto_scan_on_push': repo[6],
                    'auto_create_prs': repo[7],
                    'auto_scan_on_pr': repo[8],
                    'last_scanned_at': last_scan_date.isoformat() if last_scan_date else None,
                    'last_scan_status': last_scan_status,
                    'settings': repo[11],
                    'installation_id': repo[12],
                    'github_account': repo[13]
                })
            
            logger.info(f"[INSTALLATION_SERVICE] Returning {len(result)} repositories")
            return result
            
        except Exception as e:
            logger.error(f"Error getting user repositories: {e}", exc_info=True)
            return []
    
    def toggle_repository_automation(self, user_id: str, repo_full_name: str, 
                                   enabled: bool) -> Dict[str, Any]:
        """Enable or disable automation for a specific repository"""
        try:
            repository = self.db.query(InstallationRepository).join(
                GitHubInstallation,
                InstallationRepository.installation_id == GitHubInstallation.id
            ).filter(
                GitHubInstallation.user_id == user_id,
                InstallationRepository.repository_full_name == repo_full_name,
                GitHubInstallation.is_active == True,
                InstallationRepository.is_active == True
            ).first()
            
            if not repository:
                return {'success': False, 'error': 'Repository not found'}
            
            repository.automation_enabled = enabled
            repository.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            logger.info(f"{'Enabled' if enabled else 'Disabled'} automation for {repo_full_name}")
            
            return {
                'success': True,
                'repository': repo_full_name,
                'automation_enabled': enabled
            }
            
        except Exception as e:
            logger.error(f"Error toggling repository automation: {e}")
            self.db.rollback()
            return {'success': False, 'error': str(e)}
    
    def update_repository_settings(self, user_id: str, repo_full_name: str, 
                                 settings: Dict[str, Any]) -> Dict[str, Any]:
        """Update automation settings for a repository"""
        try:
            repository = self.db.query(InstallationRepository).join(
                GitHubInstallation,
                InstallationRepository.installation_id == GitHubInstallation.id
            ).filter(
                GitHubInstallation.user_id == user_id,
                InstallationRepository.repository_full_name == repo_full_name,
                GitHubInstallation.is_active == True,
                InstallationRepository.is_active == True
            ).first()
            
            if not repository:
                return {'success': False, 'error': 'Repository not found'}
            
            # Update individual settings
            if 'auto_scan_on_push' in settings:
                repository.auto_scan_on_push = settings['auto_scan_on_push']
            
            if 'auto_create_prs' in settings:
                repository.auto_create_prs = settings['auto_create_prs']
            
            if 'auto_scan_on_pr' in settings:
                repository.auto_scan_on_pr = settings['auto_scan_on_pr']
            
            # Update settings JSON
            if 'settings' in settings:
                current_settings = repository.settings or {}
                current_settings.update(settings['settings'])
                repository.settings = current_settings
            
            repository.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            logger.info(f"Updated settings for {repo_full_name}: {settings}")
            
            return {
                'success': True,
                'repository': repo_full_name,
                'settings': {
                    'auto_scan_on_push': repository.auto_scan_on_push,
                    'auto_create_prs': repository.auto_create_prs,
                    'auto_scan_on_pr': repository.auto_scan_on_pr,
                    'settings': repository.settings
                }
            }
            
        except Exception as e:
            logger.error(f"Error updating repository settings: {e}")
            self.db.rollback()
            return {'success': False, 'error': str(e)}
    
    def get_repository_for_webhook(self, repo_full_name: str) -> Optional[InstallationRepository]:
        """Get repository record for webhook processing"""
        try:
            return self.db.query(InstallationRepository).join(
                GitHubInstallation,
                InstallationRepository.installation_id == GitHubInstallation.id
            ).filter(
                InstallationRepository.repository_full_name == repo_full_name,
                InstallationRepository.automation_enabled == True,
                GitHubInstallation.is_active == True,
                InstallationRepository.is_active == True
            ).first()
            
        except Exception as e:
            logger.error(f"Error getting repository for webhook: {e}")
            return None
    
    def handle_installation_deleted(self, installation_id: int) -> Dict[str, Any]:
        """Handle GitHub App installation deletion"""
        try:
            installation = self.db.query(GitHubInstallation).filter(
                GitHubInstallation.installation_id == installation_id
            ).first()
            
            if installation:
                installation.is_active = False
                installation.updated_at = datetime.utcnow()
                
                # Deactivate all repositories
                for repo in installation.repositories:
                    repo.is_active = False
                    repo.automation_enabled = False
                    repo.updated_at = datetime.utcnow()
                
                self.db.commit()
                
                logger.info(f"Deactivated installation {installation_id}")
                
                return {'success': True, 'installation_id': installation_id}
            else:
                return {'success': False, 'error': 'Installation not found'}
                
        except Exception as e:
            logger.error(f"Error handling installation deletion: {e}")
            self.db.rollback()
            return {'success': False, 'error': str(e)}