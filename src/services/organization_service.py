"""
Organization Management Service
Handles multi-tenancy, teams, and enterprise features
"""

import logging
import hashlib
import secrets
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from src.models.organization import Organization, Team, TeamMember, APIKey

logger = logging.getLogger(__name__)

class OrganizationService:
    """Service for managing organizations and teams"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def create_organization(self, name: str, display_name: str, 
                          github_org_id: str = None, 
                          plan_type: str = 'free') -> Organization:
        """Create a new organization"""
        try:
            org = Organization(
                name=name,
                display_name=display_name,
                github_org_id=github_org_id,
                plan_type=plan_type
            )
            
            self.db.add(org)
            self.db.commit()
            
            # Create default team
            self.create_team(
                org.id,
                name='Default',
                description='Default team for all organization members'
            )
            
            logger.info(f"Created organization: {name} ({org.id})")
            return org
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to create organization: {e}")
            raise
    
    def get_organization_by_github_id(self, github_org_id: str) -> Optional[Organization]:
        """Get organization by GitHub organization ID"""
        return self.db.query(Organization).filter(
            Organization.github_org_id == github_org_id,
            Organization.is_active == True
        ).first()
    
    def create_team(self, organization_id: str, name: str, 
                   description: str = None) -> Team:
        """Create a new team within an organization"""
        try:
            team = Team(
                name=name,
                description=description,
                organization_id=organization_id
            )
            
            self.db.add(team)
            self.db.commit()
            
            logger.info(f"Created team: {name} in org {organization_id}")
            return team
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to create team: {e}")
            raise
    
    def add_user_to_team(self, team_id: str, user_id: str, 
                        role: str = 'member') -> TeamMember:
        """Add user to team with specified role"""
        try:
            # Check if membership already exists
            existing = self.db.query(TeamMember).filter(
                TeamMember.team_id == team_id,
                TeamMember.user_id == user_id,
                TeamMember.is_active == True
            ).first()
            
            if existing:
                # Update role if different
                if existing.role != role:
                    existing.role = role
                    existing.updated_at = datetime.utcnow()
                    self.db.commit()
                return existing
            
            # Create new membership
            membership = TeamMember(
                team_id=team_id,
                user_id=user_id,
                role=role
            )
            
            self.db.add(membership)
            self.db.commit()
            
            logger.info(f"Added user {user_id} to team {team_id} as {role}")
            return membership
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to add user to team: {e}")
            raise
    
    def get_user_organizations(self, user_id: str) -> List[Organization]:
        """Get all organizations a user belongs to"""
        return self.db.query(Organization).join(
            Team, Organization.id == Team.organization_id
        ).join(
            TeamMember, Team.id == TeamMember.team_id
        ).filter(
            TeamMember.user_id == user_id,
            TeamMember.is_active == True,
            Organization.is_active == True
        ).distinct().all()
    
    def get_user_permissions(self, user_id: str, organization_id: str) -> Dict[str, Any]:
        """Get user's effective permissions in an organization"""
        try:
            # Get user's team memberships in the organization
            memberships = self.db.query(TeamMember).join(
                Team, TeamMember.team_id == Team.id
            ).filter(
                TeamMember.user_id == user_id,
                Team.organization_id == organization_id,
                TeamMember.is_active == True,
                Team.is_active == True
            ).all()
            
            if not memberships:
                return {'can_access': False}
            
            # Aggregate permissions from all teams
            effective_permissions = {
                'can_access': True,
                'can_create_scans': False,
                'can_view_all_scans': False,
                'can_manage_team': False,
                'can_access_ai_patching': False,
                'allowed_repositories': set(),
                'scan_quotas': {
                    'daily_limit': 0,
                    'monthly_limit': 0
                }
            }
            
            for membership in memberships:
                team_perms = membership.team.permissions or {}
                
                # Union of permissions (most permissive wins)
                effective_permissions['can_create_scans'] |= team_perms.get('can_create_scans', False)
                effective_permissions['can_view_all_scans'] |= team_perms.get('can_view_all_scans', False)
                effective_permissions['can_manage_team'] |= team_perms.get('can_manage_team', False)
                effective_permissions['can_access_ai_patching'] |= team_perms.get('can_access_ai_patching', False)
                
                # Repository access (union)
                team_repos = team_perms.get('allowed_repositories', [])
                if not team_repos:  # Empty list means all repositories
                    effective_permissions['allowed_repositories'] = set()  # All access
                elif effective_permissions['allowed_repositories'] is not None:
                    effective_permissions['allowed_repositories'].update(team_repos)
                
                # Quotas (maximum)
                team_quotas = team_perms.get('scan_quotas', {})
                effective_permissions['scan_quotas']['daily_limit'] = max(
                    effective_permissions['scan_quotas']['daily_limit'],
                    team_quotas.get('daily_limit', 0)
                )
                effective_permissions['scan_quotas']['monthly_limit'] = max(
                    effective_permissions['scan_quotas']['monthly_limit'],
                    team_quotas.get('monthly_limit', 0)
                )
            
            # Convert set back to list for JSON serialization
            if isinstance(effective_permissions['allowed_repositories'], set):
                effective_permissions['allowed_repositories'] = list(effective_permissions['allowed_repositories'])
            
            return effective_permissions
            
        except Exception as e:
            logger.error(f"Failed to get user permissions: {e}")
            return {'can_access': False, 'error': str(e)}
    
    def create_api_key(self, organization_id: str, user_id: str, 
                      name: str, scopes: List[str] = None,
                      expires_days: int = 365) -> tuple[str, APIKey]:
        """Create API key for programmatic access"""
        try:
            # Generate secure API key
            api_key = f"avr_{secrets.token_urlsafe(32)}"
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Set expiration
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
            
            # Create API key record
            api_key_record = APIKey(
                name=name,
                key_hash=key_hash,
                organization_id=organization_id,
                created_by_user_id=user_id,
                scopes=scopes or ['scans:read', 'scans:write'],
                expires_at=expires_at
            )
            
            self.db.add(api_key_record)
            self.db.commit()
            
            logger.info(f"Created API key: {name} for org {organization_id}")
            return api_key, api_key_record
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to create API key: {e}")
            raise
    
    def validate_api_key(self, api_key: str) -> Optional[APIKey]:
        """Validate API key and return associated record"""
        try:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            api_key_record = self.db.query(APIKey).filter(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True,
                APIKey.expires_at > datetime.utcnow()
            ).first()
            
            if api_key_record:
                # Update usage tracking
                api_key_record.last_used_at = datetime.utcnow()
                api_key_record.usage_count += 1
                self.db.commit()
            
            return api_key_record
            
        except Exception as e:
            logger.error(f"Failed to validate API key: {e}")
            return None
    
    def sync_github_teams(self, organization_id: str, github_teams: List[Dict]):
        """Sync GitHub teams with internal teams"""
        try:
            org = self.db.query(Organization).filter(
                Organization.id == organization_id
            ).first()
            
            if not org:
                raise ValueError("Organization not found")
            
            for github_team in github_teams:
                # Find or create team
                team = self.db.query(Team).filter(
                    Team.organization_id == organization_id,
                    Team.github_team_id == str(github_team['id'])
                ).first()
                
                if not team:
                    team = Team(
                        name=github_team['name'],
                        description=github_team.get('description', ''),
                        organization_id=organization_id,
                        github_team_id=str(github_team['id'])
                    )
                    self.db.add(team)
                else:
                    # Update team info
                    team.name = github_team['name']
                    team.description = github_team.get('description', '')
                    team.updated_at = datetime.utcnow()
            
            self.db.commit()
            logger.info(f"Synced {len(github_teams)} GitHub teams for org {organization_id}")
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to sync GitHub teams: {e}")
            raise