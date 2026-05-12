"""
Organization and Team Models for Multi-tenancy
Enterprise-grade user and access management
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Text, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Organization(Base):
    """Organization model for multi-tenancy"""
    __tablename__ = 'organizations'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False)
    display_name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # GitHub integration
    github_org_id = Column(String(50), unique=True)  # GitHub organization ID
    github_installation_id = Column(String(50))  # GitHub App installation ID
    
    # Subscription and limits
    plan_type = Column(String(50), default='free')  # free, pro, enterprise
    max_scans_per_month = Column(Integer, default=100)
    max_users = Column(Integer, default=5)
    
    # Features enabled
    features = Column(JSON, default=lambda: {
        'advanced_fuzzing': False,
        'ai_patching': False,
        'custom_integrations': False,
        'priority_support': False
    })
    
    # Settings
    settings = Column(JSON, default=lambda: {
        'default_analysis_tool': 'cppcheck',
        'auto_scan_on_pr': True,
        'notification_channels': [],
        'security_policies': {}
    })
    
    # Audit fields
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    users = relationship("User", back_populates="organization")
    teams = relationship("Team", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")

class Team(Base):
    """Team model for fine-grained access control"""
    __tablename__ = 'teams'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Organization relationship
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    
    # Team settings
    default_role = Column(String(50), default='developer')  # viewer, developer, security_lead
    
    # Permissions
    permissions = Column(JSON, default=lambda: {
        'can_create_scans': True,
        'can_view_all_scans': False,
        'can_manage_team': False,
        'can_access_ai_patching': False,
        'allowed_repositories': [],  # Empty = all repositories
        'scan_quotas': {
            'daily_limit': 10,
            'monthly_limit': 100
        }
    })
    
    # GitHub team mapping
    github_team_id = Column(String(50))  # GitHub team ID for sync
    
    # Audit fields
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    organization = relationship("Organization", back_populates="teams")
    members = relationship("TeamMember", back_populates="team")

class TeamMember(Base):
    """Team membership with roles"""
    __tablename__ = 'team_members'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    # Role and permissions
    role = Column(String(50), default='member')  # member, lead, admin
    
    # Custom permissions override
    custom_permissions = Column(JSON)
    
    # Audit fields
    joined_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    team = relationship("Team", back_populates="members")
    user = relationship("User")

class APIKey(Base):
    """API keys for programmatic access"""
    __tablename__ = 'api_keys'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)  # Hashed API key
    
    # Ownership
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    # Permissions and scopes
    scopes = Column(JSON, default=lambda: ['scans:read', 'scans:write'])
    
    # Usage tracking
    last_used_at = Column(DateTime)
    usage_count = Column(Integer, default=0)
    
    # Expiration
    expires_at = Column(DateTime)
    
    # Audit fields
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    organization = relationship("Organization")
    created_by = relationship("User")