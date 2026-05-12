"""
GitHub App Installation Models
Tracks GitHub App installations and repository access
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Text, Integer, JSON, BigInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from src.models.base import Base

class GitHubInstallation(Base):
    """GitHub App installation tracking"""
    __tablename__ = 'github_installations'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    installation_id = Column(BigInteger, unique=True, nullable=False)
    
    # User who installed the app
    user_id = Column(String(36), nullable=False)  # Removed ForeignKey temporarily
    
    # GitHub account info
    github_account_login = Column(String(255), nullable=False)
    github_account_id = Column(BigInteger)
    github_account_type = Column(String(50))  # 'User' or 'Organization'
    
    # Installation details
    repository_selection = Column(String(50))  # 'all' or 'selected'
    permissions = Column(JSON)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    installed_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    repositories = relationship("InstallationRepository", back_populates="installation")

class InstallationRepository(Base):
    """Repositories accessible through GitHub App installation"""
    __tablename__ = 'installation_repositories'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Installation relationship
    installation_id = Column(UUID(as_uuid=True), ForeignKey('github_installations.id'), nullable=False)
    
    # Repository info
    repository_full_name = Column(String(255), nullable=False)  # 'owner/repo'
    repository_id = Column(BigInteger, nullable=False)
    repository_name = Column(String(255))
    repository_private = Column(Boolean, default=False)
    repository_language = Column(String(100))
    
    # Automation settings
    automation_enabled = Column(Boolean, default=False)
    auto_scan_on_push = Column(Boolean, default=True)
    auto_create_prs = Column(Boolean, default=True)
    auto_scan_on_pr = Column(Boolean, default=True)
    
    # Settings
    settings = Column(JSON, default=lambda: {
        'scan_schedule': 'on_push',  # 'on_push', 'daily', 'weekly'
        'severity_threshold': 'medium',  # 'low', 'medium', 'high'
        'create_issues': False,
        'block_prs_on_critical': False
    })
    
    # Status
    is_active = Column(Boolean, default=True)
    last_scanned_at = Column(DateTime)
    last_scan_status = Column(String(50))  # 'completed', 'failed', 'running'
    
    # Timestamps
    added_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    installation = relationship("GitHubInstallation", back_populates="repositories")

class GitHubAppToken(Base):
    """Cache for GitHub App installation tokens"""
    __tablename__ = 'github_app_tokens'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    installation_id = Column(BigInteger, nullable=False, unique=True)
    
    # Token info
    access_token = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)