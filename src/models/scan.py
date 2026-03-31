import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship

# Import our new database connection module
from src.database.connection import get_session, create_database
from .base import Base

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=True)  # Foreign key to users table
    source_type = Column(String(20), nullable=False)  # 'zip', 'repo_url', 'code_snippet'
    source_path = Column(Text, nullable=True)  # File path for zip/snippet
    repo_url = Column(Text, nullable=True)  # GitHub URL for repo scans
    analysis_tool = Column(String(20), nullable=False, default='cppcheck')
    status = Column(String(20), nullable=False, default='queued')  # queued, running, completed, failed
    artifacts_path = Column(Text, nullable=True)  # Path to analysis artifacts
    vulnerabilities_json = Column(JSON, nullable=True)
    patches_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to User (optional, for when user_id is not null)
    # Note: We don't define the relationship here to avoid circular imports
    # The relationship can be queried manually when needed

# Re-export functions for backward compatibility
__all__ = ['Scan', 'Base', 'get_session', 'create_database']