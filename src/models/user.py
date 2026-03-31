"""
User model for persistent user storage
"""

from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Boolean
from flask_login import UserMixin
from .base import Base

class User(Base, UserMixin):
    """User model for database storage"""
    __tablename__ = 'users'
    
    id = Column(String(36), primary_key=True)  # GitHub user ID
    username = Column(String(100), nullable=False)  # GitHub username
    email = Column(String(255), nullable=True)  # GitHub email (if available)
    avatar_url = Column(Text, nullable=True)  # GitHub avatar URL
    github_token = Column(Text, nullable=True)  # Encrypted GitHub token
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    def __init__(self, id_, username, email=None, avatar_url=None, token=None):
        self.id = id_
        self.username = username
        self.email = email
        self.avatar_url = avatar_url
        self.github_token = token
        self.last_login = datetime.utcnow()
    
    def get_id(self):
        """Required by Flask-Login"""
        return str(self.id)
    
    def is_authenticated(self):
        """Required by Flask-Login"""
        return True
    
    def is_anonymous(self):
        """Required by Flask-Login"""
        return False
    
    def __repr__(self):
        return f'<User {self.username}>'