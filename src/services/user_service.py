"""
User service for managing user database operations
"""

import logging
from datetime import datetime
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from src.models.user import User, Base
from src.database.connection import get_session

logger = logging.getLogger(__name__)

class UserService:
    """Service for user database operations"""
    
    def __init__(self):
        self.session = get_session
    
    def create_or_update_user(self, user_id, username, email=None, avatar_url=None, token=None):
        """Create a new user or update existing user"""
        session_db = self.session()
        try:
            # Check if user already exists
            existing_user = session_db.query(User).filter_by(id=user_id).first()
            
            if existing_user:
                # Update existing user
                existing_user.username = username
                existing_user.email = email or existing_user.email
                existing_user.avatar_url = avatar_url or existing_user.avatar_url
                existing_user.github_token = token or existing_user.github_token
                existing_user.last_login = datetime.utcnow()
                existing_user.updated_at = datetime.utcnow()
                
                session_db.commit()
                
                # Create a new detached User object with all the data
                detached_user = User(
                    id_=existing_user.id,
                    username=existing_user.username,
                    email=existing_user.email,
                    avatar_url=existing_user.avatar_url,
                    token=existing_user.github_token
                )
                # Set additional attributes that aren't in __init__
                detached_user.is_active = existing_user.is_active
                detached_user.created_at = existing_user.created_at
                detached_user.updated_at = existing_user.updated_at
                detached_user.last_login = existing_user.last_login
                
                logger.info(f"Updated user {username} (ID: {user_id})")
                return detached_user
            else:
                # Create new user
                new_user = User(
                    id_=user_id,
                    username=username,
                    email=email,
                    avatar_url=avatar_url,
                    token=token
                )
                
                session_db.add(new_user)
                session_db.commit()
                
                # Create a new detached User object with all the data
                detached_user = User(
                    id_=new_user.id,
                    username=new_user.username,
                    email=new_user.email,
                    avatar_url=new_user.avatar_url,
                    token=new_user.github_token
                )
                # Set additional attributes that aren't in __init__
                detached_user.is_active = new_user.is_active
                detached_user.created_at = new_user.created_at
                detached_user.updated_at = new_user.updated_at
                detached_user.last_login = new_user.last_login
                
                logger.info(f"Created new user {username} (ID: {user_id})")
                return detached_user
                
        except Exception as e:
            session_db.rollback()
            logger.error(f"Error creating/updating user {username}: {e}")
            raise
        finally:
            session_db.close()
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        session_db = self.session()
        try:
            user = session_db.query(User).filter_by(id=user_id).first()
            if user:
                # Create a new detached User object with all the data
                detached_user = User(
                    id_=user.id,
                    username=user.username,
                    email=user.email,
                    avatar_url=user.avatar_url,
                    token=user.github_token
                )
                # Set additional attributes that aren't in __init__
                detached_user.is_active = user.is_active
                detached_user.created_at = user.created_at
                detached_user.updated_at = user.updated_at
                detached_user.last_login = user.last_login
                
                return detached_user
            return None
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None
        finally:
            session_db.close()
    
    def get_user_by_username(self, username):
        """Get user by username"""
        session_db = self.session()
        try:
            user = session_db.query(User).filter_by(username=username).first()
            if user:
                # Create a new detached User object with all the data
                detached_user = User(
                    id_=user.id,
                    username=user.username,
                    email=user.email,
                    avatar_url=user.avatar_url,
                    token=user.github_token
                )
                # Set additional attributes that aren't in __init__
                detached_user.is_active = user.is_active
                detached_user.created_at = user.created_at
                detached_user.updated_at = user.updated_at
                detached_user.last_login = user.last_login
                
                return detached_user
            return None
        except Exception as e:
            logger.error(f"Error getting user by username {username}: {e}")
            return None
        finally:
            session_db.close()
    
    def update_user_token(self, user_id, token):
        """Update user's GitHub token"""
        session_db = self.session()
        try:
            user = session_db.query(User).filter_by(id=user_id).first()
            if user:
                user.github_token = token
                user.updated_at = datetime.utcnow()
                session_db.commit()
                logger.info(f"Updated token for user {user.username}")
                return True
            return False
        except Exception as e:
            session_db.rollback()
            logger.error(f"Error updating token for user {user_id}: {e}")
            return False
        finally:
            session_db.close()
    
    def get_user_scan_count(self, user_id):
        """Get total number of scans for a user"""
        from src.models.scan import Scan
        session_db = self.session()
        try:
            count = session_db.query(Scan).filter_by(user_id=user_id).count()
            return count
        except Exception as e:
            logger.error(f"Error getting scan count for user {user_id}: {e}")
            return 0
        finally:
            session_db.close()
    
    def create_tables(self):
        """Create user tables if they don't exist"""
        try:
            from src.database.connection import DatabaseConfig
            from src.models.base import Base
            engine = DatabaseConfig.create_engine_with_config()
            Base.metadata.create_all(engine)
            logger.info("User tables created successfully")
        except Exception as e:
            logger.error(f"Error creating user tables: {e}")
            raise

# Global user service instance
user_service = UserService()