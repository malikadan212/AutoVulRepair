import uuid
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), nullable=True)  # Nullable for public scans
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

# Database setup
def get_database_url():
    # Ensure both app and celery use the same database path
    db_path = os.getenv('DATABASE_PATH', '/app/scans.db')
    
    # Ensure the directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # If the database file doesn't exist, create it
    if not os.path.exists(db_path):
        try:
            # Create empty file
            with open(db_path, 'w') as f:
                pass
            # Set permissions
            os.chmod(db_path, 0o666)
        except Exception as e:
            print(f"Warning: Could not create database file {db_path}: {e}")
    
    return f"sqlite:///{db_path}"

def create_database():
    """Create database tables if they don't exist"""
    try:
        # Add connection args to improve performance and handle disk issues better
        engine = create_engine(
            get_database_url(),
            connect_args={
                'timeout': 30,  # Increase timeout for busy database
                'check_same_thread': False  # Allow multi-threading
            },
            pool_pre_ping=True,  # Verify connections before using
            pool_recycle=3600  # Recycle connections every hour
        )
        Base.metadata.create_all(engine)
        return engine
    except Exception as e:
        print(f"Database creation error: {e}")
        # Fallback to in-memory database
        print("Falling back to in-memory database")
        engine = create_engine(
            'sqlite:///:memory:',
            connect_args={'check_same_thread': False},
            pool_pre_ping=True
        )
        Base.metadata.create_all(engine)
        return engine

def get_session():
    """Get database session"""
    engine = create_database()
    Session = sessionmaker(bind=engine)
    return Session()