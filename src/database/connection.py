"""
Database connection management for Kubernetes deployment
Supports both SQLite (development) and PostgreSQL (production)
"""
import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class DatabaseConfig:
    """Database configuration management"""
    
    @staticmethod
    def get_database_url():
        """
        Get database URL with fallback logic:
        1. PostgreSQL (production/Kubernetes)
        2. SQLite (development/local)
        """
        # Check for PostgreSQL URL first (Kubernetes deployment)
        postgres_url = os.getenv('DATABASE_URL')
        if postgres_url:
            # Validate PostgreSQL URL
            parsed = urlparse(postgres_url)
            if parsed.scheme in ['postgresql', 'postgres']:
                logger.info(f"Using PostgreSQL database: {parsed.hostname}:{parsed.port}")
                return postgres_url
            else:
                logger.warning(f"Invalid DATABASE_URL scheme: {parsed.scheme}")
        
        # Fallback to SQLite for local development
        db_path = os.getenv('DATABASE_PATH', '/app/scans.db')
        logger.info(f"Using SQLite database: {db_path}")
        
        # Ensure the directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Create SQLite file if it doesn't exist
        if not os.path.exists(db_path):
            try:
                with open(db_path, 'w') as f:
                    pass
                os.chmod(db_path, 0o666)
                logger.info(f"Created SQLite database: {db_path}")
            except Exception as e:
                logger.error(f"Could not create database file {db_path}: {e}")
        
        return f"sqlite:///{db_path}"
    
    @staticmethod
    def create_engine_with_config():
        """Create SQLAlchemy engine with appropriate configuration"""
        database_url = DatabaseConfig.get_database_url()
        
        if database_url.startswith('postgresql'):
            # PostgreSQL configuration for production
            engine = create_engine(
                database_url,
                pool_size=20,                    # Connection pool size
                max_overflow=30,                 # Additional connections beyond pool_size
                pool_pre_ping=True,              # Verify connections before using
                pool_recycle=3600,               # Recycle connections every hour
                echo=False,                      # Set to True for SQL debugging
                connect_args={
                    "connect_timeout": 10,       # Connection timeout
                    "application_name": "autovulrepair"
                }
            )
            logger.info("PostgreSQL engine created with production settings")
        else:
            # SQLite configuration for development
            engine = create_engine(
                database_url,
                poolclass=StaticPool,            # Required for SQLite threading
                connect_args={
                    'timeout': 30,               # Increase timeout for busy database
                    'check_same_thread': False   # Allow multi-threading
                },
                pool_pre_ping=True,
                pool_recycle=3600,
                echo=False
            )
            logger.info("SQLite engine created with development settings")
        
        return engine
    
    @staticmethod
    def test_connection():
        """Test database connectivity"""
        try:
            engine = DatabaseConfig.create_engine_with_config()
            with engine.connect() as conn:
                # Test query based on database type
                if engine.url.drivername.startswith('postgresql'):
                    result = conn.execute("SELECT version()")
                else:
                    result = conn.execute("SELECT sqlite_version()")
                
                version = result.fetchone()[0]
                logger.info(f"Database connection successful. Version: {version}")
                return True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False

def get_session():
    """Get database session with proper configuration"""
    engine = DatabaseConfig.create_engine_with_config()
    Session = sessionmaker(bind=engine)
    return Session()

def create_database():
    """Create database tables if they don't exist"""
    try:
        engine = DatabaseConfig.create_engine_with_config()
        
        # Import here to avoid circular imports
        from src.models.base import Base
        
        # Create all tables
        Base.metadata.create_all(engine)
        logger.info("Database tables created successfully")
        return engine
    except Exception as e:
        logger.error(f"Database creation error: {e}")
        
        # Fallback to in-memory database for development
        logger.warning("Falling back to in-memory SQLite database")
        engine = create_engine(
            'sqlite:///:memory:',
            connect_args={'check_same_thread': False},
            pool_pre_ping=True
        )
        
        from src.models.base import Base
        Base.metadata.create_all(engine)
        return engine