"""
Configuration management for Kubernetes deployment
Handles environment variables, secrets, and configuration validation
"""
import os
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str
    pool_size: int = 20
    max_overflow: int = 30
    pool_recycle: int = 3600
    echo: bool = False

@dataclass
class RedisConfig:
    """Redis configuration"""
    url: str
    max_connections: int = 50
    socket_timeout: int = 30
    socket_connect_timeout: int = 30

@dataclass
class APIConfig:
    """External API configuration"""
    groq_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None

@dataclass
class StorageConfig:
    """Storage configuration"""
    scans_dir: str = '/app/scans'
    faiss_indexes_dir: str = '/app/faiss_indexes'
    max_scan_size_mb: int = 100

@dataclass
class SecurityConfig:
    """Security configuration"""
    flask_secret_key: str
    session_timeout: int = 3600
    max_upload_size: int = 100 * 1024 * 1024  # 100MB

class AppConfig:
    """Main application configuration"""
    
    def __init__(self):
        self.environment = os.getenv('FLASK_ENV', 'production')
        self.debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
        self.port = int(os.getenv('PORT', '5000'))
        self.host = os.getenv('HOST', '0.0.0.0')
        
        # Load configurations
        self.database = self._load_database_config()
        self.redis = self._load_redis_config()
        self.apis = self._load_api_config()
        self.storage = self._load_storage_config()
        self.security = self._load_security_config()
        
        # Validate configuration
        self._validate_config()
    
    def _load_database_config(self) -> DatabaseConfig:
        """Load database configuration"""
        database_url = os.getenv('DATABASE_URL')
        
        if not database_url:
            # Fallback to SQLite for development
            db_path = os.getenv('DATABASE_PATH', '/app/scans.db')
            database_url = f"sqlite:///{db_path}"
        
        return DatabaseConfig(
            url=database_url,
            pool_size=int(os.getenv('DB_POOL_SIZE', '20')),
            max_overflow=int(os.getenv('DB_MAX_OVERFLOW', '30')),
            pool_recycle=int(os.getenv('DB_POOL_RECYCLE', '3600')),
            echo=os.getenv('DB_ECHO', 'false').lower() == 'true'
        )
    
    def _load_redis_config(self) -> RedisConfig:
        """Load Redis configuration"""
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        
        return RedisConfig(
            url=redis_url,
            max_connections=int(os.getenv('REDIS_MAX_CONNECTIONS', '50')),
            socket_timeout=int(os.getenv('REDIS_SOCKET_TIMEOUT', '30')),
            socket_connect_timeout=int(os.getenv('REDIS_CONNECT_TIMEOUT', '30'))
        )
    
    def _load_api_config(self) -> APIConfig:
        """Load external API configuration"""
        return APIConfig(
            groq_api_key=os.getenv('GROQ_API_KEY'),
            gemini_api_key=os.getenv('GEMINI_API_KEY'),
            github_client_id=os.getenv('GITHUB_CLIENT_ID'),
            github_client_secret=os.getenv('GITHUB_CLIENT_SECRET')
        )
    
    def _load_storage_config(self) -> StorageConfig:
        """Load storage configuration"""
        return StorageConfig(
            scans_dir=os.getenv('SCANS_DIR', '/app/scans'),
            faiss_indexes_dir=os.getenv('FAISS_INDEXES_DIR', '/app/faiss_indexes'),
            max_scan_size_mb=int(os.getenv('MAX_SCAN_SIZE_MB', '100'))
        )
    
    def _load_security_config(self) -> SecurityConfig:
        """Load security configuration"""
        flask_secret_key = os.getenv('FLASK_SECRET_KEY')
        if not flask_secret_key:
            if self.environment == 'production':
                # Only raise error in actual production, not during testing
                if not os.getenv('TESTING', 'false').lower() == 'true':
                    raise ValueError("FLASK_SECRET_KEY must be set in production")
            flask_secret_key = 'dev-secret-key-change-in-production'
            logger.warning("Using default secret key for development")
        
        return SecurityConfig(
            flask_secret_key=flask_secret_key,
            session_timeout=int(os.getenv('SESSION_TIMEOUT', '3600')),
            max_upload_size=int(os.getenv('MAX_UPLOAD_SIZE', str(100 * 1024 * 1024)))
        )
    
    def _validate_config(self):
        """Validate configuration"""
        errors = []
        
        # Validate required directories exist
        for directory in [self.storage.scans_dir, self.storage.faiss_indexes_dir]:
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory, exist_ok=True)
                    logger.info(f"Created directory: {directory}")
                except Exception as e:
                    errors.append(f"Cannot create directory {directory}: {e}")
        
        # Validate API keys in production
        if self.environment == 'production':
            if not self.apis.groq_api_key and not self.apis.gemini_api_key:
                logger.warning("No AI API keys configured - AI features will be disabled")
        
        # Log configuration summary
        logger.info(f"Configuration loaded:")
        logger.info(f"  Environment: {self.environment}")
        logger.info(f"  Database: {self.database.url.split('@')[-1] if '@' in self.database.url else self.database.url}")
        logger.info(f"  Redis: {self.redis.url}")
        logger.info(f"  Scans directory: {self.storage.scans_dir}")
        logger.info(f"  AI APIs: {'Configured' if self.apis.groq_api_key or self.apis.gemini_api_key else 'Not configured'}")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary (for debugging)"""
        return {
            'environment': self.environment,
            'debug': self.debug,
            'port': self.port,
            'host': self.host,
            'database_url': self.database.url.split('@')[-1] if '@' in self.database.url else self.database.url,
            'redis_url': self.redis.url,
            'scans_dir': self.storage.scans_dir,
            'has_ai_keys': bool(self.apis.groq_api_key or self.apis.gemini_api_key)
        }

# Global configuration instance
config = AppConfig()