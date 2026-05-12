# Database connection module
from src.database.connection import (
    DatabaseConfig,
    get_session,
    create_database
)

# Alias for backward compatibility
get_db_connection = get_session

__all__ = [
    'DatabaseConfig',
    'get_session',
    'get_db_connection',
    'create_database'
]