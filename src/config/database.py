"""
Secure Database Configuration Module

This module provides secure database URL retrieval without hardcoded credentials.
All database credentials MUST be provided via environment variables.
"""

import os
import sys


def get_database_url(required=True):
    """
    Get database URL from environment variable.
    
    Args:
        required (bool): If True, raises error when DATABASE_URL is not set.
                        If False, returns None when not set.
    
    Returns:
        str: Database URL from environment variable
        
    Raises:
        ValueError: If DATABASE_URL is not set and required=True
    """
    database_url = os.getenv('DATABASE_URL')
    
    if not database_url and required:
        error_msg = (
            "DATABASE_URL environment variable is required but not set.\n"
            "Please set DATABASE_URL in your environment or .env file.\n"
            "Example: DATABASE_URL=postgresql://user:password@host:5432/dbname"
        )
        raise ValueError(error_msg)
    
    return database_url


def validate_database_url(database_url):
    """
    Validate that database URL is properly formatted.
    
    Args:
        database_url (str): Database URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not database_url:
        return False
    
    # Check for basic PostgreSQL URL format
    if not database_url.startswith('postgresql://'):
        return False
    
    # Check that it contains required components
    required_parts = ['@', ':', '/']
    if not all(part in database_url for part in required_parts):
        return False
    
    return True


def get_secure_database_url():
    """
    Get and validate database URL securely.
    
    Returns:
        str: Validated database URL
        
    Raises:
        ValueError: If DATABASE_URL is not set or invalid
    """
    database_url = get_database_url(required=True)
    
    if not validate_database_url(database_url):
        raise ValueError(
            f"Invalid DATABASE_URL format. "
            f"Expected: postgresql://user:password@host:port/database"
        )
    
    return database_url


# For backward compatibility - but this will raise error if not set
def get_database_url_with_fallback():
    """
    DEPRECATED: This function is kept for backward compatibility only.
    Use get_secure_database_url() instead.
    
    Returns:
        str: Database URL from environment
        
    Raises:
        ValueError: If DATABASE_URL is not set
    """
    import warnings
    warnings.warn(
        "get_database_url_with_fallback() is deprecated. "
        "Use get_secure_database_url() instead.",
        DeprecationWarning,
        stacklevel=2
    )
    return get_secure_database_url()
