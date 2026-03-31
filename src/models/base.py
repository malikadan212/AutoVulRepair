"""
Shared SQLAlchemy base for all models
"""

from sqlalchemy.orm import declarative_base

# Single shared Base for all models
Base = declarative_base()