#!/usr/bin/env python3
"""
Database Migration Script for AutoVulRepair
Runs GitHub App table migrations automatically
"""

import os
import sys
import logging
import psycopg2
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_migration():
    """Run the GitHub App tables migration"""
    try:
        # Get database URL from environment
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            logger.error("DATABASE_URL environment variable not set")
            return False
        
        # Read migration SQL
        migration_file = Path(__file__).parent / 'migrations' / 'add_github_app_tables.sql'
        if not migration_file.exists():
            logger.error(f"Migration file not found: {migration_file}")
            return False
        
        with open(migration_file, 'r') as f:
            migration_sql = f.read()
        
        # Connect to database and run migration
        logger.info("Connecting to database...")
        conn = psycopg2.connect(database_url)
        
        with conn.cursor() as cursor:
            logger.info("Running GitHub App tables migration...")
            cursor.execute(migration_sql)
            conn.commit()
            logger.info("Migration completed successfully")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return False

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)