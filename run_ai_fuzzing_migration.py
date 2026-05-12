#!/usr/bin/env python3
"""
Run AI and Fuzzing tables migration
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config.database import DatabaseConnection
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_migration():
    """Run the AI and Fuzzing tables migration"""
    try:
        db = DatabaseConnection()
        
        # Read migration file
        migration_file = 'migrations/add_ai_fuzzing_tables.sql'
        logger.info(f"Reading migration file: {migration_file}")
        
        with open(migration_file, 'r') as f:
            migration_sql = f.read()
        
        # Execute migration
        logger.info("Executing migration...")
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(migration_sql)
                conn.commit()
        
        logger.info("✅ Migration completed successfully!")
        logger.info("Created tables:")
        logger.info("  - patches (for AI-generated vulnerability fixes)")
        logger.info("  - fuzzing_results (for fuzzing test results)")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        return False

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)
