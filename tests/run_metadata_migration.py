#!/usr/bin/env python3
"""
Run database migration to add metadata_json column to static_findings table
"""

import os
import sys
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

def run_migration():
    """Run the metadata_json migration"""
    
    # Get database URL
    DATABASE_URL = os.getenv('DATABASE_URL')
    if not DATABASE_URL:
        print("❌ ERROR: DATABASE_URL not set in environment")
        print("Please set DATABASE_URL in your .env file")
        return False
    
    print("=" * 60)
    print("Database Migration: Add metadata_json to static_findings")
    print("=" * 60)
    print()
    
    try:
        # Create engine
        print(f"Connecting to database...")
        engine = create_engine(DATABASE_URL)
        
        # Read migration SQL
        migration_file = 'migrations/add_metadata_json_to_static_findings.sql'
        print(f"Reading migration file: {migration_file}")
        
        with open(migration_file, 'r') as f:
            migration_sql = f.read()
        
        # Execute migration
        print("Executing migration...")
        with engine.connect() as conn:
            # Split by semicolon and execute each statement
            statements = [s.strip() for s in migration_sql.split(';') if s.strip() and not s.strip().startswith('--')]
            
            for i, statement in enumerate(statements, 1):
                if statement:
                    print(f"  Executing statement {i}/{len(statements)}...")
                    conn.execute(text(statement))
                    conn.commit()
        
        print()
        print("✅ Migration completed successfully!")
        print()
        print("The static_findings table now has a metadata_json column.")
        print("This column will store false positive detection results.")
        print()
        return True
        
    except Exception as e:
        print()
        print(f"❌ Migration failed: {e}")
        print()
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)
