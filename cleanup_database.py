#!/usr/bin/env python3
"""
Database cleanup utility to free up disk space
"""
import os
import sys
from datetime import datetime, timedelta
from src.models.scan import get_session, Scan

def get_database_size():
    """Get the size of the database file"""
    db_path = os.getenv('DATABASE_PATH', './scans.db')
    if os.path.exists(db_path):
        size_mb = os.path.getsize(db_path) / (1024 * 1024)
        return size_mb, db_path
    return 0, db_path

def count_scans():
    """Count total scans in database"""
    session = get_session()
    try:
        total = session.query(Scan).count()
        return total
    finally:
        session.close()

def delete_old_scans(days_old=7, dry_run=True):
    """Delete scans older than specified days"""
    session = get_session()
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        old_scans = session.query(Scan).filter(Scan.created_at < cutoff_date).all()
        
        print(f"\nFound {len(old_scans)} scans older than {days_old} days")
        
        if not old_scans:
            print("Nothing to delete.")
            return 0
        
        if dry_run:
            print("\nDRY RUN - Would delete the following scans:")
            for scan in old_scans[:10]:  # Show first 10
                print(f"  - ID: {scan.id}, Created: {scan.created_at}, Status: {scan.status}")
            if len(old_scans) > 10:
                print(f"  ... and {len(old_scans) - 10} more")
            print("\nRun with --execute to actually delete these scans.")
            return len(old_scans)
        else:
            # Delete scans
            for scan in old_scans:
                session.delete(scan)
            session.commit()
            print(f"\nDeleted {len(old_scans)} old scans.")
            return len(old_scans)
    except Exception as e:
        print(f"Error: {e}")
        session.rollback()
        return 0
    finally:
        session.close()

def delete_failed_scans(dry_run=True):
    """Delete failed scans"""
    session = get_session()
    try:
        failed_scans = session.query(Scan).filter(Scan.status == 'failed').all()
        
        print(f"\nFound {len(failed_scans)} failed scans")
        
        if not failed_scans:
            print("No failed scans to delete.")
            return 0
        
        if dry_run:
            print("\nDRY RUN - Would delete the following failed scans:")
            for scan in failed_scans[:10]:
                print(f"  - ID: {scan.id}, Created: {scan.created_at}")
            if len(failed_scans) > 10:
                print(f"  ... and {len(failed_scans) - 10} more")
            print("\nRun with --execute to actually delete these scans.")
            return len(failed_scans)
        else:
            for scan in failed_scans:
                session.delete(scan)
            session.commit()
            print(f"\nDeleted {len(failed_scans)} failed scans.")
            return len(failed_scans)
    except Exception as e:
        print(f"Error: {e}")
        session.rollback()
        return 0
    finally:
        session.close()

def vacuum_database():
    """Vacuum the database to reclaim space"""
    import sqlite3
    
    db_path = os.getenv('DATABASE_PATH', './scans.db')
    print(f"\nVacuuming database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("VACUUM")
        conn.close()
        print("Database vacuumed successfully!")
    except Exception as e:
        print(f"Error vacuuming database: {e}")

def main():
    """Main cleanup function"""
    print("=" * 60)
    print("Database Cleanup Utility")
    print("=" * 60)
    
    # Show current state
    size_mb, db_path = get_database_size()
    total_scans = count_scans()
    
    print(f"\nCurrent database: {db_path}")
    print(f"Database size: {size_mb:.2f} MB")
    print(f"Total scans: {total_scans}")
    
    # Check if --execute flag is present
    execute = '--execute' in sys.argv
    
    if not execute:
        print("\n" + "=" * 60)
        print("DRY RUN MODE - No changes will be made")
        print("Add --execute flag to actually perform cleanup")
        print("=" * 60)
    
    # Options
    print("\nCleanup options:")
    print("1. Delete scans older than 7 days")
    print("2. Delete scans older than 30 days")
    print("3. Delete failed scans")
    print("4. Vacuum database (reclaim space)")
    print("5. All of the above")
    
    choice = input("\nEnter your choice (1-5): ").strip()
    
    if choice == '1':
        delete_old_scans(days_old=7, dry_run=not execute)
    elif choice == '2':
        delete_old_scans(days_old=30, dry_run=not execute)
    elif choice == '3':
        delete_failed_scans(dry_run=not execute)
    elif choice == '4':
        if execute:
            vacuum_database()
        else:
            print("\nWould vacuum database (add --execute to perform)")
    elif choice == '5':
        delete_old_scans(days_old=7, dry_run=not execute)
        delete_failed_scans(dry_run=not execute)
        if execute:
            vacuum_database()
        else:
            print("\nWould vacuum database (add --execute to perform)")
    else:
        print("Invalid choice")
        return
    
    # Show new state
    if execute:
        print("\n" + "=" * 60)
        size_mb, _ = get_database_size()
        total_scans = count_scans()
        print(f"New database size: {size_mb:.2f} MB")
        print(f"Remaining scans: {total_scans}")
        print("=" * 60)

if __name__ == '__main__':
    main()

