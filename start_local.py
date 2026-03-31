#!/usr/bin/env python3
"""
Local Development Startup Script
Handles database connection issues and starts the app with proper configuration
"""

import os
import sys
from pathlib import Path

def setup_local_environment():
    """Setup environment for local development"""
    
    # Use local environment file if it exists
    if Path('.env.local').exists():
        print("🔧 Using .env.local for local development")
        os.environ['ENV_FILE'] = '.env.local'
    
    # Disable PostgreSQL for local development
    if 'DATABASE_URL' in os.environ and 'postgres' in os.environ['DATABASE_URL']:
        print("🔧 Disabling PostgreSQL for local development (will use SQLite)")
        del os.environ['DATABASE_URL']
    
    print("🚀 Starting AutoVulRepair in local development mode...")
    print("📊 Database: SQLite (file-based)")
    print("🐳 Analysis: Docker-based tools")
    print("🌐 Web UI: http://localhost:5000")
    print("🔧 Advanced Scanner: http://localhost:5000/advanced-scan")
    print()

def main():
    """Main startup function"""
    setup_local_environment()
    
    # Import and run the Flask app
    try:
        from app import app
        app.run(host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        print("\n🔧 Troubleshooting:")
        print("   1. Make sure Docker is running")
        print("   2. Check that port 5000 is available")
        print("   3. Try: python app.py")
        sys.exit(1)

if __name__ == '__main__':
    main()