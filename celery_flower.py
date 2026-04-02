#!/usr/bin/env python3
"""
Celery flower monitoring interface
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set Celery worker flag to avoid Flask secret key requirement
os.environ['CELERY_WORKER'] = 'true'
os.environ['FLASK_SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key')

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import Celery app from the workers module
try:
    from src.workers.job_worker import celery_app
except ImportError:
    # Fallback to queue tasks if workers module is not available
    from src.queue.tasks import celery_app

if __name__ == '__main__':
    # Start Celery flower monitoring
    celery_app.start(['celery', 'flower', '--port=5555'])