#!/usr/bin/env python3
"""
Start Celery worker with correct queue configuration
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
os.environ['CELERY_WORKER'] = 'true'

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from src.workers.job_worker import celery_app

if __name__ == '__main__':
    # Start worker with correct queues
    celery_app.worker_main([
        'worker', 
        '--loglevel=info', 
        '--pool=solo', 
        '--queues=scan_queue,fuzzing_queue,celery'
    ])