#!/usr/bin/env python3
"""
Celery worker for vulnerability scanning tasks
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import Celery app
from src.queue.tasks import celery_app

if __name__ == '__main__':
    # Start Celery worker
    celery_app.start()