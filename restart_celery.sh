#!/bin/bash
# Restart Celery Worker Script

echo "Stopping Celery worker..."
pkill -f "celery.*worker" || echo "No Celery worker running"

echo "Clearing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

echo "Starting Celery worker..."
python celery_worker.py &

echo "Celery worker restarted!"
echo "Check logs with: tail -f celery.log"
