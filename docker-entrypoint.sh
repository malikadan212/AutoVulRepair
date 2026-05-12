#!/bin/bash
# Docker entrypoint script for AutoVulRepair

set -e

# Set default environment variables for Docker
export CELERY_WORKER=${CELERY_WORKER:-false}
export FLASK_SECRET_KEY=${FLASK_SECRET_KEY:-dev-secret-key}
export PYTHONUNBUFFERED=1

# Create necessary directories
mkdir -p /app/scans /app/logs /app/faiss_indexes

# Set proper permissions
chown -R autovulrepair:autovulrepair /app/scans /app/logs /app/faiss_indexes 2>/dev/null || true

# Log startup information
echo "🚀 Starting AutoVulRepair Docker Container"
echo "   Environment: ${FLASK_ENV:-production}"
echo "   Celery Worker: ${CELERY_WORKER}"
echo "   Database: ${DATABASE_URL}"
echo "   Redis: ${REDIS_URL}"

# Execute the command passed to the container
exec "$@"