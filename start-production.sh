#!/bin/bash
# Start AutoVulRepair in production mode

set -e

echo "Starting AutoVulRepair..."

# Check if .env exists
if [ ! -f .env ]; then
    if [ -f .env.production ]; then
        echo "Copying .env.production to .env"
        cp .env.production .env
    else
        echo "ERROR: No .env file found!"
        echo "Please create .env from .env.production"
        exit 1
    fi
fi

# Build and start services
echo "Building Docker images..."
docker-compose -f docker-compose.production.yml build

echo "Starting services..."
docker-compose -f docker-compose.production.yml up -d

echo ""
echo "✅ AutoVulRepair started!"
echo ""
echo "Checking service status..."
sleep 5
docker-compose -f docker-compose.production.yml ps

echo ""
echo "View logs: docker-compose -f docker-compose.production.yml logs -f"
echo "Stop services: docker-compose -f docker-compose.production.yml down"
echo ""
echo "Application should be available at: http://YOUR_EC2_IP:5000"
