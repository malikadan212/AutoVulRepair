#!/bin/bash
# Stop AutoVulRepair (saves costs when not in use)

echo "Stopping AutoVulRepair..."
docker-compose -f docker-compose.production.yml down

echo ""
echo "✅ All services stopped"
echo "Data is preserved in Docker volumes"
echo ""
echo "To start again: ./start-production.sh"
