# 🐳 Docker Usage Guide

## Quick Start

```bash
# Start all services (PostgreSQL + Redis + App + Workers)
docker-compose up

# Start in background
docker-compose up -d

# Stop all services
docker-compose down

# Rebuild and start (after code changes)
docker-compose up --build
```

## What's Included

The `docker-compose.yml` includes:

### Core Services
- **app** - Main Flask application (port 5000)
- **postgres** - PostgreSQL database (port 5432)
- **redis** - Redis cache and job queue (port 6379)

### Background Workers
- **celery-worker-scan** - Handles scan processing (2 replicas)
- **celery-worker-fuzz** - Handles fuzzing tasks (1 replica)
- **celery-beat** - Task scheduler

### Optional Services (use profiles)
- **celery-flower** - Worker monitoring (port 5555)
- **nginx** - Reverse proxy (ports 80/443)
- **prometheus** - Metrics collection (port 9090)
- **grafana** - Dashboards (port 3000)

## Environment Variables

Required in `.env`:
```env
POSTGRES_PASSWORD=your_secure_password
GRAFANA_PASSWORD=your_grafana_password
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GROQ_API_KEY=your_groq_api_key
```

## Profiles

Start optional services:
```bash
# With monitoring
docker-compose --profile monitoring up

# With production setup
docker-compose --profile production up
```

## Troubleshooting

### Database Connection Issues
- Make sure PostgreSQL container is healthy: `docker-compose ps`
- Check logs: `docker-compose logs postgres`

### App Won't Start
- Check app logs: `docker-compose logs app`
- Verify environment variables in `.env`

### Workers Not Processing
- Check worker logs: `docker-compose logs celery-worker-scan`
- Monitor with Flower: http://localhost:5555 (if enabled)

## Development

For development with live code reloading, the compose file uses volume mounting:
```yaml
volumes:
  - .:/app  # Live code reloading
```

Changes to Python files will automatically restart the Flask app.

## Production Notes

- Uses PostgreSQL with optimized settings
- Includes health checks for all services
- Configured for horizontal scaling
- Includes monitoring and reverse proxy options