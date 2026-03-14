# 🐳 Running AutoVulRepair with Docker

## Quick Start

### 1. Setup Environment Variables

Copy the example file and add your API key:

```bash
copy .env.example .env
```

Then edit `.env` and add your Gemini API key:
```
GEMINI_API_KEY=your_actual_api_key_here
```

### 2. Build and Run

```bash
docker-compose up --build
```

The application will be available at: http://localhost:5000

### 3. Stop the Application

```bash
docker-compose down
```

## What's Included

The Docker setup includes:

✅ **Flask Application** - Main web server with AI patching
✅ **Redis** - Task queue for background jobs
✅ **Celery Worker** - Background task processor
✅ **Clang/LLVM** - For fuzzing and compilation
✅ **AI Patching** - Gemini AI + FAISS vector database

## Environment Variables

Required:
- `GEMINI_API_KEY` - Your Google Gemini API key for AI patching

Optional:
- `FLASK_SECRET_KEY` - Flask session secret (auto-generated if not set)
- `GITHUB_CLIENT_ID` - For GitHub OAuth login
- `GITHUB_CLIENT_SECRET` - For GitHub OAuth login

## Volumes

The following directories are mounted:
- `./scans` - Scan results and patches
- `./logs` - Application logs
- `./faiss_indexes` - CVE vector database
- `./templates` - UI templates (for development)
- `./src` - Source code (for development)

## Updating the Application

If you make code changes:

```bash
# Rebuild and restart
docker-compose up --build

# Or just restart without rebuilding
docker-compose restart app
```

## Viewing Logs

```bash
# All services
docker-compose logs -f

# Just the app
docker-compose logs -f app

# Just Celery worker
docker-compose logs -f celery
```

## Troubleshooting

### AI Patching Not Available

**Symptom**: "AI Patching not available" message in UI

**Solution**: 
1. Check `.env` file has `GEMINI_API_KEY`
2. Restart containers: `docker-compose restart`
3. Check logs: `docker-compose logs app | grep "Patch Generator"`

You should see: `✓ AI Patch Generator initialized`

### FAISS Index Not Found

**Symptom**: "FAISS index not available" warning

**Solution**: The FAISS index is optional. If you have it:
1. Ensure `faiss_indexes/cve-full/` exists
2. Check it's mounted in docker-compose.yml
3. Restart: `docker-compose restart app`

### Port Already in Use

**Symptom**: `Error: port 5000 already in use`

**Solution**:
```bash
# Stop any running instance
docker-compose down

# Or change the port in docker-compose.yml
ports:
  - "5001:5000"  # Use port 5001 instead
```

## Development Mode

For active development with hot-reload:

```bash
# Run with volume mounts for live code updates
docker-compose up
```

Changes to Python files will automatically reload the app.

## Production Deployment

For production:

1. Update `.env` with production values
2. Set `FLASK_ENV=production`
3. Use a proper secret key
4. Remove debug volumes from docker-compose.yml
5. Use a production WSGI server (gunicorn)

```bash
docker-compose -f docker-compose.prod.yml up -d
```

## Cleaning Up

Remove all containers, volumes, and images:

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (WARNING: deletes scan data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## Health Checks

The application includes health checks:

```bash
# Check if services are healthy
docker-compose ps

# All services should show "healthy" status
```

## Resource Usage

Typical resource usage:
- **App**: ~500MB RAM, 1 CPU
- **Redis**: ~50MB RAM
- **Celery**: ~300MB RAM

For AI patching with FAISS:
- **Additional**: ~1GB RAM for model loading

## Quick Commands Reference

```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# View logs
docker-compose logs -f

# Rebuild
docker-compose up --build

# Check status
docker-compose ps

# Execute command in container
docker-compose exec app python -c "print('Hello')"

# Access shell
docker-compose exec app bash
```

---

**Status**: ✅ Docker configuration updated for AI patching!

Run `docker-compose up --build` to start with all features enabled.
