# AutoVulRepair - User Guide

## Zero-Installation Setup

Everything you need (including the fuzzing compiler) is bundled in Docker. No manual installation required!

## Prerequisites

Only Docker Desktop is required:
- **Windows**: Download from https://www.docker.com/products/docker-desktop/
- **macOS**: Download from https://www.docker.com/products/docker-desktop/
- **Linux**: `sudo apt-get install docker.io docker-compose`

## Quick Start

### 1. Start the Application

```bash
docker-compose up
```

That's it! The application will:
- ✅ Install clang automatically
- ✅ Set up Redis
- ✅ Start the web server
- ✅ Start the background worker

### 2. Access the Application

Open your browser to: **http://localhost:5000**

### 3. Stop the Application

```bash
docker-compose down
```

## What's Included

The Docker container includes:
- ✅ Python 3.11
- ✅ Clang/LLVM (for fuzzing)
- ✅ All Python dependencies
- ✅ Redis (for task queue)
- ✅ Celery worker

**No manual installation needed!**

## Configuration

Create a `.env` file for optional configuration:

```env
FLASK_SECRET_KEY=your-secret-key
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

## Data Persistence

Your scan results are stored in `./scans/` on your host machine, so they persist even if you restart the container.

## Updating

To update to the latest version:

```bash
docker-compose down
docker-compose pull
docker-compose up --build
```

## Troubleshooting

### Port 5000 already in use
Change the port in `docker-compose.yml`:
```yaml
ports:
  - "8080:5000"  # Use port 8080 instead
```

### Container won't start
Check logs:
```bash
docker-compose logs app
```

### Need to rebuild
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up
```

## Advanced: Development Mode

To develop with live code reloading:

```bash
docker-compose -f docker-compose.dev.yml up
```

This mounts your source code as a volume for instant updates.

## System Requirements

- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 2GB for Docker images + space for scan results
- **OS**: Windows 10+, macOS 10.14+, or Linux

## Support

For issues or questions, see the troubleshooting section or check the logs with `docker-compose logs`.
