# Development Setup

This guide explains how to set up AutoVulRepair for development with live code reloading.

## Quick Start

### Option 1: Use Development Scripts (Recommended)
```powershell
# Start development environment
.\dev-start.ps1

# Stop development environment  
.\dev-stop.ps1
```

### Option 2: Manual Docker Compose
```bash
# Start with live reloading
docker-compose -f docker-compose-dev.yml up -d

# Stop
docker-compose -f docker-compose-dev.yml down
```

## What's Different in Development Mode?

### ✅ Live Code Reloading
- **No rebuilding needed** - Code changes are reflected immediately
- Flask auto-reloader detects file changes and restarts the server
- Volume mounts sync your local code with the container

### ✅ Debug Mode Enabled
- Detailed error messages and stack traces
- Flask debug toolbar (if enabled)
- Enhanced logging

### ✅ Fast Iteration
- Make changes → Save file → Changes appear immediately
- No more waiting for Docker builds during development

## Development vs Production

| Feature | Development | Production |
|---------|-------------|------------|
| Code Changes | Immediate (volume mount) | Requires rebuild |
| Debug Mode | Enabled | Disabled |
| Error Details | Full stack traces | Minimal |
| Performance | Slower (debug overhead) | Optimized |
| Security | Less secure (debug info) | Hardened |

## File Structure

```
├── docker-compose-dev.yml     # Development configuration
├── docker-compose-minimal.yml # Production-like minimal setup  
├── dev-start.ps1             # Development startup script
├── dev-stop.ps1              # Development stop script
└── Dockerfile.minimal        # Shared container definition
```

## Tips for Development

1. **Use the development setup** for coding and testing
2. **Test with minimal setup** before deploying to production
3. **Check logs** with: `docker-compose -f docker-compose-dev.yml logs -f`
4. **Restart services** if needed: `docker-compose -f docker-compose-dev.yml restart app`

## Troubleshooting

### Code changes not appearing?
- Check that Flask auto-reloader is working: look for restart messages in logs
- Verify volume mounts are correct in docker-compose-dev.yml
- Try restarting the app container: `docker-compose -f docker-compose-dev.yml restart app`

### Performance issues?
- Development mode has debug overhead - use minimal setup for performance testing
- Consider using production build for load testing

### Permission issues?
- Ensure your user has permissions to the project directory
- On Windows, make sure Docker Desktop has access to the drive