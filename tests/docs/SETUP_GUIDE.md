# AutoVulRepair - Complete Setup Guide

This guide will help you set up the entire AutoVulRepair project from scratch after cloning the repository.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Backend Setup](#backend-setup)
3. [Docker Setup](#docker-setup)
4. [VS Code Extension Setup](#vs-code-extension-setup)
5. [Testing the Setup](#testing-the-setup)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software
- **Python 3.11+** - [Download](https://www.python.org/downloads/)
- **Node.js 18+** - [Download](https://nodejs.org/)
- **Docker Desktop** - [Download](https://www.docker.com/products/docker-desktop/)
- **VS Code** - [Download](https://code.visualstudio.com/)
- **Git** - [Download](https://git-scm.com/)

### Optional Tools
- **vsce** (VS Code Extension Manager) - Install via: `npm install -g @vscode/vsce`

### System Requirements
- **OS**: Windows 10/11, macOS 10.15+, or Linux
- **RAM**: 8GB minimum (16GB recommended)
- **Disk**: 10GB free space
- **Docker**: Must be running with at least 4GB RAM allocated

---

## Backend Setup

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd autovulrepair
```

### Step 2: Create Python Virtual Environment
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
The `.env` file is already in the repository. Review and update if needed:

```bash
# Open .env file and verify/update these values:
FLASK_SECRET_KEY=<your-secret-key>
PORT=5000
DATABASE_PATH=./scans.db
REDIS_URL=redis://localhost:6379/0
SCANS_DIR=./scans

# API Keys (optional for AI-powered repair)
GROQ_API_KEY=<your-groq-api-key>
GEMINI_API_KEY=<your-gemini-api-key>
```

**Note:** The existing API keys in `.env` are for development. For production, generate your own:
- Groq API: https://console.groq.com/keys (FREE)
- Gemini API: https://makersuite.google.com/app/apikey (FREE)

### Step 5: Initialize Database
```bash
python -c "from app import init_db; init_db()"
```

This creates `scans.db` with the required schema.

---

## Docker Setup

### Step 1: Verify Docker is Running
```bash
docker --version
docker ps
```

If Docker isn't running, start Docker Desktop.

### Step 2: Build Docker Images for Analysis Tools

**Build Cppcheck Image:**
```bash
cd dockerfiles/cppcheck
docker build -t vuln-scanner/cppcheck:latest .
cd ../..
```

**Build CodeQL Image:**
```bash
cd dockerfiles/codeql
docker build -t vuln-scanner/codeql:latest .
cd ../..
```

**Verify Images:**
```bash
docker images | grep vuln-scanner
```

You should see:
```
vuln-scanner/cppcheck   latest   <image-id>   <time>   617MB
vuln-scanner/codeql     latest   <image-id>   <time>   2.5GB
```

### Step 3: Start Backend Services with Docker Compose
```bash
docker-compose up -d
```

This starts:
- **app** - Flask backend (port 5000)
- **celery** - Background task worker
- **redis** - Message broker

**Verify Services:**
```bash
docker-compose ps
```

All services should show "Up" status.

**View Logs:**
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app
docker-compose logs -f celery
```

### Step 4: Test Backend API
```bash
# Test health endpoint
curl http://localhost:5000/

# Or use the test script
python test_api_endpoints.py
```

Expected output: Status 200 with HTML response or JSON success.

---

## VS Code Extension Setup

### Step 1: Navigate to Extension Directory
```bash
cd vscode-extension
```

### Step 2: Install Node Dependencies
```bash
npm install
```

This installs ~555 packages (may take 2-3 minutes).

### Step 3: Compile Extension
```bash
npm run compile
```

This runs webpack and creates `dist/extension.js`.

### Step 4: Package Extension
```bash
# If you have vsce installed globally
vsce package --allow-missing-repository

# If not, use npx
npx vsce package --allow-missing-repository
```

This creates `autovulrepair-0.1.0.vsix` (~1.5MB).

### Step 5: Install Extension in VS Code

**Option A: Command Line**
```bash
code --install-extension autovulrepair-0.1.0.vsix --force
```

**Option B: VS Code UI**
1. Open VS Code
2. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
3. Type "Extensions: Install from VSIX"
4. Select `autovulrepair-0.1.0.vsix`

### Step 6: Restart VS Code
Close and reopen VS Code to activate the extension.

### Step 7: Verify Extension is Loaded
1. Press `Ctrl+Shift+P`
2. Type "AutoVulRepair"
3. You should see commands like:
   - AutoVulRepair: Scan for Vulnerabilities
   - AutoVulRepair: Test Backend Connection
   - AutoVulRepair: Clear All Diagnostics

---

## Testing the Setup

### Test 1: Backend Connection
1. Open VS Code
2. Press `Ctrl+Shift+P`
3. Run "AutoVulRepair: Test Backend Connection"
4. Should show: "Backend connection successful"

### Test 2: Scan a File
1. Open `test.c` in VS Code (in the root directory)
2. Right-click in the editor
3. Select "Scan for Vulnerabilities"
4. Wait 5-10 seconds
5. You should see:
   - Squiggly lines under vulnerable code
   - Vulnerabilities in the AutoVulRepair sidebar
   - Message: "Found 2 vulnerabilities"

### Test 3: View Sidebar
1. Click the AutoVulRepair icon in the Activity Bar (left side)
2. You should see:
   ```
   test.c (2)
   ├─ [High] Unknown (Line 7)
   └─ [Medium] Unknown (Line 6)
   ```
3. Click on a vulnerability to jump to that line

### Test 4: Backend Logs
```bash
# Check if scan was processed
docker-compose logs app --tail 50

# Should show:
# [SCAN_SUBMISSION] New scan request received
# [CPPCHECK] Found X vulnerabilities
# [RESPONSE] POST /api/scan - Status: 202
```

---

## Troubleshooting

### Backend Issues

**Problem: "Cannot connect to backend"**
```bash
# Check if Docker containers are running
docker-compose ps

# Restart if needed
docker-compose restart

# Check logs
docker-compose logs app
```

**Problem: "Cppcheck Docker image not found"**
```bash
# Rebuild the image
cd dockerfiles/cppcheck
docker build -t vuln-scanner/cppcheck:latest .
```

**Problem: "Redis connection failed"**
```bash
# Check Redis is running
docker-compose ps redis

# Restart Redis
docker-compose restart redis
```

**Problem: "Database error"**
```bash
# Reinitialize database
rm scans.db
python -c "from app import init_db; init_db()"
```

### Extension Issues

**Problem: "Extension not found"**
```bash
# Verify installation
code --list-extensions | grep autovulrepair

# Reinstall
code --uninstall-extension autovulrepair.autovulrepair
code --install-extension vscode-extension/autovulrepair-0.1.0.vsix --force
```

**Problem: "No vulnerabilities found" (but there are vulnerabilities)**
- Check Developer Console: `Ctrl+Shift+I` → Console tab
- Look for errors or `[Sidebar]` logs
- Verify backend is running: `curl http://localhost:5000/`

**Problem: "Extension commands not showing"**
- Restart VS Code completely
- Check if extension is activated: Look for "AutoVulRepair extension is now active" in console
- Verify you're editing a C/C++ file (`.c`, `.cpp`, `.h`, `.hpp`)

**Problem: "Scan timeout"**
- Increase timeout in settings: `autoVulRepair.scanTimeout`
- Check backend logs for errors
- Verify Docker has enough resources (4GB+ RAM)

### Docker Issues

**Problem: "Docker daemon not running"**
- Start Docker Desktop
- Wait for it to fully start (green icon)
- Run `docker ps` to verify

**Problem: "Port 5000 already in use"**
```bash
# Find process using port 5000
# Windows
netstat -ano | findstr :5000

# macOS/Linux
lsof -i :5000

# Kill the process or change port in .env and docker-compose.yml
```

**Problem: "Out of disk space"**
```bash
# Clean up old Docker data
docker system prune -a

# Remove old scan data
rm -rf scans/*
```

---

## Development Workflow

### Running Backend Locally (without Docker)
```bash
# Terminal 1: Start Redis
docker run -p 6379:6379 redis:alpine

# Terminal 2: Start Flask
python app.py

# Terminal 3: Start Celery
python celery_worker.py
```

### Rebuilding Extension After Changes
```bash
cd vscode-extension
npm run compile
vsce package --allow-missing-repository
code --install-extension autovulrepair-0.1.0.vsix --force
```

### Running Tests

**Backend Tests:**
```bash
pytest tests/
```

**Extension Tests:**
```bash
cd vscode-extension
npm test
```

---

## Quick Reference

### Start Everything
```bash
# Backend
docker-compose up -d

# Extension (if not installed)
cd vscode-extension
npm install
npm run compile
vsce package --allow-missing-repository
code --install-extension autovulrepair-0.1.0.vsix --force
```

### Stop Everything
```bash
docker-compose down
```

### View Logs
```bash
docker-compose logs -f app
docker-compose logs -f celery
```

### Restart Services
```bash
docker-compose restart app
docker-compose restart celery
```

---

## Next Steps

1. **Test with your own C/C++ files**
2. **Configure settings** in VS Code: `Ctrl+,` → Search "AutoVulRepair"
3. **Read the documentation** in `docs/` folder
4. **Report issues** if you encounter problems

---

## Support

- **Documentation**: See `docs/` folder
- **API Reference**: See `BACKEND_API_CHANGES.md`
- **Extension Guide**: See `vscode-extension/README.md`
- **Testing Guide**: See `TESTING_CHECKLIST.md`

---

## Summary Checklist

- [ ] Python 3.11+ installed
- [ ] Node.js 18+ installed
- [ ] Docker Desktop installed and running
- [ ] Repository cloned
- [ ] Python virtual environment created and activated
- [ ] Python dependencies installed (`pip install -r requirements.txt`)
- [ ] Database initialized
- [ ] Docker images built (cppcheck, codeql)
- [ ] Docker Compose services started (`docker-compose up -d`)
- [ ] Backend API tested (http://localhost:5000/)
- [ ] Extension dependencies installed (`npm install`)
- [ ] Extension compiled (`npm run compile`)
- [ ] Extension packaged (`vsce package`)
- [ ] Extension installed in VS Code
- [ ] VS Code restarted
- [ ] Test scan completed successfully

**Estimated Setup Time:** 30-45 minutes (depending on download speeds)

---

**Last Updated:** 2026-03-17
**Version:** 1.0.0
