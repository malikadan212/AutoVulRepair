# VS Code Extension Testing Guide

## Overview

This guide walks you through testing the AutoVulRepair VS Code extension with your Docker-based backend.

## Prerequisites

✅ Docker Desktop installed and running  
✅ VS Code 1.75.0 or later  
✅ Node.js 18+  
✅ Extension dependencies installed (`npm install` in vscode-extension/)

## Step 1: Start the Backend

### Start Docker Services

From the main project directory (not vscode-extension):

```bash
# Start all services (Flask app, Redis, Celery worker)
docker-compose up
```

Wait for these messages:
- `redis_1   | Ready to accept connections`
- `app_1     | Running on http://0.0.0.0:5000`
- `celery_1  | celery@... ready`

The backend will be available at: **http://localhost:5000**

### Verify Backend is Running

Open browser to http://localhost:5000 - you should see the AutoVulRepair web interface.

## Step 2: Check API Compatibility

The VS Code extension expects these REST API endpoints:

### Currently Available in Backend ✅
- `GET /api/scan-status/<scan_id>` - Get scan status
- `POST /api/fuzz/start/<scan_id>` - Start fuzzing campaign
- `GET /api/fuzz/results/<scan_id>` - Get fuzzing results

### Need to be Added ⚠️
- `POST /api/scan` - Initiate scan (extension expects this)
- `GET /api/scan/<scan_id>/results` - Get scan results (extension format)
- `DELETE /api/scan/<scan_id>` - Cancel scan
- `WebSocket /ws/scan/<scan_id>` - Real-time progress updates

### Workaround for Testing

For initial testing, you can:
1. Create a scan through the web interface
2. Note the scan ID
3. Use the extension to view results of existing scans


## Step 3: Launch the Extension

### Open Extension in VS Code

```bash
cd vscode-extension
code .
```

### Start Debugging

Press **F5** (or Run → Start Debugging)

This will:
1. Compile the extension
2. Open a new "Extension Development Host" window
3. Load your extension in that window

### Verify Extension Loaded

In the Extension Development Host window:
1. Check the Activity Bar (left sidebar) for the AutoVulRepair icon
2. Open Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
3. Type "AutoVulRepair" - you should see all commands

## Step 4: Test Core Features

### Test 1: Backend Connection

1. Open Command Palette
2. Run: `AutoVulRepair: Test Backend Connection`
3. Expected: Success message or connection error

**If connection fails:**
- Verify Docker services are running: `docker ps`
- Check backend URL in settings: `autoVulRepair.backendURL`
- Default should be: `http://localhost:5000`

### Test 2: View Existing Scan Results

Since the scan initiation endpoint needs to be added, test with existing scans:

1. **Create a scan via web interface:**
   - Go to http://localhost:5000
   - Submit a repository or code snippet
   - Note the scan ID from the URL (e.g., `abc123-def456-...`)

2. **View in extension:**
   - Open a C/C++ file in the Extension Development Host
   - Open Command Palette
   - Run: `AutoVulRepair: View Scan Results` (if implemented)
   - Or manually check: `GET http://localhost:5000/api/scan-status/<scan_id>`

### Test 3: Sidebar View

1. Click the AutoVulRepair icon in Activity Bar
2. Sidebar should open showing "Vulnerabilities" view
3. Initially empty (no scans yet)

### Test 4: Configuration

1. Open Settings (Ctrl+, / Cmd+,)
2. Search for "AutoVulRepair"
3. Verify all settings appear:
   - Backend URL
   - Background Scan Enabled
   - Background Scan Delay
   - Max File Size KB
   - Exclude Patterns
   - Max Concurrent Scans
   - Default Severity Filter
   - Enable WebSocket Progress
   - Allow Self Signed Certificates

4. Try changing Backend URL to test validation


## Step 5: Debug and Troubleshooting

### View Extension Logs

In the Extension Development Host window:
1. Open Debug Console (View → Debug Console)
2. Look for extension output and errors

### View Backend Logs

In the terminal running `docker-compose up`:
- Watch for API requests
- Check for errors in Flask app, Redis, or Celery

### Common Issues

#### "Cannot connect to backend"
- Verify Docker services: `docker ps`
- Check if port 5000 is accessible: `curl http://localhost:5000`
- Check firewall settings

#### "Extension not loading"
- Check Debug Console for compilation errors
- Verify all dependencies installed: `npm install`
- Try rebuilding: `npm run compile`

#### "Commands not appearing"
- Reload Extension Development Host: Ctrl+R / Cmd+R
- Check package.json has all commands registered
- Verify activation events in package.json

#### "Tests failing"
- Run tests: `npm run test:unit`
- Check for TypeScript errors: `npm run compile`
- Fix linting issues: `npm run lint -- --fix`

## Step 6: Next Steps for Full Integration

### Backend API Additions Needed

To enable full extension functionality, add these endpoints to `app.py`:

#### 1. POST /api/scan
```python
@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Initiate a new scan from VS Code extension"""
    data = request.json
    file_path = data.get('filePath')
    file_content = data.get('fileContent')
    scan_type = data.get('scanType', 'cppcheck')
    
    # Create scan record
    scan_id = str(uuid.uuid4())
    # ... implementation
    
    return jsonify({
        'scanId': scan_id,
        'status': 'queued'
    })
```

#### 2. GET /api/scan/<scan_id>/results
```python
@app.route('/api/scan/<scan_id>/results')
def api_scan_results(scan_id):
    """Get scan results in extension format"""
    # Load scan from database
    # Format vulnerabilities for extension
    return jsonify({
        'scanId': scan_id,
        'status': 'completed',
        'vulnerabilities': [
            {
                'id': 'vuln-1',
                'type': 'Buffer Overflow',
                'severity': 'High',
                'file': 'main.c',
                'line': 42,
                'column': 10,
                'description': '...',
                'cwe': 'CWE-120',
                'exploitability': 0.85,
                'patch': '...'  # Optional
            }
        ]
    })
```

#### 3. DELETE /api/scan/<scan_id>
```python
@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def api_cancel_scan(scan_id):
    """Cancel an active scan"""
    # Revoke Celery task
    # Update scan status
    return jsonify({'status': 'cancelled'})
```

#### 4. WebSocket /ws/scan/<scan_id>
```python
from flask_socketio import SocketIO, emit

socketio = SocketIO(app)

@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'ok'})

@socketio.on('subscribe')
def handle_subscribe(data):
    scan_id = data.get('scanId')
    # Join room for this scan
    # Send progress updates
```

### Testing with Full API

Once endpoints are added:

1. **Test File Scan:**
   - Open a C/C++ file
   - Right-click → "Scan for Vulnerabilities"
   - Watch progress indicator
   - Verify diagnostics appear

2. **Test Patch Application:**
   - Click on diagnostic with patch
   - Click "View Patch" quick fix
   - Verify diff view opens
   - Click "Apply Patch"
   - Verify code updates

3. **Test Background Scanning:**
   - Enable: `autoVulRepair.backgroundScanEnabled: true`
   - Edit and save a C/C++ file
   - Verify automatic scan after delay

## Monitoring

### Extension Performance
- Activation time: Should be < 2 seconds
- Scan initiation: Should be < 1 second
- UI responsiveness: No blocking operations

### Backend Performance
- API response time: Should be < 500ms
- Scan completion: Depends on file size
- WebSocket latency: Should be < 100ms

## Success Criteria

✅ Extension loads without errors  
✅ Backend connection successful  
✅ Commands appear in Command Palette  
✅ Sidebar view displays  
✅ Settings are configurable  
✅ Can view existing scan results  
✅ (After API additions) Can initiate scans  
✅ (After API additions) Can view/apply patches  
✅ (After API additions) Background scanning works  

## Resources

- Extension source: `vscode-extension/src/`
- Backend source: `app.py`
- Docker config: `docker-compose.yml`
- Extension tests: `vscode-extension/test/unit/`
- Backend API docs: Check existing `/api/*` routes in `app.py`
