# API Compatibility Report - Backend vs Extension

## Summary

✅ **Good News:** Your backend has most of the functionality needed!  
⚠️ **Minor Adjustments:** Need to add JSON response formats and one DELETE endpoint

## Detailed Analysis

### 1. POST /api/scan - Initiate Scan

**Extension Expects:** `POST /api/scan`

**Backend Has:** `POST /scan-public` ✅

**Status:** ✅ **EXISTS** - Just needs minor adjustments

**Current Implementation:**
- Located at line 1382 in `app.py`
- Accepts JSON requests with `repo_url`, `code_snippet`, or `zip_file`
- Returns HTML redirect for form submissions
- Supports both `cppcheck` and `codeql` analysis tools

**What Needs to Change:**
```python
# Current behavior (line ~1382)
@app.route('/scan-public', methods=['POST'])
def scan_public():
    # ... processes scan ...
    if is_form_submission:
        return redirect(url_for('scan_progress', scan_id=scan_id))
    # No JSON response for API clients!
```

**Recommended Fix:**
```python
# Option 1: Add /api/scan as alias
@app.route('/api/scan', methods=['POST'])
@app.route('/scan-public', methods=['POST'])
def scan_public():
    # ... existing code ...
    
    # At the end, add JSON response for API clients:
    if is_json_request or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'scanId': scan_id,
            'status': 'queued',
            'message': 'Scan initiated successfully'
        }), 202
    
    # Keep existing redirect for web UI
    return redirect(url_for('scan_progress', scan_id=scan_id))
```

**Extension Request Format:**
```json
{
  "code_snippet": "int main() { char buf[10]; gets(buf); }",
  "analysis_tool": "cppcheck"
}
```

**Expected Response:**
```json
{
  "scanId": "abc123-def456-...",
  "status": "queued",
  "message": "Scan initiated successfully"
}
```


### 2. GET /api/scan/<scan_id>/results - Get Scan Results

**Extension Expects:** `GET /api/scan/<scan_id>/results`

**Backend Has:** 
- `GET /api/scan-status/<scan_id>` ✅ (line 564)
- `GET /public-results/<scan_id>` ✅ (line 1699)

**Status:** ⚠️ **PARTIAL** - Has data but needs JSON format

**Current Implementation:**
```python
# Line 564 - Returns status only
@app.route('/api/scan-status/<scan_id>')
def api_scan_status(scan_id):
    # Returns: {'status': 'completed', 'progress': 100, ...}
    # Missing: vulnerability details

# Line 1699 - Returns HTML page
@app.route('/public-results/<scan_id>')
def public_results(scan_id):
    # Has vulnerabilities data but returns HTML template
    vulnerabilities = scan.vulnerabilities_json or []
    patches = scan.patches_json or []
```

**Recommended Fix:**
```python
@app.route('/api/scan/<scan_id>/results')
def api_scan_results(scan_id):
    """Get scan results in JSON format for VS Code extension"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = scan.vulnerabilities_json or []
        patches = scan.patches_json or []
        
        # Format vulnerabilities for extension
        formatted_vulns = []
        for vuln in vulnerabilities:
            formatted_vulns.append({
                'id': vuln.get('id', str(uuid.uuid4())),
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'Medium'),
                'file': vuln.get('file', ''),
                'line': vuln.get('line', 0),
                'column': vuln.get('column', 0),
                'endLine': vuln.get('endLine', vuln.get('line', 0)),
                'endColumn': vuln.get('endColumn', vuln.get('column', 0) + 10),
                'description': vuln.get('description', ''),
                'cwe': vuln.get('cwe', ''),
                'exploitability': vuln.get('exploitability', 0.5),
                'impact': vuln.get('impact', ''),
                'recommendation': vuln.get('recommendation', ''),
                'patch': next((p['content'] for p in patches if p.get('vuln_id') == vuln.get('id')), None)
            })
        
        # Calculate summary
        summary = {
            'total': len(formatted_vulns),
            'critical': sum(1 for v in formatted_vulns if v['severity'].lower() == 'critical'),
            'high': sum(1 for v in formatted_vulns if v['severity'].lower() == 'high'),
            'medium': sum(1 for v in formatted_vulns if v['severity'].lower() == 'medium'),
            'low': sum(1 for v in formatted_vulns if v['severity'].lower() == 'low')
        }
        
        return jsonify({
            'scanId': scan_id,
            'status': scan.status,
            'progress': 100 if scan.status == 'completed' else 50,
            'stage': 'Analysis Complete' if scan.status == 'completed' else 'In Progress',
            'vulnerabilities': formatted_vulns,
            'summary': summary
        })
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()
```

**Extension Expected Response:**
```json
{
  "scanId": "abc123-...",
  "status": "completed",
  "progress": 100,
  "stage": "Analysis Complete",
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "type": "Buffer Overflow",
      "severity": "High",
      "file": "main.c",
      "line": 42,
      "column": 10,
      "endLine": 42,
      "endColumn": 25,
      "description": "Potential buffer overflow",
      "cwe": "CWE-120",
      "exploitability": 0.85,
      "patch": "- gets(buf);\n+ fgets(buf, sizeof(buf), stdin);"
    }
  ],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  }
}
```


### 3. DELETE /api/scan/<scan_id> - Cancel Scan

**Extension Expects:** `DELETE /api/scan/<scan_id>`

**Backend Has:** ❌ **DOES NOT EXIST**

**Status:** ❌ **MISSING** - Needs to be added

**Recommended Implementation:**
```python
@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def api_cancel_scan(scan_id):
    """Cancel an active scan"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status in ['completed', 'failed', 'cancelled']:
            return jsonify({
                'error': f'Cannot cancel scan with status: {scan.status}'
            }), 400
        
        # Revoke Celery task if it exists
        if scan.celery_task_id:
            try:
                celery_app.control.revoke(scan.celery_task_id, terminate=True)
                logger.info(f"Revoked Celery task {scan.celery_task_id} for scan {scan_id}")
            except Exception as e:
                logger.warning(f"Failed to revoke Celery task: {e}")
        
        # Update scan status
        scan.status = 'cancelled'
        session_db.commit()
        
        logger.info(f"Scan {scan_id} cancelled successfully")
        
        return jsonify({
            'scanId': scan_id,
            'status': 'cancelled',
            'message': 'Scan cancelled successfully'
        })
    except Exception as e:
        logger.error(f"Error cancelling scan {scan_id}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()
```

**Extension Expected Response:**
```json
{
  "scanId": "abc123-...",
  "status": "cancelled",
  "message": "Scan cancelled successfully"
}
```


### 4. WebSocket /ws/scan/<scan_id> - Real-time Progress

**Extension Expects:** `WebSocket /ws/scan/<scan_id>`

**Backend Has:** ❌ **DOES NOT EXIST**

**Status:** ❌ **MISSING** - Optional (extension has polling fallback)

**Priority:** 🟢 **LOW** - Extension will automatically fall back to polling `/api/scan-status/<scan_id>`

**If You Want to Add It (Optional):**
```python
# Install: pip install flask-socketio
from flask_socketio import SocketIO, emit, join_room

socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    logger.info(f"WebSocket client connected: {request.sid}")
    emit('connected', {'status': 'ok'})

@socketio.on('subscribe')
def handle_subscribe(data):
    scan_id = data.get('scanId')
    if scan_id:
        join_room(scan_id)
        logger.info(f"Client {request.sid} subscribed to scan {scan_id}")
        emit('subscribed', {'scanId': scan_id})

# In your Celery task, emit progress updates:
def emit_progress(scan_id, progress, stage, message):
    socketio.emit('progress', {
        'type': 'progress',
        'scanId': scan_id,
        'progress': progress,
        'stage': stage,
        'message': message
    }, room=scan_id)

# At the end of app.py:
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
```

**Note:** Extension will work fine without WebSocket using polling fallback.


## Implementation Priority

### 🔴 High Priority (Required for MVP)

1. **Add JSON response to `/scan-public`** (5 minutes)
   - Add route alias: `@app.route('/api/scan', methods=['POST'])`
   - Return JSON for API clients instead of redirect
   - Keep existing HTML redirect for web UI

2. **Add `/api/scan/<scan_id>/results` endpoint** (15 minutes)
   - Reuse existing data from `/public-results/<scan_id>`
   - Format vulnerabilities for extension
   - Return JSON instead of HTML

### 🟡 Medium Priority (Nice to Have)

3. **Add `/api/scan/<scan_id>` DELETE endpoint** (10 minutes)
   - Revoke Celery task
   - Update scan status to 'cancelled'
   - Clean up resources

### 🟢 Low Priority (Optional)

4. **Add WebSocket support** (1-2 hours)
   - Install flask-socketio
   - Implement real-time progress updates
   - Extension works fine without this (uses polling)

## Quick Implementation Guide

### Step 1: Update /scan-public (5 minutes)

Add this at the top of `app.py` after imports:
```python
def is_api_request():
    """Check if request is from API client (VS Code extension)"""
    return (
        request.headers.get('Accept') == 'application/json' or
        (request.content_type and 'application/json' in request.content_type)
    )
```

Find the `/scan-public` route (line ~1382) and add route alias:
```python
@app.route('/api/scan', methods=['POST'])  # ADD THIS LINE
@app.route('/scan-public', methods=['POST'])
def scan_public():
    # ... existing code ...
```

At the end of the function (after scan is created), replace the redirect with:
```python
    # Return JSON for API clients, HTML redirect for web UI
    if is_api_request():
        return jsonify({
            'scanId': scan_id,
            'status': 'queued',
            'message': 'Scan initiated successfully'
        }), 202
    
    return redirect(url_for('scan_progress', scan_id=scan_id))
```

### Step 2: Add /api/scan/<scan_id>/results (15 minutes)

Add this new route anywhere in `app.py` (suggest after `/api/scan-status/<scan_id>`):

```python
@app.route('/api/scan/<scan_id>/results')
def api_scan_results(scan_id):
    """Get scan results in JSON format for VS Code extension"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        vulnerabilities = scan.vulnerabilities_json or []
        patches = scan.patches_json or []
        
        # Format for extension
        formatted_vulns = []
        for vuln in vulnerabilities:
            # Find matching patch
            patch_content = None
            for p in patches:
                if p.get('vuln_id') == vuln.get('id'):
                    patch_content = p.get('content')
                    break
            
            formatted_vulns.append({
                'id': vuln.get('id', str(uuid.uuid4())),
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'Medium'),
                'file': vuln.get('file', ''),
                'line': int(vuln.get('line', 0)),
                'column': int(vuln.get('column', 0)),
                'endLine': int(vuln.get('endLine', vuln.get('line', 0))),
                'endColumn': int(vuln.get('endColumn', vuln.get('column', 0) + 10)),
                'description': vuln.get('description', ''),
                'cwe': vuln.get('cwe', ''),
                'exploitability': float(vuln.get('exploitability', 0.5)),
                'impact': vuln.get('impact', ''),
                'recommendation': vuln.get('recommendation', ''),
                'patch': patch_content
            })
        
        summary = {
            'total': len(formatted_vulns),
            'critical': sum(1 for v in formatted_vulns if v['severity'].lower() == 'critical'),
            'high': sum(1 for v in formatted_vulns if v['severity'].lower() == 'high'),
            'medium': sum(1 for v in formatted_vulns if v['severity'].lower() == 'medium'),
            'low': sum(1 for v in formatted_vulns if v['severity'].lower() == 'low')
        }
        
        return jsonify({
            'scanId': scan_id,
            'status': scan.status,
            'progress': 100 if scan.status == 'completed' else 50,
            'stage': 'Analysis Complete' if scan.status == 'completed' else 'In Progress',
            'vulnerabilities': formatted_vulns,
            'summary': summary
        })
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()
```

### Step 3: Add DELETE endpoint (10 minutes)

Add this new route:

```python
@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def api_cancel_scan(scan_id):
    """Cancel an active scan"""
    session_db = get_session()
    try:
        scan = session_db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status in ['completed', 'failed', 'cancelled']:
            return jsonify({
                'error': f'Cannot cancel scan with status: {scan.status}'
            }), 400
        
        # Revoke Celery task if exists
        if hasattr(scan, 'celery_task_id') and scan.celery_task_id:
            try:
                celery_app.control.revoke(scan.celery_task_id, terminate=True)
                logger.info(f"Revoked Celery task for scan {scan_id}")
            except Exception as e:
                logger.warning(f"Failed to revoke Celery task: {e}")
        
        scan.status = 'cancelled'
        session_db.commit()
        
        return jsonify({
            'scanId': scan_id,
            'status': 'cancelled',
            'message': 'Scan cancelled successfully'
        })
    except Exception as e:
        logger.error(f"Error cancelling scan: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()
```

## Testing the Changes

### Test with curl

```bash
# Test scan initiation
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "code_snippet": "int main() { char buf[10]; gets(buf); return 0; }",
    "analysis_tool": "cppcheck"
  }'

# Expected: {"scanId": "...", "status": "queued", ...}

# Test results (replace <scan_id>)
curl http://localhost:5000/api/scan/<scan_id>/results

# Expected: {"scanId": "...", "vulnerabilities": [...], ...}

# Test cancellation
curl -X DELETE http://localhost:5000/api/scan/<scan_id>

# Expected: {"scanId": "...", "status": "cancelled", ...}
```

### Test with Extension

1. Start backend: `docker-compose up`
2. Apply the changes above to `app.py`
3. Restart Docker: `docker-compose restart app`
4. Launch extension: Press F5 in VS Code
5. Open a C/C++ file
6. Right-click → "Scan for Vulnerabilities"
7. Watch for diagnostics to appear

## Summary

✅ **Backend has 90% of what's needed!**

Just need to:
1. Add JSON responses to existing `/scan-public` route (5 min)
2. Add new `/api/scan/<scan_id>/results` endpoint (15 min)
3. Add DELETE endpoint for cancellation (10 min)

**Total time: ~30 minutes of backend work**

Then the extension will be fully functional! 🎉
