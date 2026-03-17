# Backend API Requirements for VS Code Extension

## Overview

The VS Code extension requires specific REST API endpoints to function. This document lists what's needed vs. what already exists in the backend.

## Current Backend Status

### ✅ Already Implemented

These endpoints exist and can be used:

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/scan-status/<scan_id>` | GET | Get scan status | ✅ Available |
| `/api/fuzz/start/<scan_id>` | POST | Start fuzzing | ✅ Available |
| `/api/fuzz/results/<scan_id>` | GET | Get fuzz results | ✅ Available |
| `/api/generate-stage1-patches/<scan_id>` | POST | Generate patches | ✅ Available |
| `/api/repair/start/<scan_id>` | POST | Start AI repair | ✅ Available |
| `/api/repair/status/<scan_id>` | GET | Get repair status | ✅ Available |
| `/api/repair/patch/<scan_id>/<crash_id>` | GET | Get patch details | ✅ Available |

### ⚠️ Need to be Added

These endpoints are required by the extension but don't exist yet:

| Endpoint | Method | Purpose | Priority |
|----------|--------|---------|----------|
| `/api/scan` | POST | Initiate new scan | 🔴 High |
| `/api/scan/<scan_id>/results` | GET | Get formatted results | 🔴 High |
| `/api/scan/<scan_id>` | DELETE | Cancel scan | 🟡 Medium |
| `/ws/scan/<scan_id>` | WebSocket | Real-time progress | 🟢 Low |

## Required Endpoint Specifications

### 1. POST /api/scan (High Priority)

Initiate a new vulnerability scan from the extension.

**Request:**
```json
{
  "filePath": "path/to/file.c",
  "fileContent": "int main() { ... }",
  "scanType": "cppcheck",
  "options": {
    "enabledChecks": ["all"],
    "severity": ["error", "warning"]
  }
}
```

**Response:**
```json
{
  "scanId": "abc123-def456-...",
  "status": "queued",
  "message": "Scan initiated successfully"
}
```

**Implementation Notes:**
- Reuse existing scan creation logic from web interface
- Store file content temporarily or in database
- Queue Celery task for analysis
- Return scan ID immediately


### 2. GET /api/scan/<scan_id>/results (High Priority)

Get scan results formatted for the VS Code extension.

**Response:**
```json
{
  "scanId": "abc123-def456-...",
  "status": "completed",
  "progress": 100,
  "stage": "Analysis Complete",
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "type": "Buffer Overflow",
      "severity": "High",
      "file": "src/main.c",
      "line": 42,
      "column": 10,
      "endLine": 42,
      "endColumn": 25,
      "description": "Potential buffer overflow when copying user input",
      "cwe": "CWE-120",
      "exploitability": 0.85,
      "impact": "Code execution possible",
      "recommendation": "Use strncpy with size limit",
      "patch": "- strcpy(buffer, input);\n+ strncpy(buffer, input, sizeof(buffer) - 1);\n+ buffer[sizeof(buffer) - 1] = '\\0';"
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

**Implementation Notes:**
- Convert existing scan results to this format
- Map Cppcheck/CodeQL findings to vulnerability objects
- Include patch if available from repair module
- Calculate exploitability score (can be placeholder initially)

### 3. DELETE /api/scan/<scan_id> (Medium Priority)

Cancel an active scan.

**Response:**
```json
{
  "scanId": "abc123-def456-...",
  "status": "cancelled",
  "message": "Scan cancelled successfully"
}
```

**Implementation Notes:**
- Revoke Celery task if running
- Update scan status in database
- Clean up temporary files
- Return error if scan already completed

### 4. WebSocket /ws/scan/<scan_id> (Low Priority)

Real-time progress updates during scan.

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:5000/ws/scan/abc123-def456-...');
```

**Messages (Server → Client):**
```json
{
  "type": "progress",
  "scanId": "abc123-def456-...",
  "progress": 45,
  "stage": "Running static analysis",
  "message": "Analyzing file 3 of 10"
}
```

```json
{
  "type": "complete",
  "scanId": "abc123-def456-...",
  "status": "completed",
  "vulnerabilitiesFound": 5
}
```

```json
{
  "type": "error",
  "scanId": "abc123-def456-...",
  "error": "Analysis failed: Invalid C++ syntax"
}
```

**Implementation Notes:**
- Use Flask-SocketIO or similar
- Emit progress updates from Celery tasks
- Handle client disconnection gracefully
- Extension will fall back to polling if WebSocket unavailable


## Implementation Roadmap

### Phase 1: Basic Scan Support (High Priority)

Implement these to enable basic extension functionality:

1. **POST /api/scan** - Allow extension to initiate scans
2. **GET /api/scan/<scan_id>/results** - Return formatted results

**Estimated effort:** 2-4 hours

**Testing:**
- Extension can scan files
- Results display as diagnostics
- Sidebar shows vulnerabilities

### Phase 2: Scan Management (Medium Priority)

Add scan control features:

3. **DELETE /api/scan/<scan_id>** - Allow cancellation

**Estimated effort:** 1-2 hours

**Testing:**
- Extension can cancel running scans
- Resources cleaned up properly

### Phase 3: Real-time Updates (Low Priority)

Enhance user experience with live progress:

4. **WebSocket /ws/scan/<scan_id>** - Real-time progress

**Estimated effort:** 3-5 hours (if not familiar with WebSockets)

**Testing:**
- Progress bar updates in real-time
- Graceful fallback to polling

## Adapter Pattern (Alternative)

If modifying the backend is not immediately feasible, you can create an adapter service:

```
VS Code Extension → Adapter Service → Existing Backend
```

The adapter would:
- Translate extension API calls to existing backend endpoints
- Format responses for extension consumption
- Handle WebSocket → polling conversion
- Run as a separate lightweight service

**Pros:**
- No backend changes needed
- Can be developed independently
- Easy to test

**Cons:**
- Additional service to maintain
- Extra network hop (minimal latency)
- Duplicate some logic

## Testing the APIs

### Using curl

```bash
# Test scan initiation
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "filePath": "test.c",
    "fileContent": "int main() { char buf[10]; gets(buf); }",
    "scanType": "cppcheck"
  }'

# Test results retrieval
curl http://localhost:5000/api/scan/<scan_id>/results

# Test cancellation
curl -X DELETE http://localhost:5000/api/scan/<scan_id>
```

### Using the Extension

Once endpoints are implemented:

1. Open a C/C++ file in VS Code
2. Right-click → "Scan for Vulnerabilities"
3. Watch for progress indicator
4. Check Debug Console for API calls
5. Verify diagnostics appear in editor

## Compatibility Notes

### Existing Endpoints

The extension can already use these existing endpoints:

- **Fuzzing:** Use `/api/fuzz/start/<scan_id>` for fuzzing campaigns
- **Patches:** Use `/api/repair/patch/<scan_id>/<crash_id>` for patch retrieval
- **Status:** Use `/api/scan-status/<scan_id>` for status checks

### Data Format Mapping

Map existing backend data to extension format:

| Backend Field | Extension Field | Notes |
|---------------|-----------------|-------|
| `vulnerability_type` | `type` | Direct mapping |
| `severity_level` | `severity` | Capitalize first letter |
| `file_path` | `file` | Relative to workspace |
| `line_number` | `line` | 1-indexed |
| `column_number` | `column` | 0-indexed in extension |
| `cwe_id` | `cwe` | Format as "CWE-XXX" |
| `suggested_fix` | `patch` | Diff format preferred |

## Questions?

If you need help implementing these endpoints:

1. Check existing scan endpoints in `app.py` for patterns
2. Look at Celery task definitions in `src/queue/tasks.py`
3. Review scan model in `src/models/scan.py`
4. See extension API client in `vscode-extension/src/apiClient.ts`

The extension is designed to be flexible and can work with variations in the API response format.
