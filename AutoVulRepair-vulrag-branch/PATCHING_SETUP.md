# AI Patching System - Setup Guide

## Overview

The AI-powered patching system is now fully integrated into AutoVulRepair. It uses Google's Gemini AI with CVE database context to generate intelligent security patches.

## Features

✅ AI-powered patch generation using Gemini Pro
✅ CVE database integration via FAISS vector search
✅ Detailed explanations and testing recommendations
✅ Batch patch generation for multiple vulnerabilities
✅ Export patches as JSON
✅ Track patch application status

## Setup Instructions

### 1. Install Dependencies

```bash
pip install google-generativeai
```

Or install all patching dependencies:

```bash
pip install -r requirements_patching.txt
```

### 2. Get Gemini API Key

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Click "Create API Key"
3. Copy your API key (starts with `AIza...`)

### 3. Configure Environment

Add to your `.env` file:

```bash
GEMINI_API_KEY=your_api_key_here
```

### 4. (Optional) Setup CVE Database

For enhanced patch generation with CVE context:

```bash
# If you have cves.db, convert it to FAISS
# python cve_to_faiss.py --index-name cve-full --max-records 10000
```

This creates a FAISS index in `faiss_indexes/cve-full/` that the patching system will use automatically.

### 5. Restart Application

```bash
python app.py
```

You should see:
```
✓ AI Patch Generator initialized
```

## Usage

### Via Web Interface

1. Run a scan to find vulnerabilities
2. Go to "Detailed Findings" page
3. Click "AI-Powered Patching" button
4. Select a vulnerability to patch
5. Click "Generate AI Patch"
6. Review the generated patch, explanation, and testing recommendations
7. Mark as applied or download the patch

### Batch Generation

From the Patch Dashboard:
- Click "Generate All Patches" to create patches for all vulnerabilities at once

### Export Patches

- Click "Export Patches" to download all patches as JSON

## How It Works

1. **Vulnerability Analysis**: The system analyzes the vulnerability details (type, severity, code context)

2. **CVE Context**: Searches the FAISS CVE database for similar vulnerabilities and their fixes

3. **AI Generation**: Sends the vulnerability + CVE context to Gemini AI to generate:
   - Patched code
   - Detailed explanation
   - Testing recommendations
   - Additional security recommendations

4. **Storage**: Patches are saved to `scans/{scan_id}/patches.json`

## API Endpoints

### Generate Single Patch
```
POST /api/patch/{scan_id}/generate/{vuln_index}
```

### Generate All Patches
```
POST /api/patch/{scan_id}/batch-generate
```

### Mark Patch as Applied
```
POST /api/patch/{scan_id}/apply/{vuln_index}
```

### Export Patches
```
GET /api/patch/{scan_id}/export
```

## Troubleshooting

### "AI Patching not available"

**Cause**: Missing dependencies or API key

**Solution**:
```bash
pip install google-generativeai
# Add GEMINI_API_KEY to .env
```

### "FAISS index not available"

**Cause**: CVE database not converted to FAISS

**Impact**: Patches will still work, but without CVE context

**Solution** (optional):
```bash
python cve_to_faiss.py --index-name cve-full
```

### Slow patch generation

**Cause**: Gemini API rate limits or network latency

**Solution**: 
- Use batch generation for multiple patches
- Wait a few seconds between individual patch generations

## File Structure

```
AutoVulRepair/
├── ai_patch_generator.py          # Core patching logic
├── search_cve_faiss.py            # CVE database search
├── templates/
│   ├── patch_dashboard.html       # Main patching UI
│   └── patch_vulnerability.html   # Single patch UI
├── faiss_indexes/
│   └── cve-full/                  # CVE vector database
└── scans/
    └── {scan_id}/
        └── patches.json           # Generated patches
```

## Example Patch Output

```json
{
  "0": {
    "patched_code": "// Fixed buffer overflow\nchar buffer[256];\nstrncpy(buffer, input, sizeof(buffer)-1);\nbuffer[sizeof(buffer)-1] = '\\0';",
    "explanation": "The vulnerability was a buffer overflow...",
    "testing_recommendations": "1. Test with inputs larger than buffer size...",
    "additional_recommendations": "Consider using std::string...",
    "related_cves": [
      {
        "cve_id": "CVE-2023-12345",
        "severity": "HIGH",
        "description": "Buffer overflow in similar context..."
      }
    ],
    "status": "generated",
    "file": "src/main.c",
    "line": 42
  }
}
```

## Next Steps

1. ✅ Setup complete - AI patching is now available
2. Run a scan to find vulnerabilities
3. Use the "AI-Powered Patching" button to generate fixes
4. Review and apply patches to your code
5. Re-run scans to verify fixes

## Support

For issues or questions:
- Check the logs for detailed error messages
- Ensure GEMINI_API_KEY is set correctly
- Verify google-generativeai is installed
- Check that the Gemini API key has proper permissions

## Cost Considerations

- Gemini API has a free tier with generous limits
- Each patch generation uses ~1000-2000 tokens
- Batch generation is more efficient than individual patches
- Monitor your API usage at [Google AI Studio](https://makersuite.google.com/)

---

**Status**: ✅ AI Patching System Fully Integrated

The system is ready to use. Just set your GEMINI_API_KEY and start generating patches!
