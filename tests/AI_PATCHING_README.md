# 🤖 AI-Powered Patching System

## Overview

The AI-Powered Patching System is now fully integrated into AutoVulRepair! It uses Google's Gemini AI combined with a CVE database to automatically generate intelligent, secure patches for discovered vulnerabilities.

## ✨ Features

- **AI-Powered Generation**: Uses Gemini Pro to generate context-aware patches
- **CVE Database Integration**: Leverages FAISS vector search to find similar vulnerabilities
- **Detailed Explanations**: Each patch includes why it works and how it fixes the issue
- **Testing Recommendations**: Suggests specific test cases for each patch
- **Batch Processing**: Generate patches for all vulnerabilities at once
- **Export Functionality**: Download patches as JSON for integration into your workflow
- **Status Tracking**: Track which patches have been applied

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install google-generativeai
```

### 2. Get API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a free API key
3. Add to `.env`:

```bash
GEMINI_API_KEY=your_api_key_here
```

### 3. Run Setup Script

```bash
setup_ai_patching.bat
```

Or manually:

```bash
python app.py
```

### 4. Use the System

1. Run a vulnerability scan
2. Go to "Detailed Findings"
3. Click "AI-Powered Patching"
4. Generate patches for vulnerabilities
5. Review and apply fixes

## 📋 How It Works

### Workflow

```
Vulnerability Detection
        ↓
CVE Database Search (finds similar vulnerabilities)
        ↓
AI Analysis (Gemini Pro)
        ↓
Patch Generation
        ↓
Review & Apply
```

### What Gets Generated

For each vulnerability, the system generates:

1. **Patched Code**: The fixed version of the vulnerable code
2. **Explanation**: Detailed description of the vulnerability and fix
3. **Testing Recommendations**: Specific test cases to verify the fix
4. **Additional Recommendations**: Best practices and related security measures
5. **Related CVEs**: Similar vulnerabilities from the database

## 🎯 Usage Examples

### Web Interface

#### Single Patch Generation

1. Navigate to scan results
2. Click "AI-Powered Patching"
3. Select a vulnerability
4. Click "Generate AI Patch"
5. Review the generated patch
6. Mark as applied or download

#### Batch Generation

1. Go to Patch Dashboard
2. Click "Generate All Patches"
3. Wait for processing (may take 1-2 minutes)
4. Review all generated patches

### API Usage

#### Generate Single Patch

```bash
curl -X POST http://localhost:5000/api/patch/{scan_id}/generate/0
```

#### Generate All Patches

```bash
curl -X POST http://localhost:5000/api/patch/{scan_id}/batch-generate
```

#### Mark as Applied

```bash
curl -X POST http://localhost:5000/api/patch/{scan_id}/apply/0 \
  -H "Content-Type: application/json" \
  -d '{"action": "mark_applied"}'
```

#### Export Patches

```bash
curl http://localhost:5000/api/patch/{scan_id}/export -o patches.json
```

## 📁 File Structure

```
AutoVulRepair/
├── ai_patch_generator.py          # Core patching engine
├── search_cve_faiss.py            # CVE database search
├── app.py                         # Flask routes (patching section added)
├── templates/
│   ├── patch_dashboard.html       # Patching dashboard UI
│   ├── patch_vulnerability.html   # Single patch UI
│   └── detailed_findings.html     # Updated with patching button
├── faiss_indexes/
│   └── cve-full/                  # CVE vector database (optional)
├── scans/
│   └── {scan_id}/
│       └── patches.json           # Generated patches
└── setup_ai_patching.bat          # Setup script
```

## 🔧 Configuration

### Environment Variables

```bash
# Required
GEMINI_API_KEY=your_gemini_api_key

# Optional
SCANS_DIR=./scans                  # Where to store scan data
```

### CVE Database (Optional)

The system works without the CVE database, but including it provides better context:

```bash
# Convert CVE database to FAISS
python cve_to_faiss.py --index-name cve-full --max-records 10000
```

This creates `faiss_indexes/cve-full/` which the system uses automatically.

## 📊 Example Output

### Patch JSON Structure

```json
{
  "0": {
    "patched_code": "char buffer[256];\nstrncpy(buffer, input, sizeof(buffer)-1);\nbuffer[sizeof(buffer)-1] = '\\0';",
    "explanation": "The original code had a buffer overflow vulnerability...",
    "testing_recommendations": "1. Test with inputs larger than 256 bytes\n2. Test with empty input...",
    "additional_recommendations": "Consider using std::string for automatic memory management...",
    "related_cves": [
      {
        "cve_id": "CVE-2023-12345",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Buffer overflow in similar context..."
      }
    ],
    "status": "generated",
    "file": "src/main.c",
    "line": 42,
    "original_code": "char buffer[256];\nstrcpy(buffer, input);"
  }
}
```

## 🎨 UI Components

### Patch Dashboard

- Overview of all vulnerabilities
- Patch status for each (not started, generated, applied)
- Batch generation button
- Export functionality

### Patch Vulnerability Page

- Vulnerability details
- Related CVEs from database
- Generated patch code with syntax highlighting
- Detailed explanation
- Testing recommendations
- Additional security recommendations
- Navigation between vulnerabilities

## 🔍 Troubleshooting

### Issue: "AI Patching not available"

**Cause**: Missing dependencies or API key

**Solution**:
```bash
pip install google-generativeai
# Add GEMINI_API_KEY to .env
```

### Issue: "FAISS index not available"

**Cause**: CVE database not set up

**Impact**: Patches work but without CVE context

**Solution** (optional):
```bash
python cve_to_faiss.py --index-name cve-full
```

### Issue: Slow patch generation

**Cause**: API rate limits or network latency

**Solution**:
- Use batch generation for multiple patches
- Wait a few seconds between requests
- Check your internet connection

### Issue: Poor quality patches

**Cause**: Insufficient code context

**Solution**:
- Ensure vulnerability has file and line information
- Check that source code is available in scan directory
- Provide more detailed vulnerability descriptions

## 💰 Cost Considerations

### Gemini API Pricing

- **Free Tier**: 60 requests per minute
- **Cost**: Free for most use cases
- **Token Usage**: ~1000-2000 tokens per patch

### Optimization Tips

1. Use batch generation (more efficient)
2. Cache patches for similar vulnerabilities
3. Monitor usage at [Google AI Studio](https://makersuite.google.com/)

## 🔐 Security Considerations

### Generated Patches

- **Always review patches before applying**
- Test patches in a safe environment first
- Verify patches don't introduce new vulnerabilities
- Use the testing recommendations provided

### API Key Security

- Never commit `.env` file to version control
- Use environment variables in production
- Rotate API keys regularly
- Monitor API usage for anomalies

## 📈 Performance

### Benchmarks

- Single patch generation: ~5-15 seconds
- Batch generation (10 patches): ~30-60 seconds
- CVE database search: <1 second

### Optimization

- Patches are cached in `patches.json`
- CVE database uses FAISS for fast similarity search
- Batch processing reduces API overhead

## 🛠️ Development

### Adding Custom Patch Templates

Edit `ai_patch_generator.py`:

```python
def _create_patch_prompt(self, vulnerability, analysis):
    # Customize the prompt here
    prompt = f"""Your custom prompt..."""
    return prompt
```

### Extending CVE Integration

Edit `search_cve_faiss.py`:

```python
def search(self, query, top_k=5):
    # Customize search logic
    pass
```

## 📚 API Reference

### Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/patch/<scan_id>` | GET | Patch dashboard |
| `/patch/<scan_id>/vulnerability/<vuln_index>` | GET | Single patch page |
| `/api/patch/<scan_id>/generate/<vuln_index>` | POST | Generate patch |
| `/api/patch/<scan_id>/apply/<vuln_index>` | POST | Mark as applied |
| `/api/patch/<scan_id>/batch-generate` | POST | Generate all |
| `/api/patch/<scan_id>/export` | GET | Export patches |

### Response Format

```json
{
  "success": true,
  "patch": {
    "patched_code": "...",
    "explanation": "...",
    "testing_recommendations": "...",
    "additional_recommendations": "...",
    "related_cves": [...],
    "status": "generated"
  }
}
```

## 🎓 Best Practices

1. **Review All Patches**: Never blindly apply AI-generated code
2. **Test Thoroughly**: Use the provided testing recommendations
3. **Understand the Fix**: Read the explanation to learn why it works
4. **Check Related CVEs**: Learn from similar vulnerabilities
5. **Iterate**: Regenerate patches if the first attempt isn't perfect
6. **Document**: Keep track of applied patches for audit purposes

## 🤝 Contributing

To improve the patching system:

1. Enhance prompt engineering in `ai_patch_generator.py`
2. Add more CVE data to improve context
3. Improve UI/UX in templates
4. Add support for more programming languages
5. Implement patch validation logic

## 📞 Support

For issues or questions:

1. Check this README
2. Review `PATCHING_SETUP.md`
3. Check application logs
4. Verify API key and dependencies
5. Test with a simple vulnerability first

## 🎉 Success Indicators

You'll know it's working when you see:

```
✓ AI Patch Generator initialized
```

In the application logs, and the "AI-Powered Patching" button appears in the UI.

## 📝 Changelog

### v1.0.0 - Initial Release

- ✅ Gemini AI integration
- ✅ CVE database search
- ✅ Batch patch generation
- ✅ Web UI for patch review
- ✅ Export functionality
- ✅ Status tracking

---

**Status**: ✅ Fully Integrated and Ready to Use

The AI-Powered Patching System is now part of AutoVulRepair. Set your API key and start generating intelligent patches for your vulnerabilities!
