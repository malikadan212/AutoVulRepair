# 🔧 AI-Powered Patching System - Integration Guide

## Overview

This adds an intelligent patching system to your AutoVulRepair project that:
1. Analyzes vulnerabilities with CVE context from FAISS
2. Generates secure patches using Gemini AI
3. Provides explanations and testing recommendations
4. Tracks patch status across your workflow

## Workflow

```
Fuzzing → Vulnerabilities Found → AI Patch Generation → Apply Patches
```

## Files Created

1. **`ai_patch_generator.py`** - Core patching engine
2. **`patch_routes.py`** - Flask routes for patching
3. **`templates/patch_dashboard.html`** - Dashboard showing all vulnerabilities
4. **`templates/patch_vulnerability.html`** - Detailed patching page
5. **`PATCHING_INTEGRATION_GUIDE.md`** - This guide

## Integration Steps

### Step 1: Add Routes to app.py

Add this at the top of `app.py` (after other imports):

```python
# Import patching components
from ai_patch_generator import AIPatchGenerator

# Initialize patch generator (after app initialization)
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_API_KEY:
    try:
        patch_generator = AIPatchGenerator(
            gemini_api_key=GEMINI_API_KEY,
            index_name='cve-full'
        )
        logger.info("✓ AI Patch Generator initialized")
    except Exception as e:
        patch_generator = None
        logger.warning(f"⚠ Patch Generator initialization failed: {e}")
else:
    patch_generator = None
    logger.warning("⚠ GEMINI_API_KEY not set - Patching features disabled")
```

Then copy all the routes from `patch_routes.py` into your `app.py`.

### Step 2: Update .env File

Add your Gemini API key:

```bash
GEMINI_API_KEY=your_gemini_api_key_here
```

Get your key from: https://makersuite.google.com/app/apikey

### Step 3: Add Navigation Links

Update your templates to add links to the patching system.

In `templates/detailed_findings.html`, add:

```html
<a href="{{ url_for('patch_dashboard', scan_id=scan_id) }}" class="btn btn-success">
    <i class="fas fa-wrench"></i> Generate Patches
</a>
```

In `templates/final_results.html`, add:

```html
<div class="card">
    <div class="card-header">
        <h5>🔧 AI-Powered Patching</h5>
    </div>
    <div class="card-body">
        <p>Generate intelligent patches for discovered vulnerabilities</p>
        <a href="{{ url_for('patch_dashboard', scan_id=scan_id) }}" class="btn btn-primary">
            Start Patching
        </a>
    </div>
</div>
```

### Step 4: Install Dependencies

```bash
pip install google-generativeai
```

### Step 5: Test the Integration

1. Run a scan to find vulnerabilities
2. Navigate to the patching dashboard
3. Generate patches for vulnerabilities
4. Review and apply patches

## Usage

### Access Patching Dashboard

After a scan completes:

```
http://localhost:5000/patch/YOUR_SCAN_ID
```

### Generate Single Patch

```
http://localhost:5000/patch/YOUR_SCAN_ID/vulnerability/0
```

### API Endpoints

```bash
# Generate patch for specific vulnerability
POST /api/patch/{scan_id}/generate/{vuln_index}

# Apply patch
POST /api/patch/{scan_id}/apply/{vuln_index}

# Batch generate all patches
POST /api/patch/{scan_id}/batch-generate

# Export patches
GET /api/patch/{scan_id}/export
```

## Features

### 1. Dashboard View
- Overview of all vulnerabilities
- Patch status tracking
- Batch operations
- Export functionality

### 2. Detailed Patching
- CVE context from vector database
- AI-generated secure patches
- Detailed explanations
- Testing recommendations
- Additional security advice

### 3. Patch Management
- Mark patches as applied
- Download patches
- Regenerate if needed
- Navigate between vulnerabilities

## Example Workflow

### 1. Complete a Scan

```bash
# Your existing workflow
1. Upload code
2. Run static analysis
3. Generate fuzz plan
4. Execute fuzzing
5. Triage crashes
```

### 2. Access Patching

```
Navigate to: /patch/{scan_id}
```

### 3. Generate Patches

Click "Generate All Patches" or generate individually.

### 4. Review Patches

Each patch includes:
- Corrected code
- Explanation of the fix
- Testing recommendations
- Related CVEs
- Additional security advice

### 5. Apply Patches

- Review the patch
- Download if needed
- Mark as applied
- Move to next vulnerability

## Customization

### Modify Patch Prompt

Edit `ai_patch_generator.py`, function `_create_patch_prompt()`:

```python
def _create_patch_prompt(self, vulnerability, analysis):
    prompt = f"""You are a security expert...
    
    [Customize your prompt here]
    
    Generate the patch now:"""
    return prompt
```

### Add Custom Analysis

In `ai_patch_generator.py`, extend `analyze_vulnerability()`:

```python
def analyze_vulnerability(self, vulnerability):
    # Your custom analysis
    analysis = super().analyze_vulnerability(vulnerability)
    
    # Add custom context
    analysis['custom_data'] = your_analysis()
    
    return analysis
```

### Customize UI

Edit `templates/patch_vulnerability.html` to:
- Change colors/styling
- Add more sections
- Modify layout
- Add custom actions

## Advanced Features

### 1. Automatic Patch Application

Add to `patch_routes.py`:

```python
@app.route('/api/patch/<scan_id>/auto-apply/<int:vuln_index>', methods=['POST'])
def auto_apply_patch(scan_id, vuln_index):
    """Actually apply patch to source file"""
    # Load patch
    # Read source file
    # Apply patch
    # Save file
    # Return result
```

### 2. Patch Validation

```python
def validate_patch(original_code, patched_code):
    """Validate that patch compiles and is secure"""
    # Compile check
    # Security scan
    # Return validation result
```

### 3. Patch History

Track all patch versions:

```python
patches_history = {
    'vuln_0': [
        {'version': 1, 'patch': '...', 'timestamp': '...'},
        {'version': 2, 'patch': '...', 'timestamp': '...'}
    ]
}
```

### 4. Collaborative Review

Add review workflow:

```python
@app.route('/api/patch/<scan_id>/review/<int:vuln_index>', methods=['POST'])
def review_patch(scan_id, vuln_index):
    """Submit patch review"""
    data = request.json
    # approved, rejected, needs_changes
    # Add comments
    # Notify team
```

## Troubleshooting

### "AI Patching not available"

Check:
1. GEMINI_API_KEY is set in .env
2. google-generativeai is installed
3. patch_generator initialized successfully

### "FAISS index not available"

The system will work without FAISS, but patches won't have CVE context.

To fix:
```bash
python cve_to_faiss.py --index-name cve-full
```

### Slow Patch Generation

- Reduce `top_k` in CVE search (default: 5)
- Use shorter prompts
- Cache common vulnerabilities

### Rate Limits

Gemini free tier: 60 requests/minute

If hitting limits:
- Add delays between batch operations
- Upgrade to paid tier
- Cache generated patches

## Best Practices

### 1. Review All Patches

Never apply patches blindly:
- Review the code
- Understand the fix
- Test thoroughly
- Check for side effects

### 2. Test Patches

Always test patches:
- Unit tests
- Integration tests
- Security tests
- Performance tests

### 3. Version Control

Commit patches separately:
```bash
git add patched_file.c
git commit -m "fix: Apply AI-generated patch for CVE-XXXX"
```

### 4. Document Changes

Add comments explaining:
- What was vulnerable
- How it was fixed
- Related CVEs
- Testing performed

## Security Considerations

### 1. Validate AI Output

AI can make mistakes:
- Always review patches
- Test thoroughly
- Get human approval for critical code

### 2. Protect API Keys

Never commit API keys:
```bash
# Add to .gitignore
.env
*.key
```

### 3. Audit Trail

Keep records of:
- What was patched
- When it was patched
- Who approved it
- Test results

## Performance

### Patch Generation Time

- Single patch: 10-30 seconds
- Batch (10 vulns): 2-5 minutes
- Depends on: code complexity, CVE search, AI response time

### Optimization

1. **Parallel Generation**
```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=3) as executor:
    patches = list(executor.map(generate_patch, vulnerabilities))
```

2. **Caching**
```python
from functools import lru_cache

@lru_cache(maxsize=100)
def cached_patch(vuln_hash):
    return generate_patch(vulnerability)
```

3. **Batch Processing**
Generate patches overnight for large scans.

## Next Steps

1. ✅ Integrate routes into app.py
2. ✅ Add GEMINI_API_KEY to .env
3. ✅ Test with a scan
4. ✅ Customize prompts if needed
5. ✅ Add to your workflow

## Support

For issues:
1. Check logs for errors
2. Verify API key is valid
3. Ensure FAISS index exists
4. Test with simple vulnerability first

## Resources

- Gemini API: https://ai.google.dev/
- FAISS: https://github.com/facebookresearch/faiss
- AutoVulRepair Docs: Your existing documentation

---

**You now have a complete AI-powered patching system!**

The workflow is:
1. Scan code → Find vulnerabilities
2. Generate patches → AI creates fixes
3. Review patches → Human approval
4. Apply patches → Fix the code
5. Test → Verify the fix

This completes your AutoVulRepair pipeline! 🎉
