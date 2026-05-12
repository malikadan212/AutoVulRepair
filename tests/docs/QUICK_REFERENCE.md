# AI Patching - Quick Reference Card

## 🚀 Setup (One-Time)

```bash
# Install
pip install google-generativeai

# Configure
echo GEMINI_API_KEY=your_key_here >> .env

# Start
python app.py
```

## 🎯 Usage

### Web UI
1. Run scan → Find vulnerabilities
2. Click "AI-Powered Patching"
3. Select vulnerability → "Generate AI Patch"
4. Review → Mark as applied

### API
```bash
# Generate patch
POST /api/patch/{scan_id}/generate/{vuln_index}

# Batch generate
POST /api/patch/{scan_id}/batch-generate

# Export
GET /api/patch/{scan_id}/export
```

## 📁 Key Files

| File | Purpose |
|------|---------|
| `app.py` | Patching routes |
| `ai_patch_generator.py` | Core logic |
| `templates/patch_*.html` | UI |
| `scans/{id}/patches.json` | Saved patches |

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| "AI Patching not available" | Install: `pip install google-generativeai` |
| "API key not set" | Add `GEMINI_API_KEY` to `.env` |
| "FAISS not available" | Optional - patches work without it |
| Slow generation | Use batch mode or wait between requests |

## 📊 What You Get

Each patch includes:
- ✅ Fixed code
- ✅ Explanation
- ✅ Testing recommendations
- ✅ Security tips
- ✅ Related CVEs

## 💰 Cost

- **Free tier**: 60 requests/minute
- **Per patch**: ~1000-2000 tokens
- **Typical usage**: Free for most projects

## 🔐 Security

- ⚠️ Always review patches before applying
- ⚠️ Test in safe environment
- ⚠️ Never commit `.env` file
- ✅ Use testing recommendations

## 📚 Documentation

- **Setup**: `PATCHING_SETUP.md`
- **Full docs**: `AI_PATCHING_README.md`
- **Changes**: `INTEGRATION_SUMMARY.md`

## ✅ Verification

```bash
# Check if working
python app.py
# Look for: "✓ AI Patch Generator initialized"
```

## 🎓 Best Practices

1. Review all patches
2. Test thoroughly
3. Use batch mode for multiple patches
4. Read explanations to learn
5. Check related CVEs

## 📞 Get Help

1. Check logs
2. Read `PATCHING_SETUP.md`
3. Verify API key is set
4. Test with simple vulnerability first

---

**Quick Start**: `setup_ai_patching.bat` → Add API key → `python app.py` → Done!
