# Quick Start Guide - AutoVulRepair VS Code Extension

## 🎯 Current Status

✅ **MVP Complete** - All core features implemented and tested (141 tests passing)  
⚠️ **Backend Integration** - Some API endpoints need to be added for full functionality  
🚀 **Ready for Testing** - Can test with Docker backend right now

## 🚀 5-Minute Setup

### 1. Start Backend (Terminal 1)

```bash
# From main project directory
docker-compose up
```

Wait for: `app_1 | Running on http://0.0.0.0:5000`

### 2. Launch Extension (Terminal 2)

```bash
cd vscode-extension
code .
# Press F5 in VS Code
```

### 3. Test Connection

In Extension Development Host:
- Open Command Palette (Ctrl+Shift+P)
- Run: `AutoVulRepair: Test Backend Connection`
- Should see success message

## 📋 What Works Now

✅ Extension loads and activates  
✅ Backend connection test  
✅ Configuration settings  
✅ Sidebar view  
✅ Command palette integration  
✅ Can view existing scan results (via web UI)

## ⚠️ What Needs Backend Updates

These features need API endpoints to be added (see [BACKEND_API_REQUIREMENTS.md](BACKEND_API_REQUIREMENTS.md)):

🔴 **High Priority:**
- Initiate scans from extension (`POST /api/scan`)
- Get formatted results (`GET /api/scan/<id>/results`)

🟡 **Medium Priority:**
- Cancel scans (`DELETE /api/scan/<id>`)

🟢 **Low Priority:**
- Real-time progress (`WebSocket /ws/scan/<id>`)

## 📚 Documentation

- **[MVP_STATUS.md](MVP_STATUS.md)** - Complete feature list and test results
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Detailed testing instructions
- **[BACKEND_API_REQUIREMENTS.md](BACKEND_API_REQUIREMENTS.md)** - API specs for backend team

## 🔧 Quick Commands

```bash
# Run tests
npm run test:unit

# Compile extension
npm run compile

# Fix linting
npm run lint -- --fix

# Package for distribution
npm run package
```

## 🐛 Troubleshooting

**Extension won't load:**
```bash
npm install
npm run compile
```

**Backend connection fails:**
```bash
docker ps  # Check services running
curl http://localhost:5000  # Test backend
```

**Tests failing:**
```bash
npm run test:unit  # Should show 141 passing
```

## 📞 Next Steps

1. **Test current functionality** - Follow [TESTING_GUIDE.md](TESTING_GUIDE.md)
2. **Add backend endpoints** - See [BACKEND_API_REQUIREMENTS.md](BACKEND_API_REQUIREMENTS.md)
3. **Full integration test** - Scan files end-to-end
4. **Production readiness** - Security, docs, performance (Tasks 20-31)
5. **Publish to marketplace** - Package and release

## 🎉 Success Criteria

You'll know it's working when:
- ✅ Extension loads without errors
- ✅ Backend connection succeeds
- ✅ Commands appear in palette
- ✅ Sidebar displays
- ✅ Settings are configurable
- ✅ (After API updates) Can scan files
- ✅ (After API updates) Diagnostics appear
- ✅ (After API updates) Can apply patches

**Estimated time to full functionality:** 2-4 hours (adding backend endpoints)
