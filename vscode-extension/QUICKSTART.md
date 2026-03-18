# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies

```bash
cd vscode-extension
npm install
```

This will install all required packages including TypeScript, VS Code API, testing frameworks, and dependencies.

### Step 2: Verify Setup

```bash
# Compile TypeScript
npm run compile

# Run linter
npm run lint
```

If both commands succeed, your setup is ready!

### Step 3: Test the Extension

1. Press `F5` in VS Code (or Run > Start Debugging)
2. A new VS Code window will open with "[Extension Development Host]" in the title
3. Open any C/C++ file
4. Right-click and select "Scan for Vulnerabilities"
5. You should see a test message (backend integration comes later)

### Step 4: Start Implementing

Open `.kiro/specs/tasks.md` and start with:

**Task 2: Implement core type definitions** ✅ (Already done!)
- `src/types.ts` is created with all interfaces

**Task 3: Implement Configuration Manager** (Next!)
- Create `src/configurationManager.ts`
- Follow the design in `.kiro/specs/design.md`

### Development Workflow

```bash
# Watch mode - auto-recompile on changes
npm run watch

# In another terminal, press F5 to debug
# Make changes, reload the extension window (Ctrl+R)
```

### Project Structure

```
vscode-extension/
├── src/
│   ├── extension.ts          ✅ Entry point (skeleton)
│   └── types.ts              ✅ Type definitions (complete)
├── test/
│   ├── unit/                 📝 Unit tests go here
│   ├── property/             📝 Property tests go here
│   └── integration/          📝 Integration tests go here
├── .kiro/specs/
│   ├── requirements.md       📖 What to build
│   ├── design.md            📖 How to build it
│   └── tasks.md             📋 Step-by-step tasks
└── package.json              ⚙️ Extension manifest
```

### Next Steps

1. **Read the specs**: Start with `requirements.md` to understand what you're building
2. **Follow the tasks**: Open `tasks.md` and work through Phase 1
3. **Write tests**: Add tests as you implement each component
4. **Test frequently**: Press F5 often to test in the Extension Development Host

### Backend Integration

The extension expects a Flask backend at `http://localhost:5000` with these endpoints:
- `POST /api/scan`
- `GET /api/scan/{sessionId}/status`
- `GET /api/scan/{sessionId}/results`
- `DELETE /api/scan/{sessionId}`
- `WebSocket /api/scan/{sessionId}/progress`

You'll implement these in your AutoVulRepair backend later.

### Need Help?

- Check `CONTRIBUTING.md` for detailed development guide
- Review `.kiro/specs/design.md` for component architecture
- Look at `package.json` for available npm scripts

## 🎯 Your First Task

Create `src/configurationManager.ts` following Task 3 in `tasks.md`. Good luck!
