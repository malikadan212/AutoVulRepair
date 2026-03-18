# AutoVulRepair Testing Checklist

## ✅ Phase 1: Core Functionality (PRIORITY)

### 1. Patch Generation & Application
- [ ] Backend generates patches for detected vulnerabilities
- [ ] "View Patch" command shows patch preview
- [ ] "Apply Patch" command applies fix to file
- [ ] Applied patch actually fixes the vulnerability
- [ ] Re-scan shows vulnerability is gone

**Test:**
```bash
# Check if patches are in backend response
curl http://localhost:5000/api/scan/<scan_id>/results | jq '.vulnerabilities[].patch'
```

### 2. Multiple File Types
- [ ] Scan `.c` file
- [ ] Scan `.cpp` file  
- [ ] Scan `.h` header file
- [ ] Scan `.hpp` header file
- [ ] Scan large file (>1000 lines)
- [ ] Scan file with no vulnerabilities

### 3. Error Handling
- [ ] Scan file with syntax errors (should complete, may find fewer issues)
- [ ] Scan empty file (should complete with no vulnerabilities)
- [ ] Stop Docker backend → scan fails gracefully with clear error
- [ ] Cancel scan mid-execution
- [ ] Scan non-C/C++ file (should show error)

### 4. CodeQL Analysis
- [ ] Change analysis tool to CodeQL in settings
- [ ] Scan with CodeQL
- [ ] Compare results with Cppcheck
- [ ] Verify CodeQL Docker image exists

**Test:**
```bash
docker images | grep codeql
```

---

## ✅ Phase 2: Performance & Reliability

### 5. Concurrent Scans
- [ ] Open 3 different C files
- [ ] Scan all 3 simultaneously
- [ ] All complete successfully
- [ ] Check backend logs for queue management

### 6. Large Codebases
- [ ] Scan folder with 10+ C/C++ files
- [ ] Monitor scan time per file
- [ ] Check memory usage (should stay under 2GB)
- [ ] Verify all results appear in sidebar

### 7. Background Scanning
- [ ] Enable "Scan on Save" in settings
- [ ] Edit and save file
- [ ] Verify scan triggers automatically
- [ ] Save multiple times quickly → only one scan runs

---

## ✅ Phase 3: User Experience

### 8. UI/UX
- [ ] Progress indicator shows during scan
- [ ] Error messages are clear and actionable
- [ ] Sidebar updates immediately after scan
- [ ] Click vulnerability in sidebar → jumps to code
- [ ] Hover over squiggly line → shows details

### 9. Configuration
- [ ] Change backend URL in settings → extension uses new URL
- [ ] Change severity filter → sidebar updates
- [ ] Add exclude pattern → files are skipped
- [ ] Test connection command works

---

## Critical Issues to Fix Before Deployment

### Backend
- [ ] Patch generation works for all vulnerability types
- [ ] CodeQL integration is functional
- [ ] Error responses are consistent (JSON format)
- [ ] Rate limiting for API endpoints
- [ ] Health check endpoint returns proper status

### Extension
- [ ] All commands work without errors
- [ ] No console errors in normal operation
- [ ] Extension doesn't slow down VS Code
- [ ] Works on Windows, Mac, Linux
- [ ] Memory leaks checked (long-running sessions)

### Documentation
- [ ] README with installation instructions
- [ ] Configuration guide
- [ ] Troubleshooting section
- [ ] API documentation for backend

---

## Test Files to Create

Create these test files in a `test-samples/` directory:

**1. buffer_overflow.c** - Buffer overflow vulnerabilities
**2. memory_leak.cpp** - Memory management issues
**3. null_pointer.c** - Null pointer dereferences
**4. race_condition.cpp** - Threading issues
**5. clean_code.c** - No vulnerabilities (control)
**6. syntax_error.c** - Invalid C code
**7. large_file.c** - 2000+ lines of code

---

## Performance Benchmarks

Target metrics before deployment:

- **Scan Time:** <10 seconds for files <500 lines
- **Memory Usage:** <500MB per scan
- **Concurrent Scans:** Support 5+ simultaneous scans
- **Extension Load Time:** <2 seconds
- **API Response Time:** <100ms for status checks

---

## Next Steps

1. **Test patch generation** (most important missing feature)
2. **Create test sample files** (for consistent testing)
3. **Run full test suite** (all checkboxes above)
4. **Fix critical issues** found during testing
5. **Performance optimization** if needed
6. **Documentation** for users
7. **Deploy to cloud** when all tests pass
