# AutoVulRepair Navigation Map

This document maps all routes and navigation paths between pages in the AutoVulRepair application.

## 🏠 Entry Points

### Home Page (`/`)
**Template:** `home.html`
**Navigation From Here:**
- → `/login` - Login with GitHub (if OAuth enabled)
- → `/no-login` - Continue without GitHub login

### No-Login Scan (`/no-login`)
**Template:** `no_login_scan.html`
**Navigation From Here:**
- → `/scan-public` (POST) - Submit scan (GitHub URL, ZIP, or code snippet)
- → Redirects to `/detailed-findings/<scan_id>` after scan submission

---

## 🔐 Authentication Flow

### Login (`/login`)
**Function:** Redirects to GitHub OAuth
**Navigation From Here:**
- → `/auth` - OAuth callback
- → `/dashboard` - After successful authentication

### OAuth Callback (`/auth`)
**Function:** Handles GitHub OAuth response
**Navigation From Here:**
- → `/dashboard` - After successful authentication
- → `/login` - If authentication fails

### Logout (`/logout`)
**Function:** Clears session
**Navigation From Here:**
- → `/` - Redirects to home page

---

## 📊 Dashboard & Main Navigation

### Dashboard (`/dashboard`) 🔒
**Template:** `dashboard.html` / `enhanced_dashboard.html`
**Requires:** Login
**Navigation From Here:**
- → `/scan` - New authenticated scan
- → `/fuzzing-dashboard` - Fuzzing operations
- → `/monitoring` - System monitoring
- → `/detailed-findings/<scan_id>` - View specific scan results

---

## 🔍 Scanning Workflow

### Authenticated Scan (`/scan`) 🔒
**Template:** `scan.html`
**Requires:** Login
**Navigation From Here:**
- → `/scan/<scan_id>/status` - View scan status
- → `/dashboard` - Back to dashboard

### Public Scan Form (`/scan-public`)
**Template:** `no_login_scan.html`
**Navigation From Here:**
- → `/detailed-findings/<scan_id>` - After form submission (POST)

### Scan Status (`/scan/<scan_id>/status`) 🔒
**Template:** `scan_status.html`
**Requires:** Login
**Navigation From Here:**
- → `/results/<scan_id>` - When scan completes
- → `/dashboard` - Back to dashboard

### Scan Progress (`/scan-progress/<scan_id>`)
**Template:** `scan_progress.html`
**Public Access**
**Navigation From Here:**
- → `/detailed-findings/<scan_id>` - When scan completes
- → `/no-login` - Start new scan

---

## 📋 Results & Analysis

### Detailed Findings (`/detailed-findings/<scan_id>`)
**Template:** `detailed_findings.html`
**Public Access**
**Navigation From Here:**
- → `/dashboard` - If authenticated
- → `/no-login` - If not authenticated
- → `/scan-progress/<scan_id>` - View progress (if still running)
- → `/patch-review/<scan_id>` - Generate patches
- → `/fuzz-plan/<scan_id>` - Generate fuzz plan
- → `/fuzz-execution/<scan_id>` - View fuzzing details
- → `/repair/<scan_id>` - AI Patching

---

## 🔧 Patch Management

### Patch Review (`/patch-review/<scan_id>`)
**Template:** `patch_review.html`
**Public Access**
**Navigation From Here:**
- → `/detailed-findings/<scan_id>` - Back to findings
- → Download individual patches
- → Generate patches via API calls

### Patch Dashboard (`/patch/<scan_id>`)
**Function:** **REDIRECTS TO** `/repair/<scan_id>`
**Note:** This is a temporary redirect route

---

## 🤖 AI Repair System

### Repair Dashboard (`/repair/<scan_id>`)
**Template:** `repair_dashboard_enhanced.html`
**Public Access**
**Navigation From Here:**
- → `/detailed-findings/<scan_id>` - Back to findings
- → Download repair patches
- → View patch details
- → Apply patches

**API Endpoints:**
- `/api/repair/start/<scan_id>` - Start AI repair
- `/api/repair/status/<scan_id>` - Get repair status
- `/api/repair/patch/<scan_id>/<crash_id>` - Get patch details
- `/api/repair/download/<scan_id>/<crash_id>` - Download patch
- `/api/repair/apply/<scan_id>/<crash_id>` - Apply patch

---

## 🎯 Fuzzing Pipeline

### Fuzz Plan (`/fuzz-plan/<scan_id>`)
**Template:** `fuzz_plan.html`
**Public Access**
**Navigation From Here:**
- → `/detailed-findings/<scan_id>` - Back to findings
- → `/harness-generation/<scan_id>` - Generate harnesses (after plan creation)

### Harness Generation (`/harness-generation/<scan_id>`)
**Template:** `harness_generation.html`
**Public Access**
**Navigation From Here:**
- → `/fuzz-plan/<scan_id>` - Back to fuzz plan
- → `/build-orchestration/<scan_id>` - Build targets (via JavaScript)

### Build Orchestration (`/build-orchestration/<scan_id>`)
**Template:** `build_orchestration.html`
**Public Access**
**Navigation From Here:**
- → `/harness-generation/<scan_id>` - Back to harnesses
- → `/fuzz-execution/<scan_id>` - Execute fuzzing

### Fuzz Execution (`/fuzz-execution/<scan_id>`)
**Template:** `fuzz_execution.html`
**Public Access**
**Navigation From Here:**
- → Download crash inputs
- → Analyze crashes

---

## 📊 Monitoring & Dashboards

### Fuzzing Dashboard (`/fuzzing-dashboard`)
**Template:** `fuzzing_dashboard.html`
**Public Access**
**Navigation From Here:**
- → `/detailed-findings/<scan_id>` - Back to results (if scan_id provided)
- → `/no-login` - Start new scan (if no scan_id)

### Monitoring Dashboard (`/monitoring`)
**Template:** `monitoring_dashboard.html`
**Public Access**
**Navigation From Here:**
- → Various system monitoring views

### Triage Dashboard (`/triage/<scan_id>`)
**Template:** `triage_dashboard.html`
**Public Access**
**Navigation From Here:**
- → Crash analysis tools
- → Reproduction kits

---

## 🔧 Utility & Debug Routes

### Debug Session (`/debug/session`)
**Function:** Shows session state (JSON)
**Public Access**

### Debug Test (`/debug-test`)
**Function:** Simple debug endpoint
**Public Access**

### Tool Status (`/api/tool-status`)
**Function:** Check analysis tool availability (JSON)
**Public Access**

---

## 📁 File Downloads

### Download Patch (`/download-patch/<scan_id>/<patch_id>`)
**Function:** Download patch file
**Public Access**

### Download Artifact (`/artifacts/<scan_id>/<filename>`)
**Function:** Download analysis artifacts (XML/SARIF)
**Public Access**

---

## 🚨 Potential Navigation Issues

### 1. Redirect Confusion ✅ **FIXED**
- **REMOVED**: `/patch/<scan_id>` → `/repair/<scan_id>` redirect route
- **REMOVED**: `/results/<scan_id>` and `/public-results/<scan_id>` redundant routes
- **SOLUTION**: Use direct routes only: `/repair/<scan_id>` and `/detailed-findings/<scan_id>`

### 2. Authentication Inconsistency
- Some routes require login (`🔒`), others don't
- Navigation might not respect authentication state

### 3. Template Issues Found
```html
<!-- Commented out in detailed_findings.html -->
<!-- <a href="{{ url_for('repair_dashboard', scan_id=scan_id) }}" class="btn btn-success"> -->
```

### 4. JavaScript Navigation
- Some navigation uses `window.location.href` in JavaScript
- May not properly handle URL generation

### 5. Duplicate Route Patterns ✅ **FIXED**
- **REMOVED**: `/results/<scan_id>` vs `/public-results/<scan_id>` duplication
- **KEPT**: `/api/scan-status/<scan_id>` vs `/api/scan_status/<scan_id>` (legacy) - TODO: Remove legacy

---

## 🔄 Common Navigation Flows

### Public User Flow ✅ **UPDATED**
1. `/` → `/no-login` → `/scan-public` (POST) → `/detailed-findings/<scan_id>`
2. `/detailed-findings/<scan_id>` → `/patch-review/<scan_id>` → Generate patches
3. `/detailed-findings/<scan_id>` → `/fuzz-plan/<scan_id>` → `/harness-generation/<scan_id>` → `/build-orchestration/<scan_id>` → `/fuzz-execution/<scan_id>`

### Authenticated User Flow ✅ **UPDATED**
1. `/` → `/login` → `/auth` → `/dashboard`
2. `/dashboard` → `/scan` → `/scan/<scan_id>/status` → `/detailed-findings/<scan_id>`
3. `/dashboard` → `/fuzzing-dashboard` → Various fuzzing operations

### AI Repair Flow
1. `/detailed-findings/<scan_id>` → `/repair/<scan_id>`
2. `/repair/<scan_id>` → API calls for repair operations
3. Download/apply patches from repair dashboard

---

## 🛠️ Recommendations for Fixing Navigation Issues

1. **Standardize Authentication Checks** - Ensure templates properly check `current_user.is_authenticated`

2. **Fix Commented Routes** - Uncomment and fix the repair dashboard link in `detailed_findings.html`

3. **Remove Legacy Routes** ✅ **COMPLETED** - Removed duplicate `/results/` and `/public-results/` routes

4. **Update JavaScript Navigation** - Replace hardcoded URLs with proper Flask URL generation

5. **Add Breadcrumbs** - Implement consistent breadcrumb navigation across all pages

6. **Test All Navigation Paths** - Verify each link works correctly in both authenticated and public modes

## ✅ **COMPLETED CLEANUP**

**Removed Routes:**
- `/results/<scan_id>` - Redundant with `/detailed-findings/<scan_id>`
- `/public-results/<scan_id>` - Redundant with `/detailed-findings/<scan_id>`

**Removed Templates:**
- `templates/results.html`
- `templates/public_results.html` 
- `templates/final_results.html`

**Updated References:**
- `templates/repro_kit.html` - Changed `url_for('results')` to `url_for('detailed_findings')`
- `test_valid_scan_routes.py` - Updated to test only `/detailed-findings/`

**Result:** Simplified navigation with single results page (`/detailed-findings/<scan_id>`) for all users.