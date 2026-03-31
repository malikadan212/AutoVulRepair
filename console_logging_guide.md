# 🔍 Browser Console Logging Guide

## Overview
Comprehensive browser console logging has been added to track user authentication and scan operations in real-time.

## How to View Console Logs

1. **Open Browser Developer Tools**:
   - **Chrome/Edge**: Press `F12` or `Ctrl+Shift+I`
   - **Firefox**: Press `F12` or `Ctrl+Shift+K`
   - **Safari**: Press `Cmd+Option+I`

2. **Navigate to Console Tab**
   - Click on the "Console" tab in developer tools
   - Clear any existing logs with the clear button (🗑️)

## Expected Console Logs

### 🏠 **Home Page (`http://localhost:5000/`)**
```javascript
🔧 AutoVulRepair User System Debug Logs Enabled
🏠 Home page loaded
🔐 GitHub OAuth login available
👤 User Authentication Status: NOT AUTHENTICATED
ℹ️  User needs to login via GitHub OAuth
✅ Home page login tracking initialized

// When clicking "Login with GitHub":
🚀 GitHub OAuth login initiated from home page
📍 Redirecting to: /login -> GitHub OAuth
⏳ User will be redirected back after GitHub authentication
💾 Upon successful login, user will be created/updated in database
🔐 GitHub Login initiated by user
📍 Redirecting to GitHub OAuth...
```

### 🔐 **After GitHub Login (Redirect Back)**
```javascript
🔧 AutoVulRepair User System Debug Logs Enabled
👤 User Authentication Status: AUTHENTICATED
📊 User Details: {
    id: "114865899",
    username: "your-github-username",
    email: "your-email@example.com",
    avatar_url: "https://avatars.githubusercontent.com/u/114865899?v=4",
    created_at: "2026-03-30 22:45:12",
    last_login: "2026-03-30 22:45:12"
}
✅ User successfully loaded from database
```

### 🛡️ **Unified Scan Page (`http://localhost:5000/scan`)**
```javascript
🔧 AutoVulRepair User System Debug Logs Enabled
🛡️  Security Scanner Debug Logs Enabled
📍 Current page: Unified Scan Interface
👤 Authenticated user detected for scanning
📊 User scan context: {
    username: "your-github-username",
    user_id: "114865899",
    can_save_scans: true,
    dashboard_access: true
}
🔧 Initializing scan interface...
🎛️  Setting up scan form event listeners...

🔍 Loading scanner capabilities...
✅ Scanner capabilities loaded successfully
🛠️  Available tools: ["codeql", "cppcheck"]
🔧 Tool details: {
    codeql: {available: true, languages: "C C++ Python JavaScript TypeScript Java C# Go", version: "Not available"},
    cppcheck: {available: true, languages: "C C++", version: "Unknown"}
}
📋 Supported languages: ["C", "C#", "C++", "Go", "Java", "JavaScript", "Python", "TypeScript"]
```

### 📚 **Loading User Repositories**
```javascript
// When clicking "Load My Repositories":
📚 Loading user repositories from GitHub...
🔗 Fetching repositories from GitHub API...
✅ Successfully loaded repositories: {
    count: 15,
    rate_limit_remaining: 4999,
    user: "your-github-username"
}
📋 Repository dropdown populated with user repositories
```

### 📝 **Repository Selection**
```javascript
// When selecting a repository from dropdown:
📚 Repository selected: {
    name: "your-username/your-repo",
    private: false,
    clone_url: "https://github.com/your-username/your-repo.git",
    language: "JavaScript",
    size: 1234
}
✅ Repository URL auto-filled from selection
```

### 🚀 **Starting a Scan**
```javascript
// When submitting the scan form:
📝 Repository scan form submitted
🔗 Repository URL: https://github.com/your-username/your-repo.git
✅ GitHub URL format valid
🛠️  Selected analysis tools: ["cppcheck"]
💾 Scan will be saved to database for user: your-github-username
🚀 Starting repository scan...
```

### 🔀 **Pull Request Scan**
```javascript
// When starting a PR scan:
🔀 Pull Request scan initiated
📊 PR Scan details: {
    repository: "owner/repo",
    pr_number: 123,
    tools: ["codeql"],
    user: "your-github-username"
}
🚀 Starting PR differential scan...
```

### 📦 **Batch Scan**
```javascript
// When starting a batch scan:
📦 Batch scan initiated
📊 Batch scan details: {
    repository_count: 3,
    repositories: ["https://github.com/user/repo1", "https://github.com/user/repo2", "https://github.com/user/repo3"],
    tools: ["cppcheck", "codeql"],
    user: "your-github-username"
}
🚀 Starting batch repository scan...
```

## 🖥️ **Backend Logs (Docker Logs)**

You can also view backend logs with:
```bash
docker logs autovulrepair-app-1 -f
```

### Expected Backend Logs:

#### **User Authentication**
```
[AUTH] GitHub OAuth callback initiated
[AUTH] GitHub OAuth token received successfully
[AUTH] Fetching user info from GitHub API
[AUTH] GitHub user info received: your-username (ID: 114865899)
[AUTH] Creating/updating user in database: your-username
[AUTH] User successfully saved to database: your-username (ID: 114865899)
[AUTH] User logged in successfully: your-username
```

#### **Scan Creation**
```
[SCAN] New scan initiated by user your-username (ID: 114865899)
[SCAN] Scan ID: abc123-def456-ghi789
[SCAN] Source: Repository URL
[SCAN] Repository: https://github.com/your-username/your-repo.git
[SCAN] Analysis tool: cppcheck
[SCAN] Creating scan record in database...
[SCAN] ✅ Scan record created successfully: abc123-def456-ghi789 for user your-username
[SCAN] 💾 Scan saved to database with user association
```

## 🎯 **What This Shows You**

1. **User Creation**: See exactly when users are created/updated in the database
2. **Authentication State**: Know if you're logged in and with what user details
3. **Scan Operations**: Track every step of the scanning process
4. **Database Operations**: Confirm scans are being saved with user association
5. **Error Tracking**: See any issues with authentication or scanning
6. **Performance Monitoring**: Track loading times and API calls

## 🔧 **Troubleshooting**

If you don't see logs:
1. Make sure Developer Tools Console is open
2. Refresh the page after opening console
3. Check that logs aren't filtered out (show all log levels)
4. Clear console and try the action again

The logs will help you verify that:
- ✅ Users are properly created in the database
- ✅ Scans are associated with the correct user
- ✅ Authentication state is maintained
- ✅ All operations are working as expected