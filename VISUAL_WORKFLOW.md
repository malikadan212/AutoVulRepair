# 🎨 AI Patching System - Visual Workflow

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AutoVulRepair                             │
│                                                              │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │   Scanner    │─────▶│ Vulnerabilities│                   │
│  │  (Cppcheck/  │      │   Database     │                   │
│  │   CodeQL)    │      └────────┬───────┘                   │
│  └──────────────┘               │                           │
│                                  │                           │
│                                  ▼                           │
│                    ┌─────────────────────────┐              │
│                    │  AI Patching System     │              │
│                    │                         │              │
│                    │  ┌──────────────────┐  │              │
│                    │  │ Patch Generator  │  │              │
│                    │  │   (Gemini AI)    │  │              │
│                    │  └────────┬─────────┘  │              │
│                    │           │             │              │
│                    │  ┌────────▼─────────┐  │              │
│                    │  │  CVE Database    │  │              │
│                    │  │  (FAISS Search)  │  │              │
│                    │  └──────────────────┘  │              │
│                    └─────────────────────────┘              │
│                                  │                           │
│                                  ▼                           │
│                    ┌─────────────────────────┐              │
│                    │   Generated Patches     │              │
│                    │   (JSON + Web UI)       │              │
│                    └─────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

## 🔄 User Workflow

```
START
  │
  ▼
┌─────────────────┐
│  Run Scan       │  ← Upload code or provide GitHub URL
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ View Results    │  ← See vulnerabilities found
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Click "AI       │  ← Navigate to patching system
│ Patching"       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Patch Dashboard │  ← See all vulnerabilities
└────────┬────────┘
         │
         ├─────────────────┬─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Single Patch │  │ Batch Patches│  │ Export JSON  │
└──────┬───────┘  └──────┬───────┘  └──────────────┘
       │                 │
       ▼                 ▼
┌─────────────────────────────┐
│  Review Generated Patches   │
│  - Code                     │
│  - Explanation              │
│  - Testing Tips             │
│  - Related CVEs             │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────┐
│ Apply Patches   │  ← Fix your code
└─────────────────┘
           │
           ▼
         END
```

## 🎯 Patch Generation Flow

```
Vulnerability Detected
         │
         ▼
┌─────────────────────────────┐
│ Extract Context             │
│ - File path                 │
│ - Line number               │
│ - Code snippet              │
│ - Vulnerability type        │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Search CVE Database         │
│ - Find similar vulns        │
│ - Get fix patterns          │
│ - Extract best practices    │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Generate AI Prompt          │
│ - Vulnerability details     │
│ - CVE context               │
│ - Code context              │
│ - Fix requirements          │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Call Gemini AI              │
│ - Send prompt               │
│ - Wait for response         │
│ - Parse result              │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Format Patch                │
│ - Extract code              │
│ - Parse explanation         │
│ - Format recommendations    │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Save & Display              │
│ - Save to JSON              │
│ - Show in UI                │
│ - Enable export             │
└─────────────────────────────┘
```

## 🖥️ UI Navigation Map

```
Home Page
    │
    ├─▶ Quick Scan
    │       │
    │       ▼
    │   Upload/URL Input
    │       │
    │       ▼
    │   Scan Progress
    │       │
    │       ▼
    │   Detailed Findings ◀─────────┐
    │       │                       │
    │       ├─▶ AI Patching ────────┤
    │       │       │               │
    │       │       ▼               │
    │       │   Patch Dashboard     │
    │       │       │               │
    │       │       ├─▶ Single Patch│
    │       │       │       │       │
    │       │       │       ├─▶ Generate
    │       │       │       ├─▶ Review
    │       │       │       ├─▶ Apply
    │       │       │       └─▶ Download
    │       │       │               │
    │       │       ├─▶ Batch Generate
    │       │       └─▶ Export All │
    │       │                       │
    │       ├─▶ Fuzz Plan ──────────┤
    │       └─▶ Final Results ──────┘
    │
    └─▶ Login (Optional)
```

## 📦 Data Flow Diagram

```
┌──────────────┐
│  User Input  │
│ (Scan Code)  │
└──────┬───────┘
       │
       ▼
┌──────────────────────┐
│  Static Analysis     │
│  - Cppcheck/CodeQL   │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Vulnerabilities     │
│  (JSON in Database)  │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  AI Patch Generator  │
│  - Extract context   │
│  - Search CVE DB     │
│  - Call Gemini       │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Generated Patches   │
│  (JSON on Disk)      │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Web UI Display      │
│  - Dashboard         │
│  - Single view       │
│  - Export            │
└──────────────────────┘
```

## 🔐 Security Flow

```
┌─────────────────┐
│  API Key        │
│  (in .env)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Environment    │
│  Variable       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  App Init       │
│  (Secure Load)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Gemini Client  │
│  (Encrypted)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  API Call       │
│  (HTTPS)        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Response       │
│  (Validated)    │
└─────────────────┘
```

## 📊 Component Interaction

```
┌─────────────────────────────────────────────────────────┐
│                      Flask App                          │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐                 │
│  │   Routes     │◀──▶│   Templates  │                 │
│  │              │    │              │                 │
│  │ /patch/*     │    │ patch_*.html │                 │
│  └──────┬───────┘    └──────────────┘                 │
│         │                                              │
│         ▼                                              │
│  ┌──────────────────────────────────┐                 │
│  │   AIPatchGenerator               │                 │
│  │                                  │                 │
│  │  ┌────────────┐  ┌────────────┐ │                 │
│  │  │ CVE Search │  │ Gemini AI  │ │                 │
│  │  └────────────┘  └────────────┘ │                 │
│  └──────────────────────────────────┘                 │
│         │                                              │
│         ▼                                              │
│  ┌──────────────┐                                     │
│  │  File System │                                     │
│  │  (patches.   │                                     │
│  │   json)      │                                     │
│  └──────────────┘                                     │
└─────────────────────────────────────────────────────────┘
```

## 🎨 UI Components

```
┌─────────────────────────────────────────────────────────┐
│                  Patch Dashboard                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Stats Cards                                     │  │
│  │  [Total: 10] [Patched: 3] [Pending: 7]         │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Actions                                         │  │
│  │  [Generate All] [Export] [Back]                 │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Vulnerabilities Table                           │  │
│  │  ┌────┬──────────┬─────────────┬────────────┐  │  │
│  │  │ #  │ Severity │ Description │ Actions    │  │  │
│  │  ├────┼──────────┼─────────────┼────────────┤  │  │
│  │  │ 1  │ HIGH     │ Buffer...   │ [Patch]    │  │  │
│  │  │ 2  │ MEDIUM   │ SQL Inj...  │ [Patch]    │  │  │
│  │  └────┴──────────┴─────────────┴────────────┘  │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│              Single Patch View                          │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Vulnerability Details                           │  │
│  │  Type: Buffer Overflow | Severity: HIGH         │  │
│  │  File: main.c:42                                │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  [Generate AI Patch]                            │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Related CVEs                                    │  │
│  │  • CVE-2023-12345 (HIGH)                        │  │
│  │  • CVE-2023-67890 (MEDIUM)                      │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Patched Code                                    │  │
│  │  ```c                                           │  │
│  │  char buffer[256];                              │  │
│  │  strncpy(buffer, input, sizeof(buffer)-1);     │  │
│  │  ```                                            │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Explanation                                     │  │
│  │  The vulnerability was caused by...             │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Testing Recommendations                         │  │
│  │  1. Test with large inputs...                   │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  [Mark Applied] [Download] [Regenerate]        │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 🔄 State Transitions

```
Vulnerability States:
┌─────────────┐
│ Not Started │
└──────┬──────┘
       │ (Generate Patch)
       ▼
┌─────────────┐
│  Generated  │
└──────┬──────┘
       │ (Mark Applied)
       ▼
┌─────────────┐
│   Applied   │
└─────────────┘

Patch Generation States:
┌─────────────┐
│    Idle     │
└──────┬──────┘
       │ (User clicks Generate)
       ▼
┌─────────────┐
│  Analyzing  │
└──────┬──────┘
       │ (CVE Search)
       ▼
┌─────────────┐
│ Generating  │
└──────┬──────┘
       │ (AI Response)
       ▼
┌─────────────┐
│  Complete   │
└─────────────┘
```

## 📈 Performance Timeline

```
User Action: Generate Patch
│
├─ 0ms: Request received
│
├─ 100ms: Extract code context
│
├─ 500ms: Search CVE database
│
├─ 1000ms: Build AI prompt
│
├─ 2000ms: Send to Gemini API
│
├─ 10000ms: Receive AI response
│
├─ 10500ms: Parse and format
│
├─ 11000ms: Save to disk
│
└─ 11100ms: Display to user

Total: ~11 seconds
```

## 🎯 Success Path

```
✅ Setup Complete
    │
    ▼
✅ Scan Running
    │
    ▼
✅ Vulnerabilities Found
    │
    ▼
✅ Patches Generated
    │
    ▼
✅ Patches Reviewed
    │
    ▼
✅ Patches Applied
    │
    ▼
✅ Code Fixed
    │
    ▼
✅ Re-scan Clean
```

---

**Visual Guide Complete!** Use these diagrams to understand how the system works. 🎨
