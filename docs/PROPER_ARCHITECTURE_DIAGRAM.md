# AutoVulRepair - Proper System Architecture Diagram
## Step-by-Step Guide to Create in draw.io

---

## Architecture Style: **Layered Architecture with Component View**

This is what professional architecture diagrams look like - showing **STRUCTURE**, not workflow.

---

## Layout Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                    AUTOVULREPAIR SYSTEM ARCHITECTURE                 │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 1: PRESENTATION TIER                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Web UI     │    │  REST API    │    │   CLI Tool   │          │
│  │  (Browser)   │    │  (JSON)      │    │  (Optional)  │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
                              ▼ HTTP/HTTPS
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 2: APPLICATION TIER                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Flask Web Application (Port 5000)                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │   │
│  │  │   Routes     │  │ Controllers  │  │   Auth       │     │   │
│  │  │   Handler    │  │   (Logic)    │  │  (OAuth)     │     │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Background Task Queue                                      │   │
│  │  ┌──────────────┐         ┌──────────────┐                │   │
│  │  │    Celery    │◄────────│    Redis     │                │   │
│  │  │    Worker    │  Broker │   (6379)     │                │   │
│  │  └──────────────┘         └──────────────┘                │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              ▼ Function Calls
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: BUSINESS LOGIC TIER (Processing Modules)                  │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  STATIC ANALYSIS SUBSYSTEM                                     │ │
│  │  ┌──────────────┐    ┌──────────────┐                        │ │
│  │  │  Cppcheck    │    │   CodeQL     │                        │ │
│  │  │  Analyzer    │    │   Analyzer   │                        │ │
│  │  └──────────────┘    └──────────────┘                        │ │
│  │  ┌──────────────────────────────────┐                        │ │
│  │  │  Findings Converter              │                        │ │
│  │  └──────────────────────────────────┘                        │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  FUZZING SUBSYSTEM                                             │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │ │
│  │  │  Fuzz Plan   │  │   Harness    │  │    Build     │       │ │
│  │  │  Generator   │  │  Generator   │  │ Orchestrator │       │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │ │
│  │  │    Fuzz      │  │    Crash     │  │  Repro Kit   │       │ │
│  │  │  Executor    │  │   Triage     │  │  Generator   │       │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │ │
│  │  ┌──────────────────────────────────┐                        │ │
│  │  │  LibFuzzer Engine                │                        │ │
│  │  └──────────────────────────────────┘                        │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  UTILITIES & HELPERS                                           │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │ │
│  │  │  Signature   │  │  Parameter   │  │  Validation  │       │ │
│  │  │  Extractor   │  │   Mapper     │  │   Utils      │       │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              ▼ Read/Write
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 4: DATA TIER                                                  │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  DATABASE                                                      │ │
│  │  ┌──────────────────────────────────────┐                    │ │
│  │  │  SQLite (scans.db)                   │                    │ │
│  │  │  - Scan metadata                     │                    │ │
│  │  │  - Status tracking                   │                    │ │
│  │  │  - Vulnerabilities (JSON)            │                    │ │
│  │  │  - Patches (JSON)                    │                    │ │
│  │  └──────────────────────────────────────┘                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  FILE SYSTEM STORAGE                                           │ │
│  │  ┌──────────────────────────────────────┐                    │ │
│  │  │  scans/{scan_id}/                    │                    │ │
│  │  │  ├── source/          (Source code)  │                    │ │
│  │  │  ├── artifacts/       (Reports)      │                    │ │
│  │  │  ├── fuzz/            (Fuzz data)    │                    │ │
│  │  │  ├── build/           (Binaries)     │                    │ │
│  │  │  └── repro_kits/      (Repro kits)   │                    │ │
│  │  └──────────────────────────────────────┘                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              ▼ Runs on
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 5: INFRASTRUCTURE TIER                                        │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  DOCKER COMPOSE ORCHESTRATION                                  │ │
│  │                                                                 │ │
│  │  ┌──────────────────┐  ┌──────────────────┐                  │ │
│  │  │  App Container   │  │  Redis Container │                  │ │
│  │  │  - Python 3.11   │  │  - Redis Alpine  │                  │ │
│  │  │  - Flask         │  │  - Port 6379     │                  │ │
│  │  │  - Clang/LLVM    │  │                  │                  │ │
│  │  │  - Port 5000     │  │                  │                  │ │
│  │  └──────────────────┘  └──────────────────┘                  │ │
│  │                                                                 │ │
│  │  ┌──────────────────────────────────────┐                    │ │
│  │  │  Shared Volumes                      │                    │ │
│  │  │  - ./scans:/app/scans                │                    │ │
│  │  │  - ./scans.db:/app/scans.db          │                    │ │
│  │  └──────────────────────────────────────┘                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  HOST OPERATING SYSTEM                                         │ │
│  │  - Windows / Linux / macOS                                     │ │
│  │  - Docker Engine                                               │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  EXTERNAL SYSTEMS                                                    │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   GitHub     │    │  Cppcheck    │    │  LibFuzzer   │          │
│  │   OAuth      │    │   (Tool)     │    │   (Engine)   │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## How to Create This in draw.io

### Step 1: Setup Canvas
1. Open draw.io
2. Create new blank diagram
3. Set canvas size: 1600 x 1400

### Step 2: Create Layers (Horizontal Bands)

**Layer 1: Presentation Tier** (Top)
- Rectangle: Width 1400, Height 150
- Fill: Light Blue (#dae8fc)
- Label: "PRESENTATION TIER"
- Add 3 boxes inside:
  - Web UI (Browser)
  - REST API (JSON)
  - CLI Tool (Optional)

**Layer 2: Application Tier**
- Rectangle: Width 1400, Height 200
- Fill: Light Yellow (#fff2cc)
- Label: "APPLICATION TIER"
- Add 2 sections:
  - Flask Web Application (with Routes, Controllers, Auth)
  - Background Task Queue (Celery + Redis)

**Layer 3: Business Logic Tier**
- Rectangle: Width 1400, Height 350
- Fill: Light Green (#d5e8d4)
- Label: "BUSINESS LOGIC TIER"
- Add 3 subsystems:
  - Static Analysis Subsystem (Cppcheck, CodeQL, Converter)
  - Fuzzing Subsystem (6 modules + LibFuzzer)
  - Utilities & Helpers (3 components)

**Layer 4: Data Tier**
- Rectangle: Width 1400, Height 200
- Fill: Light Orange (#ffe6cc)
- Label: "DATA TIER"
- Add 2 sections:
  - Database (SQLite)
  - File System Storage

**Layer 5: Infrastructure Tier**
- Rectangle: Width 1400, Height 200
- Fill: Light Gray (#f5f5f5)
- Label: "INFRASTRUCTURE TIER"
- Add:
  - Docker Compose (App Container + Redis Container)
  - Shared Volumes
  - Host OS

**External Systems** (Bottom)
- Rectangle: Width 1400, Height 100
- Fill: White
- Label: "EXTERNAL SYSTEMS"
- Add: GitHub OAuth, Cppcheck, LibFuzzer

### Step 3: Add Arrows (Vertical Only!)

**Key difference from workflow diagram:** Arrows go **UP and DOWN** between layers, NOT left to right!

1. **Presentation → Application**
   - Arrow: HTTP/HTTPS
   - Style: Solid, thick

2. **Application → Business Logic**
   - Arrow: Function Calls
   - Style: Solid, thick

3. **Business Logic → Data**
   - Arrow: Read/Write
   - Style: Solid, thick

4. **Data → Infrastructure**
   - Arrow: Runs on
   - Style: Dashed

5. **Application ↔ External Systems**
   - Arrows: API Calls
   - Style: Dashed

### Step 4: Add Component Details

Inside each box, add small text showing:
- **Technology used** (e.g., "Python 3.11", "Redis Alpine")
- **Port numbers** (e.g., "Port 5000", "Port 6379")
- **Key responsibilities** (e.g., "Scan metadata", "Source code")

### Step 5: Add Legend (Bottom Right)

```
┌─────────────────────┐
│  LEGEND             │
├─────────────────────┤
│  ━━━  Data Flow     │
│  ┈┈┈  Dependency    │
│  ▭    Component     │
│  ▭    Subsystem     │
└─────────────────────┘
```

---

## Color Scheme (Professional)

| Layer | Color | Hex Code |
|-------|-------|----------|
| Presentation | Light Blue | #dae8fc |
| Application | Light Yellow | #fff2cc |
| Business Logic | Light Green | #d5e8d4 |
| Data | Light Orange | #ffe6cc |
| Infrastructure | Light Gray | #f5f5f5 |
| External | White | #ffffff |

---

## Key Differences from Workflow Diagram

| Workflow Diagram | Architecture Diagram |
|------------------|----------------------|
| Shows sequence (1→2→3) | Shows structure (layers) |
| Horizontal flow | Vertical layers |
| Process-oriented | Component-oriented |
| "What happens?" | "What exists?" |
| Arrows show data flow | Arrows show relationships |

---

## What Makes This a PROPER Architecture Diagram

✅ **Layered structure** - Shows separation of concerns
✅ **Component grouping** - Related components together
✅ **Technology stack** - Shows what tech is used where
✅ **Deployment view** - Shows Docker containers
✅ **External dependencies** - Shows third-party systems
✅ **No sequential flow** - Not showing step-by-step process
✅ **Bidirectional arrows** - Shows relationships, not workflow

---

## Alternative: Component Diagram (UML Style)

If you want even more formal, use **UML Component Diagram**:

```
┌─────────────────────────────────────────────────────────┐
│                    «system»                              │
│                  AutoVulRepair                           │
│                                                          │
│  ┌──────────────┐         ┌──────────────┐             │
│  │«component»   │         │«component»   │             │
│  │ Flask App    │────────▶│ Celery Worker│             │
│  │              │         │              │             │
│  └──────────────┘         └──────────────┘             │
│         │                        │                      │
│         │                        │                      │
│         ▼                        ▼                      │
│  ┌──────────────┐         ┌──────────────┐             │
│  │«database»    │         │«component»   │             │
│  │ SQLite       │         │ Redis Queue  │             │
│  └──────────────┘         └──────────────┘             │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │         «subsystem»                            │    │
│  │         Processing Modules                     │    │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐         │    │
│  │  │Module│ │Module│ │Module│ │Module│         │    │
│  │  │  1   │ │  2   │ │  3   │ │  4   │         │    │
│  │  └──────┘ └──────┘ └──────┘ └──────┘         │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Checklist: Is This an Architecture Diagram?

✅ Shows **components** (not steps)
✅ Shows **layers** (not sequence)
✅ Shows **technologies** (not data)
✅ Shows **structure** (not flow)
✅ Shows **relationships** (not order)
✅ Can be read **top-to-bottom** (not left-to-right)
✅ Answers "**What is the system made of?**" (not "What does it do?")

---

## For Your Thesis Defense

**When presenting:**

> "This is the system architecture showing our layered design. At the top, we have the Presentation Tier with web UI and REST API. Below that, the Application Tier handles requests using Flask and processes them asynchronously with Celery. The Business Logic Tier contains our processing modules organized into subsystems. The Data Tier manages persistence with SQLite and file storage. Finally, the Infrastructure Tier shows our Docker-based deployment."

**Point to each layer as you explain!**

---

## Summary

**Your current diagram:** Workflow (shows process)
**What you need:** Architecture (shows structure)

**Main changes:**
1. ❌ Remove left-to-right module flow
2. ✅ Add horizontal layers (tiers)
3. ❌ Remove "Input → Output" labels
4. ✅ Add component groupings
5. ❌ Remove sequential arrows
6. ✅ Add vertical layer relationships
7. ✅ Show technology stack
8. ✅ Show deployment structure

**Want me to create the exact draw.io XML for this?** I can give you copy-paste code!
