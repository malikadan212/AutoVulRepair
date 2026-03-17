# AutoVulRepair - Actor Model Summary

## Overview
The AutoVulRepair system has been simplified to have **ONE PRIMARY ACTOR** with supporting secondary actors.

---

## Primary Actor

### **DEVELOPER**
The single primary user who interacts with all 6 modules of the AutoVulRepair system.

**Role**: Software developer who wants to find and fix security vulnerabilities in C/C++ code

**Capabilities**:
- Submit code for analysis (GitHub URL, ZIP file, or code snippet)
- View static analysis findings
- Generate fuzz plans and harnesses
- Execute fuzzing campaigns
- Review crash triage results
- Request AI-generated patches
- Review and accept/reject patches
- View sandbox validation results
- Monitor system metrics and dashboards
- Configure CI/CD pipelines
- Manage API keys for automation

**Access Methods**:
- **Web UI**: Interactive browser-based interface
- **API**: Programmatic access for automation
- **CI/CD Integration**: Automated workflows via GitHub Actions, Jenkins, GitLab CI

**Authentication**:
- GitHub OAuth for web UI access
- API keys for programmatic access
- Public access available for quick testing (no authentication required)

---

## Secondary Actors

These actors support the Developer's workflow but do not directly interact with the system UI:

### 1. **Static Analysis Tools** (Cppcheck, CodeQL)
- **Role**: Execute vulnerability detection
- **Module**: Module 1 (Static Analysis)
- **Interaction**: System invokes these tools to analyze code

### 2. **LLM Service** (OpenAI, Anthropic, Local Models)
- **Role**: Generate vulnerability patches using RAG
- **Module**: Module 3 (Patch Generation - Vul-RAG)
- **Interaction**: System queries LLM for patch suggestions

### 3. **Container Orchestrator** (Kubernetes)
- **Role**: Manage workloads, scale workers, execute jobs
- **Module**: Module 4 (CI/CD Orchestration)
- **Interaction**: System submits jobs to K8s cluster

### 4. **Monitoring System** (Prometheus + Grafana)
- **Role**: Collect metrics, visualize dashboards, send alerts
- **Module**: Module 6 (Monitoring & Metrics)
- **Interaction**: System exports metrics, Developer views dashboards

### 5. **Sandbox Environment** (gVisor)
- **Role**: Execute patched code safely in isolation
- **Module**: Module 5 (Sandbox Testing)
- **Interaction**: System runs validation tests in sandbox

### 6. **CI/CD System** (GitHub Actions, Jenkins, GitLab CI)
- **Role**: Automate Developer's workflows
- **Module**: Module 4 (CI/CD Orchestration)
- **Interaction**: Triggers scans automatically on code push, acts on behalf of Developer

---

## Actor Interaction Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         DEVELOPER                                │
│  (Primary Actor - Single User)                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Interacts via Web UI / API / CI/CD
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AutoVulRepair System                          │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Module 1    │  │  Module 2    │  │  Module 3    │          │
│  │  Static      │→ │  Dynamic     │→ │  Patch Gen   │          │
│  │  Analysis    │  │  Analysis    │  │  (Vul-RAG)   │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                    │
│         ▼                 ▼                 ▼                    │
│  ┌──────────────────────────────────────────────────┐          │
│  │  Module 5: Sandbox Testing                        │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────────────────────────────────────────┐          │
│  │  Module 4: CI/CD Orchestration (Manages All)     │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                   │
│  ┌──────────────────────────────────────────────────┐          │
│  │  Module 6: Monitoring & Metrics (Observes All)   │          │
│  └──────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
┌──────────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐
│ Static       │ │ LLM      │ │ K8s      │ │ Monitoring   │
│ Analysis     │ │ Service  │ │ Cluster  │ │ System       │
│ Tools        │ │          │ │          │ │              │
└──────────────┘ └──────────┘ └──────────┘ └──────────────┘
  (Secondary)     (Secondary)   (Secondary)   (Secondary)
```

---

## Use Case Distribution

### Developer's Use Cases by Module:

**Module 1 - Static Analysis** (10 use cases)
- UC-SA-01 through UC-SA-10

**Module 2 - Dynamic Analysis** (16 use cases)
- UC-DA-01 through UC-DA-16

**Module 3 - Patch Generation** (11 use cases)
- UC-PG-01 through UC-PG-11

**Module 4 - CI/CD Orchestration** (9 use cases)
- UC-CD-01 through UC-CD-09

**Module 5 - Sandbox Testing** (9 use cases)
- UC-ST-01 through UC-ST-09

**Module 6 - Monitoring & Metrics** (10 use cases)
- UC-MM-01 through UC-MM-10

**Authentication & User Management** (5 use cases)
- UC-AU-01 through UC-AU-05

**Total**: 70+ use cases, all accessible by the Developer

---

## Key Benefits of Single Primary Actor Model

1. **Simplicity**: Clear ownership - one user type for all functionality
2. **Consistency**: Same authentication and authorization model throughout
3. **Flexibility**: Developer can use web UI, API, or CI/CD as needed
4. **Scalability**: Secondary actors handle heavy lifting (LLM, K8s, etc.)
5. **Maintainability**: Easier to document and test with single actor model

---

## Authentication Modes

The Developer can access the system in three ways:

### 1. **Authenticated Mode** (GitHub OAuth)
- Full access to all features
- Personal dashboard
- Scan history
- API key management

### 2. **Public Mode** (No Authentication)
- Quick vulnerability scanning
- Limited to basic features
- No scan history
- Useful for evaluation

### 3. **API Mode** (API Keys)
- Programmatic access
- CI/CD integration
- Automated workflows
- Same capabilities as authenticated mode

---

## Conclusion

The AutoVulRepair system is designed around a **single primary actor (Developer)** who interacts with all 6 modules through multiple access methods (Web UI, API, CI/CD). Secondary actors provide supporting services but do not directly interact with the system interface.

This model provides:
- ✅ Clear user experience
- ✅ Consistent authentication
- ✅ Flexible access methods
- ✅ Scalable architecture
- ✅ Easy integration with existing workflows
