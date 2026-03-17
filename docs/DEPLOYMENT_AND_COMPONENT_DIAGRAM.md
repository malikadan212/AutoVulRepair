# AutoVulRepair - Deployment and Component Architecture

## Document Information
- **Project**: AutoVulRepair - Automated Vulnerability Detection and Patching System
- **Version**: 1.0
- **Date**: December 7, 2025
- **Purpose**: Complete deployment architecture and component diagrams

---

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Component Diagram](#component-diagram)
3. [Deployment Diagram](#deployment-diagram)
4. [Container Architecture](#container-architecture)
5. [Network Architecture](#network-architecture)
6. [Infrastructure Components](#infrastructure-components)
7. [Scalability and High Availability](#scalability-and-high-availability)
8. [Security Architecture](#security-architecture)

---

## Architecture Overview

AutoVulRepair follows a **microservices-inspired modular architecture** with the following characteristics:

### Architectural Style
- **Modular Monolith**: Single application with clear module boundaries
- **Event-Driven**: Asynchronous task processing via Celery
- **Containerized**: Docker-based deployment for consistency
- **Scalable**: Horizontal scaling via Kubernetes (production)

### Key Architectural Principles
1. **Separation of Concerns**: Each module has distinct responsibilities
2. **Loose Coupling**: Modules communicate via well-defined interfaces
3. **High Cohesion**: Related functionality grouped within modules
4. **Asynchronous Processing**: Long-running tasks handled by workers
5. **Stateless Services**: Application servers are stateless for scalability


---

## Component Diagram

### High-Level Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AutoVulRepair System                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Presentation Layer                               │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │    │
│  │  │   Web UI     │  │   REST API   │  │   Webhooks   │            │    │
│  │  │  (Flask)     │  │  (Flask)     │  │   (Flask)    │            │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘            │    │
│  │         │                  │                  │                     │    │
│  └─────────┼──────────────────┼──────────────────┼─────────────────────┘    │
│            │                  │                  │                           │
│            └──────────────────┴──────────────────┘                           │
│                               │                                               │
│  ┌────────────────────────────┼────────────────────────────────────────┐    │
│  │                    Application Layer                                 │    │
│  ├────────────────────────────┼────────────────────────────────────────┤    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │              Core Application (app.py)                        │  │    │
│  │  │  - Route Handlers                                             │  │    │
│  │  │  - Request Validation                                         │  │    │
│  │  │  - Session Management                                         │  │    │
│  │  │  - Authentication (OAuth)                                     │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │              Domain Services Layer                            │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │                                                                │  │    │
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │  │    │
│  │  │  │ Scan           │  │ Fuzz Plan      │  │ Harness        │ │  │    │
│  │  │  │ Orchestration  │  │ Generation     │  │ Generation     │ │  │    │
│  │  │  │ Service        │  │ Service        │  │ Service        │ │  │    │
│  │  │  └────────────────┘  └────────────────┘  └────────────────┘ │  │    │
│  │  │                                                                │  │    │
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │  │    │
│  │  │  │ Build          │  │ Fuzz           │  │ Crash          │ │  │    │
│  │  │  │ Orchestration  │  │ Execution      │  │ Triage         │ │  │    │
│  │  │  │ Service        │  │ Service        │  │ Service        │ │  │    │
│  │  │  └────────────────┘  └────────────────┘  └────────────────┘ │  │    │
│  │  │                                                                │  │    │
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │  │    │
│  │  │  │ Patch          │  │ Patch          │  │ Workflow       │ │  │    │
│  │  │  │ Generation     │  │ Validation     │  │ Orchestration  │ │  │    │
│  │  │  │ Service        │  │ Service        │  │ Service        │ │  │    │
│  │  │  └────────────────┘  └────────────────┘  └────────────────┘ │  │    │
│  │  │                                                                │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Module Layer (Business Logic)                     │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │  Module 1    │  │  Module 2    │  │  Module 3    │              │   │
│  │  │  Static      │  │  Dynamic     │  │  Patch Gen   │              │   │
│  │  │  Analysis    │  │  Analysis    │  │  (Vul-RAG)   │              │   │
│  │  ├──────────────┤  ├──────────────┤  ├──────────────┤              │   │
│  │  │ - Cppcheck   │  │ - FuzzPlan   │  │ - LLM Client │              │   │
│  │  │ - CodeQL     │  │ - Harness    │  │ - RAG Query  │              │   │
│  │  │ - Converter  │  │ - Build      │  │ - Compiler   │              │   │
│  │  │              │  │ - Executor   │  │   Feedback   │              │   │
│  │  │              │  │ - Triage     │  │              │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  │                                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │  Module 4    │  │  Module 5    │  │  Module 6    │              │   │
│  │  │  CI/CD       │  │  Sandbox     │  │  Monitoring  │              │   │
│  │  │  Orchestrate │  │  Testing     │  │  & Metrics   │              │   │
│  │  ├──────────────┤  ├──────────────┤  ├──────────────┤              │   │
│  │  │ - K8s Client │  │ - gVisor     │  │ - Prometheus │              │   │
│  │  │ - Workflow   │  │ - Benchmark  │  │ - Metrics    │              │   │
│  │  │ - Pipeline   │  │ - Regression │  │ - Logging    │              │   │
│  │  │              │  │              │  │              │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Infrastructure Layer                              │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │  Task Queue  │  │  Database    │  │  File        │              │   │
│  │  │  (Celery)    │  │  (SQLite/    │  │  Storage     │              │   │
│  │  │              │  │  PostgreSQL) │  │              │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  │         │                  │                  │                      │   │
│  │         ▼                  ▼                  ▼                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │  Redis       │  │  SQLAlchemy  │  │  Local FS /  │              │   │
│  │  │  (Broker)    │  │  (ORM)       │  │  S3 / NFS    │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    External Services                                 │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │  GitHub      │  │  LLM Service │  │  Docker      │              │   │
│  │  │  OAuth       │  │  (OpenAI/    │  │  Registry    │              │   │
│  │  │              │  │  Claude)     │  │              │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  │                                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │  Kubernetes  │  │  Prometheus  │  │  Grafana     │              │   │
│  │  │  Cluster     │  │  Server      │  │  Server      │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```


---

## Deployment Diagram

### Development Environment (Docker Compose)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Development Host Machine                             │
│                         (Windows/macOS/Linux)                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Docker Compose Network                           │    │
│  │                    (bridge: autovulrepair_default)                  │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Container: app                                               │  │    │
│  │  │  Image: autovulrepair:latest                                  │  │    │
│  │  │  Hostname: app                                                │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │  Components:                                                  │  │    │
│  │  │  - Flask Application (app.py)                                │  │    │
│  │  │  - Python 3.11                                               │  │    │
│  │  │  - Clang/LLVM 19 (fuzzing compiler)                         │  │    │
│  │  │  - LibFuzzer                                                 │  │    │
│  │  │  - Cppcheck                                                  │  │    │
│  │  │  - CodeQL (optional)                                         │  │    │
│  │  │                                                               │  │    │
│  │  │  Ports:                                                       │  │    │
│  │  │  - 5000:5000 (HTTP)                                          │  │    │
│  │  │                                                               │  │    │
│  │  │  Volumes:                                                     │  │    │
│  │  │  - ./scans:/app/scans (scan data)                           │  │    │
│  │  │  - ./logs:/app/logs (application logs)                      │  │    │
│  │  │  - ./scans.db:/app/scans.db (SQLite database)               │  │    │
│  │  │  - /var/run/docker.sock (Docker socket)                     │  │    │
│  │  │                                                               │  │    │
│  │  │  Environment:                                                 │  │    │
│  │  │  - FLASK_SECRET_KEY                                          │  │    │
│  │  │  - GITHUB_CLIENT_ID                                          │  │    │
│  │  │  - GITHUB_CLIENT_SECRET                                      │  │    │
│  │  │  - REDIS_URL=redis://redis:6379/0                           │  │    │
│  │  │  - SCANS_DIR=/app/scans                                      │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            │ HTTP                                    │    │
│  │                            ▼                                         │    │
│  │                    ┌───────────────┐                                │    │
│  │                    │  Port 5000    │                                │    │
│  │                    │  (exposed)    │                                │    │
│  │                    └───────────────┘                                │    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Container: celery                                            │  │    │
│  │  │  Image: autovulrepair:latest                                  │  │    │
│  │  │  Hostname: celery                                             │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │  Components:                                                  │  │    │
│  │  │  - Celery Worker (celery_worker.py)                          │  │    │
│  │  │  - Python 3.11                                               │  │    │
│  │  │  - Clang/LLVM 19                                             │  │    │
│  │  │  - Analysis Tools (Cppcheck, CodeQL)                         │  │    │
│  │  │                                                               │  │    │
│  │  │  Command:                                                     │  │    │
│  │  │  python celery_worker.py                                     │  │    │
│  │  │                                                               │  │    │
│  │  │  Volumes:                                                     │  │    │
│  │  │  - ./scans:/app/scans (shared scan data)                    │  │    │
│  │  │  - ./logs:/app/logs (worker logs)                           │  │    │
│  │  │  - ./scans.db:/app/scans.db (shared database)               │  │    │
│  │  │  - /var/run/docker.sock (Docker socket)                     │  │    │
│  │  │                                                               │  │    │
│  │  │  Environment:                                                 │  │    │
│  │  │  - REDIS_URL=redis://redis:6379/0                           │  │    │
│  │  │  - SCANS_DIR=/app/scans                                      │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            │ Redis Protocol                          │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Container: redis                                             │  │    │
│  │  │  Image: redis:7-alpine                                        │  │    │
│  │  │  Hostname: redis                                              │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │  Components:                                                  │  │    │
│  │  │  - Redis Server 7.x                                          │  │    │
│  │  │  - AOF Persistence (appendonly yes)                          │  │    │
│  │  │                                                               │  │    │
│  │  │  Ports:                                                       │  │    │
│  │  │  - 6379:6379 (Redis)                                         │  │    │
│  │  │                                                               │  │    │
│  │  │  Volumes:                                                     │  │    │
│  │  │  - redis-data:/data (persistent storage)                     │  │    │
│  │  │                                                               │  │    │
│  │  │  Health Check:                                                │  │    │
│  │  │  - Command: redis-cli ping                                   │  │    │
│  │  │  - Interval: 10s                                             │  │    │
│  │  │  - Timeout: 5s                                               │  │    │
│  │  │  - Retries: 5                                                │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                                                                      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Host File System                                 │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │  - ./scans/          (scan artifacts and results)                  │    │
│  │  - ./logs/           (application and worker logs)                 │    │
│  │  - ./scans.db        (SQLite database file)                        │    │
│  │  - ./templates/      (Flask HTML templates)                        │    │
│  │  - ./src/            (Python source code)                          │    │
│  │  - ./app.py          (Flask application)                           │    │
│  │  - .env              (environment variables)                       │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Internet
                                    ▼
                    ┌───────────────────────────────┐
                    │   External Services           │
                    ├───────────────────────────────┤
                    │ - GitHub OAuth                │
                    │ - GitHub API (repo cloning)   │
                    │ - OpenAI API (optional)       │
                    │ - Anthropic API (optional)    │
                    └───────────────────────────────┘
```


---

### Production Environment (Kubernetes)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                                   │
│                         (AWS EKS / GCP GKE / Azure AKS)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Namespace: autovulrepair                         │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Ingress Controller (NGINX / Traefik)                        │  │    │
│  │  │  - SSL/TLS Termination                                       │  │    │
│  │  │  - Load Balancing                                            │  │    │
│  │  │  - Rate Limiting                                             │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            │ HTTPS                                   │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Service: autovulrepair-web (LoadBalancer)                   │  │    │
│  │  │  Port: 80 → 5000                                             │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Deployment: autovulrepair-app                               │  │    │
│  │  │  Replicas: 3 (auto-scaling: 2-10)                           │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │  Pod 1                                                        │  │    │
│  │  │  ┌────────────────────────────────────────────────────────┐ │  │    │
│  │  │  │  Container: app                                         │ │  │    │
│  │  │  │  Image: autovulrepair:v1.0.0                           │ │  │    │
│  │  │  │  Resources:                                             │ │  │    │
│  │  │  │  - CPU: 1000m (request), 2000m (limit)                │ │  │    │
│  │  │  │  - Memory: 2Gi (request), 4Gi (limit)                 │ │  │    │
│  │  │  │  Probes:                                                │ │  │    │
│  │  │  │  - Liveness: /health                                   │ │  │    │
│  │  │  │  - Readiness: /ready                                   │ │  │    │
│  │  │  └────────────────────────────────────────────────────────┘ │  │    │
│  │  │                                                               │  │    │
│  │  │  Pod 2, Pod 3 (identical configuration)                      │  │    │
│  │  │                                                               │  │    │
│  │  │  ConfigMap: app-config                                        │  │    │
│  │  │  Secret: app-secrets (GitHub OAuth, API keys)                │  │    │
│  │  │                                                               │  │    │
│  │  │  PersistentVolumeClaim: scans-pvc (ReadWriteMany)           │  │    │
│  │  │  - Storage: 100Gi                                            │  │    │
│  │  │  - StorageClass: nfs / efs / azurefile                       │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            │ Redis Protocol                          │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  StatefulSet: redis                                          │  │    │
│  │  │  Replicas: 1 (or Redis Cluster for HA)                      │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │  Pod: redis-0                                                │  │    │
│  │  │  ┌────────────────────────────────────────────────────────┐ │  │    │
│  │  │  │  Container: redis                                       │ │  │    │
│  │  │  │  Image: redis:7-alpine                                  │ │  │    │
│  │  │  │  Resources:                                             │ │  │    │
│  │  │  │  - CPU: 500m (request), 1000m (limit)                 │ │  │    │
│  │  │  │  - Memory: 1Gi (request), 2Gi (limit)                 │ │  │    │
│  │  │  │  PersistentVolumeClaim: redis-data-redis-0             │ │  │    │
│  │  │  │  - Storage: 10Gi                                       │ │  │    │
│  │  │  └────────────────────────────────────────────────────────┘ │  │    │
│  │  │                                                               │  │    │
│  │  │  Service: redis (ClusterIP)                                  │  │    │
│  │  │  Port: 6379                                                   │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            │ Task Queue                              │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Deployment: celery-worker                                   │  │    │
│  │  │  Replicas: 5 (auto-scaling: 3-20)                           │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │  Pod 1-5                                                      │  │    │
│  │  │  ┌────────────────────────────────────────────────────────┐ │  │    │
│  │  │  │  Container: celery-worker                               │ │  │    │
│  │  │  │  Image: autovulrepair:v1.0.0                           │ │  │    │
│  │  │  │  Command: python celery_worker.py                      │ │  │    │
│  │  │  │  Resources:                                             │ │  │    │
│  │  │  │  - CPU: 2000m (request), 4000m (limit)                │ │  │    │
│  │  │  │  - Memory: 4Gi (request), 8Gi (limit)                 │ │  │    │
│  │  │  │  PersistentVolumeClaim: scans-pvc (shared)             │ │  │    │
│  │  │  └────────────────────────────────────────────────────────┘ │  │    │
│  │  │                                                               │  │    │
│  │  │  HorizontalPodAutoscaler:                                     │  │    │
│  │  │  - Target CPU: 70%                                            │  │    │
│  │  │  - Target Memory: 80%                                         │  │    │
│  │  │  - Min Replicas: 3                                            │  │    │
│  │  │  - Max Replicas: 20                                           │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            │ SQL                                     │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  StatefulSet: postgresql                                     │  │    │
│  │  │  Replicas: 1 (or PostgreSQL HA cluster)                     │  │    │
│  │  ├──────────────────────────────────────────────────────────────┤  │    │
│  │  │  Pod: postgresql-0                                           │  │    │
│  │  │  ┌────────────────────────────────────────────────────────┐ │  │    │
│  │  │  │  Container: postgresql                                  │ │  │    │
│  │  │  │  Image: postgres:15-alpine                              │ │  │    │
│  │  │  │  Resources:                                             │ │  │    │
│  │  │  │  - CPU: 1000m (request), 2000m (limit)                │ │  │    │
│  │  │  │  - Memory: 2Gi (request), 4Gi (limit)                 │ │  │    │
│  │  │  │  PersistentVolumeClaim: postgres-data-postgresql-0     │ │  │    │
│  │  │  │  - Storage: 50Gi                                       │ │  │    │
│  │  │  │  Secret: postgres-credentials                          │ │  │    │
│  │  │  └────────────────────────────────────────────────────────┘ │  │    │
│  │  │                                                               │  │    │
│  │  │  Service: postgresql (ClusterIP)                             │  │    │
│  │  │  Port: 5432                                                   │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                                                                      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Namespace: monitoring                            │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Deployment: prometheus                                      │  │    │
│  │  │  - Metrics collection                                        │  │    │
│  │  │  - Alert manager                                             │  │    │
│  │  │  - PersistentVolume: 100Gi                                   │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                            │                                         │    │
│  │                            ▼                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  Deployment: grafana                                         │  │    │
│  │  │  - Dashboards                                                │  │    │
│  │  │  - Visualization                                             │  │    │
│  │  │  - Alerting                                                  │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                                                                      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Internet
                                    ▼
                    ┌───────────────────────────────┐
                    │   External Services           │
                    ├───────────────────────────────┤
                    │ - GitHub OAuth                │
                    │ - GitHub API                  │
                    │ - OpenAI API                  │
                    │ - Anthropic API               │
                    │ - Docker Registry (ECR/GCR)   │
                    │ - Object Storage (S3/GCS)     │
                    └───────────────────────────────┘
```


---

## Container Architecture

### Docker Container Details

#### 1. **Application Container (app)**

**Base Image**: `python:3.11`

**Installed Components**:
```dockerfile
# System Dependencies
- git
- curl
- ca-certificates

# Fuzzing Toolchain
- clang (LLVM 19)
- llvm
- libfuzzer-19-dev
- libc++-dev
- libc++abi-dev
- libclang-rt-19-dev

# Analysis Tools
- cppcheck (via apt or pip)
- codeql (optional, downloaded separately)

# Python Dependencies (from requirements.txt)
- Flask
- Flask-Login
- Authlib
- Celery
- Redis
- SQLAlchemy
- python-dotenv
- requests
```

**Directory Structure**:
```
/app/
├── app.py                  # Flask application entry point
├── celery_worker.py        # Celery worker entry point
├── requirements.txt        # Python dependencies
├── src/                    # Source code modules
│   ├── analysis/           # Module 1: Static analysis
│   ├── fuzz_plan/          # Module 2: Fuzz plan generation
│   ├── harness/            # Module 2: Harness generation
│   ├── build/              # Module 2: Build orchestration
│   ├── fuzz_exec/          # Module 2: Fuzz execution
│   ├── triage/             # Module 2: Crash triage
│   ├── repro/              # Module 2: Reproduction kits
│   ├── models/             # Database models
│   ├── queue/              # Celery tasks
│   └── utils/              # Utilities
├── templates/              # Flask HTML templates
├── scans/                  # Scan artifacts (volume mount)
├── logs/                   # Application logs (volume mount)
└── scans.db                # SQLite database (volume mount)
```

**Exposed Ports**:
- `5000`: Flask HTTP server

**Health Check**:
```bash
curl -f http://localhost:5000/ || exit 1
```

**Environment Variables**:
- `FLASK_SECRET_KEY`: Flask session secret
- `GITHUB_CLIENT_ID`: GitHub OAuth client ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth client secret
- `REDIS_URL`: Redis connection URL
- `SCANS_DIR`: Scan artifacts directory
- `DATABASE_PATH`: Database file path
- `FLASK_ENV`: Environment (development/production)
- `FLASK_DEBUG`: Debug mode (0/1)

---

#### 2. **Celery Worker Container (celery)**

**Base Image**: Same as app container (`python:3.11` with toolchain)

**Command**: `python celery_worker.py`

**Worker Configuration**:
```python
# celery_worker.py
celery_app.worker_main([
    'worker',
    '--loglevel=info',
    '--pool=solo',  # Windows compatibility
    '--concurrency=4',  # Number of worker processes
    '--max-tasks-per-child=100'  # Restart after 100 tasks
])
```

**Task Types**:
1. **Static Analysis Tasks**:
   - `analyze_with_cppcheck(scan_id)`
   - `analyze_with_codeql(scan_id)`

2. **Fuzzing Tasks** (future):
   - `generate_fuzz_plan(scan_id)`
   - `generate_harnesses(scan_id)`
   - `build_targets(scan_id)`
   - `execute_fuzzing(scan_id)`

3. **Patch Generation Tasks** (future):
   - `generate_patches(scan_id)`
   - `validate_patches(scan_id)`

**Resource Requirements**:
- CPU: 2-4 cores per worker
- Memory: 4-8 GB per worker
- Disk: Shared with app container

---

#### 3. **Redis Container (redis)**

**Base Image**: `redis:7-alpine`

**Configuration**:
```bash
redis-server --appendonly yes
```

**Persistence**:
- AOF (Append-Only File) enabled
- Volume: `redis-data:/data`

**Exposed Ports**:
- `6379`: Redis protocol

**Health Check**:
```bash
redis-cli ping
```

**Use Cases**:
1. **Celery Broker**: Task queue for async jobs
2. **Celery Backend**: Task result storage
3. **Session Storage** (optional): Flask sessions
4. **Cache** (optional): Temporary data caching

---

### Container Communication

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Network Bridge                         │
│                    (autovulrepair_default)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐         ┌──────────────┐                      │
│  │     app      │────────▶│    redis     │                      │
│  │  (Flask)     │  Redis  │  (Broker)    │                      │
│  │              │  Proto  │              │                      │
│  └──────────────┘         └──────────────┘                      │
│         │                         ▲                              │
│         │                         │                              │
│         │ Task Queue              │ Task Queue                   │
│         │ (publish)               │ (consume)                    │
│         │                         │                              │
│         ▼                         │                              │
│  ┌──────────────┐                │                              │
│  │    celery    │────────────────┘                              │
│  │   (Worker)   │                                               │
│  │              │                                               │
│  └──────────────┘                                               │
│         │                                                        │
│         │ Shared Volume                                         │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  scans.db    │  (SQLite database)                           │
│  │  ./scans/    │  (Scan artifacts)                            │
│  │  ./logs/     │  (Application logs)                          │
│  └──────────────┘                                               │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Communication Protocols**:
1. **HTTP**: Client → app (port 5000)
2. **Redis Protocol**: app ↔ redis, celery ↔ redis (port 6379)
3. **File System**: app ↔ celery (shared volumes)
4. **Docker Socket**: app → Docker daemon (for nested containers)


---

## Network Architecture

### Network T
opology

### Development Network Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Internet / External Services                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  - GitHub OAuth (oauth.github.com)                                          │
│  - GitHub API (api.github.com)                                              │
│  - OpenAI API (api.openai.com)                                              │
│  - Anthropic API (api.anthropic.com)                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTPS
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Host Machine Firewall                                │
│                         (iptables / Windows Firewall)                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Docker Bridge Network                                │
│                         (172.18.0.0/16)                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐  │
│  │  app             │      │  celery          │      │  redis           │  │
│  │  172.18.0.2      │      │  172.18.0.3      │      │  172.18.0.4      │  │
│  │  Port: 5000      │      │  No exposed port │      │  Port: 6379      │  │
│  └──────────────────┘      └──────────────────┘      └──────────────────┘  │
│         │                           │                           │            │
│         └───────────────────────────┴───────────────────────────┘            │
│                                     │                                         │
│                                     │ Internal DNS                            │
│                                     │ (app, celery, redis)                    │
│                                     │                                         │
└─────────────────────────────────────┼─────────────────────────────────────────┘
                                      │
                                      │ Port Mapping
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Host Machine                                         │
│                         (localhost / 127.0.0.1)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  - Port 5000 → app:5000 (HTTP)                                              │
│  - Port 6379 → redis:6379 (Redis)                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTP
                                      ▼
                              ┌──────────────┐
                              │   Browser    │
                              │   Client     │
                              └──────────────┘
```

### Production Network Topology (Kubernetes)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Internet                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTPS (443)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Cloud Load Balancer                                  │
│                         (AWS ALB / GCP LB / Azure LB)                        │
│  - SSL/TLS Termination                                                       │
│  - DDoS Protection                                                           │
│  - WAF (Web Application Firewall)                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTP (80)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Ingress Controller                        │
│                         (NGINX / Traefik / Istio)                            │
│  - Path-based routing                                                        │
│  - Rate limiting                                                             │
│  - Authentication                                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Service Network                           │
│                         (ClusterIP / NodePort / LoadBalancer)                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Service: autovulrepair-web (LoadBalancer)                           │  │
│  │  ClusterIP: 10.96.0.10                                                │  │
│  │  Port: 80 → 5000                                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    │ Round-robin                             │
│                                    ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Pod Network (CNI: Calico / Flannel / Cilium)                        │  │
│  │  CIDR: 10.244.0.0/16                                                  │  │
│  ├──────────────────────────────────────────────────────────────────────┤  │
│  │                                                                        │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐                      │  │
│  │  │  app-pod-1 │  │  app-pod-2 │  │  app-pod-3 │                      │  │
│  │  │  10.244.1.5│  │  10.244.2.8│  │  10.244.3.2│                      │  │
│  │  └────────────┘  └────────────┘  └────────────┘                      │  │
│  │                                                                        │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐                      │  │
│  │  │ worker-1   │  │ worker-2   │  │ worker-3   │                      │  │
│  │  │ 10.244.1.6 │  │ 10.244.2.9 │  │ 10.244.3.3 │                      │  │
│  │  └────────────┘  └────────────┘  └────────────┘                      │  │
│  │                                                                        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    │ Internal DNS                            │
│                                    ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Service: redis (ClusterIP)                                          │  │
│  │  ClusterIP: 10.96.0.20                                                │  │
│  │  Port: 6379                                                           │  │
│  │  DNS: redis.autovulrepair.svc.cluster.local                          │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Service: postgresql (ClusterIP)                                     │  │
│  │  ClusterIP: 10.96.0.30                                                │  │
│  │  Port: 5432                                                           │  │
│  │  DNS: postgresql.autovulrepair.svc.cluster.local                     │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Egress
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         External Services                                    │
│  - GitHub OAuth / API                                                        │
│  - OpenAI / Anthropic APIs                                                   │
│  - Docker Registry (ECR / GCR / ACR)                                         │
│  - Object Storage (S3 / GCS / Azure Blob)                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Infrastructure Components

### 1. **Storage Components**

#### Development (Docker Compose)
```yaml
volumes:
  redis-data:
    driver: local
  
  # Host bind mounts
  ./scans:/app/scans
  ./logs:/app/logs
  ./scans.db:/app/scans.db
```

#### Production (Kubernetes)
```yaml
# Persistent Volume Claims
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: scans-pvc
spec:
  accessModes:
    - ReadWriteMany  # Shared across pods
  storageClassName: nfs  # or efs, azurefile
  resources:
    requests:
      storage: 100Gi

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-data
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: gp3  # or pd-ssd, managed-premium
  resources:
    requests:
      storage: 50Gi

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-data
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: gp3
  resources:
    requests:
      storage: 10Gi
```

**Storage Classes**:
- **NFS / EFS / Azure Files**: For shared scan artifacts (ReadWriteMany)
- **GP3 / PD-SSD / Premium SSD**: For databases (ReadWriteOnce)
- **S3 / GCS / Azure Blob**: For long-term artifact archival

---

### 2. **Configuration Management**

#### ConfigMap (Non-sensitive configuration)
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  SCANS_DIR: "/app/scans"
  FLASK_ENV: "production"
  FLASK_DEBUG: "0"
  REDIS_URL: "redis://redis:6379/0"
  DATABASE_URL: "postgresql://postgres:5432/autovulrepair"
  MAX_CONTENT_LENGTH: "104857600"  # 100MB
  CELERY_CONCURRENCY: "4"
```

#### Secret (Sensitive configuration)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  FLASK_SECRET_KEY: "<random-secret-key>"
  GITHUB_CLIENT_ID: "<github-oauth-client-id>"
  GITHUB_CLIENT_SECRET: "<github-oauth-client-secret>"
  OPENAI_API_KEY: "<openai-api-key>"
  ANTHROPIC_API_KEY: "<anthropic-api-key>"
  DATABASE_PASSWORD: "<postgres-password>"
```

---

### 3. **Service Mesh (Optional - Advanced)**

For production environments with complex microservices:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Istio Service Mesh                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Ingress Gateway                                          │  │
│  │  - TLS termination                                        │  │
│  │  - Authentication                                         │  │
│  │  - Rate limiting                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Virtual Services                                         │  │
│  │  - Traffic routing                                        │  │
│  │  - Canary deployments                                     │  │
│  │  - A/B testing                                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Sidecar Proxies (Envoy)                                 │  │
│  │  - mTLS encryption                                        │  │
│  │  - Circuit breaking                                       │  │
│  │  - Retry logic                                            │  │
│  │  - Observability                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Benefits**:
- Automatic mTLS between services
- Advanced traffic management
- Distributed tracing
- Service-to-service authentication
- Circuit breaking and retries

---

## Scalability and High Availability

### Horizontal Pod Autoscaling (HPA)

#### Application Pods
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: autovulrepair-app
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
```

#### Celery Workers
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: celery-worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: celery-worker
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: External
    external:
      metric:
        name: redis_queue_length
      target:
        type: AverageValue
        averageValue: "10"  # Scale up if queue > 10 tasks per worker
```

---

### High Availability Configuration

#### Redis High Availability (Redis Sentinel)
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
spec:
  serviceName: redis
  replicas: 3  # 1 master + 2 replicas
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
          - redis-server
          - --appendonly yes
          - --replica-announce-ip $(POD_IP)
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: data
          mountPath: /data
      - name: sentinel
        image: redis:7-alpine
        command:
          - redis-sentinel
          - /etc/redis/sentinel.conf
        ports:
        - containerPort: 26379
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
```

#### PostgreSQL High Availability (Patroni)
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgresql
spec:
  serviceName: postgresql
  replicas: 3  # 1 primary + 2 standby
  selector:
    matchLabels:
      app: postgresql
  template:
    metadata:
      labels:
        app: postgresql
    spec:
      containers:
      - name: postgresql
        image: postgres:15-alpine
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-credentials
              key: password
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 5
          periodSeconds: 5
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 50Gi
```

---

### Load Balancing Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│                    Load Balancing Layers                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Layer 1: Cloud Load Balancer (L7)                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  - Geographic distribution                                │  │
│  │  - SSL/TLS termination                                    │  │
│  │  - DDoS protection                                        │  │
│  │  - Health checks                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  Layer 2: Ingress Controller (L7)                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  - Path-based routing                                     │  │
│  │  - Host-based routing                                     │  │
│  │  - Rate limiting                                          │  │
│  │  - Authentication                                         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  Layer 3: Kubernetes Service (L4)                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  - Round-robin distribution                               │  │
│  │  - Session affinity (optional)                            │  │
│  │  - Health-based routing                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  Layer 4: Application Pods                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Pod 1    Pod 2    Pod 3    ...    Pod N                 │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Security Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Security Architecture                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Layer 1: Network Security                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Cloud Firewall (Security Groups / NSGs)                          │   │
│  │  - Network Policies (Kubernetes)                                     │   │
│  │  - DDoS Protection                                                   │   │
│  │  - WAF (Web Application Firewall)                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Layer 2: Transport Security                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - TLS 1.3 for external traffic                                     │   │
│  │  - mTLS for internal service-to-service (optional)                  │   │
│  │  - Certificate management (cert-manager)                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Layer 3: Authentication & Authorization                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - GitHub OAuth for user authentication                             │   │
│  │  - API keys for programmatic access                                 │   │
│  │  - RBAC (Role-Based Access Control)                                 │   │
│  │  - JWT tokens for session management                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Layer 4: Application Security                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Input validation and sanitization                                │   │
│  │  - SQL injection prevention (SQLAlchemy ORM)                        │   │
│  │  - XSS protection (template escaping)                               │   │
│  │  - CSRF protection (Flask-WTF)                                      │   │
│  │  - Rate limiting                                                     │   │
│  │  - Path traversal prevention                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Layer 5: Data Security                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Encryption at rest (volume encryption)                           │   │
│  │  - Encryption in transit (TLS)                                      │   │
│  │  - Secret management (Kubernetes Secrets / Vault)                   │   │
│  │  - Database encryption (PostgreSQL)                                 │   │
│  │  - API key hashing (bcrypt)                                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Layer 6: Container Security                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Non-root containers                                              │   │
│  │  - Read-only root filesystem                                        │   │
│  │  - Security contexts (securityContext)                              │   │
│  │  - Pod Security Standards (restricted)                              │   │
│  │  - Image scanning (Trivy / Clair)                                   │   │
│  │  - gVisor sandbox for patch validation                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Layer 7: Monitoring & Auditing                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Audit logs for all operations                                    │   │
│  │  - Security event monitoring                                        │   │
│  │  - Intrusion detection (Falco)                                      │   │
│  │  - Vulnerability scanning                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```


### Network Policies (Kubernetes)

#### Restrict Traffic to Application Pods
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
spec:
  podSelector:
    matchLabels:
      app: autovulrepair-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: ingress-controller
    ports:
    - protocol: TCP
      port: 5000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  - to:
    - podSelector:
        matchLabels:
          app: postgresql
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 443  # External APIs
```

#### Restrict Traffic to Redis
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: redis-network-policy
spec:
  podSelector:
    matchLabels:
      app: redis
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: autovulrepair-app
    - podSelector:
        matchLabels:
          app: celery-worker
    ports:
    - protocol: TCP
      port: 6379
```

---

### Security Best Practices

#### 1. **Container Security**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: autovulrepair:v1.0.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/.cache
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

#### 2. **Secret Management**
```yaml
# Using External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: FLASK_SECRET_KEY
    remoteRef:
      key: autovulrepair/flask-secret
  - secretKey: GITHUB_CLIENT_SECRET
    remoteRef:
      key: autovulrepair/github-oauth
  - secretKey: OPENAI_API_KEY
    remoteRef:
      key: autovulrepair/openai-key
```

#### 3. **Pod Security Standards**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: autovulrepair
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

---

## Deployment Strategies

### 1. **Rolling Update (Default)**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autovulrepair-app
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1        # Max 1 extra pod during update
      maxUnavailable: 0  # Always maintain availability
  template:
    # ... pod spec
```

**Process**:
1. Create 1 new pod with new version
2. Wait for new pod to be ready
3. Terminate 1 old pod
4. Repeat until all pods updated

**Advantages**:
- Zero downtime
- Gradual rollout
- Easy rollback

---

### 2. **Blue-Green Deployment**
```yaml
# Blue deployment (current)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autovulrepair-app-blue
  labels:
    version: blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: autovulrepair
      version: blue
  # ... pod spec

---
# Green deployment (new)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autovulrepair-app-green
  labels:
    version: green
spec:
  replicas: 3
  selector:
    matchLabels:
      app: autovulrepair
      version: green
  # ... pod spec with new version

---
# Service switches between blue and green
apiVersion: v1
kind: Service
metadata:
  name: autovulrepair-web
spec:
  selector:
    app: autovulrepair
    version: blue  # Switch to 'green' to deploy
  ports:
  - port: 80
    targetPort: 5000
```

**Process**:
1. Deploy green version alongside blue
2. Test green version
3. Switch service selector to green
4. Monitor for issues
5. Delete blue deployment if successful

**Advantages**:
- Instant rollback (switch selector back)
- Full testing before switch
- Zero downtime

---

### 3. **Canary Deployment**
```yaml
# Stable deployment (90% traffic)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autovulrepair-app-stable
spec:
  replicas: 9
  selector:
    matchLabels:
      app: autovulrepair
      track: stable
  # ... pod spec

---
# Canary deployment (10% traffic)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autovulrepair-app-canary
spec:
  replicas: 1
  selector:
    matchLabels:
      app: autovulrepair
      track: canary
  # ... pod spec with new version

---
# Service routes to both
apiVersion: v1
kind: Service
metadata:
  name: autovulrepair-web
spec:
  selector:
    app: autovulrepair  # Matches both stable and canary
  ports:
  - port: 80
    targetPort: 5000
```

**Process**:
1. Deploy canary with 10% traffic
2. Monitor metrics and errors
3. Gradually increase canary replicas
4. Decrease stable replicas
5. Eventually replace all stable with canary

**Advantages**:
- Gradual rollout with monitoring
- Minimal risk
- Real user testing

---

## Monitoring and Observability

### Monitoring Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Observability Stack                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Metrics (Prometheus)                             │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │  - Application metrics (scan success rate, patch rate)             │    │
│  │  - System metrics (CPU, memory, disk)                              │    │
│  │  - Container metrics (pod status, restarts)                        │    │
│  │  - Custom metrics (queue length, processing time)                  │    │
│  │                                                                      │    │
│  │  Exporters:                                                         │    │
│  │  - Node Exporter (host metrics)                                    │    │
│  │  - cAdvisor (container metrics)                                    │    │
│  │  - Redis Exporter (queue metrics)                                  │    │
│  │  - PostgreSQL Exporter (database metrics)                          │    │
│  │  - Custom Python exporter (application metrics)                    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Visualization (Grafana)                          │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │  Dashboards:                                                        │    │
│  │  - System Overview                                                  │    │
│  │  - Scan Performance                                                 │    │
│  │  - Fuzzing Metrics                                                  │    │
│  │  - Patch Success Rate                                               │    │
│  │  - Resource Utilization                                             │    │
│  │  - Error Rates                                                      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Logging (ELK / Loki)                             │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │  - Application logs (Flask, Celery)                                │    │
│  │  - Container logs (stdout/stderr)                                  │    │
│  │  - Audit logs (authentication, API calls)                          │    │
│  │  - Error logs (exceptions, failures)                               │    │
│  │                                                                      │    │
│  │  Stack:                                                             │    │
│  │  - Fluentd / Fluent Bit (log collection)                           │    │
│  │  - Elasticsearch / Loki (log storage)                              │    │
│  │  - Kibana / Grafana (log visualization)                            │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Tracing (Jaeger / Zipkin)                        │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │  - Request tracing across services                                 │    │
│  │  - Performance bottleneck identification                           │    │
│  │  - Dependency mapping                                               │    │
│  │  - Latency analysis                                                 │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Alerting (AlertManager)                          │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │  Alert Rules:                                                       │    │
│  │  - High error rate (> 5%)                                          │    │
│  │  - High response time (> 5s)                                       │    │
│  │  - Pod crash loop                                                   │    │
│  │  - Disk space low (< 10%)                                          │    │
│  │  - Database connection failures                                     │    │
│  │  - Queue backlog (> 100 tasks)                                     │    │
│  │                                                                      │    │
│  │  Notification Channels:                                             │    │
│  │  - Email                                                            │    │
│  │  - Slack                                                            │    │
│  │  - PagerDuty                                                        │    │
│  │  - Webhook                                                          │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Metrics to Monitor

#### Application Metrics
```python
# Custom Prometheus metrics in app.py
from prometheus_client import Counter, Histogram, Gauge

# Scan metrics
scan_total = Counter('autovulrepair_scans_total', 'Total scans', ['status'])
scan_duration = Histogram('autovulrepair_scan_duration_seconds', 'Scan duration')
scan_vulnerabilities = Histogram('autovulrepair_vulnerabilities_found', 'Vulnerabilities found')

# Fuzzing metrics
fuzz_targets = Gauge('autovulrepair_fuzz_targets', 'Active fuzz targets')
fuzz_crashes = Counter('autovulrepair_crashes_found', 'Crashes found', ['severity'])
fuzz_coverage = Gauge('autovulrepair_code_coverage', 'Code coverage percentage')

# Patch metrics
patch_generated = Counter('autovulrepair_patches_generated', 'Patches generated')
patch_compiled = Counter('autovulrepair_patches_compiled', 'Patches compiled successfully')
patch_validated = Counter('autovulrepair_patches_validated', 'Patches validated', ['status'])

# System metrics
celery_queue_length = Gauge('autovulrepair_celery_queue_length', 'Celery queue length')
celery_workers = Gauge('autovulrepair_celery_workers', 'Active Celery workers')
```

---

## Disaster Recovery

### Backup Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Backup Strategy                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Component 1: Database Backups                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Automated daily backups (pg_dump)                                │   │
│  │  - Point-in-time recovery (WAL archiving)                           │   │
│  │  - Retention: 30 days                                               │   │
│  │  - Storage: S3 / GCS / Azure Blob                                   │   │
│  │  - Encryption: AES-256                                              │   │
│  │  - Testing: Monthly restore tests                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Component 2: Scan Artifacts Backups                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Incremental backups (rsync / rclone)                             │   │
│  │  - Retention: 90 days                                               │   │
│  │  - Storage: Object storage (S3 / GCS)                               │   │
│  │  - Lifecycle policies: Archive to Glacier after 30 days            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Component 3: Configuration Backups                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Kubernetes manifests (Git repository)                            │   │
│  │  - ConfigMaps and Secrets (encrypted backups)                       │   │
│  │  - Infrastructure as Code (Terraform state)                         │   │
│  │  - Version control: Git                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  Component 4: Redis Backups                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - AOF (Append-Only File) persistence                               │   │
│  │  - RDB snapshots (hourly)                                           │   │
│  │  - Retention: 7 days                                                │   │
│  │  - Storage: Persistent volumes                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)

| Component | RTO | RPO | Recovery Strategy |
|-----------|-----|-----|-------------------|
| Application Pods | < 5 minutes | 0 (stateless) | Redeploy from registry |
| Database | < 30 minutes | < 1 hour | Restore from backup + WAL replay |
| Redis | < 10 minutes | < 1 hour | Restore from RDB snapshot |
| Scan Artifacts | < 2 hours | < 24 hours | Restore from object storage |
| Configuration | < 15 minutes | 0 | Redeploy from Git |

---

## Cost Optimization

### Resource Optimization Strategies

#### 1. **Right-Sizing**
```yaml
# Use VPA (Vertical Pod Autoscaler) for recommendations
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: app-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: autovulrepair-app
  updatePolicy:
    updateMode: "Auto"  # or "Recommend" for manual review
```

#### 2. **Spot Instances for Workers**
```yaml
# Use spot instances for Celery workers (interruptible workloads)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: celery-worker
spec:
  template:
    spec:
      nodeSelector:
        node.kubernetes.io/instance-type: spot
      tolerations:
      - key: "spot"
        operator: "Equal"
        value: "true"
        effect: "NoSchedule"
```

#### 3. **Storage Tiering**
- **Hot**: Recent scans (< 7 days) → SSD
- **Warm**: Recent scans (7-30 days) → Standard storage
- **Cold**: Old scans (> 30 days) → Archive storage (Glacier / Coldline)

#### 4. **Auto-Scaling Policies**
- Scale down during off-hours (nights, weekends)
- Scale up during peak hours (business hours)
- Use cluster autoscaler for node-level scaling

---

## Conclusion

This deployment and component architecture document provides:

✅ **Complete component breakdown** across all layers
✅ **Development and production deployment diagrams**
✅ **Container architecture** with Docker and Kubernetes
✅ **Network topology** for both environments
✅ **Infrastructure components** (storage, configuration, service mesh)
✅ **Scalability strategies** (HPA, HA configurations)
✅ **Security architecture** with multiple layers
✅ **Deployment strategies** (rolling, blue-green, canary)
✅ **Monitoring and observability** stack
✅ **Disaster recovery** and backup strategies
✅ **Cost optimization** recommendations

The architecture is designed to be:
- **Scalable**: Horizontal scaling for all components
- **Highly Available**: Redundancy at every layer
- **Secure**: Defense in depth with multiple security layers
- **Observable**: Comprehensive monitoring and logging
- **Cost-Effective**: Right-sized resources with optimization strategies
- **Maintainable**: Clear separation of concerns and modular design

This architecture supports the AutoVulRepair system from development through production deployment, ensuring reliability, security, and performance at scale.

