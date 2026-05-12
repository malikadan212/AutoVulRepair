# Comprehensive System Verification Checklist

## 1. Container Status
- [ ] Main app container running
- [ ] Worker-scan-1 running
- [ ] Worker-scan-2 running
- [ ] Worker-fuzz running
- [ ] Redis running
- [ ] PostgreSQL running

## 2. Docker Socket Access
- [ ] Main app has Docker socket mounted
- [ ] Worker-scan-1 has Docker socket mounted
- [ ] Worker-scan-2 has Docker socket mounted
- [ ] Worker-fuzz has Docker socket mounted
- [ ] Workers can actually connect to Docker daemon
- [ ] Workers can run Docker containers

## 3. Code Files Updated
- [ ] src/analysis/cppcheck.py (CWE mapping)
- [ ] src/services/scan_service.py (CWE extraction + fallback labeling)
- [ ] src/repositories/scan_repository.py (tool storage)
- [ ] src/models/scan_v2.py (tool extraction)
- [ ] src/utils/docker_helper.py (no --cwe flag)
- [ ] templates/detailed_findings.html (warning badges)

## 4. Code Files in Containers
- [ ] Main app has all updated files
- [ ] Worker-scan-1 has all updated files
- [ ] Worker-scan-2 has all updated files
- [ ] Worker-fuzz has all updated files

## 5. Celery Integration
- [ ] Celery detected as available in main app
- [ ] process_scan_task can be imported
- [ ] Workers are connected to Redis
- [ ] Workers can receive tasks
- [ ] Tasks are being queued to scan_queue

## 6. Cppcheck Functionality
- [ ] Cppcheck Docker image exists
- [ ] Workers can run Cppcheck via Docker
- [ ] Cppcheck produces XML output
- [ ] XML contains CWE IDs
- [ ] CWE IDs are extracted correctly
- [ ] CWE mapping fallback works

## 7. End-to-End Flow
- [ ] Web form submission creates scan
- [ ] Scan is queued to Celery
- [ ] Worker picks up task
- [ ] Worker runs real Cppcheck (not fallback)
- [ ] Results stored in database
- [ ] Results include CWE IDs
- [ ] Results include tool field
- [ ] JSON file created
- [ ] Web UI displays results correctly

## 8. Fallback Behavior
- [ ] Fallback triggers when Docker unavailable
- [ ] Fallback sets tool="Pattern-Based Fallback"
- [ ] Fallback sets confidence="low"
- [ ] Fallback sets analysis_method="pattern_matching"
- [ ] UI shows warning badges for fallback

## 9. No Regression
- [ ] Old scans still viewable
- [ ] Database migrations not needed
- [ ] Existing functionality preserved
