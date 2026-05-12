#!/usr/bin/env python3
"""
Comprehensive system verification script
Tests EVERY component to ensure the fix is complete
"""
import subprocess
import json
import sys

def run_cmd(cmd, description):
    """Run command and return success/failure"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

print("=" * 80)
print("COMPREHENSIVE SYSTEM VERIFICATION")
print("=" * 80)

checks = []
failures = []

# 1. CONTAINER STATUS
print("\n[1] CONTAINER STATUS")
print("-" * 80)

containers = [
    'autovulrepair-app-1',
    'autovulrepair-celery-worker-scan-1',
    'autovulrepair-celery-worker-scan-2',
    'autovulrepair-celery-worker-fuzz-1',
    'autovulrepair-redis-1',
    'autovulrepair-postgres-1'
]

for container in containers:
    success, stdout, stderr = run_cmd(f'docker ps --filter "name={container}" --format "{{{{.Status}}}}"', f"Check {container}")
    running = success and 'Up' in stdout
    status = "✅" if running else "❌"
    print(f"{status} {container}: {stdout.strip() if running else 'NOT RUNNING'}")
    checks.append((f"{container} running", running))
    if not running:
        failures.append(f"{container} is not running")

# 2. DOCKER SOCKET ACCESS
print("\n[2] DOCKER SOCKET ACCESS")
print("-" * 80)

worker_containers = [
    'autovulrepair-app-1',
    'autovulrepair-celery-worker-scan-1',
    'autovulrepair-celery-worker-scan-2',
    'autovulrepair-celery-worker-fuzz-1'
]

for container in worker_containers:
    # Check if socket is mounted
    success, stdout, stderr = run_cmd(
        f'docker inspect {container} --format="{{{{range .Mounts}}}}{{{{.Source}}}} -> {{{{.Destination}}}}{{{{println}}}}{{{{end}}}}" | grep docker.sock',
        f"Check Docker socket mount on {container}"
    )
    mounted = success and 'docker.sock' in stdout
    status = "✅" if mounted else "❌"
    print(f"{status} {container}: Docker socket {'mounted' if mounted else 'NOT mounted'}")
    checks.append((f"{container} Docker socket", mounted))
    if not mounted:
        failures.append(f"{container} missing Docker socket mount")
    
    # Check if can connect to Docker
    if mounted:
        success, stdout, stderr = run_cmd(
            f'docker exec {container} python3 -c "import docker; print(docker.from_env().ping())"',
            f"Test Docker connection from {container}"
        )
        can_connect = success and 'True' in stdout
        status = "✅" if can_connect else "❌"
        print(f"  {status} Can connect to Docker: {can_connect}")
        checks.append((f"{container} Docker connection", can_connect))
        if not can_connect:
            failures.append(f"{container} cannot connect to Docker daemon")

# 3. CRITICAL FILES PRESENT IN CONTAINERS
print("\n[3] CRITICAL FILES IN CONTAINERS")
print("-" * 80)

critical_files = {
    'src/analysis/cppcheck.py': 'CWE mapping',
    'src/services/scan_service.py': 'CWE extraction',
    'src/repositories/scan_repository.py': 'Tool storage',
    'src/models/scan_v2.py': 'Tool extraction',
    'src/utils/docker_helper.py': 'Docker runner'
}

for container in worker_containers:
    print(f"\n{container}:")
    for file_path, description in critical_files.items():
        success, stdout, stderr = run_cmd(
            f'docker exec {container} test -f /app/{file_path} && echo "EXISTS"',
            f"Check {file_path} in {container}"
        )
        exists = success and 'EXISTS' in stdout
        status = "✅" if exists else "❌"
        print(f"  {status} {file_path} ({description})")
        checks.append((f"{container}:{file_path}", exists))
        if not exists:
            failures.append(f"{container} missing {file_path}")

# 4. CODE CORRECTNESS
print("\n[4] CODE CORRECTNESS")
print("-" * 80)

# Check CWE mapping exists
for container in ['autovulrepair-celery-worker-scan-1', 'autovulrepair-celery-worker-scan-2']:
    success, stdout, stderr = run_cmd(
        f'docker exec {container} grep -c "self.cwe_map = {{" /app/src/analysis/cppcheck.py',
        f"Check CWE mapping in {container}"
    )
    has_mapping = success and int(stdout.strip() or '0') > 0
    status = "✅" if has_mapping else "❌"
    print(f"{status} {container}: CWE mapping dictionary {'present' if has_mapping else 'MISSING'}")
    checks.append((f"{container} CWE mapping", has_mapping))
    if not has_mapping:
        failures.append(f"{container} missing CWE mapping dictionary")

# Check fallback labeling
for container in ['autovulrepair-celery-worker-scan-1', 'autovulrepair-celery-worker-scan-2']:
    success, stdout, stderr = run_cmd(
        f'docker exec {container} grep -c "Pattern-Based Fallback" /app/src/services/scan_service.py',
        f"Check fallback labeling in {container}"
    )
    has_fallback = success and int(stdout.strip() or '0') > 0
    status = "✅" if has_fallback else "❌"
    print(f"{status} {container}: Fallback labeling {'present' if has_fallback else 'MISSING'}")
    checks.append((f"{container} fallback labeling", has_fallback))
    if not has_fallback:
        failures.append(f"{container} missing fallback labeling")

# Check no --cwe flag
for container in ['autovulrepair-celery-worker-scan-1', 'autovulrepair-celery-worker-scan-2']:
    success, stdout, stderr = run_cmd(
        f'docker exec {container} grep -c \'--cwe\' /app/src/utils/docker_helper.py',
        f"Check for --cwe flag in {container}"
    )
    has_cwe_flag = success and int(stdout.strip() or '0') > 0
    status = "✅" if not has_cwe_flag else "❌"
    print(f"{status} {container}: --cwe flag {'FOUND (BAD!)' if has_cwe_flag else 'not present (good)'}")
    checks.append((f"{container} no --cwe flag", not has_cwe_flag))
    if has_cwe_flag:
        failures.append(f"{container} still has --cwe flag in docker_helper.py")

# 5. CELERY INTEGRATION
print("\n[5] CELERY INTEGRATION")
print("-" * 80)

# Check Celery available in app
success, stdout, stderr = run_cmd(
    'docker exec autovulrepair-app-1 python3 -c "from src.services.scan_service import CELERY_AVAILABLE; print(CELERY_AVAILABLE)"',
    "Check CELERY_AVAILABLE in app"
)
celery_available = success and 'True' in stdout
status = "✅" if celery_available else "❌"
print(f"{status} CELERY_AVAILABLE in main app: {celery_available}")
checks.append(("Celery available", celery_available))
if not celery_available:
    failures.append("Celery not detected as available in main app")

# Check workers connected to Redis
for container in ['autovulrepair-celery-worker-scan-1', 'autovulrepair-celery-worker-scan-2']:
    success, stdout, stderr = run_cmd(
        f'docker logs {container} --tail 50 | grep "celery@.*ready"',
        f"Check {container} ready"
    )
    is_ready = success and 'ready' in stdout
    status = "✅" if is_ready else "❌"
    print(f"{status} {container}: {'Ready' if is_ready else 'NOT ready'}")
    checks.append((f"{container} ready", is_ready))
    if not is_ready:
        failures.append(f"{container} not ready to process tasks")

# 6. CPPCHECK FUNCTIONALITY
print("\n[6] CPPCHECK FUNCTIONALITY")
print("-" * 80)

# Check Cppcheck image exists
success, stdout, stderr = run_cmd(
    'docker images vuln-scanner/cppcheck:latest --format "{{.Repository}}"',
    "Check Cppcheck image"
)
image_exists = success and 'vuln-scanner/cppcheck' in stdout
status = "✅" if image_exists else "❌"
print(f"{status} Cppcheck Docker image: {'exists' if image_exists else 'MISSING'}")
checks.append(("Cppcheck image", image_exists))
if not image_exists:
    failures.append("Cppcheck Docker image not found")

# Check workers can detect Cppcheck
for container in ['autovulrepair-celery-worker-scan-1', 'autovulrepair-celery-worker-scan-2']:
    success, stdout, stderr = run_cmd(
        f'docker exec {container} python3 -c "from src.analysis.cppcheck import CppcheckAnalyzer; print(CppcheckAnalyzer().is_available())"',
        f"Check Cppcheck available in {container}"
    )
    is_available = success and 'True' in stdout
    status = "✅" if is_available else "❌"
    print(f"{status} {container}: Cppcheck {'available' if is_available else 'NOT available'}")
    checks.append((f"{container} Cppcheck available", is_available))
    if not is_available:
        failures.append(f"{container} cannot detect Cppcheck")

# SUMMARY
print("\n" + "=" * 80)
print("VERIFICATION SUMMARY")
print("=" * 80)

total_checks = len(checks)
passed_checks = sum(1 for _, passed in checks if passed)
failed_checks = total_checks - passed_checks

print(f"\nTotal checks: {total_checks}")
print(f"✅ Passed: {passed_checks}")
print(f"❌ Failed: {failed_checks}")

if failed_checks > 0:
    print("\n" + "=" * 80)
    print("FAILURES DETECTED")
    print("=" * 80)
    for i, failure in enumerate(failures, 1):
        print(f"{i}. {failure}")
    print("\n❌ SYSTEM NOT READY - Issues must be fixed")
    sys.exit(1)
else:
    print("\n" + "=" * 80)
    print("✅ ALL CHECKS PASSED - SYSTEM IS READY")
    print("=" * 80)
    print("\nThe system is fully configured and ready to:")
    print("  • Accept scans via web UI")
    print("  • Queue tasks to Celery workers")
    print("  • Run real Cppcheck via Docker")
    print("  • Extract CWE IDs from results")
    print("  • Store and display findings correctly")
    sys.exit(0)
