#!/usr/bin/env python3
"""Quick check of scan processing status"""

from src.services.scan_service import ScanService
from src.repositories.scan_repository import ScanRepository
from src.models.scan_v2 import DatabaseManager
import os

DATABASE_URL = 'postgresql://autovulrepair:autovulrepair_secure_password_2024@localhost:5432/autovulrepair'
db_manager = DatabaseManager(DATABASE_URL)
scan_repository = ScanRepository(db_manager, use_database=True)
scan_service = ScanService(scan_repository)

# Get recent scans
scans = scan_service.get_user_scans('test-user-1', limit=5)
print('Recent scan statuses:')
for scan in scans[:3]:
    print(f'  {scan["scan_id"][:8]}... -> {scan["status"]}')

# Check if any completed
completed = [s for s in scans if s['status'] == 'completed']
print(f'\nCompleted scans: {len(completed)}')

if completed:
    scan_id = completed[0]['scan_id']
    results = scan_service.get_scan_results(scan_id)
    print(f'Sample completed scan findings: {len(results.get("findings", []))}')