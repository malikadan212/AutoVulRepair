rom src.models.scan_v2 import ScanV2, RepairPatch, DatabaseManager
from src.config.database import get_secure_database_url

db_manager = DatabaseManager(get_secure_database_url())
session = db_manager.get_session()

# Check the scan with patches
patch_scan_id = '2de128ea-1484-4155-b6fd-6d63ec9e30b8'
scan = session.query(ScanV2).filter_by(scan_id=patch_scan_id).first()

print(f'Scan exists: {scan is not None}')
if scan:
    print(f'Scan status: {scan.status}')
    print(f'Created: {scan.created_at}')
    print(f'Repo URL: {scan.repo_url}')

patch_count = session.query(RepairPatch).filter_by(scan_id=patch_scan_id).count()
print(f'\nPatches for this scan: {patch_count}')

# Check the most recent scan
recent_scan = session.query(ScanV2).order_by(ScanV2.created_at.desc()).first()
print(f'\nMost recent scan ID: {recent_scan.scan_id}')
print(f'Most recent scan status: {recent_scan.status}')
print(f'Most recent scan repo: {recent_scan.repo_url}')

recent_patch_count = session.query(RepairPatch).filter_by(scan_id=recent_scan.scan_id).count()
print(f'Patches for most recent scan: {recent_patch_count}')
