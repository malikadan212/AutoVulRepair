"""
Repository layer for scan data access
This provides a clean interface that can work with both file system and database
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timedelta
import os
import json
import hashlib
from pathlib import Path

from src.models.scan_v2 import (
    DatabaseManager, ScanV2, ScanSource, StaticFinding, FuzzPlan, FuzzTarget,
    HarnessFile, FuzzCampaign, FuzzExecution, CrashArtifact, RepairPatch, JobQueue
)
from src.models.scan import Scan, get_session  # Legacy models
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_


class ScanRepository:
    """
    Repository for scan data - supports both legacy file system and new database
    """
    
    def __init__(self, db_manager: DatabaseManager, use_database: bool = True):
        self.db_manager = db_manager
        self.use_database = use_database
        self.scans_dir = os.getenv('SCANS_DIR', './scans')
    
    # ============================================================================
    # Scan Management
    # ============================================================================
    
    def create_scan(self, scan_data: Dict[str, Any]) -> str:
        """
        Create a new scan
        Returns: scan_id
        """
        if self.use_database:
            return self._create_scan_db(scan_data)
        else:
            return self._create_scan_legacy(scan_data)
    
    def _create_scan_db(self, scan_data: Dict[str, Any]) -> str:
        """Create scan in database"""
        session = self.db_manager.get_session()
        try:
            scan = ScanV2(
                scan_id=scan_data['scan_id'],
                user_id=scan_data.get('user_id'),
                repo_url=scan_data.get('repo_url'),
                source_type=scan_data['source_type'],
                analysis_tool=scan_data.get('analysis_tool', 'cppcheck'),
                status='queued',
                metadata_json=scan_data.get('metadata', {})
            )
            session.add(scan)
            session.commit()
            return scan.scan_id
        finally:
            session.close()
    
    def _create_scan_legacy(self, scan_data: Dict[str, Any]) -> str:
        """Create scan using legacy file system"""
        # Use existing legacy code
        session = get_session()
        try:
            scan = Scan(
                id=scan_data['scan_id'],
                repo_url=scan_data.get('repo_url', 'unknown'),
                source_type=scan_data['source_type'],
                analysis_tool=scan_data.get('analysis_tool', 'cppcheck'),
                status='queued'
            )
            session.add(scan)
            session.commit()
            return scan.id
        finally:
            session.close()
    
    def get_scans_by_user(self, user_id: str, limit: int = None) -> List[Dict[str, Any]]:
        """Get all scans for a specific user"""
        if self.use_database:
            return self._get_scans_by_user_db(user_id, limit)
        else:
            return self._get_scans_by_user_legacy(user_id, limit)
    
    def _get_scans_by_user_db(self, user_id: str, limit: int = None) -> List[Dict[str, Any]]:
        """Get scans by user from database"""
        session = self.db_manager.get_session()
        try:
            query = session.query(ScanV2).filter(ScanV2.user_id == user_id).order_by(desc(ScanV2.created_at))
            if limit:
                query = query.limit(limit)
            scans = query.all()
            return [scan.to_dict() for scan in scans]
        finally:
            session.close()
    
    def _get_scans_by_user_legacy(self, user_id: str, limit: int = None) -> List[Dict[str, Any]]:
        """Get scans by user from legacy system"""
        session = get_session()
        try:
            query = session.query(Scan).filter(Scan.user_id == user_id).order_by(desc(Scan.created_at))
            if limit:
                query = query.limit(limit)
            scans = query.all()
            return [{
                'scan_id': scan.id,
                'user_id': scan.user_id,
                'repo_url': scan.repo_url,
                'source_type': scan.source_type,
                'analysis_tool': scan.analysis_tool,
                'status': scan.status,
                'created_at': scan.created_at.isoformat() if scan.created_at else None
            } for scan in scans]
        finally:
            session.close()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan by ID"""
        if self.use_database:
            return self._get_scan_db(scan_id)
        else:
            return self._get_scan_legacy(scan_id)
    
    def _get_scan_db(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan from database"""
        session = self.db_manager.get_session()
        try:
            scan = session.query(ScanV2).filter(ScanV2.scan_id == scan_id).first()
            return scan.to_dict() if scan else None
        finally:
            session.close()
    
    def _get_scan_legacy(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan from legacy system"""
        session = get_session()
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                return {
                    'scan_id': scan.id,
                    'repo_url': scan.repo_url,
                    'source_type': scan.source_type,
                    'analysis_tool': scan.analysis_tool,
                    'status': scan.status,
                    'created_at': scan.created_at.isoformat() if scan.created_at else None
                }
            return None
        finally:
            session.close()
    
    def update_scan_status(self, scan_id: str, status: str, error_message: str = None) -> bool:
        """Update scan status"""
        if self.use_database:
            return self._update_scan_status_db(scan_id, status, error_message)
        else:
            return self._update_scan_status_legacy(scan_id, status, error_message)
    
    def _update_scan_status_db(self, scan_id: str, status: str, error_message: str = None) -> bool:
        """Update scan status in database"""
        session = self.db_manager.get_session()
        try:
            scan = session.query(ScanV2).filter(ScanV2.scan_id == scan_id).first()
            if scan:
                scan.status = status
                if error_message:
                    scan.error_message = error_message
                if status == 'processing' and not scan.started_at:
                    scan.started_at = datetime.utcnow()
                elif status in ['completed', 'failed']:
                    scan.completed_at = datetime.utcnow()
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    def _update_scan_status_legacy(self, scan_id: str, status: str, error_message: str = None) -> bool:
        """Update scan status in legacy system"""
        session = get_session()
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    # ============================================================================
    # Source Code Management
    # ============================================================================
    
    def store_source_files(self, scan_id: str, files: List[Dict[str, Any]]) -> bool:
        """
        Store source files for a scan
        files: [{'path': str, 'content': str}, ...]
        """
        if self.use_database:
            success = self._store_source_files_db(scan_id, files)
            # CRITICAL FIX: Also create legacy source directory for compatibility
            if success:
                self._create_legacy_source_directory(scan_id, files)
            return success
        else:
            return self._store_source_files_legacy(scan_id, files)
    
    def _create_legacy_source_directory(self, scan_id: str, files: List[Dict[str, Any]]) -> bool:
        """Create legacy source directory structure for compatibility with existing modules"""
        try:
            legacy_scan_dir = os.path.join(self.scans_dir, scan_id)
            source_dir = os.path.join(legacy_scan_dir, 'source')
            os.makedirs(source_dir, exist_ok=True)
            
            for file_data in files:
                file_path = os.path.join(source_dir, file_data['path'])
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_data['content'])
            
            return True
        except Exception as e:
            print(f"Error creating legacy source directory: {e}")
            return False
    
    def _store_source_files_db(self, scan_id: str, files: List[Dict[str, Any]]) -> bool:
        """Store source files in database"""
        session = self.db_manager.get_session()
        try:
            for file_data in files:
                content = file_data['content']
                file_hash = hashlib.sha256(content.encode()).hexdigest()
                
                source = ScanSource(
                    scan_id=scan_id,
                    file_path=file_data['path'],
                    file_content=content,
                    file_size=len(content),
                    file_hash=file_hash
                )
                session.add(source)
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error storing source files: {e}")
            return False
        finally:
            session.close()
    
    def _store_source_files_legacy(self, scan_id: str, files: List[Dict[str, Any]]) -> bool:
        """Store source files using legacy file system"""
        try:
            scan_dir = os.path.join(self.scans_dir, scan_id, 'source')
            os.makedirs(scan_dir, exist_ok=True)
            
            for file_data in files:
                file_path = os.path.join(scan_dir, file_data['path'])
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_data['content'])
            
            return True
        except Exception as e:
            print(f"Error storing source files: {e}")
            return False
    
    def get_source_files(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get source files for a scan"""
        if self.use_database:
            return self._get_source_files_db(scan_id)
        else:
            return self._get_source_files_legacy(scan_id)
    
    def _get_source_files_db(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get source files from database"""
        session = self.db_manager.get_session()
        try:
            sources = session.query(ScanSource).filter(ScanSource.scan_id == scan_id).all()
            return [source.to_dict() for source in sources]
        finally:
            session.close()
    
    def _get_source_files_legacy(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get source files from legacy file system"""
        files = []
        scan_dir = os.path.join(self.scans_dir, scan_id, 'source')
        
        if not os.path.exists(scan_dir):
            return files
        
        for root, _, filenames in os.walk(scan_dir):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, scan_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    files.append({
                        'file_path': rel_path,
                        'file_size': len(content),
                        'file_hash': hashlib.sha256(content.encode()).hexdigest()
                    })
                except Exception:
                    continue
        
        return files
    
    # ============================================================================
    # Static Analysis Results
    # ============================================================================
    
    def store_static_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Store static analysis findings"""
        if self.use_database:
            success = self._store_static_findings_db(scan_id, findings)
            # CRITICAL FIX: Also create legacy static_findings.json for compatibility
            if success:
                self._create_legacy_static_findings_file(scan_id, findings)
            return success
        else:
            return self._store_static_findings_legacy(scan_id, findings)
    
    def _create_legacy_static_findings_file(self, scan_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Create legacy static_findings.json file for compatibility with existing modules"""
        try:
            legacy_scan_dir = os.path.join(self.scans_dir, scan_id)
            os.makedirs(legacy_scan_dir, exist_ok=True)
            
            findings_data = {
                'version': '1.0',
                'generated_at': datetime.now().isoformat(),
                'tool': 'database_stored',
                'total_findings': len(findings),
                'findings': findings,
                'metadata': {
                    'storage_type': 'database_with_legacy_compat',
                    'note': 'Data is stored in database but this file is maintained for compatibility'
                }
            }
            
            with open(os.path.join(legacy_scan_dir, 'static_findings.json'), 'w') as f:
                json.dump(findings_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error creating legacy static findings file: {e}")
            return False
    
    def _store_static_findings_db(self, scan_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Store static findings in database with automatic false positive detection"""
        session = self.db_manager.get_session()
        try:
            # First, store all findings
            for finding_data in findings:
                # Store tool and analysis_method in metadata
                metadata = finding_data.get('metadata_json', {})
                if 'tool' not in metadata and 'tool' in finding_data:
                    metadata['tool'] = finding_data.get('tool')
                if 'analysis_method' not in metadata and 'analysis_method' in finding_data:
                    metadata['analysis_method'] = finding_data.get('analysis_method')
                
                finding = StaticFinding(
                    scan_id=scan_id,
                    rule_id=finding_data.get('rule_id', 'unknown'),
                    severity=finding_data.get('severity', 'medium'),
                    confidence=finding_data.get('confidence', 'medium'),
                    file_path=finding_data.get('file', ''),
                    line_number=finding_data.get('line', 0),
                    column_number=finding_data.get('column', 0),
                    function_name=finding_data.get('function'),
                    message=finding_data.get('message', ''),
                    description=finding_data.get('description'),
                    cwe=finding_data.get('cwe'),
                    cvss_score=finding_data.get('cvss_score'),
                    exploitability_score=finding_data.get('exploitability_score'),
                    metadata_json=metadata
                )
                session.add(finding)
            
            session.commit()
            
            # Now run automatic false positive detection
            try:
                self._detect_false_positives_automatically(scan_id, session)
            except Exception as fp_error:
                print(f"Warning: False positive detection failed: {fp_error}")
                # Don't fail the whole operation if FP detection fails
            
            return True
        except Exception as e:
            session.rollback()
            print(f"Error storing static findings: {e}")
            return False
        finally:
            session.close()
    
    def _detect_false_positives_automatically(self, scan_id: str, session):
        """Automatically detect false positives after storing findings"""
        try:
            import sys
            import os
            # Ensure /app is in the path for worker processes
            app_path = '/app'
            if app_path not in sys.path and os.path.exists(app_path):
                sys.path.insert(0, app_path)
            
            from src.analysis.false_positive_detector import FalsePositiveDetector
            from sqlalchemy.orm.attributes import flag_modified
        except ImportError as e:
            print(f"[AUTO-FP] Failed to import FalsePositiveDetector: {e}")
            print(f"[AUTO-FP] sys.path: {sys.path}")
            return  # Skip false positive detection if import fails
        
        print(f"[AUTO-FP] Running automatic false positive detection for scan {scan_id}")
        
        # Get all findings for this scan
        findings = session.query(StaticFinding).filter(StaticFinding.scan_id == scan_id).all()
        
        # Get source files
        source_files = {}
        sources = session.query(ScanSource).filter(ScanSource.scan_id == scan_id).all()
        for source in sources:
            source_files[source.file_path] = source.file_content
        
        # Run detection
        detector = FalsePositiveDetector()
        fp_count = 0
        
        for finding in findings:
            # Get source code for this file
            source_code = source_files.get(finding.file_path, '')
            
            # Get the actual line content
            if source_code and finding.line_number > 0:
                lines = source_code.split('\n')
                if finding.line_number <= len(lines):
                    line_content = lines[finding.line_number - 1]
                else:
                    line_content = finding.message
            else:
                line_content = finding.message
            
            # Debug logging for CWE-561 findings
            if finding.cwe == 'CWE-561':
                print(f"[AUTO-FP] Checking CWE-561 finding:")
                print(f"  - file_path: {finding.file_path}")
                print(f"  - message: {finding.message}")
                print(f"  - line_content: {line_content[:100]}")
                print(f"  - rule_id: {finding.rule_id}")
            
            # Check if it's a false positive
            fp_result = detector.is_false_positive(
                line_content=line_content,
                rule_id=finding.rule_id,
                cwe=finding.cwe or '',
                source_code=source_code,
                line_number=finding.line_number,
                file_path=finding.file_path,
                message=finding.message
            )
            
            # Update finding with false positive info
            if fp_result['is_false_positive']:
                metadata = dict(finding.metadata_json) if finding.metadata_json else {}
                metadata['is_false_positive'] = True
                metadata['false_positive_reason'] = fp_result['reason']
                metadata['false_positive_confidence'] = fp_result['confidence']
                metadata['false_positive_category'] = fp_result['category']
                
                finding.metadata_json = metadata
                flag_modified(finding, 'metadata_json')
                fp_count += 1
        
        session.commit()
        print(f"[AUTO-FP] Detected {fp_count} false positives out of {len(findings)} findings")

    
    def _store_static_findings_legacy(self, scan_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Store static findings using legacy file system"""
        try:
            scan_dir = os.path.join(self.scans_dir, scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            
            findings_data = {
                'total_findings': len(findings),
                'findings': findings
            }
            
            with open(os.path.join(scan_dir, 'static_findings.json'), 'w') as f:
                json.dump(findings_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error storing static findings: {e}")
            return False
    
    def get_static_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get static analysis findings"""
        if self.use_database:
            return self._get_static_findings_db(scan_id)
        else:
            return self._get_static_findings_legacy(scan_id)
    
    def _get_static_findings_db(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get static findings from database"""
        session = self.db_manager.get_session()
        try:
            findings = session.query(StaticFinding).filter(StaticFinding.scan_id == scan_id).all()
            return [finding.to_dict() for finding in findings]
        finally:
            session.close()
    
    def _get_static_findings_legacy(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get static findings from legacy file system"""
        findings_file = os.path.join(self.scans_dir, scan_id, 'static_findings.json')
        
        if not os.path.exists(findings_file):
            return []
        
        try:
            with open(findings_file, 'r') as f:
                data = json.load(f)
            return data.get('findings', [])
        except Exception:
            return []
    
    # ============================================================================
    # Job Queue Management
    # ============================================================================
    
    def enqueue_job(self, job_type: str, scan_id: str, payload: Dict[str, Any], priority: int = 5) -> str:
        """Enqueue a background job"""
        if not self.use_database:
            # For legacy mode, execute immediately (no queue)
            return "immediate"
        
        session = self.db_manager.get_session()
        try:
            job = JobQueue(
                job_type=job_type,
                scan_id=scan_id,
                priority=priority,
                payload=payload
            )
            session.add(job)
            session.commit()
            return str(job.id)
        finally:
            session.close()
    
    def get_next_job(self) -> Optional[Dict[str, Any]]:
        """Get next job from queue"""
        if not self.use_database:
            return None
        
        session = self.db_manager.get_session()
        try:
            job = session.query(JobQueue).filter(
                JobQueue.status == 'queued'
            ).order_by(
                desc(JobQueue.priority),
                JobQueue.created_at
            ).first()
            
            if job:
                job.status = 'processing'
                job.started_at = datetime.utcnow()
                job.attempts += 1
                session.commit()
                return job.to_dict()
            
            return None
        finally:
            session.close()
    
    def complete_job(self, job_id: str, result: Dict[str, Any] = None, error: str = None) -> bool:
        """Mark job as completed or failed"""
        if not self.use_database:
            return True
        
        session = self.db_manager.get_session()
        try:
            job = session.query(JobQueue).filter(JobQueue.id == job_id).first()
            if job:
                job.status = 'completed' if error is None else 'failed'
                job.completed_at = datetime.utcnow()
                job.result = result
                job.error_message = error
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    # ============================================================================
    # Cleanup and Maintenance
    # ============================================================================
    
    def cleanup_old_scans(self, older_than_days: int = 30) -> int:
        """Clean up old scan data"""
        if self.use_database:
            return self._cleanup_old_scans_db(older_than_days)
        else:
            return self._cleanup_old_scans_legacy(older_than_days)
    
    def _cleanup_old_scans_db(self, older_than_days: int) -> int:
        """Clean up old scans from database"""
        cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
        session = self.db_manager.get_session()
        try:
            # Delete old completed scans
            deleted = session.query(ScanV2).filter(
                and_(
                    ScanV2.status.in_(['completed', 'failed']),
                    ScanV2.created_at < cutoff_date
                )
            ).delete()
            
            session.commit()
            return deleted
        finally:
            session.close()
    
    def _cleanup_old_scans_legacy(self, older_than_days: int) -> int:
        """Clean up old scans from file system"""
        cutoff_time = datetime.utcnow() - timedelta(days=older_than_days)
        deleted_count = 0
        
        if not os.path.exists(self.scans_dir):
            return 0
        
        for scan_id in os.listdir(self.scans_dir):
            scan_path = os.path.join(self.scans_dir, scan_id)
            if os.path.isdir(scan_path):
                # Check modification time
                mod_time = datetime.fromtimestamp(os.path.getmtime(scan_path))
                if mod_time < cutoff_time:
                    try:
                        import shutil
                        shutil.rmtree(scan_path)
                        deleted_count += 1
                    except Exception:
                        continue
        
        return deleted_count
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        if self.use_database:
            return self._get_storage_stats_db()
        else:
            return self._get_storage_stats_legacy()
    
    def _get_storage_stats_db(self) -> Dict[str, Any]:
        """Get storage stats from database"""
        session = self.db_manager.get_session()
        try:
            total_scans = session.query(ScanV2).count()
            active_scans = session.query(ScanV2).filter(
                ScanV2.status.in_(['queued', 'processing'])
            ).count()
            completed_scans = session.query(ScanV2).filter(
                ScanV2.status == 'completed'
            ).count()
            failed_scans = session.query(ScanV2).filter(
                ScanV2.status == 'failed'
            ).count()
            
            return {
                'total_scans': total_scans,
                'active_scans': active_scans,
                'completed_scans': completed_scans,
                'failed_scans': failed_scans,
                'storage_type': 'database'
            }
        finally:
            session.close()
    
    def _get_storage_stats_legacy(self) -> Dict[str, Any]:
        """Get storage stats from file system"""
        if not os.path.exists(self.scans_dir):
            return {'total_scans': 0, 'storage_type': 'filesystem'}
        
        scan_dirs = [d for d in os.listdir(self.scans_dir) 
                    if os.path.isdir(os.path.join(self.scans_dir, d))]
        
        total_size = 0
        for scan_dir in scan_dirs:
            scan_path = os.path.join(self.scans_dir, scan_dir)
            for root, dirs, files in os.walk(scan_path):
                for file in files:
                    try:
                        total_size += os.path.getsize(os.path.join(root, file))
                    except Exception:
                        continue
        
        return {
            'total_scans': len(scan_dirs),
            'total_size_mb': total_size / (1024 * 1024),
            'storage_type': 'filesystem'
        }