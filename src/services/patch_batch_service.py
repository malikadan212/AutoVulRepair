"""
Patch Batch Service
Manages coordinated application of Stage 1 + Stage 2 patches
"""
import logging
import os
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid

from src.database import get_db_connection

logger = logging.getLogger(__name__)


class PatchBatchService:
    """Manages patch batches for coordinated application"""
    
    def __init__(self):
        self.conn = get_db_connection()
    
    def create_batch(self, scan_id: str, stage1_vuln_count: int = 0, stage2_vuln_count: int = 0) -> Dict[str, Any]:
        """
        Create a new patch batch for a scan
        
        Args:
            scan_id: Scan ID
            stage1_vuln_count: Number of Stage 1 vulnerabilities
            stage2_vuln_count: Number of Stage 2 vulnerabilities
            
        Returns:
            Batch dict
        """
        batch_id = str(uuid.uuid4())
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO patch_batches (
                id, scan_id, status, 
                stage1_vulnerabilities_count, stage2_vulnerabilities_count,
                created_at
            )
            VALUES (%s, %s, 'generating', %s, %s, NOW())
            RETURNING id, scan_id, status, created_at
        """, (batch_id, scan_id, stage1_vuln_count, stage2_vuln_count))
        
        result = cursor.fetchone()
        self.conn.commit()
        
        batch = {
            'id': result[0],
            'scan_id': result[1],
            'status': result[2],
            'created_at': result[3]
        }
        
        logger.info(f"Created patch batch {batch_id} for scan {scan_id} "
                   f"(Stage 1: {stage1_vuln_count} vulns, Stage 2: {stage2_vuln_count} vulns)")
        return batch
    
    def get_or_create_batch(self, scan_id: str, stage1_vuln_count: int = 0, stage2_vuln_count: int = 0) -> Dict[str, Any]:
        """Get existing batch or create new one"""
        batch = self.get_batch_by_scan(scan_id)
        if batch:
            return batch
        return self.create_batch(scan_id, stage1_vuln_count, stage2_vuln_count)
    
    def mark_stage1_complete(self, batch_id: str, patch_count: int):
        """
        Mark Stage 1 as complete
        
        Args:
            batch_id: Batch ID
            patch_count: Number of patches generated
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE patch_batches
            SET stage1_complete = TRUE,
                stage1_patches_count = %s,
                stage1_completed_at = NOW()
            WHERE id = %s
        """, (patch_count, batch_id))
        self.conn.commit()
        
        logger.info(f"Batch {batch_id}: Stage 1 complete ({patch_count} patches)")
        
        # Check if both stages are complete
        self._check_and_mark_ready(batch_id)
    
    def mark_stage2_complete(self, batch_id: str, patch_count: int):
        """
        Mark Stage 2 as complete
        
        Args:
            batch_id: Batch ID
            patch_count: Number of patches generated
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE patch_batches
            SET stage2_complete = TRUE,
                stage2_patches_count = %s,
                stage2_completed_at = NOW()
            WHERE id = %s
        """, (patch_count, batch_id))
        self.conn.commit()
        
        logger.info(f"Batch {batch_id}: Stage 2 complete ({patch_count} patches)")
        
        # Check if both stages are complete
        self._check_and_mark_ready(batch_id)
    
    def _check_and_mark_ready(self, batch_id: str):
        """Check if both stages are complete and mark batch as ready"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT stage1_complete, stage2_complete, stage2_vulnerabilities_count
            FROM patch_batches
            WHERE id = %s
        """, (batch_id,))
        
        result = cursor.fetchone()
        if not result:
            return
        
        stage1_complete, stage2_complete, stage2_vuln_count = result
        
        # If no Stage 2 vulnerabilities, mark Stage 2 as complete automatically
        if stage2_vuln_count == 0 and not stage2_complete:
            cursor.execute("""
                UPDATE patch_batches
                SET stage2_complete = TRUE,
                    stage2_completed_at = NOW()
                WHERE id = %s
            """, (batch_id,))
            stage2_complete = True
        
        # If both stages complete, mark batch as ready
        if stage1_complete and stage2_complete:
            cursor.execute("""
                UPDATE patch_batches
                SET status = 'ready'
                WHERE id = %s
            """, (batch_id,))
            self.conn.commit()
            
            logger.info(f"Batch {batch_id}: All patches ready!")
            
            # TODO: Send notification to user
            # self._notify_batch_ready(batch_id)
    
    def get_batch_by_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get batch by scan ID"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, scan_id, status,
                   stage1_complete, stage2_complete,
                   stage1_patches_count, stage2_patches_count, total_patches_count,
                   stage1_vulnerabilities_count, stage2_vulnerabilities_count,
                   created_at, stage1_completed_at, stage2_completed_at, applied_at,
                   applied_by, commit_sha, pr_url, branch_name
            FROM patch_batches
            WHERE scan_id = %s
        """, (scan_id,))
        
        result = cursor.fetchone()
        if not result:
            return None
        
        return {
            'id': result[0],
            'scan_id': result[1],
            'status': result[2],
            'stage1_complete': result[3],
            'stage2_complete': result[4],
            'stage1_patches_count': result[5],
            'stage2_patches_count': result[6],
            'total_patches_count': result[7],
            'stage1_vulnerabilities_count': result[8],
            'stage2_vulnerabilities_count': result[9],
            'created_at': result[10],
            'stage1_completed_at': result[11],
            'stage2_completed_at': result[12],
            'applied_at': result[13],
            'applied_by': result[14],
            'commit_sha': result[15],
            'pr_url': result[16],
            'branch_name': result[17],
            'all_ready': result[3] and result[4]  # Both stages complete
        }
    
    def get_batch_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get current batch status for a scan"""
        return self.get_batch_by_scan(scan_id)
    
    def get_batch_patches(self, batch_id: str, stage: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get all patches in a batch
        
        Args:
            batch_id: Batch ID
            stage: Optional filter by stage (1 or 2)
            
        Returns:
            List of patch dicts
        """
        cursor = self.conn.cursor()
        
        if stage:
            cursor.execute("""
                SELECT id, batch_id, stage, vulnerability_id, file, line,
                       original, repaired, diff, description, confidence,
                       category, selected_for_application, created_at
                FROM patches
                WHERE batch_id = %s AND stage = %s
                ORDER BY file, line
            """, (batch_id, stage))
        else:
            cursor.execute("""
                SELECT id, batch_id, stage, vulnerability_id, file, line,
                       original, repaired, diff, description, confidence,
                       category, selected_for_application, created_at
                FROM patches
                WHERE batch_id = %s
                ORDER BY stage, file, line
            """, (batch_id,))
        
        patches = []
        for row in cursor.fetchall():
            patches.append({
                'id': row[0],
                'batch_id': row[1],
                'stage': row[2],
                'vulnerability_id': row[3],
                'file': row[4],
                'line': row[5],
                'original': row[6],
                'repaired': row[7],
                'diff': row[8],
                'description': row[9],
                'confidence': row[10],
                'category': row[11],
                'selected_for_application': row[12],
                'created_at': row[13]
            })
        
        return patches
    
    def apply_batch(
        self,
        batch_id: str,
        user_id: str,
        selected_patch_ids: Optional[List[str]] = None,
        create_pr: bool = True
    ) -> Dict[str, Any]:
        """
        Apply all patches in a batch
        
        Args:
            batch_id: Batch ID
            user_id: User applying the patches
            selected_patch_ids: Optional list of specific patch IDs to apply
            create_pr: Whether to create a pull request
            
        Returns:
            Result dict with commit_sha, pr_url, etc.
        """
        # Get batch
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, scan_id, stage1_complete, stage2_complete, status
            FROM patch_batches
            WHERE id = %s
        """, (batch_id,))
        
        result = cursor.fetchone()
        if not result:
            raise Exception(f"Batch {batch_id} not found")
        
        _, scan_id, stage1_complete, stage2_complete, status = result
        
        if not (stage1_complete and stage2_complete):
            raise Exception("Cannot apply batch: not all patches are ready")
        
        if status == 'applied':
            raise Exception("Batch already applied")
        
        # Get patches to apply
        if selected_patch_ids:
            patches = self._get_patches_by_ids(selected_patch_ids)
        else:
            patches = self.get_batch_patches(batch_id)
            # Filter to only selected patches
            patches = [p for p in patches if p['selected_for_application']]
        
        if not patches:
            raise Exception("No patches selected for application")
        
        logger.info(f"Applying {len(patches)} patches from batch {batch_id}")
        
        # Apply patches in single commit
        try:
            result = self._apply_patches_single_commit(
                patches=patches,
                scan_id=scan_id,
                user_id=user_id,
                create_pr=create_pr
            )
            
            # Update batch status
            cursor.execute("""
                UPDATE patch_batches
                SET status = 'applied',
                    applied_at = NOW(),
                    applied_by = %s,
                    commit_sha = %s,
                    pr_url = %s,
                    branch_name = %s
                WHERE id = %s
            """, (user_id, result.get('commit_sha'), result.get('pr_url'), 
                  result.get('branch_name'), batch_id))
            
            # Mark patches as applied
            patch_ids = [p['id'] for p in patches]
            cursor.execute("""
                UPDATE patches
                SET status = 'applied'
                WHERE id = ANY(%s)
            """, (patch_ids,))
            
            self.conn.commit()
            
            logger.info(f"Batch {batch_id} applied successfully")
            return result
            
        except Exception as e:
            # Mark batch as failed
            cursor.execute("""
                UPDATE patch_batches
                SET status = 'failed',
                    notes = %s
                WHERE id = %s
            """, (str(e), batch_id))
            self.conn.commit()
            
            logger.error(f"Failed to apply batch {batch_id}: {e}")
            raise
    
    def _get_patches_by_ids(self, patch_ids: List[str]) -> List[Dict[str, Any]]:
        """Get patches by their IDs"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, batch_id, stage, vulnerability_id, file, line,
                   original, repaired, diff, description, confidence,
                   category, selected_for_application
            FROM patches
            WHERE id = ANY(%s)
            ORDER BY file, line
        """, (patch_ids,))
        
        patches = []
        for row in cursor.fetchall():
            patches.append({
                'id': row[0],
                'batch_id': row[1],
                'stage': row[2],
                'vulnerability_id': row[3],
                'file': row[4],
                'line': row[5],
                'original': row[6],
                'repaired': row[7],
                'diff': row[8],
                'description': row[9],
                'confidence': row[10],
                'category': row[11],
                'selected_for_application': row[12]
            })
        
        return patches
    
    def _apply_patches_single_commit(
        self,
        patches: List[Dict[str, Any]],
        scan_id: str,
        user_id: str,
        create_pr: bool = True
    ) -> Dict[str, Any]:
        """
        Apply multiple patches in a single git commit
        
        Args:
            patches: List of patch dicts
            scan_id: Scan ID
            user_id: User ID
            create_pr: Whether to create PR
            
        Returns:
            Result dict
        """
        repo_path = f"scans/{scan_id}/repo"
        
        if not os.path.exists(repo_path):
            raise Exception(f"Repository not found: {repo_path}")
        
        # Group patches by file
        patches_by_file = {}
        for patch in patches:
            file_path = patch['file']
            if file_path not in patches_by_file:
                patches_by_file[file_path] = []
            patches_by_file[file_path].append(patch)
        
        # Apply patches to each file
        modified_files = []
        for file_path, file_patches in patches_by_file.items():
            full_path = os.path.join(repo_path, file_path)
            
            if not os.path.exists(full_path):
                logger.warning(f"File not found: {full_path}, skipping patches")
                continue
            
            # Read current content
            with open(full_path, 'r') as f:
                content = f.read()
            
            # Apply patches (sorted by line number, descending to avoid offset issues)
            file_patches_sorted = sorted(file_patches, key=lambda p: p['line'], reverse=True)
            
            lines = content.split('\n')
            for patch in file_patches_sorted:
                line_num = patch['line']
                if 1 <= line_num <= len(lines):
                    # Simple line replacement
                    lines[line_num - 1] = patch['repaired']
            
            # Write back
            patched_content = '\n'.join(lines)
            with open(full_path, 'w') as f:
                f.write(patched_content)
            
            modified_files.append(file_path)
            logger.info(f"Applied {len(file_patches)} patches to {file_path}")
        
        # Create git commit
        os.chdir(repo_path)
        
        # Stage files
        for file_path in modified_files:
            subprocess.run(['git', 'add', file_path], check=True)
        
        # Generate commit message
        commit_message = self._generate_commit_message(patches, scan_id)
        
        # Commit
        subprocess.run(['git', 'commit', '-m', commit_message], check=True)
        
        # Get commit SHA
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                              capture_output=True, text=True, check=True)
        commit_sha = result.stdout.strip()
        
        logger.info(f"Created commit {commit_sha} with {len(patches)} patches")
        
        # Create PR if requested
        pr_url = None
        branch_name = None
        
        if create_pr:
            try:
                branch_name = f"autovulrepair/scan-{scan_id[:8]}"
                subprocess.run(['git', 'checkout', '-b', branch_name], check=True)
                subprocess.run(['git', 'push', 'origin', branch_name], check=True)
                
                # TODO: Create PR via GitHub API
                pr_url = f"https://github.com/owner/repo/pull/new/{branch_name}"
                logger.info(f"Created branch {branch_name}")
            except Exception as e:
                logger.error(f"Failed to create PR: {e}")
        
        return {
            'success': True,
            'commit_sha': commit_sha,
            'pr_url': pr_url,
            'branch_name': branch_name,
            'patches_applied': len(patches),
            'files_modified': len(modified_files),
            'modified_files': modified_files
        }
    
    def _generate_commit_message(self, patches: List[Dict[str, Any]], scan_id: str) -> str:
        """Generate comprehensive commit message"""
        
        # Group by category
        by_category = {}
        for patch in patches:
            category = patch.get('category', 'unknown')
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(patch)
        
        # Group by stage
        stage1_patches = [p for p in patches if p.get('stage') == 1]
        stage2_patches = [p for p in patches if p.get('stage') == 2]
        
        message = f"Fix {len(patches)} security vulnerabilities\n\n"
        message += f"Scan ID: {scan_id}\n"
        message += f"Patches applied: {len(patches)}\n"
        message += f"  - Stage 1 (deterministic): {len(stage1_patches)}\n"
        message += f"  - Stage 2 (AI-assisted): {len(stage2_patches)}\n\n"
        
        message += "Vulnerabilities fixed:\n\n"
        
        for category, cat_patches in sorted(by_category.items()):
            category_name = category.replace('_', ' ').title()
            message += f"{category_name} ({len(cat_patches)}):\n"
            for patch in cat_patches:
                message += f"  - {patch['file']}:{patch['line']} - {patch['description']}\n"
            message += "\n"
        
        message += f"Applied by: AutoVulRepair\n"
        message += f"Applied at: {datetime.now().isoformat()}\n"
        
        return message
    
    def update_patch_selection(self, patch_id: str, selected: bool):
        """Update whether a patch is selected for application"""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE patches
            SET selected_for_application = %s
            WHERE id = %s
        """, (selected, patch_id))
        self.conn.commit()
    
    def __del__(self):
        """Close database connection"""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
