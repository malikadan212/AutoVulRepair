"""
Patch Generation Service
Coordinates Stage 1 and Stage 2 patch generation with batch tracking
"""
import logging
import os
from typing import Dict, Any, List
from celery import shared_task

from src.services.patch_batch_service import PatchBatchService
from src.repair.stage1.repair_engine import Stage1RepairEngine
from src.repair.stage1.classifier import classify_vulnerability
from src.database import get_db_connection

logger = logging.getLogger(__name__)


class PatchGenerationService:
    """Coordinates patch generation across Stage 1 and Stage 2"""
    
    def __init__(self):
        self.stage1_engine = Stage1RepairEngine(enable_dead_code=False)
        self.batch_service = PatchBatchService()
        self.conn = get_db_connection()
    
    def generate_all_patches(self, scan_id: str) -> Dict[str, Any]:
        """
        Generate patches for all vulnerabilities in a scan
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Dict with batch info and generation status
        """
        logger.info(f"Starting patch generation for scan {scan_id}")
        
        # Get vulnerabilities from database
        vulnerabilities = self._get_vulnerabilities(scan_id)
        
        if not vulnerabilities:
            logger.warning(f"No vulnerabilities found for scan {scan_id}")
            return {'error': 'No vulnerabilities found'}
        
        # Classify vulnerabilities by stage
        stage1_vulns = []
        stage2_vulns = []
        
        for vuln in vulnerabilities:
            classification = classify_vulnerability(vuln)
            if classification['stage'] == 1 and classification['enabled']:
                stage1_vulns.append(vuln)
            else:
                stage2_vulns.append(vuln)
        
        logger.info(f"Classified {len(stage1_vulns)} Stage 1 and {len(stage2_vulns)} Stage 2 vulnerabilities")
        
        # Create or get batch
        batch = self.batch_service.get_or_create_batch(
            scan_id=scan_id,
            stage1_vuln_count=len(stage1_vulns),
            stage2_vuln_count=len(stage2_vulns)
        )
        batch_id = batch['id']
        
        # Generate Stage 1 patches (synchronous, fast)
        stage1_patches = self._generate_stage1_patches(
            scan_id=scan_id,
            batch_id=batch_id,
            vulnerabilities=stage1_vulns
        )
        
        # Mark Stage 1 complete
        self.batch_service.mark_stage1_complete(batch_id, len(stage1_patches))
        
        # Generate Stage 2 patches (asynchronous, slow)
        if stage2_vulns:
            # Trigger async task
            generate_stage2_patches_task.delay(scan_id, batch_id, stage2_vulns)
            logger.info(f"Triggered Stage 2 patch generation for {len(stage2_vulns)} vulnerabilities")
        else:
            # No Stage 2 needed
            self.batch_service.mark_stage2_complete(batch_id, 0)
            logger.info("No Stage 2 vulnerabilities, marking as complete")
        
        return {
            'batch_id': batch_id,
            'scan_id': scan_id,
            'stage1_patches': len(stage1_patches),
            'stage2_pending': len(stage2_vulns),
            'status': 'generating'
        }
    
    def _get_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities from database"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                finding_id as id,
                rule_id,
                cwe,
                severity,
                file,
                line,
                column,
                message as description,
                metadata_json
            FROM findings
            WHERE scan_id = %s
            AND (metadata_json->>'is_false_positive')::boolean IS NOT TRUE
            ORDER BY severity DESC, file, line
        """, (scan_id,))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln = {
                'id': row[0],
                'finding_id': row[0],
                'rule_id': row[1],
                'cwe': row[2],
                'severity': row[3],
                'file': row[4],
                'line': row[5],
                'column': row[6],
                'description': row[7],
                'metadata_json': row[8] or {}
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _generate_stage1_patches(
        self,
        scan_id: str,
        batch_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate Stage 1 patches"""
        logger.info(f"Generating Stage 1 patches for {len(vulnerabilities)} vulnerabilities")
        
        # Get source files
        source_files = self._load_source_files(scan_id, vulnerabilities)
        
        # Generate patches using Stage 1 engine
        patches = []
        
        for vuln in vulnerabilities:
            try:
                file_path = vuln.get('file', '')
                source_code = source_files.get(file_path)
                
                if not source_code:
                    logger.warning(f"Source code not found for {file_path}")
                    continue
                
                # Generate patch
                patch = self.stage1_engine.generate_patch(
                    vuln=vuln,
                    source_code=source_code,
                    source_file=file_path
                )
                
                if patch:
                    # Add batch info
                    patch['batch_id'] = batch_id
                    patch['stage'] = 1
                    patch['scan_id'] = scan_id
                    
                    # Save to database
                    patch_id = self._save_patch(patch)
                    patch['id'] = patch_id
                    
                    patches.append(patch)
                    logger.info(f"Generated Stage 1 patch for {file_path}:{vuln.get('line')}")
                
            except Exception as e:
                logger.error(f"Error generating Stage 1 patch for {vuln.get('id')}: {e}", exc_info=True)
        
        logger.info(f"Generated {len(patches)} Stage 1 patches")
        return patches
    
    def _load_source_files(self, scan_id: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, str]:
        """Load source files for vulnerabilities"""
        source_files = {}
        repo_path = f"scans/{scan_id}/repo"
        
        # Get unique file paths
        file_paths = set(v.get('file', '') for v in vulnerabilities)
        
        for file_path in file_paths:
            if not file_path:
                continue
            
            full_path = os.path.join(repo_path, file_path)
            
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        source_files[file_path] = f.read()
                except Exception as e:
                    logger.error(f"Error reading {full_path}: {e}")
        
        return source_files
    
    def _save_patch(self, patch: Dict[str, Any]) -> str:
        """Save patch to database"""
        import uuid
        
        patch_id = str(uuid.uuid4())
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO patches (
                id, batch_id, stage, vulnerability_id, scan_id,
                file, line, original, repaired, diff,
                description, confidence, category,
                selected_for_application, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            patch_id,
            patch.get('batch_id'),
            patch.get('stage', 1),
            patch.get('vulnerability_id'),
            patch.get('scan_id'),
            patch.get('file'),
            patch.get('line'),
            patch.get('original'),
            patch.get('repaired'),
            patch.get('diff'),
            patch.get('description'),
            patch.get('confidence', 0.0),
            patch.get('category'),
            True  # selected_for_application
        ))
        self.conn.commit()
        
        return patch_id


@shared_task(bind=True, max_retries=3)
def generate_stage2_patches_task(self, scan_id: str, batch_id: str, vulnerabilities: List[Dict[str, Any]]):
    """
    Celery task to generate Stage 2 (AI) patches asynchronously
    
    Args:
        scan_id: Scan ID
        batch_id: Batch ID
        vulnerabilities: List of vulnerabilities needing AI repair
    """
    logger.info(f"Starting Stage 2 patch generation for {len(vulnerabilities)} vulnerabilities")
    
    try:
        # Import AI patch generator
        from ai_patch_generator import AIPatchGenerator
        
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        if not gemini_api_key:
            logger.error("GEMINI_API_KEY not set, cannot generate Stage 2 patches")
            batch_service = PatchBatchService()
            batch_service.mark_stage2_complete(batch_id, 0)
            return
        
        ai_generator = AIPatchGenerator(gemini_api_key=gemini_api_key, index_name='cve-full')
        
        # Load source files
        service = PatchGenerationService()
        source_files = service._load_source_files(scan_id, vulnerabilities)
        
        patches = []
        
        for vuln in vulnerabilities:
            try:
                file_path = vuln.get('file', '')
                source_code = source_files.get(file_path)
                
                if not source_code:
                    logger.warning(f"Source code not found for {file_path}")
                    continue
                
                # Generate AI patch
                patch = ai_generator.generate_patch(
                    vulnerability=vuln,
                    source_code=source_code,
                    file_path=file_path
                )
                
                if patch:
                    # Add batch info
                    patch['batch_id'] = batch_id
                    patch['stage'] = 2
                    patch['scan_id'] = scan_id
                    patch['vulnerability_id'] = vuln.get('id')
                    
                    # Save to database
                    patch_id = service._save_patch(patch)
                    patch['id'] = patch_id
                    
                    patches.append(patch)
                    logger.info(f"Generated Stage 2 patch for {file_path}:{vuln.get('line')}")
                
            except Exception as e:
                logger.error(f"Error generating Stage 2 patch for {vuln.get('id')}: {e}", exc_info=True)
        
        # Mark Stage 2 complete
        batch_service = PatchBatchService()
        batch_service.mark_stage2_complete(batch_id, len(patches))
        
        logger.info(f"Completed Stage 2 patch generation: {len(patches)} patches")
        
    except Exception as e:
        logger.error(f"Stage 2 patch generation failed: {e}", exc_info=True)
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))
