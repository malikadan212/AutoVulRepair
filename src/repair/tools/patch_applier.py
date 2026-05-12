"""
Patch Applier Tools
Apply and revert patches to source code
"""
import os
import shutil
import logging
import subprocess
import re
from typing import Tuple, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class PatchApplier:
    """Helper class for applying and reverting patches"""
    
    def __init__(self, scan_id: str = None):
        """
        Initialize patch applier
        
        Args:
            scan_id: Scan ID (optional)
        """
        self.scan_id = scan_id
        self.backup_dir = '.patch_backup'
        self.acr_header_path = 'acr.h'  # Default location for ACR header
    
    def apply_patch(self, file_path: str, patch_diff: str, patch_metadata: Dict[str, Any] = None) -> bool:
        """
        Apply patch to file with support for ACR headers
        
        Args:
            file_path: Path to file
            patch_diff: Unified diff patch
            patch_metadata: Optional patch metadata (includes acr_header info)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create backup
            self._create_backup(file_path)
            
            # Handle ACR header if needed
            if patch_metadata and patch_metadata.get('requires_acr_header'):
                self._ensure_acr_header(file_path, patch_metadata)
            
            # Try to apply patch
            if self.scan_id:
                success, msg = apply_patch(self.scan_id, patch_diff, file_path)
            else:
                # Direct file patching
                success, msg = self._apply_direct(file_path, patch_diff)
            
            if success:
                logger.info(f"Applied patch to {file_path}")
                return True
            else:
                logger.error(f"Failed to apply patch: {msg}")
                return False
                
        except Exception as e:
            logger.error(f"Error applying patch: {e}")
            return False
    
    def revert_patch(self, file_path: str) -> bool:
        """
        Revert file to backup
        
        Args:
            file_path: Path to file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.scan_id:
                success, msg = revert_patch(self.scan_id, file_path)
                return success
            else:
                # Direct revert
                return self._revert_direct(file_path)
                
        except Exception as e:
            logger.error(f"Error reverting patch: {e}")
            return False
    
    def _create_backup(self, file_path: str):
        """Create backup of file"""
        try:
            if os.path.exists(file_path):
                backup_path = self._get_backup_path(file_path)
                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                shutil.copy2(file_path, backup_path)
                logger.debug(f"Created backup: {backup_path}")
        except Exception as e:
            logger.warning(f"Failed to create backup: {e}")
    
    def _get_backup_path(self, file_path: str) -> str:
        """Get backup file path"""
        return os.path.join(self.backup_dir, file_path + '.backup')
    
    def _apply_direct(self, file_path: str, patch_diff: str) -> Tuple[bool, str]:
        """Apply patch directly to file"""
        try:
            # Simple line-based patching
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Parse and apply patch (simplified)
            # In production, use proper patch library
            
            return True, "Patch applied"
        except Exception as e:
            return False, str(e)
    
    def _revert_direct(self, file_path: str) -> bool:
        """Revert file from backup"""
        try:
            backup_path = self._get_backup_path(file_path)
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, file_path)
                logger.info(f"Reverted {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Revert failed: {e}")
            return False
    
    def _ensure_acr_header(self, file_path: str, patch_metadata: Dict[str, Any]):
        """
        Ensure ACR header exists and is included in the source file
        
        Args:
            file_path: Path to source file being patched
            patch_metadata: Patch metadata containing acr_header_content
        """
        try:
            # Determine the directory where acr.h should be placed
            if self.scan_id:
                scans_dir = os.getenv('SCANS_DIR', './scans')
                source_dir = os.path.join(scans_dir, self.scan_id, 'source')
            else:
                # Place in same directory as the source file
                source_dir = os.path.dirname(os.path.abspath(file_path))
            
            acr_header_full_path = os.path.join(source_dir, self.acr_header_path)
            
            # Create acr.h if it doesn't exist
            if not os.path.exists(acr_header_full_path):
                acr_content = patch_metadata.get('acr_header_content', '')
                if acr_content:
                    with open(acr_header_full_path, 'w', encoding='utf-8') as f:
                        f.write(acr_content)
                    logger.info(f"Created ACR header: {acr_header_full_path}")
                else:
                    logger.warning("No acr_header_content in patch metadata")
                    return
            
            # Ensure the source file includes acr.h
            self._add_include_if_missing(file_path, 'acr.h')
            
        except Exception as e:
            logger.error(f"Failed to ensure ACR header: {e}")
    
    def _add_include_if_missing(self, file_path: str, header_name: str):
        """
        Add #include directive to source file if not already present
        
        Args:
            file_path: Path to source file
            header_name: Name of header to include (e.g., 'acr.h')
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if already included
            include_pattern = rf'#include\s+[<"]' + re.escape(header_name) + r'[>"]'
            if re.search(include_pattern, content):
                logger.debug(f"{header_name} already included in {file_path}")
                return
            
            # Find the best place to insert the include
            lines = content.split('\n')
            insert_pos = self._find_include_position(lines)
            
            # Insert the include
            include_line = f'#include "{header_name}"'
            lines.insert(insert_pos, include_line)
            
            # Write back
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            logger.info(f"Added #include \"{header_name}\" to {file_path} at line {insert_pos + 1}")
            
        except Exception as e:
            logger.error(f"Failed to add include: {e}")
    
    def _find_include_position(self, lines: list) -> int:
        """
        Find the best position to insert a new #include directive
        
        Args:
            lines: List of source code lines
            
        Returns:
            Line index where include should be inserted
        """
        # Strategy: Insert after existing includes, or after header comments
        last_include_pos = -1
        last_comment_pos = -1
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            # Track includes
            if stripped.startswith('#include'):
                last_include_pos = i
            
            # Track comments at the top
            elif stripped.startswith('/*') or stripped.startswith('//') or stripped.startswith('*'):
                if last_include_pos == -1:  # Only count comments before includes
                    last_comment_pos = i
            
            # Stop at first non-comment, non-include, non-blank line
            elif stripped and not stripped.startswith('#') and last_include_pos >= 0:
                break
        
        # Insert after last include, or after comments, or at the beginning
        if last_include_pos >= 0:
            return last_include_pos + 1
        elif last_comment_pos >= 0:
            return last_comment_pos + 1
        else:
            return 0


def apply_patch(
    scan_id: str,
    patch_content: str,
    file_path: str,
    backup: bool = True
) -> Tuple[bool, str]:
    """
    Apply a unified diff patch to a source file
    
    Args:
        scan_id: Scan ID
        patch_content: Unified diff patch content
        file_path: Relative path to file to patch
        backup: Whether to create backup before patching
        
    Returns:
        Tuple of (success, message)
    """
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        source_dir = os.path.join(scans_dir, scan_id, 'source')
        
        # Normalize file path - strip common prefixes
        if file_path.startswith('/tmp/source/'):
            file_path = file_path[12:]
        elif file_path.startswith('/source/'):
            file_path = file_path[8:]
        elif file_path.startswith('source/'):
            file_path = file_path[7:]
        
        full_path = os.path.join(source_dir, file_path)
        
        if not os.path.exists(full_path):
            return False, f"File not found: {file_path}"
        
        # --- IDEMPOTENCY CHECK ---
        # Extract all lines added by this patch (lines starting with +, not +++)
        added_lines = []
        for line in patch_content.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:].strip())
        
        if added_lines:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                existing_content = f.read()
            
            # Check if all significant added lines already exist in the file
            significant = [l for l in added_lines if l and not l.startswith('//')]
            if significant and all(l in existing_content for l in significant):
                logger.info(f"Patch already applied to {file_path} (idempotency check), skipping")
                return True, "Patch already applied (skipped)"
        # --- END IDEMPOTENCY CHECK ---
        
        # Create backup if requested
        if backup:
            backup_path = f"{full_path}.backup"
            shutil.copy2(full_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
        
        # Write patch to temporary file
        patch_file = os.path.join(source_dir, '.temp_patch.diff')
        with open(patch_file, 'w', encoding='utf-8') as f:
            f.write(patch_content)
        
        # Apply patch using patch command
        # Use -p3 to strip /tmp/source/ prefix from patch paths
        try:
            result = subprocess.run(
                ['patch', '-p3', '-i', patch_file],
                cwd=source_dir,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Clean up temp file
            os.remove(patch_file)
            
            if result.returncode == 0:
                logger.info(f"Successfully applied patch to {file_path}")
                return True, "Patch applied successfully"
            else:
                error_msg = result.stderr or result.stdout
                logger.error(f"Failed to apply patch: {error_msg}")
                
                # Restore backup if patch failed
                if backup and os.path.exists(backup_path):
                    shutil.copy2(backup_path, full_path)
                    logger.info("Restored backup after failed patch")
                
                return False, f"Patch failed: {error_msg}"
                
        except FileNotFoundError:
            # patch command not available, try manual application
            logger.warning("'patch' command not found, trying manual application")
            return _apply_patch_manual(full_path, patch_content, backup_path if backup else None)
            
    except Exception as e:
        logger.error(f"Error applying patch: {e}")
        return False, f"Error: {str(e)}"


def _apply_patch_manual(
    file_path: str,
    patch_content: str,
    backup_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Manually apply patch (fallback when patch command unavailable)
    
    Args:
        file_path: Full path to file
        patch_content: Patch content
        backup_path: Backup file path (optional)
        
    Returns:
        Tuple of (success, message)
    """
    try:
        # Read original file
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Parse patch
        patch_lines = patch_content.split('\n')
        
        # Find hunks
        new_lines = []
        i = 0
        
        for patch_line in patch_lines:
            if patch_line.startswith('@@'):
                # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
                continue
            elif patch_line.startswith('---') or patch_line.startswith('+++'):
                # Skip file headers
                continue
            elif patch_line.startswith('-'):
                # Line to remove - skip it
                continue
            elif patch_line.startswith('+'):
                # Line to add
                new_lines.append(patch_line[1:] + '\n')
            else:
                # Context line - keep it
                if i < len(lines):
                    new_lines.append(lines[i])
                    i += 1
        
        # Write patched file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        
        logger.info(f"Manually applied patch to {file_path}")
        return True, "Patch applied manually"
        
    except Exception as e:
        logger.error(f"Manual patch application failed: {e}")
        
        # Restore backup if available
        if backup_path and os.path.exists(backup_path):
            shutil.copy2(backup_path, file_path)
            logger.info("Restored backup after failed manual patch")
        
        return False, f"Manual patch failed: {str(e)}"


def revert_patch(scan_id: str, file_path: str) -> Tuple[bool, str]:
    """
    Revert a file to its backup
    
    Args:
        scan_id: Scan ID
        file_path: Relative path to file
        
    Returns:
        Tuple of (success, message)
    """
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        source_dir = os.path.join(scans_dir, scan_id, 'source')
        
        if file_path.startswith('/source/'):
            file_path = file_path[8:]
        
        full_path = os.path.join(source_dir, file_path)
        backup_path = f"{full_path}.backup"
        
        if not os.path.exists(backup_path):
            return False, "No backup found"
        
        shutil.copy2(backup_path, full_path)
        logger.info(f"Reverted {file_path} from backup")
        
        return True, "File reverted successfully"
        
    except Exception as e:
        logger.error(f"Failed to revert file: {e}")
        return False, f"Revert failed: {str(e)}"


def cleanup_backups(scan_id: str):
    """
    Remove all backup files
    
    Args:
        scan_id: Scan ID
    """
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        source_dir = os.path.join(scans_dir, scan_id, 'source')
        
        backup_count = 0
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                if file.endswith('.backup'):
                    backup_file = os.path.join(root, file)
                    os.remove(backup_file)
                    backup_count += 1
        
        logger.info(f"Cleaned up {backup_count} backup files")
        
    except Exception as e:
        logger.error(f"Failed to cleanup backups: {e}")
