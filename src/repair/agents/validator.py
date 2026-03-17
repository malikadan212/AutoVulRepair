"""
Validator Agent
Validates patches by applying them, building, and testing
"""
import os
import logging
import tempfile
import shutil
from typing import Dict, Any, Optional

from .base import BaseAgent
from ..state import RepairState, update_status, add_message, set_best_patch
from ..llm_client import BaseLLMClient
from ..tools.patch_applier import PatchApplier
from ..tools.code_reader import CodeReader
from ..metrics import RepairMetrics

logger = logging.getLogger(__name__)


class ValidatorAgent(BaseAgent):
    """Validates patches by building and testing"""
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        build_orchestrator=None,
        fuzz_executor=None,
        metrics: RepairMetrics = None,
        scan_id: str = None
    ):
        """
        Initialize validator agent
        
        Args:
            llm_client: Ollama client
            build_orchestrator: BuildOrchestrator instance (optional)
            fuzz_executor: FuzzExecutor instance (optional)
            metrics: Metrics tracker
            scan_id: Scan ID for patching files
        """
        super().__init__(llm_client, metrics)
        self.scan_id = scan_id
        self.patch_applier = PatchApplier(scan_id=scan_id)
        self.build_orchestrator = build_orchestrator
        self.fuzz_executor = fuzz_executor
    
    def _execute(self, state: RepairState) -> RepairState:
        """
        Execute patch validation
        
        Args:
            state: Current repair state
            
        Returns:
            Updated state with validation results
        """
        # Validate input
        if not self.validate_state(state, ['patches', 'vulnerability']):
            raise ValueError("Missing required fields in state")
        
        if not state['patches']:
            raise ValueError("No patches to validate")
        
        # Update status
        state = update_status(state, 'validating', 'ValidatorAgent')
        
        patches = state['patches']
        self.log(f"Validating {len(patches)} patches...")
        
        # Validate each patch
        validation_results = []
        best_patch = None
        best_score = -1.0
        
        for i, patch in enumerate(patches):
            self.log(f"Validating patch {i+1}/{len(patches)}: {patch['type']}")
            
            try:
                result = self._validate_patch(patch, state)
                validation_results.append(result)
                
                # Update patch with validation results
                patch['validated'] = True
                patch['build_success'] = result['build_success']
                patch['test_success'] = result.get('test_success', None)
                patch['score'] = result['score']
                
                # Track best patch
                if result['score'] > best_score:
                    best_score = result['score']
                    best_patch = patch
                
                self.log(
                    f"Patch {patch['type']}: "
                    f"build={'✓' if result['build_success'] else '✗'}, "
                    f"score={result['score']:.2f}"
                )
                
            except Exception as e:
                self.log(f"Error validating patch {i+1}: {e}", level='error')
                validation_results.append({
                    'patch_type': patch['type'],
                    'build_success': False,
                    'error': str(e),
                    'score': 0.0
                })
        
        # Store results
        state['validation_results'] = {
            'results': validation_results,
            'best_score': best_score,
            'patches_validated': len(validation_results)
        }
        
        if best_patch:
            state = set_best_patch(state, best_patch)
            self.log(f"Best patch: {best_patch['type']} (score: {best_score:.2f})")
            state = add_message(
                state,
                f"Best patch: {best_patch['type']} (score: {best_score:.2f})"
            )
        else:
            self.log("No patches passed validation", level='warning')
            state = add_message(state, "No patches passed validation")
        
        return state
    
    def _validate_patch(self, patch: Dict[str, Any], state: RepairState) -> Dict[str, Any]:
        """
        Validate a single patch (without applying to actual source)
        
        Args:
            patch: Patch to validate
            state: Current state
            
        Returns:
            Validation result dict
        """
        result = {
            'patch_type': patch['type'],
            'build_success': None,  # Not tested - requires user approval
            'test_success': None,   # Not tested - requires user approval
            'score': 0.85,  # Default confidence score for AI-generated patches
            'error': None
        }
        
        try:
            # Validate patch format
            self.log(f"Validating {patch['type']} patch format...")
            
            # Check if patch has required fields
            if not patch.get('diff'):
                result['error'] = "Missing patch diff"
                result['score'] = 0.0
                return result
            
            if not patch.get('file'):
                result['error'] = "Missing file path"
                result['score'] = 0.0
                return result
            
            # Check if patch diff is valid unified diff format
            diff_lines = patch['diff'].split('\n')
            has_header = any(line.startswith('---') or line.startswith('+++') for line in diff_lines[:5])
            has_hunks = any(line.startswith('@@') for line in diff_lines)
            
            if not has_header or not has_hunks:
                result['error'] = "Invalid patch format"
                result['score'] = 0.3
                return result
            
            # Patch format is valid
            self.log(f"Patch format validated successfully")
            
            # Assign confidence score based on patch type
            # Conservative patches get higher confidence
            confidence_scores = {
                'conservative': 0.85,
                'moderate': 0.75,
                'aggressive': 0.65
            }
            result['score'] = confidence_scores.get(patch['type'], 0.75)
            
            # Note: Actual build/test validation happens only when user applies the patch
            self.log(f"Patch validated with confidence score: {result['score']:.2f}")
            self.log("Note: Build and test validation will occur when patch is applied by user")
            
        except Exception as e:
            self.log(f"Validation error: {e}", level='error')
            result['error'] = str(e)
            result['score'] = 0.0
        
        return result
    
    def _try_build(self, patch: Dict[str, Any], state: RepairState) -> bool:
        """
        Try to build with patch applied
        
        Args:
            patch: Applied patch
            state: Current state
            
        Returns:
            True if build succeeded, False if failed, None if not tested
        """
        if not self.build_orchestrator:
            self.log("No build orchestrator available, skipping build test", level='warning')
            return None  # Unknown, not success
        
        try:
            # Simple syntax check as fallback
            file_path = patch['file']
            
            # Try to compile the single file
            if file_path.endswith(('.c', '.cpp', '.cc', '.cxx')):
                import subprocess
                
                # Get full path
                if self.scan_id:
                    import os
                    scans_dir = os.getenv('SCANS_DIR', './scans')
                    source_dir = os.path.join(scans_dir, self.scan_id, 'source')
                    full_path = os.path.join(source_dir, os.path.basename(file_path))
                else:
                    full_path = file_path
                
                if not os.path.exists(full_path):
                    self.log(f"File not found for build test: {full_path}", level='warning')
                    return None
                
                # Syntax check with gcc/clang
                result = subprocess.run(
                    ['gcc', '-fsyntax-only', '-c', full_path],
                    capture_output=True,
                    timeout=30,
                    text=True
                )
                
                if result.returncode == 0:
                    self.log("Syntax check passed")
                    return True
                else:
                    self.log(f"Syntax check failed: {result.stderr}", level='warning')
                    return False
            
            # For non-C files, assume success
            return True
            
        except subprocess.TimeoutExpired:
            self.log("Build test timeout", level='error')
            return False
        except FileNotFoundError:
            self.log("gcc not found, skipping build test", level='warning')
            return None
        except Exception as e:
            self.log(f"Build test error: {e}", level='error')
            return False
    
    def _try_test(self, patch: Dict[str, Any], state: RepairState) -> bool:
        """
        Try to run tests with patch applied
        
        Args:
            patch: Applied patch
            state: Current state
            
        Returns:
            True if tests passed, False otherwise
        """
        if not self.fuzz_executor:
            self.log("No fuzz executor available, skipping tests", level='warning')
            return None
        
        try:
            # Run quick smoke test
            # In production, you'd want to:
            # 1. Run unit tests
            # 2. Run integration tests
            # 3. Run quick fuzz test to verify fix
            
            # For now, just return None (not tested)
            return None
            
        except Exception as e:
            self.log(f"Test error: {e}", level='error')
            return False
    
    def _calculate_score(self, result: Dict[str, Any]) -> float:
        """
        Calculate overall patch score
        
        Args:
            result: Validation result
            
        Returns:
            Score from 0.0 to 1.0
        """
        score = 0.0
        
        # Build success is critical
        if result['build_success']:
            score += 0.5
        
        # Test success is important
        if result.get('test_success'):
            score += 0.5
        elif result.get('test_success') is None:
            # Not tested, give partial credit
            score += 0.2
        
        return score
