"""
Generator Agent
Generates multiple patch candidates (conservative, moderate, aggressive)
"""
import logging
from typing import Dict, Any, List

from .base import BaseAgent
from ..state import RepairState, update_status, add_message, add_patch
from ..llm_client import BaseLLMClient
from ..validators import ResponseValidator
from ..prompts import GENERATOR_SYSTEM_PROMPT, format_generator_prompt
from ..tools.code_reader import CodeReader
from ..metrics import RepairMetrics
from ..rag import CVERAGSystem

logger = logging.getLogger(__name__)


class GeneratorAgent(BaseAgent):
    """Generates multiple patch candidates with different risk levels"""
    
    def __init__(self, llm_client: BaseLLMClient, metrics: RepairMetrics = None, scan_id: str = None):
        """
        Initialize generator agent
        
        Args:
            llm_client: Ollama client
            metrics: Metrics tracker
            scan_id: Scan ID for reading source files
        """
        super().__init__(llm_client, metrics)
        self.scan_id = scan_id
        self.code_reader = CodeReader(scan_id=scan_id)
        self.patch_types = ['conservative', 'moderate', 'aggressive']
        
        # Initialize RAG system
        try:
            self.rag = CVERAGSystem(llm_client=llm_client)
        except Exception as e:
            logger.warning(f"GeneratorAgent: Failed to initialize RAG system: {e}")
            self.rag = None
    
    def _execute(self, state: RepairState) -> RepairState:
        """
        Execute patch generation
        
        Args:
            state: Current repair state
            
        Returns:
            Updated state with patch candidates
        """
        # Validate input
        if not self.validate_state(state, ['vulnerability', 'analysis']):
            raise ValueError("Missing required fields in state")
        
        # Update status
        state = update_status(state, 'generating', 'GeneratorAgent')
        
        # Get data
        vuln = state['vulnerability']
        analysis = state['analysis']
        file_path = vuln.get('file', '')
        line_num = vuln.get('line', 0)
        
        # Update scan_id if not set during init
        if not self.scan_id and 'scan_id' in state:
            self.scan_id = state['scan_id']
            self.code_reader = CodeReader(scan_id=self.scan_id)
        
        self.log(f"Generating patches for {file_path}:{line_num}")
        
        # Read code context
        try:
            code_context = self.code_reader.extract_code_around_line(
                file_path=file_path,
                line_number=line_num,
                context_lines=15  # More context for patch generation
            )
            
            if not code_context or not code_context.strip():
                raise RuntimeError(f"Failed to read code from {file_path}")
                
        except Exception as e:
            self.log(f"Error reading code: {e}", level='error')
            raise RuntimeError(f"Cannot generate patches without code context: {e}")
        
        # Get RAG context
        rag_context = ""
        if self.rag:
            try:
                self.log("Retrieving VUL-RAG context...")
                # Search based on vulnerability description and bug class
                query = f"{vuln.get('description', '')} {vuln.get('bug_class', '')}"
                cves = self.rag.retrieve_context(query)
                rag_context = self.rag.format_context_for_prompt(cves)
                self.log(f"VUL-RAG: Found {len(cves)} relevant examples")
            except Exception as e:
                self.log(f"VUL-RAG error: {e}", level='warning')
        
        # Generate patches for each type IN PARALLEL
        patches_generated = 0
        
        # Use ThreadPoolExecutor for parallel generation with timeout
        from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Submit all patch generation tasks
            future_to_type = {
                executor.submit(
                    self._generate_patch,
                    patch_type=patch_type,
                    analysis=analysis,
                    code_context=code_context,
                    rag_context=rag_context,
                    file_path=file_path,
                    line_num=line_num
                ): patch_type
                for patch_type in self.patch_types
            }
            
            # Collect results as they complete (with 120s timeout)
            try:
                for future in as_completed(future_to_type, timeout=120):
                    patch_type = future_to_type[future]
                    try:
                        self.log(f"Generating {patch_type} patch...")
                        patch = future.result(timeout=60)  # 60s per patch
                        
                        if patch:
                            state = add_patch(state, patch)
                            patches_generated += 1
                            self.log(f"{patch_type.capitalize()} patch generated successfully")
                            state = add_message(state, f"Generated {patch_type} patch")
                        else:
                            self.log(f"Failed to generate {patch_type} patch", level='warning')
                            
                    except TimeoutError:
                        self.log(f"Timeout generating {patch_type} patch", level='error')
                    except Exception as e:
                        self.log(f"Error generating {patch_type} patch: {e}", level='error')
                        # Continue with other patch types
            except TimeoutError:
                self.log("Overall timeout waiting for patches", level='error')
        
        if patches_generated == 0:
            raise RuntimeError("Failed to generate any valid patches")
        
        self.log(f"Generated {patches_generated}/{len(self.patch_types)} patches")
        state = add_message(state, f"Generated {patches_generated} patch candidates")
        
        return state
    
    def _generate_patch(
        self,
        patch_type: str,
        analysis: Dict[str, Any],
        code_context: str,
        rag_context: str,
        file_path: str,
        line_num: int
    ) -> Dict[str, Any]:
        """
        Generate a single patch
        
        Args:
            patch_type: 'conservative', 'moderate', or 'aggressive'
            analysis: Analysis results
            code_context: Source code context
            file_path: File to patch
            line_num: Line number
            
        Returns:
            Patch dict or None if failed
        """
        # Format prompt
        prompt = format_generator_prompt(
            patch_type=patch_type,
            analysis=analysis,
            code_context=code_context,
            file=file_path,
            rag_context=rag_context
        )
        
        # Call LLM with validation
        response = self.llm.generate(
            prompt=prompt,
            system=GENERATOR_SYSTEM_PROMPT,
            validator=ResponseValidator.validate_patch,
            max_tokens=1500
        )
        
        if not response:
            self.log(f"LLM failed to generate {patch_type} patch", level='warning')
            return None
        
        # Parse patch
        patch_diff = response if isinstance(response, str) else response
        
        # Count changes
        lines = patch_diff.split('\n')
        lines_added = sum(1 for line in lines if line.startswith('+') and not line.startswith('+++'))
        lines_removed = sum(1 for line in lines if line.startswith('-') and not line.startswith('---'))
        
        # Create patch dict
        patch = {
            'type': patch_type,
            'file': file_path,
            'line': line_num,
            'diff': patch_diff,
            'lines_added': lines_added,
            'lines_removed': lines_removed,
            'validated': False,
            'build_success': None,
            'test_success': None,
            'score': 0.0
        }
        
        return patch
    
    def _estimate_patch_risk(self, patch: Dict[str, Any]) -> str:
        """
        Estimate risk level of patch
        
        Args:
            patch: Patch dict
            
        Returns:
            Risk level: 'low', 'medium', 'high'
        """
        lines_changed = patch['lines_added'] + patch['lines_removed']
        
        if lines_changed <= 3:
            return 'low'
        elif lines_changed <= 7:
            return 'medium'
        else:
            return 'high'
