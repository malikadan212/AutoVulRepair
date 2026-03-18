"""
Analyzer Agent
Analyzes vulnerabilities to understand root cause and fix strategy
"""
import logging
from typing import Dict, Any

from .base import BaseAgent
from ..state import RepairState, update_status, add_message
from ..llm_client import BaseLLMClient
from ..validators import ResponseValidator
from ..prompts import ANALYZER_SYSTEM_PROMPT, format_analyzer_prompt
from ..tools.code_reader import CodeReader
from ..metrics import RepairMetrics

logger = logging.getLogger(__name__)


class AnalyzerAgent(BaseAgent):
    """Analyzes vulnerabilities to determine root cause and fix strategy"""
    
    def __init__(self, llm_client: BaseLLMClient, metrics: RepairMetrics = None, scan_id: str = None):
        """
        Initialize analyzer agent
        
        Args:
            llm_client: Ollama client
            metrics: Metrics tracker
            scan_id: Scan ID for reading source files
        """
        super().__init__(llm_client, metrics)
        self.scan_id = scan_id
        self.code_reader = CodeReader(scan_id=scan_id)
    
    def _execute(self, state: RepairState) -> RepairState:
        """
        Execute analysis
        
        Args:
            state: Current repair state
            
        Returns:
            Updated state with analysis results
        """
        # Validate input
        if not self.validate_state(state, ['vulnerability', 'scan_id']):
            raise ValueError("Missing required fields in state")
        
        # Update status
        state = update_status(state, 'analyzing', 'AnalyzerAgent')
        
        # Get vulnerability data
        vuln = state['vulnerability']
        file_path = vuln.get('file', '')
        line_num = vuln.get('line', 0)
        
        # Update scan_id if not set during init
        if not self.scan_id and 'scan_id' in state:
            self.scan_id = state['scan_id']
            self.code_reader = CodeReader(scan_id=self.scan_id)
        
        self.log(f"Analyzing {vuln.get('crash_type', 'Unknown')} in {file_path}:{line_num}")
        
        # Read code context
        try:
            code_context = self.code_reader.extract_code_around_line(
                file_path=file_path,
                line_number=line_num,
                context_lines=10
            )
            
            if not code_context:
                self.log("Failed to read code context, using minimal context", level='warning')
                code_context = f"// Unable to read {file_path}\n// Line {line_num}"
                
        except Exception as e:
            self.log(f"Error reading code: {e}", level='error')
            code_context = f"// Error reading {file_path}: {e}"
        
        # Format prompt
        prompt = format_analyzer_prompt(vuln, code_context)
        
        self.log("Sending analysis request to LLM...")
        
        # Call LLM with validation
        response = self.llm.generate(
            prompt=prompt,
            system=ANALYZER_SYSTEM_PROMPT,
            validator=ResponseValidator.validate_analysis,
            max_tokens=1000
        )
        
        if not response:
            raise RuntimeError("LLM failed to generate valid analysis")
        
        # Parse response (validator already did this)
        if isinstance(response, dict):
            analysis = response
        else:
            # Fallback parsing
            analysis = ResponseValidator.validate_analysis(response)
            if not analysis:
                raise RuntimeError("Failed to parse analysis response")
        
        # Store analysis in state
        state['analysis'] = analysis
        
        self.log(f"Analysis complete: {analysis['root_cause'][:60]}...")
        state = add_message(
            state,
            f"Root cause: {analysis['root_cause']}"
        )
        state = add_message(
            state,
            f"Fix strategy: {analysis['fix_strategy']}"
        )
        
        return state
    
    def _extract_vulnerability_info(self, vuln: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract key information from vulnerability
        
        Args:
            vuln: Vulnerability dict
            
        Returns:
            Dict with extracted info
        """
        return {
            'crash_type': vuln.get('crash_type', 'Unknown'),
            'file': vuln.get('file', 'unknown'),
            'function': vuln.get('function', 'unknown'),
            'line': str(vuln.get('line', 0)),
            'severity': vuln.get('severity', 'Unknown'),
            'stack_trace': '\n'.join(vuln.get('stack_trace', [])),
            'sanitizer_output': vuln.get('sanitizer_output', 'No output')
        }
