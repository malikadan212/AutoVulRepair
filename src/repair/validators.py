"""
Response Validators
Validate and parse LLM responses to ensure they're well-formed
"""
import re
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class ResponseValidator:
    """Validate and parse LLM responses"""
    
    @staticmethod
    def validate_analysis(response: str) -> Optional[Dict]:
        """
        Validate analyzer response and extract structured data
        
        Expected format:
        Root cause: <description>
        Vulnerable pattern: <pattern>
        Fix strategy: <strategy>
        
        Args:
            response: Raw LLM response
            
        Returns:
            Parsed dict or None if invalid
        """
        try:
            # Extract structured fields
            root_cause_match = re.search(r'Root cause:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
            pattern_match = re.search(r'Vulnerable pattern:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
            strategy_match = re.search(r'Fix strategy:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
            
            if not root_cause_match or not strategy_match:
                logger.warning("Analysis response missing required fields")
                return None
            
            result = {
                'root_cause': root_cause_match.group(1).strip(),
                'vulnerable_pattern': pattern_match.group(1).strip() if pattern_match else 'Unknown',
                'fix_strategy': strategy_match.group(1).strip(),
                'confidence': 0.8,
                'raw_response': response
            }
            
            logger.info(f"Validated analysis: {result['root_cause'][:50]}...")
            return result
            
        except Exception as e:
            logger.error(f"Failed to validate analysis response: {e}")
            return None
    
    @staticmethod
    def validate_patch(response: str) -> Optional[str]:
        """
        Validate patch is valid unified diff format
        
        Expected format:
        --- a/file.c
        +++ b/file.c
        @@ -line,count +line,count @@
        -old line
        +new line
        
        Args:
            response: Raw LLM response
            
        Returns:
            Clean patch or None if invalid
        """
        try:
            # Extract code from markdown blocks if present
            cleaned = ResponseValidator.extract_code_block(response)
            
            # Must start with ---
            if not cleaned.strip().startswith('---'):
                logger.warning("Patch doesn't start with '---'")
                return None
            
            # Must have +++ line
            if '+++' not in cleaned:
                logger.warning("Patch missing '+++'")
                return None
            
            # Must have @@ hunk markers
            if '@@' not in cleaned:
                logger.warning("Patch missing '@@' hunk markers")
                return None
            
            # Check for basic structure
            lines = cleaned.split('\n')
            has_minus = any(line.startswith('-') and not line.startswith('---') for line in lines)
            has_plus = any(line.startswith('+') and not line.startswith('+++') for line in lines)
            
            if not (has_minus or has_plus):
                logger.warning("Patch has no actual changes (no +/- lines)")
                return None
            
            logger.info(f"Validated patch: {len(lines)} lines")
            return cleaned
            
        except Exception as e:
            logger.error(f"Failed to validate patch: {e}")
            return None
    
    @staticmethod
    def extract_code_block(response: str) -> str:
        """
        Extract code from markdown code blocks
        
        Handles:
        ```diff
        code here
        ```
        
        Or:
        ```
        code here
        ```
        
        Args:
            response: Raw response with potential markdown
            
        Returns:
            Cleaned code
        """
        # Remove markdown code block markers
        code = re.sub(r'```\w*\n', '', response)
        code = re.sub(r'```', '', code)
        
        # Remove common LLM preambles
        code = re.sub(r'^Here\'s the patch:?\s*', '', code, flags=re.IGNORECASE)
        code = re.sub(r'^Here is the patch:?\s*', '', code, flags=re.IGNORECASE)
        code = re.sub(r'^Patch:?\s*', '', code, flags=re.IGNORECASE)
        
        return code.strip()
    
    @staticmethod
    def validate_json_response(response: str) -> Optional[Dict]:
        """
        Validate and parse JSON response
        
        Args:
            response: Raw LLM response
            
        Returns:
            Parsed JSON dict or None if invalid
        """
        try:
            import json
            
            # Try to find JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                logger.warning("No JSON found in response")
                return None
            
            json_str = json_match.group(0)
            parsed = json.loads(json_str)
            
            logger.info(f"Validated JSON with {len(parsed)} keys")
            return parsed
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to validate JSON: {e}")
            return None
    
    @staticmethod
    def sanitize_response(response: str, max_length: int = 10000) -> str:
        """
        Sanitize LLM response for safety
        
        Args:
            response: Raw response
            max_length: Maximum allowed length
            
        Returns:
            Sanitized response
        """
        # Truncate if too long
        if len(response) > max_length:
            logger.warning(f"Response truncated from {len(response)} to {max_length} chars")
            response = response[:max_length]
        
        # Remove null bytes
        response = response.replace('\x00', '')
        
        # Normalize line endings
        response = response.replace('\r\n', '\n')
        
        return response
