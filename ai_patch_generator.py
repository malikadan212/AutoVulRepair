"""
AI-Powered Patch Generator

Uses RAG (FAISS + Gemini) to generate intelligent patches for vulnerabilities.

Features:
- Analyzes vulnerability with CVE context
- Generates code patches
- Provides explanation and testing recommendations
- Supports multiple programming languages
"""

import os
from typing import Dict, Any, List
from search_cve_faiss import FAISSCVESearch

try:
    import google.generativeai as genai
except ImportError:
    print("ERROR: Google Generative AI package not installed!")
    print("Please run: pip install google-generativeai")
    exit(1)


class AIPatchGenerator:
    """Generate AI-powered patches for vulnerabilities"""
    
    def __init__(self, gemini_api_key: str, index_name: str = 'cve-full'):
        """
        Initialize patch generator
        
        Args:
            gemini_api_key: Google Gemini API key
            index_name: FAISS index name
        """
        # Initialize FAISS searcher
        try:
            self.searcher = FAISSCVESearch(index_name)
        except:
            self.searcher = None
            print("Warning: FAISS index not available. Patches will be generated without CVE context.")
        
        # Initialize Gemini
        genai.configure(api_key=gemini_api_key)
        self.model = genai.GenerativeModel('gemini-pro')
    
    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze vulnerability and find related CVEs
        
        Args:
            vulnerability: Dict with keys: description, file, line, code_snippet, severity
        
        Returns:
            Analysis with related CVEs
        """
        if not self.searcher:
            return {'related_cves': [], 'context': ''}
        
        # Search for related CVEs
        query = f"{vulnerability.get('description', '')} {vulnerability.get('bug_class', '')}"
        related_cves = self.searcher.search(query, top_k=5)
        
        # Format context
        context = self._format_cve_context(related_cves)
        
        return {
            'related_cves': related_cves,
            'context': context
        }
    
    def _format_cve_context(self, cves: List[Dict[str, Any]]) -> str:
        """Format CVEs into context string"""
        if not cves:
            return "No related CVEs found."
        
        context_parts = []
        for cve in cves:
            context_parts.append(
                f"- {cve['cve_id']} ({cve['severity']}, CVSS: {cve.get('cvss_score', 'N/A')}): "
                f"{cve['description'][:150]}..."
            )
        
        return "\n".join(context_parts)
    
    def generate_patch(self, vulnerability: Dict[str, Any], analysis: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate patch for vulnerability
        
        Args:
            vulnerability: Vulnerability details
            analysis: Optional pre-computed analysis
        
        Returns:
            Dict with patch, explanation, and recommendations
        """
        # Get analysis if not provided
        if analysis is None:
            analysis = self.analyze_vulnerability(vulnerability)
        
        # Create prompt
        prompt = self._create_patch_prompt(vulnerability, analysis)
        
        # Generate patch
        response = self.model.generate_content(prompt)
        
        # Parse response
        patch_data = self._parse_patch_response(response.text, vulnerability)
        
        # Add metadata
        patch_data['related_cves'] = analysis.get('related_cves', [])
        patch_data['vulnerability'] = vulnerability
        
        return patch_data
    
    def _create_patch_prompt(self, vulnerability: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Create prompt for patch generation"""
        
        prompt = f"""You are an expert security engineer specializing in vulnerability remediation.

VULNERABILITY DETAILS:
- Type: {vulnerability.get('bug_class', 'Unknown')}
- Description: {vulnerability.get('description', 'No description')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- File: {vulnerability.get('file', 'Unknown')}
- Line: {vulnerability.get('line', 'Unknown')}

VULNERABLE CODE:
```{vulnerability.get('language', 'c')}
{vulnerability.get('code_snippet', 'Code not available')}
```

RELATED CVE CONTEXT:
{analysis.get('context', 'No CVE context available')}

TASK:
Generate a secure patch for this vulnerability. Provide:

1. PATCH CODE:
   - Write the corrected code
   - Use the same programming language and style
   - Ensure the fix is complete and secure
   - Add security-focused comments

2. EXPLANATION:
   - Explain what the vulnerability is
   - Explain how the patch fixes it
   - Explain why this approach is secure

3. TESTING RECOMMENDATIONS:
   - Suggest specific test cases
   - Include both positive and negative tests
   - Mention edge cases to consider

4. ADDITIONAL RECOMMENDATIONS:
   - Any additional security measures
   - Related code that might need review
   - Best practices to follow

FORMAT YOUR RESPONSE AS:

## Patched Code
```{vulnerability.get('language', 'c')}
[Your patched code here]
```

## Explanation
[Your explanation here]

## Testing Recommendations
[Your testing recommendations here]

## Additional Recommendations
[Your additional recommendations here]

Generate the patch now:"""
        
        return prompt
    
    def _parse_patch_response(self, response_text: str, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Gemini response into structured patch data"""
        
        # Extract sections
        sections = {
            'patched_code': '',
            'explanation': '',
            'testing_recommendations': '',
            'additional_recommendations': ''
        }
        
        # Simple parsing (you can make this more robust)
        current_section = None
        lines = response_text.split('\n')
        
        for line in lines:
            if '## Patched Code' in line or '##Patched Code' in line:
                current_section = 'patched_code'
            elif '## Explanation' in line or '##Explanation' in line:
                current_section = 'explanation'
            elif '## Testing' in line or '##Testing' in line:
                current_section = 'testing_recommendations'
            elif '## Additional' in line or '##Additional' in line:
                current_section = 'additional_recommendations'
            elif current_section:
                sections[current_section] += line + '\n'
        
        # Clean up code blocks
        patched_code = sections['patched_code']
        if '```' in patched_code:
            # Extract code from markdown code blocks
            parts = patched_code.split('```')
            if len(parts) >= 2:
                code = parts[1]
                # Remove language identifier
                if '\n' in code:
                    code = '\n'.join(code.split('\n')[1:])
                patched_code = code.strip()
        
        return {
            'patched_code': patched_code.strip(),
            'explanation': sections['explanation'].strip(),
            'testing_recommendations': sections['testing_recommendations'].strip(),
            'additional_recommendations': sections['additional_recommendations'].strip(),
            'original_code': vulnerability.get('code_snippet', ''),
            'file': vulnerability.get('file', ''),
            'line': vulnerability.get('line', ''),
            'status': 'generated'
        }
    
    def generate_batch_patches(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate patches for multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dicts
        
        Returns:
            List of patch dicts
        """
        patches = []
        
        for vuln in vulnerabilities:
            try:
                # Analyze
                analysis = self.analyze_vulnerability(vuln)
                
                # Generate patch
                patch = self.generate_patch(vuln, analysis)
                
                patches.append(patch)
                
            except Exception as e:
                # Add error patch
                patches.append({
                    'vulnerability': vuln,
                    'error': str(e),
                    'status': 'failed'
                })
        
        return patches
