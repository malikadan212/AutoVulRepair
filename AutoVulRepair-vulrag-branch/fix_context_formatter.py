"""
Fix Context Formatter

Formats vulnerability data for LLM consumption, creating structured text blocks
that include CVE descriptions, root causes, fix strategies, code patterns, and
attack conditions from VUL-RAG enrichment data.

Usage:
    from fix_context_formatter import FixContextFormatter
    
    formatter = FixContextFormatter()
    
    # Format single CVE
    cve_data = {
        'cve_id': 'CVE-2023-12345',
        'description': '...',
        'root_cause': '...',
        'fix_strategy': '...'
    }
    context = formatter.format_single_cve(cve_data)
    
    # Format multiple CVEs
    context = formatter.format_multiple_cves([cve_data1, cve_data2])
"""

from typing import Dict, List, Optional, Any


class FixContextFormatter:
    """
    Formats vulnerability data for LLM consumption
    
    Creates structured text blocks with clear section headers that include
    all available CVE and VUL-RAG enrichment data. Handles partial data
    gracefully by including only available fields.
    """
    
    def __init__(self):
        """Initialize the formatter"""
        pass
    
    def format_single_cve(self, cve_data: Dict[str, Any]) -> str:
        """
        Format a single CVE for LLM consumption
        
        Creates a structured text block with clear sections for each field.
        Only includes sections for fields that have data. Optimized for
        LLM comprehension with clear headers and formatting.
        
        Args:
            cve_data: Dictionary containing CVE and VUL-RAG enrichment data.
                     Expected fields:
                     - cve_id (required)
                     - description (required)
                     - severity (optional)
                     - cvss_score (optional)
                     - cwe (optional)
                     - vulnerability_type (optional)
                     - root_cause (optional)
                     - fix_strategy (optional)
                     - code_pattern (optional)
                     - attack_condition (optional)
        
        Returns:
            Formatted text string suitable for LLM context
        """
        # Check if this CVE has any VUL-RAG enrichment
        has_enrichment = any(
            cve_data.get(field) 
            for field in ['vulnerability_type', 'root_cause', 'fix_strategy', 
                         'code_pattern', 'attack_condition']
        )
        
        if not has_enrichment:
            # Fallback formatting for CVEs without enrichment
            return self._format_fallback(cve_data)
        
        # Build formatted context with available fields
        lines = []
        
        # Header with CVE ID
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        lines.append(f"=== {cve_id} ===")
        
        # Vulnerability Type (if available)
        if cve_data.get('vulnerability_type'):
            lines.append(f"Vulnerability Type: {cve_data['vulnerability_type']}")
        
        # Severity and CVSS (if available)
        severity_parts = []
        if cve_data.get('severity'):
            severity_parts.append(cve_data['severity'])
        if cve_data.get('cvss_score'):
            severity_parts.append(f"CVSS: {cve_data['cvss_score']}")
        if severity_parts:
            lines.append(f"Severity: {' ('.join(severity_parts) + ')' if len(severity_parts) > 1 else severity_parts[0]}")
        
        # CWE (if available)
        if cve_data.get('cwe'):
            lines.append(f"CWE: {cve_data['cwe']}")
        
        lines.append("")  # Blank line for readability
        
        # Description
        if cve_data.get('description'):
            lines.append("Description:")
            lines.append(cve_data['description'])
            lines.append("")
        
        # Root Cause (if available)
        if cve_data.get('root_cause'):
            lines.append("Root Cause:")
            lines.append(cve_data['root_cause'])
            lines.append("")
        
        # Attack Condition (if available)
        if cve_data.get('attack_condition'):
            lines.append("Attack Condition:")
            lines.append(cve_data['attack_condition'])
            lines.append("")
        
        # Fix Strategy (if available)
        if cve_data.get('fix_strategy'):
            lines.append("Fix Strategy:")
            lines.append(cve_data['fix_strategy'])
            lines.append("")
        
        # Code Pattern (if available)
        if cve_data.get('code_pattern'):
            lines.append("Code Pattern:")
            lines.append(cve_data['code_pattern'])
            lines.append("")
        
        # Footer
        lines.append("=" * 35)
        
        return "\n".join(lines)
    
    def _format_fallback(self, cve_data: Dict[str, Any]) -> str:
        """
        Format CVE without VUL-RAG enrichment
        
        Provides basic CVE information with a note indicating limited
        context availability.
        
        Args:
            cve_data: Dictionary containing basic CVE data
        
        Returns:
            Formatted text string with fallback formatting
        """
        lines = []
        
        # Header with CVE ID
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        lines.append(f"=== {cve_id} ===")
        
        # Severity and CVSS (if available)
        severity_parts = []
        if cve_data.get('severity'):
            severity_parts.append(cve_data['severity'])
        if cve_data.get('cvss_score'):
            severity_parts.append(f"CVSS: {cve_data['cvss_score']}")
        if severity_parts:
            lines.append(f"Severity: {' ('.join(severity_parts) + ')' if len(severity_parts) > 1 else severity_parts[0]}")
        
        # CWE (if available)
        if cve_data.get('cwe'):
            lines.append(f"CWE: {cve_data['cwe']}")
        
        lines.append("")
        
        # Description
        if cve_data.get('description'):
            lines.append("Description:")
            lines.append(cve_data['description'])
            lines.append("")
        
        # Note about limited context
        lines.append("Note: Limited context available - VUL-RAG enrichment data not found for this CVE.")
        lines.append("")
        
        # Footer
        lines.append("=" * 35)
        
        return "\n".join(lines)
    
    def format_multiple_cves(self, cve_list: List[Dict[str, Any]]) -> str:
        """
        Format multiple CVEs with clear delimiters
        
        Concatenates individual CVE contexts with clear separators between
        each CVE. Useful for providing comprehensive context about multiple
        related vulnerabilities to an LLM.
        
        Args:
            cve_list: List of CVE data dictionaries
        
        Returns:
            Formatted text string with all CVEs separated by delimiters
        """
        if not cve_list:
            return ""
        
        # Format each CVE individually
        formatted_cves = []
        for cve_data in cve_list:
            formatted_cves.append(self.format_single_cve(cve_data))
        
        # Join with double newlines for clear separation
        return "\n\n".join(formatted_cves)
    
    def format_for_patch_generation(self, cve_data: Dict[str, Any], 
                                   code_snippet: str) -> str:
        """
        Create a patch generation prompt with CVE context and code
        
        Combines CVE fix context with a code snippet to create a complete
        prompt for LLM-based patch generation.
        
        Args:
            cve_data: Dictionary containing CVE and VUL-RAG data
            code_snippet: The vulnerable code that needs patching
        
        Returns:
            Formatted prompt string for patch generation
        """
        lines = []
        
        # Add CVE context
        lines.append("VULNERABILITY CONTEXT:")
        lines.append("")
        lines.append(self.format_single_cve(cve_data))
        lines.append("")
        lines.append("")
        
        # Add code snippet
        lines.append("VULNERABLE CODE:")
        lines.append("")
        lines.append("```")
        lines.append(code_snippet)
        lines.append("```")
        lines.append("")
        
        # Add instruction
        lines.append("TASK:")
        lines.append("Generate a patch to fix the vulnerability described above. "
                    "The patch should address the root cause and implement the "
                    "suggested fix strategy while maintaining code functionality.")
        
        return "\n".join(lines)


def main():
    """Example usage and testing of FixContextFormatter"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Format CVE data for LLM consumption',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run test formatting
  python fix_context_formatter.py --test
        """
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run test formatting examples'
    )
    
    args = parser.parse_args()
    
    if args.test:
        print("Testing Fix Context Formatter")
        print("=" * 80)
        print()
        
        formatter = FixContextFormatter()
        
        # Test 1: CVE with complete VUL-RAG enrichment
        print("Test 1: CVE with complete VUL-RAG enrichment")
        print("-" * 80)
        complete_cve = {
            'cve_id': 'CVE-2023-12345',
            'severity': 'HIGH',
            'cvss_score': 7.5,
            'cwe': 'CWE-79',
            'description': 'Cross-site scripting (XSS) vulnerability in web application allows remote attackers to inject arbitrary web script or HTML via the search parameter.',
            'vulnerability_type': 'Cross-Site Scripting (XSS)',
            'root_cause': 'Insufficient input validation and output encoding on user-supplied data in the search functionality.',
            'attack_condition': 'Attacker can inject malicious JavaScript code through the search parameter, which is reflected in the page without proper sanitization.',
            'fix_strategy': 'Implement proper input validation to reject malicious patterns and apply context-aware output encoding (HTML entity encoding) for all user-supplied data before rendering in HTML context.',
            'code_pattern': 'Direct insertion of user input into HTML without escaping: response.write("<div>" + searchQuery + "</div>")'
        }
        
        context = formatter.format_single_cve(complete_cve)
        print(context)
        print()
        print()
        
        # Test 2: CVE with partial VUL-RAG data
        print("Test 2: CVE with partial VUL-RAG enrichment")
        print("-" * 80)
        partial_cve = {
            'cve_id': 'CVE-2023-67890',
            'severity': 'CRITICAL',
            'cvss_score': 9.8,
            'description': 'Buffer overflow vulnerability in network service allows remote code execution.',
            'root_cause': 'Lack of bounds checking when copying user input to fixed-size buffer.',
            'fix_strategy': 'Implement proper bounds checking and use safe string functions like strncpy instead of strcpy.'
        }
        
        context = formatter.format_single_cve(partial_cve)
        print(context)
        print()
        print()
        
        # Test 3: CVE without VUL-RAG enrichment (fallback)
        print("Test 3: CVE without VUL-RAG enrichment (fallback)")
        print("-" * 80)
        basic_cve = {
            'cve_id': 'CVE-2023-11111',
            'severity': 'MEDIUM',
            'cvss_score': 5.3,
            'cwe': 'CWE-20',
            'description': 'Improper input validation in authentication module.'
        }
        
        context = formatter.format_single_cve(basic_cve)
        print(context)
        print()
        print()
        
        # Test 4: Multiple CVEs
        print("Test 4: Multiple CVEs")
        print("-" * 80)
        cve_list = [
            {
                'cve_id': 'CVE-2023-AAA',
                'description': 'SQL injection vulnerability',
                'root_cause': 'Unparameterized SQL queries',
                'fix_strategy': 'Use prepared statements'
            },
            {
                'cve_id': 'CVE-2023-BBB',
                'description': 'Path traversal vulnerability',
                'root_cause': 'Insufficient path validation',
                'fix_strategy': 'Validate and sanitize file paths'
            }
        ]
        
        context = formatter.format_multiple_cves(cve_list)
        print(context)
        print()
        print()
        
        # Test 5: Patch generation format
        print("Test 5: Patch generation format")
        print("-" * 80)
        code = """
def search(query):
    results = db.execute("SELECT * FROM items WHERE name = '" + query + "'")
    return results
"""
        
        patch_prompt = formatter.format_for_patch_generation(
            {
                'cve_id': 'CVE-2023-SQL',
                'description': 'SQL injection in search function',
                'root_cause': 'String concatenation in SQL query',
                'fix_strategy': 'Use parameterized queries',
                'vulnerability_type': 'SQL Injection'
            },
            code
        )
        print(patch_prompt)
        print()
        
        print("✓ All tests completed successfully!")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
