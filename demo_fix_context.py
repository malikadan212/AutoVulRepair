"""
Demo: Fix Context Formatter Integration

Demonstrates how the FixContextFormatter integrates with EnhancedFAISSCVESearch
to provide comprehensive vulnerability context for LLM-based patch generation.
"""

import sqlite3
from fix_context_formatter import FixContextFormatter


def demo_with_sample_data():
    """Demonstrate fix context formatting with sample CVE data"""
    
    print("=" * 80)
    print("Fix Context Formatter Demo")
    print("=" * 80)
    print()
    
    formatter = FixContextFormatter()
    
    # Sample CVE data as would be returned from EnhancedFAISSCVESearch
    sample_cves = [
        {
            'cve_id': 'CVE-2023-12345',
            'score': 0.8542,
            'severity': 'HIGH',
            'cvss_score': 7.5,
            'cwe': 'CWE-79',
            'description': 'Cross-site scripting (XSS) vulnerability in web application allows remote attackers to inject arbitrary web script or HTML via the search parameter.',
            'vulnerability_type': 'Cross-Site Scripting (XSS)',
            'root_cause': 'Insufficient input validation and output encoding on user-supplied data in the search functionality.',
            'attack_condition': 'Attacker can inject malicious JavaScript code through the search parameter, which is reflected in the page without proper sanitization.',
            'fix_strategy': 'Implement proper input validation to reject malicious patterns and apply context-aware output encoding (HTML entity encoding) for all user-supplied data before rendering in HTML context.',
            'code_pattern': 'Direct insertion of user input into HTML without escaping: response.write("<div>" + searchQuery + "</div>")'
        },
        {
            'cve_id': 'CVE-2023-67890',
            'score': 0.7821,
            'severity': 'CRITICAL',
            'cvss_score': 9.8,
            'description': 'Buffer overflow vulnerability in network service allows remote code execution.',
            'root_cause': 'Lack of bounds checking when copying user input to fixed-size buffer.',
            'fix_strategy': 'Implement proper bounds checking and use safe string functions like strncpy instead of strcpy.',
            'vulnerability_type': 'Buffer Overflow'
        },
        {
            'cve_id': 'CVE-2023-11111',
            'score': 0.6543,
            'severity': 'MEDIUM',
            'cvss_score': 5.3,
            'cwe': 'CWE-20',
            'description': 'Improper input validation in authentication module allows bypass of security checks.'
        }
    ]
    
    # Demo 1: Format single CVE with complete enrichment
    print("Demo 1: Single CVE with Complete VUL-RAG Enrichment")
    print("-" * 80)
    context = formatter.format_single_cve(sample_cves[0])
    print(context)
    print()
    print()
    
    # Demo 2: Format single CVE with partial enrichment
    print("Demo 2: Single CVE with Partial VUL-RAG Enrichment")
    print("-" * 80)
    context = formatter.format_single_cve(sample_cves[1])
    print(context)
    print()
    print()
    
    # Demo 3: Format single CVE without enrichment (fallback)
    print("Demo 3: Single CVE without VUL-RAG Enrichment (Fallback)")
    print("-" * 80)
    context = formatter.format_single_cve(sample_cves[2])
    print(context)
    print()
    print()
    
    # Demo 4: Format multiple CVEs
    print("Demo 4: Multiple CVEs for Comprehensive Context")
    print("-" * 80)
    context = formatter.format_multiple_cves(sample_cves)
    print(context)
    print()
    print()
    
    # Demo 5: Patch generation format
    print("Demo 5: Patch Generation Format")
    print("-" * 80)
    vulnerable_code = """
def search_users(query):
    # Vulnerable: Direct string concatenation in SQL query
    sql = "SELECT * FROM users WHERE username = '" + query + "'"
    results = db.execute(sql)
    return results
"""
    
    patch_prompt = formatter.format_for_patch_generation(
        sample_cves[0],
        vulnerable_code
    )
    print(patch_prompt)
    print()
    
    print("=" * 80)
    print("Demo Complete!")
    print("=" * 80)


def demo_integration_pattern():
    """Show how to integrate with EnhancedFAISSCVESearch"""
    
    print()
    print("=" * 80)
    print("Integration Pattern Example")
    print("=" * 80)
    print()
    
    print("Example code showing how to use FixContextFormatter with EnhancedFAISSCVESearch:")
    print()
    
    code_example = """
from enhanced_cve_search import EnhancedFAISSCVESearch
from fix_context_formatter import FixContextFormatter

# Initialize search and formatter
searcher = EnhancedFAISSCVESearch('cve-vulrag')
formatter = FixContextFormatter()

# Search for relevant CVEs
query = "SQL injection vulnerabilities"
results = searcher.search_with_enrichment(query, top_k=5)

# Format fix context for LLM
if results:
    # Single CVE context
    single_context = formatter.format_single_cve(results[0])
    
    # Multiple CVE context
    multi_context = formatter.format_multiple_cves(results)
    
    # Patch generation prompt
    vulnerable_code = "..."  # Your vulnerable code
    patch_prompt = formatter.format_for_patch_generation(
        results[0], 
        vulnerable_code
    )
    
    # Send to LLM for patch generation
    # llm_response = llm.generate(patch_prompt)
"""
    
    print(code_example)
    print()


if __name__ == '__main__':
    demo_with_sample_data()
    demo_integration_pattern()
