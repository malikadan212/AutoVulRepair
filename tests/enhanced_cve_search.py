"""
Enhanced CVE Search with VUL-RAG Enrichment

Extends the standard FAISS CVE search to include VUL-RAG enrichment data
(root causes, fix strategies, code patterns, attack conditions).

Usage:
    from enhanced_cve_search import EnhancedFAISSCVESearch
    
    searcher = EnhancedFAISSCVESearch('cve-vulrag')
    results = searcher.search_with_enrichment("SQL injection", top_k=5)
    
    for result in results:
        print(f"{result['cve_id']}: {result.get('fix_strategy', 'N/A')}")
"""

import sqlite3
from typing import List, Dict, Optional, Any, Union
from search_cve_faiss import FAISSCVESearch
from fix_context_formatter import FixContextFormatter


class EnhancedFAISSCVESearch(FAISSCVESearch):
    """
    Enhanced CVE search that includes VUL-RAG enrichment data.
    
    Extends FAISSCVESearch to retrieve and merge VUL-RAG fields
    (root_cause, fix_strategy, code_pattern, attack_condition, vulnerability_type)
    with standard CVE search results.
    """
    
    def __init__(self, index_name: str, index_dir: str = 'faiss_indexes', db_path: str = 'cves.db'):
        """
        Initialize enhanced search with VUL-RAG support.
        
        Args:
            index_name: Name of the FAISS index to use
            index_dir: Directory containing FAISS indexes
            db_path: Path to SQLite database with vulrag_enrichment table
        """
        super().__init__(index_name, index_dir)
        self.db_path = db_path
        self.formatter = FixContextFormatter()
    
    def search_with_enrichment(
        self, 
        query: str, 
        top_k: int = 10, 
        severity_filter: str = None, 
        min_cvss: float = None
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs and return results with VUL-RAG enrichment data.
        
        Args:
            query: Natural language search query
            top_k: Number of results to return
            severity_filter: Filter by severity (HIGH, MEDIUM, LOW, CRITICAL)
            min_cvss: Minimum CVSS score
        
        Returns:
            List of CVE dictionaries with standard fields plus VUL-RAG enrichment:
            - Standard fields: cve_id, score, severity, cvss_score, cwe, published_date, description
            - VUL-RAG fields: vulnerability_type, root_cause, fix_strategy, code_pattern, attack_condition
        """
        # Get standard search results
        results = self.search(query, top_k, severity_filter, min_cvss)
        
        if not results:
            return results
        
        # Extract CVE IDs
        cve_ids = [result['cve_id'] for result in results]
        
        # Load VUL-RAG enrichment data
        enrichment_data = self._load_vulrag_data(cve_ids)
        
        # Merge enrichment with results
        enriched_results = self._merge_results_with_enrichment(results, enrichment_data)
        
        return enriched_results
    
    def _load_vulrag_data(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Load VUL-RAG enrichment data from database for given CVE IDs.
        
        Args:
            cve_ids: List of CVE IDs to fetch enrichment for
        
        Returns:
            Dictionary mapping CVE ID to enrichment data dict.
            CVEs without enrichment are not included in the result.
        """
        if not cve_ids:
            return {}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Create placeholders for SQL IN clause
            placeholders = ','.join('?' * len(cve_ids))
            
            # Query enrichment data
            query = f"""
                SELECT 
                    cve_id,
                    cwe_id,
                    vulnerability_type,
                    root_cause,
                    attack_condition,
                    fix_strategy,
                    code_pattern
                FROM vulrag_enrichment
                WHERE cve_id IN ({placeholders})
            """
            
            cursor.execute(query, cve_ids)
            rows = cursor.fetchall()
            
            # Build enrichment dictionary
            enrichment = {}
            for row in rows:
                enrichment[row[0]] = {
                    'cwe_id': row[1],
                    'vulnerability_type': row[2],
                    'root_cause': row[3],
                    'attack_condition': row[4],
                    'fix_strategy': row[5],
                    'code_pattern': row[6]
                }
            
            return enrichment
            
        finally:
            conn.close()
    
    def _merge_results_with_enrichment(
        self, 
        results: List[Dict[str, Any]], 
        enrichment: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Merge VUL-RAG enrichment data with search results.
        
        Args:
            results: List of standard search results
            enrichment: Dictionary of enrichment data keyed by CVE ID
        
        Returns:
            List of results with VUL-RAG fields added.
            CVEs without enrichment have VUL-RAG fields set to None.
        """
        enriched_results = []
        
        for result in results:
            cve_id = result['cve_id']
            
            # Create enriched result with all standard fields
            enriched_result = result.copy()
            
            # Add VUL-RAG fields
            if cve_id in enrichment:
                # CVE has enrichment data
                vulrag_data = enrichment[cve_id]
                enriched_result['vulnerability_type'] = vulrag_data.get('vulnerability_type')
                enriched_result['root_cause'] = vulrag_data.get('root_cause')
                enriched_result['fix_strategy'] = vulrag_data.get('fix_strategy')
                enriched_result['code_pattern'] = vulrag_data.get('code_pattern')
                enriched_result['attack_condition'] = vulrag_data.get('attack_condition')
            else:
                # CVE has no enrichment - set fields to None
                enriched_result['vulnerability_type'] = None
                enriched_result['root_cause'] = None
                enriched_result['fix_strategy'] = None
                enriched_result['code_pattern'] = None
                enriched_result['attack_condition'] = None
            
            enriched_results.append(enriched_result)
        
        return enriched_results
    
    def get_fix_context_single(self, cve_id: str) -> Optional[str]:
        """
        Get formatted fix context for a single CVE.
        
        Retrieves CVE data and VUL-RAG enrichment, then formats it
        for LLM consumption using FixContextFormatter.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2023-12345')
        
        Returns:
            Formatted fix context string, or None if CVE not found
        """
        # Get CVE data from metadata
        cve_data = None
        for entry in self.metadata:
            if entry.get('cve_id') == cve_id:
                cve_data = entry.copy()
                break
        
        if not cve_data:
            return None
        
        # Load VUL-RAG enrichment
        enrichment_data = self._load_vulrag_data([cve_id])
        
        # Merge enrichment if available
        if cve_id in enrichment_data:
            vulrag_data = enrichment_data[cve_id]
            cve_data['vulnerability_type'] = vulrag_data.get('vulnerability_type')
            cve_data['root_cause'] = vulrag_data.get('root_cause')
            cve_data['fix_strategy'] = vulrag_data.get('fix_strategy')
            cve_data['code_pattern'] = vulrag_data.get('code_pattern')
            cve_data['attack_condition'] = vulrag_data.get('attack_condition')
        
        # Format using FixContextFormatter
        return self.formatter.format_single_cve(cve_data)
    
    def get_fix_context(self, cve_ids: Union[str, List[str]]) -> str:
        """
        Get formatted fix context for one or more CVEs.
        
        Handles both single CVE IDs (as string) and lists of CVE IDs.
        Retrieves CVE data and VUL-RAG enrichment, then formats for
        LLM consumption.
        
        Args:
            cve_ids: Single CVE ID string or list of CVE IDs
        
        Returns:
            Formatted fix context string. For multiple CVEs, contexts
            are concatenated with clear delimiters. Returns empty string
            if no CVEs found.
        """
        # Handle single CVE ID as string
        if isinstance(cve_ids, str):
            result = self.get_fix_context_single(cve_ids)
            return result if result else ""
        
        # Handle list of CVE IDs
        if not cve_ids:
            return ""
        
        # Get CVE data for all requested IDs
        cve_data_list = []
        for cve_id in cve_ids:
            # Find CVE in metadata
            for entry in self.metadata:
                if entry.get('cve_id') == cve_id:
                    cve_data_list.append(entry.copy())
                    break
        
        if not cve_data_list:
            return ""
        
        # Load VUL-RAG enrichment for all CVEs
        enrichment_data = self._load_vulrag_data(cve_ids)
        
        # Merge enrichment with CVE data
        for cve_data in cve_data_list:
            cve_id = cve_data['cve_id']
            if cve_id in enrichment_data:
                vulrag_data = enrichment_data[cve_id]
                cve_data['vulnerability_type'] = vulrag_data.get('vulnerability_type')
                cve_data['root_cause'] = vulrag_data.get('root_cause')
                cve_data['fix_strategy'] = vulrag_data.get('fix_strategy')
                cve_data['code_pattern'] = vulrag_data.get('code_pattern')
                cve_data['attack_condition'] = vulrag_data.get('attack_condition')
        
        # Format using FixContextFormatter
        return self.formatter.format_multiple_cves(cve_data_list)


def main():
    """Example usage of EnhancedFAISSCVESearch"""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description='Search CVEs with VUL-RAG enrichment')
    parser.add_argument('--index-name', required=True, help='Name of the FAISS index')
    parser.add_argument('--query', required=True, help='Search query')
    parser.add_argument('--top-k', type=int, default=10, help='Number of results')
    parser.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 
                       help='Filter by severity')
    parser.add_argument('--min-cvss', type=float, help='Minimum CVSS score')
    parser.add_argument('--db-path', default='cves.db', help='Path to CVE database')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    try:
        # Initialize enhanced searcher
        searcher = EnhancedFAISSCVESearch(args.index_name, db_path=args.db_path)
        
        print(f"\nSearching for: '{args.query}'")
        if args.severity:
            print(f"Filter: Severity = {args.severity}")
        if args.min_cvss:
            print(f"Filter: CVSS >= {args.min_cvss}")
        
        # Search with enrichment
        results = searcher.search_with_enrichment(
            args.query,
            top_k=args.top_k,
            severity_filter=args.severity,
            min_cvss=args.min_cvss
        )
        
        if args.json:
            # Output as JSON
            print(json.dumps(results, indent=2))
        else:
            # Display formatted results
            print(f"\n{'='*80}")
            print(f"Found {len(results)} results")
            print(f"{'='*80}\n")
            
            for i, result in enumerate(results, 1):
                print(f"{i}. {result['cve_id']}")
                print(f"   Similarity Score: {result['score']:.4f}")
                print(f"   Severity: {result['severity']}")
                
                if result.get('cvss_score'):
                    print(f"   CVSS Score: {result['cvss_score']}")
                
                if result.get('cwe'):
                    print(f"   CWE: {result['cwe']}")
                
                print(f"   Published: {result.get('published_date', 'N/A')[:10]}")
                print(f"   Description: {result['description'][:150]}...")
                
                # Display VUL-RAG enrichment if available
                if result.get('vulnerability_type'):
                    print(f"\n   VUL-RAG Enrichment:")
                    print(f"   - Type: {result['vulnerability_type']}")
                    
                    if result.get('root_cause'):
                        print(f"   - Root Cause: {result['root_cause'][:100]}...")
                    
                    if result.get('fix_strategy'):
                        print(f"   - Fix Strategy: {result['fix_strategy'][:100]}...")
                    
                    if result.get('attack_condition'):
                        print(f"   - Attack Condition: {result['attack_condition'][:100]}...")
                else:
                    print(f"   (No VUL-RAG enrichment available)")
                
                print()
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
