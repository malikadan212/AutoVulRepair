#!/usr/bin/env python3
"""
Search Enhanced CVE - Command-Line Tool

Search CVEs with VUL-RAG enrichment data including root causes, fix strategies,
code patterns, and attack conditions. Supports filtering by severity and CVSS score.

Usage:
    python search_enhanced_cve.py --query "SQL injection"
    python search_enhanced_cve.py --query "buffer overflow" --top-k 5
    python search_enhanced_cve.py --query "XSS" --severity HIGH --min-cvss 7.0
    python search_enhanced_cve.py --query "input validation" --json
    python search_enhanced_cve.py --fix-context CVE-2023-12345

Requirements: 6.1, 6.2, 6.3
"""

import argparse
import sys
import json
import os
from enhanced_cve_search import EnhancedFAISSCVESearch


def print_banner():
    """Print application banner"""
    print("=" * 80)
    print("Enhanced CVE Search with VUL-RAG Enrichment")
    print("Search vulnerabilities with fix strategies and root cause analysis")
    print("=" * 80)
    print()


def search_cves(args):
    """
    Search CVEs with enrichment
    
    Args:
        args: Parsed command-line arguments
    """
    try:
        # Initialize searcher
        if args.verbose:
            print(f"Loading index: {args.index_name}")
            print(f"Database: {args.db_path}")
            print()
        
        searcher = EnhancedFAISSCVESearch(
            index_name=args.index_name,
            index_dir=args.index_dir,
            db_path=args.db_path
        )
        
        if args.verbose:
            print(f"✓ Index loaded: {len(searcher.metadata):,} CVEs")
            print()
        
        # Display search parameters
        if not args.json:
            print(f"Query: '{args.query}'")
            print(f"Results: Top {args.top_k}")
            
            if args.severity:
                print(f"Severity filter: {args.severity}")
            if args.min_cvss:
                print(f"Minimum CVSS: {args.min_cvss}")
            
            print()
            print("Searching...")
            print()
        
        # Perform search
        results = searcher.search_with_enrichment(
            query=args.query,
            top_k=args.top_k,
            severity_filter=args.severity,
            min_cvss=args.min_cvss
        )
        
        # Output results
        if args.json:
            # JSON output
            print(json.dumps(results, indent=2))
        else:
            # Human-readable output
            display_results(results, args)
        
        return 0
        
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        print()
        print("Available indexes:")
        if os.path.exists(args.index_dir):
            for file in os.listdir(args.index_dir):
                if file.endswith('.index'):
                    print(f"  - {file.replace('.index', '')}")
        return 1
    except Exception as e:
        print(f"✗ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def display_results(results, args):
    """
    Display search results in human-readable format
    
    Args:
        results: List of search result dictionaries
        args: Parsed command-line arguments
    """
    print("=" * 80)
    print(f"Found {len(results)} results")
    print("=" * 80)
    print()
    
    if not results:
        print("No matching CVEs found.")
        print()
        print("Tips:")
        print("  - Try different search terms")
        print("  - Remove or adjust filters (--severity, --min-cvss)")
        print("  - Use broader queries")
        return
    
    for i, result in enumerate(results, 1):
        # Header
        print(f"{i}. {result['cve_id']}")
        print("-" * 80)
        
        # Basic info
        print(f"Similarity Score: {result['score']:.4f}")
        print(f"Severity: {result['severity']}")
        
        if result.get('cvss_score'):
            print(f"CVSS Score: {result['cvss_score']}")
        
        if result.get('cwe'):
            print(f"CWE: {result['cwe']}")
        
        if result.get('published_date'):
            print(f"Published: {result['published_date'][:10]}")
        
        print()
        
        # Description
        desc = result['description']
        if len(desc) > 200 and not args.full:
            desc = desc[:200] + "..."
        print(f"Description:")
        print(f"  {desc}")
        print()
        
        # VUL-RAG enrichment
        has_enrichment = any([
            result.get('vulnerability_type'),
            result.get('root_cause'),
            result.get('fix_strategy'),
            result.get('code_pattern'),
            result.get('attack_condition')
        ])
        
        if has_enrichment:
            print("VUL-RAG Enrichment:")
            
            if result.get('vulnerability_type'):
                print(f"  Type: {result['vulnerability_type']}")
            
            if result.get('root_cause'):
                root_cause = result['root_cause']
                if len(root_cause) > 150 and not args.full:
                    root_cause = root_cause[:150] + "..."
                print(f"  Root Cause: {root_cause}")
            
            if result.get('fix_strategy'):
                fix_strategy = result['fix_strategy']
                if len(fix_strategy) > 150 and not args.full:
                    fix_strategy = fix_strategy[:150] + "..."
                print(f"  Fix Strategy: {fix_strategy}")
            
            if result.get('attack_condition'):
                attack_cond = result['attack_condition']
                if len(attack_cond) > 150 and not args.full:
                    attack_cond = attack_cond[:150] + "..."
                print(f"  Attack Condition: {attack_cond}")
            
            if result.get('code_pattern') and args.full:
                print(f"  Code Pattern: {result['code_pattern']}")
        else:
            print("(No VUL-RAG enrichment available)")
        
        print()
    
    # Summary
    enriched_count = sum(1 for r in results if r.get('root_cause') or r.get('fix_strategy'))
    if enriched_count > 0:
        print(f"Note: {enriched_count} of {len(results)} results have VUL-RAG enrichment")
        print()


def get_fix_context(args):
    """
    Get fix context for specific CVE(s)
    
    Args:
        args: Parsed command-line arguments
    """
    try:
        # Initialize searcher
        searcher = EnhancedFAISSCVESearch(
            index_name=args.index_name,
            index_dir=args.index_dir,
            db_path=args.db_path
        )
        
        # Parse CVE IDs
        cve_ids = [cve.strip() for cve in args.fix_context.split(',')]
        
        if args.verbose:
            print(f"Retrieving fix context for: {', '.join(cve_ids)}")
            print()
        
        # Get fix context
        if len(cve_ids) == 1:
            context = searcher.get_fix_context_single(cve_ids[0])
        else:
            context = searcher.get_fix_context(cve_ids)
        
        if context:
            print(context)
            return 0
        else:
            print(f"✗ No data found for CVE(s): {', '.join(cve_ids)}")
            return 1
        
    except Exception as e:
        print(f"✗ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def list_indexes(args):
    """
    List available FAISS indexes
    
    Args:
        args: Parsed command-line arguments
    """
    print("Available FAISS Indexes:")
    print("=" * 80)
    print()
    
    if not os.path.exists(args.index_dir):
        print(f"Index directory not found: {args.index_dir}")
        return 1
    
    # Find all index files
    indexes = []
    for file in os.listdir(args.index_dir):
        if file.endswith('.index'):
            index_name = file.replace('.index', '')
            info_file = os.path.join(args.index_dir, f'{index_name}.info')
            
            # Load info if available
            info = {}
            if os.path.exists(info_file):
                try:
                    with open(info_file, 'r') as f:
                        info = json.load(f)
                except:
                    pass
            
            indexes.append((index_name, info))
    
    if not indexes:
        print("No indexes found.")
        print()
        print("To create an enhanced index:")
        print("  python create_enhanced_index.py")
        return 1
    
    # Display indexes
    for index_name, info in sorted(indexes):
        print(f"• {index_name}")
        
        if info:
            if info.get('total_vectors'):
                print(f"  Vectors: {info['total_vectors']:,}")
            if info.get('dimension'):
                print(f"  Dimension: {info['dimension']}")
            if info.get('vulrag_enrichment'):
                print(f"  VUL-RAG Enrichment: Yes")
                if 'enrichment_stats' in info:
                    stats = info['enrichment_stats']
                    enriched = stats.get('enriched_cves', 0)
                    total = stats.get('total_cves', 0)
                    if total > 0:
                        pct = enriched / total * 100
                        print(f"  Enrichment Coverage: {enriched:,} / {total:,} ({pct:.1f}%)")
            else:
                print(f"  VUL-RAG Enrichment: No")
        
        print()
    
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Search CVEs with VUL-RAG enrichment data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic search
  python search_enhanced_cve.py --query "SQL injection"
  
  # Search with filters
  python search_enhanced_cve.py --query "buffer overflow" --severity HIGH --min-cvss 7.0
  
  # Get more results
  python search_enhanced_cve.py --query "XSS" --top-k 20
  
  # JSON output for programmatic use
  python search_enhanced_cve.py --query "input validation" --json
  
  # Get fix context for specific CVE
  python search_enhanced_cve.py --fix-context CVE-2023-12345
  
  # Get fix context for multiple CVEs
  python search_enhanced_cve.py --fix-context "CVE-2023-1,CVE-2023-2,CVE-2023-3"
  
  # List available indexes
  python search_enhanced_cve.py --list-indexes
  
  # Use custom index
  python search_enhanced_cve.py --query "RCE" --index-name cve-vulrag-v2

Search Tips:
  - Use natural language queries: "SQL injection fixes", "buffer overflow causes"
  - Search by fix strategy: "input validation", "bounds checking"
  - Search by root cause: "insufficient validation", "memory corruption"
  - Combine terms: "XSS input sanitization"
        """
    )
    
    # Main operation mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--query',
        help='Search query (natural language)'
    )
    mode_group.add_argument(
        '--fix-context',
        help='Get fix context for CVE ID(s) (comma-separated for multiple)'
    )
    mode_group.add_argument(
        '--list-indexes',
        action='store_true',
        help='List available FAISS indexes'
    )
    
    # Search parameters
    parser.add_argument(
        '--top-k',
        type=int,
        default=10,
        help='Number of results to return (default: 10)'
    )
    parser.add_argument(
        '--severity',
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        help='Filter by severity level'
    )
    parser.add_argument(
        '--min-cvss',
        type=float,
        help='Minimum CVSS score (0.0-10.0)'
    )
    
    # Index configuration
    parser.add_argument(
        '--index-name',
        default='cve-vulrag',
        help='Name of FAISS index to use (default: cve-vulrag)'
    )
    parser.add_argument(
        '--index-dir',
        default='faiss_indexes',
        help='Directory containing FAISS indexes (default: faiss_indexes)'
    )
    parser.add_argument(
        '--db-path',
        default='cves.db',
        help='Path to CVE database (default: cves.db)'
    )
    
    # Output options
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    parser.add_argument(
        '--full',
        action='store_true',
        help='Show full text (no truncation)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Print banner (unless JSON output)
    if not args.json:
        print_banner()
    
    # Validate arguments
    if not args.query and not args.fix_context and not args.list_indexes:
        parser.print_help()
        return 1
    
    # Validate CVSS range
    if args.min_cvss is not None:
        if args.min_cvss < 0.0 or args.min_cvss > 10.0:
            print("✗ Error: --min-cvss must be between 0.0 and 10.0")
            return 1
    
    # Execute command
    if args.list_indexes:
        return list_indexes(args)
    elif args.fix_context:
        return get_fix_context(args)
    else:
        return search_cves(args)


if __name__ == '__main__':
    sys.exit(main())
