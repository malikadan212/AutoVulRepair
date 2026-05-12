#!/usr/bin/env python3
"""
Download VUL-RAG Knowledge Base

Downloads vulnerability knowledge from the KnowledgeRAG4LLMVulD repository
and converts it to the format required by our system.

Repository: https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD
Source: vulnerability knowledge folder (organized by CWE)

Usage:
    python download_vulrag_knowledge.py
    python download_vulrag_knowledge.py --output vulrag_knowledge.json
    python download_vulrag_knowledge.py --cwe CWE-79 --cwe CWE-89
"""

import requests
import json
import argparse
import sys
from typing import List, Dict, Any
from pathlib import Path


# GitHub repository information
GITHUB_REPO = "KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD"
GITHUB_BRANCH = "38aa707fdb6bf592f1ed7753e90af400d3b9dcd3"
KNOWLEDGE_PATH = "vulnerability%20knowledge"

# GitHub API base URL
GITHUB_API_BASE = "https://api.github.com/repos"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


def get_cwe_files() -> List[Dict[str, str]]:
    """
    Get list of CWE JSON files from the repository
    
    Returns:
        List of dictionaries with 'name' and 'download_url'
    """
    api_url = f"{GITHUB_API_BASE}/{GITHUB_REPO}/contents/{KNOWLEDGE_PATH}?ref={GITHUB_BRANCH}"
    
    print(f"Fetching file list from GitHub...")
    print(f"URL: {api_url}")
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        
        files = response.json()
        
        # Filter for JSON files
        cwe_files = [
            {
                'name': f['name'],
                'download_url': f['download_url']
            }
            for f in files
            if f['name'].endswith('.json') and f['type'] == 'file'
        ]
        
        print(f"✓ Found {len(cwe_files)} CWE knowledge files")
        return cwe_files
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Error fetching file list: {e}")
        sys.exit(1)


def download_cwe_file(download_url: str, filename: str) -> Dict[str, Any]:
    """
    Download a single CWE knowledge file
    
    Args:
        download_url: URL to download from
        filename: Name of the file (for display)
    
    Returns:
        Parsed JSON data
    """
    try:
        response = requests.get(download_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Error downloading {filename}: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"  ✗ Error parsing {filename}: {e}")
        return None


def convert_to_our_format(cwe_data: Dict[str, Any], cwe_name: str) -> List[Dict[str, Any]]:
    """
    Convert KnowledgeRAG format to our VUL-RAG format
    
    The KnowledgeRAG format contains detailed vulnerability information including:
    - vulnerability_behavior (cause, trigger, specific behavior)
    - solution (fix strategy)
    - CVE_id
    - code_before_change and code_after_change
    - analysis
    
    Args:
        cwe_data: Raw data from CWE JSON file
        cwe_name: CWE identifier (e.g., "CWE-119")
    
    Returns:
        List of vulnerability entries in our format
    """
    converted_entries = []
    
    # The format is a list of vulnerability objects
    if isinstance(cwe_data, list):
        vulnerabilities = cwe_data
    elif isinstance(cwe_data, dict):
        # Check for common keys that might contain the vulnerability list
        if 'vulnerabilities' in cwe_data:
            vulnerabilities = cwe_data['vulnerabilities']
        elif 'cves' in cwe_data:
            vulnerabilities = cwe_data['cves']
        elif 'data' in cwe_data:
            vulnerabilities = cwe_data['data']
        else:
            # Treat the whole object as a single vulnerability
            vulnerabilities = [cwe_data]
    else:
        return converted_entries
    
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        
        # Extract CVE ID
        cve_id = vuln.get('CVE_id') or vuln.get('cve_id') or vuln.get('CVE_ID')
        
        if not cve_id:
            continue
        
        # Ensure CVE ID format
        if not str(cve_id).startswith('CVE-'):
            cve_id = f"CVE-{cve_id}"
        
        # Extract vulnerability behavior information
        vuln_behavior = vuln.get('vulnerability_behavior', {})
        if isinstance(vuln_behavior, dict):
            root_cause = vuln_behavior.get('vulnerability_cause_description', '')
            trigger_condition = vuln_behavior.get('trigger_condition', '')
            specific_behavior = vuln_behavior.get('specific_code_behavior_causing_vulnerability', '')
        else:
            root_cause = vuln.get('vulnerability_cause_description', '')
            trigger_condition = vuln.get('trigger_condition', '')
            specific_behavior = vuln.get('specific_code_behavior_causing_vulnerability', '')
        
        # Combine root cause information
        root_cause_parts = [p for p in [root_cause, specific_behavior] if p]
        combined_root_cause = ' '.join(root_cause_parts) if root_cause_parts else ''
        
        # Extract solution/fix strategy
        fix_strategy = vuln.get('solution', '')
        
        # Extract attack condition
        attack_condition = trigger_condition
        
        # Extract code pattern from code_before_change
        code_before = vuln.get('code_before_change', '')
        code_after = vuln.get('code_after_change', '')
        
        # Create a code pattern description
        if code_before:
            # Take first 500 chars of vulnerable code as pattern
            code_pattern = code_before[:500] + ('...' if len(code_before) > 500 else '')
        else:
            code_pattern = ''
        
        # Extract description from analysis or purpose
        description = (
            vuln.get('analysis', '') or
            vuln.get('purpose', '') or
            vuln.get('description', '') or
            f"Vulnerability in {cwe_name}"
        )
        
        # Truncate description if too long
        if len(description) > 500:
            description = description[:500] + '...'
        
        # Determine vulnerability type from CWE name
        vuln_type = cwe_name.replace('_', ' ').title()
        
        # Create entry in our format
        entry = {
            'cve_id': cve_id,
            'cwe_id': cwe_name,
            'vulnerability_type': vuln_type,
            'root_cause': combined_root_cause,
            'attack_condition': attack_condition,
            'fix_strategy': fix_strategy,
            'code_pattern': code_pattern,
            'description': description
        }
        
        # Only add if we have at least CVE ID
        if entry['cve_id']:
            converted_entries.append(entry)
    
    return converted_entries


def download_and_convert(cwe_filter: List[str] = None, output_file: str = "vulrag_knowledge.json"):
    """
    Download all CWE knowledge files and convert to our format
    
    Args:
        cwe_filter: Optional list of CWE IDs to download (e.g., ['CWE-79', 'CWE-89'])
        output_file: Output JSON file path
    """
    print("=" * 80)
    print("VUL-RAG Knowledge Base Downloader")
    print("=" * 80)
    print()
    
    # Get list of files
    cwe_files = get_cwe_files()
    
    if not cwe_files:
        print("✗ No CWE files found")
        return
    
    # Filter by CWE if specified
    if cwe_filter:
        cwe_filter_lower = [c.lower() for c in cwe_filter]
        cwe_files = [
            f for f in cwe_files 
            if any(cwe.lower() in f['name'].lower() for cwe in cwe_filter_lower)
        ]
        print(f"Filtered to {len(cwe_files)} files matching: {', '.join(cwe_filter)}")
    
    print()
    print(f"Downloading and converting {len(cwe_files)} files...")
    print()
    
    all_entries = []
    successful = 0
    failed = 0
    
    for file_info in cwe_files:
        filename = file_info['name']
        download_url = file_info['download_url']
        
        # Extract CWE name from filename (e.g., "linux_kernel_CWE-119_knowledge.json" -> "CWE-119")
        import re
        cwe_match = re.search(r'CWE-\d+', filename)
        if cwe_match:
            cwe_name = cwe_match.group(0)
        else:
            # Fallback: use filename without extension
            cwe_name = filename.replace('.json', '').replace('_knowledge', '').upper()
        
        print(f"Processing {filename} ({cwe_name})...")
        
        # Download file
        cwe_data = download_cwe_file(download_url, filename)
        
        if cwe_data is None:
            failed += 1
            continue
        
        # Convert to our format
        entries = convert_to_our_format(cwe_data, cwe_name)
        
        if entries:
            all_entries.extend(entries)
            print(f"  ✓ Converted {len(entries)} vulnerabilities")
            successful += 1
        else:
            print(f"  ⚠ No vulnerabilities extracted")
            failed += 1
    
    print()
    print("=" * 80)
    print("Download Complete")
    print("=" * 80)
    print(f"Files processed: {successful + failed}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Total vulnerabilities: {len(all_entries)}")
    print()
    
    if all_entries:
        # Save to file
        print(f"Saving to {output_file}...")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_entries, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Saved {len(all_entries)} vulnerabilities to {output_file}")
        print()
        print("Next steps:")
        print(f"  1. Review the data: cat {output_file} | head -n 50")
        print(f"  2. Import to database: python import_vulrag_data.py --file {output_file}")
        print(f"  3. Create enhanced index: python create_enhanced_index.py")
    else:
        print("✗ No vulnerabilities were extracted")


def main():
    parser = argparse.ArgumentParser(
        description='Download VUL-RAG knowledge base from KnowledgeRAG repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download all CWE knowledge files
  python download_vulrag_knowledge.py
  
  # Download specific CWEs only
  python download_vulrag_knowledge.py --cwe CWE-79 --cwe CWE-89 --cwe CWE-120
  
  # Specify output file
  python download_vulrag_knowledge.py --output my_vulrag_data.json
  
  # Download and immediately import
  python download_vulrag_knowledge.py && python import_vulrag_data.py --file vulrag_knowledge.json

Repository:
  https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD
  
Note:
  This script requires internet connection to download from GitHub.
  The data format may vary - the script attempts to handle different formats.
        """
    )
    
    parser.add_argument(
        '--output', '-o',
        default='vulrag_knowledge.json',
        help='Output JSON file path (default: vulrag_knowledge.json)'
    )
    parser.add_argument(
        '--cwe',
        action='append',
        help='Download specific CWE only (can be specified multiple times)'
    )
    
    args = parser.parse_args()
    
    try:
        download_and_convert(
            cwe_filter=args.cwe,
            output_file=args.output
        )
    except KeyboardInterrupt:
        print("\n\n✗ Download cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
