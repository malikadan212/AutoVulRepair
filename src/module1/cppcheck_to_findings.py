#!/usr/bin/env python3
"""
Convert Cppcheck XML output to standardized static_findings.json format
This bridges Module 1 (static analysis) to Module 2 (fuzzing)
"""
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


def parse_cppcheck_xml(xml_path: str) -> List[Dict[str, Any]]:
    """Parse Cppcheck XML and extract findings"""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    findings = []
    
    for error in root.findall('.//error'):
        error_id = error.get('id', 'unknown')
        severity = error.get('severity', 'unknown')
        msg = error.get('msg', '')
        cwe = error.get('cwe', '')
        
        # Get primary location (first location element)
        locations = error.findall('location')
        if not locations:
            continue
            
        primary_loc = locations[0]
        file_path = primary_loc.get('file', '')
        line = primary_loc.get('line', '0')
        column = primary_loc.get('column', '0')
        
        # Extract function name from file path if possible
        # Format: /source/test.cpp -> test.cpp -> test
        file_name = Path(file_path).name if file_path else 'unknown'
        file_stem = Path(file_path).stem if file_path else 'unknown'
        
        # Map severity to confidence
        confidence_map = {
            'error': 'high',
            'warning': 'medium',
            'style': 'low',
            'information': 'low'
        }
        confidence = confidence_map.get(severity, 'medium')
        
        # Map severity to priority score
        severity_score_map = {
            'error': 9.0,
            'warning': 6.0,
            'style': 3.0,
            'information': 1.0
        }
        base_score = severity_score_map.get(severity, 5.0)
        
        finding = {
            'finding_id': f"{file_stem}_{error_id}_{line}",
            'rule_id': error_id,
            'severity': severity,
            'confidence': confidence,
            'message': msg,
            'cwe': cwe,
            'file': file_path,
            'file_name': file_name,
            'file_stem': file_stem,
            'line': int(line) if line.isdigit() else 0,
            'column': int(column) if column.isdigit() else 0,
            'function': 'unknown',  # Cppcheck doesn't always provide function name
            'priority_score': base_score,
            'locations': [
                {
                    'file': loc.get('file', ''),
                    'line': int(loc.get('line', '0')) if loc.get('line', '0').isdigit() else 0,
                    'column': int(loc.get('column', '0')) if loc.get('column', '0').isdigit() else 0,
                    'info': loc.get('info', '')
                }
                for loc in locations
            ]
        }
        
        findings.append(finding)
    
    return findings


def infer_function_from_error_id(error_id: str, file_stem: str) -> str:
    """
    Infer likely function name from error ID and file stem
    This is a heuristic - in real implementation, would parse source code
    """
    # Common patterns in the test file
    function_patterns = {
        'arrayIndexOutOfBounds': 'test_array_bounds_overflow',
        'bufferAccessOutOfBounds': 'test_sprintf_overflow',
        'getsCalled': 'test_gets_vulnerability',
        'memleak': 'test_malloc_memory_leak',
        'doubleFree': 'test_double_free',
        'resourceLeak': 'test_file_handle_leak',
        'nullPointer': 'test_null_pointer_dereference',
        'integerOverflow': 'test_integer_overflow',
        'uninitvar': 'test_uninitialized_variables',
    }
    
    return function_patterns.get(error_id, f"{file_stem}_function")


def filter_relevant_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter findings to only include those relevant for fuzzing
    Exclude style issues, unused functions, etc.
    """
    # Error IDs that are fuzzable vulnerabilities
    fuzzable_ids = {
        'arrayIndexOutOfBounds', 'bufferAccessOutOfBounds', 'getsCalled',
        'memleak', 'doubleFree', 'resourceLeak', 'nullPointer',
        'integerOverflow', 'uninitvar', 'useAfterFree'
    }
    
    # Severity levels to include
    relevant_severities = {'error', 'warning'}
    
    filtered = []
    for finding in findings:
        if (finding['rule_id'] in fuzzable_ids or 
            finding['severity'] in relevant_severities):
            # Infer function name
            finding['function'] = infer_function_from_error_id(
                finding['rule_id'], 
                finding['file_stem']
            )
            filtered.append(finding)
    
    return filtered


def convert_cppcheck_to_findings(xml_path: str, output_path: str) -> Dict[str, Any]:
    """
    Main conversion function
    Converts Cppcheck XML to static_findings.json
    """
    print(f"[CONVERTER] Parsing Cppcheck XML: {xml_path}")
    findings = parse_cppcheck_xml(xml_path)
    print(f"[CONVERTER] Found {len(findings)} total findings")
    
    # Filter to relevant findings
    relevant_findings = filter_relevant_findings(findings)
    print(f"[CONVERTER] Filtered to {len(relevant_findings)} fuzzable findings")
    
    # Create output structure
    output = {
        'version': '1.0',
        'generated_at': datetime.now().isoformat(),
        'tool': 'cppcheck',
        'tool_version': '2.7',
        'total_findings': len(relevant_findings),
        'findings': relevant_findings,
        'metadata': {
            'source_files': list(set(f['file'] for f in relevant_findings)),
            'severity_breakdown': {},
            'rule_id_breakdown': {}
        }
    }
    
    # Calculate breakdowns
    for finding in relevant_findings:
        severity = finding['severity']
        rule_id = finding['rule_id']
        
        output['metadata']['severity_breakdown'][severity] = \
            output['metadata']['severity_breakdown'].get(severity, 0) + 1
        output['metadata']['rule_id_breakdown'][rule_id] = \
            output['metadata']['rule_id_breakdown'].get(rule_id, 0) + 1
    
    # Write output
    print(f"[CONVERTER] Writing static_findings.json to: {output_path}")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    
    print(f"[CONVERTER] Conversion complete!")
    print(f"[CONVERTER] Severity breakdown: {output['metadata']['severity_breakdown']}")
    print(f"[CONVERTER] Rule ID breakdown: {output['metadata']['rule_id_breakdown']}")
    
    return output


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cppcheck_to_findings.py <cppcheck-xml-path> [output-path]")
        sys.exit(1)
    
    xml_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'static_findings.json'
    
    convert_cppcheck_to_findings(xml_path, output_path)
