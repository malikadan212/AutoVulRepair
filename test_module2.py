#!/usr/bin/env python3
"""
Quick test script for Module 2 Component 1
Tests the fuzz plan generation pipeline
"""
import os
import json
from src.fuzz_plan.generator import FuzzPlanGenerator

def test_fuzz_plan_generation():
    """Test fuzz plan generation from static findings"""
    print("=" * 60)
    print("Testing Module 2 - Component 1: Fuzz Plan Generator")
    print("=" * 60)
    
    # Test with the reference static_findings.json
    findings_path = "static_findings.json"
    output_path = "test_fuzzplan.json"
    
    if not os.path.exists(findings_path):
        print(f"❌ Error: {findings_path} not found")
        return False
    
    print(f"\n✓ Found static findings: {findings_path}")
    
    # Generate fuzz plan
    print("\n[TEST] Generating fuzz plan...")
    generator = FuzzPlanGenerator(findings_path)
    generator.save_fuzz_plan(output_path)
    
    # Verify output
    if not os.path.exists(output_path):
        print(f"❌ Error: Output file not created: {output_path}")
        return False
    
    print(f"✓ Fuzz plan generated: {output_path}")
    
    # Load and validate
    with open(output_path, 'r', encoding='utf-8') as f:
        fuzz_plan = json.load(f)
    
    print("\n" + "=" * 60)
    print("Fuzz Plan Summary")
    print("=" * 60)
    print(f"Version: {fuzz_plan['version']}")
    print(f"Total Findings: {fuzz_plan['metadata']['total_findings']}")
    print(f"Deduplicated Targets: {fuzz_plan['metadata']['deduplicated_targets']}")
    print(f"\nBug Class Breakdown:")
    for bug_class, count in fuzz_plan['metadata']['bug_class_breakdown'].items():
        print(f"  - {bug_class}: {count}")
    print(f"\nSanitizers Used: {', '.join(fuzz_plan['metadata']['sanitizers_used'])}")
    
    print("\n" + "=" * 60)
    print("Top 5 Priority Targets")
    print("=" * 60)
    for i, target in enumerate(fuzz_plan['targets'][:5], 1):
        print(f"\n{i}. {target['function_name']}()")
        print(f"   Bug Class: {target['bug_class']}")
        print(f"   Priority: {target['priority']}")
        print(f"   Sanitizers: {', '.join(target['sanitizers'])}")
        print(f"   Harness Type: {target['harness_type']}")
    
    print("\n" + "=" * 60)
    print("✅ All tests passed!")
    print("=" * 60)
    
    # Cleanup
    os.remove(output_path)
    print(f"\n✓ Cleaned up test file: {output_path}")
    
    return True

if __name__ == '__main__':
    success = test_fuzz_plan_generation()
    exit(0 if success else 1)
