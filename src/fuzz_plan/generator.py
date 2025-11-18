#!/usr/bin/env python3
"""
Module 2 - Component 1: Fuzz-Plan Generator
Converts static_findings.json into fuzz/fuzzplan.json

Implements FR1-FR4:
- FR1: Convert static findings to fuzz plan
- FR2: Infer bug class, sanitizers, priority
- FR3: De-duplicate by function
- FR4: Generate complete target metadata
"""
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Set
from collections import defaultdict


class FuzzPlanGenerator:
    """Generates fuzz plans from static analysis findings"""
    
    # Bug class inference from rule IDs (Enhanced with more mappings)
    BUG_CLASS_MAP = {
        # Out-of-Bounds (OOB)
        'arrayIndexOutOfBounds': 'OOB',
        'bufferAccessOutOfBounds': 'OOB',
        'bufferOverflow': 'OOB',
        'outOfBounds': 'OOB',
        'getsCalled': 'OOB',
        'strcpyOverflow': 'OOB',
        'strcatOverflow': 'OOB',
        'sprintfOverflow': 'OOB',
        'memcpyOverflow': 'OOB',
        'arrayIndexThenCheck': 'OOB',
        'possibleBufferAccessOutOfBounds': 'OOB',
        
        # Use-After-Free (UAF) / Memory Issues
        'memleak': 'UAF',
        'memoryLeak': 'UAF',
        'doubleFree': 'UAF',
        'useAfterFree': 'UAF',
        'danglingPointer': 'UAF',
        'invalidPointerFree': 'UAF',
        'mismatchAllocDealloc': 'UAF',
        'deallocDealloc': 'UAF',
        'deallocuse': 'UAF',
        
        # Integer Undefined Behavior
        'integerOverflow': 'Integer-UB',
        'signedIntegerOverflow': 'Integer-UB',
        'unsignedIntegerOverflow': 'Integer-UB',
        'shiftOverflow': 'Integer-UB',
        'shiftTooManyBits': 'Integer-UB',
        'integerDivisionByZero': 'Integer-UB',
        'moduloByZero': 'Integer-UB',
        'negativeIndex': 'Integer-UB',
        
        # Null Pointer Dereference
        'nullPointer': 'Null-Deref',
        'nullDereference': 'Null-Deref',
        'nullPointerArithmetic': 'Null-Deref',
        'nullPointerRedundantCheck': 'Null-Deref',
        'dereferencePossibleNull': 'Null-Deref',
        
        # Format String
        'formatString': 'Format-String',
        'printfFormat': 'Format-String',
        'wrongPrintfScanfArgNum': 'Format-String',
        'invalidPrintfArgType': 'Format-String',
        
        # Resource Leaks
        'resourceLeak': 'Resource-Leak',
        'fileHandleLeak': 'Resource-Leak',
        'socketLeak': 'Resource-Leak',
        'fdLeak': 'Resource-Leak',
        
        # Uninitialized Variables
        'uninitvar': 'Uninit-Var',
        'uninitdata': 'Uninit-Var',
        'uninitStructMember': 'Uninit-Var',
        'uninitMemberVar': 'Uninit-Var',
        
        # Race Conditions / Concurrency
        'dataRace': 'Race-Condition',
        'raceAfterInterlockedDecrement': 'Race-Condition',
        'threadUnsafeFunction': 'Race-Condition',
        
        # Type Confusion
        'invalidPointerCast': 'Type-Confusion',
        'objectIndex': 'Type-Confusion',
        'containerOutOfBounds': 'Type-Confusion',
    }
    
    # Sanitizer selection based on bug class (Enhanced)
    SANITIZER_MAP = {
        'OOB': ['address', 'undefined'],
        'UAF': ['address'],
        'Integer-UB': ['undefined'],
        'Null-Deref': ['address', 'undefined'],
        'Format-String': ['address'],
        'Resource-Leak': ['address'],
        'Uninit-Var': ['memory'],
        'Race-Condition': ['thread'],
        'Type-Confusion': ['address', 'undefined'],
    }
    
    # Seed directory selection (Enhanced)
    SEED_MAP = {
        'OOB': ['fuzz/seeds/parser/', 'fuzz/seeds/generic/'],
        'UAF': ['fuzz/seeds/generic/', 'fuzz/seeds/api/'],
        'Integer-UB': ['fuzz/seeds/api/', 'fuzz/seeds/numeric/'],
        'Null-Deref': ['fuzz/seeds/generic/', 'fuzz/seeds/api/'],
        'Format-String': ['fuzz/seeds/parser/', 'fuzz/seeds/strings/'],
        'Resource-Leak': ['fuzz/seeds/generic/', 'fuzz/seeds/api/'],
        'Uninit-Var': ['fuzz/seeds/generic/'],
        'Race-Condition': ['fuzz/seeds/concurrent/'],
        'Type-Confusion': ['fuzz/seeds/api/', 'fuzz/seeds/generic/'],
    }
    
    # Dictionary selection (Enhanced)
    DICT_MAP = {
        'OOB': ['fuzz/auto.dict', 'fuzz/bounds.dict'],
        'Format-String': ['fuzz/auto.dict', 'fuzz/format.dict'],
        'Integer-UB': ['fuzz/numeric.dict'],
        'Type-Confusion': ['fuzz/types.dict'],
    }
    
    def __init__(self, findings_path: str, max_targets: int = 100):
        """Initialize generator with static findings - Issue #7 fixed"""
        self.findings_path = findings_path
        self.findings_data = None
        self.targets = []
        self.max_targets = max_targets  # Resource limit
        
    def load_findings(self) -> None:
        """Load static findings from JSON"""
        print(f"[FUZZ_PLAN] Loading findings from: {self.findings_path}")
        
        # Check if file exists
        if not Path(self.findings_path).exists():
            raise FileNotFoundError(f"Static findings file not found: {self.findings_path}")
        
        try:
            with open(self.findings_path, 'r', encoding='utf-8') as f:
                self.findings_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in findings file: {e}")
        except Exception as e:
            raise RuntimeError(f"Error reading findings file: {e}")
        
        # Validate basic structure
        if not isinstance(self.findings_data, dict):
            raise ValueError("Findings file must contain a JSON object")
        
        total_findings = self.findings_data.get('total_findings', 0)
        print(f"[FUZZ_PLAN] Loaded {total_findings} findings")
    
    def infer_bug_class(self, rule_id: str) -> str:
        """Infer bug class from rule ID (FR2)"""
        return self.BUG_CLASS_MAP.get(rule_id, 'Unknown')
    
    def select_sanitizers(self, bug_class: str) -> List[str]:
        """Select sanitizers based on bug class (FR2)"""
        return self.SANITIZER_MAP.get(bug_class, ['address'])
    
    def select_seeds(self, bug_class: str) -> List[str]:
        """Select seed directories based on bug class (FR2)"""
        return self.SEED_MAP.get(bug_class, ['fuzz/seeds/generic/'])
    
    def select_dictionaries(self, bug_class: str) -> List[str]:
        """Select dictionaries based on bug class (FR2)"""
        return self.DICT_MAP.get(bug_class, [])
    
    def calculate_priority(self, finding: Dict[str, Any]) -> float:
        """Calculate priority score (FR2) - Enhanced algorithm"""
        # Use validated priority_score or calculate from severity
        base_score = finding.get('priority_score')
        
        if base_score is None or not isinstance(base_score, (int, float)):
            # Calculate from severity if priority_score missing/invalid
            severity = finding.get('severity', 'unknown')
            severity_scores = {
                'error': 9.0,
                'warning': 6.0,
                'style': 3.0,
                'information': 1.0,
                'unknown': 5.0
            }
            base_score = severity_scores.get(severity, 5.0)
        
        # Boost priority for high confidence
        confidence = finding.get('confidence', 'medium')
        confidence_boost = {
            'high': 1.5,
            'medium': 1.0,
            'low': 0.5
        }.get(confidence, 1.0)
        
        # Boost priority for critical bug classes (Enhanced)
        bug_class = self.infer_bug_class(finding.get('rule_id', 'unknown'))
        bug_class_boost = {
            'UAF': 1.3,              # Highest - memory corruption
            'OOB': 1.25,             # Very high - buffer overflows
            'Format-String': 1.2,    # High - code execution
            'Integer-UB': 1.15,      # High - can lead to OOB
            'Type-Confusion': 1.1,   # Medium-high
            'Null-Deref': 1.0,       # Medium - DoS mostly
            'Race-Condition': 0.95,  # Medium - hard to exploit
            'Resource-Leak': 0.9,    # Lower - DoS
            'Uninit-Var': 0.85,      # Lower - unpredictable
        }.get(bug_class, 1.0)
        
        # CWE-based boost (if available)
        cwe = finding.get('cwe', '')
        cwe_boost = 1.0
        if cwe:
            critical_cwes = {
                '119': 1.2,  # Buffer overflow
                '120': 1.2,  # Buffer copy without size check
                '121': 1.2,  # Stack-based buffer overflow
                '122': 1.2,  # Heap-based buffer overflow
                '125': 1.15, # Out-of-bounds read
                '787': 1.2,  # Out-of-bounds write
                '416': 1.3,  # Use after free
                '415': 1.25, # Double free
                '190': 1.15, # Integer overflow
                '134': 1.2,  # Format string
                '476': 1.0,  # NULL pointer dereference
            }
            cwe_boost = critical_cwes.get(cwe, 1.0)
        
        # Location-based boost (earlier in code = more critical)
        line = finding.get('line', 1000)
        location_boost = 1.0
        if line < 100:
            location_boost = 1.05  # Early in file, likely initialization code
        
        final_score = base_score * confidence_boost * bug_class_boost * cwe_boost * location_boost
        return round(final_score, 2)
    
    def deduplicate_findings(self, findings: List[Dict[str, Any]], keep_multi_bug: bool = True) -> List[Dict[str, Any]]:
        """De-duplicate findings by <file_stem>::<function> (FR3) - Issue #6 fixed"""
        print(f"[FUZZ_PLAN] De-duplicating {len(findings)} findings...")
        
        # Group by target key
        target_groups = defaultdict(list)
        for finding in findings:
            file_stem = finding.get('file_stem', 'unknown')
            function = finding.get('function', 'unknown')
            target_key = f"{file_stem}::{function}"
            target_groups[target_key].append(finding)
        
        # Select findings per target
        deduplicated = []
        for target_key, group in target_groups.items():
            # Sort by priority (highest first)
            group.sort(key=lambda f: self.calculate_priority(f), reverse=True)
            
            if keep_multi_bug and len(group) > 1:
                # Keep multiple bugs if they're different bug classes
                seen_bug_classes = set()
                for finding in group:
                    bug_class = self.infer_bug_class(finding.get('rule_id', 'unknown'))
                    if bug_class not in seen_bug_classes:
                        # Create unique target ID for multi-bug coverage
                        finding['_multi_bug_suffix'] = f"_{bug_class.lower()}"
                        deduplicated.append(finding)
                        seen_bug_classes.add(bug_class)
                        if len(seen_bug_classes) >= 3:  # Limit to top 3 bug classes per function
                            break
                
                if len(seen_bug_classes) > 1:
                    print(f"[FUZZ_PLAN] Kept {len(seen_bug_classes)} bug classes for {target_key}")
            else:
                # Keep only highest priority
                deduplicated.append(group[0])
            
            if len(group) > 1:
                print(f"[FUZZ_PLAN] Processed {len(group)} findings for {target_key}")
        
        print(f"[FUZZ_PLAN] Deduplicated to {len(deduplicated)} targets")
        return deduplicated
    
    def infer_harness_type(self, finding: Dict[str, Any], bug_class: str) -> str:
        """Infer harness type based on target characteristics (FR2) - Enhanced ML-like scoring"""
        function = finding.get('function', '').lower()
        message = finding.get('message', '').lower()
        file_path = finding.get('file', '').lower()
        
        # Multi-factor scoring system
        parser_score = 0
        api_score = 0
        fdp_score = 0
        
        # Parser indicators (weighted)
        parser_keywords = {
            'parse': 3, 'decode': 3, 'deserialize': 3, 'unmarshal': 3,
            'read': 2, 'load': 2, 'import': 2, 'process': 1,
            'convert': 1, 'transform': 1, 'extract': 1
        }
        for keyword, weight in parser_keywords.items():
            if keyword in function:
                parser_score += weight * 2
            if keyword in message:
                parser_score += weight
        
        # API indicators (weighted)
        api_keywords = {
            'api': 3, 'handle': 3, 'request': 3, 'response': 3,
            'endpoint': 2, 'service': 2, 'route': 2, 'controller': 2,
            'process': 1, 'execute': 1, 'invoke': 1
        }
        for keyword, weight in api_keywords.items():
            if keyword in function:
                api_score += weight * 2
            if keyword in message:
                api_score += weight
        
        # FuzzedDataProvider indicators (typed parameters)
        fdp_keywords = {
            'get': 2, 'set': 2, 'create': 2, 'init': 2,
            'config': 2, 'option': 2, 'param': 2, 'arg': 2,
            'validate': 1, 'check': 1, 'verify': 1
        }
        for keyword, weight in fdp_keywords.items():
            if keyword in function:
                fdp_score += weight
        
        # Bug class hints (strong signals)
        if bug_class in ['OOB', 'Format-String']:
            parser_score += 3  # Often parser-related
        elif bug_class in ['Integer-UB', 'Type-Confusion']:
            fdp_score += 2  # Often parameter validation
        elif bug_class in ['UAF', 'Resource-Leak']:
            api_score += 2  # Often API lifecycle issues
        
        # File path hints
        if any(x in file_path for x in ['parser', 'decode', 'deserialize']):
            parser_score += 2
        if any(x in file_path for x in ['api', 'handler', 'controller']):
            api_score += 2
        
        # Message content analysis
        if any(x in message for x in ['buffer', 'array', 'string', 'overflow']):
            parser_score += 1
        if any(x in message for x in ['parameter', 'argument', 'input']):
            fdp_score += 1
        
        # Decision logic with thresholds
        scores = {
            'parser_wrapper': parser_score,
            'fdp_adapter': fdp_score,
            'api_sequence': api_score
        }
        
        # Get highest score
        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]
        
        # Require minimum confidence (score >= 4)
        if best_score >= 4:
            return best_type
        
        # Default to bytes-to-api (most flexible, works for everything)
        return 'bytes_to_api'
    
    def validate_finding(self, finding: Dict[str, Any]) -> bool:
        """Validate that finding has all required fields"""
        required_fields = ['rule_id', 'file', 'file_stem', 'function', 
                          'severity', 'confidence', 'line', 'message']
        
        for field in required_fields:
            if field not in finding:
                print(f"[FUZZ_PLAN] Warning: Finding missing required field '{field}', skipping")
                return False
            if not finding[field]:  # Check for empty values
                print(f"[FUZZ_PLAN] Warning: Finding has empty '{field}', skipping")
                return False
        
        return True
    
    def generate_target_metadata(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate complete target metadata (FR4)"""
        # Validate finding first
        if not self.validate_finding(finding):
            return None
        
        bug_class = self.infer_bug_class(finding.get('rule_id', 'unknown'))
        sanitizers = self.select_sanitizers(bug_class)
        seeds = self.select_seeds(bug_class)
        dictionaries = self.select_dictionaries(bug_class)
        priority = self.calculate_priority(finding)
        harness_type = self.infer_harness_type(finding, bug_class)
        
        # Safe access with defaults
        file_stem = finding.get('file_stem', 'unknown')
        function = finding.get('function', 'unknown_function')
        
        # Handle multi-bug suffix for unique target IDs (Issue #6)
        multi_bug_suffix = finding.get('_multi_bug_suffix', '')
        target_id = f"{file_stem}_{function}{multi_bug_suffix}"
        
        target = {
            'target_id': target_id,
            'source_file': finding.get('file', ''),
            'file_stem': file_stem,
            'function_name': function,
            'bug_class': bug_class,
            'rule_id': finding.get('rule_id', 'unknown'),
            'severity': finding.get('severity', 'unknown'),
            'confidence': finding.get('confidence', 'medium'),
            'line_number': finding.get('line', 0),
            'column_number': finding.get('column', 0),
            'message': finding.get('message', 'No message'),
            'cwe': finding.get('cwe', ''),
            'sanitizers': sanitizers,
            'seed_directories': seeds,
            'dictionaries': dictionaries,
            'priority': priority,
            'harness_type': harness_type,
            'harness_template': harness_type,
        }
        
        return target
    
    def generate_fuzz_plan(self) -> Dict[str, Any]:
        """Generate complete fuzz plan (FR1)"""
        print(f"[FUZZ_PLAN] Generating fuzz plan...")
        
        # Load findings
        self.load_findings()
        
        # Validate findings data structure
        if not isinstance(self.findings_data, dict):
            raise ValueError("Invalid findings data: expected dictionary")
        
        if 'findings' not in self.findings_data:
            raise ValueError("Invalid findings data: missing 'findings' key")
        
        if not isinstance(self.findings_data['findings'], list):
            raise ValueError("Invalid findings data: 'findings' must be a list")
        
        # De-duplicate
        findings = self.findings_data['findings']
        deduplicated = self.deduplicate_findings(findings)
        
        # Generate targets (filter out None values from validation failures)
        targets = []
        skipped_count = 0
        for finding in deduplicated:
            target = self.generate_target_metadata(finding)
            if target is not None:
                targets.append(target)
            else:
                skipped_count += 1
        
        if skipped_count > 0:
            print(f"[FUZZ_PLAN] Skipped {skipped_count} invalid findings")
        
        # Sort by priority (highest first)
        targets.sort(key=lambda t: t['priority'], reverse=True)
        
        # Apply resource limits (Issue #7)
        original_count = len(targets)
        if len(targets) > self.max_targets:
            print(f"[FUZZ_PLAN] Warning: {len(targets)} targets exceeds limit of {self.max_targets}")
            print(f"[FUZZ_PLAN] Keeping top {self.max_targets} highest priority targets")
            targets = targets[:self.max_targets]
        
        # Calculate metadata
        bug_class_breakdown = defaultdict(int)
        for target in targets:
            bug_class_breakdown[target['bug_class']] += 1
        
        fuzz_plan = {
            'version': '1.0',
            'generated_at': datetime.now().isoformat(),
            'source': self.findings_path,
            'targets': targets,
            'metadata': {
                'total_findings': self.findings_data['total_findings'],
                'deduplicated_targets': len(targets),
                'bug_class_breakdown': dict(bug_class_breakdown),
                'sanitizers_used': list(set(
                    san for t in targets for san in t['sanitizers']
                )),
            }
        }
        
        print(f"[FUZZ_PLAN] Generated {len(targets)} fuzz targets")
        print(f"[FUZZ_PLAN] Bug class breakdown: {dict(bug_class_breakdown)}")
        
        return fuzz_plan
    
    def create_required_directories(self, base_path: str) -> None:
        """Create required seed and dictionary directories"""
        required_dirs = [
            'fuzz/seeds/parser',
            'fuzz/seeds/api',
            'fuzz/seeds/generic',
            'fuzz/corpus',
            'fuzz/artifacts',
            'fuzz/targets',
        ]
        
        base = Path(base_path).parent.parent  # Go up from fuzz/fuzzplan.json to project root
        
        for dir_path in required_dirs:
            full_path = base / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
        
        # Create placeholder dictionary file if it doesn't exist
        dict_path = base / 'fuzz' / 'auto.dict'
        if not dict_path.exists():
            with open(dict_path, 'w', encoding='utf-8') as f:
                f.write('# Auto-generated fuzzing dictionary\n')
                f.write('# Add common tokens here\n')
                f.write('"FRAME"\n')
                f.write('"LEN"\n')
                f.write('"DATA"\n')
        
        print(f"[FUZZ_PLAN] Created required directories under {base}")
    
    def validate_output(self, fuzz_plan: Dict[str, Any]) -> bool:
        """Validate output fuzz plan structure (Issue #8)"""
        required_keys = ['version', 'generated_at', 'targets', 'metadata']
        
        # Check top-level structure
        for key in required_keys:
            if key not in fuzz_plan:
                print(f"[FUZZ_PLAN] Validation error: Missing key '{key}'")
                return False
        
        # Validate targets
        if not isinstance(fuzz_plan['targets'], list):
            print(f"[FUZZ_PLAN] Validation error: 'targets' must be a list")
            return False
        
        # Validate each target has required fields
        target_required = ['target_id', 'function_name', 'bug_class', 'sanitizers', 
                          'priority', 'harness_type']
        
        for i, target in enumerate(fuzz_plan['targets']):
            for key in target_required:
                if key not in target:
                    print(f"[FUZZ_PLAN] Validation error: Target {i} missing '{key}'")
                    return False
        
        # Validate metadata
        if not isinstance(fuzz_plan['metadata'], dict):
            print(f"[FUZZ_PLAN] Validation error: 'metadata' must be a dict")
            return False
        
        print(f"[FUZZ_PLAN] Output validation passed")
        return True
    
    def save_fuzz_plan(self, output_path: str) -> None:
        """Save fuzz plan to JSON file"""
        fuzz_plan = self.generate_fuzz_plan()
        
        # Validate output before saving (Issue #8)
        if not self.validate_output(fuzz_plan):
            raise ValueError("Generated fuzz plan failed validation")
        
        print(f"[FUZZ_PLAN] Saving fuzz plan to: {output_path}")
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create required directories
        self.create_required_directories(output_path)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(fuzz_plan, f, indent=2)
        
        print(f"[FUZZ_PLAN] Fuzz plan saved successfully!")


def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python generator.py <static_findings.json> [output_path]")
        sys.exit(1)
    
    findings_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'fuzz/fuzzplan.json'
    
    generator = FuzzPlanGenerator(findings_path)
    generator.save_fuzz_plan(output_path)


if __name__ == '__main__':
    main()
