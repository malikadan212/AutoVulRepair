"""
Harness Generator
Generates fuzzing harnesses from fuzz plan targets
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .toolbox import HarnessToolbox

logger = logging.getLogger(__name__)


class HarnessGenerator:
    """Generate fuzzing harnesses from fuzz plan"""
    
    # Bug class specific implementation hints
    BUG_CLASS_HINTS = {
        'OOB': """    // Out-of-Bounds Access Pattern
    // 1. Create buffer with controlled size
    // 2. Use fuzzer data to generate index/offset
    // 3. Attempt access that may go out of bounds
    //
    // Example:
    // if (size >= sizeof(int)) {
    //     int index = *(int*)data;
    //     // Call function that may access array[index]
    // }""",
        
        'UAF': """    // Use-After-Free Pattern
    // 1. Allocate object/memory
    // 2. Free/delete the object
    // 3. Use fuzzer data to trigger use of freed memory
    //
    // Example:
    // void* ptr = malloc(size);
    // free(ptr);
    // // Call function that may use ptr""",
        
        'Integer-UB': """    // Integer Undefined Behavior Pattern
    // 1. Extract integer values from fuzzer data
    // 2. Perform operations that may overflow/underflow
    // 3. Use result in calculations or array indexing
    //
    // Example:
    // if (size >= 2 * sizeof(int)) {
    //     int a = *(int*)data;
    //     int b = *(int*)(data + sizeof(int));
    //     // Call function with a + b, a * b, etc.
    // }""",
        
        'Null-Deref': """    // Null Pointer Dereference Pattern
    // 1. Create pointer that may be null
    // 2. Use fuzzer data to control null condition
    // 3. Attempt to dereference
    //
    // Example:
    // void* ptr = (data[0] & 1) ? malloc(size) : nullptr;
    // // Call function that may dereference ptr""",
        
        'Memory-Leak': """    // Memory Leak Pattern
    // 1. Allocate memory based on fuzzer input
    // 2. Create conditions where free may not be called
    // 3. Repeat allocation
    //
    // Example:
    // for (size_t i = 0; i < size && i < 100; i++) {
    //     void* ptr = malloc(data[i]);
    //     // Conditionally free based on fuzzer data
    // }""",
        
        'Buffer-Overflow': """    // Buffer Overflow Pattern
    // 1. Create fixed-size buffer
    // 2. Use fuzzer data for copy size
    // 3. Attempt copy that may overflow
    //
    // Example:
    // char buffer[256];
    // size_t copy_size = (size > 0) ? data[0] : 0;
    // // Call function that copies data to buffer"""
    }
    
    def __init__(self, fuzz_plan_path: str):
        """
        Initialize harness generator
        
        Args:
            fuzz_plan_path: Path to fuzzplan.json file
        """
        self.fuzz_plan_path = fuzz_plan_path
        self.fuzz_plan = self._load_fuzz_plan()
        self.template_dir = Path(__file__).parent / 'templates'
        self.toolbox = HarnessToolbox()  # Initialize toolbox
        
    def _load_fuzz_plan(self) -> Dict:
        """Load fuzz plan from JSON file"""
        try:
            with open(self.fuzz_plan_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load fuzz plan: {e}")
            raise
    
    def _get_bug_class_hints(self, bug_class: str) -> str:
        """Get implementation hints for bug class"""
        return self.BUG_CLASS_HINTS.get(bug_class, """    // Generic fuzzing pattern
    // 1. Parse fuzzer input data
    // 2. Call target function with parsed data
    // 3. Check for crashes or sanitizer violations""")
    
    def _sanitize_function_name(self, name: str) -> str:
        """Sanitize function name for use in filenames"""
        # Remove special characters, keep alphanumeric and underscore
        sanitized = ''.join(c if c.isalnum() or c == '_' else '_' for c in name)
        # Remove consecutive underscores
        while '__' in sanitized:
            sanitized = sanitized.replace('__', '_')
        return sanitized.strip('_')
    
    def _format_sanitizers(self, sanitizers: List[str]) -> str:
        """Format sanitizers for compilation command"""
        # Map sanitizer names to clang flags
        sanitizer_map = {
            'ASan': 'address',
            'UBSan': 'undefined',
            'MSan': 'memory',
            'TSan': 'thread',
            'LSan': 'leak'
        }
        
        formatted = []
        for san in sanitizers:
            if san in sanitizer_map:
                formatted.append(sanitizer_map[san])
        
        return ','.join(formatted) if formatted else 'address,undefined'
    
    def _extract_file_stem(self, target: Dict) -> str:
        """
        Extract file stem from target source file
        
        Args:
            target: Target metadata
            
        Returns:
            File stem (filename without extension)
        """
        source_file = target.get('source_file', '')
        if source_file:
            # Extract filename from path and remove extension
            filename = os.path.basename(source_file)
            stem = os.path.splitext(filename)[0]
            return self._sanitize_function_name(stem)
        return 'unknown'
    
    def generate_harness(self, target: Dict, output_dir: str) -> Dict:
        """
        Generate a single harness from target using toolbox approach
        
        Args:
            target: Target dictionary from fuzz plan
            output_dir: Directory to write harness file
            
        Returns:
            Dictionary with harness metadata
        """
        # Extract target information
        function_name = target.get('function_name', 'unknown_function')
        bug_class = target.get('bug_class', 'Unknown')
        priority = target.get('priority', 0)
        sanitizers = target.get('sanitizers', ['ASan', 'UBSan'])
        target_id = target.get('target_id', 'unknown')
        
        # Generate filename using spec naming convention: fuzz_<file_stem>_<function_name>.cc
        file_stem = self._extract_file_stem(target)
        safe_function_name = self._sanitize_function_name(function_name)
        harness_filename = f"fuzz_{file_stem}_{safe_function_name}.cc"
        harness_path = os.path.join(output_dir, harness_filename)
        
        # Use toolbox to select and generate appropriate harness type
        harness_type = self.toolbox.select_harness_type(target)
        harness_code = self.toolbox.generate_harness(target, harness_type)
        
        logger.info(f"Generated {harness_type} harness: {harness_filename}")
        
        # Write harness file
        os.makedirs(output_dir, exist_ok=True)
        with open(harness_path, 'w', encoding='utf-8') as f:
            f.write(harness_code)
        
        # Generate timestamp
        generation_timestamp = datetime.now().isoformat()
        
        # Return metadata
        return {
            'name': harness_filename,
            'file_path': harness_filename,
            'full_path': harness_path,
            'function_name': function_name,
            'bug_class': bug_class,
            'priority': priority,
            'sanitizers': sanitizers,
            'target_id': target_id,
            'harness_type': harness_type,
            'file_stem': file_stem,
            'generation_timestamp': generation_timestamp,
            'generator_version': '1.0.0',
            'file_size': os.path.getsize(harness_path),
            'lines': len(harness_code.split('\n')),
            'source_file': target.get('source_file', 'unknown'),
            'line_number': target.get('line_number', 0)
        }
    
    def _save_metadata(self, output_dir: str, harnesses: List[Dict]) -> str:
        """
        Save harness generation metadata to .metadata.json
        
        Args:
            output_dir: Directory containing harness files
            harnesses: List of harness metadata dictionaries
            
        Returns:
            Path to metadata file
        """
        metadata_path = os.path.join(output_dir, '.metadata.json')
        
        metadata = {
            'generation_timestamp': datetime.now().isoformat(),
            'generator_version': '1.0.0',
            'total_harnesses': len(harnesses),
            'fuzz_plan_path': self.fuzz_plan_path,
            'harnesses': harnesses,
            'toolbox_types': {
                'bytes_to_api': sum(1 for h in harnesses if h['harness_type'] == 'bytes_to_api'),
                'fdp_adapter': sum(1 for h in harnesses if h['harness_type'] == 'fdp_adapter'),
                'parser_wrapper': sum(1 for h in harnesses if h['harness_type'] == 'parser_wrapper'),
                'api_sequence': sum(1 for h in harnesses if h['harness_type'] == 'api_sequence')
            },
            'bug_class_breakdown': {}
        }
        
        # Calculate bug class breakdown
        for harness in harnesses:
            bug_class = harness.get('bug_class', 'Unknown')
            metadata['bug_class_breakdown'][bug_class] = metadata['bug_class_breakdown'].get(bug_class, 0) + 1
        
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Saved metadata to: {metadata_path}")
        return metadata_path
    
    def generate_all_harnesses(self, output_dir: str) -> List[Dict]:
        """
        Generate harnesses for all targets in fuzz plan
        
        Args:
            output_dir: Directory to write harness files
            
        Returns:
            List of harness metadata dictionaries
        """
        targets = self.fuzz_plan.get('targets', [])
        
        if not targets:
            logger.warning("No targets found in fuzz plan")
            return []
        
        harnesses = []
        for i, target in enumerate(targets, 1):
            try:
                harness_meta = self.generate_harness(target, output_dir)
                harnesses.append(harness_meta)
                logger.info(f"Generated harness {i}/{len(targets)}: {harness_meta['name']}")
            except Exception as e:
                logger.error(f"Failed to generate harness for target {i}: {e}")
                continue
        
        logger.info(f"Successfully generated {len(harnesses)}/{len(targets)} harnesses")
        
        # Save metadata file
        if harnesses:
            self._save_metadata(output_dir, harnesses)
        
        return harnesses
    
    def generate_build_script(self, output_dir: str, harnesses: List[Dict]) -> str:
        """
        Generate build script for all harnesses
        
        Args:
            output_dir: Directory containing harness files
            harnesses: List of harness metadata
            
        Returns:
            Path to build script
        """
        build_script_path = os.path.join(output_dir, 'build_harnesses.sh')
        
        script_lines = [
            "#!/bin/bash",
            "# Auto-generated build script for fuzzing harnesses",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "set -e",
            "",
            "echo 'Building fuzzing harnesses...'",
            ""
        ]
        
        for harness in harnesses:
            harness_file = harness['file_path']
            target_id = harness['target_id']
            sanitizers = ','.join([s.lower() for s in harness['sanitizers']])
            
            script_lines.extend([
                f"echo 'Building {harness_file}...'",
                f"clang++ -fsanitize=fuzzer,{sanitizers} -g -O1 -std=c++17 \\",
                f"  -o {target_id} {harness_file}",
                ""
            ])
        
        script_lines.append("echo 'Build complete!'")
        
        script_content = '\n'.join(script_lines)
        
        with open(build_script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        # Make executable on Unix systems
        try:
            os.chmod(build_script_path, 0o755)
        except:
            pass
        
        logger.info(f"Generated build script: {build_script_path}")
        return build_script_path
    
    def generate_readme(self, output_dir: str, harnesses: List[Dict]) -> str:
        """
        Generate README for harness directory
        
        Args:
            output_dir: Directory containing harness files
            harnesses: List of harness metadata
            
        Returns:
            Path to README file
        """
        readme_path = os.path.join(output_dir, 'README.md')
        
        metadata = self.fuzz_plan.get('metadata', {})
        
        # Calculate toolbox type breakdown
        toolbox_breakdown = {}
        for harness in harnesses:
            htype = harness.get('harness_type', 'unknown')
            toolbox_breakdown[htype] = toolbox_breakdown.get(htype, 0) + 1
        
        readme_lines = [
            "# Fuzzing Harnesses",
            "",
            f"Generated: {datetime.now().isoformat()}",
            f"Generator Version: 1.0.0",
            "",
            "## Overview",
            "",
            f"- Total Harnesses: {len(harnesses)}",
            f"- Total Targets: {metadata.get('deduplicated_targets', len(harnesses))}",
            f"- Bug Classes: {', '.join(metadata.get('bug_class_breakdown', {}).keys())}",
            "",
            "## Toolbox Types Used",
            "",
        ]
        
        for htype, count in toolbox_breakdown.items():
            readme_lines.append(f"- **{htype}**: {count} harnesses")
        
        readme_lines.extend([
            "",
            "## Building",
            "",
            "```bash",
            "./build_harnesses.sh",
            "```",
            "",
            "Or build individually:",
            "",
            "```bash",
            "clang++ -fsanitize=fuzzer,address,undefined -g -O1 -std=c++17 \\",
            "  -o target_harness harness_file.cc source_file.cc",
            "```",
            "",
            "## Running",
            "",
            "```bash",
            "./target_harness -max_total_time=3600 -artifact_prefix=crashes/",
            "```",
            "",
            "## Harnesses",
            ""
        ])
        
        # Add table of harnesses
        readme_lines.extend([
            "| Harness | Function | Bug Class | Priority | Sanitizers |",
            "|---------|----------|-----------|----------|------------|"
        ])
        
        for harness in harnesses:
            name = harness['name']
            function = harness['function_name']
            bug_class = harness['bug_class']
            priority = harness['priority']
            sanitizers = ', '.join(harness['sanitizers'])
            
            readme_lines.append(f"| {name} | {function} | {bug_class} | {priority} | {sanitizers} |")
        
        readme_lines.extend([
            "",
            "## Harness Types",
            "",
            "### bytes_to_api",
            "Direct byte stream to function call. Best for functions that take raw data buffers.",
            "",
            "### fdp_adapter", 
            "Uses FuzzedDataProvider for typed parameters (int, bool, string). Best for API-like functions.",
            "",
            "### parser_wrapper",
            "Parser-specific input handling with null-termination. Best for parsing functions.",
            "",
            "### api_sequence",
            "Stateful API sequence with initialization/cleanup. Best for stateful components.",
            "",
            "## Notes",
            "",
            "- These harnesses are templates and may require manual implementation",
            "- Review the TODO comments in each harness file",
            "- Adjust buffer sizes and input parsing as needed",
            "- Add necessary includes for your target functions",
            "- Check `.metadata.json` for detailed generation information",
            "",
            "## Sanitizer Options",
            "",
            "- **ASan** (Address Sanitizer): Detects memory errors",
            "- **UBSan** (Undefined Behavior Sanitizer): Detects undefined behavior",
            "- **MSan** (Memory Sanitizer): Detects uninitialized memory reads",
            "- **TSan** (Thread Sanitizer): Detects data races",
            "- **LSan** (Leak Sanitizer): Detects memory leaks",
            ""
        ])
        
        readme_content = '\n'.join(readme_lines)
        
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        logger.info(f"Generated README: {readme_path}")
        return readme_path
