"""
Automatic Seed Generator
Uses OSS-Fuzz's proven seed generation strategy:
1. Extract test files from repository
2. Use minimal generic seeds
3. Let LibFuzzer's mutation do the work

Based on: https://github.com/google/oss-fuzz
"""

import os
import logging
import shutil
from pathlib import Path
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)


class SeedGenerator:
    """Automatically generates seed files using OSS-Fuzz strategy"""
    
    # OSS-Fuzz's minimal seed set (proven effective)
    # Source: https://github.com/google/oss-fuzz/tree/master/infra/base-images/base-runner
    OSS_FUZZ_MINIMAL_SEEDS = [
        b'',                    # Empty input (most important!)
        b'\x00',                # Null byte
        b'A',                   # Single ASCII
        b'\xff',                # Max byte
        b'0',                   # Zero string
        b'1',                   # One string
    ]
    
    # Extended seeds for specific bug classes (still minimal)
    EXTENDED_SEEDS = {
        # Only add a few extra seeds for specific bug classes
        # OSS-Fuzz philosophy: Keep it minimal, let mutation do the work
        'Format-String': [
            b'%s',
            b'%n',
        ],
        'Integer-UB': [
            b'2147483647',  # INT_MAX
            b'-2147483648',  # INT_MIN
        ],
    }
    
    # File extensions to look for when mining repository for test files
    # Based on OSS-Fuzz's seed corpus extraction
    TEST_FILE_EXTENSIONS = {
        '.txt', '.dat', '.bin', '.test',
        '.c', '.cpp', '.cc', '.h',  # Source files can be seeds too
        '.json', '.xml', '.html',
        '.png', '.jpg', '.gif', '.pdf',  # Binary formats
    }
    
    # Directories to search for test files (OSS-Fuzz pattern)
    TEST_DIRECTORIES = [
        'test', 'tests', 'testing',
        'testdata', 'test_data', 'test-data',
        'samples', 'examples',
        'corpus', 'seed', 'seeds',
        'fixtures',
    ]
    
    def extract_test_files_from_repo(self, repo_dir: str, max_files: int = 20, max_size_kb: int = 100) -> List[bytes]:
        """
        Extract test files from repository (OSS-Fuzz strategy)
        
        This is OSS-Fuzz's primary seed source - real test files from the project.
        
        Args:
            repo_dir: Path to cloned repository
            max_files: Maximum number of test files to extract
            max_size_kb: Maximum file size in KB
            
        Returns:
            List of file contents as bytes
        """
        extracted_seeds = []
        
        if not os.path.exists(repo_dir):
            return extracted_seeds
        
        try:
            # Search for test directories
            for root, dirs, files in os.walk(repo_dir):
                # Check if we're in a test directory
                dir_name = os.path.basename(root).lower()
                is_test_dir = any(test_dir in dir_name for test_dir in self.TEST_DIRECTORIES)
                
                if is_test_dir:
                    for file in files:
                        if len(extracted_seeds) >= max_files:
                            break
                        
                        # Check file extension
                        file_ext = Path(file).suffix.lower()
                        if file_ext in self.TEST_FILE_EXTENSIONS:
                            file_path = os.path.join(root, file)
                            
                            try:
                                # Check file size
                                file_size_kb = os.path.getsize(file_path) / 1024
                                if file_size_kb > max_size_kb:
                                    continue
                                
                                # Read file content
                                with open(file_path, 'rb') as f:
                                    content = f.read()
                                    if content:  # Skip empty files
                                        extracted_seeds.append(content)
                                        logger.debug(f"Extracted seed from: {file_path}")
                            except Exception as e:
                                logger.debug(f"Could not read {file_path}: {e}")
                                continue
                
                if len(extracted_seeds) >= max_files:
                    break
            
            logger.info(f"Extracted {len(extracted_seeds)} test files from repository")
            return extracted_seeds
            
        except Exception as e:
            logger.warning(f"Error extracting test files: {e}")
            return extracted_seeds
    
    def generate_seeds_for_target(self, target: Dict[str, Any], output_dir: str, repo_dir: str = None) -> int:
        """
        Generate seed files for a specific target using OSS-Fuzz strategy
        
        OSS-Fuzz approach:
        1. Try to extract test files from repository (best seeds)
        2. Fall back to minimal generic seeds
        3. Add bug-class specific seeds if applicable
        
        Args:
            target: Target metadata from fuzz plan
            output_dir: Directory to write seed files
            repo_dir: Path to repository (for extracting test files)
            
        Returns:
            Number of seed files generated
        """
        bug_class = target.get('bug_class', 'Unknown')
        target_id = target.get('target_id', 'unknown')
        
        # Create target-specific seed directory
        seed_dir = os.path.join(output_dir, target_id)
        os.makedirs(seed_dir, exist_ok=True)
        
        seeds = []
        
        # Strategy 1: Extract test files from repository (OSS-Fuzz primary strategy)
        if repo_dir and os.path.exists(repo_dir):
            repo_seeds = self.extract_test_files_from_repo(repo_dir, max_files=10)
            seeds.extend(repo_seeds)
            if repo_seeds:
                logger.info(f"Using {len(repo_seeds)} test files from repository as seeds")
        
        # Strategy 2: Always include OSS-Fuzz minimal seeds (proven effective)
        seeds.extend(self.OSS_FUZZ_MINIMAL_SEEDS)
        
        # Strategy 3: Add bug-class specific seeds (only if we have them)
        if bug_class in self.EXTENDED_SEEDS:
            seeds.extend(self.EXTENDED_SEEDS[bug_class])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_seeds = []
        for seed in seeds:
            if seed not in seen:
                seen.add(seed)
                unique_seeds.append(seed)
        
        # Write seed files
        generated_count = 0
        for i, seed_data in enumerate(unique_seeds):
            seed_file = os.path.join(seed_dir, f'seed_{i:03d}')
            try:
                with open(seed_file, 'wb') as f:
                    f.write(seed_data)
                generated_count += 1
            except Exception as e:
                logger.warning(f"Failed to write seed file {seed_file}: {e}")
        
        logger.info(f"Generated {generated_count} seeds for {target_id} ({bug_class})")
        return generated_count
    
    def generate_seeds_for_fuzz_plan(self, fuzz_plan: Dict[str, Any], base_dir: str, repo_dir: str = None) -> Dict[str, int]:
        """
        Generate seeds for all targets in fuzz plan using OSS-Fuzz strategy
        
        Args:
            fuzz_plan: Complete fuzz plan
            base_dir: Base directory (usually scans/<scan_id>/fuzz)
            repo_dir: Path to cloned repository (for extracting test files)
            
        Returns:
            Dictionary mapping target_id to seed count
        """
        seeds_dir = os.path.join(base_dir, 'seeds')
        os.makedirs(seeds_dir, exist_ok=True)
        
        results = {}
        targets = fuzz_plan.get('targets', [])
        
        # Log OSS-Fuzz strategy
        if repo_dir and os.path.exists(repo_dir):
            logger.info(f"Using OSS-Fuzz strategy: extracting test files from {repo_dir}")
        else:
            logger.info("Using OSS-Fuzz minimal seeds (no repository available)")
        
        for target in targets:
            target_id = target.get('target_id', 'unknown')
            count = self.generate_seeds_for_target(target, seeds_dir, repo_dir=repo_dir)
            results[target_id] = count
        
        total_seeds = sum(results.values())
        logger.info(f"Generated {total_seeds} total seeds for {len(targets)} targets")
        
        return results
    
    def generate_signature_aware_seeds(self, target: Dict[str, Any], output_dir: str) -> int:
        """
        Generate seeds based on function signature (advanced)
        
        Args:
            target: Target with function_signature field
            output_dir: Directory to write seed files
            
        Returns:
            Number of seed files generated
        """
        signature = target.get('function_signature')
        if not signature:
            # Fall back to basic seeds
            return self.generate_seeds_for_target(target, output_dir)
        
        target_id = target.get('target_id', 'unknown')
        seed_dir = os.path.join(output_dir, target_id)
        os.makedirs(seed_dir, exist_ok=True)
        
        parameters = signature.get('parameters', [])
        
        # Generate seeds based on parameter types
        seeds = []
        
        if not parameters:
            # No parameters - use basic seeds
            seeds = self.GENERIC_SEEDS
        else:
            # Generate seeds for each parameter type
            for param in parameters:
                param_type = param.get('type', '')
                
                if 'char*' in param_type or 'string' in param_type:
                    # String parameter
                    seeds.extend([
                        b'',
                        b'test',
                        b'A' * 10,
                        b'A' * 100,
                    ])
                elif 'int' in param_type or 'size' in param_type:
                    # Integer parameter
                    seeds.extend([
                        b'\x00\x00\x00\x00',  # 0
                        b'\x01\x00\x00\x00',  # 1
                        b'\xff\xff\xff\xff',  # -1 or MAX
                    ])
                elif param.get('is_pointer'):
                    # Pointer parameter
                    seeds.extend([
                        b'\x00' * 8,  # NULL
                        b'A' * 16,
                    ])
        
        # Write seed files
        generated_count = 0
        for i, seed_data in enumerate(seeds[:20]):  # Limit to 20 seeds
            seed_file = os.path.join(seed_dir, f'seed_{i:03d}')
            try:
                with open(seed_file, 'wb') as f:
                    f.write(seed_data)
                generated_count += 1
            except Exception as e:
                logger.warning(f"Failed to write seed file {seed_file}: {e}")
        
        logger.info(f"Generated {generated_count} signature-aware seeds for {target_id}")
        return generated_count
