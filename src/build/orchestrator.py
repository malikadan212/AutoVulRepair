"""
Build Orchestrator
Compiles fuzzing harnesses into executable fuzz targets
"""

import os
import json
import subprocess
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def is_running_in_docker() -> bool:
    """Check if we're running inside a Docker container"""
    return os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')


class BuildOrchestrator:
    """Orchestrate building of fuzz targets from harnesses"""
    
    def __init__(self, scan_dir: str):
        """
        Initialize build orchestrator
        
        Args:
            scan_dir: Path to scan directory containing fuzz plan and harnesses
        """
        self.scan_dir = scan_dir
        self.fuzz_dir = os.path.join(scan_dir, 'fuzz')
        self.harness_dir = os.path.join(self.fuzz_dir, 'harnesses')
        self.build_dir = os.path.join(scan_dir, 'build')
        self.fuzz_plan_path = os.path.join(self.fuzz_dir, 'fuzzplan.json')
        
        # Create build directory
        os.makedirs(self.build_dir, exist_ok=True)
        
    def _load_fuzz_plan(self) -> Dict:
        """Load fuzz plan"""
        try:
            with open(self.fuzz_plan_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load fuzz plan: {e}")
            raise
    
    def _patch_source_file_for_fuzzing(self, source_file_path: str) -> bool:
        """
        Patch source file to make it compatible with fuzzing:
        1. Wrap main() with preprocessor guards to prevent conflicts with LibFuzzer
        2. Fix common compilation errors (like deprecated gets())
        
        Args:
            source_file_path: Path to source file
            
        Returns:
            True if patched successfully, False otherwise
        """
        try:
            with open(source_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            modified = False
            import re
            
            # Fix 1: Replace gets() with fgets() - gets() was removed in C++14
            # This is a common issue with legacy/vulnerable code
            if re.search(r'\bgets\s*\(', content):
                # Replace gets(buffer) with fgets(buffer, sizeof(buffer), stdin)
                content = re.sub(
                    r'\bgets\s*\(\s*(\w+)\s*\)',
                    r'fgets(\1, sizeof(\1), stdin)',
                    content
                )
                modified = True
                logger.info(f"✓ Replaced deprecated gets() with fgets()")
            
            # Fix 2: Wrap main() function with preprocessor guards
            if 'FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION' not in content:
                # Pattern to find main function (handles various formats)
                main_pattern = r'(int\s+main\s*\([^)]*\)\s*\{)'
                
                if re.search(main_pattern, content):
                    # Add guard before main
                    content = re.sub(
                        main_pattern,
                        r'#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION\n\1',
                        content,
                        count=1
                    )
                    
                    # Add endif at the end of file
                    lines = content.split('\n')
                    if lines and lines[-1].strip() == '}':
                        lines.insert(-1, '#endif // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION')
                    else:
                        lines.append('#endif // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION')
                    
                    content = '\n'.join(lines)
                    modified = True
                    logger.info(f"✓ Wrapped main() with preprocessor guards")
            
            # Write back if modified
            if modified:
                with open(source_file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"✓ Patched source file for fuzzing: {source_file_path}")
            else:
                logger.debug(f"Source file already compatible: {source_file_path}")
            
            return True
                
        except Exception as e:
            logger.warning(f"Failed to patch source file: {e}")
            return False
    
    def _compile_source_file(self) -> Optional[str]:
        """
        Compile the source file into an object file (shared by all targets)
        
        Returns:
            Path to compiled object file, or None if compilation failed
        """
        try:
            compiler, engine = self._get_compiler()
        except RuntimeError as e:
            logger.warning(f"No compiler available: {e}")
            return None
        
        in_docker = is_running_in_docker()
        source_dir = os.path.join(self.scan_dir, 'source')
        
        # Find source file
        source_file = None
        if in_docker:
            for ext in ['.cpp', '.cc', '.c', '.cxx']:
                potential_source = os.path.join(source_dir, f'test{ext}')
                if os.path.exists(potential_source):
                    source_file = potential_source
                    # Patch the source file to exclude main() when fuzzing
                    self._patch_source_file_for_fuzzing(potential_source)
                    break
        else:
            # Running on host - check in Docker
            scan_id = os.path.basename(self.scan_dir)
            for ext in ['.cpp', '.cc', '.c', '.cxx']:
                docker_source = f'/app/scans/{scan_id}/source/test{ext}'
                # We can't easily check if file exists in Docker from host
                # So we'll try to compile and see if it works
                source_file = docker_source
                # For Docker, we need to patch inside the container
                # We'll do this via a docker exec command
                host_source = os.path.join(self.scan_dir, 'source', f'test{ext}')
                if os.path.exists(host_source):
                    self._patch_source_file_for_fuzzing(host_source)
                break
        
        if not source_file:
            logger.warning("No source file found to compile")
            return None
        
        # Output object file path
        if in_docker:
            source_obj = os.path.join(self.build_dir, 'test_source.o')
        else:
            scan_id = os.path.basename(self.scan_dir)
            source_obj = f'/app/scans/{scan_id}/build/test_source.o'
        
        # Compile command (use address,undefined as default sanitizers)
        # Define FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION to exclude main() function
        # Use permissive flags to handle legacy/problematic code
        compile_cmd = [
            compiler,
            '-c',
            '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
            '-Wno-deprecated-declarations',  # Ignore deprecated function warnings
            '-Wno-error',  # Don't treat warnings as errors
            '-fsanitize=address,undefined',
            '-g',
            '-O1',
            '-std=c++17',
            f'-I{source_dir if in_docker else f"/app/scans/{scan_id}/source"}',
            '-o', source_obj,
            source_file
        ]
        
        logger.info("Compiling source file...")
        logger.debug(f"Command: {' '.join(compile_cmd)}")
        
        try:
            if in_docker:
                result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
            else:
                result = self._run_in_docker(compile_cmd, timeout=30)
            
            if result.returncode == 0:
                logger.info(f"✓ Source file compiled successfully: {source_obj}")
                return source_obj
            else:
                logger.warning(f"Source file compilation failed: {result.stderr}")
                return None
        except Exception as e:
            logger.warning(f"Failed to compile source file: {e}")
            return None
    
    def _run_in_docker(self, cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
        """
        Execute a command inside the Docker container
        
        Args:
            cmd: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            subprocess.CompletedProcess result
        """
        # Build docker exec command
        docker_cmd = [
            'docker', 'exec',
            'autovulrepair-app-1',  # Container name from docker-compose
            *cmd
        ]
        
        logger.debug(f"Executing in Docker: {' '.join(cmd)}")
        
        return subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    
    def _get_compiler(self) -> tuple[str, str]:
        """
        Get available C++ compiler and fuzzing engine
        Returns: (compiler_path, engine_type)
        """
        # If running in Docker, we know clang++ is available
        if is_running_in_docker():
            logger.info("Running in Docker - using clang++ with LibFuzzer")
            return ('clang++', 'libfuzzer')
        
        # Try LibFuzzer with clang++ (preferred)
        try:
            result = subprocess.run(['clang++', '--version'], 
                                  capture_output=True, 
                                  timeout=5)
            if result.returncode == 0:
                logger.info("Using compiler: clang++ with LibFuzzer")
                return ('clang++', 'libfuzzer')
        except:
            pass
        
        # Try AFL++ (alternative that works with GCC)
        try:
            result = subprocess.run(['afl-clang-fast++', '--version'], 
                                  capture_output=True, 
                                  timeout=5)
            if result.returncode == 0:
                logger.info("Using compiler: afl-clang-fast++ with AFL++")
                return ('afl-clang-fast++', 'afl')
        except:
            pass
        
        try:
            result = subprocess.run(['afl-g++', '--version'], 
                                  capture_output=True, 
                                  timeout=5)
            if result.returncode == 0:
                logger.info("Using compiler: afl-g++ with AFL++")
                return ('afl-g++', 'afl')
        except:
            pass
        
        raise RuntimeError(
            "No fuzzing compiler found. Please install one of:\n\n"
            "Option 1 - LibFuzzer (Recommended):\n"
            "  - Linux: sudo apt-get install clang\n"
            "  - macOS: brew install llvm\n"
            "  - Windows: Use WSL2 or download from https://releases.llvm.org/\n\n"
            "Option 2 - AFL++:\n"
            "  - Linux: sudo apt-get install afl++\n"
            "  - macOS: brew install afl++\n"
            "  - Windows: Use WSL2"
        )
    
    def _build_single_target(self, target: Dict, harness_file: str) -> Dict:
        """
        Build a single fuzz target
        
        Args:
            target: Target metadata from fuzz plan
            harness_file: Path to harness file
            
        Returns:
            Build result dictionary
        """
        start_time = time.time()
        
        # Extract target information
        function_name = target.get('function_name', 'unknown')
        target_id = target.get('target_id', 'unknown')
        sanitizers = target.get('sanitizers', ['ASan', 'UBSan'])
        source_file = target.get('file_path', '')
        
        # Sanitize function name for output
        safe_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in function_name)
        output_name = f"fuzz_{safe_name}"
        output_path = os.path.join(self.build_dir, output_name)
        
        # Map sanitizers to clang flags
        sanitizer_map = {
            'ASan': 'address',
            'UBSan': 'undefined',
            'MSan': 'memory',
            'TSan': 'thread',
            'LSan': 'leak'
        }
        
        sanitizer_flags = []
        for san in sanitizers:
            if san in sanitizer_map:
                sanitizer_flags.append(sanitizer_map[san])
        
        # Default to address,undefined if none specified
        if not sanitizer_flags:
            sanitizer_flags = ['address', 'undefined']
        
        sanitizer_str = ','.join(sanitizer_flags)
        
        # Get compiler and fuzzing engine
        try:
            compiler, engine = self._get_compiler()
        except RuntimeError as e:
            return {
                'target_name': output_name,
                'target_id': target_id,
                'harness_file': os.path.basename(harness_file),
                'source_file': source_file,
                'sanitizers': ', '.join(sanitizers),
                'status': 'error',
                'build_time': 0,
                'command': str(e),
                'log': str(e),
                'output_path': None
            }
        
        # Determine if we're running in Docker
        in_docker = is_running_in_docker()
        
        # Convert paths based on environment
        if in_docker:
            # Already in Docker - use paths as-is
            harness_file = os.path.abspath(harness_file)
            output_path = os.path.abspath(output_path)
            source_dir = os.path.join(self.scan_dir, 'source')
        else:
            # Running on host - convert to Docker paths
            # Host paths like C:\Users\...\scans\xxx become /app/scans/xxx
            harness_file_abs = os.path.abspath(harness_file)
            output_path_abs = os.path.abspath(output_path)
            
            # Convert Windows paths to Docker paths
            # Extract the scan ID from the path
            scan_id = os.path.basename(self.scan_dir)
            harness_file = f'/app/scans/{scan_id}/fuzz/harnesses/{os.path.basename(harness_file)}'
            output_path = f'/app/scans/{scan_id}/build/{os.path.basename(output_path)}'
            source_dir = f'/app/scans/{scan_id}/source'
        
        # Build command based on fuzzing engine
        if engine == 'libfuzzer':
            cmd = [
                compiler,
                f'-fsanitize=fuzzer,{sanitizer_str}',
                '-g',
                '-O1',
                '-std=c++17',
                f'-I{source_dir}',
                f'-o{output_path}',
                harness_file
            ]
        elif engine == 'afl':
            # AFL++ doesn't use -fsanitize=fuzzer
            cmd = [
                compiler,
                f'-fsanitize={sanitizer_str}',
                '-g',
                '-O1',
                '-std=c++17',
                f'-I{source_dir}',
                f'-o{output_path}',
                harness_file
            ]
        else:
            raise RuntimeError(f"Unknown fuzzing engine: {engine}")
        
        # Use shared source object file (compiled once in build_all_targets)
        # Only add it if it exists - it's optional
        if in_docker:
            source_obj = os.path.join(self.build_dir, 'test_source.o')
            if os.path.exists(source_obj):
                cmd.append(source_obj)
                logger.debug(f"Linking with source object file: {source_obj}")
            else:
                logger.debug(f"Source object file not found, building harness standalone")
        else:
            # Running on host - check if object file exists in Docker
            scan_id = os.path.basename(self.scan_dir)
            source_obj = f'/app/scans/{scan_id}/build/test_source.o'
            host_obj_path = os.path.join(self.scan_dir, 'build', 'test_source.o')
            
            # Check on host filesystem (Docker volume mount)
            if os.path.exists(host_obj_path):
                cmd.append(source_obj)
                logger.debug(f"Linking with source object file: {source_obj}")
            else:
                logger.debug(f"Source object file not found, building harness standalone")
        
        command_str = ' '.join(cmd)
        
        logger.info(f"Building {output_name}...")
        logger.debug(f"Command: {command_str}")
        
        # Execute build
        try:
            if in_docker:
                # Run directly
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60  # 60 second timeout per build
                )
            else:
                # Run inside Docker container
                result = self._run_in_docker(cmd, timeout=60)
            
            build_time = time.time() - start_time
            
            if result.returncode == 0:
                status = 'success'
                log = result.stdout if result.stdout else 'Build successful'
                logger.info(f"✓ Built {output_name} in {build_time:.2f}s")
                error_category = None
                user_message = None
            else:
                status = 'error'
                log = result.stderr if result.stderr else result.stdout
                logger.error(f"✗ Failed to build {output_name}: {log[:200]}")
                
                # Categorize the error and provide user-friendly explanation
                error_category, user_message = self._categorize_build_error(log, function_name)
            
            return {
                'target_name': output_name,
                'target_id': target_id,
                'harness_file': os.path.basename(harness_file),
                'source_file': source_file,
                'sanitizers': ', '.join(sanitizers),
                'status': status,
                'build_time': round(build_time, 2),
                'command': command_str,
                'log': log,
                'output_path': output_path if status == 'success' else None,
                'error_category': error_category,
                'user_message': user_message
            }
            
        except subprocess.TimeoutExpired:
            build_time = time.time() - start_time
            logger.error(f"✗ Build timeout for {output_name}")
            return {
                'target_name': output_name,
                'target_id': target_id,
                'harness_file': os.path.basename(harness_file),
                'source_file': source_file,
                'sanitizers': ', '.join(sanitizers),
                'status': 'error',
                'build_time': round(build_time, 2),
                'command': command_str,
                'log': 'Build timeout (>60s)',
                'output_path': None
            }
        except Exception as e:
            build_time = time.time() - start_time
            logger.error(f"✗ Build exception for {output_name}: {e}")
            return {
                'target_name': output_name,
                'target_id': target_id,
                'harness_file': os.path.basename(harness_file),
                'source_file': source_file,
                'sanitizers': ', '.join(sanitizers),
                'status': 'error',
                'build_time': round(build_time, 2),
                'command': command_str,
                'log': str(e),
                'output_path': None,
                'error_category': 'system_error',
                'user_message': f'System error during build: {str(e)}'
            }
    
    def _categorize_build_error(self, error_log: str, function_name: str) -> tuple:
        """
        Categorize build errors and provide user-friendly explanations
        
        Args:
            error_log: The compiler error output
            function_name: Name of the function being built
            
        Returns:
            Tuple of (error_category, user_message)
        """
        error_log_lower = error_log.lower()
        
        # Compiler not found (check early)
        if 'command not found' in error_log_lower or ('no such file or directory' in error_log_lower and ('clang' in error_log_lower or 'g++' in error_log_lower)):
            return ('compiler_missing',
                   f'🚫 Compiler not found. LibFuzzer requires clang++ to be installed. '
                   f'Please install LLVM/Clang and restart the build.')
        
        # Permission errors (check early)
        if 'permission denied' in error_log_lower:
            return ('permission_error',
                   f'🔒 Permission denied. Check file permissions and Docker volume mounts.')
        
        # Function signature conflicts (most common for unknown functions)
        if 'conflicting types' in error_log_lower and 'previous declaration' in error_log_lower:
            return ('signature_conflict', 
                   f'⚠️ Function signature ambiguity for "{function_name}". '
                   f'This happens when the function signature cannot be determined automatically. '
                   f'The harness generator tried multiple common signatures but they conflict. '
                   f'This is expected for functions with unknown signatures and can be safely ignored.')
        
        # Missing function definition
        if 'undefined reference' in error_log_lower or 'undefined symbol' in error_log_lower:
            return ('missing_function',
                   f'❌ Function "{function_name}" not found in source code. '
                   f'The function may have been renamed, removed, or is in a different file. '
                   f'Check that the function exists in the source files.')
        
        # Include/header issues (check before generic error)
        if ('file not found' in error_log_lower or 'no such file or directory' in error_log_lower) and ('.h' in error_log_lower or '.hpp' in error_log_lower or '#include' in error_log_lower):
            return ('missing_headers',
                   f'📁 Missing header files. Some #include statements cannot be resolved. '
                   f'This may require additional include directories or installing dependencies.')
        
        # Syntax errors in generated harness
        if 'syntax error' in error_log_lower or 'expected' in error_log_lower:
            return ('syntax_error',
                   f'🔧 Syntax error in generated harness. '
                   f'The harness generator may have created invalid C++ code. '
                   f'This can happen with complex function signatures.')
        
        # Linker errors
        if 'ld:' in error_log_lower or 'linker' in error_log_lower:
            return ('linker_error',
                   f'🔗 Linker error. All code compiled successfully but linking failed. '
                   f'This may require additional libraries or object files.')
        
        # Sanitizer issues
        if 'sanitizer' in error_log_lower:
            return ('sanitizer_error',
                   f'🛡️ Sanitizer configuration issue. '
                   f'The requested sanitizers may not be compatible or available.')
        
        # Generic compilation error
        if 'error:' in error_log_lower:
            return ('compilation_error',
                   f'⚙️ Compilation error in "{function_name}". '
                   f'There may be issues with the source code or harness generation.')
        
        # Unknown error
        return ('unknown_error',
               f'❓ Unknown build error for "{function_name}". '
               f'Check the detailed error log for more information.')
    
    def build_all_targets(self) -> List[Dict]:
        """
        Build all fuzz targets from harnesses
        
        Returns:
            List of build result dictionaries
        """
        logger.info(f"Starting build orchestration for {self.scan_dir}")
        
        # Load fuzz plan
        try:
            fuzz_plan = self._load_fuzz_plan()
        except Exception as e:
            logger.error(f"Cannot load fuzz plan: {e}")
            return []
        
        targets = fuzz_plan.get('targets', [])
        if not targets:
            logger.warning("No targets in fuzz plan")
            return []
        
        # Check if harnesses exist
        if not os.path.exists(self.harness_dir):
            logger.error(f"Harness directory not found: {self.harness_dir}")
            return []
        
        # Get list of harness files
        harness_files = [
            f for f in os.listdir(self.harness_dir)
            if f.endswith('.cc') or f.endswith('.cpp')
        ]
        
        if not harness_files:
            logger.warning("No harness files found")
            return []
        
        logger.info(f"Found {len(harness_files)} harness files")
        
        # Compile source file once (shared by all targets)
        self._compile_source_file()
        
        # Build each target
        build_results = []
        for i, target in enumerate(targets, 1):
            function_name = target.get('function_name', 'unknown')
            
            # Find matching harness file
            harness_file = None
            for hf in harness_files:
                if function_name.lower() in hf.lower():
                    harness_file = os.path.join(self.harness_dir, hf)
                    break
            
            if not harness_file:
                logger.warning(f"No harness file found for {function_name}")
                continue
            
            logger.info(f"Building target {i}/{len(targets)}: {function_name}")
            result = self._build_single_target(target, harness_file)
            build_results.append(result)
        
        # Save build log
        self._save_build_log(build_results)
        
        # Summary
        success_count = sum(1 for r in build_results if r['status'] == 'success')
        error_count = sum(1 for r in build_results if r['status'] == 'error')
        
        logger.info(f"Build complete: {success_count} successful, {error_count} failed")
        
        return build_results
    
    def _save_build_log(self, build_results: List[Dict]):
        """Save build log to JSON file"""
        log_path = os.path.join(self.build_dir, '.build_log.json')
        
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'scan_dir': self.scan_dir,
            'total_targets': len(build_results),
            'successful': sum(1 for r in build_results if r['status'] == 'success'),
            'failed': sum(1 for r in build_results if r['status'] == 'error'),
            'builds': build_results
        }
        
        with open(log_path, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2)
        
        logger.info(f"Build log saved: {log_path}")
    
    def get_build_results(self) -> Optional[Dict]:
        """Load existing build results"""
        log_path = os.path.join(self.build_dir, '.build_log.json')
        
        if not os.path.exists(log_path):
            return None
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load build log: {e}")
            return None
    
    def test_run_target(self, target_name: str, runs: int = 100) -> Dict:
        """
        Run a quick test of a built target
        
        Args:
            target_name: Name of the target to test
            runs: Number of test runs
            
        Returns:
            Test result dictionary
        """
        target_path = os.path.join(self.build_dir, target_name)
        
        if not os.path.exists(target_path):
            return {
                'success': False,
                'error': 'Target not found'
            }
        
        # Run with limited iterations
        cmd = [target_path, f'-runs={runs}']
        
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            elapsed = time.time() - start_time
            
            return {
                'success': True,
                'executions': runs,
                'time': round(elapsed, 2),
                'output': result.stdout + result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Test run timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
