"""
Docker helper utilities for running static analysis tools in containers
"""
import os
import docker
import logging
import tempfile
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

class DockerToolRunner:
    """Helper class to run analysis tools in Docker containers"""
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.client.ping()  # Test connection
            self.available = True
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            self.available = False
            self.client = None
    
    def is_docker_available(self):
        """Check if Docker daemon is accessible"""
        return self.available
    
    def image_exists(self, image_name):
        """Check if a Docker image exists"""
        if not self.available:
            return False
        try:
            self.client.images.get(image_name)
            return True
        except docker.errors.ImageNotFound:
            # For Microsoft container, also check if we can pull it
            if 'mcr.microsoft.com' in image_name:
                try:
                    self.client.images.pull(image_name)
                    return True
                except:
                    pass
            return False
    
    def run_cppcheck(self, source_path, output_file=None, timeout=120):
        """
        Run Cppcheck in Docker container
        
        Args:
            source_path: Path to source code directory
            output_file: Optional path to save XML output
            timeout: Container timeout in seconds
            
        Returns:
            tuple: (stdout, stderr, return_code)
        """
        if not self.available:
            raise RuntimeError("Docker is not available")
        
        if not self.image_exists('vuln-scanner/cppcheck:latest'):
            raise RuntimeError("Cppcheck Docker image not found. Run: python build_docker_tools.py")
        
        # Ensure source path exists and is absolute
        source_path = os.path.abspath(source_path)
        if not os.path.exists(source_path):
            raise ValueError(f"Source path does not exist: {source_path}")
        
        # Create output directory if needed
        output_dir = None
        if output_file:
            output_dir = os.path.dirname(output_file)
            os.makedirs(output_dir, exist_ok=True)
            output_filename = os.path.basename(output_file)
        else:
            # Use temporary file
            temp_dir = tempfile.mkdtemp()
            output_dir = temp_dir
            output_filename = 'cppcheck-results.xml'
        
        # Ensure absolute host paths for Docker volume mounts (Windows-safe)
        output_dir = os.path.abspath(output_dir)
        source_path = os.path.abspath(source_path)
        
        try:
            # Copy source files into container instead of volume mounting (Windows compatibility)
            import tarfile
            import io
            
            # Create tar archive of source directory
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                tar.add(source_path, arcname='source')
            tar_buffer.seek(0)
            
            # Create container (don't start yet)
            container = self.client.containers.create(
                'vuln-scanner/cppcheck:latest',
                command=[
                    '--enable=all',
                    '--inconclusive',
                    '--xml',
                    '--xml-version=2',
                    '--output-file=/tmp/cppcheck-report.xml',
                    '/tmp/source'
                ],
                working_dir='/tmp',
                mem_limit='2g',
                network_disabled=True
            )
            
            # Copy source files into container
            container.put_archive('/tmp', tar_buffer)
            
            # Start container and wait for completion
            container.start()
            result = container.wait()
            exit_code = result['StatusCode']
            
            # Get the XML output from container
            try:
                archive_data, _ = container.get_archive('/tmp/cppcheck-report.xml')
                
                # Extract XML content from tar archive
                tar_buffer = io.BytesIO()
                for chunk in archive_data:
                    tar_buffer.write(chunk)
                tar_buffer.seek(0)
                
                with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
                    xml_file = tar.extractfile('cppcheck-report.xml')
                    if xml_file:
                        stdout = xml_file.read().decode('utf-8', errors='ignore')
                        
                        # Save to final destination if specified
                        if output_file:
                            try:
                                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                                with open(output_file, 'w', encoding='utf-8') as f:
                                    f.write(stdout)
                            except Exception as copy_err:
                                logger.warning(f"Failed to save output file: {copy_err}")
                        
                        # Remove container
                        container.remove()
                        
                        # Return success - exit code doesn't matter if we have XML
                        return stdout, "", 0
                    else:
                        container.remove()
                        return "", f"Could not extract XML from container (exit code: {exit_code})", 1
                        
            except docker.errors.NotFound:
                # XML file not created
                container.remove()
                return "", f"Cppcheck did not produce output file (exit code: {exit_code})", 1
            
        except docker.errors.ContainerError as e:
            return "", str(e), e.exit_status
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API error: {e}")
        except Exception as e:
            return "", f"Unexpected error: {e}", 1
    
    def run_codeql_database_create(self, source_path, db_path, languages, timeout=300):
        """
        Create CodeQL database using Microsoft CodeQL container
        
        Args:
            source_path: Path to source code
            db_path: Path where database will be created
            languages: List of language strings (e.g., ['cpp', 'python'])
            timeout: Container timeout in seconds
            
        Returns:
            tuple: (stdout, stderr, return_code)
        """
        if not self.available:
            raise RuntimeError("Docker is not available")
        
        # Use Microsoft container - check for either tag
        image_name = 'vuln-scanner/codeql:latest'
        if not self.image_exists(image_name):
            image_name = 'mcr.microsoft.com/cstsectools/codeql-container:latest'
            if not self.image_exists(image_name):
                raise RuntimeError("CodeQL Docker image not found. Run: python build_docker_tools.py")
        
        source_path = os.path.abspath(source_path)
        db_path = os.path.abspath(db_path)
        os.makedirs(db_path, exist_ok=True)
        
        language_str = ','.join(languages)
        
        try:
            # Microsoft container - bypass entrypoint to avoid setup.py permission issues
            # CodeQL is located at /usr/local/codeql-home/codeql/codeql
            # Use full path to ensure it works regardless of PATH
            codeql_path = '/usr/local/codeql-home/codeql/codeql'
            
            # For compiled languages (C++/Java/C#), let autobuild detect build system
            # If Makefile/CMakeLists.txt exists, autobuild will use it
            # If not, analysis will fail (which is correct behavior)
            logger.info(f"[CODEQL_DOCKER] Creating database for language: {language_str}")
            cmd = f'{codeql_path} database create --language={language_str} /opt/results/source_db -s /opt/src'
            container = self.client.containers.run(
                image_name,
                command=[cmd],  # Pass as list with single string for /bin/sh -c
                volumes={
                    source_path: {'bind': '/opt/src', 'mode': 'rw'},  # RW needed for symlink creation
                    db_path: {'bind': '/opt/results', 'mode': 'rw'}
                },
                remove=False,  # Keep container to check logs
                mem_limit='4g',
                network_disabled=False,
                detach=True,  # Run in background
                entrypoint=['/bin/sh', '-c']  # Override entrypoint to bypass setup.py
            )
            
            # Wait for container to complete
            try:
                result = container.wait(timeout=timeout)
                exit_code = result.get('StatusCode', result) if isinstance(result, dict) else result
                
                # Get logs
                logs = container.logs(stdout=True, stderr=True)
                log_text = logs.decode('utf-8', errors='ignore') if logs else ""
                
                # Clean up
                try:
                    container.remove()
                except:
                    pass
                
                # Check if database was created
                db_expected_path = os.path.join(db_path, 'source_db')
                
                if exit_code == 0 and os.path.exists(db_expected_path):
                    return log_text, "", 0
                else:
                    return "", f"Exit code: {exit_code}. Logs: {log_text[:500]}", exit_code
                    
            except Exception as wait_error:
                # Container timed out or failed
                try:
                    logs = container.logs()
                    log_text = logs.decode('utf-8', errors='ignore') if logs else str(wait_error)
                    container.remove()
                except:
                    log_text = str(wait_error)
                
                return "", f"Container wait failed: {log_text[:500]}", 1
                
        except docker.errors.ImageNotFound:
            raise RuntimeError(f"CodeQL Docker image '{image_name}' not found")
        except docker.errors.ContainerError as e:
            return "", str(e), e.exit_status if hasattr(e, 'exit_status') else 1
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API error: {e}")
    
    def run_codeql_analyze(self, db_path, sarif_output_path, language='javascript', timeout=300):
        """
        Run CodeQL analysis using Microsoft CodeQL container
        
        Args:
            db_path: Path to CodeQL database directory (contains source_db subdirectory)
            sarif_output_path: Path to save SARIF output
            language: Programming language for QL pack selection (e.g., 'python', 'javascript', 'cpp')
            timeout: Container timeout in seconds
            
        Returns:
            tuple: (stdout, stderr, return_code)
        """
        if not self.available:
            raise RuntimeError("Docker is not available")
        
        # Use Microsoft container - check for either tag
        image_name = 'vuln-scanner/codeql:latest'
        if not self.image_exists(image_name):
            image_name = 'mcr.microsoft.com/cstsectools/codeql-container:latest'
            if not self.image_exists(image_name):
                raise RuntimeError("CodeQL Docker image not found. Run: python build_docker_tools.py")
        
        db_path = os.path.abspath(db_path)
        sarif_dir = os.path.abspath(os.path.dirname(sarif_output_path))
        os.makedirs(sarif_dir, exist_ok=True)
        sarif_filename = os.path.basename(sarif_output_path)
        
        # Microsoft container creates db at /opt/results/source_db
        # So db_path contains source_db subdirectory
        # We mount db_path to /opt/results so /opt/results/source_db exists
        try:
            # Microsoft container - bypass entrypoint and run codeql command directly
            # CodeQL is located at /usr/local/codeql-home/codeql/codeql
            codeql_path = '/usr/local/codeql-home/codeql/codeql'
            logger.debug(f"Running analysis for language: {language}")
            
            # Use language-specific query pack (standard security queries)
            # Format: codeql/language-queries:codeql-suites/language-security-extended.qls
            query_pack_map = {
                'cpp': 'codeql/cpp-queries:codeql-suites/cpp-security-extended.qls',
                'c': 'codeql/cpp-queries:codeql-suites/cpp-security-extended.qls'
            }
            
            query_suite = query_pack_map.get(language, f'codeql/{language}-queries')
            logger.info(f"Using query suite: {query_suite}")
            
            # Write SARIF to a dedicated output mount so it lands at sarif_output_path on host
            cmd = f'{codeql_path} database analyze --format=sarif-latest --output=/opt/out/{sarif_filename} /opt/results/source_db {query_suite}'
            container = self.client.containers.run(
                image_name,
                command=[cmd],  # Pass as list with single string for /bin/sh -c
                volumes={
                    db_path: {'bind': '/opt/results', 'mode': 'rw'},
                    sarif_dir: {'bind': '/opt/out', 'mode': 'rw'}
                },
                remove=False,  # Keep to check logs
                mem_limit='4g',
                network_disabled=False,
                detach=True,  # Run in background
                entrypoint=['/bin/sh', '-c']  # Override entrypoint to bypass setup.py
            )
            
            # Wait for container to complete - CodeQL queries can take 5-15 minutes
            try:
                logger.info(f"[CODEQL_ANALYZE] Waiting for analysis to complete (timeout: {timeout}s)...")
                result = container.wait(timeout=timeout)
                exit_code = result.get('StatusCode', result) if isinstance(result, dict) else result
                logger.info(f"[CODEQL_ANALYZE] Container finished with exit code: {exit_code}")
                
                # Get logs
                logs = container.logs(stdout=True, stderr=True)
                log_text = logs.decode('utf-8', errors='ignore') if logs else ""
                
                # Clean up
                try:
                    container.remove()
                except:
                    pass
                
                # Check if SARIF file was created
                if exit_code == 0 and os.path.exists(sarif_output_path):
                    return log_text, "", 0
                else:
                    return "", f"Exit code: {exit_code}. Logs: {log_text[:500]}", exit_code
                    
            except Exception as wait_error:
                # Timeout or other error - try to get logs anyway
                logger.warning(f"[CODEQL_ANALYZE] Container wait exception: {wait_error}")
                try:
                    logs = container.logs(stdout=True, stderr=True)
                    log_text = logs.decode('utf-8', errors='ignore') if logs else str(wait_error)
                    logger.debug(f"[CODEQL_ANALYZE] Partial logs: {log_text[:500]}")
                    container.stop(timeout=10)
                    container.remove()
                except:
                    log_text = str(wait_error)
                
                return "", f"Container wait failed: {log_text[:500]}", 1
            
        except docker.errors.ContainerError as e:
            # Check if file was still created despite error
            expected_path = os.path.join(sarif_dir, sarif_filename)
            if os.path.exists(expected_path):
                import shutil
                try:
                    # Already in the correct location; ensure final path exists
                    if expected_path != sarif_output_path:
                        shutil.move(expected_path, sarif_output_path)
                    return "", "", 0
                except Exception:
                    pass
            return "", str(e), e.exit_status
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API error: {e}")
    
    def test_tool_image(self, image_name):
        """Test if a Docker image is working by running version command"""
        if not self.available:
            return False
        
        if not self.image_exists(image_name):
            return False
        
        try:
            if 'cppcheck' in image_name:
                result = self.client.containers.run(
                    image_name,
                    ['--version'],
                    remove=True
                )
            elif 'codeql' in image_name:
                # Microsoft CodeQL container uses environment variable
                result = self.client.containers.run(
                    image_name,
                    environment={'CODEQL_CLI_ARGS': '--version'},
                    remove=True
                )
            else:
                return False
            
            return True
        except Exception as e:
            logger.error(f"Tool image test failed: {e}")
            return False

