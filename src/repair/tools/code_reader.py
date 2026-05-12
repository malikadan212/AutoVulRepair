"""
Code Reader Tools
Read and extract source code for analysis
"""
import os
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class CodeReader:
    """Helper class for reading and extracting source code"""
    
    def __init__(self, scan_id: str = None):
        """
        Initialize code reader
        
        Args:
            scan_id: Scan ID (optional)
        """
        self.scan_id = scan_id
        self._source_files_cache = None
    
    def _get_source_files(self) -> dict:
        """Get source files from database, with caching"""
        if self._source_files_cache is not None:
            return self._source_files_cache
        
        if not self.scan_id:
            logger.warning("No scan_id provided to CodeReader")
            return {}
        
        try:
            # Access database directly to avoid circular imports
            from src.models.scan_v2 import DatabaseManager, ScanSource
            from src.config.database import get_secure_database_url
            import os
            
            # Initialize database connection
            DATABASE_URL = get_secure_database_url()
            db_manager = DatabaseManager(DATABASE_URL)
            session = db_manager.get_session()
            
            try:
                # Get source files directly from database
                sources = session.query(ScanSource).filter(ScanSource.scan_id == self.scan_id).all()
                
                if not sources:
                    logger.warning(f"No source files found for scan {self.scan_id}")
                    return {}
                
                # Create a mapping of file paths to content
                file_map = {}
                for source in sources:
                    file_path = source.file_path
                    content = source.file_content
                    
                    if content:
                        # Map multiple path formats for compatibility
                        file_map[file_path] = content
                        file_map[f'/tmp/source/{file_path}'] = content
                        file_map[f'/tmp/source/{os.path.basename(file_path)}'] = content
                        file_map[os.path.basename(file_path)] = content
                        
                        # Also map without leading slash if it exists
                        if file_path.startswith('/'):
                            file_map[file_path[1:]] = content
                
                self._source_files_cache = file_map
                logger.info(f"Loaded {len(sources)} source files from database")
                return file_map
                
            finally:
                session.close()
        except Exception as e:
            logger.error(f"Failed to get source files from database: {e}")
            return {}
            logger.error(f"Failed to get source files from database: {e}")
            return {}
    
    def _get_file_content_from_db(self, source_id: str) -> Optional[str]:
        """Get file content from database by source ID"""
        try:
            from src.models.scan_v2 import ScanSource, DatabaseManager
            from src.config.database import get_secure_database_url
            import os
            
            DATABASE_URL = get_secure_database_url()
            db_manager = DatabaseManager(DATABASE_URL)
            session = db_manager.get_session()
            
            try:
                source = session.query(ScanSource).filter(ScanSource.id == source_id).first()
                if source:
                    return source.file_content
                return None
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Failed to get file content from database: {e}")
            return None
    
    def read_file(self, file_path: str) -> Optional[str]:
        """
        Read source file from database
        
        Args:
            file_path: Path to file
            
        Returns:
            File contents or None
        """
        try:
            source_files = self._get_source_files()
            
            # Try different path formats
            for path_variant in [file_path, f'/tmp/source/{os.path.basename(file_path)}', os.path.basename(file_path)]:
                if path_variant in source_files:
                    content = source_files[path_variant]
                    logger.info(f"Read {len(content)} chars from {file_path}")
                    return content
            
            logger.warning(f"File not found in database: {file_path}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            return None
    
    def extract_code_around_line(
        self,
        file_path: str,
        line_number: int,
        context_lines: int = 20
    ) -> Optional[str]:
        """
        Extract code around a specific line
        
        Args:
            file_path: Path to file
            line_number: Target line number
            context_lines: Lines of context
            
        Returns:
            Code context or None
        """
        try:
            # Read file
            content = self.read_file(file_path)
            if not content:
                return None
            
            # Extract context
            context, _, _ = extract_code_around_line(content, line_number, context_lines)
            return context
            
        except Exception as e:
            logger.error(f"Failed to extract code context: {e}")
            return None
    
    def extract_function(
        self,
        file_path: str,
        function_name: str,
        target_line: int = None
    ) -> Optional[str]:
        """
        Extract function code
        
        Args:
            file_path: Path to file
            function_name: Function name
            target_line: Target line (optional)
            
        Returns:
            Function code or None
        """
        try:
            content = self.read_file(file_path)
            if not content:
                return None
            
            code, _, _ = extract_function_context(content, function_name, target_line)
            return code
            
        except Exception as e:
            logger.error(f"Failed to extract function: {e}")
            return None


def read_source_code(scan_id: str, file_path: str) -> Optional[str]:
    """
    Read source code file from database
    
    Args:
        scan_id: Scan ID
        file_path: Relative path to source file
        
    Returns:
        File contents or None if not found
    """
    try:
        reader = CodeReader(scan_id)
        return reader.read_file(file_path)
        
    except Exception as e:
        logger.error(f"Failed to read source file {file_path}: {e}")
        return None


def extract_function_context(
    source_code: str,
    function_name: str,
    target_line: int = None,
    context_lines: int = 20
) -> Tuple[Optional[str], int, int]:
    """
    Extract function code with context
    
    Args:
        source_code: Full source code
        function_name: Function name to extract
        target_line: Target line number (optional)
        context_lines: Lines of context around target
        
    Returns:
        Tuple of (function_code, start_line, end_line) or (None, 0, 0)
    """
    try:
        lines = source_code.split('\n')
        
        # Find function definition
        function_start = None
        for i, line in enumerate(lines):
            # Look for function definition patterns
            if function_name in line and ('(' in line or '{' in line):
                # Check if it's a function definition (not a call)
                if any(keyword in line for keyword in ['int ', 'void ', 'char ', 'static ', 'extern ']):
                    function_start = i
                    break
        
        if function_start is None:
            logger.warning(f"Function {function_name} not found in source")
            
            # Fallback: extract around target line if provided
            if target_line:
                start = max(0, target_line - context_lines - 1)
                end = min(len(lines), target_line + context_lines)
                context = '\n'.join(lines[start:end])
                return context, start + 1, end + 1
            
            return None, 0, 0
        
        # Find function end (matching braces)
        brace_count = 0
        function_end = function_start
        in_function = False
        
        for i in range(function_start, len(lines)):
            line = lines[i]
            
            # Count braces
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            if '{' in line:
                in_function = True
            
            if in_function and brace_count == 0:
                function_end = i
                break
        
        # Extract function with some context
        start = max(0, function_start - 2)
        end = min(len(lines), function_end + 3)
        
        function_code = '\n'.join(lines[start:end])
        
        logger.info(f"Extracted function {function_name}: lines {start+1}-{end+1}")
        return function_code, start + 1, end + 1
        
    except Exception as e:
        logger.error(f"Failed to extract function context: {e}")
        return None, 0, 0


def extract_code_around_line(
    source_code: str,
    line_number: int,
    context_lines: int = 20
) -> Tuple[str, int, int]:
    """
    Extract code around a specific line
    
    Args:
        source_code: Full source code
        line_number: Target line number
        context_lines: Lines of context before and after
        
    Returns:
        Tuple of (code_context, start_line, end_line)
    """
    try:
        lines = source_code.split('\n')
        
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context = '\n'.join(lines[start:end])
        
        logger.info(f"Extracted context around line {line_number}: lines {start+1}-{end+1}")
        return context, start + 1, end + 1
        
    except Exception as e:
        logger.error(f"Failed to extract code context: {e}")
        return "", 0, 0


def get_file_info(scan_id: str, file_path: str) -> dict:
    """
    Get information about a source file
    
    Args:
        scan_id: Scan ID
        file_path: Relative path to source file
        
    Returns:
        Dict with file info (size, lines, language, etc.)
    """
    try:
        scans_dir = os.getenv('SCANS_DIR', './scans')
        source_dir = os.path.join(scans_dir, scan_id, 'source')
        
        if file_path.startswith('/source/'):
            file_path = file_path[8:]
        
        full_path = os.path.join(source_dir, file_path)
        
        if not os.path.exists(full_path):
            return {'exists': False}
        
        # Get file stats
        stat = os.stat(full_path)
        
        # Read file
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # Determine language
        ext = Path(file_path).suffix.lower()
        language_map = {
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.cxx': 'C++',
            '.h': 'C/C++ Header',
            '.hpp': 'C++ Header',
            '.py': 'Python',
            '.js': 'JavaScript',
            '.java': 'Java'
        }
        
        return {
            'exists': True,
            'path': file_path,
            'size': stat.st_size,
            'lines': len(lines),
            'language': language_map.get(ext, 'Unknown'),
            'extension': ext
        }
        
    except Exception as e:
        logger.error(f"Failed to get file info: {e}")
        return {'exists': False, 'error': str(e)}
