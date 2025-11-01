import os
import re
import zipfile
from pathlib import Path

# Maximum file size limits
MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100MB
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500MB maximum extracted size

def is_safe_path(path, base_path):
    """Check if path is safe (no directory traversal)"""
    try:
        # Resolve the path and check if it's within base_path
        resolved_path = Path(base_path).resolve() / Path(path)
        resolved_path.resolve()
        return str(resolved_path).startswith(str(Path(base_path).resolve()))
    except (OSError, ValueError):
        return False

def safe_extract_zip(zip_file_path, extract_to, timeout=120):
    """Safely extract ZIP file with path traversal protection and resource limits"""
    import threading
    import signal
    
    extracted_size = 0
    file_count = 0
    max_files = 10000  # Limit number of files to prevent exhaustion
    
    def _extract_with_limits():
        nonlocal extracted_size, file_count
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            # Validate all entries before extraction
            for member in zip_ref.infolist():
                # Check for directory traversal
                if '..' in member.filename or member.filename.startswith('/'):
                    raise ValueError(f"Unsafe path in ZIP: {member.filename}")
                
                # Check for absolute paths
                if os.path.isabs(member.filename):
                    raise ValueError(f"Absolute path in ZIP: {member.filename}")
                
                # Additional safety check
                if not is_safe_path(member.filename, extract_to):
                    raise ValueError(f"Path traversal attempt: {member.filename}")
                
                # Check file count limit
                file_count += 1
                if file_count > max_files:
                    raise ValueError(f"ZIP contains too many files (>{max_files}). Possible archive bomb.")
                
                # Check individual file size (prevent extremely large single files)
                if member.file_size > 100 * 1024 * 1024:  # 100MB per file
                    raise ValueError(f"File '{member.filename}' exceeds 100MB limit")
                
                # Track total extracted size
                extracted_size += member.file_size
                if extracted_size > MAX_EXTRACTED_SIZE:
                    raise ValueError(f"Total extracted size would exceed {MAX_EXTRACTED_SIZE / (1024*1024)}MB limit")
            
            # If all files are safe, extract them
            zip_ref.extractall(extract_to)
    
    # Extract with timeout protection (Unix-like systems)
    if hasattr(signal, 'SIGALRM'):
        # Use signal-based timeout on Unix
        def timeout_handler(signum, frame):
            raise TimeoutError(f"ZIP extraction timed out after {timeout} seconds")
        
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        try:
            _extract_with_limits()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Windows or systems without SIGALRM - use threading timeout
        import queue
        result_queue = queue.Queue()
        exception_queue = queue.Queue()
        
        def extract_thread():
            try:
                _extract_with_limits()
                result_queue.put(True)
            except Exception as e:
                exception_queue.put(e)
        
        thread = threading.Thread(target=extract_thread, daemon=True)
        thread.start()
        thread.join(timeout=timeout)
        
        # Check if thread is still running (timed out)
        if thread.is_alive():
            raise TimeoutError(f"ZIP extraction timed out after {timeout} seconds")
        
        # Check for exceptions first
        if not exception_queue.empty():
            raise exception_queue.get()
        
        # Check for successful completion
        if not result_queue.empty():
            return  # Success
        
        # If we get here, something unexpected happened
        raise RuntimeError("ZIP extraction failed for unknown reason")

def is_valid_github_url(url):
    """Validate GitHub repository URL format"""
    if not url:
        return False
    
    # GitHub URL pattern: https://github.com/username/repository
    pattern = r'^https://github\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/?$'
    return bool(re.match(pattern, url))

def validate_zip_file(file_obj):
    """Validate that uploaded file is a valid ZIP file with size limits"""
    if not file_obj:
        return False, "No file provided"
    
    # Check file extension
    if not file_obj.filename.lower().endswith('.zip'):
        return False, "File must have .zip extension"
    
    # Check file size to prevent resource exhaustion
    file_obj.seek(0, os.SEEK_END)
    file_size = file_obj.tell()
    file_obj.seek(0)  # Reset file pointer
    
    if file_size > MAX_ZIP_SIZE:
        size_mb = file_size / (1024 * 1024)
        max_mb = MAX_ZIP_SIZE / (1024 * 1024)
        return False, f"File size ({size_mb:.1f}MB) exceeds maximum allowed size ({max_mb}MB)"
    
    # Check magic bytes
    magic_bytes = file_obj.read(4)
    file_obj.seek(0)  # Reset file pointer
    
    # ZIP file magic signatures
    zip_signatures = [
        b'PK\x03\x04',  # Standard ZIP
        b'PK\x05\x06',  # Empty ZIP
        b'PK\x07\x08'   # Spanned ZIP
    ]
    
    if not any(magic_bytes.startswith(sig) for sig in zip_signatures):
        return False, "File is not a valid ZIP archive"
    
    return True, "Valid ZIP file"

def validate_code_snippet(code_snippet):
    """Validate code snippet input"""
    if not code_snippet or not code_snippet.strip():
        return False, "Code snippet cannot be empty"
    
    # Check length limits
    if len(code_snippet) > 100000:  # 100KB limit
        return False, "Code snippet too large (max 100KB)"
    
    if len(code_snippet) < 10:
        return False, "Code snippet too short (min 10 characters)"
    
    return True, "Valid code snippet"

def sanitize_filename(filename):
    """Sanitize filename for safe storage"""
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    
    return filename or 'unnamed_file'