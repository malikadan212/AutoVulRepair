import os
import re
import zipfile
from pathlib import Path

def is_safe_path(path, base_path):
    """Check if path is safe (no directory traversal)"""
    try:
        # Resolve the path and check if it's within base_path
        resolved_path = Path(base_path).resolve() / Path(path)
        resolved_path.resolve()
        return str(resolved_path).startswith(str(Path(base_path).resolve()))
    except (OSError, ValueError):
        return False

def safe_extract_zip(zip_file_path, extract_to):
    """Safely extract ZIP file with path traversal protection"""
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
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
        
        # If all files are safe, extract them
        zip_ref.extractall(extract_to)

def is_valid_github_url(url):
    """Validate GitHub repository URL format"""
    if not url:
        return False
    
    # GitHub URL pattern: https://github.com/username/repository
    pattern = r'^https://github\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/?$'
    return bool(re.match(pattern, url))

def validate_zip_file(file_obj):
    """Validate that uploaded file is a valid ZIP file"""
    if not file_obj:
        return False, "No file provided"
    
    # Check file extension
    if not file_obj.filename.lower().endswith('.zip'):
        return False, "File must have .zip extension"
    
    # Check magic bytes
    file_obj.seek(0)
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