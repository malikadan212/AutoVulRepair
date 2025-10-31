import pytest
import os
import json
import tempfile
import zipfile
from unittest.mock import patch, MagicMock
from io import BytesIO

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app
from src.models.scan import get_session, Scan, create_database

@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Use in-memory database for testing
    os.environ['DATABASE_PATH'] = ':memory:'
    create_database()
    
    with app.test_client() as client:
        yield client

@pytest.fixture
def valid_zip_file():
    """Create a valid ZIP file for testing"""
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        zip_file.writestr('test.cpp', '#include <iostream>\nint main() { return 0; }')
        zip_file.writestr('header.h', '#ifndef HEADER_H\n#define HEADER_H\n#endif')
    zip_buffer.seek(0)
    return zip_buffer

@pytest.fixture
def malicious_zip_file():
    """Create a ZIP file with path traversal attempt"""
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        zip_file.writestr('../../../etc/passwd', 'malicious content')
    zip_buffer.seek(0)
    return zip_buffer

class TestScanAPI:
    """Test cases for the scan API endpoints"""
    
    def test_scan_public_with_valid_zip(self, client, valid_zip_file):
        """Test uploading a valid ZIP file"""
        with patch('src.queue.tasks.analyze_code.delay') as mock_task:
            response = client.post('/scan-public', data={
                'zip_file': (valid_zip_file, 'test.zip'),
                'analysis_tool': 'cppcheck'
            })
            
            assert response.status_code == 202
            data = json.loads(response.data)
            assert 'scan_id' in data
            assert data['status'] == 'queued'
            
            # Verify scan record was created
            session_db = get_session()
            scan = session_db.query(Scan).filter_by(id=data['scan_id']).first()
            assert scan is not None
            assert scan.source_type == 'zip'
            assert scan.analysis_tool == 'cppcheck'
            assert scan.status == 'queued'
            session_db.close()
            
            # Verify Celery task was called
            mock_task.assert_called_once()
    
    def test_scan_public_with_github_url(self, client):
        """Test scanning with a valid GitHub URL"""
        with patch('src.queue.tasks.analyze_code.delay') as mock_task:
            response = client.post('/scan-public', data={
                'repo_url': 'https://github.com/user/repo',
                'analysis_tool': 'codeql'
            })
            
            assert response.status_code == 202
            data = json.loads(response.data)
            assert 'scan_id' in data
            assert data['status'] == 'queued'
            
            # Verify scan record
            session_db = get_session()
            scan = session_db.query(Scan).filter_by(id=data['scan_id']).first()
            assert scan is not None
            assert scan.source_type == 'repo_url'
            assert scan.repo_url == 'https://github.com/user/repo'
            assert scan.analysis_tool == 'codeql'
            session_db.close()
    
    def test_scan_public_with_code_snippet(self, client):
        """Test scanning with a code snippet"""
        code_snippet = '''
        #include <iostream>
        int main() {
            char buffer[10];
            gets(buffer);  // Vulnerable function
            return 0;
        }
        '''
        
        with patch('src.queue.tasks.analyze_code.delay') as mock_task:
            response = client.post('/scan-public', data={
                'code_snippet': code_snippet,
                'analysis_tool': 'cppcheck'
            })
            
            assert response.status_code == 202
            data = json.loads(response.data)
            assert 'scan_id' in data
            
            # Verify scan record
            session_db = get_session()
            scan = session_db.query(Scan).filter_by(id=data['scan_id']).first()
            assert scan is not None
            assert scan.source_type == 'code_snippet'
            session_db.close()
    
    def test_scan_public_with_malicious_zip(self, client, malicious_zip_file):
        """Test that malicious ZIP files are rejected"""
        response = client.post('/scan-public', data={
            'zip_file': (malicious_zip_file, 'malicious.zip'),
            'analysis_tool': 'cppcheck'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Unsafe ZIP file' in data['error']
    
    def test_scan_public_invalid_github_url(self, client):
        """Test that invalid GitHub URLs are rejected"""
        response = client.post('/scan-public', data={
            'repo_url': 'https://example.com/not-github',
            'analysis_tool': 'cppcheck'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Invalid GitHub URL' in data['error']
    
    def test_scan_public_multiple_sources(self, client, valid_zip_file):
        """Test that providing multiple source types is rejected"""
        response = client.post('/scan-public', data={
            'repo_url': 'https://github.com/user/repo',
            'zip_file': (valid_zip_file, 'test.zip'),
            'analysis_tool': 'cppcheck'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Exactly one source type must be provided' in data['error']
    
    def test_scan_public_no_source(self, client):
        """Test that providing no source is rejected"""
        response = client.post('/scan-public', data={
            'analysis_tool': 'cppcheck'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Exactly one source type must be provided' in data['error']
    
    def test_scan_public_invalid_tool(self, client):
        """Test that invalid analysis tools are rejected"""
        response = client.post('/scan-public', data={
            'repo_url': 'https://github.com/user/repo',
            'analysis_tool': 'invalid_tool'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid analysis tool' in data['error']
    
    def test_scan_status_api(self, client):
        """Test the scan status API endpoint"""
        # Create a scan record
        session_db = get_session()
        scan = Scan(
            id='test-scan-id',
            source_type='repo_url',
            repo_url='https://github.com/user/repo',
            analysis_tool='cppcheck',
            status='running'
        )
        session_db.add(scan)
        session_db.commit()
        session_db.close()
        
        # Test status endpoint
        response = client.get('/api/scan-status/test-scan-id')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['scan_id'] == 'test-scan-id'
        assert data['status'] == 'running'
        assert data['analysis_tool'] == 'cppcheck'
    
    def test_scan_status_not_found(self, client):
        """Test scan status for non-existent scan"""
        response = client.get('/api/scan-status/non-existent-id')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'not found' in data['error'].lower()
    
    def test_tool_status_api(self, client):
        """Test the tool status API endpoint"""
        with patch('src.analysis.codeql.CodeQLAnalyzer.is_available', return_value=True), \
             patch('src.analysis.cppcheck.CppcheckAnalyzer.is_available', return_value=False):
            
            response = client.get('/api/tool-status')
            assert response.status_code == 200
            
            data = json.loads(response.data)
            assert 'codeql' in data
            assert 'cppcheck' in data
            assert data['codeql']['available'] is True
            assert data['cppcheck']['available'] is False
    
    def test_empty_code_snippet_rejected(self, client):
        """Test that empty code snippets are rejected"""
        response = client.post('/scan-public', data={
            'code_snippet': '   ',  # Only whitespace
            'analysis_tool': 'cppcheck'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Code snippet cannot be empty' in data['error']
    
    def test_large_code_snippet_rejected(self, client):
        """Test that overly large code snippets are rejected"""
        large_snippet = 'x' * 200000  # 200KB
        
        response = client.post('/scan-public', data={
            'code_snippet': large_snippet,
            'analysis_tool': 'cppcheck'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Code snippet too large' in data['error']

class TestValidationUtils:
    """Test validation utility functions"""
    
    def test_github_url_validation(self):
        """Test GitHub URL validation"""
        from src.utils.validation import is_valid_github_url
        
        # Valid URLs
        assert is_valid_github_url('https://github.com/user/repo')
        assert is_valid_github_url('https://github.com/user-name/repo-name')
        assert is_valid_github_url('https://github.com/user.name/repo.name')
        
        # Invalid URLs
        assert not is_valid_github_url('http://github.com/user/repo')  # Not HTTPS
        assert not is_valid_github_url('https://gitlab.com/user/repo')  # Not GitHub
        assert not is_valid_github_url('https://github.com/user')  # Missing repo
        assert not is_valid_github_url('https://github.com/')  # Missing user and repo
        assert not is_valid_github_url('')  # Empty string
        assert not is_valid_github_url(None)  # None
    
    def test_zip_file_validation(self):
        """Test ZIP file validation"""
        from src.utils.validation import validate_zip_file
        from werkzeug.datastructures import FileStorage
        
        # Create a valid ZIP file
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('test.txt', 'test content')
        zip_buffer.seek(0)
        
        valid_file = FileStorage(
            stream=zip_buffer,
            filename='test.zip',
            content_type='application/zip'
        )
        
        is_valid, message = validate_zip_file(valid_file)
        assert is_valid
        assert message == 'Valid ZIP file'
        
        # Test invalid file (not a ZIP)
        text_buffer = BytesIO(b'not a zip file')
        invalid_file = FileStorage(
            stream=text_buffer,
            filename='test.zip',
            content_type='text/plain'
        )
        
        is_valid, message = validate_zip_file(invalid_file)
        assert not is_valid
        assert 'not a valid ZIP archive' in message
    
    def test_code_snippet_validation(self):
        """Test code snippet validation"""
        from src.utils.validation import validate_code_snippet
        
        # Valid snippets
        valid_snippet = 'int main() { return 0; }'
        is_valid, message = validate_code_snippet(valid_snippet)
        assert is_valid
        
        # Empty snippet
        is_valid, message = validate_code_snippet('')
        assert not is_valid
        assert 'cannot be empty' in message
        
        # Too short
        is_valid, message = validate_code_snippet('x')
        assert not is_valid
        assert 'too short' in message
        
        # Too large
        large_snippet = 'x' * 200000
        is_valid, message = validate_code_snippet(large_snippet)
        assert not is_valid
        assert 'too large' in message

if __name__ == '__main__':
    pytest.main([__file__])