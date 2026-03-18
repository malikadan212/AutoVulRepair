"""
Test Response Validators
Tests for LLM response validation and parsing
"""
import pytest
from src.repair.validators import ResponseValidator


class TestAnalysisValidation:
    """Test analysis response validation"""
    
    def test_valid_analysis(self):
        """Test parsing valid analysis response"""
        response = """
Root cause: Buffer overflow due to missing bounds check
Vulnerable pattern: Array access without size validation
Fix strategy: Add bounds checking before array access
Required changes: Add if statement to check index < array_size
"""
        
        result = ResponseValidator.validate_analysis(response)
        
        assert result is not None
        assert 'root_cause' in result
        assert 'vulnerable_pattern' in result
        assert 'fix_strategy' in result
        assert 'Buffer overflow' in result['root_cause']
        assert 'bounds checking' in result['fix_strategy']
    
    def test_missing_root_cause(self):
        """Test analysis with missing root cause"""
        response = """
Vulnerable pattern: Array access without size validation
Fix strategy: Add bounds checking
"""
        
        result = ResponseValidator.validate_analysis(response)
        assert result is None
    
    def test_missing_fix_strategy(self):
        """Test analysis with missing fix strategy"""
        response = """
Root cause: Buffer overflow
Vulnerable pattern: Array access
"""
        
        result = ResponseValidator.validate_analysis(response)
        assert result is None
    
    def test_case_insensitive(self):
        """Test case-insensitive parsing"""
        response = """
root cause: Buffer overflow
VULNERABLE PATTERN: Array access
Fix Strategy: Add bounds check
"""
        
        result = ResponseValidator.validate_analysis(response)
        assert result is not None
        assert result['root_cause'] == 'Buffer overflow'


class TestPatchValidation:
    """Test patch response validation"""
    
    def test_valid_patch(self):
        """Test valid unified diff patch"""
        patch = """--- a/test.c
+++ b/test.c
@@ -10,5 +10,7 @@
 void process(char *buf, int size) {
-    buf[size] = 0;
+    if (size < MAX_SIZE) {
+        buf[size] = 0;
+    }
 }
"""
        
        result = ResponseValidator.validate_patch(patch)
        assert result is not None
        assert '---' in result
        assert '+++' in result
        assert '@@' in result
    
    def test_patch_in_markdown(self):
        """Test patch wrapped in markdown code block"""
        patch = """```diff
--- a/test.c
+++ b/test.c
@@ -10,3 +10,5 @@
-    old line
+    new line
```"""
        
        result = ResponseValidator.validate_patch(patch)
        assert result is not None
        assert '```' not in result  # Markdown removed
        assert '---' in result
    
    def test_invalid_patch_no_header(self):
        """Test invalid patch without header"""
        patch = """
+    new line
-    old line
"""
        
        result = ResponseValidator.validate_patch(patch)
        assert result is None
    
    def test_invalid_patch_no_hunks(self):
        """Test invalid patch without hunk markers"""
        patch = """--- a/test.c
+++ b/test.c
some code here
"""
        
        result = ResponseValidator.validate_patch(patch)
        assert result is None
    
    def test_patch_with_preamble(self):
        """Test patch with LLM preamble text"""
        patch = """Here's the patch to fix the issue:

--- a/test.c
+++ b/test.c
@@ -10,3 +10,5 @@
-    old line
+    new line
"""
        
        result = ResponseValidator.validate_patch(patch)
        assert result is not None
        assert 'Here\'s' not in result  # Preamble removed


class TestCodeBlockExtraction:
    """Test code block extraction"""
    
    def test_extract_from_markdown(self):
        """Test extracting code from markdown"""
        response = """```c
int main() {
    return 0;
}
```"""
        
        result = ResponseValidator.extract_code_block(response)
        assert '```' not in result
        assert 'int main()' in result
    
    def test_extract_with_language(self):
        """Test extracting code with language specifier"""
        response = """```diff
--- a/file.c
+++ b/file.c
```"""
        
        result = ResponseValidator.extract_code_block(response)
        assert '```' not in result
        assert '---' in result
    
    def test_extract_plain_text(self):
        """Test extracting plain text (no markdown)"""
        response = "int main() { return 0; }"
        
        result = ResponseValidator.extract_code_block(response)
        assert result == response


class TestJSONValidation:
    """Test JSON response validation"""
    
    def test_valid_json(self):
        """Test valid JSON response"""
        response = '{"key": "value", "number": 42}'
        
        result = ResponseValidator.validate_json_response(response)
        assert result is not None
        assert result['key'] == 'value'
        assert result['number'] == 42
    
    def test_json_in_text(self):
        """Test JSON embedded in text"""
        response = """Here's the result:
{"status": "success", "data": [1, 2, 3]}
That's all!"""
        
        result = ResponseValidator.validate_json_response(response)
        assert result is not None
        assert result['status'] == 'success'
    
    def test_invalid_json(self):
        """Test invalid JSON"""
        response = "This is not JSON"
        
        result = ResponseValidator.validate_json_response(response)
        assert result is None


class TestResponseSanitization:
    """Test response sanitization"""
    
    def test_truncate_long_response(self):
        """Test truncating very long responses"""
        response = "A" * 20000
        
        result = ResponseValidator.sanitize_response(response, max_length=10000)
        assert len(result) == 10000
    
    def test_remove_null_bytes(self):
        """Test removing null bytes"""
        response = "Hello\x00World"
        
        result = ResponseValidator.sanitize_response(response)
        assert '\x00' not in result
        assert result == "HelloWorld"
    
    def test_normalize_line_endings(self):
        """Test normalizing line endings"""
        response = "Line1\r\nLine2\r\nLine3"
        
        result = ResponseValidator.sanitize_response(response)
        assert '\r\n' not in result
        assert result.count('\n') == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
