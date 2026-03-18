"""
Prompt Templates for Repair Agents
Centralized prompts for easy tuning and version control
"""

# ============================================================================
# ANALYZER AGENT PROMPTS
# ============================================================================

ANALYZER_SYSTEM_PROMPT = """You are a security expert specializing in vulnerability analysis.
Your task is to analyze code vulnerabilities and determine their root cause and fix strategy.
Be specific, technical, and concise."""

ANALYZER_PROMPT = """Analyze this {crash_type} vulnerability:

File: {file}
Function: {function}
Line: {line}
Severity: {severity}

Code Context:
```c
{code_context}
```

Stack Trace:
{stack_trace}

Sanitizer Output:
{sanitizer_output}

Provide your analysis in this exact format:

Root cause: <one sentence describing why the crash occurred>
Vulnerable pattern: <the specific code pattern that caused the vulnerability>
Fix strategy: <high-level approach to fix this vulnerability>
Required changes: <list of specific changes needed>

Be specific and technical. Focus on the actual code issue."""


# ============================================================================
# GENERATOR AGENT PROMPTS
# ============================================================================

GENERATOR_SYSTEM_PROMPT = """You are an expert at generating secure code patches.
Your task is to create unified diff patches that fix vulnerabilities while preserving functionality.
Output ONLY the unified diff format, no explanations."""

GENERATOR_CONSERVATIVE_PROMPT = """Generate a CONSERVATIVE patch to fix this vulnerability.

{rag_context}

Analysis:
Root cause: {root_cause}
Vulnerable pattern: {vulnerable_pattern}
Fix strategy: {fix_strategy}

Code to fix:
```c
{code_context}
```

Requirements for CONSERVATIVE patch:
- Minimal changes (add 1-3 lines maximum)
- Simple bounds check or null check
- No refactoring
- Preserve all existing logic

Output ONLY the unified diff format:
--- a/{file}
+++ b/{file}
@@ -line,count +line,count @@
 context line
-old line
+new line
 context line

Do not include any explanations, just the diff."""

GENERATOR_MODERATE_PROMPT = """Generate a MODERATE patch to fix this vulnerability.

{rag_context}

Analysis:
Root cause: {root_cause}
Vulnerable pattern: {vulnerable_pattern}
Fix strategy: {fix_strategy}

Code to fix:
```c
{code_context}
```

Requirements for MODERATE patch:
- Balanced fix (add 3-7 lines)
- Bounds check + error handling
- May add return statements or error codes
- Minimal refactoring

Output ONLY the unified diff format:
--- a/{file}
+++ b/{file}
@@ -line,count +line,count @@
 context line
-old line
+new line
 context line

Do not include any explanations, just the diff."""

GENERATOR_AGGRESSIVE_PROMPT = """Generate an AGGRESSIVE patch to fix this vulnerability.

{rag_context}

Analysis:
Root cause: {root_cause}
Vulnerable pattern: {vulnerable_pattern}
Fix strategy: {fix_strategy}

Code to fix:
```c
{code_context}
```

Requirements for AGGRESSIVE patch:
- Comprehensive fix (may add 7+ lines)
- Replace unsafe functions (strcpy → strncpy, malloc → calloc)
- Add comprehensive error handling
- May refactor vulnerable section
- Add input validation

Output ONLY the unified diff format:
--- a/{file}
+++ b/{file}
@@ -line,count +line,count @@
 context line
-old line
+new line
 context line

Do not include any explanations, just the diff."""


# ============================================================================
# OPTIMIZER AGENT PROMPTS
# ============================================================================

OPTIMIZER_SYSTEM_PROMPT = """You are a code quality expert.
Your task is to improve patches while maintaining their correctness.
Focus on readability, maintainability, and best practices."""

OPTIMIZER_PROMPT = """Improve this patch while maintaining its functionality:

Original Patch:
```diff
{patch_diff}
```

Analysis:
Root cause: {root_cause}
Fix strategy: {fix_strategy}

Improvements to make:
1. Add descriptive comments explaining the fix
2. Improve variable names if needed
3. Add better error messages
4. Ensure consistent code style

Output the IMPROVED unified diff format:
--- a/{file}
+++ b/{file}
@@ -line,count +line,count @@
 context line
-old line
+new line with improvements
 context line

Do not change the core logic, only improve clarity and quality."""


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def format_analyzer_prompt(vulnerability: dict, code_context: str) -> str:
    """
    Format analyzer prompt with vulnerability data
    
    Args:
        vulnerability: Vulnerability dict from triage
        code_context: Source code around the vulnerability
        
    Returns:
        Formatted prompt
    """
    return ANALYZER_PROMPT.format(
        crash_type=vulnerability.get('crash_type', 'Unknown'),
        file=vulnerability.get('file', 'unknown'),
        function=vulnerability.get('function', 'unknown'),
        line=vulnerability.get('line', 0),
        severity=vulnerability.get('severity', 'Unknown'),
        code_context=code_context,
        stack_trace='\n'.join(vulnerability.get('stack_trace', ['No stack trace'])),
        sanitizer_output=vulnerability.get('sanitizer_output', 'No sanitizer output')
    )


def format_generator_prompt(
    patch_type: str,
    analysis: dict,
    code_context: str,
    file: str,
    rag_context: str = ""
) -> str:
    """
    Format generator prompt based on patch type
    
    Args:
        patch_type: 'conservative', 'moderate', or 'aggressive'
        analysis: Analysis dict from analyzer
        code_context: Source code to patch
        file: File path
        
    Returns:
        Formatted prompt
    """
    prompt_map = {
        'conservative': GENERATOR_CONSERVATIVE_PROMPT,
        'moderate': GENERATOR_MODERATE_PROMPT,
        'aggressive': GENERATOR_AGGRESSIVE_PROMPT
    }
    
    template = prompt_map.get(patch_type, GENERATOR_MODERATE_PROMPT)
    
    return template.format(
        root_cause=analysis.get('root_cause', 'Unknown'),
        vulnerable_pattern=analysis.get('vulnerable_pattern', 'Unknown'),
        fix_strategy=analysis.get('fix_strategy', 'Unknown'),
        code_context=code_context,
        file=file,
        rag_context=rag_context
    )


def format_optimizer_prompt(patch: dict, analysis: dict) -> str:
    """
    Format optimizer prompt
    
    Args:
        patch: Patch dict with diff
        analysis: Analysis dict
        
    Returns:
        Formatted prompt
    """
    return OPTIMIZER_PROMPT.format(
        patch_diff=patch.get('diff', ''),
        root_cause=analysis.get('root_cause', 'Unknown'),
        fix_strategy=analysis.get('fix_strategy', 'Unknown'),
        file=patch.get('file', 'unknown')
    )
