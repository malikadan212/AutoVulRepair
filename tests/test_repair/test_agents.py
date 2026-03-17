"""
Test Repair Agents
Integration tests for Analyzer, Generator, and Validator agents
"""
import pytest
import os
from src.repair.agents.analyzer import AnalyzerAgent
from src.repair.agents.generator import GeneratorAgent
from src.repair.agents.validator import ValidatorAgent
from src.repair.llm_client import MultiProviderLLMClient
from src.repair.state import create_initial_state


# Sample vulnerability for testing
SAMPLE_VULNERABILITY = {
    'crash_type': 'heap-buffer-overflow',
    'file': 'test.c',
    'line': 15,
    'function': 'process_data',
    'severity': 'High',
    'stack_trace': [
        '#0 process_data at test.c:15',
        '#1 main at test.c:30'
    ],
    'sanitizer_output': 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014'
}

# Sample source code
SAMPLE_CODE = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 10

void process_data(char *input, int size) {
    char buffer[MAX_SIZE];
    
    // Vulnerable: no bounds check
    for (int i = 0; i < size; i++) {
        buffer[i] = input[i];  // Line 15 - buffer overflow
    }
    
    buffer[size] = '\\0';
    printf("Processed: %s\\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    
    char *input = argv[1];
    int len = strlen(input);
    
    process_data(input, len);
    
    return 0;
}
"""


@pytest.fixture
def llm_client():
    """Create LLM client for testing"""
    return MultiProviderLLMClient()


@pytest.fixture
def initial_state():
    """Create initial state for testing"""
    return create_initial_state(
        vulnerability=SAMPLE_VULNERABILITY,
        scan_id='test-scan-123',
        crash_id='test-crash-abc',
        max_retries=2
    )


class TestAnalyzerAgent:
    """Test Analyzer Agent"""
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_analyzer_basic(self, llm_client, initial_state):
        """Test basic analyzer functionality"""
        analyzer = AnalyzerAgent(llm_client)
        
        # Mock code reader to return sample code
        analyzer.code_reader.read_file = lambda path: SAMPLE_CODE
        
        # Run analyzer
        result_state = analyzer.run(initial_state)
        
        # Check results
        assert result_state['status'] != 'failed'
        assert result_state['analysis'] is not None
        assert 'root_cause' in result_state['analysis']
        assert 'fix_strategy' in result_state['analysis']
        
        print(f"\nAnalysis Results:")
        print(f"Root cause: {result_state['analysis']['root_cause']}")
        print(f"Fix strategy: {result_state['analysis']['fix_strategy']}")
    
    def test_analyzer_missing_vulnerability(self, llm_client):
        """Test analyzer with missing vulnerability"""
        analyzer = AnalyzerAgent(llm_client)
        
        # Create state without vulnerability
        state = create_initial_state({}, 'scan', 'crash')
        state['vulnerability'] = None
        
        # Should fail validation
        result_state = analyzer.run(state)
        assert result_state['status'] == 'failed'
        assert result_state['error'] is not None


class TestGeneratorAgent:
    """Test Generator Agent"""
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_generator_basic(self, llm_client, initial_state):
        """Test basic generator functionality"""
        # Add analysis to state
        initial_state['analysis'] = {
            'root_cause': 'Buffer overflow due to missing bounds check',
            'vulnerable_pattern': 'Loop writes to fixed-size buffer without size validation',
            'fix_strategy': 'Add bounds checking in the loop condition'
        }
        
        generator = GeneratorAgent(llm_client)
        
        # Mock code reader
        generator.code_reader.read_file = lambda path: SAMPLE_CODE
        
        # Run generator
        result_state = generator.run(initial_state)
        
        # Check results
        assert result_state['status'] != 'failed'
        assert len(result_state['patches']) > 0
        
        print(f"\nGenerated {len(result_state['patches'])} patches:")
        for patch in result_state['patches']:
            print(f"\n{patch['type'].upper()} patch:")
            print(f"Lines added: {patch['lines_added']}, removed: {patch['lines_removed']}")
            print(f"Diff preview: {patch['diff'][:200]}...")
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_generator_all_patch_types(self, llm_client, initial_state):
        """Test that generator creates all patch types"""
        initial_state['analysis'] = {
            'root_cause': 'Buffer overflow',
            'vulnerable_pattern': 'Unchecked array access',
            'fix_strategy': 'Add bounds check'
        }
        
        generator = GeneratorAgent(llm_client)
        generator.code_reader.read_file = lambda path: SAMPLE_CODE
        
        result_state = generator.run(initial_state)
        
        # Should have patches
        patches = result_state['patches']
        assert len(patches) > 0
        
        # Check patch types
        patch_types = {p['type'] for p in patches}
        print(f"\nPatch types generated: {patch_types}")
    
    def test_generator_missing_analysis(self, llm_client, initial_state):
        """Test generator without analysis"""
        generator = GeneratorAgent(llm_client)
        
        # State has no analysis
        result_state = generator.run(initial_state)
        
        assert result_state['status'] == 'failed'


class TestValidatorAgent:
    """Test Validator Agent"""
    
    def test_validator_basic(self, llm_client, initial_state):
        """Test basic validator functionality"""
        # Add patches to state
        initial_state['patches'] = [
            {
                'type': 'conservative',
                'file': 'test.c',
                'line': 15,
                'diff': '--- a/test.c\n+++ b/test.c\n@@ -12,3 +12,5 @@\n-    for (int i = 0; i < size; i++) {\n+    for (int i = 0; i < size && i < MAX_SIZE; i++) {',
                'lines_added': 1,
                'lines_removed': 1
            }
        ]
        
        validator = ValidatorAgent(llm_client)
        
        # Run validator (will use simplified validation without actual build)
        result_state = validator.run(initial_state)
        
        # Check results
        assert result_state['status'] != 'failed'
        assert 'validation_results' in result_state
        assert len(result_state['validation_results']['results']) > 0
        
        print(f"\nValidation Results:")
        for result in result_state['validation_results']['results']:
            print(f"Patch {result['patch_type']}: score={result['score']}")
    
    def test_validator_no_patches(self, llm_client, initial_state):
        """Test validator with no patches"""
        validator = ValidatorAgent(llm_client)
        
        # State has no patches
        result_state = validator.run(initial_state)
        
        assert result_state['status'] == 'failed'
        assert 'No patches' in result_state['error']


class TestAgentIntegration:
    """Test agent integration (full workflow)"""
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_full_agent_workflow(self, llm_client):
        """Test complete workflow: Analyzer -> Generator -> Validator"""
        # Create initial state
        state = create_initial_state(
            vulnerability=SAMPLE_VULNERABILITY,
            scan_id='test-scan-123',
            crash_id='test-crash-abc'
        )
        
        print("\n=== FULL AGENT WORKFLOW TEST ===\n")
        
        # Step 1: Analyzer
        print("Step 1: Running Analyzer...")
        analyzer = AnalyzerAgent(llm_client)
        analyzer.code_reader.read_file = lambda path: SAMPLE_CODE
        
        state = analyzer.run(state)
        
        if state['status'] == 'failed':
            pytest.fail(f"Analyzer failed: {state['error']}")
        
        print(f"✓ Analysis complete")
        print(f"  Root cause: {state['analysis']['root_cause'][:60]}...")
        
        # Step 2: Generator
        print("\nStep 2: Running Generator...")
        generator = GeneratorAgent(llm_client)
        generator.code_reader.read_file = lambda path: SAMPLE_CODE
        
        state = generator.run(state)
        
        if state['status'] == 'failed':
            pytest.fail(f"Generator failed: {state['error']}")
        
        print(f"✓ Generated {len(state['patches'])} patches")
        
        # Step 3: Validator
        print("\nStep 3: Running Validator...")
        validator = ValidatorAgent(llm_client)
        
        state = validator.run(state)
        
        if state['status'] == 'failed':
            pytest.fail(f"Validator failed: {state['error']}")
        
        print(f"✓ Validation complete")
        
        # Check final state
        assert state['analysis'] is not None
        assert len(state['patches']) > 0
        assert 'validation_results' in state
        
        # Print summary
        print("\n=== WORKFLOW SUMMARY ===")
        print(f"Vulnerability: {SAMPLE_VULNERABILITY['crash_type']}")
        print(f"Patches generated: {len(state['patches'])}")
        print(f"Best score: {state['validation_results']['best_score']}")
        
        if state['best_patch']:
            print(f"Best patch type: {state['best_patch']['type']}")
        
        print("\n✓ Full workflow completed successfully!")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
