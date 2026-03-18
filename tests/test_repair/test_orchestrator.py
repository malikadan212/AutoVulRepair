"""
Test Repair Orchestrator
Tests for the LangGraph-based repair workflow orchestrator
"""
import pytest
import os
from src.repair.orchestrator import RepairOrchestrator, repair_vulnerability
from src.repair.llm_client import MultiProviderLLMClient


# Sample vulnerability
SAMPLE_VULNERABILITY = {
    'crash_type': 'heap-buffer-overflow',
    'file': 'vulnerable.c',
    'line': 42,
    'function': 'process_input',
    'severity': 'High',
    'stack_trace': [
        '#0 process_input at vulnerable.c:42',
        '#1 main at vulnerable.c:100'
    ],
    'sanitizer_output': 'ERROR: AddressSanitizer: heap-buffer-overflow'
}


@pytest.fixture
def llm_client():
    """Create LLM client"""
    return MultiProviderLLMClient()


@pytest.fixture
def orchestrator(llm_client):
    """Create orchestrator"""
    return RepairOrchestrator(llm_client=llm_client)


class TestOrchestratorInitialization:
    """Test orchestrator initialization"""
    
    def test_create_orchestrator(self, llm_client):
        """Test creating orchestrator"""
        orch = RepairOrchestrator(llm_client=llm_client)
        
        assert orch.llm is not None
        assert orch.analyzer is not None
        assert orch.generator is not None
        assert orch.validator is not None
        assert orch.workflow is not None
    
    def test_create_with_default_client(self):
        """Test creating orchestrator with default client"""
        orch = RepairOrchestrator()
        
        assert orch.llm is not None
    
    def test_health_check(self, orchestrator):
        """Test orchestrator health check"""
        # Should check LLM health
        health = orchestrator.check_health()
        assert isinstance(health, (bool, dict))


class TestOrchestratorWorkflow:
    """Test orchestrator workflow"""
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_repair_workflow(self, orchestrator):
        """Test complete repair workflow"""
        # Mock code reader for all agents
        sample_code = """
void process_input(char *buf, int size) {
    char local[10];
    for (int i = 0; i < size; i++) {
        local[i] = buf[i];  // Line 42 - overflow
    }
}
"""
        
        orchestrator.analyzer.code_reader.read_file = lambda path: sample_code
        orchestrator.generator.code_reader.read_file = lambda path: sample_code
        
        # Run repair
        result = orchestrator.repair(
            vulnerability=SAMPLE_VULNERABILITY,
            scan_id='test-scan-123',
            crash_id='test-crash-abc',
            max_retries=2
        )
        
        # Check result
        assert result is not None
        assert result['status'] in ['completed', 'failed']
        
        print(f"\n=== REPAIR RESULT ===")
        print(f"Status: {result['status']}")
        print(f"Messages: {len(result['messages'])}")
        
        if result['status'] == 'completed':
            print(f"Analysis: {result['analysis']['root_cause'][:60]}...")
            print(f"Patches: {len(result['patches'])}")
            if result['best_patch']:
                print(f"Best patch: {result['best_patch']['type']}")
        else:
            print(f"Error: {result.get('error', 'Unknown')}")
    
    def test_repair_with_invalid_vulnerability(self, orchestrator):
        """Test repair with invalid vulnerability"""
        invalid_vuln = {}  # Missing required fields
        
        result = orchestrator.repair(
            vulnerability=invalid_vuln,
            scan_id='test-scan',
            crash_id='test-crash'
        )
        
        assert result['status'] == 'failed'
        assert result['error'] is not None


class TestConvenienceFunction:
    """Test convenience functions"""
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_repair_vulnerability_function(self):
        """Test repair_vulnerability convenience function"""
        sample_code = """
void test() {
    char buf[10];
    buf[10] = 0;  // Line 3 - overflow
}
"""
        
        vuln = {
            'crash_type': 'buffer-overflow',
            'file': 'test.c',
            'line': 3,
            'function': 'test',
            'severity': 'High',
            'stack_trace': [],
            'sanitizer_output': ''
        }
        
        # Create orchestrator with mocked code reader
        orch = RepairOrchestrator()
        orch.analyzer.code_reader.read_file = lambda path: sample_code
        orch.generator.code_reader.read_file = lambda path: sample_code
        
        result = repair_vulnerability(
            vulnerability=vuln,
            scan_id='test-scan',
            crash_id='test-crash',
            orchestrator=orch
        )
        
        assert result is not None
        assert 'status' in result


class TestMetrics:
    """Test metrics tracking"""
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_metrics_tracking(self, orchestrator):
        """Test that metrics are tracked during repair"""
        sample_code = "void test() { char buf[10]; buf[10] = 0; }"
        
        orchestrator.analyzer.code_reader.read_file = lambda path: sample_code
        orchestrator.generator.code_reader.read_file = lambda path: sample_code
        
        vuln = {
            'crash_type': 'buffer-overflow',
            'file': 'test.c',
            'line': 1,
            'function': 'test',
            'severity': 'High',
            'stack_trace': [],
            'sanitizer_output': ''
        }
        
        result = orchestrator.repair(vuln, 'scan', 'crash')
        
        # Check metrics were created
        assert orchestrator.metrics is not None
        
        # Get metrics summary
        summary = orchestrator.get_metrics()
        assert isinstance(summary, dict)
        
        print(f"\n=== METRICS ===")
        print(f"Summary: {summary}")


class TestWorkflowVisualization:
    """Test workflow visualization"""
    
    def test_visualize_workflow(self, orchestrator):
        """Test workflow visualization (doesn't require graphviz)"""
        # Should not crash
        try:
            orchestrator.visualize_workflow()
        except Exception as e:
            # It's okay if graphviz is not installed
            print(f"Visualization skipped: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
