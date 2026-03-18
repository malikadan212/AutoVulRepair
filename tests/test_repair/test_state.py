"""
Test Repair State Management
Tests for state creation, updates, and helper functions
"""
import pytest
from datetime import datetime
from src.repair.state import (
    RepairState,
    create_initial_state,
    update_status,
    add_message,
    add_patch,
    set_best_patch,
    get_vulnerability_summary,
    get_patch_summary,
    is_terminal_state,
    should_retry,
    increment_retry
)


class TestStateCreation:
    """Test state creation"""
    
    def test_create_initial_state(self):
        """Test creating initial repair state"""
        vuln = {
            'crash_type': 'heap-buffer-overflow',
            'file': 'test.c',
            'line': 42
        }
        
        state = create_initial_state(
            vulnerability=vuln,
            scan_id='test-scan-123',
            crash_id='crash-abc',
            max_retries=3
        )
        
        assert state['vulnerability'] == vuln
        assert state['scan_id'] == 'test-scan-123'
        assert state['crash_id'] == 'crash-abc'
        assert state['status'] == 'pending'
        assert state['retry_count'] == 0
        assert state['max_retries'] == 3
        assert state['patches'] == []
        assert state['analysis'] is None
        assert state['started_at'] is not None
    
    def test_initial_state_has_timestamp(self):
        """Test that initial state has valid timestamp"""
        state = create_initial_state({}, 'scan', 'crash')
        
        # Should be valid ISO timestamp
        timestamp = datetime.fromisoformat(state['started_at'])
        assert isinstance(timestamp, datetime)


class TestStateUpdates:
    """Test state update functions"""
    
    def test_update_status(self):
        """Test updating status"""
        state = create_initial_state({}, 'scan', 'crash')
        
        state = update_status(state, 'analyzing', 'AnalyzerAgent')
        
        assert state['status'] == 'analyzing'
        assert state['current_agent'] == 'AnalyzerAgent'
    
    def test_update_status_terminal(self):
        """Test updating to terminal status"""
        state = create_initial_state({}, 'scan', 'crash')
        
        state = update_status(state, 'completed')
        
        assert state['status'] == 'completed'
        assert state['completed_at'] is not None
    
    def test_add_message(self):
        """Test adding log message"""
        state = create_initial_state({}, 'scan', 'crash')
        
        state = add_message(state, 'Test message')
        
        assert len(state['messages']) == 1
        assert 'Test message' in state['messages'][0]
    
    def test_add_patch(self):
        """Test adding patch"""
        state = create_initial_state({}, 'scan', 'crash')
        
        patch = {
            'type': 'conservative',
            'diff': '--- a/test.c\n+++ b/test.c'
        }
        
        state = add_patch(state, patch)
        
        assert len(state['patches']) == 1
        assert state['patches'][0] == patch
    
    def test_set_best_patch(self):
        """Test setting best patch"""
        state = create_initial_state({}, 'scan', 'crash')
        
        patch = {'type': 'moderate', 'score': 0.9}
        state = set_best_patch(state, patch)
        
        assert state['best_patch'] == patch


class TestStateHelpers:
    """Test state helper functions"""
    
    def test_get_vulnerability_summary(self):
        """Test getting vulnerability summary"""
        vuln = {
            'crash_type': 'heap-buffer-overflow',
            'file': 'test.c',
            'line': 42,
            'function': 'process_data'
        }
        
        state = create_initial_state(vuln, 'scan', 'crash')
        summary = get_vulnerability_summary(state)
        
        assert 'heap-buffer-overflow' in summary
        assert 'test.c:42' in summary
        assert 'process_data' in summary
    
    def test_get_patch_summary(self):
        """Test getting patch summary"""
        patch = {
            'type': 'conservative',
            'file': 'test.c',
            'lines_added': 3,
            'lines_removed': 1
        }
        
        summary = get_patch_summary(patch)
        
        assert 'conservative' in summary
        assert 'test.c' in summary
        assert '3+' in summary
        assert '1-' in summary
    
    def test_is_terminal_state_completed(self):
        """Test terminal state detection - completed"""
        state = create_initial_state({}, 'scan', 'crash')
        state = update_status(state, 'completed')
        
        assert is_terminal_state(state)
    
    def test_is_terminal_state_failed(self):
        """Test terminal state detection - failed"""
        state = create_initial_state({}, 'scan', 'crash')
        state = update_status(state, 'failed')
        
        assert is_terminal_state(state)
    
    def test_is_not_terminal_state(self):
        """Test non-terminal state"""
        state = create_initial_state({}, 'scan', 'crash')
        state = update_status(state, 'analyzing')
        
        assert not is_terminal_state(state)
    
    def test_should_retry_true(self):
        """Test should retry when under limit"""
        state = create_initial_state({}, 'scan', 'crash', max_retries=3)
        state = update_status(state, 'failed')
        state['retry_count'] = 1
        
        assert should_retry(state)
    
    def test_should_retry_false_at_limit(self):
        """Test should not retry at limit"""
        state = create_initial_state({}, 'scan', 'crash', max_retries=3)
        state = update_status(state, 'failed')
        state['retry_count'] = 3
        
        assert not should_retry(state)
    
    def test_should_retry_false_not_failed(self):
        """Test should not retry if not failed"""
        state = create_initial_state({}, 'scan', 'crash')
        state = update_status(state, 'analyzing')
        
        assert not should_retry(state)
    
    def test_increment_retry(self):
        """Test incrementing retry counter"""
        state = create_initial_state({}, 'scan', 'crash')
        
        state = increment_retry(state)
        
        assert state['retry_count'] == 1
        assert len(state['messages']) > 0


class TestStateWorkflow:
    """Test complete state workflow"""
    
    def test_complete_workflow(self):
        """Test a complete repair workflow state transitions"""
        vuln = {'crash_type': 'buffer-overflow', 'file': 'test.c', 'line': 10}
        
        # Create initial state
        state = create_initial_state(vuln, 'scan-123', 'crash-abc')
        assert state['status'] == 'pending'
        
        # Analyzer starts
        state = update_status(state, 'analyzing', 'AnalyzerAgent')
        state = add_message(state, 'Analyzing vulnerability...')
        assert state['status'] == 'analyzing'
        
        # Analyzer completes
        state['analysis'] = {'root_cause': 'Missing bounds check'}
        state = add_message(state, 'Analysis complete')
        
        # Generator starts
        state = update_status(state, 'generating', 'GeneratorAgent')
        
        # Generator creates patches
        for patch_type in ['conservative', 'moderate', 'aggressive']:
            patch = {'type': patch_type, 'diff': f'patch for {patch_type}'}
            state = add_patch(state, patch)
        
        assert len(state['patches']) == 3
        
        # Validator starts
        state = update_status(state, 'validating', 'ValidatorAgent')
        
        # Validator selects best patch
        best = state['patches'][1]  # moderate
        best['score'] = 0.9
        state = set_best_patch(state, best)
        
        # Complete
        state = update_status(state, 'completed')
        
        assert is_terminal_state(state)
        assert state['best_patch'] is not None
        assert state['completed_at'] is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
