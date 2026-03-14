"""
Unit Tests for IndexManager

Tests the IndexManager class functionality including listing indexes,
getting index information, and verifying VUL-RAG enrichment.
"""

import os
import json
import pickle
import tempfile
import shutil
import pytest
from index_manager import IndexManager


class TestIndexManager:
    """Test suite for IndexManager class"""
    
    @pytest.fixture
    def temp_index_dir(self):
        """Create a temporary directory with test indexes"""
        temp_dir = tempfile.mkdtemp()
        
        # Create a standard index (no VUL-RAG enrichment)
        self._create_test_index(
            temp_dir, 
            'test-standard',
            has_vulrag=False,
            total_vectors=100
        )
        
        # Create an enhanced index (with VUL-RAG enrichment)
        self._create_test_index(
            temp_dir,
            'test-enhanced',
            has_vulrag=True,
            total_vectors=50,
            enrichment_stats={
                'total_cves': 100,
                'enriched_cves': 50,
                'enrichment_percentage': 50.0
            }
        )
        
        yield temp_dir
        
        # Cleanup
        shutil.rmtree(temp_dir)
    
    def _create_test_index(self, index_dir, name, has_vulrag, total_vectors, enrichment_stats=None):
        """Helper to create test index files"""
        # Create .index file (empty for testing)
        index_path = os.path.join(index_dir, f'{name}.index')
        with open(index_path, 'wb') as f:
            f.write(b'fake_index_data')
        
        # Create .info file
        info_data = {
            'name': name,
            'total_vectors': total_vectors,
            'dimension': 384,
            'model': 'all-MiniLM-L6-v2'
        }
        
        if has_vulrag:
            info_data['enhanced'] = True
            info_data['vulrag_enrichment'] = True
            if enrichment_stats:
                info_data['enrichment_stats'] = enrichment_stats
        
        info_path = os.path.join(index_dir, f'{name}.info')
        with open(info_path, 'w') as f:
            json.dump(info_data, f)
        
        # Create .metadata file
        metadata = []
        for i in range(min(10, total_vectors)):
            entry = {
                'cve_id': f'CVE-2023-{i:05d}',
                'description': f'Test CVE {i}',
                'severity': 'HIGH',
                'cvss_score': 7.5
            }
            
            if has_vulrag:
                entry.update({
                    'root_cause': f'Root cause {i}' if i % 2 == 0 else None,
                    'fix_strategy': f'Fix strategy {i}' if i % 2 == 0 else None,
                    'code_pattern': f'Code pattern {i}' if i % 2 == 0 else None,
                    'attack_condition': f'Attack condition {i}' if i % 2 == 0 else None,
                    'vulnerability_type': f'Type {i}' if i % 2 == 0 else None
                })
            
            metadata.append(entry)
        
        metadata_path = os.path.join(index_dir, f'{name}.metadata')
        with open(metadata_path, 'wb') as f:
            pickle.dump(metadata, f)
    
    def test_initialization(self, temp_index_dir):
        """Test IndexManager initialization"""
        manager = IndexManager(index_dir=temp_index_dir)
        assert manager.index_dir == temp_index_dir
    
    def test_initialization_missing_directory(self):
        """Test initialization with non-existent directory"""
        with pytest.raises(FileNotFoundError):
            IndexManager(index_dir='/nonexistent/directory')
    
    def test_list_indexes(self, temp_index_dir):
        """Test listing all indexes"""
        manager = IndexManager(index_dir=temp_index_dir)
        indexes = manager.list_indexes()
        
        # Should find both test indexes
        assert len(indexes) == 2
        
        # Check index names
        index_names = [idx['name'] for idx in indexes]
        assert 'test-standard' in index_names
        assert 'test-enhanced' in index_names
        
        # Verify all indexes have required fields
        for idx in indexes:
            assert 'name' in idx
            assert 'total_vectors' in idx
            assert 'dimension' in idx
            assert 'model' in idx
            assert 'has_vulrag_enrichment' in idx
            assert 'index_file' in idx
            assert 'metadata_file' in idx
            assert 'info_file' in idx
    
    def test_list_indexes_enrichment_indicator(self, temp_index_dir):
        """Test that list_indexes correctly identifies enriched indexes"""
        manager = IndexManager(index_dir=temp_index_dir)
        indexes = manager.list_indexes()
        
        # Find each index
        standard_idx = next(idx for idx in indexes if idx['name'] == 'test-standard')
        enhanced_idx = next(idx for idx in indexes if idx['name'] == 'test-enhanced')
        
        # Verify enrichment indicators
        assert standard_idx['has_vulrag_enrichment'] is False
        assert enhanced_idx['has_vulrag_enrichment'] is True
    
    def test_get_index_info(self, temp_index_dir):
        """Test getting detailed index information"""
        manager = IndexManager(index_dir=temp_index_dir)
        
        # Get info for enhanced index
        info = manager.get_index_info('test-enhanced')
        
        assert info['name'] == 'test-enhanced'
        assert info['total_vectors'] == 50
        assert info['dimension'] == 384
        assert info['model'] == 'all-MiniLM-L6-v2'
        assert info['has_vulrag_enrichment'] is True
        assert info['enrichment_stats'] is not None
        assert info['enrichment_stats']['total_cves'] == 100
        assert info['enrichment_stats']['enriched_cves'] == 50
    
    def test_get_index_info_nonexistent(self, temp_index_dir):
        """Test getting info for non-existent index"""
        manager = IndexManager(index_dir=temp_index_dir)
        
        with pytest.raises(FileNotFoundError):
            manager.get_index_info('nonexistent-index')
    
    def test_verify_index_schema_enhanced(self, temp_index_dir):
        """Test verifying enhanced index schema"""
        manager = IndexManager(index_dir=temp_index_dir)
        
        # Enhanced index should have VUL-RAG enrichment
        assert manager.verify_index_schema('test-enhanced') is True
    
    def test_verify_index_schema_standard(self, temp_index_dir):
        """Test verifying standard index schema"""
        manager = IndexManager(index_dir=temp_index_dir)
        
        # Standard index should not have VUL-RAG enrichment
        assert manager.verify_index_schema('test-standard') is False
    
    def test_get_enrichment_coverage(self, temp_index_dir):
        """Test getting enrichment coverage statistics"""
        manager = IndexManager(index_dir=temp_index_dir)
        
        # Enhanced index should have coverage stats
        coverage = manager.get_enrichment_coverage('test-enhanced')
        assert coverage is not None
        assert coverage['total_cves'] == 100
        assert coverage['enriched_cves'] == 50
        assert coverage['enrichment_percentage'] == 50.0
        
        # Standard index should not have coverage stats
        coverage = manager.get_enrichment_coverage('test-standard')
        assert coverage is None
    
    def test_print_index_summary(self, temp_index_dir, capsys):
        """Test printing index summary"""
        manager = IndexManager(index_dir=temp_index_dir)
        
        # Print summary
        manager.print_index_summary()
        
        # Capture output
        captured = capsys.readouterr()
        
        # Verify output contains expected information
        assert 'FAISS Index Summary' in captured.out
        assert 'test-standard' in captured.out
        assert 'test-enhanced' in captured.out
        assert 'VUL-RAG Enrichment' in captured.out


def test_index_manager_with_real_indexes():
    """Test IndexManager with real indexes if they exist"""
    if not os.path.exists('faiss_indexes'):
        pytest.skip("Real indexes directory not found")
    
    manager = IndexManager(index_dir='faiss_indexes')
    
    # List indexes
    indexes = manager.list_indexes()
    assert len(indexes) > 0
    
    # Test each index
    for idx in indexes:
        # Get detailed info
        info = manager.get_index_info(idx['name'])
        assert info['name'] == idx['name']
        
        # Verify schema
        has_enrichment = manager.verify_index_schema(idx['name'])
        assert isinstance(has_enrichment, bool)
        
        # If enriched, check coverage
        if has_enrichment:
            coverage = manager.get_enrichment_coverage(idx['name'])
            # Coverage might be None if not in info file
            if coverage:
                assert 'total_cves' in coverage
                assert 'enriched_cves' in coverage


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
