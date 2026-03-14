"""
Unit tests for CVE Update Manager

Tests the update functionality for VUL-RAG enrichment data including:
- Single CVE updates
- Bulk updates
- Error handling
- Database-index synchronization

Requirements: 8.1, 8.2, 8.3, 8.4
"""

import pytest
import sqlite3
import os
import tempfile
import shutil
import json
import numpy as np
import faiss
import pickle
from cve_update_manager import CVEUpdateManager
from enhanced_embedding_generator import EnhancedEmbeddingGenerator


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def test_db(temp_dir):
    """Create a test database with sample CVE and enrichment data"""
    db_path = os.path.join(temp_dir, 'test_cves.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create cves table
    cursor.execute("""
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            last_modified TEXT,
            description TEXT,
            raw_json TEXT
        )
    """)
    
    # Create vulrag_enrichment table
    cursor.execute("""
        CREATE TABLE vulrag_enrichment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            cwe_id TEXT,
            vulnerability_type TEXT,
            root_cause TEXT,
            attack_condition TEXT,
            fix_strategy TEXT,
            code_pattern TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        )
    """)
    
    # Insert test CVEs
    test_cves = [
        ('CVE-2023-1', '2023-01-01', '2023-01-01', 'SQL injection vulnerability', '{}'),
        ('CVE-2023-2', '2023-01-02', '2023-01-02', 'XSS vulnerability', '{}'),
        ('CVE-2023-3', '2023-01-03', '2023-01-03', 'Buffer overflow', '{}'),
    ]
    
    cursor.executemany("""
        INSERT INTO cves (cve_id, published_date, last_modified, description, raw_json)
        VALUES (?, ?, ?, ?, ?)
    """, test_cves)
    
    # Insert test enrichment data
    test_enrichment = [
        ('CVE-2023-1', 'CWE-89', 'SQL Injection', 'Insufficient input validation', 
         'Attacker can inject SQL', 'Use parameterized queries', 'Direct string concatenation'),
        ('CVE-2023-2', 'CWE-79', 'XSS', 'Unescaped output', 
         'Attacker can inject scripts', 'Output encoding', 'Unescaped user input'),
        ('CVE-2023-3', 'CWE-120', 'Buffer Overflow', 'No bounds checking',
         'Attacker can overflow buffer', 'Implement bounds checking', 'Unsafe memory operations'),
    ]
    
    cursor.executemany("""
        INSERT INTO vulrag_enrichment 
        (cve_id, cwe_id, vulnerability_type, root_cause, attack_condition, fix_strategy, code_pattern)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, test_enrichment)
    
    conn.commit()
    conn.close()
    
    return db_path


@pytest.fixture
def test_index(temp_dir, test_db):
    """Create a test FAISS index with sample data"""
    index_dir = os.path.join(temp_dir, 'indexes')
    os.makedirs(index_dir, exist_ok=True)
    
    index_name = 'test-index'
    
    # Create embedding generator
    generator = EnhancedEmbeddingGenerator()
    
    # Load CVE data from database
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT c.cve_id, c.description, c.published_date,
               v.cwe_id, v.vulnerability_type, v.root_cause,
               v.attack_condition, v.fix_strategy, v.code_pattern
        FROM cves c
        LEFT JOIN vulrag_enrichment v ON c.cve_id = v.cve_id
    """)
    
    rows = cursor.fetchall()
    conn.close()
    
    # Prepare data for embedding
    cve_list = []
    vulrag_list = []
    metadata = []
    
    for row in rows:
        cve_data = {
            'cve_id': row[0],
            'description': row[1],
            'published_date': row[2]
        }
        
        vulrag_data = {
            'cwe_id': row[3],
            'vulnerability_type': row[4],
            'root_cause': row[5],
            'attack_condition': row[6],
            'fix_strategy': row[7],
            'code_pattern': row[8]
        } if row[3] else None
        
        cve_list.append(cve_data)
        vulrag_list.append(vulrag_data)
        
        # Create metadata entry
        meta = {
            'cve_id': row[0],
            'description': row[1],
            'published_date': row[2],
            'severity': 'HIGH',
            'cvss_score': 7.5,
            'cwe': row[3]
        }
        
        if vulrag_data:
            meta.update({
                'vulnerability_type': vulrag_data['vulnerability_type'],
                'root_cause': vulrag_data['root_cause'],
                'fix_strategy': vulrag_data['fix_strategy'],
                'code_pattern': vulrag_data['code_pattern'],
                'attack_condition': vulrag_data['attack_condition']
            })
        
        metadata.append(meta)
    
    # Create embeddings
    embeddings = generator.create_embeddings(cve_list, vulrag_list)
    
    # Create FAISS index
    index = faiss.IndexFlatIP(generator.get_embedding_dimension())
    index.add(embeddings)
    
    # Save index and metadata
    index_path = os.path.join(index_dir, f'{index_name}.index')
    metadata_path = os.path.join(index_dir, f'{index_name}.metadata')
    
    faiss.write_index(index, index_path)
    
    with open(metadata_path, 'wb') as f:
        pickle.dump(metadata, f)
    
    return {
        'index_name': index_name,
        'index_dir': index_dir,
        'db_path': test_db
    }


class TestCVEUpdateManager:
    """Test suite for CVE Update Manager"""
    
    def test_initialization(self, test_index):
        """Test that manager initializes correctly"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        assert manager.index is not None
        assert manager.metadata is not None
        assert len(manager.metadata) == 3
        assert manager.get_index_size() == 3
    
    def test_single_cve_update(self, test_index):
        """Test updating a single CVE's enrichment data"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        # Get initial state
        initial_size = manager.get_index_size()
        
        # Update CVE
        cve_id = 'CVE-2023-1'
        updates = {
            'root_cause': 'Updated root cause analysis',
            'fix_strategy': 'New recommended fix strategy'
        }
        
        manager.update_vulrag_enrichment(cve_id, updates)
        
        # Verify index size unchanged
        assert manager.get_index_size() == initial_size
        
        # Verify database was updated
        conn = sqlite3.connect(test_index['db_path'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT root_cause, fix_strategy
            FROM vulrag_enrichment
            WHERE cve_id = ?
        """, (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == updates['root_cause']
        assert row[1] == updates['fix_strategy']
        
        # Verify metadata was updated
        idx = manager.cve_to_idx[cve_id]
        assert manager.metadata[idx]['root_cause'] == updates['root_cause']
        assert manager.metadata[idx]['fix_strategy'] == updates['fix_strategy']
    
    def test_selective_field_updates(self, test_index):
        """Test that only specified fields are updated, others preserved"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        cve_id = 'CVE-2023-2'
        
        # Get initial state
        conn = sqlite3.connect(test_index['db_path'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cwe_id, vulnerability_type, root_cause, attack_condition, fix_strategy, code_pattern
            FROM vulrag_enrichment
            WHERE cve_id = ?
        """, (cve_id,))
        
        initial_data = cursor.fetchone()
        conn.close()
        
        # Update only root_cause
        updates = {'root_cause': 'New root cause only'}
        manager.update_vulrag_enrichment(cve_id, updates)
        
        # Verify only root_cause changed
        conn = sqlite3.connect(test_index['db_path'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cwe_id, vulnerability_type, root_cause, attack_condition, fix_strategy, code_pattern
            FROM vulrag_enrichment
            WHERE cve_id = ?
        """, (cve_id,))
        
        updated_data = cursor.fetchone()
        conn.close()
        
        # Check that other fields are unchanged
        assert updated_data[0] == initial_data[0]  # cwe_id
        assert updated_data[1] == initial_data[1]  # vulnerability_type
        assert updated_data[2] == updates['root_cause']  # root_cause (changed)
        assert updated_data[3] == initial_data[3]  # attack_condition
        assert updated_data[4] == initial_data[4]  # fix_strategy
        assert updated_data[5] == initial_data[5]  # code_pattern
    
    def test_embedding_regeneration(self, test_index):
        """Test that embeddings are regenerated after update"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        cve_id = 'CVE-2023-1'
        idx = manager.cve_to_idx[cve_id]
        
        # Get initial embedding using reconstruct
        initial_embedding = np.zeros(manager.index.d, dtype=np.float32)
        manager.index.reconstruct(idx, initial_embedding)
        initial_embedding = initial_embedding.copy()
        
        # Update with significant change
        updates = {
            'root_cause': 'Completely different root cause that should change embedding',
            'fix_strategy': 'Entirely new fix strategy with different semantic meaning'
        }
        
        manager.update_vulrag_enrichment(cve_id, updates)
        
        # Get updated embedding using reconstruct
        updated_embedding = np.zeros(manager.index.d, dtype=np.float32)
        manager.index.reconstruct(idx, updated_embedding)
        
        # Embeddings should be different (not identical)
        diff = np.linalg.norm(initial_embedding - updated_embedding)
        assert diff > 0.01  # Significant difference expected
    
    def test_index_size_preservation(self, test_index):
        """Test that index size remains constant after updates"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        initial_size = manager.get_index_size()
        
        # Perform multiple updates
        updates_list = [
            ('CVE-2023-1', {'root_cause': 'Update 1'}),
            ('CVE-2023-2', {'fix_strategy': 'Update 2'}),
            ('CVE-2023-3', {'code_pattern': 'Update 3'}),
        ]
        
        for cve_id, updates in updates_list:
            manager.update_vulrag_enrichment(cve_id, updates)
            assert manager.get_index_size() == initial_size
    
    def test_bulk_updates(self, test_index):
        """Test bulk update functionality"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        # Prepare bulk updates
        updates = {
            'CVE-2023-1': {'root_cause': 'Bulk update 1'},
            'CVE-2023-2': {'fix_strategy': 'Bulk update 2'},
            'CVE-2023-3': {'code_pattern': 'Bulk update 3'}
        }
        
        result = manager.update_bulk(updates)
        
        # Verify results
        assert result['success_count'] == 3
        assert result['error_count'] == 0
        assert result['total'] == 3
        
        # Verify database updates
        conn = sqlite3.connect(test_index['db_path'])
        cursor = conn.cursor()
        
        cursor.execute("SELECT root_cause FROM vulrag_enrichment WHERE cve_id = 'CVE-2023-1'")
        assert cursor.fetchone()[0] == 'Bulk update 1'
        
        cursor.execute("SELECT fix_strategy FROM vulrag_enrichment WHERE cve_id = 'CVE-2023-2'")
        assert cursor.fetchone()[0] == 'Bulk update 2'
        
        cursor.execute("SELECT code_pattern FROM vulrag_enrichment WHERE cve_id = 'CVE-2023-3'")
        assert cursor.fetchone()[0] == 'Bulk update 3'
        
        conn.close()
    
    def test_error_handling_invalid_cve(self, test_index):
        """Test error handling for non-existent CVE"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        with pytest.raises(ValueError, match="CVE not found in index"):
            manager.update_vulrag_enrichment(
                'CVE-9999-9999',
                {'root_cause': 'Test'}
            )
    
    def test_error_handling_invalid_fields(self, test_index):
        """Test error handling for invalid field names"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        with pytest.raises(ValueError, match="Invalid VUL-RAG fields"):
            manager.update_vulrag_enrichment(
                'CVE-2023-1',
                {'invalid_field': 'Test', 'another_invalid': 'Test2'}
            )
    
    def test_bulk_update_error_handling(self, test_index):
        """Test that bulk updates handle errors gracefully"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        # Mix valid and invalid updates
        updates = {
            'CVE-2023-1': {'root_cause': 'Valid update'},
            'CVE-9999-9999': {'root_cause': 'Invalid CVE'},
            'CVE-2023-2': {'fix_strategy': 'Valid update'}
        }
        
        result = manager.update_bulk(updates)
        
        # Should have 2 successes and 1 error
        assert result['success_count'] == 2
        assert result['error_count'] == 1
        assert len(result['errors']) == 1
        assert result['errors'][0]['cve_id'] == 'CVE-9999-9999'
    
    def test_database_index_synchronization(self, test_index):
        """Test that database and index remain synchronized"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        cve_id = 'CVE-2023-1'
        
        # Verify initial synchronization
        assert manager.verify_synchronization(cve_id)
        
        # Update CVE
        updates = {
            'root_cause': 'Synchronized update',
            'fix_strategy': 'New strategy'
        }
        
        manager.update_vulrag_enrichment(cve_id, updates)
        
        # Verify still synchronized after update
        assert manager.verify_synchronization(cve_id)
    
    def test_standard_cve_data_preservation(self, test_index):
        """Test that standard CVE data is not modified during updates"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        cve_id = 'CVE-2023-1'
        
        # Get initial CVE data
        conn = sqlite3.connect(test_index['db_path'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, description, published_date, last_modified
            FROM cves
            WHERE cve_id = ?
        """, (cve_id,))
        
        initial_cve_data = cursor.fetchone()
        conn.close()
        
        # Update enrichment
        updates = {'root_cause': 'Updated cause'}
        manager.update_vulrag_enrichment(cve_id, updates)
        
        # Verify CVE data unchanged
        conn = sqlite3.connect(test_index['db_path'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, description, published_date, last_modified
            FROM cves
            WHERE cve_id = ?
        """, (cve_id,))
        
        updated_cve_data = cursor.fetchone()
        conn.close()
        
        assert initial_cve_data == updated_cve_data
    
    def test_multiple_sequential_updates(self, test_index):
        """Test multiple sequential updates to the same CVE"""
        manager = CVEUpdateManager(
            index_name=test_index['index_name'],
            index_dir=test_index['index_dir'],
            db_path=test_index['db_path']
        )
        
        cve_id = 'CVE-2023-1'
        
        # First update
        manager.update_vulrag_enrichment(cve_id, {'root_cause': 'First update'})
        
        # Second update
        manager.update_vulrag_enrichment(cve_id, {'fix_strategy': 'Second update'})
        
        # Third update
        manager.update_vulrag_enrichment(cve_id, {'root_cause': 'Third update'})
        
        # Verify final state
        conn = sqlite3.connect(test_index['db_path'])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT root_cause, fix_strategy
            FROM vulrag_enrichment
            WHERE cve_id = ?
        """, (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == 'Third update'  # Latest root_cause
        assert row[1] == 'Second update'  # fix_strategy from second update
        
        # Verify synchronization
        assert manager.verify_synchronization(cve_id)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
