"""
Enhanced Embedding Generator

Creates embeddings that include VUL-RAG enrichment data (root causes, fix strategies,
code patterns, attack conditions) in addition to standard CVE information.

Usage:
    from enhanced_embedding_generator import EnhancedEmbeddingGenerator
    
    generator = EnhancedEmbeddingGenerator()
    
    # Generate embedding text
    cve_data = {'cve_id': 'CVE-2023-12345', 'description': '...'}
    vulrag_data = {'root_cause': '...', 'fix_strategy': '...'}
    text = generator.generate_embedding_text(cve_data, vulrag_data)
    
    # Create embeddings
    embeddings = generator.create_embeddings([cve_data], [vulrag_data])
"""

import numpy as np
from typing import List, Dict, Optional, Any
from sentence_transformers import SentenceTransformer
import faiss


class EnhancedEmbeddingGenerator:
    """
    Generates enhanced embeddings that include VUL-RAG enrichment data
    
    This class creates vector embeddings that incorporate both standard CVE
    information and VUL-RAG enrichment fields (root cause, fix strategy, etc.)
    for improved semantic search capabilities.
    """
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        """
        Initialize the enhanced embedding generator
        
        Args:
            model_name: Name of the sentence transformer model to use
        """
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.embedding_dim = self.model.get_sentence_embedding_dimension()
    
    def generate_embedding_text(self, cve_data: Dict[str, Any], 
                               vulrag_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Format text for embedding from CVE and VUL-RAG data
        
        Creates a labeled text representation that includes all available fields
        from both standard CVE data and VUL-RAG enrichment. Fields are labeled
        for semantic clarity (e.g., "Root Cause:", "Fix Strategy:").
        
        Args:
            cve_data: Dictionary containing standard CVE fields (cve_id, description, etc.)
            vulrag_data: Optional dictionary containing VUL-RAG enrichment fields
        
        Returns:
            Formatted text string suitable for embedding generation
        """
        parts = []
        
        # Always include CVE ID and description (required fields)
        if 'cve_id' in cve_data:
            parts.append(f"CVE: {cve_data['cve_id']}")
        
        if 'description' in cve_data:
            parts.append(f"Description: {cve_data['description']}")
        
        # Add VUL-RAG enrichment fields if available
        if vulrag_data:
            # Root Cause
            if vulrag_data.get('root_cause'):
                parts.append(f"Root Cause: {vulrag_data['root_cause']}")
            
            # Fix Strategy
            if vulrag_data.get('fix_strategy'):
                parts.append(f"Fix Strategy: {vulrag_data['fix_strategy']}")
            
            # CWE ID
            if vulrag_data.get('cwe_id'):
                parts.append(f"CWE: {vulrag_data['cwe_id']}")
            
            # Vulnerability Type
            if vulrag_data.get('vulnerability_type'):
                parts.append(f"Vulnerability Type: {vulrag_data['vulnerability_type']}")
            
            # Attack Condition
            if vulrag_data.get('attack_condition'):
                parts.append(f"Attack Condition: {vulrag_data['attack_condition']}")
            
            # Code Pattern
            if vulrag_data.get('code_pattern'):
                parts.append(f"Code Pattern: {vulrag_data['code_pattern']}")
        
        # Join all parts with newlines for clear separation
        return "\n".join(parts)
    
    def format_for_semantic_search(self, vulrag_data: Dict[str, Any]) -> str:
        """
        Format VUL-RAG fields specifically for semantic search
        
        Creates a text representation of VUL-RAG enrichment data with
        clear labels for each field.
        
        Args:
            vulrag_data: Dictionary containing VUL-RAG enrichment fields
        
        Returns:
            Formatted text string with labeled VUL-RAG fields
        """
        parts = []
        
        # Add each VUL-RAG field with label if present
        field_labels = {
            'root_cause': 'Root Cause',
            'fix_strategy': 'Fix Strategy',
            'cwe_id': 'CWE',
            'vulnerability_type': 'Vulnerability Type',
            'attack_condition': 'Attack Condition',
            'code_pattern': 'Code Pattern'
        }
        
        for field, label in field_labels.items():
            if vulrag_data.get(field):
                parts.append(f"{label}: {vulrag_data[field]}")
        
        return "\n".join(parts)
    
    def create_embeddings(self, cve_list: List[Dict[str, Any]], 
                         vulrag_list: Optional[List[Optional[Dict[str, Any]]]] = None) -> np.ndarray:
        """
        Generate vector embeddings for a list of CVEs
        
        Creates normalized embeddings that include both standard CVE data and
        VUL-RAG enrichment when available. Handles cases where some CVEs have
        enrichment data and others don't.
        
        Args:
            cve_list: List of CVE data dictionaries
            vulrag_list: Optional list of VUL-RAG enrichment dictionaries
                        (can contain None for CVEs without enrichment)
        
        Returns:
            Numpy array of normalized embedding vectors (shape: [n_cves, embedding_dim])
        """
        # Ensure vulrag_list matches cve_list length
        if vulrag_list is None:
            vulrag_list = [None] * len(cve_list)
        
        if len(cve_list) != len(vulrag_list):
            raise ValueError(
                f"Length mismatch: cve_list has {len(cve_list)} items, "
                f"vulrag_list has {len(vulrag_list)} items"
            )
        
        # Generate embedding texts
        texts = []
        for cve_data, vulrag_data in zip(cve_list, vulrag_list):
            text = self.generate_embedding_text(cve_data, vulrag_data)
            texts.append(text)
        
        # Generate embeddings using the model
        embeddings = self.model.encode(
            texts,
            show_progress_bar=False,
            convert_to_numpy=True
        )
        
        # Normalize vectors using L2 normalization
        # This is required for cosine similarity search in FAISS
        faiss.normalize_L2(embeddings)
        
        return embeddings
    
    def create_single_embedding(self, cve_data: Dict[str, Any],
                               vulrag_data: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        Generate a single embedding vector
        
        Convenience method for creating an embedding for a single CVE.
        
        Args:
            cve_data: CVE data dictionary
            vulrag_data: Optional VUL-RAG enrichment dictionary
        
        Returns:
            Normalized embedding vector (shape: [embedding_dim])
        """
        embeddings = self.create_embeddings([cve_data], [vulrag_data])
        return embeddings[0]
    
    def get_embedding_dimension(self) -> int:
        """
        Get the dimensionality of generated embeddings
        
        Returns:
            Integer dimension of embedding vectors
        """
        return self.embedding_dim
    
    def get_model_name(self) -> str:
        """
        Get the name of the sentence transformer model being used
        
        Returns:
            Model name string
        """
        return self.model_name


def main():
    """Example usage of EnhancedEmbeddingGenerator"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate enhanced embeddings with VUL-RAG data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test embedding generation
  python enhanced_embedding_generator.py --test
        """
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run test embedding generation'
    )
    
    args = parser.parse_args()
    
    if args.test:
        print("Testing Enhanced Embedding Generator")
        print("=" * 60)
        
        # Initialize generator
        generator = EnhancedEmbeddingGenerator()
        print(f"✓ Model loaded: {generator.get_model_name()}")
        print(f"✓ Embedding dimension: {generator.get_embedding_dimension()}")
        print()
        
        # Test with complete VUL-RAG data
        print("Test 1: CVE with complete VUL-RAG enrichment")
        print("-" * 60)
        cve_data = {
            'cve_id': 'CVE-2023-12345',
            'description': 'SQL injection vulnerability in web application'
        }
        vulrag_data = {
            'cwe_id': 'CWE-89',
            'vulnerability_type': 'SQL Injection',
            'root_cause': 'Insufficient input validation on user-supplied data',
            'attack_condition': 'Attacker can inject SQL commands through form inputs',
            'fix_strategy': 'Use parameterized queries and input sanitization',
            'code_pattern': 'Direct string concatenation in SQL queries'
        }
        
        text = generator.generate_embedding_text(cve_data, vulrag_data)
        print("Generated embedding text:")
        print(text)
        print()
        
        embedding = generator.create_single_embedding(cve_data, vulrag_data)
        print(f"Embedding shape: {embedding.shape}")
        print(f"L2 norm: {np.linalg.norm(embedding):.6f} (should be ~1.0)")
        print()
        
        # Test with partial VUL-RAG data
        print("Test 2: CVE with partial VUL-RAG enrichment")
        print("-" * 60)
        partial_vulrag = {
            'root_cause': 'Buffer overflow in memory handling',
            'fix_strategy': 'Implement bounds checking'
        }
        
        text = generator.generate_embedding_text(cve_data, partial_vulrag)
        print("Generated embedding text:")
        print(text)
        print()
        
        embedding = generator.create_single_embedding(cve_data, partial_vulrag)
        print(f"Embedding shape: {embedding.shape}")
        print(f"L2 norm: {np.linalg.norm(embedding):.6f} (should be ~1.0)")
        print()
        
        # Test without VUL-RAG data
        print("Test 3: CVE without VUL-RAG enrichment")
        print("-" * 60)
        text = generator.generate_embedding_text(cve_data, None)
        print("Generated embedding text:")
        print(text)
        print()
        
        embedding = generator.create_single_embedding(cve_data, None)
        print(f"Embedding shape: {embedding.shape}")
        print(f"L2 norm: {np.linalg.norm(embedding):.6f} (should be ~1.0)")
        print()
        
        # Test batch generation
        print("Test 4: Batch embedding generation")
        print("-" * 60)
        cve_list = [
            {'cve_id': 'CVE-2023-1', 'description': 'XSS vulnerability'},
            {'cve_id': 'CVE-2023-2', 'description': 'CSRF vulnerability'},
            {'cve_id': 'CVE-2023-3', 'description': 'RCE vulnerability'}
        ]
        vulrag_list = [
            {'root_cause': 'Unescaped output', 'fix_strategy': 'Output encoding'},
            None,  # No enrichment for second CVE
            {'root_cause': 'Command injection', 'fix_strategy': 'Input validation'}
        ]
        
        embeddings = generator.create_embeddings(cve_list, vulrag_list)
        print(f"Generated {len(embeddings)} embeddings")
        print(f"Embeddings shape: {embeddings.shape}")
        print(f"L2 norms: {[f'{np.linalg.norm(emb):.6f}' for emb in embeddings]}")
        print()
        
        print("✓ All tests completed successfully!")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
