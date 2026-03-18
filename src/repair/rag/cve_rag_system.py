"""
CVE RAG (Retrieval-Augmented Generation) System
Integrated with AutoVulRepair's MultiProviderLLMClient.
"""

import os
import logging
from typing import List, Dict, Any, Optional
from .search_cve_faiss import FAISSCVESearch
from ..llm_client import MultiProviderLLMClient, get_client

logger = logging.getLogger(__name__)

class CVERAGSystem:
    """RAG system combining FAISS vector search with MultiProvider LLM"""
    
    def __init__(self, llm_client: MultiProviderLLMClient = None, index_name: str = 'cve-full'):
        """
        Initialize RAG system
        
        Args:
            llm_client: MultiProviderLLMClient instance
            index_name: Name of FAISS index to use
        """
        logger.info("Initializing CVE RAG System...")
        
        # Initialize FAISS searcher with correct path
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            index_dir = os.path.join(base_dir, 'faiss_indexes')
            
            # If default index doesn't exist, look for any .index file
            if not os.path.exists(os.path.join(index_dir, f"{index_name}.index")):
                logger.info(f"Index {index_name} not found, searching for alternatives in {index_dir}...")
                if os.path.exists(index_dir):
                    indices = [f.replace('.index', '') for f in os.listdir(index_dir) if f.endswith('.index')]
                    if indices:
                        index_name = indices[0]
                        logger.info(f"Auto-selected index: {index_name}")
            
            logger.info(f"Loading FAISS index '{index_name}' from: {index_dir}")
            self.searcher = FAISSCVESearch(index_name=index_name, index_dir=index_dir)
        except Exception as e:
            logger.error(f"Failed to load FAISS index: {e}")
            self.searcher = None
        
        # Initialize LLM
        self.llm = llm_client or get_client()
        
        logger.info("✓ RAG System ready!")
    
    def retrieve_context(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Retrieve relevant CVEs from FAISS"""
        if not self.searcher:
            logger.warning("Searcher not initialized, skipping retrieval")
            return []
            
        logger.info(f"Searching for relevant CVEs... (top {top_k})")
        try:
            results = self.searcher.search(query, top_k=top_k)
            return results
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    def format_context_for_prompt(self, cves: List[Dict[str, Any]]) -> str:
        """Format CVEs into context for the LLM"""
        if not cves:
            return "No specific CVE examples found, proceed with general security best practices."
            
        context_parts = ["### RELEVANT CVE CONTEXT (from VUL-RAG):"]
        
        for i, cve in enumerate(cves, 1):
            cve_text = f"""
Example {i}: {cve['cve_id']}
Severity: {cve['severity']}
Vulnerability: {cve['description'][:300]}...
"""
            context_parts.append(cve_text.strip())
        
        return "\n\n".join(context_parts)
    
    def ask(self, query: str, top_k: int = 3) -> Dict[str, Any]:
        """Ask a question and get an intelligent answer with sources"""
        relevant_cves = self.retrieve_context(query, top_k)
        context = self.format_context_for_prompt(relevant_cves)
        
        prompt = f"""You are a cybersecurity expert. Answer the following question using the provided CVE context.
        
QUESTION: {query}

CONTEXT:
{context}

ANSWER:"""
        
        answer = self.llm.generate(prompt)
        
        return {
            'answer': answer,
            'sources': relevant_cves
        }
