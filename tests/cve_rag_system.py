"""
CVE RAG (Retrieval-Augmented Generation) System

Uses FAISS for vector search + Google Gemini for intelligent responses.

Features:
- Ask questions about CVEs in natural language
- Get context-aware answers from Gemini
- Automatic retrieval of relevant CVEs
- Citation of sources

Usage:
    python cve_rag_system.py --api-key YOUR_GEMINI_KEY --query "What are the most dangerous SQL injection CVEs?"
"""

import argparse
import os
from typing import List, Dict, Any
from search_cve_faiss import FAISSCVESearch

try:
    import google.generativeai as genai
except ImportError:
    print("ERROR: Google Generative AI package not installed!")
    print("Please run: pip install google-generativeai")
    exit(1)


class CVERAGSystem:
    """RAG system combining FAISS vector search with Gemini LLM"""
    
    def __init__(self, gemini_api_key: str, index_name: str = 'cve-full'):
        """
        Initialize RAG system
        
        Args:
            gemini_api_key: Google Gemini API key
            index_name: Name of FAISS index to use
        """
        print("Initializing CVE RAG System...")
        
        # Initialize FAISS searcher
        print("Loading FAISS index...")
        self.searcher = FAISSCVESearch(index_name)
        
        # Initialize Gemini
        print("Connecting to Gemini...")
        genai.configure(api_key=gemini_api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        
        print("✓ RAG System ready!\n")
    
    def retrieve_context(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieve relevant CVEs from FAISS
        
        Args:
            query: User's question
            top_k: Number of CVEs to retrieve
        
        Returns:
            List of relevant CVEs
        """
        print(f"Searching for relevant CVEs... (top {top_k})")
        results = self.searcher.search(query, top_k=top_k)
        print(f"✓ Found {len(results)} relevant CVEs\n")
        return results
    
    def format_context(self, cves: List[Dict[str, Any]]) -> str:
        """
        Format CVEs into context for Gemini
        
        Args:
            cves: List of CVE dictionaries
        
        Returns:
            Formatted context string
        """
        context_parts = []
        
        for i, cve in enumerate(cves, 1):
            cve_text = f"""
CVE {i}: {cve['cve_id']}
Severity: {cve['severity']}
CVSS Score: {cve.get('cvss_score', 'N/A')}
Published: {cve.get('published_date', 'N/A')[:10]}
Description: {cve['description']}
"""
            context_parts.append(cve_text.strip())
        
        return "\n\n".join(context_parts)
    
    def create_prompt(self, query: str, context: str) -> str:
        """
        Create prompt for Gemini with context
        
        Args:
            query: User's question
            context: Retrieved CVE context
        
        Returns:
            Complete prompt
        """
        prompt = f"""You are a cybersecurity expert assistant with access to a comprehensive CVE database.

User Question: {query}

Relevant CVEs from Database:
{context}

Instructions:
1. Answer the user's question based on the provided CVE information
2. Be specific and cite CVE IDs when referencing vulnerabilities
3. If the question asks for recommendations, provide actionable advice
4. If the CVEs don't fully answer the question, say so and provide what information you can
5. Format your response clearly with bullet points or sections as appropriate
6. Include severity levels and CVSS scores when relevant

Answer:"""
        
        return prompt
    
    def generate_response(self, prompt: str) -> str:
        """
        Generate response from Gemini
        
        Args:
            prompt: Complete prompt with context
        
        Returns:
            Gemini's response
        """
        print("Generating response from Gemini...")
        response = self.model.generate_content(prompt)
        print("✓ Response generated\n")
        return response.text
    
    def ask(self, query: str, top_k: int = 5, show_sources: bool = True) -> Dict[str, Any]:
        """
        Ask a question and get an intelligent answer
        
        Args:
            query: User's question
            top_k: Number of CVEs to retrieve for context
            show_sources: Whether to include source CVEs in response
        
        Returns:
            Dictionary with answer and sources
        """
        # Step 1: Retrieve relevant CVEs
        relevant_cves = self.retrieve_context(query, top_k)
        
        if not relevant_cves:
            return {
                'answer': "I couldn't find any relevant CVEs for your question. Please try rephrasing or asking about a different topic.",
                'sources': []
            }
        
        # Step 2: Format context
        context = self.format_context(relevant_cves)
        
        # Step 3: Create prompt
        prompt = self.create_prompt(query, context)
        
        # Step 4: Generate response
        answer = self.generate_response(prompt)
        
        # Step 5: Return result
        result = {
            'answer': answer,
            'sources': relevant_cves if show_sources else []
        }
        
        return result
    
    def chat(self):
        """Interactive chat mode"""
        print("="*80)
        print("CVE RAG System - Interactive Chat Mode")
        print("="*80)
        print("\nAsk me anything about CVEs!")
        print("Type 'exit' or 'quit' to end the conversation.\n")
        
        while True:
            try:
                # Get user input
                query = input("You: ").strip()
                
                if not query:
                    continue
                
                if query.lower() in ['exit', 'quit', 'bye']:
                    print("\nGoodbye! Stay secure! 🔒")
                    break
                
                # Get answer
                print()
                result = self.ask(query, top_k=5, show_sources=True)
                
                # Display answer
                print("Assistant:")
                print("-" * 80)
                print(result['answer'])
                print("-" * 80)
                
                # Display sources
                if result['sources']:
                    print("\n📚 Sources:")
                    for i, cve in enumerate(result['sources'], 1):
                        print(f"  {i}. {cve['cve_id']} - {cve['severity']} "
                              f"(CVSS: {cve.get('cvss_score', 'N/A')})")
                
                print()
                
            except KeyboardInterrupt:
                print("\n\nGoodbye! Stay secure! 🔒")
                break
            except Exception as e:
                print(f"\nError: {e}")
                print("Please try again.\n")


def main():
    parser = argparse.ArgumentParser(
        description='CVE RAG System - Ask questions about CVEs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive chat mode
  python cve_rag_system.py --api-key YOUR_KEY
  
  # Single question
  python cve_rag_system.py --api-key YOUR_KEY --query "What are the most dangerous SQL injection CVEs?"
  
  # With more context
  python cve_rag_system.py --api-key YOUR_KEY --query "Explain buffer overflow vulnerabilities" --top-k 10
        """
    )
    
    parser.add_argument('--api-key', required=True, help='Google Gemini API key')
    parser.add_argument('--index-name', default='cve-full', help='FAISS index name (default: cve-full)')
    parser.add_argument('--query', help='Single question to ask (optional, starts chat mode if not provided)')
    parser.add_argument('--top-k', type=int, default=5, help='Number of CVEs to retrieve (default: 5)')
    parser.add_argument('--no-sources', action='store_true', help='Hide source CVEs')
    
    args = parser.parse_args()
    
    try:
        # Initialize RAG system
        rag = CVERAGSystem(
            gemini_api_key=args.api_key,
            index_name=args.index_name
        )
        
        if args.query:
            # Single question mode
            print(f"Question: {args.query}\n")
            result = rag.ask(args.query, top_k=args.top_k, show_sources=not args.no_sources)
            
            # Display answer
            print("Answer:")
            print("="*80)
            print(result['answer'])
            print("="*80)
            
            # Display sources
            if result['sources'] and not args.no_sources:
                print("\n📚 Sources:")
                for i, cve in enumerate(result['sources'], 1):
                    print(f"\n{i}. {cve['cve_id']}")
                    print(f"   Severity: {cve['severity']}")
                    if cve.get('cvss_score'):
                        print(f"   CVSS: {cve['cvss_score']}")
                    print(f"   Description: {cve['description'][:150]}...")
        else:
            # Interactive chat mode
            rag.chat()
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nMake sure you've converted your CVE database first:")
        print(f"  python cve_to_faiss.py --index-name {args.index_name}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
