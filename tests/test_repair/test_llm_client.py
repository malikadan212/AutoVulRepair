"""
Test LLM Client
Tests for multi-provider LLM client with Groq and Gemini
"""
import pytest
import os
from src.repair.llm_client import (
    GroqClient,
    GeminiClient,
    MultiProviderLLMClient,
    LLMProvider,
    get_client
)


class TestGroqClient:
    """Test Groq client"""
    
    def test_initialization(self):
        """Test Groq client initialization"""
        client = GroqClient()
        assert client.model == "llama-3.1-8b-instant"
        assert client.max_retries == 3
        assert client.timeout == 60
    
    def test_health_check_no_api_key(self):
        """Test health check without API key"""
        client = GroqClient(api_key="")
        assert not client.check_health()
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_health_check_with_api_key(self):
        """Test health check with valid API key"""
        client = GroqClient()
        assert client.check_health()
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_simple_generation(self):
        """Test simple text generation"""
        client = GroqClient()
        response = client.generate(
            prompt="Say 'Hello World' and nothing else.",
            max_tokens=50
        )
        
        assert response is not None
        assert len(response) > 0
        print(f"Groq response: {response}")


class TestGeminiClient:
    """Test Gemini client"""
    
    def test_initialization(self):
        """Test Gemini client initialization"""
        client = GeminiClient()
        assert client.model == "gemini-2.0-flash"
        assert client.max_retries == 3
    
    def test_health_check_no_api_key(self):
        """Test health check without API key"""
        client = GeminiClient(api_key="")
        assert not client.check_health()
    
    @pytest.mark.skipif(not os.getenv('GEMINI_API_KEY'), reason="GEMINI_API_KEY not set")
    def test_health_check_with_api_key(self):
        """Test health check with valid API key"""
        client = GeminiClient()
        assert client.check_health()
    
    @pytest.mark.skipif(not os.getenv('GEMINI_API_KEY'), reason="GEMINI_API_KEY not set")
    def test_simple_generation(self):
        """Test simple text generation"""
        client = GeminiClient()
        response = client.generate(
            prompt="Say 'Hello World' and nothing else.",
            max_tokens=50
        )
        
        assert response is not None
        assert len(response) > 0
        print(f"Gemini response: {response}")


class TestMultiProviderClient:
    """Test multi-provider client"""
    
    def test_initialization_groq_only(self):
        """Test initialization with Groq only"""
        client = MultiProviderLLMClient(providers=[LLMProvider.GROQ])
        assert len(client.clients) >= 1
        assert client.clients[0][0] == "Groq"
    
    @pytest.mark.skipif(not os.getenv('GEMINI_API_KEY'), reason="GEMINI_API_KEY not set")
    def test_initialization_both_providers(self):
        """Test initialization with both providers"""
        client = MultiProviderLLMClient(
            providers=[LLMProvider.GROQ, LLMProvider.GEMINI]
        )
        assert len(client.clients) == 2
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_generation_with_fallback(self):
        """Test generation with automatic fallback"""
        client = MultiProviderLLMClient()
        response = client.generate(
            prompt="What is 2+2? Answer with just the number.",
            max_tokens=10
        )
        
        assert response is not None
        assert "4" in response
    
    def test_health_check(self):
        """Test health check for all providers"""
        client = MultiProviderLLMClient()
        health = client.check_health()
        
        assert isinstance(health, dict)
        assert len(health) > 0
        print(f"Provider health: {health}")
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_generation_with_context(self):
        """Test generation with context variables"""
        client = MultiProviderLLMClient()
        
        prompt = "The file {file} has a {bug_type} bug. Suggest a fix."
        context = {
            'file': 'test.c',
            'bug_type': 'buffer overflow'
        }
        
        response = client.generate_with_context(prompt, context, max_tokens=100)
        
        assert response is not None
        assert 'test.c' in response or 'buffer' in response.lower()


class TestValidation:
    """Test response validation"""
    
    @pytest.mark.skipif(not os.getenv('GROQ_API_KEY'), reason="GROQ_API_KEY not set")
    def test_generation_with_validator(self):
        """Test generation with custom validator"""
        client = MultiProviderLLMClient()
        
        def validate_number(response: str):
            """Validator that checks for a number"""
            if '4' in response:
                return response
            return None
        
        response = client.generate(
            prompt="What is 2+2? Answer with just the number.",
            validator=validate_number,
            max_tokens=10
        )
        
        assert response is not None
        assert '4' in response


def test_get_default_client():
    """Test getting default client singleton"""
    client1 = get_client()
    client2 = get_client()
    
    assert client1 is client2  # Should be same instance


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
