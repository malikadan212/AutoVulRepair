"""
Multi-Provider LLM Client
Supports Groq (primary) and Gemini (optional)
"""
import os
import time
import logging
import requests
from typing import Optional, Callable, Dict, Any, List
from enum import Enum

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Available LLM providers"""
    GEMINI = "gemini"
    GROQ = "groq"
    OLLAMA = "ollama"


class BaseLLMClient:
    """Base class for LLM clients"""
    
    def __init__(self, max_retries: int = 3, timeout: int = 120):
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = requests.Session()
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        validator: Callable[[str], Optional[Any]] = None,
        max_tokens: int = 1000
    ) -> Optional[str]:
        """Generate completion - to be implemented by subclasses"""
        raise NotImplementedError
    
    def check_health(self) -> bool:
        """Check if provider is healthy"""
        raise NotImplementedError


class GeminiClient(BaseLLMClient):
    """Google Gemini API client"""
    
    def __init__(
        self,
        api_key: str = None,
        model: str = "gemini-2.0-flash",
        max_retries: int = 3,
        timeout: int = 60,
        temperature: float = 0.1
    ):
        super().__init__(max_retries, timeout)
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        self.model = model
        self.temperature = temperature
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not set")
        
        logger.info(f"Initialized Gemini client: {self.model}")
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        validator: Callable[[str], Optional[Any]] = None,
        max_tokens: int = 1000
    ) -> Optional[str]:
        """Generate completion with Gemini"""
        
        if not self.api_key:
            logger.error("Gemini API key not configured")
            return None
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Gemini: Generating (attempt {attempt + 1}/{self.max_retries})...")
                
                response = self._make_request(prompt, system, max_tokens)
                
                if not response:
                    logger.warning(f"Gemini: Empty response on attempt {attempt + 1}")
                    continue
                
                # Validate if validator provided
                if validator:
                    validated = validator(response)
                    if validated is None:
                        logger.warning(f"Gemini: Validation failed on attempt {attempt + 1}")
                        if attempt < self.max_retries - 1:
                            time.sleep(2 ** attempt)
                            continue
                    else:
                        return validated if isinstance(validated, str) else response
                
                logger.info(f"Gemini: Generated {len(response)} chars successfully")
                return response
                
            except requests.HTTPError as e:
                if e.response.status_code == 429:
                    logger.warning(f"Gemini: Rate limit hit on attempt {attempt + 1}")
                    raise  # Don't retry rate limits, switch provider
                logger.error(f"Gemini: HTTP error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    
            except requests.Timeout:
                logger.warning(f"Gemini: Timeout on attempt {attempt + 1}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    
            except Exception as e:
                logger.error(f"Gemini: Unexpected error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        
        logger.error(f"Gemini: All {self.max_retries} attempts failed")
        return None
    
    def _make_request(self, prompt: str, system: str = None, max_tokens: int = 1000) -> Optional[str]:
        """Make API request to Gemini"""
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        
        # Build content parts
        parts = []
        if system:
            parts.append({"text": f"System: {system}\n\n"})
        parts.append({"text": prompt})
        
        payload = {
            "contents": [{
                "parts": parts
            }],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": max_tokens,
                "topP": 0.9,
            }
        }
        
        response = self.session.post(
            url,
            json=payload,
            timeout=self.timeout
        )
        
        response.raise_for_status()
        data = response.json()
        
        # Extract text from response
        try:
            text = data['candidates'][0]['content']['parts'][0]['text']
            return text
        except (KeyError, IndexError) as e:
            logger.error(f"Gemini: Failed to parse response: {e}")
            return None
    
    def check_health(self) -> bool:
        """Check if Gemini is accessible"""
        if not self.api_key:
            return False
        
        try:
            # Use the list models endpoint for health check
            url = f"{self.base_url}/models?key={self.api_key}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            logger.info(f"Gemini healthy: {self.model}")
            return True
        except Exception as e:
            logger.error(f"Gemini health check failed: {e}")
            return False


class GroqClient(BaseLLMClient):
    """Groq API client"""
    
    def __init__(
        self,
        api_key: str = None,
        model: str = "llama-3.1-8b-instant",
        max_retries: int = 3,
        timeout: int = 60,
        temperature: float = 0.1
    ):
        super().__init__(max_retries, timeout)
        self.api_key = api_key or os.getenv('GROQ_API_KEY')
        self.model = model
        self.temperature = temperature
        self.base_url = "https://api.groq.com/openai/v1"
        
        if not self.api_key:
            logger.warning("GROQ_API_KEY not set")
        
        logger.info(f"Initialized Groq client: {self.model}")
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        validator: Callable[[str], Optional[Any]] = None,
        max_tokens: int = 1000
    ) -> Optional[str]:
        """Generate completion with Groq"""
        
        if not self.api_key:
            logger.error("Groq API key not configured")
            return None
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Groq: Generating (attempt {attempt + 1}/{self.max_retries})...")
                
                response = self._make_request(prompt, system, max_tokens)
                
                if not response:
                    logger.warning(f"Groq: Empty response on attempt {attempt + 1}")
                    continue
                
                # Validate if validator provided
                if validator:
                    validated = validator(response)
                    if validated is None:
                        logger.warning(f"Groq: Validation failed on attempt {attempt + 1}")
                        if attempt < self.max_retries - 1:
                            time.sleep(2 ** attempt)
                            continue
                    else:
                        return validated if isinstance(validated, str) else response
                
                logger.info(f"Groq: Generated {len(response)} chars successfully")
                return response
                
            except requests.HTTPError as e:
                if e.response.status_code == 429:
                    logger.warning(f"Groq: Rate limit hit on attempt {attempt + 1}")
                    raise  # Don't retry rate limits, switch provider
                logger.error(f"Groq: HTTP error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    
            except requests.Timeout:
                logger.warning(f"Groq: Timeout on attempt {attempt + 1}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    
            except Exception as e:
                logger.error(f"Groq: Unexpected error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        
        logger.error(f"Groq: All {self.max_retries} attempts failed")
        return None
    
    def _make_request(self, prompt: str, system: str = None, max_tokens: int = 1000) -> Optional[str]:
        """Make API request to Groq (OpenAI-compatible)"""
        url = f"{self.base_url}/chat/completions"
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
            "top_p": 0.9
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        response = self.session.post(
            url,
            json=payload,
            headers=headers,
            timeout=self.timeout
        )
        
        response.raise_for_status()
        data = response.json()
        
        # Extract text from response
        try:
            text = data['choices'][0]['message']['content']
            return text
        except (KeyError, IndexError) as e:
            logger.error(f"Groq: Failed to parse response: {e}")
            return None
    
    def check_health(self) -> bool:
        """Check if Groq is accessible"""
        if not self.api_key:
            return False
        
        try:
            url = f"{self.base_url}/models"
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            logger.info(f"Groq healthy: {self.model}")
            return True
        except Exception as e:
            logger.error(f"Groq health check failed: {e}")
            return False


class OllamaClient(BaseLLMClient):
    """Local Ollama client (Offline, Free)"""
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "deepseek-coder:6.7b",
        max_retries: int = 3,
        timeout: int = 300,  # Longer timeout for local generation
        temperature: float = 0.1
    ):
        super().__init__(max_retries, timeout)
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        
        logger.info(f"Initialized Ollama client: {self.model} at {self.base_url}")
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        validator: Callable[[str], Optional[Any]] = None,
        max_tokens: int = 1000
    ) -> Optional[str]:
        """Generate completion with Ollama"""
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Ollama: Generating (attempt {attempt + 1}/{self.max_retries})...")
                
                response = self._make_request(prompt, system, max_tokens)
                
                if not response:
                    logger.warning(f"Ollama: Empty response on attempt {attempt + 1}")
                    continue
                
                if validator:
                    validated = validator(response)
                    if validated is None:
                        logger.warning(f"Ollama: Validation failed on attempt {attempt + 1}")
                        if attempt < self.max_retries - 1:
                            time.sleep(2)
                            continue
                    else:
                        return validated if isinstance(validated, str) else response
                
                logger.info(f"Ollama: Generated {len(response)} chars successfully")
                return response
                
            except Exception as e:
                logger.error(f"Ollama: Error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2)
        
        logger.error(f"Ollama: All {self.max_retries} attempts failed")
        return None
    
    def _make_request(self, prompt: str, system: str = None, max_tokens: int = 1000) -> Optional[str]:
        """Make API request to Ollama"""
        url = f"{self.base_url}/api/generate"
        
        # Build prompt: incorporate system instruction directly into the prompt if needed
        # Ollama supports system prompts but models vary in how they handle it
        full_prompt = f"System: {system}\n\nUser: {prompt}" if system else prompt
        
        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": self.temperature,
                "top_p": 0.9
            }
        }
        
        response = self.session.post(
            url,
            json=payload,
            timeout=self.timeout
        )
        
        response.raise_for_status()
        data = response.json()
        
        try:
            return data.get('response', '')
        except Exception as e:
            logger.error(f"Ollama: Failed to parse response: {e}")
            return None
    
    def check_health(self) -> bool:
        """Check if local Ollama server is running"""
        try:
            url = f"{self.base_url}/api/tags"
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Ollama health check failed (server might be down): {e}")
            return False


class MultiProviderLLMClient:
    """
    Multi-provider LLM client with automatic fallback
    Priority: Ollama (local/free/private) -> Groq (primary) -> Gemini (optional)
    """
    
    def __init__(
        self,
        providers: List[LLMProvider] = None,
        gemini_api_key: str = None,
        groq_api_key: str = None,
        ollama_base_url: str = "http://localhost:11434"
    ):
        """
        Initialize multi-provider client
        
        Args:
            providers: List of providers to use (default: [OLLAMA, GROQ])
            gemini_api_key: Gemini API key
            groq_api_key: Groq API key
            ollama_base_url: Base URL for local Ollama
        """
        if providers is None:
            # Default priority: Local (free) -> Fast (Groq) -> Flashy (Gemini)
            providers = [LLMProvider.OLLAMA, LLMProvider.GROQ]
        
        self.clients = []
        
        # Initialize requested providers
        for provider in providers:
            try:
                if provider == LLMProvider.OLLAMA:
                    client = OllamaClient(base_url=ollama_base_url)
                    # For local production, we place OLLAMA first if it's healthy
                    if client.check_health():
                        self.clients.append(("Ollama", client))
                    else:
                        logger.warning("Ollama not healthy/running, skipping...")

                elif provider == LLMProvider.GEMINI:
                    client = GeminiClient(api_key=gemini_api_key)
                    self.clients.append(("Gemini", client))
                    
                elif provider == LLMProvider.GROQ:
                    client = GroqClient(api_key=groq_api_key)
                    self.clients.append(("Groq", client))
                    
            except Exception as e:
                logger.warning(f"Failed to initialize {provider.value}: {e}")
        
        if not self.clients:
            raise ValueError("No LLM providers could be initialized")
        
        logger.info(f"Initialized multi-provider client with {len(self.clients)} providers")
    
    def generate(
        self,
        prompt: str,
        system: str = None,
        validator: Callable[[str], Optional[Any]] = None,
        max_tokens: int = 1000
    ) -> Optional[str]:
        """
        Generate completion with automatic fallback
        
        Tries each provider in order until one succeeds
        """
        last_error = None
        
        for name, client in self.clients:
            try:
                logger.info(f"Trying provider: {name}")
                result = client.generate(prompt, system, validator, max_tokens)
                
                if result:
                    logger.info(f"Success with provider: {name}")
                    return result
                else:
                    logger.warning(f"Provider {name} returned empty result")
                    
            except requests.HTTPError as e:
                if e.response.status_code == 429:
                    logger.warning(f"Provider {name} rate limited, trying next...")
                    last_error = e
                    continue
                else:
                    logger.error(f"Provider {name} HTTP error: {e}")
                    last_error = e
                    continue
                    
            except Exception as e:
                logger.error(f"Provider {name} failed: {e}")
                last_error = e
                continue
        
        logger.error(f"All providers failed. Last error: {last_error}")
        return None
    
    def check_health(self) -> Dict[str, bool]:
        """Check health of all providers"""
        health = {}
        for name, client in self.clients:
            health[name] = client.check_health()
        return health
    
    def generate_with_context(
        self,
        prompt: str,
        context: Dict[str, Any],
        system: str = None,
        validator: Callable = None
    ) -> Optional[str]:
        """Generate with context variables injected into prompt"""
        try:
            formatted_prompt = prompt.format(**context)
            return self.generate(formatted_prompt, system, validator)
        except KeyError as e:
            logger.error(f"Missing context variable: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to generate with context: {e}")
            return None


# Singleton instance for easy access
_default_client = None

def get_client() -> MultiProviderLLMClient:
    """Get default multi-provider client instance"""
    global _default_client
    if _default_client is None:
        _default_client = MultiProviderLLMClient()
    return _default_client
