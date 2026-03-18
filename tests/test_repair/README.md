# Repair Module Tests

Comprehensive test suite for the AI-powered repair module.

## Test Structure

```
tests/test_repair/
├── test_llm_client.py      # LLM client tests (Groq, Gemini, multi-provider)
├── test_validators.py      # Response validation tests
├── test_state.py           # State management tests
├── test_agents.py          # Agent tests (Analyzer, Generator, Validator)
├── test_orchestrator.py    # Orchestrator workflow tests
└── run_tests.py            # Test runner
```

## Prerequisites

### Required
- Python 3.8+
- pytest
- At least one API key:
  - `GROQ_API_KEY` (recommended, free at https://console.groq.com)
  - `GEMINI_API_KEY` (optional, from Google AI Studio)

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Running Tests

### Quick Test (Recommended First)
Run the quick test to verify basic functionality:
```bash
python test_repair_quick.py
```

This will test:
1. LLM client connection
2. Simple text generation
3. Analyzer agent
4. Full repair workflow

### Full Test Suite
Run all tests:
```bash
python tests/test_repair/run_tests.py
```

Or use pytest directly:
```bash
pytest tests/test_repair/ -v
```

### Run Specific Test Files
```bash
# Test LLM client only
pytest tests/test_repair/test_llm_client.py -v

# Test agents only
pytest tests/test_repair/test_agents.py -v

# Test orchestrator only
pytest tests/test_repair/test_orchestrator.py -v
```

### Run Without API Keys
Some tests don't require API keys:
```bash
pytest tests/test_repair/test_state.py -v
pytest tests/test_repair/test_validators.py -v
```

## Test Categories

### Unit Tests (No API Key Required)
- `test_state.py` - State management
- `test_validators.py` - Response validation

### Integration Tests (API Key Required)
- `test_llm_client.py` - LLM client functionality
- `test_agents.py` - Individual agent tests
- `test_orchestrator.py` - Full workflow tests

## Environment Variables

Set these before running tests:

```bash
# Windows (PowerShell)
$env:GROQ_API_KEY="your-groq-api-key"
$env:GEMINI_API_KEY="your-gemini-api-key"  # Optional

# Linux/Mac
export GROQ_API_KEY="your-groq-api-key"
export GEMINI_API_KEY="your-gemini-api-key"  # Optional
```

## Expected Results

### All Tests Passing
```
✓ LLM Connection
✓ Simple Generation
✓ Analyzer Agent
✓ Full Workflow

Total: 4/4 tests passed
✓ ALL TESTS PASSED!
```

### Some Tests Skipped (No API Key)
```
⚠️  WARNING: No API keys set. Some tests will be skipped.
```

## Troubleshooting

### "No API keys found"
- Set `GROQ_API_KEY` or `GEMINI_API_KEY` environment variable
- Get free Groq API key at https://console.groq.com

### "Rate limit exceeded"
- Groq free tier: 30 requests/minute
- Wait a minute and try again
- Or set `GEMINI_API_KEY` as fallback

### "Import errors"
- Make sure you're in the project root directory
- Install dependencies: `pip install -r requirements.txt`

### "Tests timeout"
- LLM calls can take 5-30 seconds
- Increase timeout if needed
- Check your internet connection

## Test Coverage

Current test coverage:
- ✅ LLM Client (Groq, Gemini, multi-provider)
- ✅ Response Validators
- ✅ State Management
- ✅ Analyzer Agent
- ✅ Generator Agent
- ✅ Validator Agent
- ✅ Orchestrator Workflow
- ✅ Metrics Tracking

## Next Steps

After tests pass:
1. Integrate repair module into Flask app
2. Create UI templates
3. Add API endpoints
4. Test with real vulnerabilities

## Contributing

When adding new tests:
1. Follow existing test structure
2. Use descriptive test names
3. Add docstrings
4. Mock external dependencies when possible
5. Use `@pytest.mark.skipif` for tests requiring API keys
