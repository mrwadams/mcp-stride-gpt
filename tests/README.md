# STRIDE GPT MCP Server - Test Suite

This directory contains comprehensive unit tests for the STRIDE GPT MCP Server.

## Test Structure

```
tests/
├── __init__.py              # Test package initialization
├── test_tools.py            # Tests for all threat modeling tools
├── test_mcp_handler.py      # Tests for MCP JSON-RPC request handler
├── test_http_handler.py     # Tests for HTTP/Vercel handler
└── README.md                # This file
```

## Test Coverage

### test_tools.py
Tests for all 8 threat modeling tool functions:
- `get_stride_threat_framework` - STRIDE framework and threat analysis
- `generate_threat_mitigations` - Mitigation strategies and controls
- `calculate_threat_risk_scores` - DREAD risk assessment
- `create_threat_attack_trees` - Attack tree generation
- `generate_security_tests` - Security test case generation
- `generate_threat_report` - Markdown report generation
- `validate_threat_coverage` - STRIDE coverage validation
- `get_repository_analysis_guide` - Repository analysis framework

### test_mcp_handler.py
Tests for MCP protocol handling:
- `initialize` method - Server initialization
- `tools/list` method - Tool discovery
- `tools/call` method - Tool execution
- Error handling - Unknown methods, invalid tools, execution errors
- JSON-RPC 2.0 compliance - Request/response format validation

### test_http_handler.py
Tests for HTTP/Vercel handler:
- GET requests - Server info endpoint
- POST requests - MCP JSON-RPC requests
- OPTIONS requests - CORS preflight
- Security headers - X-Content-Type-Options, X-Frame-Options, etc.
- Error responses - Invalid JSON, invalid JSON-RPC, internal errors

## Running Tests

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run All Tests

```bash
pytest
```

### Run Specific Test File

```bash
pytest tests/test_tools.py
pytest tests/test_mcp_handler.py
pytest tests/test_http_handler.py
```

### Run Specific Test Class

```bash
pytest tests/test_tools.py::TestGetStrideThreatFramework
```

### Run Specific Test

```bash
pytest tests/test_tools.py::TestGetStrideThreatFramework::test_basic_call_with_minimal_args
```

### Run with Coverage Report

```bash
pytest --cov=api --cov-report=html
```

This generates an HTML coverage report in `htmlcov/index.html`.

### Run with Verbose Output

```bash
pytest -v
```

### Run Tests in Parallel (faster)

```bash
pip install pytest-xdist
pytest -n auto
```

## Test Markers

Tests can be filtered using markers:

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only handler tests
pytest -m handler

# Run only tool tests
pytest -m tools
```

## Coverage Goals

The test suite aims for:
- **>90% code coverage** for all tool functions
- **100% coverage** for MCP request handling
- **>85% coverage** for HTTP handler

Current coverage can be viewed by running:

```bash
pytest --cov=api --cov-report=term-missing
```

## Continuous Integration

These tests are designed to run in CI/CD pipelines. Add to your CI config:

```yaml
# Example GitHub Actions
- name: Install dependencies
  run: pip install -r requirements.txt

- name: Run tests
  run: pytest --cov=api --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Writing New Tests

When adding new features, follow these guidelines:

1. **Test Structure**: Use classes to group related tests
2. **Test Naming**: Use descriptive names: `test_<feature>_<scenario>`
3. **Assertions**: Use specific assertions with clear failure messages
4. **Fixtures**: Create fixtures for common test data
5. **Mocking**: Use mocks for external dependencies

Example:

```python
class TestNewFeature:
    """Tests for new feature."""

    def test_feature_with_valid_input(self):
        """Test feature with valid input."""
        result = new_feature({'valid': 'input'})
        assert result['status'] == 'success'
```

## Troubleshooting

### Import Errors

If you see import errors, ensure you're running pytest from the project root:

```bash
cd /path/to/mcp-stride-gpt
pytest
```

### Path Issues

The tests add `api/` to the Python path automatically. If you see path-related errors, check that `api/index.py` exists.

### Mock Issues

If mocks aren't working as expected, ensure you're using `unittest.mock` correctly:

```python
from unittest.mock import Mock, MagicMock, patch
```

## Test Philosophy

This test suite follows these principles:

1. **Fast**: Tests should run quickly (< 5 seconds total)
2. **Isolated**: Each test is independent, no shared state
3. **Deterministic**: Tests produce the same results every time
4. **Comprehensive**: Cover happy paths, edge cases, and error cases
5. **Maintainable**: Clear, readable, well-documented tests

## Contributing

When contributing tests:

1. Run the full test suite before submitting
2. Ensure new features have >90% test coverage
3. Add tests for bug fixes to prevent regressions
4. Update this README if adding new test files
