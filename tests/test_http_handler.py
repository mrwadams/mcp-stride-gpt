"""
Unit tests for HTTP handler (Vercel serverless function).

Tests the Vercel HTTP handler methods including:
- Error response formatting
- JSON encoding/decoding
Note: Full HTTP integration testing is done at the MCP handler level.
"""

import pytest
import sys
import os
import json

# Add api directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from index import handler, handle_mcp_request, validate_json_complexity, PAYLOAD_LIMITS, sanitize_error


class TestMCPIntegration:
    """Integration tests for MCP request handling through HTTP layer."""

    def test_mcp_initialize_flow(self):
        """Test initialize request returns valid response."""
        request = {
            'jsonrpc': '2.0',
            'method': 'initialize',
            'id': 1
        }
        response = handle_mcp_request(request)

        assert response['jsonrpc'] == '2.0'
        assert 'result' in response
        assert response['result']['serverInfo']['name'] == 'STRIDE GPT MCP Server'
        assert response['id'] == 1

    def test_mcp_tools_list_flow(self):
        """Test tools/list request returns all tools."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': 2
        }
        response = handle_mcp_request(request)

        assert response['jsonrpc'] == '2.0'
        assert 'result' in response
        assert 'tools' in response['result']
        assert len(response['result']['tools']) == 8

    def test_mcp_tool_call_flow(self):
        """Test tools/call request executes tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'get_stride_threat_framework',
                'arguments': {
                    'app_description': 'Test web application'
                }
            },
            'id': 3
        }
        response = handle_mcp_request(request)

        assert response['jsonrpc'] == '2.0'
        assert 'result' in response
        assert 'content' in response['result']

        # Verify content is JSON
        content_text = response['result']['content'][0]['text']
        parsed_content = json.loads(content_text)
        assert 'stride_framework' in parsed_content

    def test_mcp_error_handling(self):
        """Test error response format."""
        request = {
            'jsonrpc': '2.0',
            'method': 'unknown_method',
            'id': 99
        }
        response = handle_mcp_request(request)

        assert response['jsonrpc'] == '2.0'
        assert 'error' in response
        assert 'code' in response['error']
        assert 'message' in response['error']
        assert response['id'] == 99


class TestJSONSerialization:
    """Tests for JSON serialization/deserialization."""

    def test_response_is_valid_json(self):
        """Test that MCP responses can be serialized to JSON."""
        request = {
            'jsonrpc': '2.0',
            'method': 'initialize',
            'id': 1
        }
        response = handle_mcp_request(request)

        # Should be able to serialize to JSON without errors
        try:
            json_str = json.dumps(response)
            assert len(json_str) > 0
        except (TypeError, ValueError) as e:
            pytest.fail(f"Response is not JSON serializable: {e}")

    def test_json_response_roundtrip(self):
        """Test JSON encode/decode roundtrip."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': 2
        }
        response = handle_mcp_request(request)

        # Serialize and deserialize
        json_str = json.dumps(response)
        parsed = json.loads(json_str)

        assert parsed == response

    def test_tool_output_json_validity(self):
        """Test that tool outputs are valid JSON strings."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'get_stride_threat_framework',
                'arguments': {'app_description': 'Test'}
            },
            'id': 3
        }
        response = handle_mcp_request(request)

        content_text = response['result']['content'][0]['text']

        # Should parse without error
        try:
            parsed = json.loads(content_text)
            assert isinstance(parsed, dict)
        except json.JSONDecodeError as e:
            pytest.fail(f"Tool output is not valid JSON: {e}")


class TestErrorCodes:
    """Tests for error code handling."""

    def test_method_not_found_error(self):
        """Test -32601 error for unknown method."""
        request = {
            'jsonrpc': '2.0',
            'method': 'nonexistent/method',
            'id': 1
        }
        response = handle_mcp_request(request)

        assert 'error' in response
        assert response['error']['code'] == -32601

    def test_invalid_tool_error(self):
        """Test error for unknown tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'nonexistent_tool',
                'arguments': {}
            },
            'id': 2
        }
        response = handle_mcp_request(request)

        assert 'error' in response
        # Should return INVALID_PARAMETER error
        from index import ERROR_CODES
        assert response['error']['code'] == ERROR_CODES['INVALID_PARAMETER']


class TestRequestValidation:
    """Tests for request validation."""

    def test_missing_method_field(self):
        """Test handling of missing method field."""
        # Missing 'method' field should return Method not found error
        request = {
            'jsonrpc': '2.0',
            'id': 1
        }
        response = handle_mcp_request(request)

        # Should return an error (not success)
        assert 'error' in response
        assert 'result' not in response
        assert response['error']['code'] == -32601  # Method not found
        assert response['id'] == 1

    def test_missing_jsonrpc_field(self):
        """Test handling of missing jsonrpc field in request."""
        # MCP handler is lenient and processes requests even without jsonrpc field
        # but always includes it in the response per JSON-RPC 2.0 spec
        request = {
            'method': 'initialize',
            'id': 1
        }
        response = handle_mcp_request(request)

        # Response must always include jsonrpc field (per JSON-RPC 2.0 spec)
        assert 'jsonrpc' in response
        assert response['jsonrpc'] == '2.0'
        # Should still process the request successfully
        assert 'result' in response
        assert response['id'] == 1


class TestCompleteWorkflow:
    """Tests for complete MCP workflows."""

    def test_threat_modeling_workflow(self):
        """Test a complete threat modeling workflow."""
        # Step 1: Initialize
        init_response = handle_mcp_request({
            'jsonrpc': '2.0',
            'method': 'initialize',
            'id': 1
        })
        assert 'result' in init_response

        # Step 2: List tools
        tools_response = handle_mcp_request({
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': 2
        })
        assert len(tools_response['result']['tools']) == 8

        # Step 3: Get STRIDE framework
        stride_response = handle_mcp_request({
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'get_stride_threat_framework',
                'arguments': {
                    'app_description': 'E-commerce web app',
                    'app_type': 'Web Application',
                    'authentication_methods': ['JWT'],
                    'internet_facing': True,
                    'sensitive_data_types': ['Payment Cards', 'PII']
                }
            },
            'id': 3
        })
        assert 'result' in stride_response
        framework = json.loads(stride_response['result']['content'][0]['text'])
        assert 'stride_framework' in framework
        assert 'application_context' in framework

        # Step 4: Generate mitigations
        mitigations_response = handle_mcp_request({
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'generate_threat_mitigations',
                'arguments': {
                    'threats': [
                        {'id': 'T1', 'category': 'S', 'description': 'Auth bypass'}
                    ]
                }
            },
            'id': 4
        })
        assert 'result' in mitigations_response
        mitigations = json.loads(mitigations_response['result']['content'][0]['text'])
        assert 'mitigation_framework' in mitigations

        # Step 5: Calculate risk scores
        risk_response = handle_mcp_request({
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'calculate_threat_risk_scores',
                'arguments': {
                    'threats': [
                        {'id': 'T1', 'category': 'S', 'description': 'Auth bypass'}
                    ]
                }
            },
            'id': 5
        })
        assert 'result' in risk_response
        risk = json.loads(risk_response['result']['content'][0]['text'])
        assert 'dread_framework' in risk

        # Step 6: Generate report
        report_response = handle_mcp_request({
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'generate_threat_report',
                'arguments': {
                    'threat_model': [
                        {'id': 'T1', 'category': 'S', 'description': 'Auth bypass'}
                    ]
                }
            },
            'id': 6
        })
        assert 'result' in report_response
        report = report_response['result']['content'][0]['text']
        assert '# STRIDE Threat Model Report' in report


class TestPayloadValidation:
    """Tests for payload size and complexity validation."""

    def test_json_depth_validation_passes(self):
        """Test that valid depth passes validation."""
        data = {'level1': {'level2': {'level3': 'value'}}}
        result = validate_json_complexity(data)
        assert result['valid'] is True
        assert result['error'] is None

    def test_json_depth_validation_fails(self):
        """Test that excessive depth fails validation."""
        # Create deeply nested structure exceeding MAX_JSON_DEPTH (20)
        # Build a structure programmatically to avoid brace-counting errors
        data = {}
        current = data
        for i in range(1, 23):  # Create 22 levels of nesting
            current[f'level{i}'] = {}
            current = current[f'level{i}']
        current['value'] = 'too deep'

        result = validate_json_complexity(data)
        assert result['valid'] is False
        assert 'nesting depth' in result['error'].lower()

    def test_object_keys_validation_passes(self):
        """Test that object with valid number of keys passes."""
        data = {f'key{i}': f'value{i}' for i in range(50)}
        result = validate_json_complexity(data)
        assert result['valid'] is True

    def test_object_keys_validation_fails(self):
        """Test that object with too many keys fails."""
        # Create object exceeding MAX_OBJECT_KEYS (500)
        data = {f'key{i}': f'value{i}' for i in range(600)}
        result = validate_json_complexity(data)
        assert result['valid'] is False
        assert 'keys' in result['error'].lower()

    def test_array_length_validation_passes(self):
        """Test that array with valid length passes."""
        data = [i for i in range(100)]
        result = validate_json_complexity(data)
        assert result['valid'] is True

    def test_array_length_validation_fails(self):
        """Test that array exceeding max length fails."""
        # Create array exceeding MAX_ARRAY_LENGTH (2000)
        data = [i for i in range(2500)]
        result = validate_json_complexity(data)
        assert result['valid'] is False
        assert 'array length' in result['error'].lower()

    def test_string_length_validation_passes(self):
        """Test that valid string length passes."""
        data = {'text': 'a' * 1000}
        result = validate_json_complexity(data)
        assert result['valid'] is True

    def test_string_length_validation_fails(self):
        """Test that excessive string length fails."""
        # Create string exceeding MAX_STRING_LENGTH (500,000)
        data = {'text': 'a' * 600000}
        result = validate_json_complexity(data)
        assert result['valid'] is False
        assert 'string length' in result['error'].lower()

    def test_nested_array_validation(self):
        """Test validation with nested arrays."""
        data = [[i for i in range(100)] for _ in range(10)]
        result = validate_json_complexity(data)
        assert result['valid'] is True

    def test_mixed_nesting_validation(self):
        """Test validation with mixed nesting of objects and arrays."""
        data = {
            'users': [
                {'id': i, 'name': f'user{i}', 'data': {'score': i * 10}}
                for i in range(50)
            ]
        }
        result = validate_json_complexity(data)
        assert result['valid'] is True

    def test_complex_payload_passes(self):
        """Test realistic complex payload that should pass."""
        data = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'generate_threat_mitigations',
                'arguments': {
                    'threats': [
                        {
                            'id': f'T{i}',
                            'category': 'S',
                            'description': 'A' * 500,
                            'impact': 'High',
                            'likelihood': 'Medium'
                        }
                        for i in range(100)
                    ]
                }
            },
            'id': 1
        }
        result = validate_json_complexity(data)
        assert result['valid'] is True

    def test_object_key_length_validation_fails(self):
        """Test that excessively long object keys fail validation."""
        # Create object with key exceeding MAX_STRING_LENGTH (500KB)
        data = {'a' * 600000: 'value'}
        result = validate_json_complexity(data)
        assert result['valid'] is False
        assert 'key length' in result['error'].lower()

    def test_payload_limits_constants(self):
        """Test that payload limit constants are defined correctly."""
        assert PAYLOAD_LIMITS['MAX_PAYLOAD_SIZE'] == 5_242_880  # 5MB
        assert PAYLOAD_LIMITS['MAX_JSON_DEPTH'] == 20
        assert PAYLOAD_LIMITS['MAX_OBJECT_KEYS'] == 500
        assert PAYLOAD_LIMITS['MAX_ARRAY_LENGTH'] == 2000
        assert PAYLOAD_LIMITS['MAX_STRING_LENGTH'] == 500_000  # 500KB


class TestErrorSanitization:
    """Tests for error message sanitization to prevent information disclosure."""

    def test_sanitize_error_returns_generic_message(self):
        """Test that sanitize_error returns a generic message, not the raw exception."""
        try:
            # Trigger an error that contains sensitive information
            raise ValueError("Database connection failed at /internal/path/db.py line 42")
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, "test context")

            # Should NOT contain sensitive details
            assert "/internal/path" not in sanitized_message
            assert "db.py" not in sanitized_message
            assert "line 42" not in sanitized_message
            assert "ValueError" not in sanitized_message

            # Should contain generic message
            assert "An internal error occurred" in sanitized_message
            assert "Error ID:" in sanitized_message

            # Error ID should be present and reasonably short (8 chars)
            assert len(error_id) == 8

    def test_sanitize_error_includes_error_id(self):
        """Test that sanitized error includes a unique error ID for correlation."""
        try:
            raise RuntimeError("Internal server error with sensitive data")
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e)

            # Error ID should be in the message
            assert error_id in sanitized_message
            # Error ID should be UUID-like (8 hex characters)
            assert len(error_id) == 8
            # Should be hex characters
            try:
                int(error_id, 16)
            except ValueError:
                pytest.fail("Error ID should be hex string")

    def test_sanitize_error_prevents_stack_trace_leakage(self):
        """Test that stack traces are not included in sanitized message."""
        def inner_function():
            raise Exception("Error in inner_function at /app/core/module.py")

        try:
            inner_function()
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, "nested function call")

            # Should NOT leak function names or file paths
            assert "inner_function" not in sanitized_message
            assert "/app/core/module.py" not in sanitized_message
            assert "module.py" not in sanitized_message

            # Should be generic
            assert "An internal error occurred" in sanitized_message

    def test_sanitize_error_prevents_exception_type_leakage(self):
        """Test that specific exception types are not disclosed."""
        exceptions_to_test = [
            ValueError("Invalid configuration at config.yaml line 15"),
            KeyError("API_SECRET_KEY not found in environment"),
            FileNotFoundError("/etc/secrets/credentials.json not found"),
            ImportError("Failed to import internal.proprietary.module"),
            AttributeError("'DatabaseConnection' object has no attribute '_password'")
        ]

        for exc in exceptions_to_test:
            try:
                raise exc
            except Exception as e:
                error_id, sanitized_message = sanitize_error(e)

                # Should NOT contain exception type
                assert type(e).__name__ not in sanitized_message
                # Should NOT contain original error message
                assert str(e) not in sanitized_message
                # Should be generic
                assert "An internal error occurred" in sanitized_message

    def test_tool_execution_error_sanitization(self):
        """Test that tool execution errors are sanitized in MCP responses."""
        # Create a custom broken tool to test error sanitization
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

        # Temporarily replace one of the tool functions to throw an error
        from index import handle_mcp_request
        import index as index_module

        # Save original function
        original_function = index_module.get_stride_threat_framework

        # Create a function that raises an error with sensitive information
        def broken_function(args):
            raise Exception("Database connection error at /internal/db/config.py line 127: password authentication failed")

        try:
            # Replace the function temporarily
            index_module.get_stride_threat_framework = broken_function

            # Make a request that will trigger the broken function
            request = {
                'jsonrpc': '2.0',
                'method': 'tools/call',
                'params': {
                    'name': 'get_stride_threat_framework',
                    'arguments': {
                        'app_description': 'Test app'
                    }
                },
                'id': 99
            }

            response = handle_mcp_request(request)

            # Should be an error response
            assert 'error' in response
            error_message = response['error']['message']

            # Should NOT contain sensitive details
            assert '/internal/db/config.py' not in error_message
            assert 'line 127' not in error_message
            assert 'password authentication failed' not in error_message
            assert 'Database connection error' not in error_message

            # Should contain sanitized error
            assert "An internal error occurred" in error_message
            assert "Error ID:" in error_message

        finally:
            # Restore original function
            index_module.get_stride_threat_framework = original_function

    def test_error_id_uniqueness(self):
        """Test that each error gets a unique error ID."""
        error_ids = set()

        # Generate multiple errors
        for i in range(10):
            try:
                raise Exception(f"Test error {i}")
            except Exception as e:
                error_id, _ = sanitize_error(e)
                error_ids.add(error_id)

        # All error IDs should be unique
        assert len(error_ids) == 10

    def test_error_context_logged_not_exposed(self):
        """Test that error context is logged but not exposed to client."""
        # This test verifies the principle, actual log checking would require
        # capturing stderr which is complex in unit tests
        try:
            raise ValueError("Sensitive operation failed")
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, "sensitive operation context")

            # Context should NOT be in the sanitized message sent to client
            assert "sensitive operation context" not in sanitized_message
            # Only generic message should be present
            assert "An internal error occurred" in sanitized_message
