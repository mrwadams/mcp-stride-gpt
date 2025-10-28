"""Integration tests for MCP protocol handler."""
import pytest
import sys
import os

# Add api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.index import handle_mcp_request


class TestMCPProtocol:
    """Tests for MCP JSON-RPC protocol handling."""

    @pytest.mark.integration
    def test_initialize_request(self):
        """Test MCP initialize request."""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "result" in response
        assert response["result"]["protocolVersion"] == "2024-11-05"
        assert "capabilities" in response["result"]

    @pytest.mark.integration
    def test_tools_list_request(self):
        """Test tools/list request returns all tools."""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 2
        assert "result" in response
        assert "tools" in response["result"]

        tools = response["result"]["tools"]
        # Should have all 8 tools
        assert len(tools) == 8

        # Verify tool names
        tool_names = [tool["name"] for tool in tools]
        expected_tools = [
            "get_stride_threat_framework",
            "generate_threat_mitigations",
            "calculate_threat_risk_scores",
            "create_threat_attack_trees",
            "generate_security_tests",
            "generate_threat_report",
            "validate_threat_coverage",
            "get_repository_analysis_guide"
        ]

        for expected_tool in expected_tools:
            assert expected_tool in tool_names

    @pytest.mark.integration
    def test_tools_call_stride_framework(self):
        """Test tools/call for get_stride_threat_framework."""
        request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_stride_threat_framework",
                "arguments": {
                    "app_description": "Test web application",
                    "app_type": "Web Application"
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 3
        assert "result" in response
        assert "content" in response["result"]

        # Content should have framework data
        content = response["result"]["content"]
        assert len(content) > 0
        assert content[0]["type"] == "text"

    @pytest.mark.integration
    def test_tools_call_mitigations(self):
        """Test tools/call for generate_threat_mitigations."""
        request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "generate_threat_mitigations",
                "arguments": {
                    "threats": [
                        {
                            "threat_id": "T001",
                            "threat_name": "SQL Injection",
                            "severity": "High"
                        }
                    ]
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 4
        assert "result" in response

    @pytest.mark.integration
    def test_tools_call_risk_scores(self):
        """Test tools/call for calculate_threat_risk_scores."""
        request = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "calculate_threat_risk_scores",
                "arguments": {
                    "threats": [
                        {
                            "threat_id": "T001",
                            "description": "Critical vulnerability"
                        }
                    ]
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 5
        assert "result" in response

    @pytest.mark.integration
    def test_tools_call_attack_trees(self):
        """Test tools/call for create_threat_attack_trees."""
        request = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "create_threat_attack_trees",
                "arguments": {
                    "threats": [
                        {
                            "threat_id": "T001",
                            "threat_name": "Unauthorized Access"
                        }
                    ],
                    "output_format": "text"
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 6
        assert "result" in response

    @pytest.mark.integration
    def test_tools_call_security_tests(self):
        """Test tools/call for generate_security_tests."""
        request = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "generate_security_tests",
                "arguments": {
                    "threats": [
                        {
                            "threat_id": "T001",
                            "threat_name": "Authentication Bypass"
                        }
                    ],
                    "format_type": "gherkin"
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 7
        assert "result" in response

    @pytest.mark.integration
    def test_tools_call_threat_report(self):
        """Test tools/call for generate_threat_report."""
        request = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "generate_threat_report",
                "arguments": {
                    "threat_model": [
                        {
                            "threat_id": "T001",
                            "threat_name": "Test Threat",
                            "severity": "High"
                        }
                    ]
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 8
        assert "result" in response
        # Report returns markdown string
        assert "content" in response["result"]

    @pytest.mark.integration
    def test_tools_call_validate_coverage(self):
        """Test tools/call for validate_threat_coverage."""
        request = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "validate_threat_coverage",
                "arguments": {
                    "threat_model": [
                        {
                            "threat_id": "T001",
                            "stride_category": "S"
                        }
                    ],
                    "app_context": {
                        "app_type": "Web Application"
                    }
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 9
        assert "result" in response

    @pytest.mark.integration
    def test_tools_call_repository_guide(self):
        """Test tools/call for get_repository_analysis_guide."""
        request = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "get_repository_analysis_guide",
                "arguments": {
                    "analysis_stage": "initial"
                }
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 10
        assert "result" in response

    @pytest.mark.integration
    def test_invalid_method_error(self):
        """Test error handling for invalid method."""
        request = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "invalid/method"
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 11
        assert "error" in response
        assert response["error"]["code"] == -32601  # Method not found

    @pytest.mark.integration
    def test_invalid_tool_name_error(self):
        """Test error handling for invalid tool name."""
        request = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "nonexistent_tool",
                "arguments": {}
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 12
        assert "error" in response
        # Should return tool execution failed or similar error

    @pytest.mark.integration
    def test_missing_required_params_error(self):
        """Test error handling for missing required parameters."""
        request = {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "get_stride_threat_framework"
                # Missing 'arguments'
            }
        }

        response = handle_mcp_request(request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 13
        # Should handle gracefully, either with error or default behavior

    @pytest.mark.integration
    def test_malformed_json_rpc(self):
        """Test handling of malformed JSON-RPC."""
        request = {
            # Missing 'jsonrpc' field
            "id": 14,
            "method": "tools/list"
        }

        response = handle_mcp_request(request)

        # Should return error response
        assert "error" in response or response.get("jsonrpc") == "2.0"

    @pytest.mark.smoke
    def test_full_workflow_integration(self):
        """Test complete workflow: initialize -> list -> call."""
        # 1. Initialize
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }
        }
        init_response = handle_mcp_request(init_request)
        assert "result" in init_response

        # 2. List tools
        list_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }
        list_response = handle_mcp_request(list_request)
        assert "result" in list_response
        assert len(list_response["result"]["tools"]) == 8

        # 3. Call a tool
        call_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_stride_threat_framework",
                "arguments": {
                    "app_description": "Test app for CI/CD"
                }
            }
        }
        call_response = handle_mcp_request(call_request)
        assert "result" in call_response
