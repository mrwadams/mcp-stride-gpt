"""
Unit tests for MCP request handler.

Tests the JSON-RPC protocol handling including:
- initialize method
- tools/list method
- tools/call method
- Error handling
"""

import pytest
import sys
import os
import json

# Add api directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from index import handle_mcp_request, ERROR_CODES


class TestMCPInitialize:
    """Tests for MCP initialize method."""

    def test_initialize_request(self):
        """Test successful initialize request."""
        request = {
            'jsonrpc': '2.0',
            'method': 'initialize',
            'id': 1
        }
        response = handle_mcp_request(request)

        assert response['jsonrpc'] == '2.0'
        assert 'result' in response
        assert response['id'] == 1

    def test_initialize_negotiates_protocol_version(self):
        """Version negotiation on the legacy handshake: echo a legacy version the client
        requests, and offer the latest legacy version when the client requests none, an
        unsupported one, or a modern one (initialize never negotiates up to modern)."""
        from api.index import LEGACY_PROTOCOL_VERSIONS, LATEST_LEGACY_VERSION

        # No protocolVersion requested -> server offers its latest legacy version.
        response = handle_mcp_request({'jsonrpc': '2.0', 'method': 'initialize', 'id': 1})
        assert response['result']['protocolVersion'] == LATEST_LEGACY_VERSION

        # A supported legacy version requested -> echoed back unchanged.
        for version in LEGACY_PROTOCOL_VERSIONS:
            response = handle_mcp_request({
                'jsonrpc': '2.0', 'method': 'initialize', 'id': 1,
                'params': {'protocolVersion': version}
            })
            assert response['result']['protocolVersion'] == version

        # An unsupported or modern version requested -> server falls back to latest legacy.
        for requested in ('2099-01-01', '2026-07-28'):
            response = handle_mcp_request({
                'jsonrpc': '2.0', 'method': 'initialize', 'id': 1,
                'params': {'protocolVersion': requested}
            })
            assert response['result']['protocolVersion'] == LATEST_LEGACY_VERSION

    def test_initialize_capabilities(self):
        """Test that capabilities are declared."""
        request = {
            'jsonrpc': '2.0',
            'method': 'initialize',
            'id': 1
        }
        response = handle_mcp_request(request)

        assert 'capabilities' in response['result']
        assert 'tools' in response['result']['capabilities']

    def test_initialize_server_info(self):
        """Test that server info is included."""
        request = {
            'jsonrpc': '2.0',
            'method': 'initialize',
            'id': 1
        }
        response = handle_mcp_request(request)

        server_info = response['result']['serverInfo']
        assert server_info['name'] == 'STRIDE GPT MCP Server'
        assert server_info['version'] == '0.1.0'


class TestMCPToolsList:
    """Tests for MCP tools/list method."""

    def test_tools_list_request(self):
        """Test successful tools/list request."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': 2
        }
        response = handle_mcp_request(request)

        assert response['jsonrpc'] == '2.0'
        assert 'result' in response
        assert 'tools' in response['result']
        assert response['id'] == 2

    def test_tools_list_count(self):
        """Test that all tools are listed."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': 2
        }
        response = handle_mcp_request(request)

        tools = response['result']['tools']
        assert len(tools) == 8  # 8 tools in total

    def test_tools_list_names(self):
        """Test that all expected tool names are present."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': 2
        }
        response = handle_mcp_request(request)

        tool_names = [tool['name'] for tool in response['result']['tools']]
        expected_tools = [
            'get_stride_threat_framework',
            'generate_threat_mitigations',
            'create_threat_attack_trees',
            'calculate_threat_risk_scores',
            'generate_security_tests',
            'generate_threat_report',
            'validate_threat_coverage',
            'get_repository_analysis_guide'
        ]

        for expected_tool in expected_tools:
            assert expected_tool in tool_names

    def test_tool_schema_structure(self):
        """Test that each tool has required schema fields."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': 2
        }
        response = handle_mcp_request(request)

        for tool in response['result']['tools']:
            assert 'name' in tool
            assert 'description' in tool
            assert 'inputSchema' in tool
            assert 'type' in tool['inputSchema']
            assert 'properties' in tool['inputSchema']


class TestMCPResources:
    """Tests for serving the companion Agent Skill over MCP resources."""

    def test_resources_capability_advertised(self):
        """initialize and server/discover both advertise the resources capability."""
        init = handle_mcp_request({'jsonrpc': '2.0', 'method': 'initialize', 'id': 1})
        assert 'resources' in init['result']['capabilities']
        disc = handle_mcp_request({'jsonrpc': '2.0', 'method': 'server/discover', 'id': 1})
        assert 'resources' in disc['result']['capabilities']

    def test_resources_list_returns_skill_files(self):
        response = handle_mcp_request({'jsonrpc': '2.0', 'method': 'resources/list', 'id': 1})
        resources = response['result']['resources']
        uris = [r['uri'] for r in resources]
        # SKILL.md is the entry point and is listed first.
        assert uris[0] == 'stride://skill/SKILL.md'
        assert 'stride://skill/references/report-format.md' in uris
        # Every descriptor carries the required fields.
        for r in resources:
            assert r['uri'].startswith('stride://skill/')
            assert r['name'] and r['description'] and r['mimeType']
        # List results carry the cache hints.
        assert response['result']['ttlMs'] and response['result']['cacheScope'] == 'public'

    def test_resources_read_returns_file_contents(self):
        response = handle_mcp_request({
            'jsonrpc': '2.0', 'method': 'resources/read', 'id': 2,
            'params': {'uri': 'stride://skill/SKILL.md'}
        })
        contents = response['result']['contents']
        assert contents[0]['uri'] == 'stride://skill/SKILL.md'
        assert contents[0]['mimeType'] == 'text/markdown'
        assert 'stride' in contents[0]['text'].lower()

    def test_resources_read_unknown_uri_errors(self):
        response = handle_mcp_request({
            'jsonrpc': '2.0', 'method': 'resources/read', 'id': 3,
            'params': {'uri': 'stride://skill/does-not-exist.md'}
        })
        assert 'error' in response
        assert response['error']['code'] == -32602

    def test_resources_read_rejects_path_traversal(self):
        response = handle_mcp_request({
            'jsonrpc': '2.0', 'method': 'resources/read', 'id': 4,
            'params': {'uri': 'stride://skill/../../api/index.py'}
        })
        assert 'error' in response
        assert response['error']['code'] == -32602

    def test_resources_read_rejects_foreign_scheme(self):
        response = handle_mcp_request({
            'jsonrpc': '2.0', 'method': 'resources/read', 'id': 5,
            'params': {'uri': 'file:///etc/passwd'}
        })
        assert 'error' in response
        assert response['error']['code'] == -32602


class TestMCPToolsCall:
    """Tests for MCP tools/call method."""

    def test_call_get_stride_threat_framework(self):
        """Test calling get_stride_threat_framework tool."""
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
        assert len(response['result']['content']) > 0
        assert response['result']['content'][0]['type'] == 'text'

        # Parse the JSON result
        result_data = json.loads(response['result']['content'][0]['text'])
        assert 'stride_framework' in result_data

    def test_call_generate_threat_mitigations(self):
        """Test calling generate_threat_mitigations tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'generate_threat_mitigations',
                'arguments': {
                    'threats': [{'id': 'T1', 'description': 'Test threat'}]
                }
            },
            'id': 4
        }
        response = handle_mcp_request(request)

        assert 'result' in response
        result_data = json.loads(response['result']['content'][0]['text'])
        assert 'mitigation_framework' in result_data

    def test_call_calculate_threat_risk_scores(self):
        """Test calling calculate_threat_risk_scores tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'calculate_threat_risk_scores',
                'arguments': {
                    'threats': []
                }
            },
            'id': 5
        }
        response = handle_mcp_request(request)

        assert 'result' in response
        result_data = json.loads(response['result']['content'][0]['text'])
        assert 'dread_framework' in result_data

    def test_call_create_threat_attack_trees(self):
        """Test calling create_threat_attack_trees tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'create_threat_attack_trees',
                'arguments': {
                    'threats': []
                }
            },
            'id': 6
        }
        response = handle_mcp_request(request)

        assert 'result' in response
        result_data = json.loads(response['result']['content'][0]['text'])
        assert 'attack_tree_framework' in result_data

    def test_call_generate_security_tests(self):
        """Test calling generate_security_tests tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'generate_security_tests',
                'arguments': {
                    'threats': []
                }
            },
            'id': 7
        }
        response = handle_mcp_request(request)

        assert 'result' in response
        result_data = json.loads(response['result']['content'][0]['text'])
        assert 'security_testing_framework' in result_data

    def test_call_generate_threat_report(self):
        """Test calling generate_threat_report tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'generate_threat_report',
                'arguments': {
                    'threat_model': []
                }
            },
            'id': 8
        }
        response = handle_mcp_request(request)

        assert 'result' in response
        # This should return markdown directly, not JSON
        result_text = response['result']['content'][0]['text']
        assert '# STRIDE Threat Model Report' in result_text

    def test_call_validate_threat_coverage(self):
        """Test calling validate_threat_coverage tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'validate_threat_coverage',
                'arguments': {
                    'threat_model': [],
                    'app_context': {}
                }
            },
            'id': 9
        }
        response = handle_mcp_request(request)

        assert 'result' in response
        result_data = json.loads(response['result']['content'][0]['text'])
        assert 'coverage_framework' in result_data

    def test_call_get_repository_analysis_guide(self):
        """Test calling get_repository_analysis_guide tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'get_repository_analysis_guide',
                'arguments': {}
            },
            'id': 10
        }
        response = handle_mcp_request(request)

        assert 'result' in response
        result_data = json.loads(response['result']['content'][0]['text'])
        assert 'analysis_framework' in result_data


class TestMCPErrorHandling:
    """Tests for MCP error handling."""

    def test_unknown_method(self):
        """Test handling of unknown method."""
        request = {
            'jsonrpc': '2.0',
            'method': 'unknown/method',
            'id': 99
        }
        response = handle_mcp_request(request)

        assert 'error' in response
        assert response['error']['code'] == -32601
        assert 'Method not found' in response['error']['message']

    def test_unknown_tool(self):
        """Test handling of unknown tool."""
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'unknown_tool',
                'arguments': {}
            },
            'id': 100
        }
        response = handle_mcp_request(request)

        assert 'error' in response
        assert response['error']['code'] == ERROR_CODES['INVALID_PARAMETER']
        assert 'Unknown tool' in response['error']['message']

    def test_tool_execution_error(self):
        """Test handling of tool execution error."""
        # This test deliberately causes an error by passing invalid arguments
        request = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
                'name': 'get_stride_threat_framework',
                'arguments': None  # This should cause an error
            },
            'id': 101
        }
        response = handle_mcp_request(request)

        # Should return error response
        assert 'error' in response
        assert response['error']['code'] == ERROR_CODES['TOOL_EXECUTION_FAILED']


class TestMCPRequestIDHandling:
    """Tests for proper request ID handling."""

    def test_request_id_preserved(self):
        """Test that request ID is preserved in response."""
        for request_id in [1, 42, 'test-id', None]:
            request = {
                'jsonrpc': '2.0',
                'method': 'initialize',
                'id': request_id
            }
            response = handle_mcp_request(request)
            assert response['id'] == request_id

    def test_different_request_ids(self):
        """Test multiple requests with different IDs."""
        ids = [1, 2, 3, 'abc', 'xyz']
        for req_id in ids:
            request = {
                'jsonrpc': '2.0',
                'method': 'tools/list',
                'id': req_id
            }
            response = handle_mcp_request(request)
            assert response['id'] == req_id


class TestMCPJsonRpcCompliance:
    """Tests for JSON-RPC 2.0 compliance."""

    def test_jsonrpc_version_in_response(self):
        """Test that all responses include jsonrpc version."""
        requests = [
            {'jsonrpc': '2.0', 'method': 'initialize', 'id': 1},
            {'jsonrpc': '2.0', 'method': 'tools/list', 'id': 2},
        ]

        for request in requests:
            response = handle_mcp_request(request)
            assert response['jsonrpc'] == '2.0'

    def test_response_structure_success(self):
        """Test that successful responses have correct structure."""
        request = {
            'jsonrpc': '2.0',
            'method': 'initialize',
            'id': 1
        }
        response = handle_mcp_request(request)

        assert 'jsonrpc' in response
        assert 'result' in response
        assert 'error' not in response
        assert 'id' in response

    def test_response_structure_error(self):
        """Test that error responses have correct structure."""
        request = {
            'jsonrpc': '2.0',
            'method': 'unknown/method',
            'id': 1
        }
        response = handle_mcp_request(request)

        assert 'jsonrpc' in response
        assert 'error' in response
        assert 'result' not in response
        assert 'id' in response
