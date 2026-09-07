"""HTTP transport for the MCP server: request validation, Origin checks, and dispatch."""

import json
import os
from http.server import BaseHTTPRequestHandler

from .constants import (
    ERROR_CODES,
    MCP_ERR_HEADER_MISMATCH,
    MCP_ERR_UNSUPPORTED_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSIONS,
    PAYLOAD_LIMITS,
    SUPPORTED_PROTOCOL_VERSIONS,
    _META_CLIENT_CAPABILITIES,
    _META_PROTOCOL_VERSION,
)
from .errors import sanitize_error
from .mcp import (
    _MCP_NAME_SOURCE,
    _decode_mcp_header,
    _with_result_type,
    _with_server_meta,
    handle_mcp_request,
)
from .validation import validate_json_complexity

# Streamable HTTP: Origin allow-list for DNS-rebinding protection (the transport spec
# requires validating Origin and returning 403 on an invalid one). Requests with no Origin
# header (native, non-browser MCP clients) are always allowed. Extend via the
# ALLOWED_ORIGINS env var (comma-separated).
_DEFAULT_ALLOWED_ORIGINS = {
    "https://mcp.stridegpt.ai",
    "https://stridegpt.ai",
    "https://www.stridegpt.ai",
    "https://claude.ai",
    "https://www.claude.ai",
    "https://playground.ai.cloudflare.com",  # Cloudflare AI Playground (browser MCP client)
}


def _origin_allowed(origin: str) -> bool:
    """Return True if the request should be served. Absent Origin -> True (non-browser
    MCP clients send none); a present Origin must match the allow-list, with localhost
    permitted on any port for the MCP Inspector and local development."""
    if not origin:
        return True
    allowed = set(_DEFAULT_ALLOWED_ORIGINS)
    for extra in os.environ.get("ALLOWED_ORIGINS", "").split(","):
        extra = extra.strip()
        if extra:
            allowed.add(extra)
    if origin in allowed:
        return True
    for prefix in ("http://localhost", "http://127.0.0.1"):
        if origin == prefix or origin.startswith(prefix + ":"):
            return True
    return False

class handler(BaseHTTPRequestHandler):
    def _origin_ok(self):
        """Validate the Origin header (DNS-rebinding protection). If invalid, emit a
        403 with a JSON-RPC error (no id) and return False; otherwise return True."""
        if _origin_allowed(self.headers.get('Origin')):
            return True
        self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        self.wfile.write(json.dumps({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Forbidden: invalid Origin"},
            "id": None
        }).encode())
        return False

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, Authorization, MCP-Protocol-Version, Mcp-Method, Mcp-Name')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()

    def do_GET(self):
        if not self._origin_ok():
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        
        response_data = {
            "name": "STRIDE GPT MCP Server",
            "version": "0.1.0",
            "description": "Professional threat modeling server using the STRIDE methodology",
            "tools": [
                "get_stride_threat_framework",
                "generate_threat_mitigations",
                "create_threat_attack_trees",
                "calculate_threat_risk_scores",
                "generate_security_tests",
                "generate_threat_report",
                "validate_threat_coverage",
                "get_repository_analysis_guide"
            ],
            "endpoints": {
                "POST /": "MCP JSON-RPC endpoint"
            }
        }
        self.wfile.write(json.dumps(response_data, indent=2).encode())
        
    def do_POST(self):
        try:
            if not self._origin_ok():
                return

            content_length = int(self.headers.get('Content-Length', 0))

            # Validate payload size before reading
            if content_length > PAYLOAD_LIMITS['MAX_PAYLOAD_SIZE']:
                self.send_error_response(413, {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": ERROR_CODES['PAYLOAD_TOO_LARGE'],
                        "message": f"Payload size {content_length} bytes exceeds maximum of {PAYLOAD_LIMITS['MAX_PAYLOAD_SIZE']} bytes"
                    },
                    "id": None
                })
                return

            post_data = self.rfile.read(content_length)

            try:
                body = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_error_response(400, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None
                })
                return

            # Validate JSON complexity
            complexity_result = validate_json_complexity(body)
            if not complexity_result['valid']:
                self.send_error_response(400, {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": ERROR_CODES['PAYLOAD_TOO_COMPLEX'],
                        "message": f"Payload complexity validation failed: {complexity_result['error']}"
                    },
                    "id": body.get('id')
                })
                return

            # Validate JSON-RPC
            if not body.get('jsonrpc') == '2.0' or not body.get('method'):
                self.send_error_response(400, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid Request"},
                    "id": body.get('id')
                })
                return

            # Era detection. A request is served under the modern (2026-07-28) stateless
            # model when it declares a modern protocol version in its `_meta` (the signal a
            # modern client always sends) or via the MCP-Protocol-Version header.
            # `initialize` is always legacy; everything else without those signals stays on
            # the legacy path so existing 2025-era clients are unaffected.
            method = body.get('method')
            params = body.get('params') or {}
            meta = params.get('_meta') or {}
            header_version = self.headers.get('MCP-Protocol-Version')
            meta_version = meta.get(_META_PROTOCOL_VERSION)
            is_modern = method != 'initialize' and (
                _META_PROTOCOL_VERSION in meta
                or header_version in MODERN_PROTOCOL_VERSIONS
            )

            if is_modern:
                error = self._validate_modern_request(
                    body, method, params, meta, header_version, meta_version)
                if error is not None:
                    self.send_error_response(*error)
                    return
                response = _with_server_meta(_with_result_type(handle_mcp_request(body)))
                # Modern transport: an unknown method is a 404 with a JSON-RPC -32601 body
                # (distinguishing a modern endpoint from a legacy 404), not a 200-wrapped
                # error.
                status = 404 if (
                    'error' in response and response['error'].get('code') == -32601
                ) else 200
                self._send_json(status, response)
                return

            # Legacy path: tolerate an absent MCP-Protocol-Version header (spec says assume
            # 2025-03-26); reject a present-but-unsupported one.
            if header_version is not None and header_version not in SUPPORTED_PROTOCOL_VERSIONS:
                self.send_error_response(400, {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": f"Unsupported MCP-Protocol-Version: {header_version}. "
                                   f"Supported: {', '.join(SUPPORTED_PROTOCOL_VERSIONS)}"
                    },
                    "id": body.get('id')
                })
                return

            response = _with_result_type(handle_mcp_request(body))
            self._send_json(200, response)

        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, "HTTP POST request handling")
            self.send_error_response(500, {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": sanitized_message},
                "id": None
            })
    
    def _rpc_error(self, request_id, code, message, data=None):
        """Build a JSON-RPC error response body."""
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "error": error, "id": request_id}

    def _validate_modern_request(self, body, method, params, meta, header_version, meta_version):
        """Validate a request served under the modern (2026-07-28) stateless model.

        Returns None when the request is well-formed, otherwise a (http_status, error_body)
        tuple ready for send_error_response. Enforces the required per-request `_meta`
        protocol fields, protocol-version support, and the mirrored HTTP request headers
        (MCP-Protocol-Version, Mcp-Method, Mcp-Name) that the transport requires."""
        request_id = body.get('id')

        # Required per-request `_meta` fields — missing -> Invalid params (-32602).
        if meta_version is None:
            return (400, self._rpc_error(
                request_id, -32602,
                f"Missing required _meta field: {_META_PROTOCOL_VERSION}"))
        if _META_CLIENT_CAPABILITIES not in meta:
            return (400, self._rpc_error(
                request_id, -32602,
                f"Missing required _meta field: {_META_CLIENT_CAPABILITIES}"))

        # Protocol-version support -> UnsupportedProtocolVersion (-32022) with the list.
        if meta_version not in SUPPORTED_PROTOCOL_VERSIONS:
            return (400, self._rpc_error(
                request_id, MCP_ERR_UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version",
                data={"supported": SUPPORTED_PROTOCOL_VERSIONS, "requested": meta_version}))

        # Mirrored HTTP headers must be present and match the body -> HeaderMismatch (-32020).
        if header_version is None or header_version != meta_version:
            return (400, self._rpc_error(
                request_id, MCP_ERR_HEADER_MISMATCH,
                "Header mismatch: MCP-Protocol-Version header must be present and match "
                "the request _meta protocolVersion"))
        if self.headers.get('Mcp-Method') != method:
            return (400, self._rpc_error(
                request_id, MCP_ERR_HEADER_MISMATCH,
                "Header mismatch: Mcp-Method header must be present and match the body method"))
        name_field = _MCP_NAME_SOURCE.get(method)
        if name_field is not None:
            mcp_name = _decode_mcp_header(self.headers.get('Mcp-Name'))
            if mcp_name is None or mcp_name != params.get(name_field):
                return (400, self._rpc_error(
                    request_id, MCP_ERR_HEADER_MISMATCH,
                    f"Header mismatch: Mcp-Name header must be present and match params.{name_field}"))
        return None

    def _send_json(self, status_code, payload):
        """Send a JSON body with the standard security headers."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def send_error_response(self, status_code, error_data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(error_data).encode())


# Vercel's Python runtime requires the entry-point class to be named `handler`;
# `HTTPHandler` is the readable alias for callers without that constraint.
HTTPHandler = handler
