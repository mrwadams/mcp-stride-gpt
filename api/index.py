# api/index.py
import json

from server.mcp import handle_mcp_request
from server.validation import validate_json_complexity
from server.errors import sanitize_error
from server.constants import PAYLOAD_LIMITS, ERROR_CODES
from http.server import BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        
    def do_GET(self):
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
            
            # Handle MCP request using our improved server
            response = handle_mcp_request(body)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, "HTTP POST request handling")
            self.send_error_response(500, {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": sanitized_message},
                "id": None
            })
    
    def send_error_response(self, status_code, error_data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(error_data).encode())
        
        