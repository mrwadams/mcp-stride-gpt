from .tools import *
from .errors import sanitize_error
from .constants import ERROR_CODES
import json 

def handle_mcp_request(body: dict) -> dict:
    """Handle MCP JSON-RPC requests using the improved MCP server"""
    
    method = body.get('method')
    params = body.get('params', {})
    request_id = body.get('id')
    
    
    # Handle initialize
    if method == 'initialize':
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": "STRIDE GPT MCP Server",
                    "version": "0.1.0"
                },
                "instructions": "Professional threat modeling server using the STRIDE methodology."
            },
            "id": request_id
        }
    
    # Handle tools/list
    elif method == 'tools/list':
        tools = [
            {
                "name": "get_stride_threat_framework",
                "description": "Get comprehensive STRIDE threat modeling framework and guidance for threat analysis",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "app_description": {
                            "type": "string",
                            "description": "Detailed description of the application architecture and functionality"
                        },
                        "app_type": {
                            "type": "string", 
                            "description": "Type of application",
                            "default": "Web Application"
                        },
                        "authentication_methods": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of authentication methods used",
                            "default": ["Username/Password"]
                        },
                        "internet_facing": {
                            "type": "boolean",
                            "description": "Whether the application is accessible from the internet",
                            "default": True
                        },
                        "sensitive_data_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Types of sensitive data handled",
                            "default": ["User Data"]
                        }
                    },
                    "required": ["app_description"]
                }
            },
            {
                "name": "generate_threat_mitigations",
                "description": "Generate actionable security mitigations for identified threats",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "priority_filter": {
                            "type": "string",
                            "description": "Filter by priority",
                            "default": "all"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "create_threat_attack_trees",
                "description": "Generate application-wide attack tree showing common attack vectors",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects (used for context)"
                        },
                        "max_depth": {
                            "type": "integer",
                            "description": "Maximum tree depth",
                            "default": 3
                        },
                        "output_format": {
                            "type": "string",
                            "description": "Output format",
                            "default": "both"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "calculate_threat_risk_scores",
                "description": "Calculate DREAD risk scores to prioritize threats by severity",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "scoring_guidance": {
                            "type": "object",
                            "additionalProperties": True,
                            "description": "Optional guidance for scoring adjustments"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "generate_security_tests",
                "description": "Generate security test cases to validate threat mitigations",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threats": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "test_type": {
                            "type": "string",
                            "description": "Type of tests",
                            "default": "mixed"
                        },
                        "format_type": {
                            "type": "string",
                            "description": "Output format",
                            "default": "gherkin"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "generate_threat_report",
                "description": "Format complete threat analysis as professional markdown report",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threat_model": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects"
                        },
                        "mitigations": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Optional array of mitigation strategies"
                        },
                        "dread_scores": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Optional array of DREAD scores"
                        },
                        "attack_trees": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Optional array of attack trees"
                        },
                        "include_sections": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Sections to include in report",
                            "default": ["executive_summary", "threats", "mitigations", "risk_scores"]
                        }
                    },
                    "required": ["threat_model"]
                }
            },
            {
                "name": "validate_threat_coverage",
                "description": "Validate STRIDE coverage completeness and suggest threat model enhancements",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "threat_model": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True
                            },
                            "description": "Array of threat objects to validate"
                        },
                        "app_context": {
                            "type": "object",
                            "additionalProperties": True,
                            "description": "Application context information"
                        }
                    },
                    "required": ["threat_model", "app_context"]
                }
            },
            {
                "name": "get_repository_analysis_guide",
                "description": "Get structured framework for extracting threat modeling inputs from repository analysis using GitHub MCP or similar tools",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "analysis_stage": {
                            "type": "string",
                            "description": "Analysis stage: 'initial' (quick scan), 'deep_dive' (detailed security analysis), or 'validation' (readiness check)",
                            "enum": ["initial", "deep_dive", "validation"],
                            "default": "initial"
                        },
                        "repository_context": {
                            "type": "object",
                            "description": "Optional context about the repository",
                            "properties": {
                                "primary_language": {
                                    "type": "string",
                                    "description": "Primary programming language detected"
                                },
                                "framework_detected": {
                                    "type": "string",
                                    "description": "Primary framework or platform detected"
                                },
                                "repository_type": {
                                    "type": "string",
                                    "description": "Type of repository",
                                    "enum": ["application", "library", "infrastructure", "unknown"]
                                }
                            }
                        }
                    },
                    "required": []
                }
            }
        ]
        return {
            "jsonrpc": "2.0",
            "result": {"tools": tools},
            "id": request_id
        }
    
    # Handle tools/call - actual implementation
    elif method == 'tools/call':
        tool_name = params.get('name')
        arguments = params.get('arguments', {})
        
        try:
            if tool_name == 'get_stride_threat_framework':
                result = get_stride_threat_framework(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'generate_threat_mitigations':
                result = generate_threat_mitigations(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'calculate_threat_risk_scores':
                result = calculate_threat_risk_scores(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'create_threat_attack_trees':
                result = create_threat_attack_trees(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'generate_security_tests':
                result = generate_security_tests(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'generate_threat_report':
                result = generate_threat_report(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": result  # This returns markdown directly
                            }
                        ]
                    },
                    "id": request_id
                }
            
            elif tool_name == 'validate_threat_coverage':
                result = validate_threat_coverage(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }

            elif tool_name == 'get_repository_analysis_guide':
                result = get_repository_analysis_guide(arguments)
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, indent=2)
                            }
                        ]
                    },
                    "id": request_id
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": ERROR_CODES['INVALID_PARAMETER'],
                        "message": f"Unknown tool: {tool_name}"
                    },
                    "id": request_id
                }
                
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, f"Tool execution: {tool_name}")
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": ERROR_CODES['TOOL_EXECUTION_FAILED'],
                    "message": sanitized_message
                },
                "id": request_id
            }
    
    else:
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            },
            "id": request_id
        }

