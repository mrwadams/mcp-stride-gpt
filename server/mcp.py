"""MCP JSON-RPC layer: protocol negotiation, tools/list + tools/call dispatch, and the
companion Agent Skill served over the resources interface."""

import json
import os
from pathlib import Path

from .constants import (
    CACHE_SCOPE,
    CACHE_TTL_MS,
    ERROR_CODES,
    LATEST_LEGACY_VERSION,
    LEGACY_PROTOCOL_VERSIONS,
    SERVER_CAPABILITIES,
    SERVER_INFO,
    SERVER_INSTRUCTIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
    _META_SERVER_INFO,
)
from .errors import sanitize_error
from .tools import (
    calculate_threat_risk_scores,
    create_threat_attack_trees,
    generate_security_tests,
    generate_threat_mitigations,
    generate_threat_report,
    get_repository_analysis_guide,
    get_stride_threat_framework,
    validate_threat_coverage,
)

# Companion Agent Skill served over MCP resources (Option A of the Skills-over-MCP idea).
# Skill-aware clients load skills/stride-threat-modelling/ natively; this exposes the same
# files over resources/read so MCP-only clients can pull the canonical guidance (including
# the report house style) instead of relying on parallel copies embedded in tool output.
SKILL_NAME = "stride-threat-modelling"
SKILL_DIR = Path(__file__).parent.parent / "skills" / SKILL_NAME
SKILL_URI_PREFIX = "stride://skill/"
_SKILL_MIME = {".md": "text/markdown", ".html": "text/html", ".txt": "text/plain"}


def _skill_files():
    """Return skill file paths relative to SKILL_DIR (POSIX), SKILL.md first.

    Returns [] if the skill directory is not present in the deployment, so the resource
    endpoints degrade gracefully rather than erroring."""
    if not SKILL_DIR.is_dir():
        return []
    rels = [p.relative_to(SKILL_DIR).as_posix() for p in SKILL_DIR.rglob("*") if p.is_file()]
    rels.sort(key=lambda r: (r != "SKILL.md", r))  # entry point first, then alphabetical
    return rels


def _skill_resource_descriptor(rel):
    """Build a resources/list descriptor for a skill file at relative path `rel`."""
    ext = os.path.splitext(rel)[1].lower()
    if rel == "SKILL.md":
        description = "Entry point for the STRIDE threat-modelling skill: the end-to-end workflow."
    elif rel == "EXAMPLES.md":
        description = "A complete worked example of the STRIDE workflow in the report house style."
    elif rel.startswith("references/"):
        description = f"Reference material for the STRIDE skill: {rel[len('references/'):]}"
    elif rel.startswith("assets/"):
        description = f"Asset used by the STRIDE skill: {rel[len('assets/'):]}"
    else:
        description = f"STRIDE threat-modelling skill file: {rel}"
    return {
        "uri": SKILL_URI_PREFIX + rel,
        "name": f"{SKILL_NAME}/{rel}",
        "description": description,
        "mimeType": _SKILL_MIME.get(ext, "text/plain"),
    }


def _resolve_skill_uri(uri):
    """Map a stride://skill/<relpath> URI to a file inside SKILL_DIR, or None.

    Rejects anything outside the skill directory (path-traversal safe) and any URI that
    does not resolve to an existing file."""
    if not isinstance(uri, str) or not uri.startswith(SKILL_URI_PREFIX):
        return None
    rel = uri[len(SKILL_URI_PREFIX):]
    if not rel:
        return None
    base = SKILL_DIR.resolve()
    target = (base / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        return None  # traversal outside the skill directory
    return target if target.is_file() else None

def _with_result_type(response: dict) -> dict:
    """Stamp the required `resultType` on successful results (MCP 2026-07-28, SEP-2322).
    Ordinary results are "complete"; a handler returning an MRTR interim result may set
    "input_required" itself, which we leave untouched. Error responses carry no `result`
    and are left alone. Additive — older clients ignore the field."""
    result = response.get("result")
    if isinstance(result, dict) and "resultType" not in result:
        result["resultType"] = "complete"
    return response


def _with_server_meta(response: dict) -> dict:
    """Attach the modern per-response server identity — `io.modelcontextprotocol/serverInfo`
    inside the result's `_meta` — which the 2026-07-28 spec says servers SHOULD include on
    every result. Successful results only; error responses are left alone."""
    result = response.get("result")
    if isinstance(result, dict):
        meta = result.setdefault("_meta", {})
        meta.setdefault(_META_SERVER_INFO, SERVER_INFO)
    return response


def _decode_mcp_header(value):
    """Decode the Base64 sentinel form (`=?base64?...?=`) the Streamable HTTP transport
    permits for Mcp-Name / Mcp-Param-* header values; pass other values through unchanged."""
    if isinstance(value, str) and value.startswith("=?base64?") and value.endswith("?="):
        import base64
        try:
            return base64.b64decode(value[len("=?base64?"):-2]).decode("utf-8")
        except Exception:
            return value
    return value


# Body field that supplies the required Mcp-Name header, per method (2026-07-28 transport).
_MCP_NAME_SOURCE = {
    "tools/call": "name",
    "resources/read": "uri",
    "prompts/get": "name",
}


# Keys in a tool response that only echo the caller's own input back to it, or
# ship large static reference blocks the client already received once. They are
# useful for humans eyeballing a single call but pure token overhead when an
# agent drives the workflow across many calls. verbosity="brief" strips them;
# the rubric/framework, analysis_guidance, and next_steps are always retained.
_VERBOSE_ECHO_KEYS = (
    "threats",             # calculate_threat_risk_scores input echo
    "threat_context",      # mitigations / attack-trees / security-tests input echo
    "threat_model",        # validate_threat_coverage input echo
    "app_context",         # validate_threat_coverage input echo
    "application_context", # get_stride_threat_framework input echo
    "scoring_guidance",    # calculate_threat_risk_scores input echo
    "scoring_examples",    # calculate_threat_risk_scores large worked-example block
)


def _apply_verbosity(result: dict, args: dict) -> dict:
    """Optionally trim echoed inputs / large example blocks from a tool result.

    verbosity="full" (the default) returns the response unchanged, preserving
    backward compatibility for existing clients. verbosity="brief" drops the
    keys in ``_VERBOSE_ECHO_KEYS`` — the parts that merely echo the caller's
    input or repeat large static reference material — keeping the framework,
    analysis_guidance, and next_steps. Non-dict results pass through untouched.
    """
    if not isinstance(result, dict):
        return result
    if str(args.get("verbosity", "full")).lower() != "brief":
        return result
    return {k: v for k, v in result.items() if k not in _VERBOSE_ECHO_KEYS}


def handle_mcp_request(body: dict) -> dict:
    """Handle MCP JSON-RPC requests using the improved MCP server"""
    
    method = body.get('method')
    params = body.get('params', {})
    request_id = body.get('id')
    
    
    # Handle initialize (legacy handshake). Modern clients use server/discover instead.
    if method == 'initialize':
        # Version negotiation: honour the client's requested version if it is a legacy
        # version we support, otherwise offer our latest legacy version. `initialize` is a
        # legacy-only handshake, so it never offers a modern (2026-07-28) version.
        requested_version = params.get('protocolVersion')
        negotiated_version = (
            requested_version
            if requested_version in LEGACY_PROTOCOL_VERSIONS
            else LATEST_LEGACY_VERSION
        )
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": negotiated_version,
                "capabilities": SERVER_CAPABILITIES,
                "serverInfo": SERVER_INFO,
                "instructions": SERVER_INSTRUCTIONS
            },
            "id": request_id
        }

    # Handle server/discover (modern stateless model, MCP 2026-07-28). Servers MUST
    # implement it: report supported versions, capabilities and identity in one call. The
    # result is cacheable and carries serverInfo in `_meta` per the spec.
    elif method == 'server/discover':
        return {
            "jsonrpc": "2.0",
            "result": {
                "resultType": "complete",
                "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "capabilities": SERVER_CAPABILITIES,
                "instructions": SERVER_INSTRUCTIONS,
                "ttlMs": CACHE_TTL_MS,
                "cacheScope": CACHE_SCOPE,
                "_meta": {_META_SERVER_INFO: SERVER_INFO}
            },
            "id": request_id
        }

    # Handle resources/list — the companion Agent Skill's files, served over MCP so
    # clients without native Agent Skills support can still fetch the canonical guidance.
    elif method == 'resources/list':
        resources = [_skill_resource_descriptor(rel) for rel in _skill_files()]
        return {
            "jsonrpc": "2.0",
            "result": {"resources": resources, "ttlMs": CACHE_TTL_MS, "cacheScope": CACHE_SCOPE},
            "id": request_id
        }

    # Handle resources/read — return the contents of a single skill file by URI.
    elif method == 'resources/read':
        uri = params.get('uri')
        target = _resolve_skill_uri(uri)
        if target is None:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": f"Unknown resource URI: {uri}"},
                "id": request_id
            }
        try:
            text = target.read_text(encoding='utf-8')
        except Exception as e:
            error_id, sanitized_message = sanitize_error(e, f"Reading resource: {uri}")
            return {
                "jsonrpc": "2.0",
                "error": {"code": ERROR_CODES['INTERNAL_ERROR'], "message": sanitized_message},
                "id": request_id
            }
        return {
            "jsonrpc": "2.0",
            "result": {
                "contents": [{
                    "uri": uri,
                    "mimeType": _SKILL_MIME.get(target.suffix.lower(), "text/plain"),
                    "text": text
                }],
                "ttlMs": CACHE_TTL_MS,
                "cacheScope": CACHE_SCOPE
            },
            "id": request_id
        }

    # Handle tools/list
    elif method == 'tools/list':
        tools = [
            {
                "name": "get_stride_threat_framework",
                "description": "Return the STRIDE threat-modelling framework and guidance for your model to enumerate threats against the described system. Provides structure and rubrics; your model does the analysis. In skill-aware clients, the 'stride-threat-modelling' skill is the primary path.",
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
                        },
                        "verbosity": {
                            "type": "string",
                            "description": "Response detail. 'full' (default) includes the framework plus an echo of your input; 'brief' omits the echoed input to save tokens.",
                            "enum": ["full", "brief"],
                            "default": "full"
                        }
                    },
                    "required": ["app_description"]
                }
            },
            {
                "name": "generate_threat_mitigations",
                "description": "Return a mitigation-strategy framework (control types, difficulty, prioritisation) to guide your model in proposing specific mitigations for the given threats.",
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
                        },
                        "verbosity": {
                            "type": "string",
                            "description": "Response detail. 'full' (default) includes the framework plus an echo of your input; 'brief' omits the echoed input to save tokens.",
                            "enum": ["full", "brief"],
                            "default": "full"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "create_threat_attack_trees",
                "description": "Return attack-tree structure and guidance (formats, decomposition method) for your model to build application-wide attack trees from the threat context.",
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
                        },
                        "verbosity": {
                            "type": "string",
                            "description": "Response detail. 'full' (default) includes the framework plus an echo of your input; 'brief' omits the echoed input to save tokens.",
                            "enum": ["full", "brief"],
                            "default": "full"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "calculate_threat_risk_scores",
                "description": "Return the DREAD scoring rubric and criteria for your model to score and prioritise the given threats by severity. The server supplies the rubric; your model assigns the scores.",
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
                        },
                        "verbosity": {
                            "type": "string",
                            "description": "Response detail. 'full' (default) includes the DREAD rubric plus an echo of your input and worked scoring examples; 'brief' omits the echoed input and the examples to save tokens.",
                            "enum": ["full", "brief"],
                            "default": "full"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "generate_security_tests",
                "description": "Return security-test scaffolding and guidance (formats, coverage areas) for your model to write test cases that validate the threats' mitigations.",
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
                        },
                        "verbosity": {
                            "type": "string",
                            "description": "Response detail. 'full' (default) includes the framework plus an echo of your input; 'brief' omits the echoed input to save tokens.",
                            "enum": ["full", "brief"],
                            "default": "full"
                        }
                    },
                    "required": ["threats"]
                }
            },
            {
                "name": "generate_threat_report",
                "description": "Return a Markdown report template/skeleton for your model to populate with the threat analysis. Provides the section scaffold, not finished content. In skill-aware clients the 'stride-threat-modelling' skill's report-format is the authoritative house style.",
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
                "description": "Return a coverage-validation checklist and common-gap prompts for your model to audit the threat model's completeness against. The server supplies the checklist; your model finds the gaps.",
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
                        },
                        "verbosity": {
                            "type": "string",
                            "description": "Response detail. 'full' (default) includes the framework plus an echo of your input; 'brief' omits the echoed input to save tokens.",
                            "enum": ["full", "brief"],
                            "default": "full"
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
            "result": {"tools": tools, "ttlMs": CACHE_TTL_MS, "cacheScope": CACHE_SCOPE},
            "id": request_id
        }

    # Handle tools/call - actual implementation
    elif method == 'tools/call':
        tool_name = params.get('name')
        arguments = params.get('arguments', {})
        
        try:
            if tool_name == 'get_stride_threat_framework':
                result = _apply_verbosity(get_stride_threat_framework(arguments), arguments)
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
                result = _apply_verbosity(generate_threat_mitigations(arguments), arguments)
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
                result = _apply_verbosity(calculate_threat_risk_scores(arguments), arguments)
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
                result = _apply_verbosity(create_threat_attack_trees(arguments), arguments)
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
                result = _apply_verbosity(generate_security_tests(arguments), arguments)
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
                result = _apply_verbosity(validate_threat_coverage(arguments), arguments)
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

