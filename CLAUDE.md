# CLAUDE.md - MCP Server Guidelines

This file provides guidance for Claude Code when working on the STRIDE GPT MCP server.

## Overview

This is a serverless MCP (Model Context Protocol) HTTP server deployed on Vercel that provides threat modeling tools using the STRIDE methodology. The server provides frameworks and structure for LLM clients to perform security analysis.

**🌐 Hosted at**: https://mcp.stridegpt.ai/

## Companion Skill (primary path) & Source of Truth

This repo ships two complementary pieces: the **MCP server** (these tools) and the
**`stride-threat-modelling` skill** (`skills/stride-threat-modelling/`). Since the
skill-as-primary pivot, the **skill is the primary deliverable and the canonical home** of
the methodology and the report house style — it runs on the client's own model with no API
key and no dependency on this hosted server. The MCP server is the **framework-provider
fallback** for clients that don't support Agent Skills (e.g. Gemini CLI).

Practical consequences when editing this repo:

- The server's tool descriptions and the server-level `instructions` field are worded to
  make clear the tools *return frameworks/rubrics/templates* — the client's LLM does the
  analysis. Keep them honest; don't reintroduce "the server calculates/generates X" phrasing.
- `generate_threat_report`'s Markdown skeleton is an **intentional parallel copy** of
  `skills/stride-threat-modelling/references/report-format.md`, kept for non-skill clients.
  If you change one, sync the other; the skill is authoritative where available.
- See `MCP_DESIGN_PRINCIPLES.md` for the "information provider, not analyzer" rationale.

## CRITICAL: No Keyword Matching

**NEVER** use brittle keyword matching patterns in MCP server code. The MCP server should provide frameworks and instructions for the LLM client to perform the actual semantic analysis.

### Wrong Approach (DON'T DO THIS):
```python
# Brittle keyword matching - AVOID
if any(term in text.lower() for term in ["payment", "financial"]):
    score += 2
if any(term in combined_text for term in ["system compromise", "admin"]):
    score += 3
```

### Correct Approach (DO THIS):
```python
def get_stride_threat_framework(args: Dict[str, Any]) -> Dict[str, Any]:
    """Provide STRIDE threat modeling framework for LLM client analysis.
    
    Returns comprehensive framework with:
    - STRIDE categories and threat examples
    - Extended threat domains (AI/ML, cloud, IoT, etc.)
    - Application context analysis
    - Analysis guidance for LLM client
    """
    return {
        "stride_framework": { /* framework data */ },
        "application_context": { /* app context */ },
        "analysis_guidance": "Use this framework to analyze threats..."
    }
```

## Serverless Architecture

- **api/index.py**: Single-file Vercel serverless function
- **vercel.json**: Deployment configuration
- **CLAUDE.md**: Development guidelines (this file)

## Key Principles

1. **Framework Provider**: Provide structure, scoring rubrics, and guidance
2. **LLM Client Does Analysis**: Let Claude/LLM client perform semantic understanding
3. **Structured Data**: Use clear data models and return formats
4. **Single Application Focus**: Attack trees should be application-wide, not per-threat
5. **Merit-Based Scoring**: No fixed base scores - each threat scored on individual merit
6. **Composable Architecture**: Work with other MCP servers (e.g., GitHub MCP server for repo analysis)

## GitHub Integration

**DO NOT** build custom GitHub integration. Instead, recommend users install the official GitHub MCP server:

- [GitHub MCP Server](https://github.com/github/github-mcp-server)
- Users can combine GitHub MCP server (for repo analysis) with STRIDE GPT MCP server (for threat modeling)
- This follows MCP philosophy of composable, specialized tools

## Available Tools

The serverless MCP server registers 8 tools — 7 core threat modeling tools plus a
repository-analysis guide. Each *returns a framework/rubric/template* for the client's LLM
to populate; it does not perform the analysis itself.

1. **get_stride_threat_framework**: STRIDE framework + guidance (extended domains: AI/ML, cloud, IoT) for the client to enumerate threats
2. **generate_threat_mitigations**: Mitigation-strategy framework (control types, difficulty, priority) to guide the client's recommendations
3. **calculate_threat_risk_scores**: DREAD scoring rubric and criteria — the client assigns the scores
4. **create_threat_attack_trees**: Attack-tree structure and guidance (with Mermaid support) for the client to build application-wide trees
5. **generate_security_tests**: Security-test scaffolding and guidance in multiple formats (Gherkin, Checklist, Markdown)
6. **generate_threat_report**: Markdown report template/skeleton for the client to populate (see the report-format sync note above)
7. **validate_threat_coverage**: STRIDE coverage validation and enhancement suggestions
8. **get_repository_analysis_guide**: Structured framework for extracting threat-modeling inputs from a repo (pairs with the GitHub MCP server)

## Tool Design Principles

Each tool should:
- Accept structured threat data via JSON-RPC parameters
- Provide comprehensive frameworks and rubrics
- Return rich framework data (not placeholders) for LLM client analysis
- Include detailed analysis guidance in responses
- Support batch processing for efficiency

## Security Controls

The MCP server implements several security controls to protect against common attacks and information disclosure:

### Error Message Sanitization

**Purpose**: Prevent information disclosure through error messages (stack traces, file paths, internal details)

**Implementation**: The `sanitize_error()` function in `api/index.py` (lines 37-65) provides:
- Generic error messages for clients (no sensitive details)
- Detailed error logging to server logs (stderr → Vercel logs)
- Unique error IDs for correlating client reports with server logs
- Protection against leaking: stack traces, file paths, exception types, internal implementation details

**Usage**:
```python
try:
    # Risky operation
    result = process_user_input(data)
except Exception as e:
    error_id, sanitized_message = sanitize_error(e, "processing user input")
    return {"error": {"message": sanitized_message}}
```

**Testing**: See `tests/test_http_handler.py::TestErrorSanitization` for comprehensive test coverage

### Payload Validation

**Purpose**: Prevent DoS attacks via oversized or complex payloads

**Limits** (defined in `PAYLOAD_LIMITS`):
- Max payload size: 5MB
- Max JSON depth: 20 levels
- Max object keys: 500 per object
- Max array length: 2000 elements
- Max string length: 500KB

**Implementation**: `validate_json_complexity()` recursively validates JSON structure before processing

### HTTP Security Headers

All responses include security headers:
- `X-Content-Type-Options: nosniff` - Prevent MIME-type sniffing
- `X-Frame-Options: DENY` - Prevent clickjacking
- `X-XSS-Protection: 1; mode=block` - Enable XSS filtering

## Deployment & Testing

**Hosted Server**: https://mcp.stridegpt.ai/

**Testing Methods**:
- Use MCP server directly through an MCP client (e.g. Claude Code, Gemini CLI) configuration
- Test via MCP client tools for development
- Validate with real threat modeling scenarios
- Ensure consistent behavior across different LLM clients

**Local Development**: Modify `api/index.py` and deploy to Vercel for testing