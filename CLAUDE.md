# CLAUDE.md - MCP Server Guidelines

This file provides guidance for Claude Code when working on the STRIDE GPT MCP server.

## Overview

This is an MCP (Model Context Protocol) server that provides threat modeling tools using the STRIDE methodology. The server provides frameworks and structure for LLM clients to perform security analysis.

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
def _analyze_damage_potential(threat_analysis: Dict[str, Any]) -> int:
    """Provide DREAD damage scoring framework - LLM client should analyze threat context.
    
    Damage scoring considers:
    - Financial impact to the organization
    - Regulatory/compliance consequences
    - Data sensitivity implications
    - Business continuity disruption
    
    Score 1-3: Minor impact, localized effects
    Score 4-6: Moderate impact, departmental effects
    Score 7-8: High impact, organizational effects
    Score 9-10: Severe impact, industry/regulatory effects
    """
    # Return placeholder - LLM client should replace with actual analysis
    return 5
```

## MCP Server Architecture

- **server.py**: FastMCP server entry point
- **tools.py**: All 8 STRIDE threat modeling tools
- **models.py**: Pydantic data models for structured responses

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

## Tool Functions

Each tool should:
- Accept structured threat data
- Provide clear frameworks and rubrics
- Return placeholders for LLM client to replace with actual analysis
- Include comprehensive docstrings explaining the framework
- Focus on batch processing to minimize latency

## Testing

Use the MCP server directly through Claude Desktop or the MCP client to test tools with real threat data and verify outputs provide meaningful differentiation.