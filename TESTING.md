# STRIDE GPT MCP Server - Testing & Troubleshooting Guide

## Quick Verification

Test that the server can start correctly:

```bash
# Test server startup
uv run python -m stride_mcp.server

# Test module imports  
uv run python -c "from stride_mcp.server import mcp; print('✅ Server ready')"
```

## Testing Options

### Claude Desktop Testing

See README.md for complete Claude Desktop configuration instructions.

**Test prompts:**
```
"Analyze threats for an e-commerce web application with OAuth authentication and payment processing"

"Generate DREAD risk scores for the identified threats"

"Create a professional threat modeling report with mitigations and recommendations"

"Validate the completeness of my threat model and suggest improvements"
```

### MCP Dev Server (Advanced)

For development and debugging:

```bash
# Install MCP dev tools
pip install mcp

# Start development server  
uv run mcp dev src/stride_mcp/server.py
```

## Troubleshooting

### Common Issues

**"ModuleNotFoundError" errors:**
```bash
# Ensure dependencies are installed
uv sync

# Verify virtual environment
ls -la .venv/bin/python
```

**Claude Desktop connection issues:**
```bash  
# Use absolute paths in configuration
# Ensure PYTHONPATH includes src directory
# Restart Claude Desktop after config changes
```

**Repository analysis (when using GitHub MCP):**
```bash
# Ensure GitHub MCP server is configured separately
# GitHub token needed only for GitHub MCP server, not STRIDE GPT
# See README.md for GitHub MCP configuration details
```

---

**Your STRIDE GPT MCP server is ready for production use!**