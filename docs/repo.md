
```
mcp_stride_gpt/
├── app.py                  # ENTRYPOINT (local + prod)
├── server/
│   ├── __init__.py
│   ├── http_handler.py     # BaseHTTPRequestHandler + HTTP glue
│   ├── mcp.py              # MCP JSON-RPC routing (handle_mcp_request)
│   ├── tools.py            # All tool implementations
│   ├── validation.py       # Payload limits + JSON complexity
│   ├── errors.py           # Error codes + sanitize_error
│   └── constants.py        # Limits, protocol version, server info
├── tests/
│   ├── test_http_handler.py
│   ├── test_mcp_handler.py
│   └── test_tools.py
├── requirements.txt
├── README.md
└── vercel.json             # optional (can keep or delete)
```