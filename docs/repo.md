# Repository layout

```
mcp-stride-gpt/
├── api/
│   └── index.py            # Vercel entry point (re-exports server.http_handler.handler)
├── server/
│   ├── __init__.py
│   ├── http_handler.py     # BaseHTTPRequestHandler + HTTP glue, Origin allow-list
│   ├── mcp.py              # MCP JSON-RPC routing (handle_mcp_request) + skill resources
│   ├── tools.py            # All tool implementations
│   ├── validation.py       # JSON complexity validation
│   ├── errors.py           # sanitize_error
│   └── constants.py        # Error codes, payload limits, protocol versions, server info
├── skills/
│   └── stride-threat-modelling/   # Companion Agent Skill (also served over MCP resources)
├── tests/
│   ├── test_http_handler.py
│   ├── test_mcp_handler.py
│   └── test_tools.py
├── requirements.txt
├── README.md
└── vercel.json             # REQUIRED for the hosted deployment at mcp.stridegpt.ai
```

## Where things live

The modules follow the boundaries the code already changed along: protocol work lands in
`mcp.py`, threat-modelling content in `tools.py`, and the two rarely move together.

| Module | Contains |
|---|---|
| `server/tools.py` | The 8 tool implementations — frameworks, rubrics, and templates returned to the client |
| `server/mcp.py` | JSON-RPC dispatch, protocol negotiation, `tools/*`, `resources/*`, `server/discover` |
| `server/http_handler.py` | The HTTP transport: payload limits, Origin allow-list, security headers |
| `server/constants.py` | Error codes, payload limits, protocol versions, server identity |
| `server/validation.py` | `validate_json_complexity` (DoS protection) |
| `server/errors.py` | `sanitize_error` |

## Entry point

The handler is defined once, in `server/http_handler.py`. Vercel's Python runtime requires
a module-level class named `handler`, so `api/index.py` puts the repo root on `sys.path`
and re-exports it. Routing, the `mcp.stridegpt.ai` alias, and the `includeFiles` bundling
of `skills/**` and `server/**` all live in `vercel.json` — deleting it breaks the deploy.

`HTTPHandler` in `server/http_handler.py` is an alias for `handler`; the short name exists
only because Vercel insists on the lowercase one.
