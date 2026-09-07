# Repository layout

```
mcp-stride-gpt/
├── api/
│   └── index.py            # Vercel entry point (subclasses server.http_handler.HTTPHandler)
├── app.py                  # Local / container entry point (stdlib HTTP server)
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
├── Dockerfile              # Self-hosted container (runs app.py)
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

## Entry points

The handler is defined once, in `server/http_handler.py`, and reached three ways:

| Deployment | Entry point | Notes |
|---|---|---|
| Hosted (Vercel) | `api/index.py` | Vercel's runtime requires a module-level class named `handler`, and `@vercel/python` finds it by parsing this file statically — it does not follow imports or plain assignments, so an alias fails the build. This puts the repo root on `sys.path` and declares `handler` as a subclass of `HTTPHandler`. Routing, the `mcp.stridegpt.ai` alias, and the `includeFiles` bundling of `skills/**` and `server/**` all live in `vercel.json` — deleting it breaks the deploy. |
| Local | `app.py` | `python app.py`; binds loopback on port 8787. Set `MCP_HOST=0.0.0.0` to expose it. |
| Container | `app.py` | `docker build -t mcp-stride-gpt . && docker run --rm -p 8787:8787 mcp-stride-gpt` |

`HTTPHandler` in `server/http_handler.py` is an alias for `handler`; the short name exists
only because Vercel insists on the lowercase one.
