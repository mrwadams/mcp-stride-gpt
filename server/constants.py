"""Shared constants: error codes, payload limits, MCP protocol versions, server identity."""

# Enhanced error codes following MCP standards
ERROR_CODES = {
    'INVALID_PARAMETER': -32603,
    'TOOL_EXECUTION_FAILED': -32604,
    'INTERNAL_ERROR': -32603,
    'PAYLOAD_TOO_LARGE': -32600,
    'PAYLOAD_TOO_COMPLEX': -32600
}

# Payload validation limits
# These limits balance security (DoS prevention) with practical MCP usage
PAYLOAD_LIMITS = {
    'MAX_PAYLOAD_SIZE': 5_242_880,  # 5MB max payload size (increased for large threat models)
    'MAX_JSON_DEPTH': 20,            # Maximum nesting depth (MCP protocol + nested threat data)
    'MAX_OBJECT_KEYS': 500,          # Maximum keys in single object (rich threat metadata)
    'MAX_ARRAY_LENGTH': 2000,        # Maximum array length (large-scale threat assessments)
    'MAX_STRING_LENGTH': 500_000     # Maximum string length (500KB - detailed descriptions)
}

# MCP protocol revisions this server supports, newest first (spec: modelcontextprotocol.io).
# The server is dual-era: it answers the legacy `initialize` handshake (2025-11-25 and
# earlier) AND the modern per-request stateless model (2026-07-28), where a client carries
# its protocol version and capabilities in each request's `_meta` and calls `server/discover`
# instead of `initialize`. `initialize` negotiates only among the legacy versions; a modern
# client never sends it.
LEGACY_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"]
MODERN_PROTOCOL_VERSIONS = ["2026-07-28"]
SUPPORTED_PROTOCOL_VERSIONS = MODERN_PROTOCOL_VERSIONS + LEGACY_PROTOCOL_VERSIONS
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]   # newest overall (modern)
LATEST_LEGACY_VERSION = LEGACY_PROTOCOL_VERSIONS[0]        # newest handshake version

# Reserved `_meta` keys carrying the per-request protocol fields in the modern model
# (MCP 2026-07-28, basic/index#meta). Clients put these in each request's params._meta;
# servers echo their identity back in the result's _meta.
_META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
_META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
_META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# MCP-reserved JSON-RPC error codes (2026-07-28, range -32020..-32099).
MCP_ERR_HEADER_MISMATCH = -32020
MCP_ERR_MISSING_CLIENT_CAPABILITY = -32021
MCP_ERR_UNSUPPORTED_PROTOCOL_VERSION = -32022

# Cache hints for the CacheableResult interface (MCP 2026-07-28, SEP-2549). List/read
# results carry ttlMs (how long a client may reuse the response, in ms) and cacheScope
# ("public" so shared intermediaries may cache it — the tool catalogue is static and
# carries no per-client data). The fields are additive: older clients ignore them.
CACHE_SCOPE = "public"
CACHE_TTL_MS = 3_600_000  # tools/list is a static catalogue; 1 hour is safe

# Server identity and capabilities, shared by `initialize` (legacy) and `server/discover`
# (modern) so both eras report the same thing.
SERVER_INFO = {"name": "STRIDE GPT MCP Server", "version": "0.1.0"}
SERVER_CAPABILITIES = {
    "resources": {"listChanged": False},
    "tools": {"listChanged": False},
}
SERVER_INSTRUCTIONS = (
    "STRIDE threat modelling framework provider. These tools return methodology, scoring "
    "rubrics, and report templates for your own model to populate with real analysis — they "
    "do not perform the analysis themselves. If your client supports Agent Skills, the "
    "companion 'stride-threat-modelling' skill is the primary, richer path and runs "
    "standalone; use these tools when it is not available."
)
