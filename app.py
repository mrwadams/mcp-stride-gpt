"""Local / container entry point.

Serves the same MCP endpoint as the hosted deployment, using the handler from
server.http_handler. `python app.py` binds loopback; the container overrides MCP_HOST
because it needs to accept traffic from outside its own network namespace.
"""

import os
from http.server import ThreadingHTTPServer

from server.http_handler import HTTPHandler

# Loopback by default: the server has no authentication and sends
# Access-Control-Allow-Origin: *, so it should not be reachable from the network unless
# that is asked for explicitly. `or` rather than a get() default, because MCP_HOST set to
# an empty string binds every interface -- the wildcard bind has to be spelled out.
HOST = os.environ.get("MCP_HOST") or "127.0.0.1"
PORT = int(os.environ.get("MCP_PORT") or "8787")

# Without a timeout a client that connects and never sends a request line occupies its
# worker thread forever.
REQUEST_TIMEOUT_SECONDS = 30


def build_server():
    """Construct the listening server. Separate from main() so tests can bind an
    ephemeral port and exercise the real socket."""
    HTTPHandler.timeout = REQUEST_TIMEOUT_SECONDS
    return ThreadingHTTPServer((HOST, PORT), HTTPHandler)


def main():
    server = build_server()
    # Report the address the socket is actually bound to, not the requested string: a
    # banner that disagrees with the socket is how the original 0.0.0.0 bind went unnoticed.
    host, port = server.server_address[:2]
    print(f"MCP server listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
