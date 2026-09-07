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
# that is asked for explicitly.
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8787"))

# Without a timeout a client that connects and never sends a request line occupies its
# worker thread forever.
REQUEST_TIMEOUT_SECONDS = 30


def main():
    HTTPHandler.timeout = REQUEST_TIMEOUT_SECONDS
    server = ThreadingHTTPServer((HOST, PORT), HTTPHandler)
    print(f"MCP server listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
