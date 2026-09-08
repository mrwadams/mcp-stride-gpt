"""Tests for app.py, the local / container entry point.

Same reason test_entrypoint.py exists for api/index.py: the rest of the suite imports
`server.*` directly, so it stays green no matter what app.py does. The bind address is the
only thing standing between a laptop and an unauthenticated MCP endpoint on the local
network, so it is pinned here rather than left to review.
"""

import importlib
import os
import socket
import sys
import threading
from http.server import ThreadingHTTPServer

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, REPO_ROOT)


def load_app(monkeypatch, **env):
    """Import app.py with a controlled environment. HOST/PORT are read at import time."""
    for name in ('MCP_HOST', 'MCP_PORT'):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    import app
    return importlib.reload(app)


class TestBindAddress:
    """`python app.py` must not put the endpoint on the network without being asked."""

    def test_defaults_to_loopback(self, monkeypatch):
        assert load_app(monkeypatch).HOST == '127.0.0.1'

    def test_empty_mcp_host_still_means_loopback(self, monkeypatch):
        """Python binds '' to every interface. An empty MCP_HOST in a .env or compose
        file must not be a silent wildcard bind."""
        assert load_app(monkeypatch, MCP_HOST='').HOST == '127.0.0.1'

    def test_explicit_host_is_honoured(self, monkeypatch):
        """The container sets this; exposing the endpoint has to stay possible."""
        assert load_app(monkeypatch, MCP_HOST='0.0.0.0').HOST == '0.0.0.0'

    def test_binds_the_address_it_reports(self, monkeypatch):
        """The original bug was a 0.0.0.0 bind logged as 127.0.0.1."""
        app = load_app(monkeypatch, MCP_PORT='0')
        server = app.build_server()
        try:
            assert server.server_address[0] == app.HOST
        finally:
            server.server_close()


class TestServer:
    def test_one_stalled_client_does_not_block_the_next_request(self, monkeypatch):
        """A client that connects and sends nothing must not hold up everyone else.
        This fails on a plain HTTPServer, which handles one connection at a time."""
        app = load_app(monkeypatch, MCP_PORT='0')
        server = app.build_server()
        assert isinstance(server, ThreadingHTTPServer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        stalled = socket.create_connection(('127.0.0.1', port))
        try:
            live = socket.create_connection(('127.0.0.1', port), timeout=5)
            live.sendall(b'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
            assert b'200 OK' in live.recv(64)
            live.close()
        finally:
            stalled.close()
            server.shutdown()
            server.server_close()

    def test_handler_gets_a_request_timeout(self, monkeypatch):
        """Without it a stalled connection holds its worker thread forever."""
        app = load_app(monkeypatch, MCP_PORT='0')
        server = app.build_server()
        try:
            assert app.HTTPHandler.timeout == app.REQUEST_TIMEOUT_SECONDS
        finally:
            server.server_close()

    def test_serves_the_real_handler(self, monkeypatch):
        """A wrong import would still be a request handler. Check it is the shared one."""
        from server.http_handler import HTTPHandler

        assert load_app(monkeypatch).HTTPHandler is HTTPHandler
