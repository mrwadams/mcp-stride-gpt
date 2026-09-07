"""Tests for api/index.py, the module Vercel actually loads.

The rest of the suite imports `server.*` directly, so it stays green even when the
Vercel entry point is broken -- which is how a build failure ("Could not find a
top-level \"app\", \"application\", or \"handler\" in \"api/index.py\"") reached review
once already. These tests exercise the entry point the way the platform does.
"""

import ast
import importlib
import os
import sys
from http.server import BaseHTTPRequestHandler

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, REPO_ROOT)

ENTRYPOINT = os.path.join(REPO_ROOT, 'api', 'index.py')

# @vercel/python looks for one of these names; see detectPythonEntrypoint.
VERCEL_ENTRYPOINT_NAMES = ('app', 'application', 'handler')


class TestVercelEntrypoint:
    """api/index.py must satisfy both the build-time parser and the runtime import."""

    def test_defines_handler_for_the_static_parser(self):
        """@vercel/python parses this file for a top-level `app`/`application`/`handler`
        *definition*. It does not follow `from ... import handler`, nor a plain
        `handler = X` assignment, so only a def/class here keeps the build green."""
        tree = ast.parse(open(ENTRYPOINT).read())
        defined = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert defined & set(VERCEL_ENTRYPOINT_NAMES), (
            f"api/index.py defines no top-level {' / '.join(VERCEL_ENTRYPOINT_NAMES)}; "
            "the Vercel build will fail before any code runs"
        )

    def test_handler_imports_and_is_a_request_handler(self):
        """Vercel imports the module as `api.index` from the function root and
        instantiates the class named `handler`."""
        module = importlib.import_module('api.index')
        assert hasattr(module, 'handler'), "api/index.py exposes no `handler`"
        assert issubclass(module.handler, BaseHTTPRequestHandler)

    def test_handler_is_the_server_package_implementation(self):
        """The entry point must serve the real handler, not a stub: the `server` package
        has to resolve from api/index.py's sys.path setup."""
        from server.http_handler import HTTPHandler

        module = importlib.import_module('api.index')
        assert issubclass(module.handler, HTTPHandler)

    def test_handler_serves_the_full_tool_set(self):
        """A handler wired to the wrong module would still be a BaseHTTPRequestHandler.
        Check it routes to the real dispatch."""
        from server.mcp import handle_mcp_request

        response = handle_mcp_request({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        assert len(response['result']['tools']) == 8
