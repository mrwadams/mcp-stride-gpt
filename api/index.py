"""Vercel serverless entry point.

Vercel's Python runtime imports this module and instantiates the class named `handler`.
The implementation lives in the `server` package so the same code serves the hosted
deployment, the local `app.py` server, and the Docker image.
"""

import os
import sys

# Vercel executes this module from within api/; put the repo root on the path so the
# sibling `server` package (and the bundled skills/ directory it reads) resolve.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.http_handler import handler  # noqa: E402  (path setup must precede import)

__all__ = ["handler"]
