"""Vercel serverless entry point.

Vercel's Python runtime imports this module and instantiates the class named `handler`.
The implementation lives in the `server` package, so the same code can serve the hosted
deployment and any other transport built on top of it.
"""

import os
import sys

# The function root (the repo root) holds the sibling `server` package and the bundled
# skills/ directory it reads; put it on the path before importing from it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.http_handler import HTTPHandler  # noqa: E402  (path setup must precede import)


# Subclass rather than `from server.http_handler import handler`: @vercel/python parses
# this file statically for a top-level `app`/`application`/`handler` *definition* and does
# not follow imports or plain assignments, so an alias fails the build with
# "Could not find a top-level ... handler in api/index.py".
class handler(HTTPHandler):  # noqa: N801  (Vercel requires this exact name)
    pass


__all__ = ["handler"]
