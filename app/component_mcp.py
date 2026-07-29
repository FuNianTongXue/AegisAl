"""Compatibility alias for :mod:`app.mcp.component_query`."""

import sys

from app.mcp import component_query as _implementation

sys.modules[__name__] = _implementation
