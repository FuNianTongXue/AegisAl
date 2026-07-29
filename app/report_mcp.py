"""Compatibility alias for :mod:`app.mcp.report_charts`."""

import sys

from app.mcp import report_charts as _implementation

sys.modules[__name__] = _implementation
