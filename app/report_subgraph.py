"""Compatibility alias for :mod:`app.langgraph.report_graph`."""

import sys

from app.langgraph import report_graph as _implementation

sys.modules[__name__] = _implementation
