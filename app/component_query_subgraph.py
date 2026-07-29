"""Compatibility alias for :mod:`app.langgraph.component_query_graph`."""

import sys

from app.langgraph import component_query_graph as _implementation

sys.modules[__name__] = _implementation
