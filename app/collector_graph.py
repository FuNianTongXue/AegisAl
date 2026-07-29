"""Compatibility alias for :mod:`app.langgraph.collector_graph`."""

import sys

from app.langgraph import collector_graph as _implementation

sys.modules[__name__] = _implementation
