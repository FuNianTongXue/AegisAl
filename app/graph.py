"""Compatibility alias for :mod:`app.langgraph.assistant_graph`."""

import sys

from app.langgraph import assistant_graph as _implementation

sys.modules[__name__] = _implementation
