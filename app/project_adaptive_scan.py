"""Compatibility alias for :mod:`app.agent.project_adaptive_scan`."""

import sys

from app.agent import project_adaptive_scan as _implementation

sys.modules[__name__] = _implementation
