"""Compatibility alias for :mod:`app.agent.task_agent`."""

import sys

from app.agent import task_agent as _implementation

sys.modules[__name__] = _implementation
