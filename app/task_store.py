"""Compatibility alias for :mod:`app.agent.task_store`."""

import sys

from app.agent import task_store as _implementation

sys.modules[__name__] = _implementation
