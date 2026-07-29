"""Compatibility entry point for ``uvicorn app.main:app``."""

import sys

from app.api.routes import application as _implementation

sys.modules[__name__] = _implementation
