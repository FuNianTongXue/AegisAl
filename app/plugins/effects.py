"""Deterministic effect ownership and disposal."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from threading import Condition, RLock

from .errors import EffectCleanupError, EffectScopeClosedError

Cleanup = Callable[[], object]


class EffectHandle:
    """A single idempotent cleanup callback."""

    def __init__(self, cleanup: Cleanup) -> None:
        if not callable(cleanup):
            raise TypeError("effect cleanup must be callable")
        self._cleanup = cleanup
        self._lock = RLock()
        self._disposed = False

    @property
    def disposed(self) -> bool:
        with self._lock:
            return self._disposed

    def dispose(self) -> None:
        with self._lock:
            if self._disposed:
                return
            self._disposed = True
        result = self._cleanup()
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise TypeError(
                "async effect cleanup is not supported by the synchronous plugin runtime"
            )

    __call__ = dispose


class EffectScope:
    """Owns effects and disposes every one in reverse registration order."""

    def __init__(self) -> None:
        self._condition = Condition(RLock())
        self._effects: list[EffectHandle] = []
        self._closing = False
        self._closed = False
        self._close_error: EffectCleanupError | None = None

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    def add(self, cleanup: Cleanup | EffectHandle) -> EffectHandle:
        handle = cleanup if isinstance(cleanup, EffectHandle) else EffectHandle(cleanup)
        with self._condition:
            if self._closing or self._closed:
                raise EffectScopeClosedError("effect scope is already closing")
            self._effects.append(handle)
        return handle

    defer = add

    def close(self) -> None:
        with self._condition:
            if self._closed:
                if self._close_error is not None:
                    raise self._close_error
                return
            if self._closing:
                self._condition.wait_for(lambda: self._closed)
                if self._close_error is not None:
                    raise self._close_error
                return
            self._closing = True
            effects = tuple(reversed(self._effects))
            self._effects.clear()

        failures: list[BaseException] = []
        for effect in effects:
            try:
                effect.dispose()
            except BaseException as exc:  # Cleanup must continue through every effect.
                failures.append(exc)

        error = EffectCleanupError(failures) if failures else None
        with self._condition:
            self._close_error = error
            self._closed = True
            self._closing = False
            self._condition.notify_all()
        if error is not None:
            raise error

    dispose = close

    def __enter__(self) -> EffectScope:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
