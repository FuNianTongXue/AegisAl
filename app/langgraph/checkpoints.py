from __future__ import annotations

import atexit
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver

from app.storage import DATA_DIR


class InterruptStateExpiredError(KeyError):
    """The client refers to an interrupt whose durable checkpoint no longer exists."""


class InterruptStateConflictError(ValueError):
    """The client refers to an older interrupt in a thread that has already advanced."""


_connections: list[sqlite3.Connection] = []
_connection_lock = RLock()
_event_sinks: dict[str, Any] = {}


def persistent_checkpointer(name: str) -> SqliteSaver:
    """Create a process-safe local checkpointer for user-confirmed LangGraph work."""

    directory = DATA_DIR / "langgraph"
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / f"{name}.sqlite3"
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    with _connection_lock:
        _connections.append(connection)
    return SqliteSaver(connection)


def authorize_pending_interrupt(
    graph: Any,
    config: dict[str, Any],
    *,
    expected_owner: tuple[str, str] | None,
    actual_owner: tuple[str, str],
    interrupt_id: str = "",
) -> tuple[str, str]:
    """Authorize a pending interrupt, recovering its owner from a durable checkpoint."""

    snapshot = graph.get_state(config)
    values = snapshot.values if isinstance(snapshot.values, dict) else {}
    recovered_owner = (
        str(values.get("user_id") or "default").strip() or "default",
        str(values.get("session_id") or "default").strip() or "default",
    )
    if not snapshot.next:
        raise InterruptStateExpiredError(str(config.get("configurable", {}).get("thread_id") or ""))
    owner = expected_owner or recovered_owner
    if owner != actual_owner:
        raise KeyError(str(config.get("configurable", {}).get("thread_id") or ""))

    current_ids = {
        str(item.id)
        for task in snapshot.tasks
        for item in (getattr(task, "interrupts", ()) or ())
    }
    clean_interrupt_id = str(interrupt_id or "").strip()
    if clean_interrupt_id and clean_interrupt_id not in current_ids:
        raise InterruptStateConflictError(clean_interrupt_id)
    return owner


def delete_checkpoint_thread(checkpointer: Any, thread_id: str) -> None:
    try:
        checkpointer.delete_thread(thread_id)
    except Exception:  # pragma: no cover - cleanup must not hide a completed result.
        pass


def register_event_sink(thread_id: str, sink: Any) -> None:
    if not callable(sink):
        return
    with _connection_lock:
        _event_sinks[thread_id] = sink


def emit_transient_event(thread_id: str, item: dict[str, Any]) -> None:
    with _connection_lock:
        sink = _event_sinks.get(thread_id)
    if sink is None:
        return
    try:
        sink(dict(item))
    except Exception:  # noqa: BLE001 - UI streaming must not break graph execution.
        pass


def unregister_event_sink(thread_id: str) -> None:
    with _connection_lock:
        _event_sinks.pop(thread_id, None)


@atexit.register
def _close_connections() -> None:
    with _connection_lock:
        connections = list(_connections)
        _connections.clear()
    for connection in connections:
        try:
            connection.close()
        except sqlite3.Error:
            pass
