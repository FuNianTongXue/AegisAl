from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from cryptography.exceptions import InvalidTag

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text
from app.storage import DATA_DIR, now_iso


TASK_STORE_PURPOSE = "secflow-agent-tasks"
TASK_RECORD_PURPOSE = "secflow-agent-task-record"
TASK_EVENT_PURPOSE = "secflow-agent-task-event"
TASK_EVENT_RETENTION = 500
TASK_JOB_TERMINAL_STATES = {"completed", "failed", "cancelled"}


def clear_cancelled_task_data(task: dict[str, Any]) -> None:
    """Remove partial scan/report state while retaining task identity and audit events."""

    task.update(
        current_node="cancel",
        languages=[],
        plan=[],
        result=None,
        report_ready=False,
        report_decision="unavailable",
        report=None,
        report_interrupt=None,
        report_thread_id=None,
        report_download_artifact=None,
        report_orchestration=None,
        workspace_fingerprint=None,
        ruleset_fingerprint=None,
        engine_fingerprint=None,
    )


class AgentTaskStore:
    def __init__(self, path: Path | None = None) -> None:
        configured_path = os.getenv("SECFLOW_TASK_STORE_PATH", "").strip()
        configured = path or (Path(configured_path) if configured_path else DATA_DIR / "tasks" / "tasks.sqlite3")
        if configured.suffix.casefold() == ".json":
            self.legacy_path = configured
            self.path = configured.with_suffix(".sqlite3")
        else:
            self.path = configured
            self.legacy_path = configured.with_suffix(".json")
        self._lock = RLock()
        self._initialize()
        self._migrate_legacy_json()

    def create(self, task: dict[str, Any]) -> dict[str, Any]:
        value = deepcopy(task)
        events = list(value.pop("events", []) or [])
        task_id = str(value.get("id") or "")
        if not task_id:
            raise ValueError("task id is required")
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._insert_task(connection, value)
            for event in events:
                if isinstance(event, dict):
                    self._insert_event(connection, task_id, event)
        value["events"] = events[-TASK_EVENT_RETENTION:]
        return value

    def get(self, task_id: str, *, include_events: bool = True) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            return deepcopy(self._load_task(connection, task_id, include_events=include_events))

    def list(
        self,
        user_id: str,
        limit: int = 30,
        *,
        archived: bool = False,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(limit, 100))
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, payload
                FROM tasks
                WHERE user_key = ? AND archived = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (self._user_key(user_id), int(archived), bounded_limit),
            ).fetchall()
            tasks: list[dict[str, Any]] = []
            for row in rows:
                task = self._decode_record(str(row["payload"]), TASK_RECORD_PURPOSE)
                if not isinstance(task, dict):
                    continue
                task["events"] = self._load_events(connection, str(row["id"]))
                tasks.append(task)
            return tasks

    def events(self, task_id: str, *, after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(limit, TASK_EVENT_RETENTION))
        with self._lock, self._connection() as connection:
            if connection.execute("SELECT 1 FROM tasks WHERE id = ?", (task_id,)).fetchone() is None:
                raise KeyError(task_id)
            return self._load_events(connection, task_id, after=max(0, after), limit=bounded_limit)

    def delete(self, task_id: str) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._load_task(connection, task_id, include_events=True)
            connection.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            return deepcopy(task)

    def update(self, task_id: str, **changes: Any) -> dict[str, Any]:
        return self.mutate(task_id, lambda task: task.update(changes))

    def mutate(
        self,
        task_id: str,
        mutation: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._load_task(connection, task_id, include_events=True)
            mutation(task)
            task["updated_at"] = now_iso()
            events = list(task.pop("events", []) or [])
            self._update_task(connection, task)
            task["events"] = events
            return deepcopy(task)

    def add_event(
        self,
        task_id: str,
        *,
        event_type: str,
        node: str,
        status: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._load_task(connection, task_id, include_events=False)
            row = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM task_events WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            sequence = int(row[0] if row else 0) + 1
            event = {
                "sequence": sequence,
                "type": event_type,
                "node": node,
                "status": status,
                "message": message,
                "data": deepcopy(data or {}),
                "time": now_iso(),
            }
            self._insert_event(connection, task_id, event)
            connection.execute(
                "DELETE FROM task_events WHERE task_id = ? AND sequence <= ?",
                (task_id, max(0, sequence - TASK_EVENT_RETENTION)),
            )
            if not event_type.startswith("report."):
                task["current_node"] = node
            task["updated_at"] = now_iso()
            self._update_task(connection, task)
            task["events"] = self._load_events(connection, task_id)
            return deepcopy(task)

    def enqueue(self, task_id: str, *, delay_seconds: float = 0.0) -> dict[str, Any]:
        """Persist a task for execution without assigning it to an API process."""

        timestamp = now_iso()
        available_at = time.time() + max(0.0, float(delay_seconds))
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM tasks WHERE id = ?", (task_id,)).fetchone() is None:
                raise KeyError(task_id)
            connection.execute(
                """
                INSERT INTO task_jobs(
                    task_id, state, available_at, lease_owner, lease_expires_at,
                    heartbeat_at, attempts, last_error, created_at, updated_at
                ) VALUES (?, 'queued', ?, '', 0, 0, 0, '', ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    state = 'queued', available_at = excluded.available_at,
                    lease_owner = '', lease_expires_at = 0, heartbeat_at = 0,
                    attempts = 0, last_error = '', updated_at = excluded.updated_at
                """,
                (task_id, available_at, timestamp, timestamp),
            )
            return self._load_job(connection, task_id)

    def claim(self, worker_id: str, *, lease_seconds: float = 30.0) -> dict[str, Any] | None:
        """Atomically lease the next available job to one worker process."""

        owner = worker_id.strip()
        if not owner:
            raise ValueError("worker id is required")
        now = time.time()
        lease_expires_at = now + max(5.0, float(lease_seconds))
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT job.task_id, job.attempts, job.state, job.lease_expires_at
                FROM task_jobs AS job
                JOIN tasks AS task ON task.id = job.task_id
                WHERE job.available_at <= ?
                  AND (
                    job.state = 'queued'
                    OR (job.state = 'leased' AND job.lease_expires_at <= ?)
                  )
                  AND task.status IN ('queued', 'running', 'cancelling')
                ORDER BY job.available_at ASC, job.rowid ASC
                LIMIT 1
                """,
                (now, now),
            ).fetchone()
            if row is None:
                return None
            task_id = str(row["task_id"])
            previous_state = str(row["state"])
            previous_attempts = int(row["attempts"] or 0)
            cursor = connection.execute(
                """
                UPDATE task_jobs
                SET state = 'leased', lease_owner = ?, lease_expires_at = ?,
                    heartbeat_at = ?, attempts = attempts + 1, updated_at = ?
                WHERE task_id = ?
                  AND (
                    state = 'queued'
                    OR (state = 'leased' AND lease_expires_at <= ?)
                  )
                """,
                (owner, lease_expires_at, now, now_iso(), task_id, now),
            )
            if cursor.rowcount != 1:
                return None
            job = self._load_job(connection, task_id)
            job["recovered"] = previous_state == "leased" or previous_attempts > 0
            return job

    def renew_lease(self, task_id: str, worker_id: str, *, lease_seconds: float = 30.0) -> bool:
        now = time.time()
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE task_jobs
                SET lease_expires_at = ?, heartbeat_at = ?, updated_at = ?
                WHERE task_id = ? AND state = 'leased' AND lease_owner = ?
                """,
                (
                    now + max(5.0, float(lease_seconds)),
                    now,
                    now_iso(),
                    task_id,
                    worker_id,
                ),
            )
            return cursor.rowcount == 1

    def finish_job(
        self,
        task_id: str,
        worker_id: str,
        *,
        state: str,
        error: str = "",
    ) -> dict[str, Any]:
        if state not in TASK_JOB_TERMINAL_STATES:
            raise ValueError(f"invalid terminal job state: {state}")
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE task_jobs
                SET state = ?, lease_owner = '', lease_expires_at = 0,
                    heartbeat_at = 0, last_error = ?, updated_at = ?
                WHERE task_id = ? AND state = 'leased' AND lease_owner = ?
                """,
                (state, error, now_iso(), task_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("task lease ownership was lost before completion")
            return self._load_job(connection, task_id)

    def cancel_queued_job(self, task_id: str) -> bool:
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE task_jobs
                SET state = 'cancelled', lease_owner = '', lease_expires_at = 0,
                    heartbeat_at = 0, updated_at = ?
                WHERE task_id = ? AND state = 'queued'
                """,
                (now_iso(), task_id),
            )
            return cursor.rowcount == 1

    def job(self, task_id: str) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            return deepcopy(self._load_job(connection, task_id))

    def has_runnable_jobs(self) -> bool:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM task_jobs AS job
                JOIN tasks AS task ON task.id = job.task_id
                WHERE job.state IN ('queued', 'leased')
                  AND task.status IN ('queued', 'running', 'cancelling')
                LIMIT 1
                """
            ).fetchone()
            return row is not None

    def reconcile_pending_jobs(self) -> list[str]:
        """Requeue active tasks whose worker lease disappeared or expired."""

        recovered: list[str] = []
        now = time.time()
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT id, payload FROM tasks WHERE status IN ('queued', 'running', 'cancelling')"
            ).fetchall()
            for row in rows:
                task_id = str(row["id"])
                task = self._decode_record(str(row["payload"]), TASK_RECORD_PURPOSE)
                if not isinstance(task, dict):
                    continue
                job = connection.execute(
                    "SELECT state, lease_expires_at FROM task_jobs WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
                if str(task.get("status") or "") == "cancelling":
                    lease_expired = (
                        job is not None
                        and str(job["state"]) == "leased"
                        and float(job["lease_expires_at"] or 0) <= now
                    )
                    if job is None or str(job["state"]) != "leased" or lease_expired:
                        clear_cancelled_task_data(task)
                        task["status"] = "cancelled"
                        task["error"] = "任务已在恢复阶段完成取消。"
                        task["updated_at"] = now_iso()
                        self._update_task(connection, task)
                        if job is not None:
                            connection.execute(
                                "UPDATE task_jobs SET state = 'cancelled', updated_at = ? WHERE task_id = ?",
                                (now_iso(), task_id),
                            )
                    continue
                lease_expired = (
                    job is not None
                    and str(job["state"]) == "leased"
                    and float(job["lease_expires_at"] or 0) <= now
                )
                if job is not None and not lease_expired:
                    continue
                timestamp = now_iso()
                connection.execute(
                    """
                    INSERT INTO task_jobs(
                        task_id, state, available_at, lease_owner, lease_expires_at,
                        heartbeat_at, attempts, last_error, created_at, updated_at
                    ) VALUES (?, 'queued', ?, '', 0, 0, 0, '', ?, ?)
                    ON CONFLICT(task_id) DO UPDATE SET
                        state = 'queued', available_at = excluded.available_at,
                        lease_owner = '', lease_expires_at = 0, heartbeat_at = 0,
                        updated_at = excluded.updated_at
                    """,
                    (task_id, now, timestamp, timestamp),
                )
                task["status"] = "queued"
                task["report_ready"] = False
                task["error"] = ""
                task["updated_at"] = timestamp
                self._update_task(connection, task)
                recovered.append(task_id)
        return recovered

    def recover_interrupted(self) -> None:
        """Compatibility alias for the durable queue recovery introduced in schema v3."""

        self.reconcile_pending_jobs()

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS task_store_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    user_key TEXT NOT NULL,
                    archived INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_user_archived_created
                    ON tasks(user_key, archived, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
                CREATE TABLE IF NOT EXISTS task_events (
                    task_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL,
                    PRIMARY KEY(task_id, sequence),
                    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_task_events_task_sequence
                    ON task_events(task_id, sequence);
                CREATE TABLE IF NOT EXISTS task_jobs (
                    task_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL DEFAULT 'queued',
                    available_at REAL NOT NULL DEFAULT 0,
                    lease_owner TEXT NOT NULL DEFAULT '',
                    lease_expires_at REAL NOT NULL DEFAULT 0,
                    heartbeat_at REAL NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_task_jobs_claim
                    ON task_jobs(state, available_at, lease_expires_at);
                """
            )
            connection.execute(
                "INSERT OR REPLACE INTO task_store_metadata(key, value) VALUES ('schema_version', '3')"
            )

    def _migrate_legacy_json(self) -> None:
        if not self.legacy_path.is_file():
            return
        with self._lock, self._connection() as connection:
            migrated = connection.execute(
                "SELECT value FROM task_store_metadata WHERE key = 'legacy_json_migrated'"
            ).fetchone()
            if migrated is not None:
                return
            try:
                decoded = decrypt_json_from_text(
                    self.legacy_path.read_text(encoding="utf-8"),
                    TASK_STORE_PURPOSE,
                )
            except (InvalidTag, json.JSONDecodeError, OSError, ValueError):
                decoded = {"tasks": []}
            tasks = decoded.get("tasks") if isinstance(decoded, dict) else []
            connection.execute("BEGIN IMMEDIATE")
            for raw_task in tasks if isinstance(tasks, list) else []:
                if not isinstance(raw_task, dict) or not str(raw_task.get("id") or ""):
                    continue
                task = deepcopy(raw_task)
                events = list(task.pop("events", []) or [])
                self._insert_task(connection, task, ignore_existing=True)
                for event in events[-TASK_EVENT_RETENTION:]:
                    if isinstance(event, dict):
                        self._insert_event(connection, str(task["id"]), event, ignore_existing=True)
            connection.execute(
                "INSERT OR REPLACE INTO task_store_metadata(key, value) VALUES ('legacy_json_migrated', ?)",
                (now_iso(),),
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=15000")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _insert_task(
        self,
        connection: sqlite3.Connection,
        task: dict[str, Any],
        *,
        ignore_existing: bool = False,
    ) -> None:
        task_id = str(task.get("id") or "")
        statement = "INSERT OR IGNORE" if ignore_existing else "INSERT"
        connection.execute(
            f"""
            {statement} INTO tasks(id, user_key, archived, status, created_at, updated_at, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            self._task_row(task_id, task),
        )

    def _update_task(self, connection: sqlite3.Connection, task: dict[str, Any]) -> None:
        task_id = str(task.get("id") or "")
        values = self._task_row(task_id, task)
        cursor = connection.execute(
            """
            UPDATE tasks
            SET user_key = ?, archived = ?, status = ?, created_at = ?, updated_at = ?, payload = ?
            WHERE id = ?
            """,
            (*values[1:], values[0]),
        )
        if cursor.rowcount != 1:
            raise KeyError(task_id)

    def _task_row(self, task_id: str, task: dict[str, Any]) -> tuple[Any, ...]:
        value = deepcopy(task)
        value.pop("events", None)
        return (
            task_id,
            self._user_key(str(value.get("user_id") or "default")),
            int(bool(value.get("archived", False))),
            str(value.get("status") or ""),
            str(value.get("created_at") or ""),
            str(value.get("updated_at") or ""),
            encrypt_json_to_text(value, TASK_RECORD_PURPOSE, compact=True),
        )

    def _load_task(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        *,
        include_events: bool,
    ) -> dict[str, Any]:
        row = connection.execute("SELECT payload FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(task_id)
        task = self._decode_record(str(row["payload"]), TASK_RECORD_PURPOSE)
        if not isinstance(task, dict):
            raise KeyError(task_id)
        task["events"] = self._load_events(connection, task_id) if include_events else []
        return task

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        event: dict[str, Any],
        *,
        ignore_existing: bool = False,
    ) -> None:
        sequence = max(1, int(event.get("sequence") or 1))
        value = {**deepcopy(event), "sequence": sequence}
        statement = "INSERT OR IGNORE" if ignore_existing else "INSERT"
        connection.execute(
            f"""
            {statement} INTO task_events(task_id, sequence, event_type, created_at, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                task_id,
                sequence,
                str(value.get("type") or ""),
                str(value.get("time") or ""),
                encrypt_json_to_text(value, TASK_EVENT_PURPOSE, compact=True),
            ),
        )

    def _load_events(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        *,
        after: int = 0,
        limit: int = TASK_EVENT_RETENTION,
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT payload
            FROM task_events
            WHERE task_id = ? AND sequence > ?
            ORDER BY sequence ASC
            LIMIT ?
            """,
            (task_id, max(0, after), max(1, min(limit, TASK_EVENT_RETENTION))),
        ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            event = self._decode_record(str(row["payload"]), TASK_EVENT_PURPOSE)
            if isinstance(event, dict):
                events.append(event)
        return events

    @staticmethod
    def _load_job(connection: sqlite3.Connection, task_id: str) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT task_id, state, available_at, lease_owner, lease_expires_at,
                   heartbeat_at, attempts, last_error, created_at, updated_at
            FROM task_jobs
            WHERE task_id = ?
            """,
            (task_id,),
        ).fetchone()
        if row is None:
            raise KeyError(task_id)
        return {key: row[key] for key in row.keys()}

    @staticmethod
    def _decode_record(payload: str, purpose: str) -> Any:
        try:
            return decrypt_json_from_text(payload, purpose)
        except (InvalidTag, json.JSONDecodeError, OSError, ValueError):
            return None

    @staticmethod
    def _user_key(user_id: str) -> str:
        normalized = user_id or "default"
        return hashlib.sha256(f"secflow-task-user:{normalized}".encode("utf-8")).hexdigest()
