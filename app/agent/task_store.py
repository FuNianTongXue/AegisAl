from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from cryptography.exceptions import InvalidTag

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text
from app.storage import DATA_DIR, now_iso


TASK_STORE_PURPOSE = "secflow-agent-tasks"


class AgentTaskStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (DATA_DIR / "tasks" / "tasks.json")
        self._lock = RLock()

    def create(self, task: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            state = self._read()
            state["tasks"].insert(0, deepcopy(task))
            state["tasks"] = state["tasks"][:100]
            self._write(state)
            return deepcopy(task)

    def get(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._find(self._read(), task_id)
            return deepcopy(task)

    def list(
        self,
        user_id: str,
        limit: int = 30,
        *,
        archived: bool = False,
    ) -> list[dict[str, Any]]:
        with self._lock:
            tasks = [
                deepcopy(task)
                for task in self._read()["tasks"]
                if str(task.get("user_id") or "default") == (user_id or "default")
                and bool(task.get("archived", False)) is archived
            ]
            return tasks[: max(1, min(limit, 100))]

    def delete(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            state = self._read()
            for index, task in enumerate(state["tasks"]):
                if str(task.get("id") or "") == task_id:
                    removed = state["tasks"].pop(index)
                    self._write(state)
                    return deepcopy(removed)
            raise KeyError(task_id)

    def update(self, task_id: str, **changes: Any) -> dict[str, Any]:
        return self.mutate(task_id, lambda task: task.update(changes))

    def mutate(
        self,
        task_id: str,
        mutation: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        with self._lock:
            state = self._read()
            task = self._find(state, task_id)
            mutation(task)
            task["updated_at"] = now_iso()
            self._write(state)
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
        def append(task: dict[str, Any]) -> None:
            events = task.setdefault("events", [])
            sequence = int(events[-1].get("sequence") or 0) + 1 if events else 1
            events.append(
                {
                    "sequence": sequence,
                    "type": event_type,
                    "node": node,
                    "status": status,
                    "message": message,
                    "data": deepcopy(data or {}),
                    "time": now_iso(),
                }
            )
            task["events"] = events[-500:]
            if not event_type.startswith("report."):
                task["current_node"] = node

        return self.mutate(task_id, append)

    def recover_interrupted(self) -> None:
        with self._lock:
            state = self._read()
            changed = False
            for task in state["tasks"]:
                if task.get("status") in {"queued", "running", "cancelling"}:
                    task["status"] = "interrupted"
                    task["report_ready"] = False
                    task["error"] = "应用上次退出时任务尚未完成，可重新运行该任务。"
                    task["updated_at"] = now_iso()
                    changed = True
            if changed:
                self._write(state)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "tasks": []}
        try:
            raw = self.path.read_text(encoding="utf-8")
            state = decrypt_json_from_text(raw, TASK_STORE_PURPOSE)
            if not isinstance(state, dict) or not isinstance(state.get("tasks"), list):
                raise ValueError("invalid task store")
            return state
        except (InvalidTag, json.JSONDecodeError, OSError, ValueError):
            return {"version": 1, "tasks": []}

    def _write(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            encrypt_json_to_text(state, TASK_STORE_PURPOSE, compact=True),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)

    @staticmethod
    def _find(state: dict[str, Any], task_id: str) -> dict[str, Any]:
        for task in state["tasks"]:
            if str(task.get("id") or "") == task_id:
                return task
        raise KeyError(task_id)
