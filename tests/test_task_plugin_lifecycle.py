from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

from app.agent.task_agent import TaskAgentService
from app.agent.task_store import AgentTaskStore
from app.composition import RUNTIME_SCHEMA_VERSION, SecFlowRuntime
from app.storage import now_iso


class _LeaseInspectingGraph:
    def __init__(self, runtime: SecFlowRuntime) -> None:
        self.runtime = runtime
        self.invocations = 0

    def invoke(self, **_kwargs):
        self.invocations += 1
        records = self.runtime.manager._plugins
        assert records
        assert all(record.active_leases == 1 for record in records.values())
        return {
            "languages": [],
            "plan": [],
            "result": {"project_profile": {}},
        }


def _legacy_task(task_id: str, workspace: Path) -> dict:
    timestamp = now_iso()
    return {
        "id": task_id,
        "objective": "scan legacy task",
        "workspace_path": str(workspace),
        "workspace_name": workspace.name,
        "workspace_type": "directory",
        "user_id": "analyst",
        "session_id": f"agent-task:{task_id}",
        "status": "queued",
        "current_node": "queued",
        "languages": [],
        "plan": [],
        "events": [],
        "result": None,
        "report_ready": False,
        "report_decision": "unavailable",
        "report": None,
        "error": "",
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def test_new_task_persists_plugin_pin_and_holds_lease_during_graph(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = AgentTaskStore(tmp_path / "tasks.sqlite3")
    runtime = SecFlowRuntime()
    graph = _LeaseInspectingGraph(runtime)
    service = TaskAgentService(
        store,
        graph=graph,
        execution_mode="worker",
        plugin_runtime=runtime,
    )

    with patch.dict("os.environ", {"SECFLOW_STORAGE_MASTER_KEY": "task-plugin-pin-key"}):
        try:
            task = service.create(
                objective="scan project",
                workspace_path=str(workspace),
                user_id="analyst",
            )
            persisted = store.get(task["id"])
            assert persisted["plugin_state"] == task["plugin_state"]
            assert persisted["plugin_state"]["schema_version"] == RUNTIME_SCHEMA_VERSION

            with patch.object(
                runtime,
                "validate_task_pin",
                wraps=runtime.validate_task_pin,
            ) as validate:
                service._run(task["id"])

            assert validate.call_count == 1
            assert validate.call_args.kwargs["snapshot"].generation == task["plugin_state"][
                "runtime_generation"
            ]
            assert graph.invocations == 1
            assert store.get(task["id"])["status"] == "completed"
            assert all(
                record.active_leases == 0
                for record in runtime.manager._plugins.values()
            )
        finally:
            service.shutdown(wait=True)
            runtime.close(timeout=0.0)


def test_recovered_worker_rejects_plugin_generation_drift(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = AgentTaskStore(tmp_path / "tasks.sqlite3")
    runtime = SecFlowRuntime()
    graph = Mock()
    service = TaskAgentService(
        store,
        graph=graph,
        execution_mode="worker",
        plugin_runtime=runtime,
    )

    with patch.dict("os.environ", {"SECFLOW_STORAGE_MASTER_KEY": "task-plugin-drift-key"}):
        try:
            task = service.create(
                objective="scan project",
                workspace_path=str(workspace),
                user_id="analyst",
            )
            stale_pin = deepcopy(task["plugin_state"])
            plugin_id = next(iter(stale_pin["plugins"]))
            stale_pin["plugins"][plugin_id]["generation"] += 1
            store.update(task["id"], plugin_state=stale_pin)
            job = store.claim("worker-recovery")
            assert job is not None

            recovered = service.run_claimed(
                task["id"],
                "worker-recovery",
                recovered=True,
            )

            assert recovered["status"] == "failed"
            assert "Pinned task plugin changed" in recovered["error"]
            assert store.job(task["id"])["state"] == "failed"
            graph.invoke.assert_not_called()
            assert all(
                record.active_leases == 0
                for record in runtime.manager._plugins.values()
            )
            assert any(
                event["type"] == "task.recovered"
                for event in store.get(task["id"])["events"]
            )
        finally:
            service.shutdown(wait=True)
            runtime.close(timeout=0.0)


def test_legacy_task_is_pinned_before_recovered_graph_execution(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = AgentTaskStore(tmp_path / "tasks.sqlite3")
    runtime = SecFlowRuntime()
    graph = _LeaseInspectingGraph(runtime)
    service = TaskAgentService(
        store,
        graph=graph,
        execution_mode="worker",
        plugin_runtime=runtime,
    )
    task_id = "task-legacy-without-plugin-state"

    with patch.dict("os.environ", {"SECFLOW_STORAGE_MASTER_KEY": "task-plugin-legacy-key"}):
        try:
            store.create(_legacy_task(task_id, workspace))
            store.enqueue(task_id)
            job = store.claim("worker-legacy")
            assert job is not None

            recovered = service.run_claimed(
                task_id,
                "worker-legacy",
                recovered=True,
            )

            assert recovered["status"] == "completed"
            persisted = store.get(task_id)
            assert persisted["plugin_state"] == runtime.task_pin()
            assert graph.invocations == 1
            assert any(
                event["type"] == "task.plugin_state_migrated"
                for event in persisted["events"]
            )
        finally:
            service.shutdown(wait=True)
            runtime.close(timeout=0.0)
