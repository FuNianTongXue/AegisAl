from __future__ import annotations

from copy import deepcopy
from typing import Any, TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # noqa: BLE001
    END = "__end__"
    StateGraph = None

from app.storage import now_iso, store


class CollectorState(TypedDict, total=False):
    collector_id: str
    years: list[int]
    max_results: int | None
    config: dict[str, Any]
    records: list[dict[str, Any]]
    errors: list[str]
    skip_reason: str
    inserted: int
    trace: list[dict[str, Any]]
    result: dict[str, Any]


class CollectorGraph:
    """Collection subgraph shared by API requests and assistant live retrieval."""

    def __init__(self, service: Any) -> None:
        self._service = service
        self._graph = self._build_graph()

    def invoke(
        self,
        collector_id: str,
        *,
        years: list[int] | None = None,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        state: CollectorState = {
            "collector_id": collector_id,
            "years": sorted(set(years or []), reverse=True),
            "max_results": max_results,
            "config": {},
            "records": [],
            "errors": [],
            "skip_reason": "",
            "inserted": 0,
            "trace": [],
            "result": {},
        }
        if self._graph is None:
            state = self._validate_config(state)
            if not state.get("skip_reason"):
                state = self._fetch_records(state)
                state = self._normalize_records(state)
                state = self._persist_records(state)
            state = self._compose_result(state)
            return state["result"]
        final = self._graph.invoke(state)
        return final["result"]

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Security Intelligence Collector Subgraph",
            "nodes": [
                {"id": "validate_config", "label": "校验采集配置"},
                {"id": "fetch_records", "label": "拉取情报记录"},
                {"id": "normalize_records", "label": "规范化与去重"},
                {"id": "persist_records", "label": "持久化知识记录"},
                {"id": "compose_result", "label": "汇总采集结果"},
            ],
            "edges": [
                {"source": "validate_config", "target": "fetch_records", "label": "配置可用"},
                {"source": "validate_config", "target": "compose_result", "label": "禁用或凭证缺失"},
                {"source": "fetch_records", "target": "normalize_records", "label": "完成拉取"},
                {"source": "normalize_records", "target": "persist_records", "label": "完成去重"},
                {"source": "persist_records", "target": "compose_result", "label": "完成写入"},
            ],
        }

    def _build_graph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(CollectorState)
        graph.add_node("validate_config", self._validate_config)
        graph.add_node("fetch_records", self._fetch_records)
        graph.add_node("normalize_records", self._normalize_records)
        graph.add_node("persist_records", self._persist_records)
        graph.add_node("compose_result", self._compose_result)
        graph.set_entry_point("validate_config")
        graph.add_conditional_edges(
            "validate_config",
            lambda state: "compose_result" if state.get("skip_reason") else "fetch_records",
            {"fetch_records": "fetch_records", "compose_result": "compose_result"},
        )
        graph.add_edge("fetch_records", "normalize_records")
        graph.add_edge("normalize_records", "persist_records")
        graph.add_edge("persist_records", "compose_result")
        graph.add_edge("compose_result", END)
        return graph.compile()

    def _validate_config(self, state: CollectorState) -> CollectorState:
        collector_id = state["collector_id"]
        config = store.read().get("collectors", {}).get(collector_id)
        if config is None:
            raise KeyError(collector_id)
        state["config"] = deepcopy(config)
        if not config.get("enabled", True):
            state["skip_reason"] = f"{config['name']} is disabled."
            return _add_trace(state, "validate_config", "采集器已禁用，跳过本次执行。", "warning")
        credential_error = self._service.credential_error(collector_id, config)
        if credential_error:
            state["skip_reason"] = credential_error
            return _add_trace(state, "validate_config", "采集凭证未就绪，跳过本次执行。", "warning")
        if state.get("years") and collector_id != "cve":
            state["skip_reason"] = "Year-filtered collection is only supported by the CVE collector."
            return _add_trace(state, "validate_config", "当前采集器不支持年份过滤。", "warning")
        return _add_trace(state, "validate_config", "采集配置与凭证校验通过。")

    def _fetch_records(self, state: CollectorState) -> CollectorState:
        config = state["config"]
        collector_id = state["collector_id"]
        years = state.get("years", [])
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        if years:
            limit = max(1, min(int(state.get("max_results") or 20), int(config.get("max_results", 20))))
            for year in years:
                try:
                    records.extend(self._service._collect_cve(config, year=year, max_results=limit))
                except Exception as exc:  # noqa: BLE001 - retain successful year windows.
                    errors.append(f"{year}: {exc}")
        else:
            try:
                if collector_id == "cve":
                    records = self._service._collect_cve(config, max_results=state.get("max_results"))
                elif collector_id == "github_advisory":
                    records = self._service._collect_github_advisory(config, max_results=state.get("max_results"))
                else:
                    raise KeyError(collector_id)
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
        state["records"] = records
        state["errors"] = errors
        status = "warning" if errors else "completed"
        message = f"已拉取 {len(records)} 条候选记录。"
        if errors:
            message += f" {len(errors)} 个请求窗口失败。"
        return _add_trace(state, "fetch_records", message, status)

    @staticmethod
    def _normalize_records(state: CollectorState) -> CollectorState:
        records: dict[str, dict[str, Any]] = {}
        for record in state.get("records", []):
            record_id = str(record.get("id") or "").strip()
            if record_id:
                records[record_id.lower()] = record
        normalized = sorted(records.values(), key=_record_sort_key, reverse=True)
        if state.get("max_results"):
            normalized = normalized[: max(1, int(state["max_results"] or 1))]
        state["records"] = normalized
        return _add_trace(state, "normalize_records", f"规范化后保留 {len(normalized)} 条唯一记录。")

    @staticmethod
    def _persist_records(state: CollectorState) -> CollectorState:
        persisted_state = store.read()
        collector_id = state["collector_id"]
        config = persisted_state["collectors"][collector_id]
        existing = {str(item.get("id", "")).lower(): item for item in persisted_state.get("records", [])}
        inserted = 0
        for record in state.get("records", []):
            key = str(record["id"]).lower()
            if key not in existing:
                persisted_state["records"].append(record)
                existing[key] = record
                inserted += 1
            else:
                existing[key].update(record)
        errors = state.get("errors", [])
        status = "success" if not errors else "warning" if state.get("records") else "failed"
        config["last_collect"] = {
            "status": status,
            "inserted": inserted,
            "fetched": len(state.get("records", [])),
            "years": state.get("years", []),
            "errors": errors,
            "checked_at": now_iso(),
        }
        store.write(persisted_state)
        state["inserted"] = inserted
        updated = len(state.get("records", [])) - inserted
        return _add_trace(state, "persist_records", f"新增 {inserted} 条，更新 {updated} 条记录。", status)

    @staticmethod
    def _compose_result(state: CollectorState) -> CollectorState:
        errors = state.get("errors", [])
        skip_reason = state.get("skip_reason", "")
        if skip_reason:
            status = "warning"
            message = skip_reason
        elif errors and not state.get("records"):
            status = "failed"
            message = "Collection failed: " + "; ".join(errors)
        elif errors:
            status = "warning"
            message = f"Collection completed with {len(errors)} failed request window(s)."
        else:
            status = "success"
            message = f"{state['config']['name']} collection finished."
        state = _add_trace(state, "compose_result", "采集执行结果已汇总。", status)
        state["result"] = {
            "status": status,
            "message": message,
            "inserted": state.get("inserted", 0),
            "fetched": len(state.get("records", [])),
            "records": state.get("records", []),
            "years": state.get("years", []),
            "errors": errors,
            "trace": state.get("trace", []),
        }
        return state


def _add_trace(state: CollectorState, node: str, message: str, status: str = "completed") -> CollectorState:
    state.setdefault("trace", []).append({"node": node, "message": message, "status": status, "time": now_iso()})
    return state


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str]:
    return (
        str(record.get("published_at") or record.get("updated_at") or ""),
        str(record.get("id") or ""),
    )
