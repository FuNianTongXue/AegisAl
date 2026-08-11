from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.agent.task_agent import resolve_workspace_path
from app.memory import LongTermMemoryService


def resolve_project_workspace(
    *,
    user_id: str,
    session_id: str,
    question: str,
    artifact_names: list[str] | None,
    memory: LongTermMemoryService,
    tasks: list[dict[str, Any]],
) -> dict[str, Any]:
    """Resolve a user-owned project reference without deriving a path from display text."""

    owner = str(user_id or "default").strip() or "default"
    conversation = str(session_id or "default").strip() or "default"
    names = _unique_names([*(artifact_names or []), *_session_artifact_names(memory, owner, conversation)])
    name_keys = {_artifact_project_key(name) for name in names if _artifact_project_key(name)}
    question_key = _project_key(question)
    candidates: list[dict[str, Any]] = []

    for task in tasks:
        if str(task.get("user_id") or "default") != owner:
            continue
        candidates.append(
            {
                "workspace_path": str(task.get("workspace_path") or ""),
                "project_name": str(task.get("workspace_name") or ""),
                "session_id": str(task.get("session_id") or "default"),
                "task_id": str(task.get("id") or ""),
                "artifact_names": [],
                "updated_at": str(task.get("updated_at") or task.get("created_at") or ""),
                "source": "task",
            }
        )

    for link in memory.list_project_links(owner):
        candidates.append(
            {
                "workspace_path": str(link.get("workspacePath") or ""),
                "project_name": str(link.get("projectName") or ""),
                "session_id": str(link.get("sessionId") or "default"),
                "task_id": str(link.get("taskId") or ""),
                "artifact_names": list(link.get("artifactNames") or []),
                "updated_at": str(link.get("updatedAt") or ""),
                "source": "project_link",
            }
        )

    # Backward compatibility for project submissions created before projectLinks existed.
    for entry in memory.get_history(owner, limit=memory.max_history):
        if str(entry.get("mode") or "") != "project_submission":
            continue
        fields = entry.get("fields") if isinstance(entry.get("fields"), dict) else {}
        candidates.append(
            {
                "workspace_path": str(fields.get("项目路径") or ""),
                "project_name": str(fields.get("项目名称") or ""),
                "session_id": str(entry.get("sessionId") or "default"),
                "task_id": str(fields.get("任务编号") or ""),
                "artifact_names": [],
                "updated_at": str(entry.get("timestamp") or ""),
                "source": "legacy_project_memory",
            }
        )

    merged: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        workspace = candidate["workspace_path"].strip()
        if not workspace:
            continue
        previous = merged.get(workspace)
        if previous is None or candidate["updated_at"] > previous["updated_at"]:
            merged[workspace] = candidate
        elif candidate["session_id"] == conversation:
            previous["session_id"] = conversation
        previous_names = list((merged.get(workspace) or {}).get("artifact_names") or [])
        merged[workspace]["artifact_names"] = _unique_names([*previous_names, *candidate["artifact_names"]])

    accessible: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    for candidate in merged.values():
        try:
            workspace = resolve_workspace_path(candidate["workspace_path"], apply_limits=False)
        except ValueError:
            stale.append(candidate)
            if candidate["source"] == "project_link":
                memory.mark_project_link_availability(
                    owner,
                    candidate["session_id"],
                    candidate["workspace_path"],
                    available=False,
                )
            continue
        candidate["workspace_path"] = str(workspace)
        candidate["project_name"] = candidate["project_name"] or workspace.name
        candidate["score"] = _candidate_score(candidate, conversation, name_keys, question_key)
        accessible.append(candidate)
        if candidate["source"] == "project_link":
            memory.mark_project_link_availability(
                owner,
                candidate["session_id"],
                candidate["workspace_path"],
                available=True,
            )

    if not accessible:
        return {
            "status": "stale" if stale else "unavailable",
            "workspace_path": "",
            "project_name": _best_stale_name(stale, conversation, name_keys),
            "task_id": "",
            "source": "",
            "artifact_names": names,
        }

    ranked = sorted(
        accessible,
        key=lambda item: (int(item.get("score") or 0), str(item.get("updated_at") or "")),
        reverse=True,
    )
    if name_keys:
        artifact_matched = [item for item in ranked if bool(item.get("artifact_match"))]
        if artifact_matched:
            ranked = artifact_matched
        else:
            return {
                "status": "unavailable",
                "workspace_path": "",
                "project_name": "",
                "task_id": "",
                "source": "",
                "artifact_names": names,
            }
    best_score = int(ranked[0].get("score") or 0)
    top = [item for item in ranked if int(item.get("score") or 0) == best_score]
    if best_score <= 0 and len(ranked) != 1:
        return {
            "status": "ambiguous",
            "workspace_path": "",
            "project_name": "",
            "task_id": "",
            "source": "",
            "artifact_names": names,
        }
    if len(top) > 1 and len({item["workspace_path"] for item in top}) > 1:
        return {
            "status": "ambiguous",
            "workspace_path": "",
            "project_name": "",
            "task_id": "",
            "source": "",
            "artifact_names": names,
        }
    selected = top[0]
    return {
        "status": "available",
        "workspace_path": selected["workspace_path"],
        "project_name": selected["project_name"],
        "task_id": selected["task_id"],
        "source": selected["source"],
        "artifact_names": names,
    }


def _candidate_score(
    candidate: dict[str, Any],
    session_id: str,
    artifact_keys: set[str],
    question_key: str,
) -> int:
    score = 0
    project_key = _project_key(candidate.get("project_name") or Path(candidate["workspace_path"]).name)
    candidate_artifact_keys = {
        _artifact_project_key(name)
        for name in candidate.get("artifact_names") or []
        if _artifact_project_key(name)
    }
    artifact_match = bool(
        artifact_keys and (project_key in artifact_keys or bool(candidate_artifact_keys & artifact_keys))
    )
    candidate["artifact_match"] = artifact_match
    if candidate.get("session_id") == session_id:
        score += 500
    if artifact_match:
        score += 400
    if project_key and len(project_key) >= 4 and project_key in question_key:
        score += 200
    return score


def _session_artifact_names(memory: LongTermMemoryService, user_id: str, session_id: str) -> list[str]:
    names: list[str] = []
    for entry in memory.get_history(user_id, limit=memory.max_history):
        if str(entry.get("sessionId") or "default") != session_id:
            continue
        payload = entry.get("answerPayload") if isinstance(entry.get("answerPayload"), dict) else {}
        for artifact in payload.get("artifacts") or []:
            if isinstance(artifact, dict):
                names.append(str(artifact.get("file_name") or artifact.get("fileName") or ""))
    return _unique_names(names)


def _artifact_project_key(value: str) -> str:
    name = Path(str(value or "")).name
    name = re.sub(r"(?i)^secflow[-_ ]*", "", name)
    name = re.sub(r"(?i)[-_ ]*sbom(?:[-_ ].*)?\.xlsx$", "", name)
    return _project_key(name)


def _project_key(value: Any) -> str:
    return "".join(re.findall(r"[a-z0-9]+", str(value or "").casefold()))


def _unique_names(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        name = Path(str(value or "")).name.strip()
        if name and name not in output:
            output.append(name)
    return output[:100]


def _best_stale_name(
    candidates: list[dict[str, Any]],
    session_id: str,
    artifact_keys: set[str],
) -> str:
    if not candidates:
        return ""
    ranked = sorted(
        candidates,
        key=lambda item: (
            item.get("session_id") == session_id,
            _project_key(item.get("project_name")) in artifact_keys,
            str(item.get("updated_at") or ""),
        ),
        reverse=True,
    )
    return str(ranked[0].get("project_name") or "")


__all__ = ["resolve_project_workspace"]
