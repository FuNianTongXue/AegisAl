from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.agent.contracts import AgentExecution, AgentManifest
from app.mcp.protocol import call_mcp_tool
from app.privacy import public_answer_payload
from app.storage import now_iso


@dataclass
class AssistantAgentContext:
    question: str
    top_k: int
    user_id: str
    session_id: str
    response_language: str
    emoji_mode: str
    attachments: list[dict[str, Any]]
    workspace_path: str
    task_context: dict[str, Any]
    active_task: dict[str, Any]
    intent_plan: dict[str, Any]
    sbom_context: dict[str, Any]
    runtime_graph: Any
    memory: Any
    task_service: Any = None
    allow_task_creation: bool = False
    event_sink: Any = None
    content_sink: Any = None
    artifact_names: list[str] = field(default_factory=list)


class GraphSpecialistAgent:
    """Capability-scoped adapter around an existing, tested LangGraph subgraph path."""

    def __init__(self, manifest: AgentManifest, *, force_intent: str = "") -> None:
        self.manifest = manifest
        self._force_intent = force_intent

    def invoke(self, context: AssistantAgentContext) -> AgentExecution:
        intent_plan = dict(context.intent_plan)
        if self._force_intent:
            intent_plan["intent"] = self._force_intent
        if self.manifest.agent_id == "conversation_agent":
            # Preserve the knowledge graph's deterministic identity and clarification routes.
            intent_plan = {}
        if self.manifest.agent_id == "code_scan_agent" and not context.workspace_path:
            # Direct code attachments use the existing attachment analysis route.
            intent_plan = {}
        answer = context.runtime_graph.invoke(
            context.question,
            context.top_k,
            user_id=context.user_id,
            session_id=context.session_id,
            response_language=context.response_language,
            emoji_mode=context.emoji_mode,
            attachments=context.attachments,
            workspace_path=context.workspace_path,
            task_context=context.task_context,
            intent_plan=intent_plan,
            event_sink=context.event_sink,
            content_sink=context.content_sink,
        )
        return AgentExecution(
            agent_id=self.manifest.agent_id,
            status="waiting" if answer.get("interrupt") else "completed",
            answer=answer,
        )


class SBOMAgent(GraphSpecialistAgent):
    """Own SBOM generation, license inventory, and read-only SBOM result follow-up."""

    def invoke(self, context: AssistantAgentContext) -> AgentExecution:
        if context.intent_plan.get("intent") != "sbom_result_follow_up":
            return super().invoke(context)
        from app.langgraph.sbom_graph import project_sbom_subgraph, sbom_follow_up_answer

        operation = dict(context.sbom_context or {})
        thread_id = str(operation.get("threadId") or operation.get("thread_id") or "")
        if thread_id:
            try:
                operation = project_sbom_subgraph.inspect(thread_id, user_id=context.user_id)
            except KeyError:
                # Completed checkpoints are intentionally cleaned; encrypted snapshots remain valid.
                pass
        if not operation:
            answer = public_answer_payload(
                {
                    "mode": "sbom_context_required",
                    "summary": "当前用户没有可验证的 SBOM 结果上下文，请先为项目生成 SBOM 并选择是否匹配漏洞。",
                    "fields": {},
                    "artifacts": [],
                    "interrupt": None,
                    "confidence": 1.0,
                    "trace": [],
                    "generated_at": now_iso(),
                }
            )
        else:
            answer = public_answer_payload(sbom_follow_up_answer(operation, context.question))
        return AgentExecution(agent_id=self.manifest.agent_id, status="completed", answer=answer)


class SBOMLicenseCapability:
    """Capability-scoped license scanner owned by the SBOM Agent boundary."""

    def __init__(self, scanner: Any = None) -> None:
        self._scanner = scanner

    def identify_project_licenses(self, workspace_path: str, *, cancelled: Any = None) -> dict[str, Any]:
        cancel_check = cancelled or (lambda: False)
        if cancel_check():
            raise RuntimeError("License MCP call was cancelled")
        if self._scanner is not None:
            result = self._scanner(workspace_path)
        else:
            result = call_mcp_tool(
                agent_id="sbom_agent",
                tool_id="mcp__license_scan__identify_project_licenses",
                arguments={"workspace_path": workspace_path},
                cancelled=cancel_check,
            )
        if cancel_check():
            raise RuntimeError("License MCP call was cancelled")
        if not isinstance(result, dict):
            raise ValueError("SBOM Agent license capability returned no structured result")
        audit = result.get("_license_mcp") if isinstance(result.get("_license_mcp"), dict) else {}
        runtime_audit = result.get("_mcp_runtime") if isinstance(result.get("_mcp_runtime"), dict) else {}
        if audit:
            audit["agent_id"] = "sbom_agent"
            audit["transport"] = str(runtime_audit.get("transport") or "stdio")
            audit["endpoint"] = "managed-child-process"
            audit["host"] = runtime_audit
            result["_license_mcp"] = audit
        return result

    def shutdown(self) -> None:
        return None


class ProjectContextAgent:
    def __init__(self, manifest: AgentManifest) -> None:
        self.manifest = manifest

    def invoke(self, context: AssistantAgentContext) -> AgentExecution:
        from app.agent.project_context import resolve_project_workspace

        tasks = context.task_service.list(context.user_id, limit=100) if context.task_service is not None else []
        resolution = resolve_project_workspace(
            user_id=context.user_id,
            session_id=context.session_id,
            question=context.question,
            artifact_names=context.artifact_names,
            memory=context.memory,
            tasks=tasks,
        )
        if resolution["status"] == "available":
            next_agent = (
                "sbom_agent"
                if context.intent_plan.get("intent") == "project_sbom_export"
                else "code_scan_agent"
            )
            return AgentExecution(
                agent_id=self.manifest.agent_id,
                status="completed",
                next_agent=next_agent,
                metadata={"resolution": resolution},
            )

        answer = self._workspace_required_answer(context, resolution)
        try:
            context.memory.add_exchange(
                context.user_id,
                context.question,
                answer,
                session_id=context.session_id,
            )
        except Exception:  # noqa: BLE001 - recovery guidance must survive memory failures.
            pass
        return AgentExecution(
            agent_id=self.manifest.agent_id,
            status="completed",
            answer=answer,
            metadata={"resolution": resolution},
        )

    @staticmethod
    def _workspace_required_answer(
        context: AssistantAgentContext,
        resolution: dict[str, Any],
    ) -> dict[str, Any]:
        status = str(resolution.get("status") or "unavailable")
        project_name = str(resolution.get("project_name") or "原项目")
        if status == "stale":
            summary = (
                f"已找到 {project_name} 的历史项目关联，但原源码目录已移动、删除或当前不可读取。"
                "请将源码保留在本机可访问位置并重新选择原项目目录；确认源码后才能开始扫描。"
            )
        elif status == "ambiguous":
            summary = (
                "当前用户下有多个可能关联的源码项目，无法仅凭 SBOM 文件名安全确定扫描范围。"
                "请选择要扫描的项目目录，避免扫描错误项目。"
            )
        else:
            summary = (
                "当前会话只有 SBOM/报告等制品，没有可验证的源码工作区关联。"
                "请通过输入框左下角的文件按钮选择本机项目目录后再开始扫描。"
            )
        return public_answer_payload(
            {
                "mode": "project_workspace_required",
                "summary": summary,
                "fields": {
                    "扫描意图": "已识别",
                    "源码状态": {
                        "stale": "历史目录不可访问",
                        "ambiguous": "存在多个候选项目",
                    }.get(status, "未关联"),
                    "下一步": "重新选择本机源码目录",
                },
                "vulnerability_card": {},
                "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
                "chart_data": {},
                "artifacts": [],
                "confidence": 1.0,
                "trace": [],
                "generated_at": now_iso(),
            }
        )


class CodeScanAgent(GraphSpecialistAgent):
    def invoke(self, context: AssistantAgentContext) -> AgentExecution:
        intent = str(context.intent_plan.get("intent") or "")
        can_create = context.workspace_path and context.allow_task_creation and context.task_service is not None
        if can_create and intent in {"project_scan", "project_rescan"}:
            if intent == "project_rescan" and context.active_task.get("id"):
                task = context.task_service.rescan(
                    str(context.active_task["id"]),
                    objective=context.question,
                    user_id=context.user_id,
                    session_id=context.session_id,
                )
            else:
                task = context.task_service.create(
                    objective=context.question,
                    workspace_path=context.workspace_path,
                    user_id=context.user_id,
                    session_id=context.session_id,
                )
            project_name = str(task.get("workspace_name") or "项目")
            answer = {
                "mode": "project_scan",
                "summary": (
                    f"已由代码扫描 Agent 为 {project_name} 创建{'重新' if intent == 'project_rescan' else '完整'}扫描任务。"
                    "扫描将使用已验证源码工作区，并通过独立 Code Scan MCP stdio 子进程执行。"
                ),
                "fields": {
                    "项目": project_name,
                    "工作区状态": "已验证可访问",
                    "任务编号": str(task.get("id") or ""),
                    "任务状态": str(task.get("status") or "queued"),
                },
                "vulnerability_card": {},
                "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
                "chart_data": {},
                "artifacts": [],
                "agent_task": task,
                "confidence": float(context.intent_plan.get("confidence") or 1.0),
                "trace": [],
                "generated_at": now_iso(),
            }
            return AgentExecution(agent_id=self.manifest.agent_id, status="completed", answer=answer)
        return super().invoke(context)
