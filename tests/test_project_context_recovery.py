from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app.agent.assistant_service import invoke_assistant_question
from app.agent.project_context import resolve_project_workspace
from app.langgraph.assistant_graph import KnowledgeSecurityGraph
from app.memory import LongTermMemoryService
from app.models import AskRequest


class ProjectContextRecoveryTests(unittest.TestCase):
    def test_sbom_artifact_resolves_only_the_linked_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            kafka = root / "kafka-4.3.1-src"
            other = root / "kafka-sandbox"
            kafka.mkdir()
            other.mkdir()
            memory = LongTermMemoryService(root / "memory.json")
            memory.local_only = True
            memory.remember_project_link(
                "user-a",
                "old-session",
                project_name=kafka.name,
                workspace_path=str(kafka),
                artifact_names=["SecFlow-kafka-4.3.1-src-SBOM.xlsx"],
            )
            memory.remember_project_link(
                "user-a",
                "other-session",
                project_name=other.name,
                workspace_path=str(other),
                artifact_names=["SecFlow-kafka-sandbox-SBOM.xlsx"],
            )

            resolution = resolve_project_workspace(
                user_id="user-a",
                session_id="new-session",
                question="扫描这个项目的代码漏洞",
                artifact_names=["SecFlow-kafka-4.3.1-src-SBOM.xlsx"],
                memory=memory,
                tasks=[],
            )

        self.assertEqual(resolution["status"], "available")
        self.assertEqual(resolution["workspace_path"], str(kafka.resolve()))
        self.assertEqual(resolution["source"], "project_link")

    def test_deleted_workspace_is_not_returned_as_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "moved-project"
            workspace.mkdir()
            memory = LongTermMemoryService(root / "memory.json")
            memory.local_only = True
            memory.remember_project_link(
                "user-a",
                "session-a",
                project_name=workspace.name,
                workspace_path=str(workspace),
                artifact_names=["SecFlow-moved-project-SBOM.xlsx"],
            )
            workspace.rmdir()

            resolution = resolve_project_workspace(
                user_id="user-a",
                session_id="session-a",
                question="我想做代码漏洞的扫描",
                artifact_names=[],
                memory=memory,
                tasks=[],
            )

            link = memory.list_project_links("user-a", session_id="session-a")[0]

        self.assertEqual(resolution["status"], "stale")
        self.assertEqual(resolution["workspace_path"], "")
        self.assertEqual(link["availability"], "unavailable")

    def test_project_links_are_strictly_isolated_by_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "private-project"
            workspace.mkdir()
            memory = LongTermMemoryService(root / "memory.json")
            memory.local_only = True
            memory.remember_project_link(
                "owner",
                "session-a",
                project_name=workspace.name,
                workspace_path=str(workspace),
                artifact_names=["SecFlow-private-project-SBOM.xlsx"],
            )

            resolution = resolve_project_workspace(
                user_id="other-user",
                session_id="session-a",
                question="请扫描这个项目",
                artifact_names=["SecFlow-private-project-SBOM.xlsx"],
                memory=memory,
                tasks=[],
            )

        self.assertEqual(resolution["status"], "unavailable")
        self.assertEqual(resolution["workspace_path"], "")

    def test_unrelated_single_project_is_not_selected_for_named_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "apache-commons-codec"
            workspace.mkdir()
            memory = LongTermMemoryService(Path(temp_dir) / "memory.json")
            memory.local_only = True

            resolution = resolve_project_workspace(
                user_id="user-a",
                session_id="new-session",
                question="扫描这个项目",
                artifact_names=["SecFlow-kafka-4.3.1-src-SBOM.xlsx"],
                memory=memory,
                tasks=[
                    {
                        "id": "task-apache",
                        "user_id": "user-a",
                        "session_id": "old-session",
                        "workspace_name": workspace.name,
                        "workspace_path": str(workspace),
                    }
                ],
            )

        self.assertEqual(resolution["status"], "unavailable")
        self.assertEqual(resolution["workspace_path"], "")

    def test_scan_intent_starts_task_after_workspace_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "kafka-4.3.1-src"
            workspace.mkdir()
            memory = LongTermMemoryService(root / "memory.json")
            memory.local_only = True
            memory.remember_project_link(
                "user-a",
                "session-a",
                project_name=workspace.name,
                workspace_path=str(workspace),
                artifact_names=["SecFlow-kafka-4.3.1-src-SBOM.xlsx"],
            )
            payload = AskRequest(
                question="我想做代码漏洞的扫描",
                user_id="user-a",
                session_id="session-a",
            )
            task = {
                "id": "task-recovered",
                "objective": payload.question,
                "workspace_path": str(workspace),
                "workspace_name": workspace.name,
                "workspace_type": "directory",
                "user_id": "user-a",
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
                "archived": False,
                "archived_at": None,
                "created_at": "2026-07-30T10:00:00+08:00",
                "updated_at": "2026-07-30T10:00:00+08:00",
            }
            plan = {
                "intent": "project_scan",
                "reason": "用户要求执行代码漏洞扫描",
                "confidence": 0.98,
            }
            graph = Mock()
            with (
                patch("app.agent.assistant_service.memory_service", memory),
                patch("app.agent.assistant_service.heuristic_intent_plan", return_value=plan),
                patch("app.agent.assistant_service.plan_assistant_intent", return_value=plan),
                patch("app.agent.task_agent.task_agent_service.list", return_value=[]),
                patch("app.agent.task_agent.task_agent_service.create", return_value=task) as create,
            ):
                answer = invoke_assistant_question(
                    payload,
                    graph=graph,
                    allow_workspace_recovery=True,
                )

        self.assertEqual(answer["mode"], "project_scan")
        self.assertEqual(answer["agent_task"]["id"], "task-recovered")
        self.assertEqual(answer["fields"]["工作区状态"], "已验证可访问")
        create.assert_called_once_with(
            objective=payload.question,
            workspace_path=str(workspace.resolve()),
            user_id="user-a",
            session_id="session-a",
        )
        graph.invoke.assert_not_called()

    def test_workspace_answer_submission_binds_session_project_for_follow_up(self) -> None:
        """随消息提交项目的纯问答（不创建任务）也必须绑定会话项目。

        项目 chip 改为跟随发送消耗后，后续消息不再重复携带 workspace_path；
        若问答提交不写入 project_link，后续无附件消息将无法恢复该项目。
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "log4shell-demo"
            workspace.mkdir()
            memory = LongTermMemoryService(root / "memory.json")
            memory.local_only = True
            graph = KnowledgeSecurityGraph()
            state = {
                "question": "这个项目是做什么的",
                "user_id": "user-a",
                "session_id": "session-qa",
                "workspace_path": str(workspace),
                "artifacts": [],
                "intent": "security_knowledge",
                "answer": {"mode": "security_knowledge", "summary": "这是一个演示项目。", "trace": []},
                "trace": [],
            }
            with patch("app.langgraph.assistant_graph.memory_service", memory):
                graph._persist_memory(state)  # noqa: SLF001 - 节点级回归测试

            resolution = resolve_project_workspace(
                user_id="user-a",
                session_id="session-qa",
                question="继续扫描它",
                artifact_names=[],
                memory=memory,
                tasks=[],
            )

        self.assertEqual(resolution["status"], "available")
        self.assertTrue(resolution["workspace_path"].endswith("log4shell-demo"))
        self.assertEqual(resolution["source"], "project_link")

    def test_follow_up_without_workspace_prefers_the_current_session_project(self) -> None:
        """多个历史项目并存时，无附件跟进必须优先恢复当前会话提交的项目。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            kafka = root / "kafka-4.3.1-src"
            kafka.mkdir()
            log4 = root / "log4shell-demo"
            log4.mkdir()
            memory = LongTermMemoryService(root / "memory.json")
            memory.local_only = True
            memory.remember_project_link(
                "user-a",
                "session-old",
                project_name="kafka-4.3.1-src",
                workspace_path=str(kafka),
            )
            memory.remember_project_link(
                "user-a",
                "session-new",
                project_name="log4shell-demo",
                workspace_path=str(log4),
            )

            resolution = resolve_project_workspace(
                user_id="user-a",
                session_id="session-new",
                question="继续扫描",
                artifact_names=[],
                memory=memory,
                tasks=[],
            )

        self.assertEqual(resolution["status"], "available")
        self.assertTrue(resolution["workspace_path"].endswith("log4shell-demo"))

    def test_follow_up_without_workspace_recovers_project_from_session_task(self) -> None:
        """project_link 缺失时（如记忆写入失败），同会话任务记录仍可恢复提交的项目。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            kafka = root / "kafka-4.3.1-src"
            kafka.mkdir()
            memory = LongTermMemoryService(root / "memory.json")
            memory.local_only = True
            tasks = [
                {
                    "user_id": "user-a",
                    "workspace_path": str(kafka),
                    "workspace_name": "kafka-4.3.1-src",
                    "session_id": "session-task",
                    "id": "task-session-bound",
                    "updated_at": "2026-08-01T10:00:00+08:00",
                }
            ]

            resolution = resolve_project_workspace(
                user_id="user-a",
                session_id="session-task",
                question="重新扫描",
                artifact_names=[],
                memory=memory,
                tasks=tasks,
            )

        self.assertEqual(resolution["status"], "available")
        self.assertTrue(resolution["workspace_path"].endswith("kafka-4.3.1-src"))
        self.assertEqual(resolution["task_id"], "task-session-bound")


if __name__ == "__main__":
    unittest.main()
