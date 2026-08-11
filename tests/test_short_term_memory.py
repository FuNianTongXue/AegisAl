from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.langgraph.assistant_graph import KnowledgeSecurityGraph
from app.memory import LongTermMemoryService


def test_short_term_memory_is_session_scoped_and_not_persisted() -> None:
    with TemporaryDirectory() as temp_dir:
        service = LongTermMemoryService(Path(temp_dir) / "memory.json")
        service.add_exchange(
            "analyst",
            "长期问题",
            {"summary": "长期回答"},
            session_id="main-session",
        )
        service.add_short_term_exchange(
            "analyst",
            "information:one",
            "第一轮咨询",
            {"summary": "第一轮回答"},
        )
        service.add_short_term_exchange(
            "analyst",
            "information:two",
            "另一个咨询",
            {"summary": "另一个回答"},
        )

        context = service.build_short_term_context(
            "analyst",
            "information:one",
            "继续说明",
        )
        assert context["scope"] == "short-term"
        assert context["backend"] == "process-memory"
        assert "第一轮咨询" in context["promptContext"]
        assert "另一个咨询" not in context["promptContext"]
        assert "长期问题" not in context["promptContext"]
        assert len(service.get_history("analyst")) == 1

        cleared = service.clear_short_term_session("analyst", "information:one")
        assert cleared["cleared_turn_count"] == 1
        assert service.build_short_term_context("analyst", "information:one", "继续")["stats"]["recentCount"] == 0


def test_information_graph_writes_only_short_term_memory() -> None:
    with TemporaryDirectory() as temp_dir:
        service = LongTermMemoryService(Path(temp_dir) / "memory.json")
        with patch("app.langgraph.assistant_graph.memory_service", service):
            result = KnowledgeSecurityGraph().invoke(
                "你是谁",
                user_id="analyst",
                session_id="information:test-session",
            )

        assert result["summary"]
        assert service.get_history("analyst") == []
        context = service.build_short_term_context(
            "analyst",
            "information:test-session",
            "继续",
        )
        assert context["stats"]["recentCount"] == 1
        assert "你是谁" in context["promptContext"]


def test_information_consultation_returns_local_compliance_guidance_when_model_is_unavailable() -> None:
    with TemporaryDirectory() as temp_dir:
        service = LongTermMemoryService(Path(temp_dir) / "memory.json")
        with (
            patch("app.langgraph.assistant_graph.memory_service", service),
            patch(
                "app.langgraph.assistant_graph.active_model_from_env",
                return_value={"provider": "deepseek", "model": "deepseek-chat"},
            ),
            patch(
                "app.langgraph.assistant_graph.diagnose_chat_completion",
                return_value={"status": "failed", "message": "Insufficient Balance"},
            ),
        ):
            result = KnowledgeSecurityGraph().invoke(
                "金融业数据安全有哪些标准",
                user_id="analyst",
                session_id="information:compliance",
                intent_plan={"intent": "llm_direct", "confidence": 1.0},
            )

        assert "法律法规" in result["summary"]
        assert "等级保护与数据治理" in result["summary"]
        assert "Insufficient Balance" in result["summary"]
        assert service.get_history("analyst") == []
