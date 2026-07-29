from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import assistant_app
from app.api.routes import assistant as assistant_routes


class FakeKnowledgeGraph:
    @staticmethod
    def graph_spec() -> dict:
        return {"name": "standalone-test", "nodes": [], "edges": []}

    def invoke(self, _question, _top_k, **kwargs):
        sink = kwargs.get("event_sink")
        trace = {
            "node": "compose_answer",
            "status": "completed",
            "message": "已生成最终回答。",
            "time": "2026-07-29T10:00:00+00:00",
        }
        if sink is not None:
            sink(trace)
        return {
            "mode": "llm_direct",
            "summary": "独立智能问答响应",
            "fields": {},
            "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
            "confidence": 1.0,
            "trace": [trace],
            "generated_at": "2026-07-29T10:00:00+00:00",
        }


class StandaloneAssistantModuleTests(unittest.TestCase):
    def test_standalone_app_exposes_only_assistant_contract(self) -> None:
        paths = set(assistant_app.app.openapi()["paths"])

        self.assertIn("/api/assistant/questions", paths)
        self.assertIn("/api/assistant/questions/stream", paths)
        self.assertIn("/api/assistant/interrupts/resume", paths)
        self.assertIn("/api/assistant/conversations", paths)
        self.assertNotIn("/api/agent/tasks", paths)
        self.assertNotIn("/api/subscriptions", paths)

    def test_question_and_graph_use_the_standalone_router(self) -> None:
        with patch.object(assistant_routes, "knowledge_graph", FakeKnowledgeGraph()), TestClient(
            assistant_app.app
        ) as client:
            graph = client.get("/api/assistant/graph")
            response = client.post(
                "/api/assistant/questions",
                json={
                    "question": "介绍一下当前能力",
                    "top_k": 5,
                    "user_id": "tester",
                    "session_id": "standalone-session",
                    "response_language": "zh-Hans",
                    "attachments": [],
                },
            )

        self.assertEqual(graph.status_code, 200, graph.text)
        self.assertEqual(graph.json()["data"]["name"], "standalone-test")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["summary"], "独立智能问答响应")

    def test_stream_preserves_trace_content_and_result_order(self) -> None:
        with patch.object(assistant_routes, "knowledge_graph", FakeKnowledgeGraph()), TestClient(
            assistant_app.app
        ) as client:
            response = client.post(
                "/api/assistant/questions/stream",
                json={
                    "question": "流式回答",
                    "top_k": 5,
                    "user_id": "tester",
                    "session_id": "standalone-stream",
                    "response_language": "zh-Hans",
                    "attachments": [],
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertLess(response.text.index("event: trace"), response.text.index("event: content"))
        self.assertLess(response.text.index("event: content"), response.text.index("event: result"))
        content = response.text.split("event: content\ndata: ", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(json.loads(content)["delta"], "独立智能问答响应")


if __name__ == "__main__":
    unittest.main()
