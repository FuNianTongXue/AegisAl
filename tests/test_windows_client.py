from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.windows_app import APP_TITLE, TRIAL_DURATION_HOURS, WindowsBridge


ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "app" / "static"


class WindowsClientTests(unittest.TestCase):
    def test_native_bridge_returns_selected_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "demo-project"
            workspace.mkdir()

            class FakeWindow:
                @staticmethod
                def create_file_dialog(dialog_type, *, allow_multiple):
                    self.assertEqual(dialog_type, "folder")
                    self.assertFalse(allow_multiple)
                    return (str(workspace),)

            bridge = WindowsBridge()
            bridge.bind_window(FakeWindow())
            with patch.dict(sys.modules, {"webview": SimpleNamespace(FOLDER_DIALOG="folder")}):
                selected = bridge.select_workspace()

        self.assertEqual(selected["path"], str(workspace.resolve()))
        self.assertEqual(selected["name"], "demo-project")

    def test_native_bridge_handles_cancel(self) -> None:
        class FakeWindow:
            @staticmethod
            def create_file_dialog(_dialog_type, *, allow_multiple):
                return None

        bridge = WindowsBridge()
        bridge.bind_window(FakeWindow())
        with patch.dict(sys.modules, {"webview": SimpleNamespace(FOLDER_DIALOG="folder")}):
            self.assertEqual(bridge.select_workspace(), {})

    def test_static_client_exposes_current_agent_workflows(self) -> None:
        html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        script = (STATIC_DIR / "app.js").read_text(encoding="utf-8")

        self.assertIn("7 天试用版", APP_TITLE)
        self.assertEqual(TRIAL_DURATION_HOURS, 168)
        self.assertNotIn("三天试用版", html + script)
        self.assertNotIn("采集控制台", html)
        self.assertIn("/api/assistant/workspace-actions", script)
        self.assertIn("/api/assistant/tasks/${encodeURIComponent(taskId)}/actions", script)
        self.assertIn("/api/assistant/questions/stream", script)
        self.assertIn("/api/assistant/interrupts/resume", script)
        self.assertIn("report-download-decision", script)
        self.assertIn("data-conversation-action=\"archive\"", script)
        self.assertIn("data-conversation-action=\"delete\"", script)
        self.assertIn("detail.exchanges", script)
        self.assertIn("function renderInlineMarkdown", script)
        self.assertIn('class="markdown-table"', script)
        self.assertIn('target="_blank" rel="noreferrer noopener"', script)

    def test_user_scoped_settings_and_task_calls_are_present(self) -> None:
        script = (STATIC_DIR / "app.js").read_text(encoding="utf-8")

        self.assertIn('queryPath("/api/settings/profile", { user_id: state.userId })', script)
        self.assertIn('queryPath("/api/llm/config", { user_id: state.userId })', script)
        self.assertIn('queryPath("/api/system/runtime", { user_id: state.userId })', script)
        self.assertIn('queryPath("/api/agent/tasks", { user_id: state.userId', script)


if __name__ == "__main__":
    unittest.main()
