from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.macos_backend import _process_is_alive, _watch_parent


class DesktopBackendLifecycleTests(unittest.TestCase):
    def test_windows_parent_check_uses_process_handle(self) -> None:
        kernel32 = Mock()
        kernel32.OpenProcess.return_value = 42
        kernel32.WaitForSingleObject.return_value = 0x00000102

        with (
            patch("app.macos_backend.sys.platform", "win32"),
            patch(
                "app.macos_backend.ctypes.windll",
                SimpleNamespace(kernel32=kernel32),
                create=True,
            ),
        ):
            self.assertTrue(_process_is_alive(43210))

        kernel32.OpenProcess.assert_called_once_with(0x00100000, False, 43210)
        kernel32.WaitForSingleObject.assert_called_once_with(42, 0)
        kernel32.CloseHandle.assert_called_once_with(42)

    def test_windows_parent_check_rejects_missing_process(self) -> None:
        kernel32 = Mock()
        kernel32.OpenProcess.return_value = 0

        with (
            patch("app.macos_backend.sys.platform", "win32"),
            patch(
                "app.macos_backend.ctypes.windll",
                SimpleNamespace(kernel32=kernel32),
                create=True,
            ),
        ):
            self.assertFalse(_process_is_alive(43210))

    def test_parent_watch_exits_when_desktop_process_is_gone(self) -> None:
        server = SimpleNamespace(should_exit=False)
        with (
            patch("app.macos_backend._process_is_alive", return_value=False),
            patch("app.macos_backend.os._exit", side_effect=SystemExit(0)) as exit_process,
        ):
            with self.assertRaises(SystemExit):
                _watch_parent(43210, server)

        self.assertTrue(server.should_exit)
        exit_process.assert_called_once_with(0)


if __name__ == "__main__":
    unittest.main()
