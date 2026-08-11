from __future__ import annotations

import ctypes
import os
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any


APP_TITLE = "安全智脑 - 7 天试用版"
APP_USER_MODEL_ID = "SecFlow.SecurityAI.Trial7Days"
SINGLE_INSTANCE_MUTEX = "Local\\SecFlowSecurityAITrial7DaysV1"
STARTUP_TIMEOUT_SECONDS = 25
TRIAL_DURATION_HOURS = 168


class WindowsBridge:
    """Small, auditable native surface exposed to the bundled web UI."""

    def __init__(self) -> None:
        self._window: Any | None = None

    def bind_window(self, window: Any) -> None:
        self._window = window

    def select_workspace(self) -> dict[str, str]:
        if self._window is None:
            raise RuntimeError("客户端窗口尚未准备好。")
        import webview

        selected = self._window.create_file_dialog(
            webview.FOLDER_DIALOG,
            allow_multiple=False,
        )
        if not selected:
            return {}
        raw_path = selected[0] if isinstance(selected, (list, tuple)) else selected
        path = Path(str(raw_path)).expanduser().resolve()
        if not path.is_dir():
            raise ValueError("请选择有效的代码项目目录。")
        return {"path": str(path), "name": path.name or str(path)}


def main() -> int:
    if sys.platform != "win32":
        raise SystemExit("This entry point is only for the Windows package.")
    if "--task-worker" in sys.argv:
        from app.agent.task_worker import main as task_worker_main

        return task_worker_main(sys.argv[1:])
    if "--code-scan-mcp" in sys.argv:
        from app.mcp.code_scan import main as code_scan_mcp_main

        code_scan_mcp_main([item for item in sys.argv[1:] if item != "--code-scan-mcp"])
        return 0
    if "--self-test" in sys.argv:
        return _self_test()
    mutex = _acquire_single_instance()
    if mutex is None:
        _message_box("安全智脑已经在运行。", APP_TITLE)
        return 0

    _configure_windows_environment()
    server: Any | None = None
    server_thread: threading.Thread | None = None
    try:
        from app.api.routes.application import app
        import uvicorn
        import webview

        port = _available_port()
        url = f"http://127.0.0.1:{port}/ui"
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                loop="asyncio",
                http="h11",
                access_log=False,
                log_level="warning",
            )
        )
        server_thread = threading.Thread(
            target=server.run,
            daemon=True,
            name="secflow-windows-backend",
        )
        server_thread.start()
        _wait_for_backend(port, server_thread)

        webview.settings["ALLOW_DOWNLOADS"] = True
        bridge = WindowsBridge()
        window = webview.create_window(
            APP_TITLE,
            url=url,
            width=1440,
            height=920,
            min_size=(1024, 700),
            text_select=True,
            js_api=bridge,
        )
        bridge.bind_window(window)
        webview.start(debug=False, private_mode=False)
        return 0
    except Exception as exc:  # noqa: BLE001
        _message_box(f"应用启动失败：\n{exc}", APP_TITLE)
        return 1
    finally:
        if server is not None:
            server.should_exit = True
        if server_thread is not None and server_thread.is_alive():
            server_thread.join(timeout=5)
        ctypes.windll.kernel32.CloseHandle(mutex)


def _configure_windows_environment() -> None:
    local_app_data = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    data_dir = local_app_data / "SecFlow" / "SecurityAI-Trial-7Days"
    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ["SECFLOW_DATA_DIR"] = str(data_dir)
    os.environ["SECFLOW_TRIAL_ENABLED"] = "1"
    os.environ["SECFLOW_TRIAL_DURATION_HOURS"] = str(TRIAL_DURATION_HOURS)
    os.environ["SECFLOW_TRIAL_REGISTRY_KEY"] = r"Software\SecFlow\SecurityAITrial7Days"
    os.environ["SECFLOW_TRIAL_REGISTRY_VALUE"] = "TrialStateV1"
    os.environ["SECFLOW_APP_RELEASE_CHANNEL"] = "7天试用版"
    os.environ.pop("SECFLOW_STORAGE_MASTER_KEY", None)
    os.environ.pop("SECFLOW_STORAGE_KEY_FILE", None)
    os.environ.pop("SECFLOW_DISABLE_DPAPI", None)
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)


def _self_test() -> int:
    _configure_windows_environment()
    import webview  # noqa: F401
    from app.api.routes.application import STATIC_DIR
    from app.trial import trial_manager

    status = trial_manager.status()
    if (
        not status.get("enabled")
        or not status.get("usable")
        or status.get("durationHours") != TRIAL_DURATION_HOURS
    ):
        raise RuntimeError("seven-day trial enforcement is unavailable")
    if not (STATIC_DIR / "index.html").is_file():
        raise RuntimeError("packaged web interface is missing")
    if not callable(getattr(WindowsBridge(), "select_workspace", None)):
        raise RuntimeError("native workspace selection bridge is missing")
    return 0


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_backend(port: int, thread: threading.Thread) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    health_url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        if not thread.is_alive():
            raise RuntimeError("本地服务未能启动。")
        try:
            with urllib.request.urlopen(health_url, timeout=1) as response:  # noqa: S310
                if response.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.15)
    raise TimeoutError("本地服务启动超时。")


def _acquire_single_instance():
    handle = ctypes.windll.kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX)
    if not handle:
        raise ctypes.WinError()
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        ctypes.windll.kernel32.CloseHandle(handle)
        return None
    return handle


def _message_box(message: str, title: str) -> None:
    ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)


if __name__ == "__main__":
    raise SystemExit(main())
