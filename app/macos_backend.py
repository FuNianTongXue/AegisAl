from __future__ import annotations

import argparse
import ctypes
import os
import sys
import threading
import time


def main() -> None:
    import uvicorn

    if "--task-worker" in sys.argv:
        from app.agent.task_worker import main as task_worker_main

        raise SystemExit(task_worker_main(sys.argv[1:]))
    if "--code-scan-mcp" in sys.argv:
        from app.mcp.code_scan import main as code_scan_mcp_main

        code_scan_mcp_main([item for item in sys.argv[1:] if item != "--code-scan-mcp"])
        return
    from app.api.routes.application import app

    parser = argparse.ArgumentParser(description="SecFlow embedded macOS backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18781)
    parser.add_argument("--parent-pid", type=int)
    args = parser.parse_args()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=args.host,
            port=args.port,
            loop="asyncio",
            http="h11",
            access_log=False,
        )
    )
    if args.parent_pid:
        threading.Thread(
            target=_watch_parent,
            args=(args.parent_pid, server),
            daemon=True,
            name="secflow-parent-watch",
        ).start()
    server.run()


def _watch_parent(parent_pid: int, server: uvicorn.Server) -> None:
    while not server.should_exit:
        if not _process_is_alive(parent_pid):
            server.should_exit = True
            # The feed bootstrap can leave executor workers alive after Uvicorn
            # has stopped. Once the owning app is gone there is no valid reason
            # for its embedded service to survive as an orphan.
            os._exit(0)
        time.sleep(1)


def _process_is_alive(process_id: int) -> bool:
    if process_id <= 1:
        return False
    if sys.platform == "win32":
        synchronize = 0x00100000
        wait_timeout = 0x00000102
        handle = ctypes.windll.kernel32.OpenProcess(synchronize, False, process_id)
        if not handle:
            return False
        try:
            return ctypes.windll.kernel32.WaitForSingleObject(handle, 0) == wait_timeout
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


if __name__ == "__main__":
    main()
