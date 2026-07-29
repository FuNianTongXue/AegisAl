from __future__ import annotations

import argparse
import os
import threading
import time

import uvicorn

from app.api.routes.application import app


def main() -> None:
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
        if os.getppid() != parent_pid:
            server.should_exit = True
            # The feed bootstrap can leave executor workers alive after Uvicorn
            # has stopped. Once the owning app is gone there is no valid reason
            # for its embedded service to survive as an orphan.
            os._exit(0)
        time.sleep(1)


if __name__ == "__main__":
    main()
