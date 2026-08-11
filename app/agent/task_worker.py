from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Sequence
from uuid import uuid4


DEFAULT_LEASE_SECONDS = 30.0
DEFAULT_POLL_SECONDS = 0.25
DEFAULT_MAX_ATTEMPTS = 3


class TaskWorkerProcessSupervisor:
    """Keep durable-queue workers outside the FastAPI process."""

    def __init__(self, *, store_path: Path, worker_count: int = 2) -> None:
        configured_count = int(os.getenv("SECFLOW_TASK_WORKER_COUNT", str(worker_count)) or worker_count)
        self.store_path = Path(store_path).resolve()
        self.worker_count = max(1, min(configured_count, 4))
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._processes: dict[int, subprocess.Popen[bytes]] = {}
        self._monitor: threading.Thread | None = None

    def start(self) -> None:
        with self._lock:
            if self._monitor is not None and self._monitor.is_alive():
                return
            self._stop.clear()
            for slot in range(self.worker_count):
                self._processes[slot] = self._spawn(slot)
            self._monitor = threading.Thread(
                target=self._monitor_processes,
                daemon=True,
                name="secflow-task-worker-supervisor",
            )
            self._monitor.start()

    def stop(self, *, wait: bool = False) -> None:
        self._stop.set()
        with self._lock:
            processes = list(self._processes.values())
            monitor = self._monitor
            self._processes = {}
            self._monitor = None
        for process in processes:
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    pass
        deadline = time.monotonic() + (10.0 if wait else 2.0)
        for process in processes:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        if monitor is not None and monitor.is_alive() and monitor is not threading.current_thread():
            monitor.join(timeout=2.0 if wait else 0.25)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            processes = list(self._processes.values())
        return {
            "mode": "external-process",
            "configured_workers": self.worker_count,
            "running_workers": sum(process.poll() is None for process in processes),
            "store_path": str(self.store_path),
        }

    def _spawn(self, slot: int) -> subprocess.Popen[bytes]:
        environment = dict(os.environ)
        environment["SECFLOW_TASK_EXECUTION_MODE"] = "worker"
        environment["SECFLOW_TASK_STORE_PATH"] = str(self.store_path)
        environment["PYTHONUNBUFFERED"] = "1"
        return subprocess.Popen(  # noqa: S603 - executable and arguments are local constants.
            self._command(slot),
            stdin=subprocess.DEVNULL,
            env=environment,
        )

    def _command(self, slot: int) -> list[str]:
        arguments = [
            "--task-worker",
            "--store-path",
            str(self.store_path),
            "--parent-pid",
            str(os.getpid()),
            "--worker-id",
            f"worker-{slot}",
        ]
        if getattr(sys, "frozen", False):
            return [sys.executable, *arguments]
        return [sys.executable, "-m", "app.agent.task_worker", *arguments[1:]]

    def _monitor_processes(self) -> None:
        while not self._stop.wait(1.0):
            with self._lock:
                for slot, process in list(self._processes.items()):
                    if process.poll() is None or self._stop.is_set():
                        continue
                    self._processes[slot] = self._spawn(slot)


def run_worker(
    *,
    store_path: Path,
    parent_pid: int | None,
    worker_label: str,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> int:
    os.environ["SECFLOW_TASK_EXECUTION_MODE"] = "worker"
    os.environ["SECFLOW_TASK_STORE_PATH"] = str(store_path.resolve())

    from app.agent.task_agent import task_agent_service

    service = task_agent_service
    service.store.reconcile_pending_jobs()
    worker_id = f"{worker_label}:{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    stopping = threading.Event()

    def request_stop(_signum=None, _frame=None) -> None:
        stopping.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, request_stop)
        except (OSError, ValueError):
            pass

    try:
        while not stopping.is_set() and _parent_is_alive(parent_pid):
            job = service.store.claim(worker_id, lease_seconds=lease_seconds)
            if job is None:
                stopping.wait(max(0.05, poll_seconds))
                continue
            task_id = str(job["task_id"])
            attempts = int(job.get("attempts") or 1)
            if attempts > max(1, max_attempts):
                service.fail_claimed(
                    task_id,
                    worker_id,
                    f"任务已连续 {attempts - 1} 次因 Worker 中断而恢复，为避免无限重试已停止执行。",
                )
                continue

            heartbeat_stop = threading.Event()
            heartbeat = threading.Thread(
                target=_renew_lease,
                args=(service, task_id, worker_id, lease_seconds, heartbeat_stop),
                daemon=True,
                name=f"secflow-task-lease-{task_id[-8:]}",
            )
            heartbeat.start()
            try:
                service.run_claimed(
                    task_id,
                    worker_id,
                    recovered=bool(job.get("recovered")),
                )
            finally:
                heartbeat_stop.set()
                heartbeat.join(timeout=2.0)
    finally:
        service.shutdown(wait=False)
    return 0


def _renew_lease(service, task_id: str, worker_id: str, lease_seconds: float, stopping: threading.Event) -> None:
    interval = max(1.0, lease_seconds / 3.0)
    while not stopping.wait(interval):
        try:
            renewed = service.store.renew_lease(
                task_id,
                worker_id,
                lease_seconds=lease_seconds,
            )
        except Exception:  # noqa: BLE001 - a transient SQLite busy state is retried before expiry.
            continue
        if not renewed:
            try:
                if str(service.store.job(task_id).get("state") or "") in {
                    "completed",
                    "failed",
                    "cancelled",
                }:
                    return
            except KeyError:
                return
            service.signal_lease_lost(task_id)
            return


def _parent_is_alive(parent_pid: int | None) -> bool:
    if not parent_pid:
        return True
    if os.getppid() == parent_pid:
        return True
    try:
        os.kill(parent_pid, 0)
    except OSError:
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecFlow durable LangGraph task worker")
    parser.add_argument("--task-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--store-path", type=Path, required=True)
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("--worker-id", default="worker")
    parser.add_argument("--lease-seconds", type=float, default=DEFAULT_LEASE_SECONDS)
    parser.add_argument("--poll-seconds", type=float, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    args = parser.parse_args(argv)
    return run_worker(
        store_path=args.store_path,
        parent_pid=args.parent_pid,
        worker_label=args.worker_id,
        lease_seconds=max(5.0, args.lease_seconds),
        poll_seconds=max(0.05, args.poll_seconds),
        max_attempts=max(1, args.max_attempts),
    )


if __name__ == "__main__":
    raise SystemExit(main())
