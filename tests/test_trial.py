from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.main as main_module
from app.trial import TrialManager


TEST_MASTER_KEY = "unit-test-secflow-trial-master-key"


class MemoryMirror:
    def __init__(self) -> None:
        self.value: str | None = None

    def read(self) -> str | None:
        return self.value

    def write(self, value: str) -> None:
        self.value = value


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class TrialManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = patch.dict(
            os.environ,
            {
                "SECFLOW_TRIAL_ENABLED": "1",
                "SECFLOW_TRIAL_DURATION_HOURS": "72",
                "SECFLOW_STORAGE_MASTER_KEY": TEST_MASTER_KEY,
                "SECFLOW_DISABLE_BATCH_SCHEDULER": "1",
            },
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()

    def test_first_launch_creates_encrypted_redundant_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            clock = MutableClock(datetime(2026, 7, 20, 2, 0, tzinfo=timezone.utc))
            mirror = MemoryMirror()
            path = Path(temp_dir) / "trial.dat"
            manager = TrialManager(path, mirror=mirror, now=clock, binding="test-device-user")

            status = manager.status()

            self.assertTrue(status["usable"])
            self.assertEqual(status["state"], "active")
            self.assertEqual(status["secondsRemaining"], 72 * 60 * 60)
            self.assertEqual(status["expiresAt"], "2026-07-23T02:00:00Z")
            self.assertIsNotNone(mirror.value)
            self.assertIn("__secflow_encrypted__", path.read_text(encoding="utf-8"))
            self.assertNotIn("test-device-user", path.read_text(encoding="utf-8"))

    def test_trial_expires_after_72_continuous_hours(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            clock = MutableClock(datetime(2026, 7, 20, 2, 0, tzinfo=timezone.utc))
            manager = TrialManager(Path(temp_dir) / "trial.dat", now=clock, binding="test-binding")
            self.assertTrue(manager.status()["usable"])

            clock.value += timedelta(hours=72)
            status = manager.status()

            self.assertFalse(status["usable"])
            self.assertEqual(status["state"], "expired")
            self.assertEqual(status["secondsRemaining"], 0)

    def test_mac_package_can_configure_a_seven_day_trial(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_TRIAL_DURATION_HOURS": "168"},
        ):
            clock = MutableClock(datetime(2026, 7, 20, 2, 0, tzinfo=timezone.utc))
            manager = TrialManager(Path(temp_dir) / "trial.dat", now=clock, binding="test-binding")

            active = manager.status()
            self.assertEqual(active["durationHours"], 168)
            self.assertEqual(active["secondsRemaining"], 168 * 60 * 60)
            self.assertEqual(active["expiresAt"], "2026-07-27T02:00:00Z")
            self.assertEqual(active["message"], "7 天试用版可用。")

            clock.value += timedelta(hours=168)
            expired = manager.status()
            self.assertFalse(expired["usable"])
            self.assertEqual(expired["state"], "expired")

    def test_missing_primary_copy_is_restored_without_resetting_trial(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            clock = MutableClock(datetime(2026, 7, 20, 2, 0, tzinfo=timezone.utc))
            mirror = MemoryMirror()
            path = Path(temp_dir) / "trial.dat"
            manager = TrialManager(path, mirror=mirror, now=clock, binding="test-binding")
            manager.status()
            path.unlink()
            clock.value += timedelta(hours=71)

            restored = TrialManager(path, mirror=mirror, now=clock, binding="test-binding").status()

            self.assertTrue(path.exists())
            self.assertTrue(restored["usable"])
            self.assertLessEqual(restored["secondsRemaining"], 60 * 60)

    def test_clock_rollback_and_modified_state_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            clock = MutableClock(datetime(2026, 7, 20, 2, 0, tzinfo=timezone.utc))
            path = Path(temp_dir) / "trial.dat"
            manager = TrialManager(path, now=clock, binding="test-binding")
            manager.status()
            clock.value += timedelta(hours=2)
            manager.status()
            clock.value -= timedelta(hours=1)

            self.assertEqual(manager.status()["state"], "clock_rollback")

            path.write_text("modified", encoding="utf-8")
            self.assertEqual(manager.status()["state"], "tampered")

    def test_backend_blocks_core_api_but_keeps_trial_status_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            clock = MutableClock(datetime(2026, 7, 20, 2, 0, tzinfo=timezone.utc))
            manager = TrialManager(Path(temp_dir) / "trial.dat", now=clock, binding="test-binding")
            with patch.object(main_module, "trial_manager", manager):
                client = TestClient(main_module.app)
                self.assertEqual(client.get("/api/trial/status").status_code, 200)
                clock.value += timedelta(hours=72)

                blocked = client.get("/api/config")

                self.assertEqual(blocked.status_code, 403)
                self.assertEqual(blocked.json()["data"]["trial"]["state"], "expired")
                self.assertEqual(client.get("/api/trial/status").status_code, 200)
                with patch.dict(os.environ, {"SECFLOW_BACKEND_STARTUP_TOKEN": "startup-proof"}):
                    health = client.get("/health")
                self.assertEqual(health.status_code, 200)
                self.assertEqual(health.json()["startup_token"], "startup-proof")


if __name__ == "__main__":
    unittest.main()
