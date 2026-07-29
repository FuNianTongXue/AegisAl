from __future__ import annotations

import getpass
import hashlib
import os
import platform
import re
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Protocol

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text


DEFAULT_TRIAL_DURATION = timedelta(days=3)
CLOCK_ROLLBACK_TOLERANCE = timedelta(minutes=5)
LAST_SEEN_WRITE_INTERVAL = timedelta(seconds=30)
TRIAL_STATE_PURPOSE = "secflow-trial-v1"
TRIAL_STATE_VERSION = 1
REGISTRY_KEY = r"Software\SecFlow\SecurityAI"
REGISTRY_VALUE = "TrialStateV1"
KEYCHAIN_TRIAL_ACCOUNT = "trial-state-v1"


class TrialMirror(Protocol):
    def read(self) -> str | None: ...

    def write(self, value: str) -> None: ...


class WindowsRegistryTrialMirror:
    def __init__(self) -> None:
        self.registry_key = os.getenv("SECFLOW_TRIAL_REGISTRY_KEY", REGISTRY_KEY).strip() or REGISTRY_KEY
        self.registry_value = (
            os.getenv("SECFLOW_TRIAL_REGISTRY_VALUE", REGISTRY_VALUE).strip() or REGISTRY_VALUE
        )

    def read(self) -> str | None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.registry_key) as key:
                value, value_type = winreg.QueryValueEx(key, self.registry_value)
        except FileNotFoundError:
            return None
        if value_type != winreg.REG_SZ or not isinstance(value, str):
            raise ValueError("invalid trial registry value")
        return value

    def write(self, value: str) -> None:
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            self.registry_key,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            winreg.SetValueEx(key, self.registry_value, 0, winreg.REG_SZ, value)


class MacKeychainTrialMirror:
    def __init__(self) -> None:
        base_service = os.getenv("SECFLOW_KEYCHAIN_SERVICE", "com.secflow.ai.mac.intelligence").strip()
        self.service = f"{base_service or 'com.secflow.ai.mac.intelligence'}.trial"
        self.security = Path(os.getenv("SECFLOW_SECURITY_CLI", "/usr/bin/security"))

    def read(self) -> str | None:
        if not self.security.exists():
            raise OSError("macOS security CLI is unavailable")
        result = subprocess.run(
            [
                str(self.security),
                "find-generic-password",
                "-s",
                self.service,
                "-a",
                KEYCHAIN_TRIAL_ACCOUNT,
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
        if result.returncode == 44 or "could not be found" in result.stderr.lower():
            return None
        raise OSError(result.stderr.strip() or "unable to read macOS trial state")

    def write(self, value: str) -> None:
        if not self.security.exists():
            raise OSError("macOS security CLI is unavailable")
        result = subprocess.run(
            [
                str(self.security),
                "add-generic-password",
                "-U",
                "-s",
                self.service,
                "-a",
                KEYCHAIN_TRIAL_ACCOUNT,
                "-w",
                value,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or "unable to write macOS trial state")


class TrialManager:
    def __init__(
        self,
        primary_path: Path | None = None,
        *,
        mirror: TrialMirror | None = None,
        duration: timedelta | None = None,
        now: Callable[[], datetime] | None = None,
        binding: str | None = None,
    ) -> None:
        data_dir = Path(os.getenv("SECFLOW_DATA_DIR", "data"))
        self.primary_path = primary_path or (data_dir / ".secflow-trial-state")
        self.mirror = mirror
        self.duration = duration if duration is not None else _configured_trial_duration()
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.binding = binding or machine_user_binding()
        self._lock = RLock()

    @property
    def enabled(self) -> bool:
        return os.getenv("SECFLOW_TRIAL_ENABLED", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def status(self) -> dict[str, Any]:
        if not self.enabled:
            return {
                "enabled": False,
                "usable": True,
                "state": "disabled",
                "durationHours": _duration_hours(self.duration),
                "secondsRemaining": None,
                "message": "当前版本未启用限时试用。",
            }

        with self._lock:
            now = _as_utc(self._now())
            try:
                state = self._load_or_create(now)
                started_at = _parse_time(state["startedAt"])
                last_seen_at = _parse_time(state["lastSeenAt"])
                if state.get("binding") != self.binding:
                    raise ValueError("trial state belongs to another device or user")
            except Exception:  # noqa: BLE001
                return self._blocked_status(
                    "tampered",
                    "试用授权状态无效或已被修改，核心功能已停用。",
                )

            if started_at > now + CLOCK_ROLLBACK_TOLERANCE or last_seen_at > now + CLOCK_ROLLBACK_TOLERANCE:
                return self._blocked_status(
                    "clock_rollback",
                    "检测到系统时间回拨，核心功能已停用。请恢复正确时间后重试。",
                    started_at=started_at,
                    last_seen_at=last_seen_at,
                )
            if started_at > last_seen_at + CLOCK_ROLLBACK_TOLERANCE:
                return self._blocked_status(
                    "tampered",
                    "试用授权时间顺序无效，核心功能已停用。",
                    started_at=started_at,
                    last_seen_at=last_seen_at,
                )

            expires_at = started_at + self.duration
            seconds_remaining = max(0, int((expires_at - now).total_seconds()))
            expired = now >= expires_at
            if now - last_seen_at >= LAST_SEEN_WRITE_INTERVAL:
                state["lastSeenAt"] = _format_time(now)
                self._persist(state)
                last_seen_at = now

            return {
                "enabled": True,
                "usable": not expired,
                "state": "expired" if expired else "active",
                "durationHours": _duration_hours(self.duration),
                "startedAt": _format_time(started_at),
                "expiresAt": _format_time(expires_at),
                "lastSeenAt": _format_time(last_seen_at),
                "secondsRemaining": seconds_remaining,
                "message": (
                    f"{_duration_label(self.duration)}试用期已结束，核心功能已停用。"
                    if expired
                    else f"{_duration_label(self.duration)}试用版可用。"
                ),
            }

    def _load_or_create(self, now: datetime) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        invalid_source = False
        primary_loaded = False
        mirror_loaded = False
        mirror_available = self.mirror is not None

        if self.primary_path.exists():
            try:
                candidates.append(self._decode(self.primary_path.read_text(encoding="utf-8")))
                primary_loaded = True
            except Exception:  # noqa: BLE001
                invalid_source = True

        if self.mirror is not None:
            try:
                mirrored = self.mirror.read()
                if mirrored:
                    candidates.append(self._decode(mirrored))
                    mirror_loaded = True
            except OSError:
                mirror_available = False
            except Exception:  # noqa: BLE001
                invalid_source = True

        if invalid_source:
            raise ValueError("a trial state copy is invalid")
        if not candidates:
            state = {
                "version": TRIAL_STATE_VERSION,
                "installationId": str(uuid.uuid4()),
                "binding": self.binding,
                "startedAt": _format_time(now),
                "lastSeenAt": _format_time(now),
            }
            self._persist(state)
            return state

        state = self._merge_candidates(candidates)
        copies_match = all(candidate == state for candidate in candidates)
        if not primary_loaded or (mirror_available and not mirror_loaded) or not copies_match:
            self._persist(state)
        return state

    def _merge_candidates(self, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        for candidate in candidates:
            if candidate.get("version") != TRIAL_STATE_VERSION:
                raise ValueError("unsupported trial state version")
            if candidate.get("binding") != self.binding:
                raise ValueError("trial binding mismatch")
            if not str(candidate.get("installationId") or "").strip():
                raise ValueError("missing trial installation identifier")
            _parse_time(candidate["startedAt"])
            _parse_time(candidate["lastSeenAt"])

        earliest = min(candidates, key=lambda item: _parse_time(item["startedAt"]))
        latest_last_seen = max(_parse_time(item["lastSeenAt"]) for item in candidates)
        return {
            "version": TRIAL_STATE_VERSION,
            "installationId": str(earliest.get("installationId") or ""),
            "binding": self.binding,
            "startedAt": _format_time(min(_parse_time(item["startedAt"]) for item in candidates)),
            "lastSeenAt": _format_time(latest_last_seen),
        }

    def _decode(self, value: str) -> dict[str, Any]:
        state = decrypt_json_from_text(value, TRIAL_STATE_PURPOSE)
        if not isinstance(state, dict):
            raise ValueError("trial state is not an object")
        return state

    def _persist(self, state: dict[str, Any]) -> None:
        encoded = encrypt_json_to_text(state, TRIAL_STATE_PURPOSE, compact=True)
        self.primary_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.primary_path.with_suffix(f"{self.primary_path.suffix}.tmp")
        temporary_path.write_text(encoded, encoding="utf-8")
        temporary_path.replace(self.primary_path)
        if self.mirror is not None:
            try:
                self.mirror.write(encoded)
            except OSError:
                # The per-user file remains authoritative on restricted systems.
                pass

    def _blocked_status(
        self,
        state: str,
        message: str,
        *,
        started_at: datetime | None = None,
        last_seen_at: datetime | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "enabled": True,
            "usable": False,
            "state": state,
            "durationHours": _duration_hours(self.duration),
            "secondsRemaining": 0,
            "message": message,
        }
        if started_at is not None:
            result["startedAt"] = _format_time(started_at)
            result["expiresAt"] = _format_time(started_at + self.duration)
        if last_seen_at is not None:
            result["lastSeenAt"] = _format_time(last_seen_at)
        return result


def machine_user_binding() -> str:
    machine_id = platform.node() or os.getenv("COMPUTERNAME", "unknown-machine")
    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
            ) as key:
                machine_id = str(winreg.QueryValueEx(key, "MachineGuid")[0])
        except OSError:
            pass
    elif sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            matched = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', result.stdout)
            if matched:
                machine_id = matched.group(1)
        except OSError:
            pass
    account = "\\".join(
        item for item in (os.getenv("USERDOMAIN", ""), getpass.getuser()) if item
    )
    material = f"SecFlowTrial:v1:{machine_id}:{account}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_time(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return _as_utc(parsed)


def _format_time(value: datetime) -> str:
    return _as_utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _configured_trial_duration() -> timedelta:
    raw_hours = os.getenv("SECFLOW_TRIAL_DURATION_HOURS", "").strip()
    if not raw_hours:
        return DEFAULT_TRIAL_DURATION
    try:
        hours = int(raw_hours)
    except ValueError:
        return DEFAULT_TRIAL_DURATION
    if not 1 <= hours <= 24 * 365:
        return DEFAULT_TRIAL_DURATION
    return timedelta(hours=hours)


def _duration_hours(duration: timedelta) -> int:
    return int(duration.total_seconds() // 3600)


def _duration_label(duration: timedelta) -> str:
    hours = _duration_hours(duration)
    if hours % 24 == 0:
        return f"{hours // 24} 天"
    return f"{hours} 小时"


def _default_mirror() -> TrialMirror | None:
    if sys.platform == "win32":
        return WindowsRegistryTrialMirror()
    if sys.platform == "darwin":
        return MacKeychainTrialMirror()
    return None


trial_manager = TrialManager(mirror=_default_mirror())
