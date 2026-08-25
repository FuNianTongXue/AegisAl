from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PACKAGED_EDITION_FILE = "aegisal-edition.json"
PACKAGED_EDITION_SCHEMA_VERSION = 1
PACKAGED_EDITION_MODULE = "_aegisal_frozen_edition"
TRIAL_STORAGE_OVERRIDE_ENV_VARS = (
    "SECFLOW_STORAGE_MASTER_KEY",
    "SECFLOW_STORAGE_KEY_FILE",
    "SECFLOW_KEYCHAIN_PATH",
    "SECFLOW_DISABLE_KEYCHAIN",
    "SECFLOW_DISABLE_DPAPI",
    "SECFLOW_TRIAL_REGISTRY_KEY",
    "SECFLOW_TRIAL_REGISTRY_VALUE",
)


class PackagedEditionError(RuntimeError):
    """Raised when a frozen desktop backend has invalid edition metadata."""


@dataclass(frozen=True, slots=True)
class PackagedEdition:
    edition: str
    app_version: str
    release_channel: str
    backend_port: int
    trial_duration_hours: int | None = None
    keychain_service: str = ""

    @property
    def trial_enabled(self) -> bool:
        return self.edition == "trial"


def apply_packaged_edition_defaults(
    path: Path | None = None,
    *,
    required: bool | None = None,
) -> PackagedEdition | None:
    """Apply immutable edition defaults embedded by the desktop build.

    Trial settings deliberately overwrite inherited environment values. This
    keeps a packaged trial backend in trial mode when it is started directly,
    outside the Tauri launcher that normally supplies these variables.
    """

    frozen = bool(getattr(sys, "frozen", False))
    manifest_path = path or _default_manifest_path()
    must_exist = frozen if required is None else bool(required)
    if manifest_path is None or not manifest_path.is_file():
        if must_exist:
            raise PackagedEditionError("Packaged AegisAl edition metadata is missing")
        return None

    edition = _load_manifest(manifest_path)
    embedded = _load_embedded_edition(required=frozen)
    if embedded is not None and embedded != edition:
        raise PackagedEditionError("Packaged AegisAl edition metadata does not match the executable")
    os.environ["SECFLOW_APP_VERSION"] = edition.app_version
    os.environ["SECFLOW_APP_RELEASE_CHANNEL"] = edition.release_channel
    if edition.keychain_service:
        os.environ["SECFLOW_KEYCHAIN_SERVICE"] = edition.keychain_service
    if edition.trial_enabled:
        assert edition.trial_duration_hours is not None
        for variable in TRIAL_STORAGE_OVERRIDE_ENV_VARS:
            os.environ.pop(variable, None)
        if sys.platform == "darwin":
            os.environ["SECFLOW_SECURITY_CLI"] = "/usr/bin/security"
        os.environ["SECFLOW_TRIAL_ENABLED"] = "1"
        os.environ["SECFLOW_TRIAL_DURATION_HOURS"] = str(edition.trial_duration_hours)
    else:
        os.environ["SECFLOW_TRIAL_ENABLED"] = "0"
        os.environ.pop("SECFLOW_TRIAL_DURATION_HOURS", None)
    return edition


def _default_manifest_path() -> Path | None:
    if not getattr(sys, "frozen", False):
        return None
    runtime_root = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return runtime_root / PACKAGED_EDITION_FILE


def _load_manifest(path: Path) -> PackagedEdition:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackagedEditionError("Packaged AegisAl edition metadata is invalid") from exc
    return _edition_from_payload(payload)


def _load_embedded_edition(*, required: bool) -> PackagedEdition | None:
    module = sys.modules.get(PACKAGED_EDITION_MODULE)
    payload = getattr(module, "PAYLOAD", None) if module is not None else None
    if payload is None:
        if required:
            raise PackagedEditionError("Packaged AegisAl executable edition metadata is missing")
        return None
    return _edition_from_payload(payload)


def _edition_from_payload(payload: Any) -> PackagedEdition:
    if not isinstance(payload, dict) or payload.get("schema_version") != PACKAGED_EDITION_SCHEMA_VERSION:
        raise PackagedEditionError("Unsupported packaged AegisAl edition metadata")

    edition = str(payload.get("edition") or "").strip().lower()
    app_version = str(payload.get("app_version") or "").strip()
    release_channel = str(payload.get("release_channel") or "").strip()
    keychain_service = str(payload.get("keychain_service") or "").strip()
    try:
        backend_port = int(payload.get("backend_port") or 0)
    except (TypeError, ValueError) as exc:
        raise PackagedEditionError("Packaged AegisAl backend port is invalid") from exc
    if edition not in {"formal", "trial"} or not app_version or not release_channel:
        raise PackagedEditionError("Packaged AegisAl edition fields are incomplete")
    if not 1024 <= backend_port <= 65535:
        raise PackagedEditionError("Packaged AegisAl backend port is invalid")

    duration: int | None = None
    if edition == "trial":
        try:
            duration = int(payload.get("trial_duration_hours") or 0)
        except (TypeError, ValueError) as exc:
            raise PackagedEditionError("Packaged AegisAl trial duration is invalid") from exc
        if not 1 <= duration <= 24 * 365 or not keychain_service:
            raise PackagedEditionError("Packaged AegisAl trial fields are incomplete")

    return PackagedEdition(
        edition=edition,
        app_version=app_version,
        release_channel=release_channel,
        backend_port=backend_port,
        trial_duration_hours=duration,
        keychain_service=keychain_service,
    )
