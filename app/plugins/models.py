"""Immutable models shared by the AegisAl plugin runtime."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .errors import ManifestError


PLUGIN_SCHEMA_VERSION = "secflow.plugin/v1"
_PLUGIN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")


class PluginState(StrEnum):
    DISCOVERED = "discovered"
    LOADING = "loading"
    ACTIVE = "active"
    DRAINING = "draining"
    FAILED = "failed"
    DISPOSED = "disposed"


class TrustLevel(StrEnum):
    BUILTIN = "builtin"
    SIGNED = "signed"
    UNTRUSTED = "untrusted"


class ExecutionMode(StrEnum):
    """Where executable contribution code runs."""

    IN_PROCESS = "in-process"
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"


@dataclass(frozen=True, slots=True)
class PluginDependency:
    plugin_id: str
    version: str = ""
    optional: bool = False
    _specifier: SpecifierSet = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_plugin_id(self.plugin_id)
        try:
            specifier = SpecifierSet(self.version)
        except InvalidSpecifier as exc:
            raise ManifestError(
                f"invalid version constraint for dependency {self.plugin_id!r}: "
                f"{self.version!r}"
            ) from exc
        object.__setattr__(self, "_specifier", specifier)

    def accepts(self, version: str | Version) -> bool:
        try:
            parsed = version if isinstance(version, Version) else Version(version)
        except InvalidVersion:
            return False
        return parsed in self._specifier

    @classmethod
    def from_value(cls, value: PluginDependency | str | Mapping[str, Any]) -> PluginDependency:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            return cls(plugin_id=value)
        if isinstance(value, Mapping):
            plugin_id = value.get("id", value.get("plugin_id"))
            if not isinstance(plugin_id, str):
                raise ManifestError("dependency id must be a string")
            version = value.get("version", "")
            if not isinstance(version, str):
                raise ManifestError("dependency version must be a string")
            return cls(
                plugin_id=plugin_id,
                version=version,
                optional=bool(value.get("optional", False)),
            )
        raise ManifestError(f"unsupported dependency value: {value!r}")


@dataclass(frozen=True, slots=True)
class PluginManifest:
    plugin_id: str
    version: str
    trust: TrustLevel = TrustLevel.UNTRUSTED
    dependencies: tuple[PluginDependency, ...] = ()
    config: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = PLUGIN_SCHEMA_VERSION
    signature: str | None = None
    _parsed_version: Version = field(init=False, repr=False, compare=False)
    _config_hash: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_plugin_id(self.plugin_id)
        if self.schema_version != PLUGIN_SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported plugin schema {self.schema_version!r}; "
                f"expected {PLUGIN_SCHEMA_VERSION!r}"
            )
        try:
            parsed_version = Version(self.version)
        except InvalidVersion as exc:
            raise ManifestError(f"invalid plugin version {self.version!r}") from exc

        try:
            trust = self.trust if isinstance(self.trust, TrustLevel) else TrustLevel(self.trust)
        except ValueError as exc:
            raise ManifestError(f"invalid plugin trust level {self.trust!r}") from exc

        dependencies = tuple(
            PluginDependency.from_value(dependency) for dependency in self.dependencies
        )
        dependency_ids = [dependency.plugin_id for dependency in dependencies]
        if len(dependency_ids) != len(set(dependency_ids)):
            raise ManifestError("plugin dependencies must have unique ids")
        if self.plugin_id in dependency_ids:
            raise ManifestError("a plugin cannot depend on itself")

        try:
            plain_config = _plain_json_value(self.config)
            serialized_config = json.dumps(
                plain_config,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            copied_config = json.loads(serialized_config)
        except (TypeError, ValueError) as exc:
            raise ManifestError("plugin config must contain JSON-compatible values") from exc
        config = _freeze_json_value(copied_config)
        config_bytes = json.dumps(
            copied_config,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        object.__setattr__(self, "trust", trust)
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "config", config)
        object.__setattr__(self, "_parsed_version", parsed_version)
        object.__setattr__(self, "_config_hash", hashlib.sha256(config_bytes).hexdigest())

    @property
    def parsed_version(self) -> Version:
        return self._parsed_version

    @property
    def config_hash(self) -> str:
        return self._config_hash

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PluginManifest:
        plugin_id = value.get("id", value.get("plugin_id"))
        if not isinstance(plugin_id, str):
            raise ManifestError("plugin id must be a string")
        version = value.get("version")
        if not isinstance(version, str):
            raise ManifestError("plugin version must be a string")
        dependencies_value = value.get("requires", value.get("dependencies", ()))
        if not isinstance(dependencies_value, (list, tuple)):
            raise ManifestError("plugin dependencies must be a list")
        config = value.get("config", {})
        if not isinstance(config, Mapping):
            raise ManifestError("plugin config must be an object")
        return cls(
            plugin_id=plugin_id,
            version=version,
            trust=value.get("trust", TrustLevel.UNTRUSTED),
            dependencies=tuple(
                PluginDependency.from_value(item) for item in dependencies_value
            ),
            config=config,
            schema_version=value.get("schema_version", PLUGIN_SCHEMA_VERSION),
            signature=value.get("signature"),
        )


@dataclass(frozen=True, slots=True)
class PluginSnapshot:
    plugin_id: str
    version: str
    trust: TrustLevel
    state: PluginState
    config_hash: str
    generation: int


def _validate_plugin_id(plugin_id: str) -> None:
    if not isinstance(plugin_id, str) or not _PLUGIN_ID_PATTERN.fullmatch(plugin_id):
        raise ManifestError(
            "plugin id must be 1-128 lowercase ASCII letters, digits, dots, "
            "underscores, or hyphens"
        )


def _freeze_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_json_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json_value(item) for item in value)
    return value


def _plain_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ManifestError("plugin config object keys must be strings")
        return {key: _plain_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json_value(item) for item in value]
    return value
