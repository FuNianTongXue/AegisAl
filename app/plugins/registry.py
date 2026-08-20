"""Thread-safe named registries with atomic, revocable publication."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Any, Mapping
from uuid import uuid4

from .errors import PluginSecurityError, RegistryConflictError, RegistryKeyError
from .models import ExecutionMode, TrustLevel

EXECUTABLE_REGISTRIES = frozenset({"agents", "tools", "mcp", "mcp_servers", "hooks"})
IN_PROCESS_ONLY_REGISTRIES = frozenset({"agents", "hooks"})


@dataclass(frozen=True, slots=True)
class RegistrationOwner:
    plugin_id: str
    version: str
    trust: TrustLevel
    generation: int

    def __post_init__(self) -> None:
        trust = self.trust
        if not isinstance(trust, TrustLevel):
            trust = TrustLevel(trust)
            object.__setattr__(self, "trust", trust)
        if not self.plugin_id or not self.version or self.generation < 0:
            raise ValueError("registration owner identity is incomplete")


@dataclass(frozen=True, slots=True)
class RegistrationMetadata:
    executable: bool = False
    execution_mode: ExecutionMode | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        mode = self.execution_mode
        if mode is not None and not isinstance(mode, ExecutionMode):
            mode = ExecutionMode(mode)
            object.__setattr__(self, "execution_mode", mode)
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    registry: str
    key: str
    value: Any
    owner: RegistrationOwner
    metadata: RegistrationMetadata
    token: str


@dataclass(frozen=True, slots=True)
class StagedRegistration:
    registry: str
    key: str
    value: Any
    owner: RegistrationOwner
    metadata: RegistrationMetadata = field(default_factory=RegistrationMetadata)
    token: str = field(default_factory=lambda: uuid4().hex)


class RegistrationHandle:
    """Idempotently revokes one published registry entry."""

    def __init__(self, hub: RegistryHub, entry: RegistryEntry) -> None:
        self._hub = hub
        self.entry = entry
        self._lock = RLock()
        self._revoked = False

    @property
    def revoked(self) -> bool:
        with self._lock:
            return self._revoked

    def revoke(self) -> bool:
        with self._lock:
            if self._revoked:
                return False
            removed = self._hub._revoke_token(self.entry.token)
            self._revoked = True
            return removed

    dispose = revoke
    __call__ = revoke


class Registry:
    """A named view into a central RegistryHub."""

    def __init__(self, hub: RegistryHub, name: str) -> None:
        self._hub = hub
        self.name = name

    def register(
        self,
        key: str,
        value: Any,
        *,
        owner: RegistrationOwner,
        executable: bool = False,
        execution_mode: ExecutionMode | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> RegistrationHandle:
        staged = StagedRegistration(
            registry=self.name,
            key=key,
            value=value,
            owner=owner,
            metadata=RegistrationMetadata(
                executable=executable,
                execution_mode=execution_mode,
                attributes=attributes or {},
            ),
        )
        return self._hub.publish((staged,))[0]

    def get_entry(self, key: str) -> RegistryEntry | None:
        return self._hub.get_entry(self.name, key)

    def get(self, key: str, default: Any = None) -> Any:
        entry = self.get_entry(key)
        return default if entry is None else entry.value

    def require(self, key: str) -> Any:
        entry = self.get_entry(key)
        if entry is None:
            raise RegistryKeyError(f"registry {self.name!r} has no key {key!r}")
        return entry.value

    def entries(self) -> Mapping[str, RegistryEntry]:
        return self._hub.snapshot_registry(self.name)

    def values(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {key: entry.value for key, entry in self.entries().items()}
        )

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and self.get_entry(key) is not None

    def __len__(self) -> int:
        return len(self.entries())


class ReadOnlyRegistry:
    """Registry view exposed to plugin activation code."""

    def __init__(self, registry: Registry) -> None:
        self._registry = registry
        self.name = registry.name

    def get_entry(self, key: str) -> RegistryEntry | None:
        return self._registry.get_entry(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self._registry.get(key, default)

    def require(self, key: str) -> Any:
        return self._registry.require(key)

    def entries(self) -> Mapping[str, RegistryEntry]:
        return self._registry.entries()

    def values(self) -> Mapping[str, Any]:
        return self._registry.values()

    def __contains__(self, key: object) -> bool:
        return key in self._registry

    def __len__(self) -> int:
        return len(self._registry)


class RegistryHub:
    """Owns all registries and commits multi-registry batches atomically."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries: dict[str, dict[str, RegistryEntry]] = {}
        self._tokens: dict[str, tuple[str, str]] = {}
        self._revision = 0

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    def registry(self, name: str) -> Registry:
        _validate_registry_name(name)
        return Registry(self, name)

    def publish(
        self, staged: tuple[StagedRegistration, ...] | list[StagedRegistration]
    ) -> tuple[RegistrationHandle, ...]:
        records = tuple(staged)
        if not records:
            return ()
        with self._lock:
            batch_keys: set[tuple[str, str]] = set()
            normalized: list[tuple[StagedRegistration, RegistrationMetadata]] = []
            for record in records:
                metadata = _validate_registration(record)
                normalized.append((record, metadata))
                pair = (record.registry, record.key)
                if pair in batch_keys:
                    raise RegistryConflictError(
                        f"duplicate staged contribution {record.registry!r}/{record.key!r}"
                    )
                batch_keys.add(pair)
                if record.key in self._entries.get(record.registry, {}):
                    existing = self._entries[record.registry][record.key]
                    raise RegistryConflictError(
                        f"contribution {record.registry!r}/{record.key!r} is already "
                        f"owned by {existing.owner.plugin_id!r}"
                    )

            published: list[RegistryEntry] = []
            for record, metadata in normalized:
                entry = RegistryEntry(
                    registry=record.registry,
                    key=record.key,
                    value=record.value,
                    owner=record.owner,
                    metadata=metadata,
                    token=record.token,
                )
                self._entries.setdefault(record.registry, {})[record.key] = entry
                self._tokens[record.token] = (record.registry, record.key)
                published.append(entry)
            self._revision += 1
        return tuple(RegistrationHandle(self, entry) for entry in published)

    def get_entry(self, registry: str, key: str) -> RegistryEntry | None:
        with self._lock:
            return self._entries.get(registry, {}).get(key)

    def snapshot_registry(self, registry: str) -> Mapping[str, RegistryEntry]:
        with self._lock:
            return MappingProxyType(dict(self._entries.get(registry, {})))

    def snapshot(self) -> Mapping[str, Mapping[str, RegistryEntry]]:
        with self._lock:
            return MappingProxyType(
                {
                    name: MappingProxyType(dict(entries))
                    for name, entries in self._entries.items()
                    if entries
                }
            )

    def revoke_owner(self, plugin_id: str, generation: int | None = None) -> int:
        with self._lock:
            tokens = [
                entry.token
                for entries in self._entries.values()
                for entry in entries.values()
                if entry.owner.plugin_id == plugin_id
                and (generation is None or entry.owner.generation == generation)
            ]
            removed = self._revoke_tokens_locked(tokens)
            if removed:
                self._revision += 1
            return removed

    def _revoke_token(self, token: str) -> bool:
        with self._lock:
            removed = self._revoke_tokens_locked((token,))
            if removed:
                self._revision += 1
            return bool(removed)

    def _revoke_tokens_locked(self, tokens: tuple[str, ...] | list[str]) -> int:
        removed = 0
        for token in tokens:
            location = self._tokens.pop(token, None)
            if location is None:
                continue
            registry, key = location
            entries = self._entries.get(registry)
            if entries is None:
                continue
            entry = entries.get(key)
            if entry is not None and entry.token == token:
                del entries[key]
                removed += 1
            if not entries:
                self._entries.pop(registry, None)
        return removed


def _validate_registry_name(name: str) -> None:
    if not isinstance(name, str) or not name or name.strip() != name:
        raise ValueError("registry name must be a non-empty trimmed string")


def _validate_registration(record: StagedRegistration) -> RegistrationMetadata:
    _validate_registry_name(record.registry)
    if not isinstance(record.key, str) or not record.key or record.key.strip() != record.key:
        raise ValueError("registry key must be a non-empty trimmed string")

    metadata = record.metadata
    executable = (
        metadata.executable
        or callable(record.value)
        or record.registry in EXECUTABLE_REGISTRIES
        or metadata.execution_mode is not None
    )
    mode = metadata.execution_mode
    if executable and mode is None:
        mode = ExecutionMode.IN_PROCESS
    if record.registry in IN_PROCESS_ONLY_REGISTRIES and mode is not ExecutionMode.IN_PROCESS:
        raise PluginSecurityError(
            f"registry {record.registry!r} only accepts Host in-process contributions"
        )
    if (
        record.owner.trust is TrustLevel.UNTRUSTED
        and executable
        and mode is ExecutionMode.IN_PROCESS
    ):
        raise PluginSecurityError(
            f"untrusted plugin {record.owner.plugin_id!r} cannot publish in-process "
            f"executable contribution {record.registry!r}/{record.key!r}"
        )
    return RegistrationMetadata(
        executable=executable,
        execution_mode=mode,
        attributes=metadata.attributes,
    )
