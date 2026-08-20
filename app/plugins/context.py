"""Restricted activation context presented to a plugin."""

from __future__ import annotations

from collections.abc import Callable
from threading import RLock
from typing import Any, Mapping

from .effects import EffectHandle, EffectScope
from .errors import PluginStateError
from .models import ExecutionMode, PluginManifest, TrustLevel
from .registry import (
    RegistrationMetadata,
    RegistrationOwner,
    RegistryHub,
    ReadOnlyRegistry,
    StagedRegistration,
)


class PluginContext:
    """Stages contributions and owns plugin-local cleanup effects."""

    def __init__(
        self,
        manifest: PluginManifest,
        registries: RegistryHub,
        effects: EffectScope,
        generation: int,
    ) -> None:
        self.manifest = manifest
        self.generation = generation
        self._registries = registries
        self._effects = effects
        self._owner = RegistrationOwner(
            plugin_id=manifest.plugin_id,
            version=manifest.version,
            trust=manifest.trust,
            generation=generation,
        )
        self._lock = RLock()
        self._staged: list[StagedRegistration] = []
        self._sealed = False

    @property
    def plugin_id(self) -> str:
        return self.manifest.plugin_id

    @property
    def trust(self) -> TrustLevel:
        return self.manifest.trust

    def registry(self, name: str) -> ReadOnlyRegistry:
        """Return a read-only view of contributions already published by dependencies."""

        return ReadOnlyRegistry(self._registries.registry(name))

    def register(
        self,
        registry: str,
        key: str,
        value: Any,
        *,
        executable: bool = False,
        execution_mode: ExecutionMode | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> StagedRegistration:
        record = StagedRegistration(
            registry=registry,
            key=key,
            value=value,
            owner=self._owner,
            metadata=RegistrationMetadata(
                executable=executable,
                execution_mode=execution_mode,
                attributes=attributes or {},
            ),
        )
        with self._lock:
            if self._sealed:
                raise PluginStateError("plugin context has already been sealed")
            # Validate through the same atomic publisher on commit. This list remains
            # private so an activator cannot publish a partial batch by accident.
            self._staged.append(record)
        return record

    def resolve(self, registry: str, key: str, default: Any = None) -> Any:
        with self._lock:
            for record in reversed(self._staged):
                if record.registry == registry and record.key == key:
                    return record.value
        return self._registries.registry(registry).get(key, default)

    def effect(self, cleanup: Callable[[], object] | EffectHandle) -> EffectHandle:
        return self._effects.add(cleanup)

    defer = effect

    def _seal(self) -> tuple[StagedRegistration, ...]:
        with self._lock:
            self._sealed = True
            return tuple(self._staged)

    def _discard(self) -> None:
        with self._lock:
            self._sealed = True
            self._staged.clear()
