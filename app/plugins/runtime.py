"""AegisAl's process-local plugin composition and lifecycle runtime."""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from threading import Condition, RLock
from types import MappingProxyType
from typing import Any, Protocol

from .context import PluginContext
from .effects import EffectCleanupError, EffectHandle, EffectScope
from .errors import (
    DrainTimeoutError,
    PluginActivationError,
    PluginDependencyError,
    PluginNotFoundError,
    PluginRuntimeError,
    PluginSecurityError,
    PluginStateError,
)
from .models import ExecutionMode, PluginManifest, PluginSnapshot, PluginState, TrustLevel
from .registry import Registry, RegistryEntry, RegistryHub


class PluginActivator(Protocol):
    def __call__(self, context: PluginContext) -> object: ...


TrustVerifier = Callable[[PluginManifest], bool]


@dataclass(frozen=True, slots=True)
class DeclarativeContribution:
    registry: str
    key: str
    value: Any
    executable: bool = False
    execution_mode: ExecutionMode | None = None
    attributes: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class DeclarativePlugin:
    """Host-owned activator for parsed data; plugin Python is never imported."""

    contributions: tuple[DeclarativeContribution, ...]

    def activate(self, context: PluginContext) -> None:
        for contribution in self.contributions:
            context.register(
                contribution.registry,
                contribution.key,
                contribution.value,
                executable=contribution.executable,
                execution_mode=contribution.execution_mode,
                attributes=contribution.attributes,
            )


@dataclass(slots=True)
class _PluginRecord:
    manifest: PluginManifest
    activator: PluginActivator | object
    state: PluginState = PluginState.DISCOVERED
    generation: int = 0
    scope: EffectScope | None = None
    context: PluginContext | None = None
    active_leases: int = 0
    last_error: BaseException | None = None

    def snapshot(self) -> PluginSnapshot:
        return PluginSnapshot(
            plugin_id=self.manifest.plugin_id,
            version=self.manifest.version,
            trust=self.manifest.trust,
            state=self.state,
            config_hash=self.manifest.config_hash,
            generation=self.generation,
        )


@dataclass(frozen=True, slots=True)
class GenerationSnapshot:
    """An immutable registry and plugin view suitable for task/checkpoint pinning."""

    generation: int
    plugins: Mapping[str, PluginSnapshot]
    registries: Mapping[str, Mapping[str, RegistryEntry]]

    def resolve(self, registry: str, key: str, default: Any = None) -> Any:
        entry = self.registries.get(registry, {}).get(key)
        return default if entry is None else entry.value


class GenerationLease(AbstractContextManager[GenerationSnapshot]):
    """Pins selected active plugins until the caller leaves the context."""

    def __init__(self, manager: PluginManager, plugin_ids: tuple[str, ...] | None) -> None:
        self._manager = manager
        self._plugin_ids = plugin_ids
        self._acquired_ids: tuple[str, ...] = ()
        self._snapshot: GenerationSnapshot | None = None

    def __enter__(self) -> GenerationSnapshot:
        if self._snapshot is not None:
            raise PluginStateError("generation lease cannot be entered more than once")
        acquired, snapshot = self._manager._acquire_generation(self._plugin_ids)
        self._acquired_ids = acquired
        self._snapshot = snapshot
        return snapshot

    def __exit__(self, *_: object) -> None:
        acquired = self._acquired_ids
        self._acquired_ids = ()
        if acquired:
            self._manager._release_generation(acquired)


class PluginManager:
    """
    Loads Python plugin adapters while keeping contributions transactional.

    Third-party executable code is expected to live behind stdio or Streamable
    HTTP adapters. The registry policy prevents untrusted plugins from publishing
    an in-process executable contribution.
    """

    def __init__(
        self,
        *,
        registries: RegistryHub | None = None,
        trust_verifier: TrustVerifier | None = None,
    ) -> None:
        self.registries = registries or RegistryHub()
        self._trust_verifier = trust_verifier
        self._condition = Condition(RLock())
        self._operation_lock = RLock()
        self._plugins: dict[str, _PluginRecord] = {}
        self._generation = 0

    @property
    def generation(self) -> int:
        with self._condition:
            return self._generation

    def registry(self, name: str) -> Registry:
        return self.registries.registry(name)

    def discover(
        self, manifest: PluginManifest | Mapping[str, Any], activator: PluginActivator | object
    ) -> PluginSnapshot:
        parsed = (
            manifest if isinstance(manifest, PluginManifest) else PluginManifest.from_dict(manifest)
        )
        if parsed.trust is TrustLevel.UNTRUSTED and type(activator) is not DeclarativePlugin:
            raise PluginSecurityError(
                f"untrusted plugin {parsed.plugin_id!r} cannot execute a Python activator; "
                "register its capabilities through a Host-owned stdio or Streamable HTTP adapter"
            )
        if parsed.trust is TrustLevel.SIGNED:
            if not parsed.signature:
                raise PluginSecurityError(
                    f"signed plugin {parsed.plugin_id!r} has no manifest signature"
                )
            if self._trust_verifier is None or not self._trust_verifier(parsed):
                raise PluginSecurityError(
                    f"signature verification failed for plugin {parsed.plugin_id!r}"
                )
        if not callable(activator) and not callable(getattr(activator, "activate", None)):
            raise TypeError("plugin activator must be callable or expose activate(context)")

        with self._operation_lock, self._condition:
            existing = self._plugins.get(parsed.plugin_id)
            if existing is not None and existing.state not in {
                PluginState.DISPOSED,
                PluginState.FAILED,
            }:
                raise PluginStateError(
                    f"plugin {parsed.plugin_id!r} is already {existing.state.value}"
                )
            record = _PluginRecord(manifest=parsed, activator=activator)
            self._plugins[parsed.plugin_id] = record
            return record.snapshot()

    register = discover

    def status(self, plugin_id: str) -> PluginSnapshot:
        with self._condition:
            return self._get_record_locked(plugin_id).snapshot()

    def statuses(self) -> Mapping[str, PluginSnapshot]:
        with self._condition:
            return MappingProxyType(
                {plugin_id: record.snapshot() for plugin_id, record in self._plugins.items()}
            )

    def load(self, plugin_id: str) -> PluginSnapshot:
        self.load_many((plugin_id,))
        return self.status(plugin_id)

    activate = load

    def load_all(self) -> tuple[PluginSnapshot, ...]:
        with self._condition:
            plugin_ids = tuple(sorted(self._plugins))
        return self.load_many(plugin_ids)

    def load_many(self, plugin_ids: Iterable[str]) -> tuple[PluginSnapshot, ...]:
        requested = tuple(dict.fromkeys(plugin_ids))
        with self._operation_lock:
            with self._condition:
                order = self._dependency_order_locked(requested)
            activated: list[str] = []
            try:
                for current_id in order:
                    with self._condition:
                        record = self._get_record_locked(current_id)
                        if record.state is PluginState.ACTIVE:
                            continue
                    self._activate_one(current_id)
                    activated.append(current_id)
            except BaseException as activation_error:
                rollback_errors: list[BaseException] = []
                for activated_id in reversed(activated):
                    try:
                        self._unload_one(activated_id, timeout=0.0)
                    except BaseException as rollback_error:
                        rollback_errors.append(rollback_error)
                if rollback_errors and hasattr(activation_error, "add_note"):
                    activation_error.add_note(
                        "rollback cleanup failures: "
                        + "; ".join(str(error) for error in rollback_errors)
                    )
                raise
            return tuple(self.status(plugin_id) for plugin_id in requested)

    def unload(
        self,
        plugin_id: str,
        *,
        timeout: float | None = None,
        cascade: bool = False,
    ) -> tuple[PluginSnapshot, ...]:
        if timeout is not None and timeout < 0:
            raise ValueError("drain timeout cannot be negative")
        with self._operation_lock:
            with self._condition:
                self._get_record_locked(plugin_id)
                dependents = self._active_dependents_order_locked(plugin_id)
                if dependents and not cascade:
                    raise PluginDependencyError(
                        f"cannot unload plugin {plugin_id!r}; active dependents: "
                        + ", ".join(dependents)
                    )
                order = tuple(dependents) + (plugin_id,)

            deadline = None if timeout is None else time.monotonic() + timeout
            snapshots: list[PluginSnapshot] = []
            for current_id in order:
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                snapshots.append(self._unload_one(current_id, timeout=remaining))
            return tuple(snapshots)

    dispose = unload

    def snapshot(self) -> GenerationSnapshot:
        with self._condition:
            return self._snapshot_locked()

    def pin_generation(
        self, plugin_ids: str | Iterable[str] | None = None
    ) -> GenerationLease:
        if isinstance(plugin_ids, str):
            normalized: tuple[str, ...] | None = (plugin_ids,)
        elif plugin_ids is None:
            normalized = None
        else:
            normalized = tuple(dict.fromkeys(plugin_ids))
        return GenerationLease(self, normalized)

    lease = pin_generation

    def _activate_one(self, plugin_id: str) -> None:
        with self._condition:
            record = self._get_record_locked(plugin_id)
            if record.state is PluginState.ACTIVE:
                return
            if record.state is PluginState.DRAINING:
                raise PluginStateError(f"plugin {plugin_id!r} is draining")
            for dependency in record.manifest.dependencies:
                dependency_record = self._plugins.get(dependency.plugin_id)
                if dependency_record is None:
                    if dependency.optional:
                        continue
                    raise PluginDependencyError(
                        f"plugin {plugin_id!r} requires missing plugin "
                        f"{dependency.plugin_id!r}"
                    )
                if dependency_record.state is not PluginState.ACTIVE:
                    if dependency.optional:
                        continue
                    raise PluginDependencyError(
                        f"dependency {dependency.plugin_id!r} is not active"
                    )
            record.state = PluginState.LOADING
            record.last_error = None
            proposed_generation = self._generation + 1
            scope = EffectScope()
            context = PluginContext(
                record.manifest,
                self.registries,
                scope,
                proposed_generation,
            )
            record.scope = scope
            record.context = context

        try:
            result = self._invoke_activator(record.activator, context)
            if result is not None:
                cleanup = self._coerce_cleanup(result)
                scope.add(cleanup)
            staged = context._seal()
            handles = self.registries.publish(staged)
            for handle in handles:
                scope.add(handle.revoke)
        except BaseException as cause:
            context._discard()
            self.registries.revoke_owner(plugin_id, proposed_generation)
            try:
                scope.close()
            except EffectCleanupError as cleanup_error:
                if hasattr(cause, "add_note"):
                    cause.add_note(f"activation rollback cleanup failed: {cleanup_error}")
            with self._condition:
                record.state = PluginState.FAILED
                record.last_error = cause
                record.scope = None
                record.context = None
                self._condition.notify_all()
            raise PluginActivationError(plugin_id, cause) from cause

        with self._condition:
            self._generation = proposed_generation
            record.generation = proposed_generation
            record.state = PluginState.ACTIVE
            self._condition.notify_all()

    def _unload_one(self, plugin_id: str, *, timeout: float | None) -> PluginSnapshot:
        with self._condition:
            record = self._get_record_locked(plugin_id)
            if record.state in {PluginState.DISCOVERED, PluginState.FAILED}:
                record.state = PluginState.DISPOSED
                record.scope = None
                record.context = None
                return record.snapshot()
            if record.state is PluginState.DISPOSED:
                return record.snapshot()
            if record.state is PluginState.LOADING:
                raise PluginStateError(f"plugin {plugin_id!r} is still loading")
            if record.state is PluginState.ACTIVE:
                record.state = PluginState.DRAINING
                self.registries.revoke_owner(plugin_id, record.generation)
                # A generation changes when an active plugin disappears, even if it
                # happened to publish no registry entries.
                self._generation += 1
                self._condition.notify_all()

            deadline = None if timeout is None else time.monotonic() + timeout
            while record.active_leases:
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._condition.wait(timeout=remaining):
                    raise DrainTimeoutError(plugin_id, record.active_leases)
            scope = record.scope
            record.scope = None
            record.context = None

        try:
            if scope is not None:
                scope.close()
        except EffectCleanupError as cause:
            with self._condition:
                record.state = PluginState.FAILED
                record.last_error = cause
                self._condition.notify_all()
            raise

        with self._condition:
            record.state = PluginState.DISPOSED
            record.last_error = None
            self._condition.notify_all()
            return record.snapshot()

    def _dependency_order_locked(self, plugin_ids: tuple[str, ...]) -> tuple[str, ...]:
        order: list[str] = []
        permanent: set[str] = set()
        visiting: list[str] = []

        def visit(plugin_id: str) -> None:
            if plugin_id in permanent:
                return
            if plugin_id in visiting:
                cycle = visiting[visiting.index(plugin_id) :] + [plugin_id]
                raise PluginDependencyError("plugin dependency cycle: " + " -> ".join(cycle))
            record = self._plugins.get(plugin_id)
            if record is None:
                raise PluginNotFoundError(f"plugin {plugin_id!r} was not discovered")
            if record.state is PluginState.DRAINING:
                raise PluginStateError(f"plugin {plugin_id!r} is draining")
            visiting.append(plugin_id)
            for dependency in record.manifest.dependencies:
                dependency_record = self._plugins.get(dependency.plugin_id)
                if dependency_record is None:
                    if dependency.optional:
                        continue
                    raise PluginDependencyError(
                        f"plugin {plugin_id!r} requires missing plugin "
                        f"{dependency.plugin_id!r}"
                    )
                if not dependency.accepts(dependency_record.manifest.parsed_version):
                    raise PluginDependencyError(
                        f"plugin {plugin_id!r} requires {dependency.plugin_id!r} "
                        f"{dependency.version or '*'}, found "
                        f"{dependency_record.manifest.version}"
                    )
                visit(dependency.plugin_id)
            visiting.pop()
            permanent.add(plugin_id)
            order.append(plugin_id)

        for plugin_id in plugin_ids:
            visit(plugin_id)
        return tuple(order)

    def _active_dependents_order_locked(self, plugin_id: str) -> tuple[str, ...]:
        ordered: list[str] = []
        seen: set[str] = set()

        def visit(dependency_id: str) -> None:
            for candidate_id, candidate in self._plugins.items():
                if candidate_id in seen or candidate.state is not PluginState.ACTIVE:
                    continue
                if any(
                    dependency.plugin_id == dependency_id
                    for dependency in candidate.manifest.dependencies
                ):
                    seen.add(candidate_id)
                    visit(candidate_id)
                    ordered.append(candidate_id)

        visit(plugin_id)
        return tuple(ordered)

    def _acquire_generation(
        self, plugin_ids: tuple[str, ...] | None
    ) -> tuple[tuple[str, ...], GenerationSnapshot]:
        with self._condition:
            selected = (
                tuple(
                    plugin_id
                    for plugin_id, record in self._plugins.items()
                    if record.state is PluginState.ACTIVE
                )
                if plugin_ids is None
                else plugin_ids
            )
            if plugin_ids is not None:
                selected = self._dependency_closure_locked(selected)
            records = [self._get_record_locked(plugin_id) for plugin_id in selected]
            inactive = [
                record.manifest.plugin_id
                for record in records
                if record.state is not PluginState.ACTIVE
            ]
            if inactive:
                raise PluginStateError(
                    "cannot lease inactive plugin(s): " + ", ".join(inactive)
                )
            for record in records:
                record.active_leases += 1
            return selected, self._snapshot_locked(frozenset(selected))

    def _release_generation(self, plugin_ids: tuple[str, ...]) -> None:
        with self._condition:
            for plugin_id in plugin_ids:
                record = self._get_record_locked(plugin_id)
                if record.active_leases <= 0:
                    raise PluginRuntimeError(
                        f"plugin {plugin_id!r} generation lease underflow"
                    )
                record.active_leases -= 1
            self._condition.notify_all()

    def _dependency_closure_locked(self, plugin_ids: tuple[str, ...]) -> tuple[str, ...]:
        ordered: list[str] = []
        seen: set[str] = set()

        def visit(plugin_id: str) -> None:
            if plugin_id in seen:
                return
            record = self._get_record_locked(plugin_id)
            for dependency in record.manifest.dependencies:
                dependency_record = self._plugins.get(dependency.plugin_id)
                if dependency_record is None or dependency_record.state is not PluginState.ACTIVE:
                    if dependency.optional:
                        continue
                    raise PluginStateError(
                        f"cannot lease {plugin_id!r}; dependency "
                        f"{dependency.plugin_id!r} is not active"
                    )
                visit(dependency.plugin_id)
            seen.add(plugin_id)
            ordered.append(plugin_id)

        for plugin_id in plugin_ids:
            visit(plugin_id)
        return tuple(ordered)

    def _snapshot_locked(
        self, plugin_ids: frozenset[str] | None = None
    ) -> GenerationSnapshot:
        plugins = MappingProxyType(
            {
                plugin_id: record.snapshot()
                for plugin_id, record in self._plugins.items()
                if record.state is PluginState.ACTIVE
                and (plugin_ids is None or plugin_id in plugin_ids)
            }
        )
        registries = self.registries.snapshot()
        if plugin_ids is not None:
            registries = MappingProxyType(
                {
                    registry: MappingProxyType(
                        {
                            key: entry
                            for key, entry in entries.items()
                            if entry.owner.plugin_id in plugin_ids
                        }
                    )
                    for registry, entries in registries.items()
                    if any(entry.owner.plugin_id in plugin_ids for entry in entries.values())
                }
            )
        return GenerationSnapshot(
            generation=self._generation,
            plugins=plugins,
            registries=registries,
        )

    def _get_record_locked(self, plugin_id: str) -> _PluginRecord:
        try:
            return self._plugins[plugin_id]
        except KeyError as exc:
            raise PluginNotFoundError(f"plugin {plugin_id!r} was not discovered") from exc

    @staticmethod
    def _invoke_activator(activator: PluginActivator | object, context: PluginContext) -> object:
        activate = getattr(activator, "activate", None)
        if callable(activate):
            result = activate(context)
        else:
            result = activator(context)  # type: ignore[operator]
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise TypeError(
                "async plugin activators are not supported by the synchronous runtime"
            )
        return result

    @staticmethod
    def _coerce_cleanup(value: object) -> Callable[[], object] | EffectHandle:
        if isinstance(value, EffectHandle) or callable(value):
            return value
        dispose = getattr(value, "dispose", None)
        if callable(dispose):
            return dispose
        close = getattr(value, "close", None)
        if callable(close):
            return close
        raise TypeError(
            "plugin activation must return None, a cleanup callable, or an object "
            "with close()/dispose()"
        )
