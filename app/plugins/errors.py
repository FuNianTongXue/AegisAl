"""Errors raised by the SecFlow plugin runtime."""

from __future__ import annotations

from collections.abc import Sequence


class PluginRuntimeError(RuntimeError):
    """Base class for plugin runtime failures."""


class ManifestError(PluginRuntimeError, ValueError):
    """A plugin manifest is invalid."""


class PluginNotFoundError(PluginRuntimeError, LookupError):
    """A requested plugin has not been discovered."""


class PluginStateError(PluginRuntimeError):
    """An operation is not valid for the plugin's current state."""


class PluginDependencyError(PluginRuntimeError):
    """A plugin dependency is missing, incompatible, cyclic, or in use."""


class RegistryError(PluginRuntimeError):
    """Base class for registry failures."""


class RegistryConflictError(RegistryError):
    """A contribution conflicts with an already published key."""


class RegistryKeyError(RegistryError, KeyError):
    """A contribution key does not exist."""


class PluginSecurityError(PluginRuntimeError, PermissionError):
    """A plugin contribution violates the runtime trust policy."""


class EffectScopeClosedError(PluginRuntimeError):
    """A cleanup was added after its effect scope started closing."""


class EffectCleanupError(PluginRuntimeError):
    """One or more effects failed while a scope was being disposed."""

    def __init__(self, failures: Sequence[BaseException]) -> None:
        self.failures = tuple(failures)
        super().__init__(
            f"{len(self.failures)} effect cleanup(s) failed: "
            + "; ".join(str(failure) for failure in self.failures)
        )


class PluginActivationError(PluginRuntimeError):
    """A plugin could not be staged and published."""

    def __init__(self, plugin_id: str, cause: BaseException) -> None:
        self.plugin_id = plugin_id
        self.cause = cause
        super().__init__(f"failed to activate plugin {plugin_id!r}: {cause}")


class DrainTimeoutError(PluginRuntimeError, TimeoutError):
    """A draining plugin still has active generation leases."""

    def __init__(self, plugin_id: str, active_leases: int) -> None:
        self.plugin_id = plugin_id
        self.active_leases = active_leases
        super().__init__(
            f"timed out draining plugin {plugin_id!r}; "
            f"{active_leases} lease(s) remain"
        )
