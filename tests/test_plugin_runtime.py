from __future__ import annotations

import threading
import time
from types import MappingProxyType

import pytest

from app.plugins import (
    DeclarativeContribution,
    DeclarativePlugin,
    DrainTimeoutError,
    EffectCleanupError,
    EffectScope,
    EffectScopeClosedError,
    ExecutionMode,
    ManifestError,
    PluginActivationError,
    PluginDependency,
    PluginDependencyError,
    PluginManager,
    PluginManifest,
    PluginSecurityError,
    PluginState,
    PluginStateError,
    RegistrationOwner,
    RegistryConflictError,
    RegistryHub,
    TrustLevel,
)


def manifest(
    plugin_id: str,
    *,
    version: str = "1.0.0",
    trust: TrustLevel = TrustLevel.BUILTIN,
    dependencies: tuple[PluginDependency, ...] = (),
    signature: str | None = None,
    config: dict | None = None,
) -> PluginManifest:
    return PluginManifest(
        plugin_id=plugin_id,
        version=version,
        trust=trust,
        dependencies=dependencies,
        signature=signature,
        config=config or {},
    )


def test_manifest_is_versioned_validated_and_deeply_immutable() -> None:
    plugin = PluginManifest.from_dict(
        {
            "schema_version": "secflow.plugin/v1",
            "id": "secflow.report",
            "version": "1.2.3",
            "trust": "builtin",
            "requires": [{"id": "secflow.core", "version": ">=1,<2"}],
            "config": {"nested": {"enabled": True}, "items": [1, 2]},
        }
    )

    assert plugin.parsed_version.public == "1.2.3"
    assert plugin.dependencies[0].accepts("1.9.0")
    assert not plugin.dependencies[0].accepts("2.0.0")
    assert isinstance(plugin.config, MappingProxyType)
    assert isinstance(plugin.config["nested"], MappingProxyType)
    assert plugin.config["items"] == (1, 2)
    assert len(plugin.config_hash) == 64

    with pytest.raises(TypeError):
        plugin.config["new"] = True
    with pytest.raises(ManifestError):
        manifest("INVALID ID")
    with pytest.raises(ManifestError):
        PluginManifest("valid", "not a version")
    with pytest.raises(ManifestError):
        PluginManifest("valid", "1.0", schema_version="secflow.plugin/v2")


def test_effect_scope_cleans_up_in_reverse_and_continues_after_failures() -> None:
    events: list[str] = []
    scope = EffectScope()
    scope.add(lambda: events.append("first"))

    def broken() -> None:
        events.append("broken")
        raise RuntimeError("cleanup failed")

    scope.add(broken)
    scope.add(lambda: events.append("last"))

    with pytest.raises(EffectCleanupError) as raised:
        scope.close()

    assert events == ["last", "broken", "first"]
    assert len(raised.value.failures) == 1
    with pytest.raises(EffectCleanupError):
        scope.close()
    with pytest.raises(EffectScopeClosedError):
        scope.add(lambda: None)


def test_registry_batch_publish_is_atomic_and_handles_are_revocable() -> None:
    hub = RegistryHub()
    owner = RegistrationOwner("builtin", "1.0.0", TrustLevel.BUILTIN, 1)
    services = hub.registry("services")
    original = services.register("existing", object(), owner=owner)

    from app.plugins import RegistrationMetadata, StagedRegistration

    staged = (
        StagedRegistration("services", "new", 1, owner),
        StagedRegistration("services", "existing", 2, owner),
    )
    with pytest.raises(RegistryConflictError):
        hub.publish(staged)

    assert services.get("new") is None
    assert original.revoke()
    assert not original.revoke()
    assert services.get("existing") is None

    handles = hub.publish(
        (
            StagedRegistration(
                "services", "one", 1, owner, RegistrationMetadata()
            ),
            StagedRegistration(
                "settings", "two", 2, owner, RegistrationMetadata()
            ),
        )
    )
    assert len(handles) == 2
    assert hub.revoke_owner("builtin", generation=1) == 2
    assert not hub.snapshot()


def test_activation_stages_then_atomically_publishes_and_unload_revokes() -> None:
    manager = PluginManager()
    observed: list[object] = []
    cleanup: list[str] = []

    def activate(context) -> None:
        context.register("services", "answer", 42)
        context.register("settings", "feature", True)
        observed.append(manager.registry("services").get("answer"))
        context.effect(lambda: cleanup.append("disposed"))

    manager.discover(manifest("secflow.feature"), activate)
    loaded = manager.load("secflow.feature")

    assert observed == [None]
    assert loaded.state is PluginState.ACTIVE
    assert manager.registry("services").require("answer") == 42
    assert manager.snapshot().resolve("settings", "feature") is True

    unloaded = manager.unload("secflow.feature")[0]
    assert unloaded.state is PluginState.DISPOSED
    assert manager.registry("services").get("answer") is None
    assert cleanup == ["disposed"]


def test_activation_failure_discards_staged_entries_and_rolls_back_effects() -> None:
    manager = PluginManager()
    cleanup: list[str] = []

    def activate(context) -> None:
        context.register("services", "partial", "must-not-leak")
        context.effect(lambda: cleanup.append("rolled-back"))
        raise ValueError("bad configuration")

    manager.discover(manifest("secflow.broken"), activate)

    with pytest.raises(PluginActivationError) as raised:
        manager.load("secflow.broken")

    assert isinstance(raised.value.cause, ValueError)
    assert manager.status("secflow.broken").state is PluginState.FAILED
    assert manager.registry("services").get("partial") is None
    assert cleanup == ["rolled-back"]


def test_publish_conflict_rolls_back_entire_plugin_batch() -> None:
    manager = PluginManager()

    def owner(context) -> None:
        context.register("services", "shared", "owner")

    manager.discover(
        manifest("secflow.owner"),
        owner,
    )
    manager.load("secflow.owner")

    def conflicting(context) -> None:
        context.register("services", "unique", "partial")
        context.register("services", "shared", "conflict")

    manager.discover(manifest("secflow.conflict"), conflicting)
    with pytest.raises(PluginActivationError) as raised:
        manager.load("secflow.conflict")

    assert isinstance(raised.value.cause, RegistryConflictError)
    assert manager.registry("services").get("unique") is None
    assert manager.registry("services").get("shared") == "owner"


def test_dependencies_load_in_topological_order_and_versions_are_enforced() -> None:
    events: list[str] = []
    manager = PluginManager()
    manager.discover(
        manifest("secflow.base", version="1.5.0"),
        lambda context: events.append("base"),
    )
    manager.discover(
        manifest(
            "secflow.child",
            dependencies=(PluginDependency("secflow.base", ">=1,<2"),),
        ),
        lambda context: events.append("child"),
    )

    manager.load("secflow.child")
    assert events == ["base", "child"]

    incompatible = PluginManager()
    incompatible.discover(manifest("secflow.base", version="2.0.0"), lambda context: None)
    incompatible.discover(
        manifest(
            "secflow.child",
            dependencies=(PluginDependency("secflow.base", "<2"),),
        ),
        lambda context: None,
    )
    with pytest.raises(PluginDependencyError, match="found 2.0.0"):
        incompatible.load("secflow.child")


def test_dependency_cycle_and_missing_dependency_are_reported() -> None:
    cyclic = PluginManager()
    cyclic.discover(
        manifest("plugin.a", dependencies=(PluginDependency("plugin.b"),)),
        lambda context: None,
    )
    cyclic.discover(
        manifest("plugin.b", dependencies=(PluginDependency("plugin.a"),)),
        lambda context: None,
    )
    with pytest.raises(PluginDependencyError, match="plugin.a -> plugin.b -> plugin.a"):
        cyclic.load("plugin.a")

    missing = PluginManager()
    missing.discover(
        manifest("plugin.a", dependencies=(PluginDependency("plugin.missing"),)),
        lambda context: None,
    )
    with pytest.raises(PluginDependencyError, match="missing plugin"):
        missing.load("plugin.a")


def test_failed_batch_rolls_back_dependencies_loaded_by_the_batch() -> None:
    manager = PluginManager()
    cleanup: list[str] = []

    def base(context) -> None:
        context.register("services", "base", True)
        context.effect(lambda: cleanup.append("base"))

    manager.discover(manifest("plugin.base"), base)
    manager.discover(
        manifest("plugin.child", dependencies=(PluginDependency("plugin.base"),)),
        lambda context: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(PluginActivationError):
        manager.load("plugin.child")

    assert manager.status("plugin.base").state is PluginState.DISPOSED
    assert manager.registry("services").get("base") is None
    assert cleanup == ["base"]


def test_untrusted_plugins_cannot_publish_in_process_executables() -> None:
    manager = PluginManager()

    def dangerous(context) -> None:
        context.register(
            "tools",
            "dangerous",
            lambda: "executed in host",
            executable=True,
            execution_mode=ExecutionMode.IN_PROCESS,
        )

    with pytest.raises(PluginSecurityError):
        manager.discover(
            manifest("third.party", trust=TrustLevel.UNTRUSTED),
            dangerous,
        )
    assert manager.registry("tools").get("dangerous") is None

    # A declarative proxy to an isolated stdio process is allowed.
    safe = PluginManager()

    safe.discover(
        manifest("third.party", trust=TrustLevel.UNTRUSTED),
        DeclarativePlugin(
            (
                DeclarativeContribution(
                    registry="tools",
                    key="isolated",
                    value={"server": "scanner"},
                    executable=True,
                    execution_mode=ExecutionMode.STDIO,
                ),
            )
        ),
    )
    safe.load("third.party")
    assert safe.registry("tools").require("isolated") == {"server": "scanner"}
    metadata = safe.registry("tools").get_entry("isolated").metadata
    assert metadata.executable is True
    assert metadata.execution_mode is ExecutionMode.STDIO


def test_registry_policy_cannot_be_bypassed_by_omitting_executable_flag() -> None:
    hub = RegistryHub()
    untrusted = RegistrationOwner("third.party", "1.0", "untrusted", 1)

    with pytest.raises(PluginSecurityError):
        hub.registry("agents").register("agent", object(), owner=untrusted)
    with pytest.raises(PluginSecurityError):
        hub.registry("other").register("callable", lambda: None, owner=untrusted)
    with pytest.raises(PluginSecurityError, match="only accepts Host in-process"):
        hub.registry("agents").register(
            "spoofed-agent",
            object(),
            owner=untrusted,
            executable=True,
            execution_mode=ExecutionMode.STDIO,
        )


def test_signed_plugins_require_a_signature_and_verification() -> None:
    signed = manifest("signed.plugin", trust=TrustLevel.SIGNED, signature="signature")
    with pytest.raises(PluginSecurityError, match="verification failed"):
        PluginManager().discover(signed, lambda context: None)

    manager = PluginManager(trust_verifier=lambda candidate: candidate.signature == "signature")
    manager.discover(signed, lambda context: None)
    assert manager.load("signed.plugin").state is PluginState.ACTIVE

    unsigned = manifest("unsigned.plugin", trust=TrustLevel.SIGNED)
    with pytest.raises(PluginSecurityError, match="no manifest signature"):
        manager.discover(unsigned, lambda context: None)


def test_generation_snapshot_is_immutable_and_records_runtime_identity() -> None:
    manager = PluginManager()

    def activate(context) -> None:
        context.register("services", "value", 7)

    manager.discover(
        manifest("secflow.snapshot", config={"mode": "strict"}),
        activate,
    )
    loaded = manager.load("secflow.snapshot")
    snapshot = manager.snapshot()

    assert snapshot.generation == loaded.generation
    assert snapshot.resolve("services", "value") == 7
    assert snapshot.plugins["secflow.snapshot"].config_hash == manifest(
        "secflow.snapshot", config={"mode": "strict"}
    ).config_hash
    with pytest.raises(TypeError):
        snapshot.plugins["other"] = loaded

    manager.unload("secflow.snapshot")
    assert manager.generation > snapshot.generation
    assert snapshot.resolve("services", "value") == 7
    assert manager.snapshot().resolve("services", "value") is None


def test_explicit_generation_lease_includes_dependencies_and_excludes_unrelated_plugins() -> None:
    manager = PluginManager()

    def register_value(key: str):
        def activate(context) -> None:
            context.register("services", key, key)

        return activate

    manager.discover(manifest("plugin.base"), register_value("base"))
    manager.discover(
        manifest("plugin.child", dependencies=(PluginDependency("plugin.base"),)),
        register_value("child"),
    )
    manager.discover(manifest("plugin.unrelated"), register_value("unrelated"))
    manager.load("plugin.child")
    manager.load("plugin.unrelated")

    with manager.pin_generation("plugin.child") as snapshot:
        assert set(snapshot.plugins) == {"plugin.base", "plugin.child"}
        assert snapshot.resolve("services", "base") == "base"
        assert snapshot.resolve("services", "child") == "child"
        assert snapshot.resolve("services", "unrelated") is None


def test_unload_withdraws_contributions_then_waits_for_generation_leases() -> None:
    manager = PluginManager()
    cleaned = threading.Event()
    manager.discover(
        manifest("secflow.leased"),
        lambda context: (
            context.register("services", "leased", True),
            context.effect(cleaned.set),
        )[-1],
    )
    manager.load("secflow.leased")

    lease = manager.pin_generation("secflow.leased")
    lease.__enter__()
    errors: list[BaseException] = []

    def unload() -> None:
        try:
            manager.unload("secflow.leased", timeout=2)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=unload)
    thread.start()
    deadline = time.monotonic() + 1
    while manager.status("secflow.leased").state is not PluginState.DRAINING:
        assert time.monotonic() < deadline
        time.sleep(0.005)

    assert manager.registry("services").get("leased") is None
    assert not cleaned.is_set()
    with pytest.raises(PluginStateError):
        with manager.pin_generation("secflow.leased"):
            pass

    lease.__exit__(None, None, None)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert not errors
    assert cleaned.is_set()
    assert manager.status("secflow.leased").state is PluginState.DISPOSED


def test_drain_timeout_is_retryable_and_leaves_plugin_unpublished() -> None:
    manager = PluginManager()

    def activate(context) -> None:
        context.register("services", "timeout", True)

    manager.discover(
        manifest("secflow.timeout"),
        activate,
    )
    manager.load("secflow.timeout")

    lease = manager.pin_generation("secflow.timeout")
    lease.__enter__()
    with pytest.raises(DrainTimeoutError):
        manager.unload("secflow.timeout", timeout=0)

    assert manager.status("secflow.timeout").state is PluginState.DRAINING
    assert manager.registry("services").get("timeout") is None
    lease.__exit__(None, None, None)
    assert manager.unload("secflow.timeout", timeout=0)[0].state is PluginState.DISPOSED


def test_dependents_require_cascade_and_are_disposed_first() -> None:
    manager = PluginManager()
    disposed: list[str] = []
    manager.discover(
        manifest("plugin.base"), lambda context: context.effect(lambda: disposed.append("base"))
    )
    manager.discover(
        manifest("plugin.child", dependencies=(PluginDependency("plugin.base"),)),
        lambda context: context.effect(lambda: disposed.append("child")),
    )
    manager.load("plugin.child")

    with pytest.raises(PluginDependencyError, match="active dependents"):
        manager.unload("plugin.base")

    result = manager.unload("plugin.base", cascade=True)
    assert [item.plugin_id for item in result] == ["plugin.child", "plugin.base"]
    assert disposed == ["child", "base"]
