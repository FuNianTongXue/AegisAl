"""Structured, lifecycle-bound Skill registry.

Skill files are data contributions. They are parsed once at plugin activation,
published atomically with the rest of the plugin, and resolved by name at the
point of use. No Skill may execute Python code or select an arbitrary file at
runtime.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import yaml

from app.plugins import (
    PluginContext,
    ReadOnlyRegistry,
    Registry,
    RegistryEntry,
    RegistryKeyError,
)


SKILL_REGISTRY = "skills"
_FRONTMATTER_BOUNDARY = "---"


@dataclass(frozen=True, slots=True)
class SkillDocument:
    name: str
    description: str
    body: str
    metadata: Mapping[str, Any]
    sha256: str


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    """One immutable SKILL.md contribution owned by a plugin generation."""

    name: str
    path: Path
    root: Path
    description: str
    sha256: str

    @classmethod
    def from_path(cls, path: Path, *, root: Path) -> "SkillDefinition":
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        try:
            resolved_path.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"Skill path escapes its plugin root: {path}") from exc
        if resolved_path.name != "SKILL.md" or not resolved_path.is_file():
            raise ValueError(f"Skill contribution must point to SKILL.md: {path}")
        document = _parse_skill(resolved_path)
        return cls(
            name=document.name,
            path=resolved_path,
            root=resolved_root,
            description=document.description,
            sha256=document.sha256,
        )

    def load(self) -> SkillDocument:
        resolved = self.path.resolve(strict=True)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"Skill path escapes its plugin root: {self.path}") from exc
        document = _parse_skill(resolved)
        if document.name != self.name or document.sha256 != self.sha256:
            raise RuntimeError(
                f"Skill contribution changed after activation: {self.name}; reload its plugin"
            )
        return document

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.name,
            "name": self.name,
            "description": self.description,
            "sha256": self.sha256,
            "source": "plugin-registry",
        }


class SkillRegistry:
    """Read-only facade used by planners and Agent prompt assemblers."""

    def __init__(
        self,
        registry: Registry | ReadOnlyRegistry | Mapping[str, RegistryEntry],
    ) -> None:
        self._registry = registry

    def _entries(self) -> Mapping[str, RegistryEntry]:
        if isinstance(self._registry, Mapping):
            return self._registry
        return self._registry.entries()

    def definition(self, name: str) -> SkillDefinition:
        key = str(name or "").strip()
        if isinstance(self._registry, Mapping):
            entry = self._registry.get(key)
            if entry is None:
                raise RegistryKeyError(f"registry {SKILL_REGISTRY!r} has no key {key!r}")
            value = entry.value
        else:
            value = self._registry.require(key)
        if not isinstance(value, SkillDefinition):
            raise TypeError(f"Invalid Skill registry contribution: {name!r}")
        return value

    def load(self, name: str) -> SkillDocument:
        return self.definition(name).load()

    def catalog(self) -> list[dict[str, Any]]:
        definitions = []
        for key, entry in self._entries().items():
            value = entry.value
            if not isinstance(value, SkillDefinition):
                continue
            item = value.as_dict()
            item.update(
                {
                    "plugin_id": entry.owner.plugin_id,
                    "plugin_version": entry.owner.version,
                    "generation": entry.owner.generation,
                }
            )
            definitions.append((key, item))
        return [item for _, item in sorted(definitions, key=lambda pair: pair[0])]


def activate_builtin_skills(context: PluginContext) -> None:
    """Publish every packaged SKILL.md as one atomic plugin contribution."""

    root = Path(__file__).resolve().parents[1] / "resources" / "skills"
    definitions: list[SkillDefinition] = []
    for path in sorted(root.glob("*/SKILL.md")):
        definitions.append(SkillDefinition.from_path(path, root=root))
    if not definitions:
        raise RuntimeError("No packaged AegisAl skills were discovered")
    names = [definition.name for definition in definitions]
    if len(names) != len(set(names)):
        raise ValueError("Packaged Skill names must be unique")
    for definition in definitions:
        context.register(
            SKILL_REGISTRY,
            definition.name,
            definition,
            executable=False,
            attributes={
                "description": definition.description,
                "sha256": definition.sha256,
            },
        )


def builtin_skill_fingerprints() -> dict[str, str]:
    """Return the packaged Skill content hashes used by the plugin task pin."""

    root = Path(__file__).resolve().parents[1] / "resources" / "skills"
    return {
        definition.name: definition.sha256
        for definition in (
            SkillDefinition.from_path(path, root=root)
            for path in sorted(root.glob("*/SKILL.md"))
        )
    }


def default_skill_registry() -> SkillRegistry:
    # The import stays lazy so plugin composition can activate Skill
    # contributions without creating a module import cycle.
    from app.composition import secflow_runtime

    return SkillRegistry(ReadOnlyRegistry(secflow_runtime().manager.registry(SKILL_REGISTRY)))


def load_skill(name: str) -> str:
    return default_skill_registry().load(name).body


def skill_metadata(name: str, *, prompt_version: str = "") -> dict[str, str]:
    document = default_skill_registry().load(name)
    result = {"name": document.name, "sha256": document.sha256}
    if prompt_version:
        result["prompt_version"] = prompt_version
    return result


def _parse_skill(path: Path) -> SkillDocument:
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    if not lines or lines[0].strip() != _FRONTMATTER_BOUNDARY:
        raise ValueError(f"Skill frontmatter is missing: {path}")
    try:
        end = next(
            index
            for index, line in enumerate(lines[1:], start=1)
            if line.strip() == _FRONTMATTER_BOUNDARY
        )
    except StopIteration as exc:
        raise ValueError(f"Skill frontmatter is not terminated: {path}") from exc
    try:
        metadata_value = yaml.safe_load("\n".join(lines[1:end])) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Skill frontmatter is invalid YAML: {path}") from exc
    if not isinstance(metadata_value, dict):
        raise ValueError(f"Skill frontmatter must be an object: {path}")
    name = str(metadata_value.get("name") or "").strip()
    description = str(metadata_value.get("description") or "").strip()
    body = "\n".join(lines[end + 1 :]).strip()
    if not name or not description or not body:
        raise ValueError(f"Skill requires name, description, and body: {path}")
    metadata = _freeze_value(metadata_value)
    return SkillDocument(
        name=name,
        description=description,
        body=body,
        metadata=metadata,
        sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )


def _freeze_value(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({str(key): _freeze_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_value(item) for item in value)
    return value
