from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path, PurePosixPath
from typing import Any


CODE_EXTENSIONS = {
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".cs",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".swift",
    ".m",
    ".mm",
    ".sol",
}

STANDARD_IMPORT_PREFIXES = (
    "java.",
    "javax.",
    "jakarta.",
    "sun.",
    "com.sun.",
    "kotlin.",
    "scala.",
    "groovy.",
    "typing",
    "pathlib",
    "json",
    "re",
    "os",
    "sys",
    "datetime",
    "collections",
    "itertools",
    "functools",
)

JAVA_IMPORT_MAPPINGS = (
    ("org.apache.logging.log4j", "Maven", "org.apache.logging.log4j:log4j-core"),
    ("org.springframework.boot", "Maven", "org.springframework.boot:spring-boot"),
    ("org.springframework", "Maven", "org.springframework:spring-core"),
    ("com.fasterxml.jackson.databind", "Maven", "com.fasterxml.jackson.core:jackson-databind"),
    ("com.fasterxml.jackson.core", "Maven", "com.fasterxml.jackson.core:jackson-core"),
    ("org.apache.commons.lang3", "Maven", "org.apache.commons:commons-lang3"),
    ("org.apache.commons.io", "Maven", "commons-io:commons-io"),
    ("org.yaml.snakeyaml", "Maven", "org.yaml:snakeyaml"),
)

MAX_ASK_ATTACHMENTS = 300

GRADLE_VERSION_CATALOG_NAMES = {"libs.versions.toml"}
GRADLE_PROPERTIES_NAMES = {"gradle.properties"}
PYTHON_MANIFEST_NAMES = {"requirements.txt", "pyproject.toml", "pipfile", "poetry.lock"}
GO_MANIFEST_NAMES = {"go.mod", "go.sum"}
C_CPP_MANIFEST_NAMES = {"cmakelists.txt", "compile_commands.json", "conanfile.txt", "conanfile.py", "vcpkg.json"}
DOTNET_MANIFEST_NAMES = {
    "directory.packages.props",
    "directory.build.props",
    "packages.lock.json",
    "packages.config",
    "project.assets.json",
}
RUST_MANIFEST_NAMES = {"cargo.toml", "cargo.lock"}
SOLIDITY_MANIFEST_NAMES = {
    "foundry.toml",
    "remappings.txt",
    "package.json",
    "hardhat.config.js",
    "hardhat.config.ts",
    "truffle-config.js",
}
PROJECT_MANIFEST_NAMES = (
    PYTHON_MANIFEST_NAMES
    | GO_MANIFEST_NAMES
    | C_CPP_MANIFEST_NAMES
    | DOTNET_MANIFEST_NAMES
    | RUST_MANIFEST_NAMES
    | SOLIDITY_MANIFEST_NAMES
)
BUILD_MANIFEST_SOURCE_TYPES = {
    "pom",
    "gradle",
    "python_manifest",
    "go_manifest",
    "c_cpp_manifest",
    "dotnet_manifest",
    "rust_manifest",
    "solidity_manifest",
}

GRADLE_LOCAL_CONFIGURATION_HINTS = {
    "api",
    "annotationProcessor",
    "classpath",
    "compile",
    "compileOnly",
    "compileOnlyApi",
    "compileClasspath",
    "debugImplementation",
    "developmentOnly",
    "implementation",
    "jooqGenerator",
    "kapt",
    "kaptTest",
    "ksp",
    "kspTest",
    "providedCompile",
    "providedRuntime",
    "releaseImplementation",
    "runtime",
    "runtimeOnly",
    "testAnnotationProcessor",
    "testCompile",
    "testCompileOnly",
    "testImplementation",
    "testKapt",
    "testKsp",
    "testRuntime",
    "testRuntimeOnly",
}


@dataclass(frozen=True)
class GradleCatalogDependency:
    alias: str
    name: str
    version: str = ""
    source_file: str = ""
    declaration: str = ""


@dataclass(frozen=True)
class GradleDependencyContext:
    variables: dict[str, str]
    catalog_libraries: dict[str, GradleCatalogDependency]
    catalog_bundles: dict[str, list[GradleCatalogDependency]]


@dataclass(frozen=True)
class DependencyFact:
    ecosystem: str
    name: str
    version: str = ""
    source_file: str = ""
    source_type: str = "code"
    declaration: str = ""
    confidence: str = "medium"

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{self.name}|{self.version}".lower()

    def to_public_dict(self) -> dict[str, str]:
        return asdict(self)


def is_allowed_attachment_name(file_name: str) -> bool:
    path = Path(file_name)
    lowered = file_name.lower()
    return (
        lowered == "pom.xml"
        or lowered.endswith("/pom.xml")
        or is_gradle_build_file_name(file_name)
        or is_gradle_version_catalog_name(file_name)
        or is_gradle_properties_name(file_name)
        or is_python_requirements_name(file_name)
        or is_dotnet_manifest_name(file_name)
        or path.name.lower() in PROJECT_MANIFEST_NAMES
        or path.suffix.lower() in CODE_EXTENSIONS
    )


def scan_dependency_attachments(
    attachments: list[dict[str, Any]],
    max_dependencies: int | None = 80,
    *,
    include_all_attachments: bool = False,
) -> dict[str, Any]:
    dependencies: dict[str, DependencyFact] = {}
    files: list[dict[str, str]] = []
    rejected: list[str] = []
    accepted: list[tuple[str, str, str]] = []

    prioritized_attachments = sorted(attachments, key=raw_dependency_attachment_priority)
    selected_attachments = (
        prioritized_attachments
        if include_all_attachments
        else prioritized_attachments[:MAX_ASK_ATTACHMENTS]
    )
    for attachment in selected_attachments:
        file_name = str(attachment.get("file_name") or attachment.get("fileName") or "").strip()
        content = str(attachment.get("content") or "")
        if not file_name or not is_allowed_attachment_name(file_name):
            if file_name:
                rejected.append(file_name)
            continue
        kind = attachment_kind(file_name)
        files.append({"file_name": file_name, "kind": kind})
        accepted.append((file_name, content, kind))

    accepted.sort(key=lambda item: dependency_attachment_priority(item[0], item[2]))
    files.sort(key=lambda item: dependency_attachment_priority(item["file_name"], item["kind"]))
    inherited_properties, managed_versions = collect_attachment_pom_context(accepted)
    gradle_context = collect_attachment_gradle_context(accepted)
    go_contexts = collect_go_module_contexts(accepted)
    python_contexts = collect_python_requirements_contexts(accepted)
    dotnet_context = collect_dotnet_dependency_context(accepted)
    for file_name, content, kind in accepted:
        if kind == "pom":
            extracted = parse_pom_dependencies(
                file_name,
                content,
                inherited_properties=inherited_properties,
                managed_versions=managed_versions,
            )
        elif kind == "gradle":
            extracted = parse_gradle_dependencies(file_name, content, context=gradle_context)
        elif kind == "python_manifest":
            extracted = parse_python_manifest_dependencies(file_name, content)
            if not is_python_requirements_name(file_name):
                extracted = supplement_python_manifest_dependencies(file_name, extracted, python_contexts)
        elif kind == "go_manifest":
            if Path(file_name).name.lower() == "go.sum" and has_sibling_go_mod(file_name, go_contexts):
                extracted = []
            else:
                extracted = parse_go_manifest_dependencies(file_name, content)
        elif kind == "c_cpp_manifest":
            extracted = parse_c_cpp_manifest_dependencies(file_name, content)
        elif kind == "dotnet_manifest":
            extracted = parse_dotnet_manifest_dependencies(file_name, content, context=dotnet_context)
        elif kind == "rust_manifest":
            extracted = parse_rust_manifest_dependencies(file_name, content)
        elif kind == "solidity_manifest":
            extracted = parse_solidity_manifest_dependencies(file_name, content)
        else:
            extracted = parse_code_dependencies(file_name, content)
            if Path(file_name).suffix.lower() == ".go":
                extracted = normalize_go_import_dependencies(file_name, extracted, go_contexts)
            elif Path(file_name).suffix.lower() == ".py":
                extracted = normalize_python_import_dependencies(file_name, extracted, python_contexts)
        for dependency in extracted:
            component_key = f"{dependency.ecosystem}|{dependency.name}".lower()
            existing = [key for key, item in dependencies.items() if f"{item.ecosystem}|{item.name}".lower() == component_key]
            if dependency.source_type == "code" and any(dependencies[key].source_type in BUILD_MANIFEST_SOURCE_TYPES for key in existing):
                continue
            if dependency.source_type in BUILD_MANIFEST_SOURCE_TYPES:
                for key in existing:
                    if dependencies[key].source_type == "code":
                        dependencies.pop(key, None)
            dependencies.setdefault(dependency.key, dependency)
            if max_dependencies is not None and len(dependencies) >= max_dependencies:
                break

    return {
        "files": files,
        "dependencies": [dependency.to_public_dict() for dependency in dependencies.values()],
        "dependency_count": len(dependencies),
        "rejected_files": rejected,
    }


def raw_dependency_attachment_priority(attachment: dict[str, Any]) -> tuple[int, str]:
    file_name = str(attachment.get("file_name") or attachment.get("fileName") or "").strip()
    kind = attachment_kind(file_name) if file_name and is_allowed_attachment_name(file_name) else "code"
    return dependency_attachment_priority(file_name, kind)


def dependency_attachment_priority(file_name: str, kind: str) -> tuple[int, str]:
    normalized = file_name.replace("\\", "/").lower()
    basename = PurePosixPath(normalized).name
    if basename == "go.mod" or is_python_requirements_name(normalized):
        return (0, normalized)
    if kind != "code" and basename != "go.sum":
        return (1, normalized)
    if basename == "go.sum":
        return (2, normalized)
    return (3, normalized)


def is_python_requirements_name(file_name: str) -> bool:
    normalized = file_name.replace("\\", "/").lower()
    path = PurePosixPath(normalized)
    name = path.name
    return (
        name == "requirements.txt"
        or (name.startswith("requirements-") and name.endswith(".txt"))
        or ("requirements" in path.parts[:-1] and name.endswith(".txt"))
    )


def collect_python_requirements_contexts(accepted: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    for file_name, content, kind in accepted:
        if kind != "python_manifest" or not is_python_requirements_name(file_name):
            continue
        normalized = file_name.replace("\\", "/")
        contexts.append(
            {
                "directory": PurePosixPath(normalized).parent,
                "file_name": normalized,
                "requirements": parse_python_manifest_dependencies(normalized, content),
            }
        )
    return sorted(contexts, key=lambda item: len(item["directory"].parts), reverse=True)


def supplement_python_manifest_dependencies(
    file_name: str,
    dependencies: list[DependencyFact],
    contexts: list[dict[str, Any]],
) -> list[DependencyFact]:
    directory = PurePosixPath(file_name.replace("\\", "/")).parent
    requirements = [
        dependency
        for context in contexts
        if context["directory"] == directory
        for dependency in context["requirements"]
    ]
    authoritative_names = {canonical_python_package_name(item.name) for item in requirements}
    return [
        dependency
        for dependency in dependencies
        if canonical_python_package_name(dependency.name) not in authoritative_names
    ]


def normalize_python_import_dependencies(
    file_name: str,
    dependencies: list[DependencyFact],
    contexts: list[dict[str, Any]],
) -> list[DependencyFact]:
    source_path = PurePosixPath(file_name.replace("\\", "/"))
    context = next(
        (
            item
            for item in contexts
            if source_path.parent == item["directory"] or item["directory"] in source_path.parents
        ),
        None,
    )
    if context is None:
        return dependencies

    requirements: list[DependencyFact] = list(context.get("requirements") or [])
    by_name = {canonical_python_package_name(item.name): item for item in requirements}
    normalized: list[DependencyFact] = []
    for dependency in dependencies:
        requirement = by_name.get(canonical_python_package_name(dependency.name))
        if requirement is None:
            normalized.append(dependency)
            continue
        normalized.append(
            DependencyFact(
                ecosystem=requirement.ecosystem,
                name=requirement.name,
                version=requirement.version,
                source_file=requirement.source_file,
                source_type=requirement.source_type,
                declaration=f"{requirement.declaration} (imported by {file_name})",
                confidence="high",
            )
        )
    return _dedupe_manifest_facts(normalized)


def canonical_python_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip().lower())


def collect_go_module_contexts(accepted: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    for file_name, content, kind in accepted:
        if kind != "go_manifest" or Path(file_name).name.lower() != "go.mod":
            continue
        normalized = file_name.replace("\\", "/")
        module_match = re.search(r"(?m)^\s*module\s+([^\s]+)\s*$", content)
        contexts.append(
            {
                "directory": PurePosixPath(normalized).parent,
                "file_name": normalized,
                "module_path": module_match.group(1).strip() if module_match else "",
                "requirements": parse_go_manifest_dependencies(normalized, content),
            }
        )
    return sorted(contexts, key=lambda item: len(item["directory"].parts), reverse=True)


def has_sibling_go_mod(file_name: str, contexts: list[dict[str, Any]]) -> bool:
    directory = PurePosixPath(file_name.replace("\\", "/")).parent
    return any(context["directory"] == directory for context in contexts)


def normalize_go_import_dependencies(
    file_name: str,
    dependencies: list[DependencyFact],
    contexts: list[dict[str, Any]],
) -> list[DependencyFact]:
    source_path = PurePosixPath(file_name.replace("\\", "/"))
    context = next(
        (
            item
            for item in contexts
            if source_path.parent == item["directory"] or item["directory"] in source_path.parents
        ),
        None,
    )
    if context is None:
        return dependencies

    module_path = str(context.get("module_path") or "")
    requirements: list[DependencyFact] = list(context.get("requirements") or [])
    normalized: list[DependencyFact] = []
    for dependency in dependencies:
        import_path = dependency.name
        if module_path and (import_path == module_path or import_path.startswith(f"{module_path}/")):
            continue
        requirement = max(
            (
                item
                for item in requirements
                if import_path == item.name or import_path.startswith(f"{item.name}/")
            ),
            key=lambda item: len(item.name),
            default=None,
        )
        if requirement is None:
            normalized.append(dependency)
            continue
        normalized.append(
            DependencyFact(
                ecosystem=requirement.ecosystem,
                name=requirement.name,
                version=requirement.version,
                source_file=requirement.source_file,
                source_type=requirement.source_type,
                declaration=f"{requirement.declaration} (imported by {file_name})",
                confidence="high",
            )
        )
    return _dedupe_manifest_facts(normalized)


def attachment_kind(file_name: str) -> str:
    lowered = Path(file_name).name.lower()
    if lowered == "pom.xml":
        return "pom"
    if is_gradle_version_catalog_name(file_name):
        return "gradle_version_catalog"
    if is_gradle_properties_name(file_name):
        return "gradle_properties"
    if is_gradle_build_file_name(file_name):
        return "gradle"
    if is_python_requirements_name(file_name) or lowered in PYTHON_MANIFEST_NAMES:
        return "python_manifest"
    if lowered in GO_MANIFEST_NAMES:
        return "go_manifest"
    if lowered in C_CPP_MANIFEST_NAMES:
        return "c_cpp_manifest"
    if is_dotnet_manifest_name(file_name):
        return "dotnet_manifest"
    if lowered in RUST_MANIFEST_NAMES:
        return "rust_manifest"
    if lowered in SOLIDITY_MANIFEST_NAMES:
        return "solidity_manifest"
    return "code"


def is_dotnet_manifest_name(file_name: str) -> bool:
    name = Path(file_name.replace("\\", "/")).name.lower()
    return name.endswith(".csproj") or name in DOTNET_MANIFEST_NAMES


def is_gradle_build_file_name(file_name: str) -> bool:
    lowered = file_name.replace("\\", "/").lower()
    name = Path(lowered).name
    return name.endswith(".gradle") or name.endswith(".gradle.kts")


def is_gradle_version_catalog_name(file_name: str) -> bool:
    return Path(file_name.replace("\\", "/")).name.lower() in GRADLE_VERSION_CATALOG_NAMES


def is_gradle_properties_name(file_name: str) -> bool:
    return Path(file_name.replace("\\", "/")).name.lower() in GRADLE_PROPERTIES_NAMES


def parse_pom_dependencies(
    file_name: str,
    content: str,
    *,
    inherited_properties: dict[str, str] | None = None,
    managed_versions: dict[str, str] | None = None,
) -> list[DependencyFact]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    properties = dict(inherited_properties or {})
    properties.update(collect_pom_properties(root))
    effective_managed_versions = dict(managed_versions or {})
    effective_managed_versions.update(collect_pom_managed_versions(root, properties))
    result: list[DependencyFact] = []
    seen: set[str] = set()
    for dependency in declared_pom_dependencies(root):
        group_id = resolve_pom_value(child_text(dependency, "groupId"), properties)
        artifact_id = resolve_pom_value(child_text(dependency, "artifactId"), properties)
        version = resolve_pom_value(child_text(dependency, "version"), properties)
        scope = resolve_pom_value(child_text(dependency, "scope"), properties)
        if not group_id or not artifact_id:
            continue
        name = f"{group_id}:{artifact_id}"
        version = version or effective_managed_versions.get(name.lower(), "")
        version = version or inherited_parent_dependency_version(root, group_id, artifact_id, properties)
        if "${" in version:
            version = ""
        declaration = name + (f":{version}" if version else "")
        if scope:
            declaration += f" ({scope})"
        fact = DependencyFact(
            ecosystem="Maven",
            name=name,
            version=version,
            source_file=file_name,
            source_type="pom",
            declaration=declaration,
            confidence="high",
        )
        if fact.key not in seen:
            result.append(fact)
            seen.add(fact.key)
    return result


def collect_pom_properties(root: ET.Element) -> dict[str, str]:
    properties: dict[str, str] = {}
    for child in list(root):
        if local_name(child.tag) in {"groupId", "artifactId", "version"} and child.text:
            properties[f"project.{local_name(child.tag)}"] = child.text.strip()
            properties[f"pom.{local_name(child.tag)}"] = child.text.strip()
    for properties_node in direct_children(root, "properties"):
        for item in list(properties_node):
            if item.text:
                properties[local_name(item.tag)] = item.text.strip()
    parent = next(iter(direct_children(root, "parent")), None)
    if parent is not None:
        for name in ("groupId", "artifactId", "version"):
            value = child_text(parent, name)
            if value:
                properties[f"project.parent.{name}"] = value
                properties[f"parent.{name}"] = value
    return properties


def collect_attachment_pom_context(attachments: list[tuple[str, str, str]]) -> tuple[dict[str, str], dict[str, str]]:
    roots: list[ET.Element] = []
    properties: dict[str, str] = {}
    for _, content, kind in attachments:
        if kind != "pom":
            continue
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            continue
        roots.append(root)
        parent = next(iter(direct_children(root, "parent")), None)
        if (
            parent is not None
            and child_text(parent, "groupId") == "org.springframework.boot"
            and child_text(parent, "artifactId") == "spring-boot-starter-parent"
            and child_text(parent, "version")
        ):
            properties.setdefault("_secflow.spring_boot_parent_version", child_text(parent, "version"))
        for key, value in collect_pom_properties(root).items():
            properties.setdefault(key, value)
    managed_versions: dict[str, str] = {}
    for root in roots:
        local_properties = dict(properties)
        local_properties.update(collect_pom_properties(root))
        managed_versions.update(collect_pom_managed_versions(root, local_properties))
    return properties, managed_versions


def collect_pom_managed_versions(root: ET.Element, properties: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for management in elements_by_local_name(root, "dependencyManagement"):
        for dependencies in direct_children(management, "dependencies"):
            for dependency in direct_children(dependencies, "dependency"):
                group_id = resolve_pom_value(child_text(dependency, "groupId"), properties)
                artifact_id = resolve_pom_value(child_text(dependency, "artifactId"), properties)
                version = resolve_pom_value(child_text(dependency, "version"), properties)
                if group_id and artifact_id and version and "${" not in version:
                    result[f"{group_id}:{artifact_id}".lower()] = version
    return result


def declared_pom_dependencies(root: ET.Element) -> list[ET.Element]:
    parents = {id(child): parent for parent in root.iter() for child in list(parent)}
    result: list[ET.Element] = []
    excluded_ancestors = {"dependencyManagement", "plugin", "reporting"}
    for dependencies in elements_by_local_name(root, "dependencies"):
        parent = parents.get(id(dependencies))
        excluded = False
        while parent is not None and parent is not root:
            if local_name(parent.tag) in excluded_ancestors:
                excluded = True
                break
            parent = parents.get(id(parent))
        if excluded:
            continue
        result.extend(direct_children(dependencies, "dependency"))
    return result


def inherited_parent_dependency_version(
    root: ET.Element,
    group_id: str,
    artifact_id: str,
    properties: dict[str, str],
) -> str:
    parent = next(iter(direct_children(root, "parent")), None)
    if parent is None:
        return ""
    parent_group = resolve_pom_value(child_text(parent, "groupId"), properties)
    parent_artifact = resolve_pom_value(child_text(parent, "artifactId"), properties)
    parent_version = resolve_pom_value(child_text(parent, "version"), properties)
    if (
        group_id == "org.springframework.boot"
        and (artifact_id == "spring-boot" or artifact_id.startswith("spring-boot-"))
    ):
        if parent_group == "org.springframework.boot" and parent_artifact == "spring-boot-starter-parent":
            return parent_version
        return resolve_pom_value(properties.get("_secflow.spring_boot_parent_version", ""), properties)
    return ""


def resolve_pom_value(value: str, properties: dict[str, str]) -> str:
    value = (value or "").strip()
    for _ in range(8):
        tokens = re.findall(r"\$\{([^}]+)\}", value)
        if not tokens:
            break
        previous = value
        for token in tokens:
            replacement = properties.get(token, "")
            if replacement:
                value = value.replace("${" + token + "}", replacement)
        if value == previous:
            break
    return value.strip()


def collect_attachment_gradle_context(attachments: list[tuple[str, str, str]]) -> GradleDependencyContext:
    variables: dict[str, str] = {}
    catalog_libraries: dict[str, GradleCatalogDependency] = {}
    catalog_bundles: dict[str, list[GradleCatalogDependency]] = {}
    for file_name, content, kind in attachments:
        if kind == "gradle_properties":
            variables.update(parse_gradle_properties(content))
        elif kind == "gradle":
            variables.update(extract_gradle_variables(content))
        elif kind == "gradle_version_catalog":
            libraries, bundles = parse_gradle_version_catalog(file_name, content)
            catalog_libraries.update(libraries)
            catalog_bundles.update(bundles)
    return GradleDependencyContext(
        variables=variables,
        catalog_libraries=catalog_libraries,
        catalog_bundles=catalog_bundles,
    )


def parse_gradle_dependencies(
    file_name: str,
    content: str,
    *,
    context: GradleDependencyContext | None = None,
) -> list[DependencyFact]:
    clean_content = strip_gradle_comments(content)
    variables = dict(context.variables if context else {})
    variables.update(extract_gradle_variables(clean_content))
    result: list[DependencyFact] = []
    seen: set[str] = set()
    dependency_blocks = extract_gradle_block_bodies(clean_content, "dependencies")
    if not dependency_blocks and re.search(r"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\b", clean_content):
        dependency_blocks = [clean_content]

    for block in dependency_blocks:
        for config, statement in iter_gradle_dependency_statements(block):
            extracted = parse_gradle_dependency_statement(file_name, config, statement, variables, context)
            for dependency in extracted:
                if dependency.key in seen:
                    continue
                result.append(dependency)
                seen.add(dependency.key)
    return result


def parse_gradle_dependency_statement(
    file_name: str,
    config: str,
    statement: str,
    variables: dict[str, str],
    context: GradleDependencyContext | None = None,
) -> list[DependencyFact]:
    result: list[DependencyFact] = []
    map_dependency = parse_gradle_map_notation(file_name, config, statement, variables)
    if map_dependency:
        result.append(map_dependency)

    for coordinate in gradle_coordinate_strings(statement):
        dependency = dependency_fact_from_gradle_coordinate(file_name, config, coordinate, variables, statement)
        if dependency:
            result.append(dependency)

    if context:
        for accessor in gradle_catalog_accessors(statement):
            result.extend(dependency_facts_from_gradle_accessor(file_name, config, accessor, context))

    seen: set[str] = set()
    unique: list[DependencyFact] = []
    for dependency in result:
        if dependency.key in seen:
            continue
        unique.append(dependency)
        seen.add(dependency.key)
    return unique


def parse_gradle_properties(content: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            continue
        clean_key = key.strip()
        clean_value = value.strip()
        if clean_key and clean_value:
            properties[clean_key] = strip_gradle_quotes(clean_value)
    return properties


def extract_gradle_variables(content: str) -> dict[str, str]:
    content = strip_gradle_comments(content)
    variables: dict[str, str] = {}
    assignment_pattern = re.compile(
        r"""(?mx)
        (?:^|[\s;{])
        (?:(?:def|val|var)\s+)?
        (?:ext\.)?
        (?P<name>[A-Za-z_][\w.]*)\s*=\s*
        (?P<quote>['"])(?P<value>(?:\\.|(?!\2).)*)(?P=quote)
        """
    )
    for match in assignment_pattern.finditer(content):
        variables[match.group("name")] = unescape_gradle_string(match.group("value"))

    extra_index_pattern = re.compile(
        r"""extra\s*\[\s*['"](?P<name>[^'"]+)['"]\s*\]\s*=\s*['"](?P<value>[^'"]+)['"]"""
    )
    for match in extra_index_pattern.finditer(content):
        variables[match.group("name")] = unescape_gradle_string(match.group("value"))

    extra_set_pattern = re.compile(
        r"""(?:extra\.)?set\s*\(\s*['"](?P<name>[^'"]+)['"]\s*,\s*['"](?P<value>[^'"]+)['"]\s*\)"""
    )
    for match in extra_set_pattern.finditer(content):
        variables[match.group("name")] = unescape_gradle_string(match.group("value"))

    return variables


def parse_gradle_version_catalog(
    file_name: str,
    content: str,
) -> tuple[dict[str, GradleCatalogDependency], dict[str, list[GradleCatalogDependency]]]:
    try:
        catalog = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return {}, {}

    versions = {
        str(alias): version
        for alias, value in (catalog.get("versions") or {}).items()
        if (version := gradle_catalog_version_value(value))
    }

    libraries_by_alias: dict[str, GradleCatalogDependency] = {}
    raw_libraries: dict[str, GradleCatalogDependency] = {}
    for alias, value in (catalog.get("libraries") or {}).items():
        dependency = gradle_catalog_dependency_from_value(str(alias), value, versions, file_name)
        if not dependency:
            continue
        raw_libraries[str(alias)] = dependency
        for key in gradle_accessor_lookup_keys(str(alias)):
            libraries_by_alias[key] = dependency

    bundles_by_alias: dict[str, list[GradleCatalogDependency]] = {}
    for alias, entries in (catalog.get("bundles") or {}).items():
        if not isinstance(entries, list):
            continue
        dependencies: list[GradleCatalogDependency] = []
        for entry in entries:
            if not isinstance(entry, str):
                continue
            dependency = raw_libraries.get(entry) or first_catalog_lookup(libraries_by_alias, entry)
            if dependency:
                dependencies.append(dependency)
        if dependencies:
            for key in gradle_accessor_lookup_keys(str(alias)):
                bundles_by_alias[key] = dependencies

    return libraries_by_alias, bundles_by_alias


def gradle_catalog_dependency_from_value(
    alias: str,
    value: Any,
    versions: dict[str, str],
    file_name: str,
) -> GradleCatalogDependency | None:
    group = ""
    artifact = ""
    version = ""
    if isinstance(value, str):
        parsed = parse_gradle_coordinate_parts(value)
        if not parsed:
            return None
        group, artifact, version = parsed
    elif isinstance(value, dict):
        if module := str(value.get("module") or "").strip():
            module_parts = parse_gradle_coordinate_parts(module)
            if not module_parts:
                return None
            group, artifact, module_version = module_parts
            version = module_version
        else:
            group = str(value.get("group") or "").strip()
            artifact = str(value.get("name") or "").strip()
        explicit_version = value.get("version")
        if explicit_version is not None:
            version = gradle_catalog_version_value(explicit_version) or version
        version_ref = gradle_catalog_version_ref(value)
        if version_ref:
            version = versions.get(version_ref, version)
    else:
        return None
    if not group or not artifact or not is_valid_maven_coordinate_part(group) or not is_valid_maven_coordinate_part(artifact):
        return None
    declaration = f"{alias} = {group}:{artifact}" + (f":{version}" if version else "")
    return GradleCatalogDependency(
        alias=alias,
        name=f"{group}:{artifact}",
        version=version,
        source_file=file_name,
        declaration=declaration,
    )


def gradle_catalog_version_value(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("strictly", "require", "prefer", "ref"):
            if candidate := str(value.get(key) or "").strip():
                return candidate
    return ""


def gradle_catalog_version_ref(value: dict[str, Any]) -> str:
    direct = str(value.get("version.ref") or "").strip()
    if direct:
        return direct
    version = value.get("version")
    if isinstance(version, dict):
        return str(version.get("ref") or "").strip()
    return ""


def first_catalog_lookup(
    lookup: dict[str, GradleCatalogDependency],
    alias: str,
) -> GradleCatalogDependency | None:
    for key in gradle_accessor_lookup_keys(alias):
        if key in lookup:
            return lookup[key]
    return None


def strip_gradle_comments(content: str) -> str:
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    lines: list[str] = []
    for line in content.splitlines():
        lines.append(strip_gradle_line_comment(line))
    return "\n".join(lines)


def strip_gradle_line_comment(line: str) -> str:
    in_quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_quote:
            if char == in_quote:
                in_quote = ""
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            return line[:index]
    return line


def extract_gradle_block_bodies(content: str, block_name: str) -> list[str]:
    bodies: list[str] = []
    pattern = re.compile(rf"(?<![\w.]){re.escape(block_name)}\s*\{{")
    for match in pattern.finditer(content):
        open_brace = content.find("{", match.start())
        close_brace = find_matching_gradle_brace(content, open_brace)
        if close_brace > open_brace:
            bodies.append(content[open_brace + 1 : close_brace])
    return bodies


def find_matching_gradle_brace(content: str, open_brace: int) -> int:
    depth = 0
    in_quote = ""
    escaped = False
    for index in range(open_brace, len(content)):
        char = content[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_quote:
            if char == in_quote:
                in_quote = ""
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def iter_gradle_dependency_statements(block: str) -> list[tuple[str, str]]:
    statements: list[tuple[str, str]] = []
    lines = block.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"\s*(?P<config>[A-Za-z_][\w.-]*)\b(?P<tail>.*)", line)
        index += 1
        if not match:
            continue
        config = match.group("config")
        if config in {"dependencies", "constraints", "components", "modules", "all", "exclude"}:
            continue
        statement = line.strip()
        balance = gradle_paren_balance(statement)
        continuation_count = 0
        while balance > 0 and index < len(lines) and continuation_count < 40:
            statement += "\n" + lines[index].strip()
            balance += gradle_paren_balance(lines[index])
            index += 1
            continuation_count += 1
        statements.append((config, statement))

    add_pattern = re.compile(
        r"""(?ms)^\s*add\s*\(\s*['"][^'"]+['"]\s*,\s*(?P<argument>.*?)(?:\)\s*(?:\{|$)|$)"""
    )
    for match in add_pattern.finditer(block):
        statements.append(("add", "add(" + match.group("argument")))
    return statements


def gradle_paren_balance(value: str) -> int:
    balance = 0
    in_quote = ""
    escaped = False
    for char in value:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_quote:
            if char == in_quote:
                in_quote = ""
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char == "(":
            balance += 1
        elif char == ")":
            balance -= 1
    return balance


def parse_gradle_map_notation(
    file_name: str,
    config: str,
    statement: str,
    variables: dict[str, str],
) -> DependencyFact | None:
    pairs: dict[str, str] = {}
    for match in re.finditer(
        r"""(?P<key>group|name|version)\s*(?::|=)\s*(?P<value>['"][^'"]+['"]|[A-Za-z_][\w.]*)""",
        statement,
    ):
        pairs[match.group("key")] = resolve_gradle_value(strip_gradle_quotes(match.group("value")), variables)
    group = pairs.get("group", "")
    artifact = pairs.get("name", "")
    version = pairs.get("version", "")
    if not group or not artifact or not is_valid_maven_coordinate_part(group) or not is_valid_maven_coordinate_part(artifact):
        return None
    if "$" in version or "{" in version:
        version = ""
    name = f"{group}:{artifact}"
    declaration = f"{config} {name}" + (f":{version}" if version else "")
    return DependencyFact(
        ecosystem="Maven",
        name=name,
        version=version,
        source_file=file_name,
        source_type="gradle",
        declaration=declaration,
        confidence="high" if version else "medium",
    )


def gradle_coordinate_strings(statement: str) -> list[str]:
    if any(skip in statement for skip in ("project(", "files(", "fileTree(")):
        return []
    coordinates: list[str] = []
    wrapper_pattern = re.compile(r"""(?:platform|enforcedPlatform)\s*\(\s*['"](?P<coordinate>[^'"]+)['"]""")
    for match in wrapper_pattern.finditer(statement):
        coordinates.append(match.group("coordinate"))
    for match in re.finditer(r"""['"](?P<coordinate>[^'"]+:[^'"]+)['"]""", statement):
        coordinate = match.group("coordinate")
        if coordinate not in coordinates:
            coordinates.append(coordinate)
    return coordinates


def dependency_fact_from_gradle_coordinate(
    file_name: str,
    config: str,
    coordinate: str,
    variables: dict[str, str],
    statement: str,
) -> DependencyFact | None:
    resolved_coordinate = resolve_gradle_value(coordinate, variables)
    parsed = parse_gradle_coordinate_parts(resolved_coordinate)
    if not parsed:
        return None
    group, artifact, version = parsed
    if not version:
        version = gradle_rich_version_from_statement(statement, variables)
    if "$" in version or "{" in version:
        version = ""
    name = f"{group}:{artifact}"
    declaration = f"{config} {name}" + (f":{version}" if version else "")
    return DependencyFact(
        ecosystem="Maven",
        name=name,
        version=version,
        source_file=file_name,
        source_type="gradle",
        declaration=declaration,
        confidence="high" if version else "medium",
    )


def parse_gradle_coordinate_parts(coordinate: str) -> tuple[str, str, str] | None:
    coordinate = strip_gradle_quotes(coordinate).strip()
    coordinate = coordinate.split("@", 1)[0].strip()
    if not coordinate or coordinate.startswith(("$", ":", "/", ".")):
        return None
    if "://" in coordinate or coordinate.lower().startswith(("project(", "files(", "filetree(")):
        return None
    parts = [part.strip() for part in coordinate.split(":")]
    if len(parts) < 2:
        return None
    group, artifact = parts[0], parts[1]
    version = parts[2] if len(parts) >= 3 else ""
    if not is_valid_maven_coordinate_part(group) or not is_valid_maven_coordinate_part(artifact):
        return None
    version = version.strip()
    return group, artifact, version


def is_valid_maven_coordinate_part(value: str) -> bool:
    if not value or any(char.isspace() for char in value):
        return False
    if value.lower() in {"http", "https", "jdbc"}:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))


def gradle_rich_version_from_statement(statement: str, variables: dict[str, str]) -> str:
    match = re.search(r"""(?:strictly|require|prefer)\s*\(\s*['"](?P<version>[^'"]+)['"]\s*\)""", statement)
    if not match:
        return ""
    return resolve_gradle_value(match.group("version"), variables)


def gradle_catalog_accessors(statement: str) -> list[str]:
    accessors: list[str] = []
    for match in re.finditer(r"""(?<![\w.])libs(?:\.[A-Za-z_][\w-]*)+(?:\.get\(\))?""", statement):
        accessor = match.group(0).removesuffix(".get()")
        if accessor not in accessors:
            accessors.append(accessor)
    return accessors


def dependency_facts_from_gradle_accessor(
    file_name: str,
    config: str,
    accessor: str,
    context: GradleDependencyContext,
) -> list[DependencyFact]:
    alias = accessor.removeprefix("libs.")
    if alias.startswith("versions.") or alias.startswith("plugins."):
        return []
    is_bundle = alias.startswith("bundles.")
    if is_bundle:
        alias = alias.removeprefix("bundles.")
        dependencies = context.catalog_bundles.get(gradle_accessor_normalized_key(alias), [])
    else:
        dependency = context.catalog_libraries.get(gradle_accessor_normalized_key(alias))
        dependencies = [dependency] if dependency else []
    result: list[DependencyFact] = []
    for dependency in dependencies:
        if dependency is None:
            continue
        declaration = f"{config} {accessor} -> {dependency.name}"
        if dependency.version:
            declaration += f":{dependency.version}"
        if dependency.source_file:
            declaration += f" ({dependency.source_file})"
        result.append(
            DependencyFact(
                ecosystem="Maven",
                name=dependency.name,
                version=dependency.version,
                source_file=file_name,
                source_type="gradle",
                declaration=declaration,
                confidence="high" if dependency.version else "medium",
            )
        )
    return result


def gradle_accessor_lookup_keys(alias: str) -> set[str]:
    normalized = gradle_accessor_normalized_key(alias)
    compact = re.sub(r"[^a-z0-9]", "", alias.lower())
    raw = alias.lower().strip()
    return {key for key in {raw, normalized, compact} if key}


def gradle_accessor_normalized_key(alias: str) -> str:
    alias = alias.lower().strip()
    alias = alias.removeprefix("libs.")
    alias = alias.removeprefix("bundles.")
    alias = alias.removesuffix(".get()")
    return re.sub(r"[^a-z0-9]+", ".", alias).strip(".")


def resolve_gradle_value(value: str, variables: dict[str, str]) -> str:
    value = strip_gradle_quotes(value).strip()
    for _ in range(8):
        previous = value
        for token in re.findall(r"\$\{([^}]+)\}", value):
            replacement = variables.get(token, "")
            if replacement:
                value = value.replace("${" + token + "}", replacement)
        for token in re.findall(r"(?<!\\)\$([A-Za-z_][\w.]*)", value):
            replacement = variables.get(token, "")
            if replacement:
                value = value.replace("$" + token, replacement)
        if value in variables:
            value = variables[value]
        if value == previous:
            break
    return strip_gradle_quotes(value).strip()


def strip_gradle_quotes(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return unescape_gradle_string(value[1:-1])
    return value


def unescape_gradle_string(value: str) -> str:
    return value.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\").strip()


def parse_python_manifest_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    name = Path(file_name).name.lower()
    result: list[DependencyFact] = []
    if is_python_requirements_name(file_name):
        for raw_line in content.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "http://", "https://", "git+")):
                continue
            package, version = _split_package_version(line)
            if package:
                result.append(_manifest_fact("PyPI", package, version, file_name, "python_manifest", line))
        return _dedupe_manifest_facts(result)

    try:
        payload = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    if name == "pyproject.toml":
        project = payload.get("project") if isinstance(payload.get("project"), dict) else {}
        for value in project.get("dependencies") or []:
            package, version = _split_package_version(str(value))
            if package:
                result.append(_manifest_fact("PyPI", package, version, file_name, "python_manifest", str(value)))
        poetry = ((payload.get("tool") or {}).get("poetry") or {}) if isinstance(payload.get("tool"), dict) else {}
        for group_name in ("dependencies", "dev-dependencies"):
            for package, value in (poetry.get(group_name) or {}).items():
                if str(package).lower() == "python":
                    continue
                version = str(value.get("version") or "") if isinstance(value, dict) else str(value)
                result.append(_manifest_fact("PyPI", str(package), version, file_name, "python_manifest", f"{package}={version}"))
    elif name == "pipfile":
        for group_name in ("packages", "dev-packages"):
            for package, value in (payload.get(group_name) or {}).items():
                version = str(value.get("version") or "") if isinstance(value, dict) else str(value)
                result.append(_manifest_fact("PyPI", str(package), version, file_name, "python_manifest", f"{package}={version}"))
    elif name == "poetry.lock":
        for item in payload.get("package") or []:
            if isinstance(item, dict) and item.get("name"):
                result.append(
                    _manifest_fact(
                        "PyPI",
                        str(item["name"]),
                        str(item.get("version") or ""),
                        file_name,
                        "python_manifest",
                        f"{item['name']}=={item.get('version') or ''}",
                    )
                )
    return _dedupe_manifest_facts(result)


def parse_go_manifest_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    if Path(file_name).name.lower() == "go.sum":
        return parse_go_sum_dependencies(file_name, content)

    result: list[DependencyFact] = []
    in_require_block = False
    for raw_line in content.splitlines():
        declaration = raw_line.strip()
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if not in_require_block:
            if not line.startswith("require "):
                continue
            line = line.removeprefix("require ").strip()
        match = re.match(r"^([^\s()]+)\s+(v[^\s]+)", line)
        if not match:
            continue
        result.append(_manifest_fact("Go", match.group(1), match.group(2), file_name, "go_manifest", declaration))
    return _dedupe_manifest_facts(result)


def parse_go_sum_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    result: list[DependencyFact] = []
    for raw_line in content.splitlines():
        fields = raw_line.strip().split()
        if len(fields) < 2 or not fields[1].startswith("v"):
            continue
        version = fields[1].removesuffix("/go.mod")
        result.append(_manifest_fact("Go", fields[0], version, file_name, "go_manifest", raw_line.strip()))
    return _dedupe_manifest_facts(result)


def parse_c_cpp_manifest_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    name = Path(file_name).name.lower()
    result: list[DependencyFact] = []
    if name == "vcpkg.json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return []
        for item in payload.get("dependencies") or []:
            if isinstance(item, str):
                result.append(_manifest_fact("vcpkg", item, "", file_name, "c_cpp_manifest", item))
            elif isinstance(item, dict) and item.get("name"):
                version = str(item.get("version>=") or item.get("version") or "")
                result.append(_manifest_fact("vcpkg", str(item["name"]), version, file_name, "c_cpp_manifest", json.dumps(item)))
        return _dedupe_manifest_facts(result)
    if name.startswith("conanfile"):
        in_requires = False
        for raw_line in content.splitlines():
            line = raw_line.strip().strip('"\'')
            if line.lower() == "[requires]":
                in_requires = True
                continue
            if line.startswith("["):
                in_requires = False
            candidates = [line] if in_requires else re.findall(r"[\"']([A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+)[\"']", raw_line)
            for candidate in candidates:
                match = re.match(r"^([A-Za-z0-9_.+-]+)/([^\s@]+)", candidate)
                if match:
                    result.append(_manifest_fact("Conan", match.group(1), match.group(2), file_name, "c_cpp_manifest", candidate))
        return _dedupe_manifest_facts(result)
    cmake_variables = extract_cmake_variables(content)
    for match in re.finditer(
        r"find_package\s*\(\s*([A-Za-z0-9_.+-]+)(?:\s+([0-9][^\s)]*|\$\{[A-Za-z_][\w.:-]*\}))?",
        content,
        flags=re.IGNORECASE,
    ):
        version = resolve_cmake_value(match.group(2) or "", cmake_variables)
        result.append(_manifest_fact("CMake", match.group(1), version, file_name, "c_cpp_manifest", match.group(0)))
    return _dedupe_manifest_facts(result)


def collect_dotnet_dependency_context(accepted: list[tuple[str, str, str]]) -> dict[str, list[dict[str, Any]]]:
    property_contexts: list[dict[str, Any]] = []
    for file_name, content, kind in accepted:
        if kind != "dotnet_manifest":
            continue
        name = Path(file_name).name.lower()
        if name not in {"directory.build.props", "directory.packages.props"}:
            continue
        root = _parse_xml(content)
        if root is None:
            continue
        properties = _dotnet_properties(root)
        if properties:
            property_contexts.append({"directory": _manifest_directory(file_name), "properties": properties})

    central_contexts: list[dict[str, Any]] = []
    resolved_contexts: list[dict[str, Any]] = []
    for file_name, content, kind in accepted:
        if kind != "dotnet_manifest":
            continue
        name = Path(file_name).name.lower()
        if name == "directory.packages.props":
            root = _parse_xml(content)
            if root is None:
                continue
            properties = _dotnet_context_properties(file_name, property_contexts)
            properties.update(_dotnet_properties(root))
            versions: dict[str, str] = {}
            for item in elements_by_local_name(root, "PackageVersion"):
                package = str(item.attrib.get("Include") or item.attrib.get("Update") or "").strip()
                version = _dotnet_item_version(item, properties)
                if package and version:
                    versions.setdefault(package.casefold(), version)
            central_contexts.append({"directory": _manifest_directory(file_name), "versions": versions})
        elif name in {"packages.lock.json", "project.assets.json"}:
            versions = {}
            for dependency in _parse_dotnet_json_dependencies(file_name, content):
                if dependency.version:
                    versions.setdefault(dependency.name.casefold(), dependency.version)
            directory = _manifest_directory(file_name)
            if name == "project.assets.json" and directory.name.casefold() == "obj":
                directory = directory.parent
            resolved_contexts.append({"directory": directory, "versions": versions})
    return {"central": central_contexts, "resolved": resolved_contexts, "properties": property_contexts}


def parse_dotnet_manifest_dependencies(
    file_name: str,
    content: str,
    *,
    context: dict[str, list[dict[str, Any]]] | None = None,
) -> list[DependencyFact]:
    name = Path(file_name).name.lower()
    if name in {"packages.lock.json", "project.assets.json"}:
        return _parse_dotnet_json_dependencies(file_name, content)

    root = _parse_xml(content)
    if root is None:
        return []
    result: list[DependencyFact] = []
    if name == "packages.config":
        for item in elements_by_local_name(root, "package"):
            package = str(item.attrib.get("id") or "").strip()
            version = str(item.attrib.get("version") or "").strip()
            if package:
                result.append(
                    _manifest_fact("NuGet", package, version, file_name, "dotnet_manifest", ET.tostring(item, encoding="unicode"))
                )
        return _dedupe_manifest_facts(result)

    properties = _dotnet_context_properties(file_name, (context or {}).get("properties") or [])
    properties.update(_dotnet_properties(root))
    for item in elements_by_local_name(root, "PackageReference"):
        package = str(item.attrib.get("Include") or item.attrib.get("Update") or "").strip()
        if not package:
            continue
        declared_version = _dotnet_item_version(item, properties)
        version = (
            _dotnet_context_version(file_name, package, (context or {}).get("resolved") or [], exact_directory=True)
            or declared_version
            or _dotnet_context_version(file_name, package, (context or {}).get("central") or [])
        )
        result.append(
            _manifest_fact("NuGet", package, version, file_name, "dotnet_manifest", ET.tostring(item, encoding="unicode"))
        )
    return _dedupe_manifest_facts(result)


def _manifest_directory(file_name: str) -> PurePosixPath:
    return PurePosixPath(file_name.replace("\\", "/")).parent


def _dotnet_context_version(
    file_name: str,
    package: str,
    contexts: list[dict[str, Any]],
    *,
    exact_directory: bool = False,
) -> str:
    source_directory = _manifest_directory(file_name)
    candidates = sorted(contexts, key=lambda item: len(PurePosixPath(item["directory"]).parts), reverse=True)
    for item in candidates:
        directory = PurePosixPath(item["directory"])
        applies = source_directory == directory if exact_directory else (
            source_directory == directory or directory in source_directory.parents
        )
        if not applies:
            continue
        version = str((item.get("versions") or {}).get(package.casefold()) or "")
        if version:
            return version
    return ""


def _dotnet_context_properties(file_name: str, contexts: list[dict[str, Any]]) -> dict[str, str]:
    source_directory = _manifest_directory(file_name)
    merged: dict[str, str] = {}
    candidates = sorted(contexts, key=lambda item: len(PurePosixPath(item["directory"]).parts))
    for item in candidates:
        directory = PurePosixPath(item["directory"])
        if source_directory == directory or directory in source_directory.parents:
            merged.update({str(key): str(value) for key, value in (item.get("properties") or {}).items()})
    return merged


def extract_cmake_variables(content: str) -> dict[str, str]:
    variables: dict[str, str] = {}
    pattern = re.compile(
        r"""(?im)^\s*set\s*\(\s*(?P<name>[A-Za-z_][\w.]*)\s+(?P<value>"[^"]+"|'[^']+'|[^\s)]+)"""
    )
    for match in pattern.finditer(content):
        value = match.group("value").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if value:
            variables[match.group("name")] = value.strip()
    return variables


def resolve_cmake_value(value: str, variables: dict[str, str]) -> str:
    value = (value or "").strip()
    for _ in range(8):
        match = re.fullmatch(r"\$\{([^}]+)\}", value)
        if match is None:
            break
        replacement = variables.get(match.group(1), "")
        if not replacement or replacement == value:
            break
        value = replacement.strip()
    return value


def _parse_xml(content: str) -> ET.Element | None:
    try:
        return ET.fromstring(content)
    except ET.ParseError:
        return None


def _dotnet_properties(root: ET.Element) -> dict[str, str]:
    properties: dict[str, str] = {}
    for group in elements_by_local_name(root, "PropertyGroup"):
        for item in list(group):
            value = (item.text or "").strip()
            if value:
                properties.setdefault(local_name(item.tag), value)
    return properties


def _dotnet_item_version(item: ET.Element, properties: dict[str, str]) -> str:
    version = str(item.attrib.get("VersionOverride") or item.attrib.get("Version") or "").strip()
    if not version:
        for child_name in ("VersionOverride", "Version"):
            child = next(iter(direct_children(item, child_name)), None)
            if child is not None and child.text:
                version = child.text.strip()
                break
    for _ in range(8):
        match = re.fullmatch(r"\$\(([^)]+)\)", version)
        if match is None or match.group(1) not in properties:
            break
        resolved = properties[match.group(1)]
        if resolved == version:
            break
        version = resolved
    return version


def _parse_dotnet_json_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []

    name = Path(file_name).name.lower()
    result: list[DependencyFact] = []
    if name == "packages.lock.json":
        frameworks = payload.get("dependencies") or {}
        if not isinstance(frameworks, dict):
            return []
        for framework_dependencies in frameworks.values():
            if not isinstance(framework_dependencies, dict):
                continue
            for package, metadata in framework_dependencies.items():
                if not isinstance(metadata, dict):
                    continue
                version = str(metadata.get("resolved") or metadata.get("requested") or "")
                result.append(
                    _manifest_fact("NuGet", str(package), version, file_name, "dotnet_manifest", json.dumps(metadata, sort_keys=True))
                )
    elif name == "project.assets.json":
        libraries = payload.get("libraries") or {}
        if not isinstance(libraries, dict):
            return []
        for coordinate, metadata in libraries.items():
            if not isinstance(metadata, dict) or str(metadata.get("type") or "").casefold() != "package":
                continue
            package, separator, version = str(coordinate).partition("/")
            if package and separator:
                result.append(
                    _manifest_fact("NuGet", package, version, file_name, "dotnet_manifest", str(coordinate))
                )
    return _dedupe_manifest_facts(result)


def parse_rust_manifest_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    try:
        payload = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    result: list[DependencyFact] = []
    tables: list[dict[str, Any]] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = payload.get(key)
        if isinstance(value, dict):
            tables.append(value)
    for target in (payload.get("target") or {}).values() if isinstance(payload.get("target"), dict) else []:
        if isinstance(target, dict):
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target.get(key)
                if isinstance(value, dict):
                    tables.append(value)
    for table in tables:
        for package, value in table.items():
            version = str(value.get("version") or "") if isinstance(value, dict) else str(value)
            actual_name = str(value.get("package") or package) if isinstance(value, dict) else str(package)
            result.append(_manifest_fact("crates.io", actual_name, version, file_name, "rust_manifest", f"{package}={version}"))
    for item in payload.get("package") or []:
        if isinstance(item, dict) and item.get("name"):
            result.append(_manifest_fact("crates.io", str(item["name"]), str(item.get("version") or ""), file_name, "rust_manifest", str(item["name"])))
    return _dedupe_manifest_facts(result)


def parse_solidity_manifest_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    name = Path(file_name).name.lower()
    result: list[DependencyFact] = []
    if name == "package.json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return []
        for group_name in ("dependencies", "devDependencies"):
            for package, version in (payload.get(group_name) or {}).items():
                result.append(_manifest_fact("npm", str(package), str(version), file_name, "solidity_manifest", f"{package}={version}"))
        return _dedupe_manifest_facts(result)
    if name in {"foundry.toml"}:
        try:
            payload = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, ValueError):
            return []
        for table_name in ("dependencies", "dev-dependencies"):
            for package, value in (payload.get(table_name) or {}).items():
                version = str(value.get("version") or value.get("tag") or value.get("rev") or "") if isinstance(value, dict) else str(value)
                result.append(_manifest_fact("Solidity", str(package), version, file_name, "solidity_manifest", f"{package}={version}"))
    elif name == "remappings.txt":
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            package = line.split("=", 1)[0].rstrip("/")
            if package:
                result.append(_manifest_fact("Solidity", package, "", file_name, "solidity_manifest", line))
    return _dedupe_manifest_facts(result)


def _split_package_version(value: str) -> tuple[str, str]:
    text = value.strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(?:(?:===|==|~=|>=|<=|!=|>|<)\s*([^\s;,]+))?", text)
    return (match.group(1), match.group(2) or "") if match else ("", "")


def _manifest_fact(
    ecosystem: str,
    name: str,
    version: str,
    file_name: str,
    source_type: str,
    declaration: str,
) -> DependencyFact:
    return DependencyFact(
        ecosystem=ecosystem,
        name=name.strip(),
        version=version.strip().lstrip("=~^<> "),
        source_file=file_name,
        source_type=source_type,
        declaration=declaration.strip(),
        confidence="high" if version.strip() else "medium",
    )


def _dedupe_manifest_facts(values: list[DependencyFact]) -> list[DependencyFact]:
    result: list[DependencyFact] = []
    seen: set[str] = set()
    for value in values:
        if not value.name or value.key in seen:
            continue
        seen.add(value.key)
        result.append(value)
    return result[:80]


def parse_code_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    suffix = Path(file_name).suffix.lower()
    if suffix in {".java", ".kt", ".kts", ".scala", ".groovy"}:
        return parse_jvm_import_dependencies(file_name, content)
    if suffix == ".py":
        return parse_python_import_dependencies(file_name, content)
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return parse_javascript_import_dependencies(file_name, content)
    if suffix == ".go":
        return parse_go_import_dependencies(file_name, content)
    return []


def parse_jvm_import_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    imports = re.findall(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w]*(?:\.[\w*]+)+)", content, flags=re.MULTILINE)
    result: list[DependencyFact] = []
    seen: set[str] = set()
    for imported in imports:
        if imported.startswith(STANDARD_IMPORT_PREFIXES):
            continue
        mapped = map_jvm_import_to_dependency(imported)
        if not mapped:
            continue
        ecosystem, name = mapped
        fact = DependencyFact(
            ecosystem=ecosystem,
            name=name,
            source_file=file_name,
            source_type="code",
            declaration=f"import {imported}",
            confidence="medium",
        )
        if fact.key not in seen:
            result.append(fact)
            seen.add(fact.key)
    return result


def map_jvm_import_to_dependency(imported: str) -> tuple[str, str] | None:
    for prefix, ecosystem, package in JAVA_IMPORT_MAPPINGS:
        if imported.startswith(prefix):
            return ecosystem, package
    parts = imported.split(".")
    if len(parts) >= 3:
        group = ".".join(parts[:3])
        return "Maven", group
    return None


def parse_python_import_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    names = set(re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][\w]*)", content, flags=re.MULTILINE))
    return [
        DependencyFact("PyPI", name, source_file=file_name, source_type="code", declaration=f"import {name}", confidence="low")
        for name in sorted(names)
        if not name.startswith("_") and name not in STANDARD_IMPORT_PREFIXES
    ][:40]


def parse_javascript_import_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    names = re.findall(r"""(?:from\s+|require\()\s*['"]([^'"]+)['"]""", content)
    result: list[DependencyFact] = []
    seen: set[str] = set()
    for name in names:
        if name.startswith((".", "/", "node:")):
            continue
        package = npm_package_name(name)
        fact = DependencyFact("npm", package, source_file=file_name, source_type="code", declaration=name, confidence="medium")
        if fact.key not in seen:
            result.append(fact)
            seen.add(fact.key)
    return result[:40]


def npm_package_name(import_path: str) -> str:
    if import_path.startswith("@"):
        parts = import_path.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else import_path
    return import_path.split("/")[0]


def parse_go_import_dependencies(file_name: str, content: str) -> list[DependencyFact]:
    imports = re.findall(r'"([^"]+\.[^"]*)"', content)
    return [
        DependencyFact("Go", name, source_file=file_name, source_type="code", declaration=f'import "{name}"', confidence="medium")
        for name in imports
        if not name.startswith(("./", "../"))
    ][:40]


def child_text(element: ET.Element, name: str) -> str:
    child = next(iter(direct_children(element, name)), None)
    return (child.text or "").strip() if child is not None and child.text else ""


def direct_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if local_name(child.tag) == name]


def elements_by_local_name(element: ET.Element, name: str) -> list[ET.Element]:
    return [item for item in element.iter() if local_name(item.tag) == name]


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag
