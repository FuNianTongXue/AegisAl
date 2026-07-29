from __future__ import annotations

from pathlib import Path


SOURCE_STUB_CODE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".m",
    ".mm",
    ".java",
    ".py",
    ".go",
    ".rs",
    ".cs",
    ".sol",
}

EXCLUDED_SOURCE_PARTS = {
    ".git",
    ".gradle",
    ".idea",
    ".mvn",
    "benchmark",
    "benchmarks",
    "build",
    "doc",
    "docs",
    "3rd-party",
    "3rdparty",
    "3rd_party",
    "archetype-resources",
    "dev-support",
    "dist",
    "examples",
    "fuzz",
    "fuzzing",
    "generated",
    "integration",
    "jmh",
    "node_modules",
    "perf",
    "performance",
    "playground",
    "target",
    "test",
    "testdata",
    "tests",
    "third-party",
    "thirdparty",
    "third_party",
    "vendor",
    "vendored",
    "vendors",
}

EXCLUDED_DEEP_PACKAGE_PARTS = {
    "demo",
    "demos",
    "example",
    "sample",
    "samples",
    "tutorial",
    "tutorials",
}

EXCLUDED_SOURCE_PART_SUFFIXES = (
    "test",
    "tests",
    "testing",
    "benchmark",
    "benchmarks",
    "dunit",
    "jmh",
    "fuzz",
    "fuzzing",
    "playground",
)

EXCLUDED_SOURCE_FILE_SUFFIXES = (
    "_test.go",
    "_fuzz.go",
    "_test.py",
    "_test.rs",
    ".t.sol",
)

SEMGREP_EXCLUDE_PATTERNS = [
    "**/.git/**",
    "**/.gradle/**",
    "**/.idea/**",
    "**/.mvn/**",
    "**/build/**",
    "**/doc/**",
    "**/docs/**",
    "**/3rd-party/**",
    "**/3rdparty/**",
    "**/3rd_party/**",
    "**/third-party/**",
    "**/thirdparty/**",
    "**/third_party/**",
    "**/vendor/**",
    "**/vendored/**",
    "**/vendors/**",
    "**/archetype-resources/**",
    "**/target/**",
    "**/generated/**",
    "**/dev-support/**",
    "**/examples/**",
    "**/demo/src/main/**",
    "**/demos/src/main/**",
    "**/example/src/main/**",
    "**/sample/src/main/**",
    "**/samples/src/main/**",
    "**/tutorial/src/main/**",
    "**/tutorials/src/main/**",
    "**/it/**/src/main/**",
    "**/src/integration/**",
    "**/*dunit*/**",
    "**/src/main/java/*/*/*/**/demo/**",
    "**/src/main/java/*/*/*/**/demos/**",
    "**/src/main/java/*/*/*/**/example/**",
    "**/src/main/java/*/*/*/**/sample/**",
    "**/src/main/java/*/*/*/**/samples/**",
    "**/src/main/java/*/*/*/**/tutorial/**",
    "**/src/main/java/*/*/*/**/tutorials/**",
    "**/src/test/**",
    "**/src/it/**",
    "**/src/*Test/**",
    "**/src/*Tests/**",
    "**/test/**",
    "**/testdata/**",
    "**/tests/**",
    "**/*_test.go",
    "**/*_fuzz.go",
    "**/*fuzz*/**",
    "**/*playground*/**",
    "**/*Test/**",
    "**/*Tests/**",
    "**/*Testing/**",
    "**/benchmark/**",
    "**/benchmarks/**",
    "**/jmh/**",
    "**/perf/**",
    "**/performance/**",
]


def is_excluded_source_path(path: str | Path) -> bool:
    """Return whether a source path should be skipped for production-code auditing."""
    parts = _normalized_parts(path)
    if parts and parts[-1].endswith(EXCLUDED_SOURCE_FILE_SUFFIXES):
        return True
    for part in parts:
        if part in EXCLUDED_SOURCE_PARTS:
            return True
        if any(part.endswith(suffix) for suffix in EXCLUDED_SOURCE_PART_SUFFIXES):
            return True
    if _is_integration_test_module(parts):
        return True
    if _is_top_level_example_module(parts):
        return True
    if _has_deep_example_package(parts):
        return True
    return False


def is_analyzable_source_path(path: str | Path) -> bool:
    return not is_excluded_source_path(path)


def is_symlink_like_source_stub(path: str | Path, content: str) -> bool:
    """Return true for archive/raw materialized symlink target stubs.

    GitHub raw/archive materialization can expose symlinks as a regular text
    file whose whole content is just the target path, for example a ``.cc`` file
    containing ``../../sherpa-onnx/csrc/alsa.cc``. Those files are not source
    translation units and should not count as parser errors or Semgrep targets.
    """
    suffix = Path(str(path).replace("\\", "/")).suffix.lower()
    if suffix not in SOURCE_STUB_CODE_SUFFIXES:
        return False
    stripped = content.strip()
    if not stripped or len(stripped) > 512 or "\n" in stripped or "\r" in stripped:
        return False
    if any(character.isspace() for character in stripped):
        return False
    if any(marker in stripped for marker in (";", "{", "}", "(", ")", "#", '"', "'")):
        return False
    normalized = stripped.replace("\\", "/")
    if "/" not in normalized:
        return False
    if normalized.startswith(("/", "http://", "https://")):
        return False
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return False
    first_non_relative = 0
    while first_non_relative < len(parts) and parts[first_non_relative] in {".", ".."}:
        first_non_relative += 1
    if any(part in {".", ".."} for part in parts[first_non_relative:]):
        return False
    if any(part.startswith(".git") for part in parts):
        return False
    if not all(_safe_stub_path_part(part) for part in parts):
        return False
    target_suffix = Path(parts[-1]).suffix.lower()
    if target_suffix not in SOURCE_STUB_CODE_SUFFIXES:
        return False
    return normalized.startswith(("./", "../")) or all(part not in {".", ".."} for part in parts[:-1])


def _normalized_parts(path: str | Path) -> list[str]:
    return [
        part.strip().lower()
        for part in Path(str(path).replace("\\", "/")).parts
        if part not in {"", ".", "..", "/"}
    ]


def _is_integration_test_module(parts: list[str]) -> bool:
    for index, part in enumerate(parts):
        if part == "it" and parts[index + 1 : index + 4] and "src" in parts[index + 1 :]:
            return True
    return False


def _is_top_level_example_module(parts: list[str]) -> bool:
    for index, part in enumerate(parts[:-1]):
        if part in EXCLUDED_DEEP_PACKAGE_PARTS and "src" in parts[index + 1 :]:
            return True
    return False


def _has_deep_example_package(parts: list[str]) -> bool:
    java_root = _java_source_root_index(parts)
    if java_root < 0:
        return False
    package_parts = parts[java_root + 1 : -1]
    for index, part in enumerate(package_parts):
        if part in EXCLUDED_DEEP_PACKAGE_PARTS and index >= 3:
            return True
    return False


def _java_source_root_index(parts: list[str]) -> int:
    for index in range(len(parts) - 2):
        if parts[index : index + 3] == ["src", "main", "java"]:
            return index + 2
    return -1


def _safe_stub_path_part(part: str) -> bool:
    if part in {"", ".", ".."}:
        return True
    return all(character.isalnum() or character in {"_", "-", ".", "+", "@"} for character in part)
