from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "app"


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path.relative_to(ROOT)}:{self.line}: {self.message}"


def _python_files(path: Path) -> tuple[Path, ...]:
    if path.is_file():
        return (path,)
    return tuple(
        candidate
        for candidate in sorted(path.rglob("*.py"))
        if "__pycache__" not in candidate.parts
    )


def _business_files() -> tuple[Path, ...]:
    paths: list[Path] = []
    for target in (
        APP_ROOT / "agent",
        APP_ROOT / "langgraph",
        APP_ROOT / "reports.py",
        APP_ROOT / "capabilities.py",
    ):
        paths.extend(_python_files(target))
    return tuple(paths)


def _module_for_import_from(path: Path, node: ast.ImportFrom) -> str:
    module = node.module or ""
    if not node.level:
        return module

    relative = path.relative_to(ROOT).with_suffix("")
    package_parts = list(relative.parts[:-1])
    keep = len(package_parts) - node.level + 1
    if keep < 0:
        return module
    base = package_parts[:keep]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _mcp_dependency_violations() -> tuple[Violation, ...]:
    allowed_modules = {"app.mcp.runtime", "app.mcp.protocol"}
    violations: list[Violation] = []

    for path in _business_files():
        tree = _parse(path)
        for node in ast.walk(tree):
            imported: tuple[str, ...] = ()
            if isinstance(node, ast.Import):
                imported = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported = (_module_for_import_from(path, node),)

            for module in imported:
                if module == "app.mcp" or module.startswith("app.mcp."):
                    if module not in allowed_modules:
                        violations.append(
                            Violation(
                                path,
                                node.lineno,
                                f"business layer imports concrete MCP module {module!r}",
                            )
                        )

            if isinstance(node, ast.Call):
                called_name = ""
                if isinstance(node.func, ast.Name):
                    called_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    called_name = node.func.attr
                if called_name.startswith("invoke_") and called_name.endswith("_mcp"):
                    violations.append(
                        Violation(
                            path,
                            node.lineno,
                            f"business layer calls concrete MCP helper {called_name!r}",
                        )
                    )

                if called_name in {"import_module", "__import__"} and node.args:
                    first = node.args[0]
                    if (
                        isinstance(first, ast.Constant)
                        and isinstance(first.value, str)
                        and (first.value == "app.mcp" or first.value.startswith("app.mcp."))
                        and first.value not in allowed_modules
                    ):
                        violations.append(
                            Violation(
                                path,
                                node.lineno,
                                f"business layer dynamically imports concrete MCP module {first.value!r}",
                            )
                        )

    return tuple(violations)


def _legacy_mcp_sse_violations() -> tuple[Violation, ...]:
    production_files = list(_python_files(APP_ROOT))
    launcher = ROOT / "mcp_stdio_launcher.py"
    if launcher.is_file():
        production_files.append(launcher)

    violations: list[Violation] = []
    for path in production_files:
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "mcp.client.sse" or alias.name.startswith("mcp.client.sse."):
                        violations.append(
                            Violation(path, node.lineno, f"legacy MCP SSE import {alias.name!r}")
                        )
            elif isinstance(node, ast.ImportFrom):
                module = _module_for_import_from(path, node)
                if module == "mcp.client.sse" or module.startswith("mcp.client.sse."):
                    violations.append(
                        Violation(path, node.lineno, f"legacy MCP SSE import {module!r}")
                    )
                for alias in node.names:
                    if alias.name == "sse_client":
                        violations.append(
                            Violation(path, node.lineno, "legacy MCP sse_client import")
                        )

            if isinstance(node, (ast.Name, ast.Attribute)):
                identifier = node.id if isinstance(node, ast.Name) else node.attr
                if identifier == "sse_client":
                    violations.append(
                        Violation(path, node.lineno, "legacy MCP sse_client usage")
                    )

            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "transport"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                        and keyword.value.value.lower() in {"sse", "legacy-sse", "http+sse"}
                    ):
                        violations.append(
                            Violation(
                                path,
                                keyword.value.lineno,
                                f"legacy MCP transport {keyword.value.value!r}",
                            )
                        )

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.lower()
                if "code_scan_sse_mcp" in value:
                    violations.append(
                        Violation(path, node.lineno, "legacy code_scan_sse_mcp capability id")
                    )
                if value == "/sse" or value.endswith("/sse") or "/sse?" in value:
                    violations.append(
                        Violation(path, node.lineno, "legacy MCP /sse endpoint")
                    )

    return tuple(violations)


def _assert_no_violations(violations: tuple[Violation, ...]) -> None:
    assert not violations, "\n" + "\n".join(item.render() for item in violations)


def test_business_layers_use_only_the_mcp_broker_or_protocol() -> None:
    """Agents and state-machine nodes must not execute MCP implementations directly."""

    _assert_no_violations(_mcp_dependency_violations())


def test_production_code_does_not_reintroduce_legacy_mcp_sse() -> None:
    """Business event streams remain valid; only the retired MCP SSE transport is banned."""

    _assert_no_violations(_legacy_mcp_sse_violations())
