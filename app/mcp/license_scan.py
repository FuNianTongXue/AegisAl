from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import tomllib
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from app.storage import now_iso


OSI_LICENSES_API_URL = "https://opensource.org/api/licenses"
LICENSE_SCAN_SCHEMA_VERSION = 1
_MAX_FILES = 2_000
_MAX_FILE_BYTES = 512 * 1024
_MAX_TOTAL_BYTES = 12 * 1024 * 1024
_CACHE_TTL_SECONDS = 24 * 60 * 60
_LICENSE_FILE_PATTERN = re.compile(
    r"^(?:license|licence|copying|copyright|notice)(?:[-_.].*)?$",
    re.IGNORECASE,
)
_SPDX_PATTERN = re.compile(r"SPDX-License-Identifier\s*:\s*([^\r\n*]+)", re.IGNORECASE)
_EXCLUDED_PARTS = {
    ".build",
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "__pycache__",
    "bin",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "obj",
    "target",
    "vendor",
}
_MANIFEST_NAMES = {
    "cargo.toml",
    "composer.json",
    "package.json",
    "pom.xml",
    "pyproject.toml",
}
_KNOWN_LICENSES: dict[str, dict[str, Any]] = {
    "MIT": {"name": "MIT License"},
    "Apache-2.0": {"name": "Apache License 2.0"},
    "BSD-2-Clause": {"name": "BSD 2-Clause Simplified License"},
    "BSD-3-Clause": {"name": "BSD 3-Clause New or Revised License"},
    "ISC": {"name": "ISC License"},
    "GPL-2.0-only": {"name": "GNU General Public License v2.0 only"},
    "GPL-2.0-or-later": {"name": "GNU General Public License v2.0 or later"},
    "GPL-3.0-only": {"name": "GNU General Public License v3.0 only"},
    "GPL-3.0-or-later": {"name": "GNU General Public License v3.0 or later"},
    "LGPL-2.1-only": {"name": "GNU Lesser General Public License v2.1 only"},
    "LGPL-2.1-or-later": {"name": "GNU Lesser General Public License v2.1 or later"},
    "LGPL-3.0-only": {"name": "GNU Lesser General Public License v3.0 only"},
    "AGPL-3.0-only": {"name": "GNU Affero General Public License v3.0 only"},
    "MPL-2.0": {"name": "Mozilla Public License 2.0"},
    "EPL-2.0": {"name": "Eclipse Public License 2.0"},
    "Unlicense": {"name": "The Unlicense"},
}
_ALIASES = {
    "apache 2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "mozilla public license 2.0": "MPL-2.0",
}
_TEXT_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("MIT", ("permission is hereby granted, free of charge", "the software is provided \"as is\"")),
    ("Apache-2.0", ("apache license", "version 2.0, january 2004")),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "neither the name of")),
    ("BSD-2-Clause", ("redistribution and use in source and binary forms", "this list of conditions and the following disclaimer")),
    ("ISC", ("permission to use, copy, modify, and/or distribute this software", "the software is provided \"as is\"")),
    ("AGPL-3.0-only", ("gnu affero general public license", "version 3")),
    ("LGPL-3.0-only", ("gnu lesser general public license", "version 3")),
    ("LGPL-2.1-only", ("gnu lesser general public license", "version 2.1")),
    ("GPL-3.0-only", ("gnu general public license", "version 3")),
    ("GPL-2.0-only", ("gnu general public license", "version 2")),
    ("MPL-2.0", ("mozilla public license", "version 2.0")),
    ("EPL-2.0", ("eclipse public license", "version 2.0")),
    ("Unlicense", ("this is free and unencumbered software released into the public domain",)),
)

_registry_lock = RLock()
_registry_cache: tuple[float, list[dict[str, Any]]] | None = None

license_scan_mcp = FastMCP(
    "AegisAl License MCP",
    instructions=(
        "Read only dependency manifests, SPDX declarations, and license evidence from an explicitly "
        "authorized workspace. Do not run static code analysis, project code, builds, or package hooks."
    ),
)


def identify_workspace_licenses(
    workspace: Path,
    *,
    registry_fetcher: Callable[[], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    root = workspace.resolve(strict=True)
    registry, registry_source = _load_registry(registry_fetcher)
    registry_index = _registry_index(registry)
    detections: dict[str, dict[str, Any]] = {}
    scanned_files: list[dict[str, Any]] = []
    candidate_files = _candidate_files(root)
    total_bytes = 0

    for path, relative in candidate_files:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_BYTES or total_bytes + size > _MAX_TOTAL_BYTES:
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8_192]:
            continue
        total_bytes += len(raw)
        text = raw.decode("utf-8", errors="replace")
        methods: list[str] = []
        file_ids: list[str] = []

        for expression in _SPDX_PATTERN.findall(text[:128_000]):
            for license_id in _license_ids_from_expression(expression, registry_index):
                _record_detection(detections, license_id, relative, "spdx-identifier", expression)
                file_ids.append(license_id)
                methods.append("spdx-identifier")

        for declaration in _manifest_license_declarations(path, text):
            for license_id in _license_ids_from_expression(declaration, registry_index):
                _record_detection(detections, license_id, relative, "manifest-declaration", declaration)
                file_ids.append(license_id)
                methods.append("manifest-declaration")

        if _LICENSE_FILE_PATTERN.fullmatch(path.name):
            for license_id in _license_ids_from_file_name(path.name, registry_index):
                _record_detection(detections, license_id, relative, "license-file-name", path.name)
                file_ids.append(license_id)
                methods.append("license-file-name")
            for license_id in _license_ids_from_text(text):
                _record_detection(detections, license_id, relative, "license-text-signature", "")
                file_ids.append(license_id)
                methods.append("license-text-signature")

        if methods:
            scanned_files.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "methods": sorted(set(methods)),
                    "licenses": sorted(set(file_ids)),
                }
            )

    licenses = [_finalize_detection(item, registry_index) for item in detections.values()]
    licenses.sort(key=lambda item: (str(item.get("spdx_id") or "").casefold(), str(item.get("name") or "").casefold()))
    coverage_status = "complete" if registry_source["status"] == "completed" else "partial"
    return {
        "schema_version": LICENSE_SCAN_SCHEMA_VERSION,
        "generated_at": now_iso(),
        "project_name": root.name,
        "coverage_status": coverage_status,
        "license_count": len(licenses),
        "licenses": licenses,
        "scanned_file_count": len(candidate_files),
        "evidence_file_count": len(scanned_files),
        "scanned_bytes": total_bytes,
        "evidence_files": scanned_files,
        "registry": registry_source,
        "limitations": [
            "许可识别基于项目文件、SPDX 声明和清单字段，不等同于法律意见。",
            "依赖组件自身的许可需结合包仓库元数据或发布物进一步核验。",
        ],
    }


def _candidate_files(workspace: Path) -> list[tuple[Path, str]]:
    if workspace.is_file():
        return [(workspace, workspace.name)]
    selected: list[tuple[Path, str]] = []
    try:
        paths = workspace.rglob("*")
        for path in paths:
            if len(selected) >= _MAX_FILES:
                break
            try:
                relative_path = path.relative_to(workspace)
            except ValueError:
                continue
            if any(_is_excluded_part(part) for part in relative_path.parts[:-1]):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            name = path.name.casefold()
            if (
                _LICENSE_FILE_PATTERN.fullmatch(path.name)
                or name in _MANIFEST_NAMES
                or path.suffix.casefold() == ".nuspec"
            ):
                selected.append((path, relative_path.as_posix()))
    except OSError:
        return selected
    selected.sort(key=lambda item: item[1].casefold())
    return selected


def _is_excluded_part(value: str) -> bool:
    clean = value.casefold()
    return clean in _EXCLUDED_PARTS or bool(
        re.fullmatch(r"(?:build|dist|output|release|tmp)[-_.].*", clean)
    )


def _manifest_license_declarations(path: Path, text: str) -> list[str]:
    name = path.name.casefold()
    values: list[Any] = []
    try:
        if name in {"package.json", "composer.json"}:
            payload = json.loads(text)
            if isinstance(payload, dict):
                values.append(payload.get("license"))
                values.append(payload.get("licenses"))
        elif name == "pyproject.toml":
            payload = tomllib.loads(text)
            project = payload.get("project") if isinstance(payload.get("project"), dict) else {}
            poetry = ((payload.get("tool") or {}).get("poetry") or {}) if isinstance(payload.get("tool"), dict) else {}
            license_value = project.get("license")
            if isinstance(license_value, dict):
                values.extend([license_value.get("text"), license_value.get("file")])
            else:
                values.append(license_value)
            values.append(poetry.get("license") if isinstance(poetry, dict) else None)
        elif name == "cargo.toml":
            payload = tomllib.loads(text)
            package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
            values.extend([package.get("license"), package.get("license-file")])
        elif name == "pom.xml" or path.suffix.casefold() == ".nuspec":
            root = ET.fromstring(text)
            for element in root.iter():
                tag = str(element.tag).rsplit("}", 1)[-1].casefold()
                if tag in {"license", "name", "expression"} and element.text:
                    parent_text = element.text.strip()
                    if parent_text:
                        values.append(parent_text)
    except (ET.ParseError, json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, ValueError):
        return []
    return _flatten_text_values(values)


def _flatten_text_values(values: list[Any]) -> list[str]:
    result: list[str] = []
    pending = list(values)
    while pending:
        value = pending.pop(0)
        if isinstance(value, str) and value.strip():
            result.append(value.strip())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, dict):
            pending.extend(value.values())
    return result


def _license_ids_from_expression(expression: str, registry_index: dict[str, dict[str, Any]]) -> list[str]:
    text = str(expression or "").strip()
    if not text:
        return []
    direct = _canonical_license_id(text, registry_index)
    if direct:
        return [direct]
    results: list[str] = []
    for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", text):
        if token.casefold() in {"and", "or", "with", "license", "version", "file", "see"}:
            continue
        canonical = _canonical_license_id(token, registry_index)
        if canonical and canonical not in results:
            results.append(canonical)
    return results


def _license_ids_from_file_name(name: str, registry_index: dict[str, dict[str, Any]]) -> list[str]:
    stem = re.sub(r"^(?:license|licence|copying|copyright|notice)[-_.]*", "", name, flags=re.IGNORECASE)
    return _license_ids_from_expression(stem, registry_index) if stem else []


def _license_ids_from_text(text: str) -> list[str]:
    normalized = re.sub(r"\s+", " ", text.casefold())
    results: list[str] = []
    for license_id, signatures in _TEXT_SIGNATURES:
        if all(signature in normalized for signature in signatures) and license_id not in results:
            results.append(license_id)
    if "redistribution and use in source and binary forms" in normalized:
        if "neither the name of" in normalized:
            return ["BSD-3-Clause"]
        return ["BSD-2-Clause"]
    return results[:1]


def _canonical_license_id(value: str, registry_index: dict[str, dict[str, Any]]) -> str:
    clean = re.sub(r"\s+", " ", str(value or "").strip()).strip("()[]{}.,;:\"")
    if not clean:
        return ""
    alias = _ALIASES.get(clean.casefold())
    if alias:
        return alias
    entry = registry_index.get(clean.casefold())
    if entry:
        return str(entry.get("spdx_id") or entry.get("id") or clean)
    known = next((license_id for license_id in _KNOWN_LICENSES if license_id.casefold() == clean.casefold()), "")
    return known


def _record_detection(
    detections: dict[str, dict[str, Any]],
    license_id: str,
    source_file: str,
    method: str,
    declaration: str,
) -> None:
    item = detections.setdefault(
        license_id,
        {
            "spdx_id": license_id,
            "source_files": [],
            "detection_methods": [],
            "declarations": [],
        },
    )
    if source_file not in item["source_files"]:
        item["source_files"].append(source_file)
    if method not in item["detection_methods"]:
        item["detection_methods"].append(method)
    clean_declaration = str(declaration or "").strip()
    if clean_declaration and clean_declaration not in item["declarations"]:
        item["declarations"].append(clean_declaration[:500])


def _finalize_detection(item: dict[str, Any], registry_index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    license_id = str(item.get("spdx_id") or "")
    registry = registry_index.get(license_id.casefold()) or {}
    registry_listed = bool(registry) and not bool(registry.get("_fallback"))
    fallback = _KNOWN_LICENSES.get(license_id, {})
    methods = list(item.get("detection_methods") or [])
    confidence = 1.0 if "spdx-identifier" in methods else 0.95 if "manifest-declaration" in methods else 0.9 if "license-text-signature" in methods else 0.7
    links = registry.get("_links") if isinstance(registry.get("_links"), dict) else {}
    html_link = links.get("html") if isinstance(links.get("html"), dict) else {}
    self_link = links.get("self") if isinstance(links.get("self"), dict) else {}
    official_url = str(html_link.get("href") or "")
    return {
        "spdx_id": license_id,
        "name": str(registry.get("name") or fallback.get("name") or license_id),
        "confidence": confidence,
        "source_files": sorted(item.get("source_files") or []),
        "detection_methods": sorted(methods),
        "declarations": list(item.get("declarations") or []),
        "osi": {
            "listed": registry_listed,
            "approved": bool(registry.get("approved")) if registry_listed else None,
            "approval_status": "approved" if registry.get("approved") else "not_indicated" if registry_listed else "not_found",
            "keywords": [str(value) for value in registry.get("keywords") or []],
            "official_url": official_url,
            "api_url": str(self_link.get("href") or ""),
        },
    }


def _load_registry(
    fetcher: Callable[[], list[dict[str, Any]]] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    global _registry_cache
    fetched_at = now_iso()
    try:
        if fetcher is not None:
            entries = _normalize_registry(fetcher())
            cache_hit = False
        else:
            with _registry_lock:
                if _registry_cache and time.monotonic() - _registry_cache[0] < _CACHE_TTL_SECONDS:
                    entries = list(_registry_cache[1])
                    cache_hit = True
                else:
                    entries = _normalize_registry(_fetch_osi_registry())
                    _registry_cache = (time.monotonic(), list(entries))
                    cache_hit = False
        return entries, {
            "id": "osi-license-api",
            "name": "Open Source Initiative License API",
            "url": OSI_LICENSES_API_URL,
            "status": "completed",
            "fetched_at": fetched_at,
            "record_count": len(entries),
            "cache_hit": cache_hit,
            "error": "",
        }
    except Exception as exc:  # noqa: BLE001 - local identification remains useful and auditable.
        return [], {
            "id": "osi-license-api",
            "name": "Open Source Initiative License API",
            "url": OSI_LICENSES_API_URL,
            "status": "unavailable",
            "fetched_at": fetched_at,
            "record_count": 0,
            "cache_hit": False,
            "error": type(exc).__name__,
        }


def _fetch_osi_registry() -> list[dict[str, Any]]:
    timeout = max(1.0, min(float(os.getenv("SECFLOW_OSI_LICENSE_API_TIMEOUT_SECONDS", "8") or 8), 30.0))
    request = urllib.request.Request(
        OSI_LICENSES_API_URL,
        headers={"Accept": "application/json", "User-Agent": "AegisAl-License-Scanner/1"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is a fixed trusted constant.
        if int(getattr(response, "status", 200)) != 200:
            raise RuntimeError("OSI License API returned a non-200 response")
        payload = json.loads(response.read(4 * 1024 * 1024).decode("utf-8"))
    if not isinstance(payload, list):
        raise ValueError("OSI License API response is not an array")
    return [item for item in payload if isinstance(item, dict)]


def _normalize_registry(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in values
        if isinstance(item, dict) and str(item.get("spdx_id") or item.get("id") or "").strip()
    ]


def _registry_index(values: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in values:
        for key in (item.get("spdx_id"), item.get("id"), item.get("name")):
            clean = str(key or "").strip().casefold()
            if clean:
                index[clean] = item
    for license_id, fallback in _KNOWN_LICENSES.items():
        index.setdefault(license_id.casefold(), {"spdx_id": license_id, **fallback, "_fallback": True})
    return index


@license_scan_mcp.tool(
    name="identify_project_licenses",
    description="Identify project licenses without invoking the full code scanning engine.",
    structured_output=True,
)
def identify_project_licenses(workspace_path: str) -> dict[str, Any]:
    logical_input = {
        "schema_version": LICENSE_SCAN_SCHEMA_VERSION,
        "workspace_path": str(Path(workspace_path).expanduser().resolve(strict=True)),
        "registry": OSI_LICENSES_API_URL,
    }
    started_at = now_iso()
    started = time.monotonic()
    result = identify_workspace_licenses(Path(logical_input["workspace_path"]))
    result["_license_mcp"] = {
        "schema_version": LICENSE_SCAN_SCHEMA_VERSION,
        "server": license_scan_mcp.name,
        "tool": "identify_project_licenses",
        "transport": "in-process",
        "engine": "AegisAl License Analyzer",
        "process_id": os.getpid(),
        "started_at": started_at,
        "completed_at": now_iso(),
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "input_sha256": _json_sha256(logical_input),
        "output_sha256": _json_sha256(result),
        "status": "completed",
    }
    return result


def invoke_license_scan_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    response = asyncio.run(license_scan_mcp.call_tool("identify_project_licenses", arguments))
    if isinstance(response, tuple) and len(response) == 2 and isinstance(response[1], dict):
        return dict(response[1])
    raise RuntimeError("License MCP did not return structured output")


async def license_scan_mcp_spec() -> dict[str, Any]:
    tools = await license_scan_mcp.list_tools()
    return {
        "id": "license-scan",
        "name": license_scan_mcp.name,
        "transport": "in-process+stdio",
        "tools": [
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema,
                "output_schema": tool.outputSchema or {},
            }
            for tool in tools
        ],
    }


def _json_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
