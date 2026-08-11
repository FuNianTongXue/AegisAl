from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.language_support import (  # noqa: E402
    _normalized_preprocessor_definitions,
    _parse_source,
    _parser_for,
    analyze_source_structure,
    language_for_file,
)
from app.semgrep_tool import (  # noqa: E402
    _compile_definitions_by_source_file,
    _compile_definitions_for_file,
    _project_preprocessor_definitions,
)
from app.source_filter import is_symlink_like_source_stub  # noqa: E402


DEFAULT_MANIFEST = ROOT / "config" / "evaluation" / "github-multilang-high-star-random-500-2026-07-23.json"
DEFAULT_PREVIOUS_RESULT = ROOT / "docs" / "github-multilang-high-star-500-revision-4-results.json"
DEFAULT_OUTPUT = ROOT / "docs" / "github-multilang-high-star-500-parser-recovery-delta-v1-results.json"
DEFAULT_CACHE_DIR = Path("/tmp/secflow-parser-recovery-delta-cache")
DELTA_REVISION = "2026-07-25.17"
COMPILE_DATABASE_CANDIDATE_PATHS = (
    "compile_commands.json",
    "build/compile_commands.json",
    "cmake-build-debug/compile_commands.json",
    "cmake-build-release/compile_commands.json",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Re-run the current Tree-sitter compatibility parser on files that were parse errors "
            "in a previous pinned GitHub high-star evaluation result."
        )
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--previous-result", type=Path, default=DEFAULT_PREVIOUS_RESULT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--slugs", default="", help="Comma-separated repository slugs to include.")
    parser.add_argument("--languages", default="", help="Comma-separated expected languages to include, e.g. C,C++.")
    parser.add_argument("--limit", type=int, default=0, help="Maximum total files to analyze after filtering.")
    parser.add_argument("--max-files-per-project", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args(argv)

    manifest = load_json(args.manifest)
    previous = load_json(args.previous_result)
    plan = build_sample_plan(
        manifest,
        previous,
        slugs=csv_set(args.slugs),
        languages=csv_set(args.languages),
        limit=args.limit,
        max_files_per_project=args.max_files_per_project,
    )
    started = time.monotonic()
    report = evaluate_plan(
        plan,
        manifest_path=args.manifest,
        previous_result_path=args.previous_result,
        cache_dir=args.cache_dir,
        timeout=args.timeout,
        elapsed_start=started,
    )
    write_report(args.output, report)
    summary = report["summary"]
    print(
        "Parser recovery delta complete: "
        f"analyzed={summary['analyzed_files']} recovered={summary['newly_recovered_files']} "
        f"still_parse_error={summary['still_parse_error_files']} unavailable={summary['unavailable_files']} "
        f"source_stubs={summary['source_stub_files']} "
        f"output={args.output}"
    )
    return 0 if not summary["failed_projects"] else 2


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def build_sample_plan(
    manifest: dict[str, Any],
    previous: dict[str, Any],
    *,
    slugs: set[str],
    languages: set[str],
    limit: int,
    max_files_per_project: int,
) -> list[dict[str, Any]]:
    specs_by_slug = {str(item.get("slug") or ""): item for item in manifest.get("projects") or []}
    plan: list[dict[str, Any]] = []
    total = 0
    for previous_project in previous.get("projects") or []:
        slug = str(previous_project.get("slug") or "")
        spec = specs_by_slug.get(slug)
        if not slug or spec is None:
            continue
        expected_language = str(previous_project.get("expected_language") or spec.get("language") or "")
        if slugs and slug not in slugs:
            continue
        if languages and expected_language not in languages:
            continue
        file_names = list(dict.fromkeys(str(item) for item in previous_project.get("parse_error_file_names") or [] if item))
        if max_files_per_project > 0:
            file_names = file_names[:max_files_per_project]
        if limit > 0:
            remaining = limit - total
            if remaining <= 0:
                break
            file_names = file_names[:remaining]
        if not file_names:
            continue
        plan.append(
            {
                "slug": slug,
                "ref": str(spec.get("ref") or previous_project.get("commit") or ""),
                "expected_language": expected_language,
                "previous_evaluator_revision": str(previous_project.get("evaluator_revision") or ""),
                "previous_parse_errors": int(previous_project.get("parse_errors") or 0),
                "previous_raw_parse_errors": int(previous_project.get("raw_parse_errors") or 0),
                "previous_recovered_parse_errors": int(previous_project.get("recovered_parse_errors") or 0),
                "files": file_names,
            }
        )
        total += len(file_names)
    return plan


def evaluate_plan(
    plan: list[dict[str, Any]],
    *,
    manifest_path: Path,
    previous_result_path: Path,
    cache_dir: Path,
    timeout: int,
    elapsed_start: float,
) -> dict[str, Any]:
    projects: list[dict[str, Any]] = []
    for project in plan:
        projects.append(evaluate_project(project, cache_dir=cache_dir, timeout=timeout))
    elapsed = round(time.monotonic() - elapsed_start, 2)
    summary = summarize(projects)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "delta_revision": DELTA_REVISION,
        "metric_scope": "parser_recovery_delta_on_recorded_revision4_parse_errors",
        "security_truth_scope": "none",
        "interpretation": (
            "Each analyzed file was listed as a final parse error in the previous 500-project result. "
            "A newly_recovered file means the current parser no longer reports a parse error for that pinned source file. "
            "A skipped_source_stub file is an archive/raw materialized symlink target and is excluded from parser recovery math. "
            "This measures AST coverage only; it is not accuracy, precision, recall, FPR, or FNR."
        ),
        "manifest": str(manifest_path.resolve()),
        "previous_result": str(previous_result_path.resolve()),
        "language_support_sha256": sha256_file(ROOT / "app" / "language_support.py"),
        "semgrep_tool_sha256": sha256_file(ROOT / "app" / "semgrep_tool.py"),
        "source_filter_sha256": sha256_file(ROOT / "app" / "source_filter.py"),
        "elapsed_seconds": elapsed,
        "summary": summary,
        "projects": projects,
    }


def evaluate_project(project: dict[str, Any], *, cache_dir: Path, timeout: int) -> dict[str, Any]:
    slug = str(project["slug"])
    ref = str(project["ref"])
    context_files = [
        *fetch_project_compile_databases(slug, ref, cache_dir=cache_dir, timeout=timeout),
        *fetch_project_cmake_files(
            slug,
            ref,
            [str(item) for item in project.get("files") or []],
            cache_dir=cache_dir,
            timeout=timeout,
        ),
    ]
    compile_definitions = _compile_definitions_by_source_file(context_files)
    project_preprocessor_definitions = _project_preprocessor_definitions(context_files)
    files: list[dict[str, Any]] = []
    for file_name in project.get("files") or []:
        file_result = evaluate_file(
            slug,
            ref,
            str(file_name),
            cache_dir=cache_dir,
            timeout=timeout,
            compile_definitions=compile_definitions,
            project_preprocessor_definitions=project_preprocessor_definitions,
        )
        files.append(file_result)
    analyzed = [item for item in files if item["status"] == "analyzed"]
    source_stubs = [item for item in files if item["status"] == "skipped_source_stub"]
    unavailable = [item for item in files if item["status"] == "unavailable"]
    recovered = [item for item in analyzed if item["current_parse_error"] is False]
    still_error = [item for item in analyzed if item["current_parse_error"] is True]
    error_class_counts = summarize_error_classes(files)
    return {
        "slug": slug,
        "ref": ref,
        "expected_language": str(project.get("expected_language") or ""),
        "previous_evaluator_revision": str(project.get("previous_evaluator_revision") or ""),
        "previous_parse_errors": int(project.get("previous_parse_errors") or 0),
        "previous_raw_parse_errors": int(project.get("previous_raw_parse_errors") or 0),
        "previous_recovered_parse_errors": int(project.get("previous_recovered_parse_errors") or 0),
        "context_files": [item["file_name"] for item in context_files],
        "compile_database_files": [
            item["file_name"] for item in context_files if Path(item["file_name"]).name.lower() == "compile_commands.json"
        ],
        "compile_definition_entries": len(compile_definitions),
        "project_preprocessor_definition_count": len(project_preprocessor_definitions),
        "candidate_files": len(project.get("files") or []),
        "analyzed_files": len(analyzed),
        "source_stub_files": len(source_stubs),
        "newly_recovered_files": len(recovered),
        "still_parse_error_files": len(still_error),
        "unavailable_files": len(unavailable),
        "error_class_counts": error_class_counts,
        "files": files,
    }


def evaluate_file(
    slug: str,
    ref: str,
    file_name: str,
    *,
    cache_dir: Path,
    timeout: int,
    compile_definitions: list[dict[str, Any]] | None = None,
    project_preprocessor_definitions: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        content = fetch_pinned_file(slug, ref, file_name, cache_dir=cache_dir, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - delta reports must remain resumable
        return {
            "file_name": file_name,
            "status": "unavailable",
            "error": str(exc)[:500],
            "previous_parse_error": True,
            "current_parse_error": None,
        }
    if is_symlink_like_source_stub(file_name, content):
        return {
            "file_name": file_name,
            "status": "skipped_source_stub",
            "previous_parse_error": True,
            "current_parse_error": None,
            "stub_target": content.strip()[:512],
        }
    definitions = _compile_definitions_for_file(file_name, compile_definitions or [])
    analysis = analyze_source_structure(
        file_name,
        content,
        preprocessor_definitions={**(project_preprocessor_definitions or {}), **definitions},
    )
    parser_error_sample = []
    if analysis.get("parse_error"):
        parser_error_sample = parser_error_diagnostics(
            file_name,
            content,
            preprocessor_definitions={**(project_preprocessor_definitions or {}), **definitions},
        )
    return {
        "file_name": file_name,
        "status": "analyzed",
        "previous_parse_error": True,
        "current_parse_error": bool(analysis.get("parse_error")),
        "raw_parse_error": bool(analysis.get("raw_parse_error")),
        "recovered_parse_error": bool(analysis.get("recovered_parse_error")),
        "parser_mode": str(analysis.get("parser_mode") or ""),
        "parser_error_nodes": int(analysis.get("parser_error_nodes") or 0),
        "preprocessor_definition_count": int(analysis.get("preprocessor_definition_count") or 0),
        "language": str(analysis.get("language") or ""),
        "ast_node_count": int(analysis.get("ast_node_count") or 0),
        "function_sample": list(analysis.get("functions") or [])[:8],
        "type_sample": list(analysis.get("types") or [])[:8],
        "parser_error_sample": parser_error_sample,
        "parser_error_classes": list(dict.fromkeys(item["classification"] for item in parser_error_sample)),
    }


def parser_error_diagnostics(
    file_name: str,
    content: str,
    *,
    preprocessor_definitions: dict[str, str] | None = None,
    limit: int = 3,
) -> list[dict[str, Any]]:
    language = language_for_file(file_name)
    if language not in {"c", "cpp"}:
        return []
    parser = _parser_for(language)
    if parser is None:
        return []
    source = content.encode("utf-8", errors="replace")
    tree, parser_mode, _ = _parse_source(
        language,
        source,
        parser,
        preprocessor_definitions=_normalized_preprocessor_definitions(preprocessor_definitions),
    )
    diagnostics: list[dict[str, Any]] = []
    for node in walk_parser_nodes(tree.root_node):
        if node.type != "ERROR" and not node.is_missing:
            continue
        line_number = node.start_point.row + 1
        snippet = source_excerpt(source, node.start_byte, node.end_byte)
        diagnostics.append(
            {
                "line": line_number,
                "node_type": node.type,
                "missing": bool(node.is_missing),
                "start_point": [node.start_point.row + 1, node.start_point.column],
                "end_point": [node.end_point.row + 1, node.end_point.column],
                "parser_mode": parser_mode,
                "classification": classify_parser_error(
                    snippet,
                    parser_mode,
                    node_type=node.type,
                    missing=bool(node.is_missing),
                ),
                "snippet": snippet,
            }
        )
        if len(diagnostics) >= limit:
            break
    return diagnostics


def walk_parser_nodes(root: Any) -> list[Any]:
    nodes: list[Any] = []
    stack = [root]
    while stack:
        node = stack.pop()
        nodes.append(node)
        stack.extend(reversed(node.children))
    return nodes


def source_excerpt(source: bytes, start: int, end: int, *, radius: int = 400) -> str:
    lower = max(0, start - radius)
    upper = min(len(source), max(end, start + 1) + radius)
    text = source[lower:upper].decode("utf-8", errors="replace")
    return " ".join(text.replace("\r", " ").split())[:800]


def classify_parser_error(
    snippet: str,
    parser_mode: str,
    *,
    node_type: str = "",
    missing: bool = False,
) -> str:
    text = snippet.lower()
    if missing and node_type in {";", "}", ")"}:
        return "syntactically_incomplete_source"
    if re.search(r"\}\s+(?:static\s+)?(?:[a-z_]\w*\s+){1,3}[a-z_]\w+\s*\(", snippet):
        return "syntactically_incomplete_source"
    if re.search(r"\bstruct\s+\w+\s*\{[^{}]*\}\s*/\*.*\*/\s*static\s+", text):
        return "syntactically_incomplete_source"
    if re.search(r",\s*if\s*\(", text):
        return "syntactically_incomplete_source"
    if 'before "or any combination of the above"' in text:
        return "source_fragment_or_unfinished_file"
    if "#" in snippet and any(marker in text for marker in ("#if", "#ifdef", "#ifndef", "#elif", "#endif")):
        return "conditional_preprocessor"
    if any(marker in snippet for marker in ("__attribute__", "__declspec", "__asm", "asm(")):
        return "compiler_extension"
    if any(marker in snippet for marker in ("EFI_", "EFIAPI", "EDKII", "EDK2", "GUID")):
        return "uefi_edk_macro_context"
    if any(marker in snippet for marker in ("QObject", "Q_OBJECT", "Q_PROPERTY", "Q_INVOKABLE", "signals", "slots")):
        return "qt_moc_extension"
    if any(marker in snippet for marker in ("template<", "template <", "::", "namespace")) and "cpp-fallback" not in parser_mode:
        return "cpp_construct_in_c_context"
    if any(marker in snippet for marker in ("#define", "\\\n")):
        return "macro_definition_continuation"
    if any(token.isupper() and len(token) >= 3 for token in snippet.replace("(", " ").replace(")", " ").split()):
        return "unexpanded_macro_or_typedef"
    return "unclassified_syntax"


def fetch_project_compile_databases(
    slug: str,
    ref: str,
    *,
    cache_dir: Path,
    timeout: int,
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for file_name in COMPILE_DATABASE_CANDIDATE_PATHS:
        try:
            content = fetch_pinned_file(slug, ref, file_name, cache_dir=cache_dir, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - compile database context is optional
            if "HTTP 404" not in str(exc):
                continue
            continue
        result.append({"file_name": file_name, "content": content})
    return result


def fetch_project_cmake_files(
    slug: str,
    ref: str,
    file_names: list[str],
    *,
    cache_dir: Path,
    timeout: int,
) -> list[dict[str, str]]:
    candidates = ["CMakeLists.txt"]
    for file_name in file_names:
        parent = Path(file_name.replace("\\", "/")).parent
        for directory in [*parent.parents[::-1], parent]:
            if str(directory) in {"", "."}:
                continue
            candidates.append((directory / "CMakeLists.txt").as_posix())
    result: list[dict[str, str]] = []
    for file_name in dict.fromkeys(candidates):
        try:
            content = fetch_pinned_file(slug, ref, file_name, cache_dir=cache_dir, timeout=timeout)
        except Exception:
            continue
        result.append({"file_name": file_name, "content": content})
    return result


def fetch_pinned_file(slug: str, ref: str, file_name: str, *, cache_dir: Path, timeout: int) -> str:
    cache_path = cache_dir / slug.replace("/", "__") / ref / file_name
    if cache_path.is_file():
        return cache_path.read_text(encoding="utf-8", errors="replace")
    quoted_path = urllib.parse.quote(file_name, safe="/")
    url = f"https://raw.githubusercontent.com/{slug}/{ref}/{quoted_path}"
    request = urllib.request.Request(url, headers={"User-Agent": "SecFlow-parser-recovery-delta/1.0"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(1_000_001)
            break
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code} fetching {url}") from exc
        except (TimeoutError, urllib.error.URLError) as exc:
            if attempt == 2:
                raise RuntimeError(f"transient URL error fetching {url}: {exc}") from exc
            time.sleep(0.25 * (attempt + 1))
    if len(data) > 1_000_000:
        raise RuntimeError(f"file exceeds 1 MB parser delta safety limit: {file_name}")
    if b"\x00" in data[:8192]:
        raise RuntimeError(f"binary-looking file skipped: {file_name}")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(data)
    return data.decode("utf-8", errors="replace")


def summarize(projects: list[dict[str, Any]]) -> dict[str, Any]:
    candidate_files = sum(int(item.get("candidate_files") or 0) for item in projects)
    analyzed_files = sum(int(item.get("analyzed_files") or 0) for item in projects)
    source_stub_files = sum(int(item.get("source_stub_files") or 0) for item in projects)
    newly_recovered_files = sum(int(item.get("newly_recovered_files") or 0) for item in projects)
    still_parse_error_files = sum(int(item.get("still_parse_error_files") or 0) for item in projects)
    unavailable_files = sum(int(item.get("unavailable_files") or 0) for item in projects)
    failed_projects = sum(1 for item in projects if int(item.get("unavailable_files") or 0) == int(item.get("candidate_files") or 0))
    error_class_counts = summarize_error_classes(
        [file_result for project in projects for file_result in project.get("files") or []]
    )
    return {
        "projects": len(projects),
        "candidate_files": candidate_files,
        "analyzed_files": analyzed_files,
        "source_stub_files": source_stub_files,
        "newly_recovered_files": newly_recovered_files,
        "still_parse_error_files": still_parse_error_files,
        "unavailable_files": unavailable_files,
        "recovery_rate_on_analyzed_files": round(newly_recovered_files / analyzed_files, 6) if analyzed_files else None,
        "failed_projects": failed_projects,
        "error_class_counts": error_class_counts,
    }


def summarize_error_classes(files: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for file_result in files:
        for class_name in file_result.get("parser_error_classes") or []:
            counts[str(class_name)] = counts.get(str(class_name), 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


if __name__ == "__main__":
    raise SystemExit(main())
