from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agent.task_agent import TaskAgentGraph  # noqa: E402
from app.agent.task_agent import collect_workspace_inventory  # noqa: E402
from app.source_filter import EXCLUDED_SOURCE_PARTS  # noqa: E402


DEFAULT_MANIFEST = (
    ROOT / "config" / "evaluation" / "github-multilang-high-star-random-500-2026-07-23.json"
)
DEFAULT_OUTPUT = ROOT / "docs" / "github-multilang-high-star-500-baseline-results.json"
EVALUATOR_REVISION = "2026-07-29.5"
ARCHIVE_MATERIALIZATION_REVISION = "2026-07-24.3"

SPARSE_PATTERNS = (
    "*.java",
    "*.py",
    "*.go",
    "*.c",
    "*.h",
    "*.cc",
    "*.cpp",
    "*.cxx",
    "*.hh",
    "*.hpp",
    "*.hxx",
    "*.cs",
    "*.rs",
    "*.sol",
    "pom.xml",
    "*.gradle",
    "*.gradle.kts",
    "libs.versions.toml",
    "gradle.properties",
    "requirements*.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "CMakeLists.txt",
    "compile_commands.json",
    "conanfile.txt",
    "conanfile.py",
    "conan.lock",
    "vcpkg.json",
    "vcpkg-configuration.json",
    "meson.build",
    "*.wrap",
    "Cargo.toml",
    "Cargo.lock",
    "foundry.toml",
    "remappings.txt",
    "package.json",
    "hardhat.config.js",
    "hardhat.config.ts",
    "truffle-config.js",
    "*.csproj",
    "Directory.Packages.props",
    "Directory.Build.props",
    "packages.lock.json",
    "packages.config",
    "project.assets.json",
    "NuGet.Config",
    "global.json",
)
ARCHIVE_MAX_DOWNLOAD_BYTES = 250_000_000
ARCHIVE_MAX_MATERIALIZED_BYTES = 50_000_000
ARCHIVE_MAX_MATERIALIZED_FILES = 2_000
ARCHIVE_MAX_MATERIALIZED_MANIFESTS = 200
ARCHIVE_MAX_SINGLE_FILE_BYTES = 500_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the real AegisAl workspace task pipeline on pinned multi-language GitHub projects."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/secflow-multilang-500-evaluation"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--scan-timeout", type=int, default=240)
    parser.add_argument("--project-jobs", type=int, default=1)
    parser.add_argument("--checkout-mode", choices=("archive", "git"), default="archive")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SECFLOW_SEMGREP_TIMEOUT_SECONDS": str(max(30, timeout or 180)),
    }
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=environment,
    )


def git(*args: str, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return run(
        ["git", "-c", "http.proxy=", "-c", "https.proxy=", "-c", "http.version=HTTP/1.1", *args],
        cwd=cwd,
        timeout=timeout,
    )


def ensure_git_checkout(spec: dict[str, Any], repositories: Path) -> tuple[Path, str]:
    slug = str(spec["slug"])
    target = repositories / slug.replace("/", "__")
    ref = str(spec.get("ref") or "").strip()
    if len(ref) != 40:
        raise RuntimeError(f"Repository is not pinned to a full commit: {slug}")
    created = False
    if not (target / ".git").is_dir():
        target.parent.mkdir(parents=True, exist_ok=True)
        cloned: subprocess.CompletedProcess[str] | None = None
        for attempt in range(3):
            if target.exists():
                shutil.rmtree(target)
            cloned = git(
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth",
                "1",
                str(spec["url"]),
                str(target),
            )
            if cloned.returncode == 0:
                break
            time.sleep(2 * (attempt + 1))
        assert cloned is not None
        if cloned.returncode != 0:
            raise RuntimeError((cloned.stderr or cloned.stdout).strip())
        sparse = git("sparse-checkout", "set", "--no-cone", *SPARSE_PATTERNS, cwd=target)
        if sparse.returncode != 0:
            raise RuntimeError((sparse.stderr or sparse.stdout).strip())
        created = True

    current = git("rev-parse", "HEAD", cwd=target)
    if created or current.returncode != 0 or current.stdout.strip() != ref:
        fetched = git("fetch", "--depth", "1", "origin", ref, cwd=target)
        if fetched.returncode != 0:
            raise RuntimeError((fetched.stderr or fetched.stdout).strip())
        checked = git("checkout", "--force", "--detach", "FETCH_HEAD", cwd=target)
        if checked.returncode != 0:
            raise RuntimeError((checked.stderr or checked.stdout).strip())
        reapplied = git("sparse-checkout", "reapply", cwd=target)
        if reapplied.returncode != 0:
            raise RuntimeError((reapplied.stderr or reapplied.stdout).strip())

    commit = git("rev-parse", "HEAD", cwd=target)
    if commit.returncode != 0 or commit.stdout.strip() != ref:
        raise RuntimeError(f"Checkout commit mismatch for {slug}")
    return target, commit.stdout.strip()


def archive_path_is_relevant(path: str) -> bool:
    normalized = path.replace("\\", "/").strip("/")
    pure_path = PurePosixPath(normalized)
    if not normalized or any(part.startswith(".") or part.casefold() in EXCLUDED_SOURCE_PARTS for part in pure_path.parts[:-1]):
        return False
    return any(
        fnmatch.fnmatch(pure_path.name, pattern)
        or fnmatch.fnmatch(normalized, pattern)
        for pattern in SPARSE_PATTERNS
    )


def archive_path_priority(path: str) -> tuple[int, str]:
    name = PurePosixPath(path).name.casefold()
    if name.endswith((".h", ".hh", ".hpp", ".hxx")):
        return (2, path.casefold())
    is_source = name.endswith((
        ".java", ".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".cs", ".rs", ".sol"
    ))
    return (1 if is_source else 0, path.casefold())


def download_repository_archive(spec: dict[str, Any], destination: Path) -> None:
    slug = str(spec["slug"])
    ref = str(spec["ref"])
    encoded_slug = urllib.parse.quote(slug, safe="/")
    encoded_ref = urllib.parse.quote(ref, safe="")
    url = f"https://codeload.github.com/{encoded_slug}/tar.gz/{encoded_ref}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"User-Agent": "AegisAl-Multilang-500-Evaluation"})
    for attempt in range(4):
        try:
            downloaded = 0
            with opener.open(request, timeout=120) as response, destination.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    downloaded += len(chunk)
                    if downloaded > ARCHIVE_MAX_DOWNLOAD_BYTES:
                        raise RuntimeError(
                            f"repository archive exceeds {ARCHIVE_MAX_DOWNLOAD_BYTES // 1_000_000} MB"
                        )
                    output.write(chunk)
            return
        except (urllib.error.URLError, TimeoutError, OSError):
            destination.unlink(missing_ok=True)
            if attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def materialize_repository_archive(spec: dict[str, Any], repositories: Path) -> tuple[Path, str]:
    slug = str(spec["slug"])
    ref = str(spec.get("ref") or "").strip()
    if len(ref) != 40:
        raise RuntimeError(f"Repository is not pinned to a full commit: {slug}")
    target = repositories / f"{slug.replace('/', '__')}__archive"
    marker = target / ".secflow-evaluation-commit"
    expected_marker = f"{ref}\n{ARCHIVE_MATERIALIZATION_REVISION}"
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() == expected_marker:
        return target, ref

    repositories.mkdir(parents=True, exist_ok=True)
    if target.exists():
        resolved_target = target.resolve()
        resolved_repositories = repositories.resolve()
        if resolved_target.parent != resolved_repositories:
            raise RuntimeError(f"refusing to replace archive cache outside {resolved_repositories}")
        shutil.rmtree(target)
    target.mkdir(parents=True)

    archives = repositories.parent / "archives"
    archives.mkdir(parents=True, exist_ok=True)
    archive_path = archives / f"{slug.replace('/', '__')}--{ref}.tar.gz"
    try:
        download_repository_archive(spec, archive_path)
        with tarfile.open(archive_path, mode="r:gz") as archive:
            candidates: list[tuple[str, tarfile.TarInfo]] = []
            for member in archive.getmembers():
                if not member.isfile() or member.issym() or member.islnk():
                    continue
                parts = PurePosixPath(member.name).parts
                if len(parts) < 2:
                    continue
                relative = PurePosixPath(*parts[1:]).as_posix()
                if (
                    member.size <= 0
                    or member.size > ARCHIVE_MAX_SINGLE_FILE_BYTES
                    or not archive_path_is_relevant(relative)
                ):
                    continue
                candidates.append((relative, member))

            materialized_bytes = 0
            materialized_files = 0
            materialized_manifests = 0
            for relative, member in sorted(candidates, key=lambda item: archive_path_priority(item[0])):
                if materialized_files >= ARCHIVE_MAX_MATERIALIZED_FILES:
                    break
                is_manifest = archive_path_priority(relative)[0] == 0
                if is_manifest and materialized_manifests >= ARCHIVE_MAX_MATERIALIZED_MANIFESTS:
                    continue
                if materialized_bytes + member.size > ARCHIVE_MAX_MATERIALIZED_BYTES:
                    continue
                source = archive.extractfile(member)
                if source is None:
                    continue
                data = source.read(ARCHIVE_MAX_SINGLE_FILE_BYTES + 1)
                if len(data) != member.size or b"\x00" in data[:8_192]:
                    continue
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                materialized_bytes += len(data)
                materialized_files += 1
                materialized_manifests += int(is_manifest)
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise
    finally:
        archive_path.unlink(missing_ok=True)

    marker.write_text(expected_marker + "\n", encoding="utf-8")
    return target, ref


def ensure_checkout(
    spec: dict[str, Any],
    repositories: Path,
    checkout_mode: str,
) -> tuple[Path, str]:
    if checkout_mode == "git":
        return ensure_git_checkout(spec, repositories)
    return materialize_repository_archive(spec, repositories)


def compact_findings(
    result: dict[str, Any],
    *,
    finding_key: str = "findings",
    limit: int = 30,
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    counts: Counter[str] = Counter()
    review_sample: list[dict[str, Any]] = []
    for language, language_result in (result.get("language_results") or {}).items():
        for finding in language_result.get(finding_key) or []:
            rule_id = str(finding.get("rule_id") or finding.get("id") or "unknown")
            counts[rule_id] += 1
            if len(review_sample) < limit:
                review_sample.append(
                    {
                        "language": language,
                        "rule_id": rule_id,
                        "title": str(finding.get("title") or ""),
                        "severity": str(finding.get("severity") or "UNKNOWN"),
                        "file_name": str(
                            finding.get("file_name")
                            or finding.get("file")
                            or (finding.get("sink") or {}).get("file")
                            or ""
                        ),
                        "line": finding.get("line") or finding.get("risk_line") or (finding.get("sink") or {}).get("line"),
                    }
                )
    return dict(counts.most_common()), review_sample


def scan_project(checkout: Path, spec: dict[str, Any], scan_timeout: int) -> dict[str, Any]:
    previous_semgrep_timeout = os.environ.get("SECFLOW_SEMGREP_TIMEOUT_SECONDS")
    os.environ["SECFLOW_SEMGREP_TIMEOUT_SECONDS"] = str(scan_timeout)
    started = time.monotonic()
    inventory = collect_workspace_inventory(checkout)
    try:
        state = TaskAgentGraph(adaptive_upload=False).invoke(
            task_id=f"evaluation-{str(spec['slug']).replace('/', '-')}",
            objective="Run the AegisAl code and dependency security baseline.",
            workspace_path=str(checkout),
            user_id="evaluation",
        )
    finally:
        if previous_semgrep_timeout is None:
            os.environ.pop("SECFLOW_SEMGREP_TIMEOUT_SECONDS", None)
        else:
            os.environ["SECFLOW_SEMGREP_TIMEOUT_SECONDS"] = previous_semgrep_timeout
    elapsed = round(time.monotonic() - started, 2)
    result = dict(state.get("result") or {})
    rule_counts, review_sample = compact_findings(result)
    review_rule_counts, review_candidate_sample = compact_findings(result, finding_key="review_findings")
    parse_errors = sum(
        int((item.get("syntax_summary") or {}).get("parse_error_files") or 0)
        for item in (result.get("language_results") or {}).values()
    )
    raw_parse_errors = sum(
        int((item.get("syntax_summary") or {}).get("raw_parse_error_files") or 0)
        for item in (result.get("language_results") or {}).values()
    )
    recovered_parse_errors = sum(
        int((item.get("syntax_summary") or {}).get("recovered_parse_error_files") or 0)
        for item in (result.get("language_results") or {}).values()
    )
    parse_error_file_names = [
        str(file_name)
        for item in (result.get("language_results") or {}).values()
        for file_name in (item.get("syntax_summary") or {}).get("parse_error_file_names") or []
    ]
    parse_error_file_details = [
        {
            "file_name": str(detail.get("file_name") or ""),
            "language": str(detail.get("language") or ""),
            "parser_mode": str(detail.get("parser_mode") or ""),
            "parser_error_nodes": int(detail.get("parser_error_nodes") or 0),
            "raw_parse_error": bool(detail.get("raw_parse_error")),
            "recovered_parse_error": bool(detail.get("recovered_parse_error")),
        }
        for item in (result.get("language_results") or {}).values()
        for detail in item.get("parse_error_file_details") or []
        if isinstance(detail, dict)
    ]
    scanned_files = int(result.get("total_files") or 0)
    return {
        "status": "completed",
        "elapsed_seconds": elapsed,
        "expected_language": str(spec.get("language") or ""),
        "detected_languages": list(result.get("languages") or []),
        "manifest_files": list(inventory.get("manifest_files") or []),
        "unsupported_files": list(inventory.get("unsupported_files") or []),
        "skipped_files": int(inventory.get("skipped_files") or 0),
        "scanned_files": scanned_files,
        "parse_errors": parse_errors,
        "parse_error_rate": round(parse_errors / scanned_files, 6) if scanned_files else None,
        "raw_parse_errors": raw_parse_errors,
        "raw_parse_error_rate": round(raw_parse_errors / scanned_files, 6) if scanned_files else None,
        "recovered_parse_errors": recovered_parse_errors,
        "parse_recovery_rate": (
            round(recovered_parse_errors / raw_parse_errors, 6) if raw_parse_errors else None
        ),
        "parse_error_file_names": parse_error_file_names,
        "parse_error_file_names_count": len(parse_error_file_names),
        "parse_error_file_names_truncated": False,
        "parse_error_file_details": parse_error_file_details,
        "parse_error_file_details_count": len(parse_error_file_details),
        "dependencies": int(result.get("dependency_count") or 0),
        "findings": int(result.get("total_findings") or 0),
        "review_findings": int(result.get("total_review_findings") or 0),
        "rule_counts": rule_counts,
        "review_sample": review_sample,
        "review_rule_counts": review_rule_counts,
        "review_candidate_sample": review_candidate_sample,
    }


def summarize(projects: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(item.get("status") or "unknown") for item in projects)
    language_counts = Counter(str(item.get("expected_language") or "unknown") for item in projects)
    completed = [item for item in projects if item.get("status") == "completed"]
    unsupported_projects = [
        item
        for item in completed
        if not item.get("detected_languages") and int(item.get("scanned_files") or 0) == 0
    ]
    by_language: dict[str, dict[str, Any]] = {}
    for language in sorted(language_counts, key=str.casefold):
        items = [item for item in completed if str(item.get("expected_language") or "unknown") == language]
        scanned_files = sum(int(item.get("scanned_files") or 0) for item in items)
        parse_errors = sum(int(item.get("parse_errors") or 0) for item in items)
        raw_parse_errors = sum(int(item.get("raw_parse_errors") or 0) for item in items)
        recovered_parse_errors = sum(int(item.get("recovered_parse_errors") or 0) for item in items)
        by_language[language] = {
            "projects": len(items),
            "scanned_files": scanned_files,
            "parse_errors": parse_errors,
            "parse_error_rate": round(parse_errors / scanned_files, 6) if scanned_files else None,
            "raw_parse_errors": raw_parse_errors,
            "raw_parse_error_rate": round(raw_parse_errors / scanned_files, 6) if scanned_files else None,
            "recovered_parse_errors": recovered_parse_errors,
            "parse_recovery_rate": (
                round(recovered_parse_errors / raw_parse_errors, 6) if raw_parse_errors else None
            ),
            "dependencies": sum(int(item.get("dependencies") or 0) for item in items),
            "findings": sum(int(item.get("findings") or 0) for item in items),
            "review_findings": sum(int(item.get("review_findings") or 0) for item in items),
        }
    scanned_files = sum(int(item.get("scanned_files") or 0) for item in completed)
    parse_errors = sum(int(item.get("parse_errors") or 0) for item in completed)
    raw_parse_errors = sum(int(item.get("raw_parse_errors") or 0) for item in completed)
    recovered_parse_errors = sum(int(item.get("recovered_parse_errors") or 0) for item in completed)
    return {
        "projects": len(projects),
        "completed": len(completed),
        "completion_rate": round(len(completed) / len(projects), 6) if projects else 0.0,
        "status_counts": dict(status_counts),
        "language_counts": dict(language_counts),
        "scanned_files": scanned_files,
        "parse_errors": parse_errors,
        "parse_error_rate": round(parse_errors / scanned_files, 6) if scanned_files else None,
        "raw_parse_errors": raw_parse_errors,
        "raw_parse_error_rate": round(raw_parse_errors / scanned_files, 6) if scanned_files else None,
        "recovered_parse_errors": recovered_parse_errors,
        "parse_recovery_rate": (
            round(recovered_parse_errors / raw_parse_errors, 6) if raw_parse_errors else None
        ),
        "dependencies": sum(int(item.get("dependencies") or 0) for item in completed),
        "findings": sum(int(item.get("findings") or 0) for item in completed),
        "review_findings": sum(int(item.get("review_findings") or 0) for item in completed),
        "by_language": by_language,
        "unsupported_projects": len(unsupported_projects),
    }


def stratified_project_order(
    projects: list[dict[str, Any]],
    methodology: dict[str, Any],
) -> list[dict[str, Any]]:
    configured_languages = [
        str(item.get("language") or "")
        for item in methodology.get("strata") or []
        if item.get("language")
    ]
    discovered_languages = sorted(
        {str(item.get("language") or "") for item in projects if item.get("language")},
        key=str.casefold,
    )
    languages = list(dict.fromkeys([*configured_languages, *discovered_languages]))
    groups = {
        language: [item for item in projects if str(item.get("language") or "") == language]
        for language in languages
    }
    ordered: list[dict[str, Any]] = []
    for index in range(max((len(group) for group in groups.values()), default=0)):
        for language in languages:
            group = groups[language]
            if index < len(group):
                ordered.append(group[index])
    uncategorized = [item for item in projects if not item.get("language")]
    return [*ordered, *uncategorized]


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def evaluate_project(
    index: int,
    spec: dict[str, Any],
    repositories: Path,
    checkout_mode: str,
    scan_timeout: int,
) -> tuple[int, dict[str, Any]]:
    slug = str(spec["slug"])
    item: dict[str, Any] = {
        "slug": slug,
        "url": str(spec.get("url") or ""),
        "stars": int(spec.get("stars") or 0),
        "expected_language": str(spec.get("language") or ""),
        "evaluator_revision": EVALUATOR_REVISION,
    }
    try:
        checkout, commit = ensure_checkout(spec, repositories, checkout_mode)
        item["commit"] = commit
        item["source_transport"] = checkout_mode
        item.update(scan_project(checkout, spec, scan_timeout))
    except subprocess.TimeoutExpired:
        item.update({"status": "timeout", "error": f"scan exceeded {scan_timeout}s"})
    except Exception as exc:  # noqa: BLE001 - a 500-project run must continue after one failure
        item.update({"status": "failed", "error": str(exc)[:2_000]})
    return index, item


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    methodology = dict(manifest.get("methodology") or {})
    specs = stratified_project_order(list(manifest.get("projects") or []), methodology)
    if args.limit > 0:
        specs = specs[: args.limit]
    previous_by_slug: dict[str, dict[str, Any]] = {}
    if args.resume and args.output.is_file():
        previous = json.loads(args.output.read_text(encoding="utf-8"))
        previous_by_slug = {
            str(item.get("slug") or ""): item for item in previous.get("projects") or []
        }

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "manifest": str(args.manifest.resolve()),
        "selection_methodology": methodology,
        "evaluation_policy": {
            "engine": "AegisAl TaskAgentGraph (the macOS app local backend pipeline)",
            "evaluator_revision": EVALUATOR_REVISION,
            "ground_truth": "not available for ordinary high-star repositories",
            "valid_metrics": [
                "completion_rate",
                "parser_error_rate",
                "raw_parser_error_rate",
                "parser_recovery_rate",
                "finding_density",
                "dependency_coverage",
                "manual_review_yield",
            ],
            "invalid_metrics": ["accuracy", "precision", "recall", "FPR", "FNR"],
            "qualification_source": "independent labeled corpora only",
        },
        "projects": [],
        "summary": {},
    }
    repositories = args.workspace / "repositories"
    results_by_slug: dict[str, dict[str, Any]] = {}
    pending: list[tuple[int, dict[str, Any]]] = []
    for index, spec in enumerate(specs, start=1):
        slug = str(spec["slug"])
        previous = previous_by_slug.get(slug)
        if (
            args.resume
            and previous
            and previous.get("status") == "completed"
            and previous.get("commit") == spec.get("ref")
            and previous.get("evaluator_revision") == EVALUATOR_REVISION
        ):
            results_by_slug[slug] = previous
            print(f"[{index}/{len(specs)}] reused {slug}", flush=True)
            continue
        pending.append((index, spec))

    jobs = max(1, min(int(args.project_jobs), 8, len(pending) or 1))
    completed_count = len(results_by_slug)
    with ProcessPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(
                evaluate_project,
                index,
                spec,
                repositories,
                args.checkout_mode,
                args.scan_timeout,
            ): (index, spec)
            for index, spec in pending
        }
        for future in as_completed(futures):
            index, spec = futures[future]
            try:
                _, item = future.result()
            except Exception as exc:  # noqa: BLE001 - process failures must remain resumable
                item = {
                    "slug": str(spec["slug"]),
                    "url": str(spec.get("url") or ""),
                    "stars": int(spec.get("stars") or 0),
                    "expected_language": str(spec.get("language") or ""),
                    "evaluator_revision": EVALUATOR_REVISION,
                    "status": "failed",
                    "error": str(exc)[:2_000],
                }
            results_by_slug[str(spec["slug"])] = item
            completed_count += 1
            print(
                f"[{completed_count}/{len(specs)}] {item['status']} {item['slug']} (manifest index {index})",
                flush=True,
            )
            report["projects"] = [
                results_by_slug[str(candidate["slug"])]
                for candidate in specs
                if str(candidate["slug"]) in results_by_slug
            ]
            report["generated_at"] = datetime.now(UTC).isoformat()
            report["summary"] = summarize(report["projects"])
            write_report(args.output, report)

    report["projects"] = [results_by_slug[str(spec["slug"])] for spec in specs]
    report["summary"] = summarize(report["projects"])
    write_report(args.output, report)
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    return 0 if report["summary"]["completed"] == len(specs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
