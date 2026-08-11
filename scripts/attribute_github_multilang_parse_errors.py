from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DEFAULT_RESULT = ROOT / "docs" / "github-multilang-high-star-500-revision-4-results.json"
DEFAULT_OUTPUT = ROOT / "docs" / "github-multilang-high-star-500-revision-4-parse-error-attribution.json"
DEFAULT_DELTA_RESULTS = (
    ROOT / "docs" / "github-multilang-high-star-500-parser-recovery-delta-v1-c-cpp-100-results.json",
)
ATTRIBUTION_REVISION = "2026-07-29.1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize parse-error attribution coverage for a pinned GitHub high-star evaluation result. "
            "This script is metadata-only unless parser delta reports are supplied."
        )
    )
    parser.add_argument("--result", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--parser-delta-result",
        type=Path,
        action="append",
        default=None,
        help="Parser recovery delta JSON to fold into the attribution evidence.",
    )
    args = parser.parse_args(argv)

    delta_paths = args.parser_delta_result if args.parser_delta_result is not None else list(DEFAULT_DELTA_RESULTS)
    report = build_report(load_json(args.result), result_path=args.result, parser_delta_paths=delta_paths)
    write_report(args.output, report)
    summary = report["summary"]
    print(
        "Parse-error attribution coverage complete: "
        f"parse_errors={summary['parse_errors']} recorded_names={summary['recorded_parse_error_file_names']} "
        f"unrecorded_names={summary['unrecorded_parse_error_file_names']} "
        f"truncated_projects={summary['projects_with_truncated_parse_error_names']} "
        f"output={args.output}"
    )
    return 0


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def build_report(
    result: dict[str, Any],
    *,
    result_path: Path,
    parser_delta_paths: list[Path],
) -> dict[str, Any]:
    summary, by_language, truncated_projects = summarize_parse_error_name_coverage(result)
    parser_delta_evidence = [
        summarize_parser_delta_result(path, load_json(path))
        for path in parser_delta_paths
        if path.is_file()
    ]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "attribution_revision": ATTRIBUTION_REVISION,
        "metric_scope": "parse_error_attribution_coverage",
        "security_truth_scope": "none",
        "source_result": str(result_path.resolve()),
        "interpretation": (
            "This report audits parse-error file-name coverage and folds in parser recovery delta evidence. "
            "It does not measure security accuracy, precision, recall, FPR, or FNR. "
            "When recorded_parse_error_file_names is lower than parse_errors, the legacy result cannot support "
            "complete per-file attribution without a fresh full scan."
        ),
        "summary": summary,
        "by_language": by_language,
        "truncated_projects": truncated_projects,
        "parser_delta_evidence": parser_delta_evidence,
        "next_required_evidence": [
            "Run evaluate_github_multilang.py after parse_error_file_names truncation removal.",
            "Attach parser-error classifications for every final parse-error file in the fresh 500-project result.",
            "Keep high-star engineering metrics separate from sealed CWE truth-set qualification metrics.",
        ],
    }


def summarize_parse_error_name_coverage(
    result: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    projects = list(result.get("projects") or [])
    completed = [item for item in projects if item.get("status") == "completed"]
    by_language: dict[str, dict[str, Any]] = {}
    truncated_projects: list[dict[str, Any]] = []
    total_parse_errors = 0
    total_recorded_names = 0
    total_recorded_details = 0
    total_projects_with_parse_errors = 0

    for project in completed:
        language = str(project.get("expected_language") or "unknown")
        stats = by_language.setdefault(
            language,
            {
                "projects": 0,
                "projects_with_parse_errors": 0,
                "parse_errors": 0,
                "recorded_parse_error_file_names": 0,
                "recorded_parse_error_file_details": 0,
                "unrecorded_parse_error_file_names": 0,
                "projects_with_truncated_parse_error_names": 0,
                "recorded_name_coverage_rate": None,
                "recorded_detail_coverage_rate": None,
            },
        )
        parse_errors = int(project.get("parse_errors") or 0)
        recorded_names = len(project.get("parse_error_file_names") or [])
        recorded_details = len(project.get("parse_error_file_details") or [])
        unrecorded_names = max(0, parse_errors - recorded_names)
        stats["projects"] += 1
        stats["parse_errors"] += parse_errors
        stats["recorded_parse_error_file_names"] += recorded_names
        stats["recorded_parse_error_file_details"] += recorded_details
        stats["unrecorded_parse_error_file_names"] += unrecorded_names
        total_parse_errors += parse_errors
        total_recorded_names += recorded_names
        total_recorded_details += recorded_details
        if parse_errors:
            stats["projects_with_parse_errors"] += 1
            total_projects_with_parse_errors += 1
        if unrecorded_names:
            stats["projects_with_truncated_parse_error_names"] += 1
            truncated_projects.append(
                {
                    "slug": str(project.get("slug") or ""),
                    "expected_language": language,
                    "parse_errors": parse_errors,
                    "recorded_parse_error_file_names": recorded_names,
                    "unrecorded_parse_error_file_names": unrecorded_names,
                }
            )

    for stats in by_language.values():
        parse_errors = int(stats["parse_errors"])
        recorded_names = int(stats["recorded_parse_error_file_names"])
        recorded_details = int(stats["recorded_parse_error_file_details"])
        stats["recorded_name_coverage_rate"] = (
            round(recorded_names / parse_errors, 6) if parse_errors else None
        )
        stats["recorded_detail_coverage_rate"] = (
            round(recorded_details / parse_errors, 6) if parse_errors else None
        )

    total_unrecorded_names = max(0, total_parse_errors - total_recorded_names)
    summary = {
        "projects": len(projects),
        "completed": len(completed),
        "parse_errors": total_parse_errors,
        "projects_with_parse_errors": total_projects_with_parse_errors,
        "recorded_parse_error_file_names": total_recorded_names,
        "recorded_parse_error_file_details": total_recorded_details,
        "unrecorded_parse_error_file_names": total_unrecorded_names,
        "recorded_name_coverage_rate": (
            round(total_recorded_names / total_parse_errors, 6) if total_parse_errors else None
        ),
        "recorded_detail_coverage_rate": (
            round(total_recorded_details / total_parse_errors, 6) if total_parse_errors else None
        ),
        "projects_with_truncated_parse_error_names": len(truncated_projects),
        "complete_per_file_attribution_possible": total_unrecorded_names == 0,
        "complete_parse_error_detail_coverage": total_recorded_details == total_parse_errors,
    }
    truncated_projects.sort(key=lambda item: (-int(item["unrecorded_parse_error_file_names"]), item["slug"]))
    return summary, dict(sorted(by_language.items())), truncated_projects


def summarize_parser_delta_result(path: Path, result: dict[str, Any]) -> dict[str, Any]:
    summary = result.get("summary") or {}
    remaining_files: list[dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    for project in result.get("projects") or []:
        for file_result in project.get("files") or []:
            classes = [str(item) for item in file_result.get("parser_error_classes") or []]
            for class_name in classes:
                class_counts[class_name] += 1
            if file_result.get("current_parse_error"):
                remaining_files.append(
                    {
                        "slug": str(project.get("slug") or ""),
                        "file_name": str(file_result.get("file_name") or ""),
                        "parser_mode": str(file_result.get("parser_mode") or ""),
                        "parser_error_classes": classes,
                    }
                )
    return {
        "path": str(path.resolve()),
        "delta_revision": str(result.get("delta_revision") or ""),
        "metric_scope": str(result.get("metric_scope") or ""),
        "candidate_files": int(summary.get("candidate_files") or 0),
        "analyzed_files": int(summary.get("analyzed_files") or 0),
        "source_stub_files": int(summary.get("source_stub_files") or 0),
        "newly_recovered_files": int(summary.get("newly_recovered_files") or 0),
        "still_parse_error_files": int(summary.get("still_parse_error_files") or 0),
        "recovery_rate_on_analyzed_files": summary.get("recovery_rate_on_analyzed_files"),
        "error_class_counts": dict(sorted(class_counts.items())),
        "remaining_files": remaining_files,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


if __name__ == "__main__":
    raise SystemExit(main())
