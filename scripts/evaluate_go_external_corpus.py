from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_MANIFEST = ROOT / "config" / "evaluation" / "go-external-random-598x2-2026-07-24-v2.json"
GO_SEMANTIC_ANALYZER = ROOT / "app" / "go_semantic_analyzer.py"

from app.go_semantic_analyzer import analyze_go_semantics
from go_external_corpus import (
    GOSEC_COMMIT,
    GOSEC_REPOSITORY,
    SEMGREP_RULES_COMMIT,
    SEMGREP_RULES_REPOSITORY,
    ensure_checkout,
    extract_gosec_cases,
    materialize_gosec_cases,
    materialize_semgrep_files,
    normalized_cwes,
    write_json,
)
from score_labeled_security_corpus import binomial_upper_bound

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate SecFlow Go rules on the external labeled corpus.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
    )
    parser.add_argument("--partition", choices=("diagnostic", "qualification"), default="diagnostic")
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/secflow-go-labeled-corpus"))
    parser.add_argument("--gosec-source", type=Path)
    parser.add_argument("--semgrep-source", type=Path)
    parser.add_argument("--rules", type=Path, default=ROOT / "config" / "semgrep")
    parser.add_argument(
        "--adjudications",
        type=Path,
        help="Optional audited case-label overrides for CWE-level truth-set development.",
    )
    parser.add_argument(
        "--reuse-materialized",
        action="store_true",
        help="Reuse an existing materialized partition after verifying every pinned content hash.",
    )
    parser.add_argument(
        "--refresh-gosec-materialized",
        action="store_true",
        help="Rebuild only pinned gosec cases before verifying and reusing the materialized partition.",
    )
    parser.add_argument("--semgrep", default=str(Path(sys.executable).with_name("semgrep")))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--jobs", type=int, default=max(1, min(6, (os.cpu_count() or 4) - 1)))
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--min-accuracy", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.005)
    parser.add_argument("--max-fnr", type=float, default=0.005)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    selected = [case for case in manifest.get("cases") or [] if case.get("partition") == args.partition]
    if not selected:
        raise SystemExit(f"No {args.partition} cases in {args.manifest}")
    adjudication_payload = _load_adjudications(args.adjudications)
    selected, adjudication_summary = _apply_adjudications(selected, adjudication_payload)

    scan_root = args.workspace / f"materialized-{args.partition}"
    selected_gosec = {str(case["id"]): case for case in selected if case["source"] == "securego/gosec"}
    selected_semgrep = [case for case in selected if case["source"] == "semgrep/semgrep-rules"]
    if args.refresh_gosec_materialized:
        if not args.reuse_materialized or args.gosec_source is None:
            raise SystemExit(
                "--refresh-gosec-materialized requires --reuse-materialized and --gosec-source"
            )
        gosec_root = _source_checkout(
            args.gosec_source,
            GOSEC_REPOSITORY,
            GOSEC_COMMIT,
            args.workspace / "sources" / "gosec",
        )
        extracted_gosec = {
            str(case["id"]): case
            for case in extract_gosec_cases(gosec_root, include_code=True)
            if case["id"] in selected_gosec
        }
        if set(extracted_gosec) != set(selected_gosec):
            missing = sorted(set(selected_gosec) - set(extracted_gosec))
            raise SystemExit(f"Unable to reconstruct {len(missing)} gosec cases: {missing[:5]}")
        for case_id, expected in selected_gosec.items():
            if extracted_gosec[case_id]["code_hash"] != expected["code_hash"]:
                raise SystemExit(f"Pinned gosec case hash changed: {case_id}")
        gosec_destination = scan_root / "gosec"
        if gosec_destination.exists():
            shutil.rmtree(gosec_destination)
        materialize_gosec_cases(extracted_gosec.values(), gosec_destination)
    if args.reuse_materialized:
        gosec_paths, semgrep_paths = _verified_materialized_paths(
            scan_root,
            selected_gosec,
            selected_semgrep,
        )
    else:
        sources = args.workspace / "sources"
        gosec_root = _source_checkout(args.gosec_source, GOSEC_REPOSITORY, GOSEC_COMMIT, sources / "gosec")
        semgrep_root = _source_checkout(
            args.semgrep_source,
            SEMGREP_RULES_REPOSITORY,
            SEMGREP_RULES_COMMIT,
            sources / "semgrep-rules",
        )
        if scan_root.exists():
            shutil.rmtree(scan_root)
        scan_root.mkdir(parents=True)
        extracted_gosec = {
            str(case["id"]): case
            for case in extract_gosec_cases(gosec_root, include_code=True)
            if case["id"] in selected_gosec
        }
        if set(extracted_gosec) != set(selected_gosec):
            missing = sorted(set(selected_gosec) - set(extracted_gosec))
            raise SystemExit(f"Unable to reconstruct {len(missing)} gosec cases: {missing[:5]}")
        for case_id, expected in selected_gosec.items():
            if extracted_gosec[case_id]["code_hash"] != expected["code_hash"]:
                raise SystemExit(f"Pinned gosec case hash changed: {case_id}")
        gosec_paths = materialize_gosec_cases(extracted_gosec.values(), scan_root / "gosec")
        semgrep_paths = materialize_semgrep_files(selected_semgrep, semgrep_root, scan_root / "semgrep-rules")
        for case in selected_semgrep:
            source_path = semgrep_root / str(case["source_path"])
            if hashlib.sha256(source_path.read_bytes()).hexdigest() != case["code_hash"]:
                raise SystemExit(f"Pinned semgrep-rules case hash changed: {case['id']}")

    raw_result = args.workspace / f"raw-{args.partition}.json"
    started = time.monotonic()
    completed = _run_semgrep(args, scan_root, raw_result)
    elapsed = round(time.monotonic() - started, 2)
    if completed.returncode != 0 or not raw_result.is_file():
        raise SystemExit((completed.stderr or completed.stdout or "Semgrep evaluation failed").strip())
    payload = json.loads(raw_result.read_text(encoding="utf-8"))
    findings = _normalized_findings(payload, scan_root)
    semantic_findings = _go_semantic_findings(scan_root)
    findings.extend(semantic_findings)
    findings_by_path: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        findings_by_path.setdefault(finding["path"], []).append(finding)

    materialized_paths: dict[str, list[str]] = {}
    for case_id, paths in gosec_paths.items():
        materialized_paths[case_id] = [Path(path).relative_to(scan_root).as_posix() for path in paths]
    semgrep_relative_paths = {
        source_path: Path(path).relative_to(scan_root).as_posix()
        for source_path, path in semgrep_paths.items()
    }

    matrix: Counter[str] = Counter()
    by_source: dict[str, Counter[str]] = {}
    by_cwe: dict[str, Counter[str]] = {}
    cases: list[dict[str, Any]] = []
    matched_finding_keys: set[tuple[str, int, str]] = set()
    for case in selected:
        expected_cwes = set(case.get("cwes") or [])
        matches: list[dict[str, Any]] = []
        if case["source"] == "securego/gosec":
            for path in materialized_paths.get(str(case["id"]), []):
                matches.extend(
                    finding
                    for finding in findings_by_path.get(path, [])
                    if finding["cwes"] & expected_cwes
                )
        else:
            path = semgrep_relative_paths.get(str(case["source_path"]), "")
            target_line = int(case.get("line") or 0)
            matches.extend(
                finding
                for finding in findings_by_path.get(path, [])
                if (
                    finding["start_line"] <= target_line <= finding["end_line"]
                    or (path, target_line) in finding["trace_locations"]
                )
                and finding["cwes"] & expected_cwes
            )
        detected = bool(matches)
        vulnerable = bool(case["vulnerable"])
        outcome = "TP" if vulnerable and detected else "FN" if vulnerable else "FP" if detected else "TN"
        matrix[outcome] += 1
        by_source.setdefault(str(case["source"]), Counter())[outcome] += 1
        for cwe in expected_cwes:
            by_cwe.setdefault(cwe, Counter())[outcome] += 1
        for finding in matches:
            matched_finding_keys.add((finding["path"], finding["start_line"], finding["rule"]))
        cases.append(
            {
                **case,
                "detected": detected,
                "outcome": outcome,
                "matched_findings": [
                    {
                        "rule": finding["rule"],
                        "path": finding["path"],
                        "line": finding["start_line"],
                        "cwes": sorted(finding["cwes"]),
                    }
                    for finding in matches[:5]
                ],
            }
        )

    metrics = _metrics(matrix)
    methodology = dict(manifest.get("methodology") or {})
    if adjudication_payload:
        methodology.update(dict((adjudication_payload.get("methodology") or {})))
    negative_label_scope = str(methodology.get("negative_label_scope") or "external_rule_specific")
    cwe_complete_negative_labels = negative_label_scope == "cwe_complete"
    adjudication_qualification_eligible = bool(methodology.get("qualification_eligible", cwe_complete_negative_labels))
    positive_count = matrix["TP"] + matrix["FN"]
    negative_count = matrix["TN"] + matrix["FP"]
    fnr_upper = binomial_upper_bound(matrix["FN"], positive_count)
    fpr_upper = binomial_upper_bound(matrix["FP"], negative_count)
    qualification = {
        "sample_size_passed": positive_count >= 598 and negative_count >= 598,
        "negative_label_scope": negative_label_scope,
        "cwe_complete_negative_labels": cwe_complete_negative_labels,
        "adjudication_applied": bool(adjudication_payload),
        "adjudication_qualification_eligible": adjudication_qualification_eligible,
        "point_estimate_passed": (
            metrics["accuracy"] >= args.min_accuracy
            and metrics["false_positive_rate"] <= args.max_fpr
            and metrics["false_negative_rate"] <= args.max_fnr
        ),
        "confidence_passed": (
            fnr_upper is not None
            and fpr_upper is not None
            and fnr_upper <= args.max_fnr
            and fpr_upper <= args.max_fpr
        ),
        "false_negative_rate_upper_95": fnr_upper,
        "false_positive_rate_upper_95": fpr_upper,
    }
    qualification["passed"] = all(
        qualification[key]
        for key in (
            "sample_size_passed",
            "cwe_complete_negative_labels",
            "adjudication_qualification_eligible",
            "point_estimate_passed",
            "confidence_passed",
        )
    )
    output = args.output or ROOT / "docs" / f"go-external-{args.partition}-results.json"
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "partition": args.partition,
        "manifest": str(args.manifest.resolve()),
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "metric_scope": _metric_scope(cwe_complete_negative_labels, adjudication_payload),
        "adjudications": adjudication_summary,
        "rules": str(args.rules.resolve()),
        "rules_sha256": _rules_sha256(args.rules),
        "go_semantic_analyzer_sha256": _file_sha256(GO_SEMANTIC_ANALYZER),
        "evaluator_sha256": _file_sha256(Path(__file__)),
        "semgrep_version": str((payload.get("version") or completed.stdout or "")).strip(),
        "elapsed_seconds": elapsed,
        "thresholds": {
            "min_accuracy": args.min_accuracy,
            "max_false_positive_rate": args.max_fpr,
            "max_false_negative_rate": args.max_fnr,
            "confidence": 0.95,
        },
        "metrics": metrics,
        "qualification": qualification,
        "scan": {
            "targets": len((payload.get("paths") or {}).get("scanned") or []),
            "findings": len(findings),
            "semgrep_findings": len(findings) - len(semantic_findings),
            "go_semantic_findings": len(semantic_findings),
            "matched_findings": len(matched_finding_keys),
            "errors": len(payload.get("errors") or []),
        },
        "by_source": {source: _metrics(counts) for source, counts in sorted(by_source.items())},
        "by_cwe": {cwe: _metrics(counts) for cwe, counts in sorted(by_cwe.items(), key=lambda item: _cwe_number(item[0]))},
        "cases": cases,
    }
    write_json(output, report)
    print(json.dumps({"partition": args.partition, "metrics": metrics, "qualification": qualification}, ensure_ascii=False))
    if args.partition == "qualification" and not qualification["passed"]:
        return 1
    return 0


def _source_checkout(explicit: Path | None, url: str, commit: str, destination: Path) -> Path:
    if explicit is None:
        return ensure_checkout(url, commit, destination)
    root = explicit.expanduser().resolve()
    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False)
    if completed.returncode != 0 or completed.stdout.strip() != commit:
        raise SystemExit(f"Source checkout must be pinned at {commit}: {root}")
    return root


def _rules_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    resolved = path.resolve()
    files = [resolved] if resolved.is_file() else sorted(
        candidate for candidate in resolved.rglob("*") if candidate.is_file() and candidate.suffix in {".yml", ".yaml"}
    )
    if not files:
        raise SystemExit(f"No Semgrep rules found at {resolved}")
    for candidate in files:
        relative = candidate.name if resolved.is_file() else candidate.relative_to(resolved).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(candidate.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_adjudications(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload.get("cases"), list):
        raise SystemExit(f"Adjudication file must contain a cases list: {path}")
    payload["_source_path"] = str(path.resolve())
    payload["_source_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return payload


def _apply_adjudications(
    cases: list[dict[str, Any]],
    payload: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not payload:
        return cases, {"applied": False}
    raw_entries = payload.get("cases") or []
    by_id: dict[str, dict[str, Any]] = {}
    for entry in raw_entries:
        case_id = str(entry.get("id") or "")
        if not case_id:
            raise SystemExit("Adjudication entry missing id")
        if case_id in by_id:
            raise SystemExit(f"Duplicate adjudication entry: {case_id}")
        by_id[case_id] = dict(entry)

    selected_ids = {str(case.get("id")) for case in cases}
    unknown = sorted(set(by_id) - selected_ids)
    if unknown:
        raise SystemExit(f"Adjudication entries do not belong to the selected partition: {unknown[:5]}")

    adjusted: list[dict[str, Any]] = []
    excluded = 0
    overridden = 0
    for case in cases:
        case_id = str(case.get("id"))
        entry = by_id.get(case_id)
        if entry is None:
            adjusted.append(case)
            continue
        action = str(entry.get("action") or "override")
        if action not in {"override", "exclude"}:
            raise SystemExit(f"Unsupported adjudication action for {case_id}: {action}")
        if action == "exclude":
            excluded += 1
            continue
        updated = dict(case)
        updated["original_vulnerable"] = bool(case.get("vulnerable"))
        updated["original_cwes"] = list(case.get("cwes") or [])
        if "vulnerable" in entry:
            updated["vulnerable"] = bool(entry["vulnerable"])
        if "cwes" in entry:
            updated["cwes"] = list(entry.get("cwes") or [])
        updated["adjudication"] = {
            key: entry[key]
            for key in (
                "classification",
                "product_action",
                "reason",
                "evidence",
                "recommended_truth_action",
            )
            if key in entry
        }
        adjusted.append(updated)
        overridden += 1

    source_path = Path(str(payload.get("_source_path") or ""))
    return adjusted, {
        "applied": True,
        "version": payload.get("version"),
        "source": str(source_path) if source_path else None,
        "source_sha256": payload.get("_source_sha256"),
        "entries": len(raw_entries),
        "overridden": overridden,
        "excluded": excluded,
        "methodology": payload.get("methodology") or {},
    }


def _metric_scope(cwe_complete_negative_labels: bool, adjudication_payload: dict[str, Any]) -> str:
    if adjudication_payload:
        return str(
            adjudication_payload.get("metric_scope")
            or (
                "cwe_security_classification"
                if cwe_complete_negative_labels
                else "adjudicated_external_rule_label_agreement"
            )
        )
    return "cwe_security_classification" if cwe_complete_negative_labels else "external_rule_label_agreement"


def _verified_materialized_paths(
    scan_root: Path,
    selected_gosec: dict[str, dict[str, Any]],
    selected_semgrep: list[dict[str, Any]],
) -> tuple[dict[str, list[str]], dict[str, str]]:
    if not scan_root.is_dir():
        raise SystemExit(f"Materialized partition does not exist: {scan_root}")
    gosec_paths: dict[str, list[str]] = {}
    for case_id, expected in selected_gosec.items():
        directory = scan_root / "gosec" / re.sub(r"[^A-Za-z0-9_.-]+", "_", case_id)
        paths = sorted(directory.glob("source-*.go"))
        if not paths:
            raise SystemExit(f"Missing materialized gosec case: {case_id}")
        normalized = [re.sub(rb"\s+", b" ", path.read_bytes()).strip() for path in paths]
        digest = hashlib.sha256(b"\n--FILE--\n".join(normalized)).hexdigest()
        if digest != expected["code_hash"]:
            raise SystemExit(f"Materialized gosec case hash changed: {case_id}")
        gosec_paths[case_id] = [path.as_posix() for path in paths]
    semgrep_paths: dict[str, str] = {}
    for case in selected_semgrep:
        relative = str(case["source_path"])
        path = scan_root / "semgrep-rules" / relative
        if not path.is_file():
            raise SystemExit(f"Missing materialized semgrep-rules file: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != case["code_hash"]:
            raise SystemExit(f"Materialized semgrep-rules file hash changed: {relative}")
        semgrep_paths[relative] = path.as_posix()
    return gosec_paths, semgrep_paths


def _run_semgrep(args: argparse.Namespace, scan_root: Path, output: Path) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    command = [
        args.semgrep,
        "scan",
        "--config",
        str(args.rules.resolve()),
        "--json-output",
        str(output.resolve()),
        "--dataflow-traces",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--project-root",
        str(scan_root.resolve()),
        "--jobs",
        str(args.jobs),
        "--timeout",
        "15",
        "--timeout-threshold",
        "3",
        str(scan_root.resolve()),
    ]
    return subprocess.run(
        command,
        cwd=scan_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=args.timeout,
        env=environment,
    )


def _normalized_findings(payload: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in payload.get("results") or []:
        path = Path(str(item.get("path") or ""))
        if path.is_absolute():
            try:
                relative = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                relative = path.as_posix()
        else:
            relative = path.as_posix().lstrip("./")
        extra = item.get("extra") or {}
        start_line = int((item.get("start") or {}).get("line") or 0)
        source_path = root / relative
        if _finding_is_suppressed(source_path, start_line):
            continue
        result.append(
            {
                "rule": _normalized_rule(str(item.get("check_id") or "")),
                "path": relative,
                "start_line": start_line,
                "end_line": int((item.get("end") or {}).get("line") or (item.get("start") or {}).get("line") or 0),
                "cwes": normalized_cwes(extra.get("metadata") or {}),
                "trace_locations": _trace_locations(extra.get("dataflow_trace") or {}, root),
            }
        )
    return result


def _finding_is_suppressed(path: Path, line: int) -> bool:
    if not path.is_file() or line <= 0:
        return False
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    context = "\n".join(lines[max(0, line - 3) : min(len(lines), line + 1)])
    return bool(re.search(r"#\s*nosec\b|nolint(?::[^\s]+)?", context, flags=re.IGNORECASE))


def _go_semantic_findings(root: Path) -> list[dict[str, Any]]:
    code_files = [
        {
            "file_name": path.relative_to(root).as_posix(),
            "content": path.read_text(encoding="utf-8", errors="replace"),
        }
        for path in sorted(root.rglob("*.go"))
        if path.is_file()
    ]
    analysis = analyze_go_semantics(code_files)
    result: list[dict[str, Any]] = []
    for item in analysis.get("findings") or []:
        sink = item.get("sink") or {}
        source = item.get("source") or {}
        path = str(sink.get("file") or "").lstrip("./")
        line = int(sink.get("line") or 0)
        result.append(
            {
                "rule": str(item.get("rule_id") or ""),
                "path": path,
                "start_line": line,
                "end_line": line,
                "cwes": set(str(value) for value in item.get("cwes") or []),
                "trace_locations": {
                    (str(source.get("file") or path).lstrip("./"), int(source.get("line") or line)),
                    (path, line),
                },
            }
        )
    return result


def _trace_locations(value: Any, root: Path) -> set[tuple[str, int]]:
    result: set[tuple[str, int]] = set()
    if isinstance(value, list):
        for item in value:
            result.update(_trace_locations(item, root))
        return result
    if not isinstance(value, dict):
        return result
    location = value.get("location")
    if isinstance(location, dict):
        path = Path(str(location.get("path") or ""))
        if path.is_absolute():
            try:
                relative = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                relative = path.as_posix()
        else:
            relative = path.as_posix().lstrip("./")
        line = int((location.get("start") or {}).get("line") or 0)
        if relative and line:
            result.add((relative, line))
    for nested in value.values():
        result.update(_trace_locations(nested, root))
    return result


def _metrics(counts: Counter[str]) -> dict[str, Any]:
    tp, fp, tn, fn = (counts[name] for name in ("TP", "FP", "TN", "FN"))
    total = tp + fp + tn + fn
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": _ratio(tp + tn, total),
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
        "false_negative_rate": _ratio(fn, fn + tp),
    }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _normalized_rule(value: str) -> str:
    marker = "secflow."
    return marker + value.split(marker, 1)[1] if marker in value else value


def _cwe_number(value: str) -> int:
    try:
        return int(value.split("-", 1)[1])
    except (IndexError, ValueError):
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
