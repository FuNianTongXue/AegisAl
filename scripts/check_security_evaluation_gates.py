from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.validate_security_truth_manifest import validate_manifest_report
except ModuleNotFoundError:  # pragma: no cover - direct script execution from scripts/
    from validate_security_truth_manifest import validate_manifest_report


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_RESULT = ROOT / "docs" / "go-external-development-recall-v86-results.json"
DEFAULT_ADJUDICATED_RESULT = ROOT / "docs" / "go-external-adjudicated-v1-results.json"
DEFAULT_HIGH_STAR_RESULT = ROOT / "docs" / "github-multilang-high-star-500-revision-4-results.json"
DEFAULT_ADJUDICATIONS = ROOT / "config" / "evaluation" / "go-external-cwe-adjudications-v1.json"
DEFAULT_FAILURE_ATTRIBUTION = ROOT / "docs" / "go-external-development-recall-v85-failure-attribution.json"

_HIGH_STAR_FORBIDDEN_METRIC_KEYS = {
    "accuracy",
    "precision",
    "recall",
    "fpr",
    "fnr",
    "false_positive_rate",
    "false_negative_rate",
}
_HIGH_STAR_FORBIDDEN_ADAPTIVE_KEYS = {
    "adaptation",
    "adaptive_enabled",
    "overlay_fingerprint",
    "overlay_fingerprints",
    "project_overlay",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check AegisAl security-evaluation regression gates. "
            "This gate is for development regression only; ordinary high-star repositories "
            "do not provide product precision/recall ground truth."
        )
    )
    parser.add_argument("--raw", type=Path, default=DEFAULT_RAW_RESULT, help="Raw external-label result JSON.")
    parser.add_argument(
        "--adjudicated",
        type=Path,
        default=DEFAULT_ADJUDICATED_RESULT,
        help="Adjudicated partial-truth result JSON.",
    )
    parser.add_argument(
        "--high-star",
        type=Path,
        default=DEFAULT_HIGH_STAR_RESULT,
        help="Ordinary 500 high-star engineering-corpus result JSON.",
    )
    parser.add_argument("--min-accuracy", type=float, default=0.95)
    parser.add_argument("--min-precision", type=float, default=0.95)
    parser.add_argument("--raw-min-tp", type=int, default=587)
    parser.add_argument("--raw-max-fp", type=int, default=30)
    parser.add_argument("--raw-max-fn", type=int, default=11)
    parser.add_argument("--high-star-projects", type=int, default=500)
    parser.add_argument(
        "--adjudications",
        type=Path,
        default=DEFAULT_ADJUDICATIONS,
        help="Audited adjudication override JSON used to produce the adjudicated partial-truth result.",
    )
    parser.add_argument(
        "--failure-attribution",
        type=Path,
        default=DEFAULT_FAILURE_ATTRIBUTION,
        help="Failure attribution JSON for the raw external-label false negatives.",
    )
    parser.add_argument(
        "--sealed-manifest",
        type=Path,
        help="Optional sealed CWE-complete qualification truth manifest to validate before formal use.",
    )
    parser.add_argument(
        "--sealed-forbidden-manifest",
        type=Path,
        action="append",
        default=[],
        help="Previously observed manifest that the sealed truth manifest must not reuse.",
    )
    parser.add_argument("--sealed-min-positive-cases", type=int, default=598)
    parser.add_argument("--sealed-min-negative-cases", type=int, default=598)
    args = parser.parse_args(argv)

    failures: list[str] = []
    raw = load_result(args.raw)
    adjudicated = load_result(args.adjudicated)
    high_star = load_result(args.high_star)
    adjudications = load_result(args.adjudications)
    failure_attribution = load_result(args.failure_attribution)
    sealed_report: dict[str, Any] | None = None

    failures.extend(
        check_raw_external_label_gate(
            raw,
            min_accuracy=args.min_accuracy,
            min_precision=args.min_precision,
            min_tp=args.raw_min_tp,
            max_fp=args.raw_max_fp,
            max_fn=args.raw_max_fn,
        )
    )
    failures.extend(
        check_sealed_qualification_integrity_gate(
            raw,
            label="raw external-label",
            min_accuracy=args.min_accuracy,
            min_precision=args.min_precision,
        )
    )
    failures.extend(
        check_adjudicated_partial_truth_gate(
            adjudicated,
            min_accuracy=args.min_accuracy,
            min_precision=args.min_precision,
        )
    )
    failures.extend(
        check_adjudication_consistency_gate(
            adjudications,
            raw_result=raw,
            adjudicated_result=adjudicated,
            failure_attribution=failure_attribution,
        )
    )
    failures.extend(
        check_sealed_qualification_integrity_gate(
            adjudicated,
            label="adjudicated partial-truth",
            min_accuracy=args.min_accuracy,
            min_precision=args.min_precision,
        )
    )
    failures.extend(
        check_high_star_engineering_corpus_gate(
            high_star,
            expected_projects=args.high_star_projects,
        )
    )
    if args.sealed_manifest:
        forbidden_manifests = [load_result(path) for path in args.sealed_forbidden_manifest]
        sealed_report = validate_manifest_report(
            load_result(args.sealed_manifest),
            manifest_path=args.sealed_manifest,
            forbidden_manifests=forbidden_manifests,
            forbidden_manifest_paths=args.sealed_forbidden_manifest,
            min_positive_cases=args.sealed_min_positive_cases,
            min_negative_cases=args.sealed_min_negative_cases,
        )
        failures.extend(f"sealed truth manifest: {failure}" for failure in sealed_report["failures"])

    if failures:
        print("Security evaluation gates failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    raw_metrics = raw.get("metrics") or {}
    adjudicated_metrics = adjudicated.get("metrics") or {}
    print(
        "Security evaluation gates passed: "
        f"raw TP={raw_metrics.get('tp')} FP={raw_metrics.get('fp')} FN={raw_metrics.get('fn')}; "
        f"adjudicated TP={adjudicated_metrics.get('tp')} FP={adjudicated_metrics.get('fp')} "
        f"FN={adjudicated_metrics.get('fn')} accuracy={adjudicated_metrics.get('accuracy')} "
        f"precision={adjudicated_metrics.get('precision')}; "
        f"high-star projects={((high_star.get('summary') or {}).get('projects'))} "
        f"completed={((high_star.get('summary') or {}).get('completed'))} "
        "truth_scope=engineering-only"
        + (
            f"; sealed-manifest cases={sealed_report['summary']['cases']} "
            f"positive={sealed_report['summary']['positive_cases']} "
            f"negative={sealed_report['summary']['negative_cases']}."
            if sealed_report
            else "."
        )
    )
    return 0


def load_result(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return payload


def check_raw_external_label_gate(
    result: dict[str, Any],
    *,
    min_accuracy: float,
    min_precision: float,
    min_tp: int,
    max_fp: int,
    max_fn: int,
) -> list[str]:
    failures: list[str] = []
    metric_scope = str(result.get("metric_scope") or "")
    if metric_scope != "external_rule_label_agreement":
        failures.append(f"raw metric_scope must be external_rule_label_agreement, got {metric_scope!r}")
    qualification = result.get("qualification") or {}
    if qualification.get("adjudication_applied"):
        failures.append("raw result must not apply adjudications")
    failures.extend(
        check_metric_thresholds(
            result,
            label="raw external-label",
            min_accuracy=min_accuracy,
            min_precision=min_precision,
        )
    )
    metrics = result.get("metrics") or {}
    if int(metrics.get("tp") or 0) < min_tp:
        failures.append(f"raw external-label TP regressed below {min_tp}: {metrics.get('tp')}")
    if int(metrics.get("fp") or 0) > max_fp:
        failures.append(f"raw external-label FP rose above {max_fp}: {metrics.get('fp')}")
    if int(metrics.get("fn") or 0) > max_fn:
        failures.append(f"raw external-label FN rose above {max_fn}: {metrics.get('fn')}")
    return failures


def check_adjudicated_partial_truth_gate(
    result: dict[str, Any],
    *,
    min_accuracy: float,
    min_precision: float,
) -> list[str]:
    failures: list[str] = []
    metric_scope = str(result.get("metric_scope") or "")
    if metric_scope != "adjudicated_cwe_truth_partial":
        failures.append(f"adjudicated metric_scope must be adjudicated_cwe_truth_partial, got {metric_scope!r}")
    qualification = result.get("qualification") or {}
    if not qualification.get("adjudication_applied"):
        failures.append("adjudicated result must apply adjudications")
    if qualification.get("passed"):
        failures.append("adjudicated partial truth must not be reported as a sealed qualification pass")
    failures.extend(
        check_metric_thresholds(
            result,
            label="adjudicated partial-truth",
            min_accuracy=min_accuracy,
            min_precision=min_precision,
        )
    )
    metrics = result.get("metrics") or {}
    if int(metrics.get("fn") or 0) != 0:
        failures.append(f"adjudicated partial-truth FN must remain 0, got {metrics.get('fn')}")
    return failures


def check_adjudication_consistency_gate(
    adjudications: dict[str, Any],
    *,
    raw_result: dict[str, Any],
    adjudicated_result: dict[str, Any],
    failure_attribution: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if str(adjudications.get("metric_scope") or "") != "adjudicated_cwe_truth_partial":
        failures.append("adjudications metric_scope must be adjudicated_cwe_truth_partial")
    methodology = adjudications.get("methodology") or {}
    if methodology.get("qualification_eligible") is not False:
        failures.append("adjudications methodology.qualification_eligible must be false")
    if methodology.get("cwe_complete_negative_labels") is not False:
        failures.append("adjudications methodology.cwe_complete_negative_labels must be false")
    if str(methodology.get("negative_label_scope") or "") != "adjudicated_partial":
        failures.append("adjudications methodology.negative_label_scope must be adjudicated_partial")

    entries = adjudications.get("cases") or []
    if not isinstance(entries, list) or not entries:
        failures.append("adjudications must contain a non-empty cases list")
        entries = []
    entry_ids: list[str] = []
    allowed_actions = {"override", "exclude"}
    allowed_classifications = {
        "label_conflict",
        "safe_or_bounded_flow",
        "fixed_file_artifact",
        "upstream_autofix_artifact",
        "overbroad_upstream_rule",
    }
    allowed_product_actions = {"do_not_add_broad_rule", "do_not_flag", "exclude_from_partial_truth"}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            failures.append(f"adjudication entry {index} must be a JSON object")
            continue
        entry_id = str(entry.get("id") or "").strip()
        if not entry_id:
            failures.append(f"adjudication entry {index} missing id")
            continue
        entry_ids.append(entry_id)
        if str(entry.get("action") or "") not in allowed_actions:
            failures.append(f"adjudication {entry_id} action must be one of {sorted(allowed_actions)}")
        if str(entry.get("classification") or "") not in allowed_classifications:
            failures.append(f"adjudication {entry_id} classification must be one of {sorted(allowed_classifications)}")
        if str(entry.get("product_action") or "") not in allowed_product_actions:
            failures.append(f"adjudication {entry_id} product_action must be one of {sorted(allowed_product_actions)}")
        if not str(entry.get("evidence") or "").strip():
            failures.append(f"adjudication {entry_id} must include evidence")
        cwes = entry.get("cwes") or []
        if not isinstance(cwes, list) or not cwes:
            failures.append(f"adjudication {entry_id} must include non-empty cwes")

    if len(entry_ids) != len(set(entry_ids)):
        failures.append("adjudication ids must be unique")

    raw_cases = {str(case.get("id") or ""): case for case in raw_result.get("cases") or [] if isinstance(case, dict)}
    adjudicated_cases = {
        str(case.get("id") or ""): case for case in adjudicated_result.get("cases") or [] if isinstance(case, dict)
    }
    attribution_ids = {
        str(item.get("id") or "")
        for item in failure_attribution.get("remaining_false_negatives") or []
        if isinstance(item, dict)
    }
    raw_fn_ids = {
        case_id
        for case_id, case in raw_cases.items()
        if str(case.get("outcome") or "") == "FN"
    }
    entry_id_set = set(entry_ids)
    unknown_ids = sorted(entry_id_set - set(raw_cases))
    if unknown_ids:
        failures.append(f"adjudications reference unknown raw cases: {unknown_ids[:10]}")
    if entry_id_set != raw_fn_ids:
        failures.append(
            "adjudications must cover exactly the raw external-label FN set: "
            f"missing={sorted(raw_fn_ids - entry_id_set)[:10]} extra={sorted(entry_id_set - raw_fn_ids)[:10]}"
        )
    if attribution_ids and entry_id_set != attribution_ids:
        failures.append(
            "adjudications must match failure attribution remaining_false_negatives: "
            f"missing={sorted(attribution_ids - entry_id_set)[:10]} extra={sorted(entry_id_set - attribution_ids)[:10]}"
        )

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id") or "")
        raw_case = raw_cases.get(entry_id) or {}
        adjudicated_case = adjudicated_cases.get(entry_id) or {}
        if raw_case and str(raw_case.get("outcome") or "") != "FN":
            failures.append(f"adjudication {entry_id} must reference a raw FN case, got {raw_case.get('outcome')}")
        if raw_case and set(entry.get("cwes") or []) != set(raw_case.get("cwes") or []):
            failures.append(f"adjudication {entry_id} CWE set must match the raw case")
        if adjudicated_case and str(adjudicated_case.get("outcome") or "") == "FN":
            failures.append(f"adjudication {entry_id} remains FN after adjudicated evaluation")

    adjudication_summary = adjudicated_result.get("adjudications") or {}
    if adjudication_summary.get("applied") is not True:
        failures.append("adjudicated result must record adjudications.applied=true")
    if int(adjudication_summary.get("entries") or 0) != len(entry_id_set):
        failures.append(
            f"adjudicated result entries must equal adjudication case count {len(entry_id_set)}, "
            f"got {adjudication_summary.get('entries')}"
        )
    adjudicated_metrics = adjudicated_result.get("metrics") or {}
    if int(adjudicated_metrics.get("fn") or 0) != 0:
        failures.append(f"adjudicated result FN must be 0 after adjudication, got {adjudicated_metrics.get('fn')}")
    return failures


def check_high_star_engineering_corpus_gate(
    result: dict[str, Any],
    *,
    expected_projects: int,
) -> list[str]:
    failures: list[str] = []
    policy = result.get("evaluation_policy") or {}
    summary = result.get("summary") or {}
    projects = result.get("projects") or []

    if int(summary.get("projects") or 0) != expected_projects:
        failures.append(f"high-star corpus project count must be {expected_projects}, got {summary.get('projects')}")
    if int(summary.get("completed") or 0) != expected_projects:
        failures.append(f"high-star corpus completed count must be {expected_projects}, got {summary.get('completed')}")
    if float(summary.get("completion_rate") or 0.0) < 1.0:
        failures.append(f"high-star corpus completion_rate must be 1.0, got {summary.get('completion_rate')}")
    if len(projects) != expected_projects:
        failures.append(f"high-star corpus projects array must contain {expected_projects} entries, got {len(projects)}")
    if len({str(project.get("slug") or "") for project in projects}) != len(projects):
        failures.append("high-star corpus project slugs must be unique")

    ground_truth = str(policy.get("ground_truth") or "").casefold()
    if "not available" not in ground_truth:
        failures.append("high-star corpus must state that ordinary repositories have no ground truth")
    qualification_source = str(policy.get("qualification_source") or "").casefold()
    if "independent" not in qualification_source or "corpora" not in qualification_source:
        failures.append("high-star corpus qualification_source must point to independent labeled corpora")

    invalid_metrics = {str(item).casefold() for item in policy.get("invalid_metrics") or []}
    missing_invalid = {"accuracy", "precision", "recall", "fpr", "fnr"} - invalid_metrics
    if missing_invalid:
        failures.append(f"high-star corpus invalid_metrics missing {sorted(missing_invalid)}")

    valid_metrics = {str(item) for item in policy.get("valid_metrics") or []}
    required_valid_metrics = {
        "completion_rate",
        "parser_error_rate",
        "raw_parser_error_rate",
        "parser_recovery_rate",
        "finding_density",
        "dependency_coverage",
        "manual_review_yield",
    }
    missing_valid = required_valid_metrics - valid_metrics
    if missing_valid:
        failures.append(f"high-star corpus valid_metrics missing {sorted(missing_valid)}")

    forbidden_metric_paths = _find_forbidden_keys(result, _HIGH_STAR_FORBIDDEN_METRIC_KEYS)
    allowed_policy_paths = {
        "evaluation_policy.invalid_metrics[]",
    }
    unexpected_metric_paths = [
        path
        for path in forbidden_metric_paths
        if not any(path.startswith(prefix) for prefix in allowed_policy_paths)
    ]
    if unexpected_metric_paths:
        failures.append(
            "high-star corpus must not contain product truth metric fields outside evaluation_policy.invalid_metrics: "
            + ", ".join(unexpected_metric_paths[:8])
        )

    adaptive_paths = _find_forbidden_keys(result, _HIGH_STAR_FORBIDDEN_ADAPTIVE_KEYS)
    if adaptive_paths:
        failures.append("high-star corpus must not contain adaptive overlay fields: " + ", ".join(adaptive_paths[:8]))
    adaptive_scan_modes = [
        path
        for path, value in _iter_json_values(result)
        if path.endswith(".scan_mode") and str(value) == "adaptive_upload"
    ]
    if adaptive_scan_modes:
        failures.append("high-star corpus must not include adaptive_upload scan_mode: " + ", ".join(adaptive_scan_modes[:8]))

    qualification_paths = [
        path
        for path, value in _iter_json_values(result)
        if path.endswith(".qualification") or path == "qualification"
    ]
    if qualification_paths:
        failures.append("high-star corpus must not include qualification result objects")
    adjudication_paths = [
        path
        for path, value in _iter_json_values(result)
        if path.endswith(".adjudication") or path == "adjudication" or path.endswith(".adjudication_applied")
    ]
    if adjudication_paths:
        failures.append("high-star corpus must not include adjudication result fields")

    return failures


def check_sealed_qualification_integrity_gate(
    result: dict[str, Any],
    *,
    label: str,
    min_accuracy: float,
    min_precision: float,
) -> list[str]:
    qualification = result.get("qualification") or {}
    passed_claim = qualification.get("passed") is True or result.get("passed") is True
    if not passed_claim:
        return []

    failures: list[str] = []
    metric_scope = str(result.get("metric_scope") or "")
    if metric_scope and metric_scope != "cwe_security_classification":
        failures.append(f"{label} qualification pass requires cwe_security_classification metric_scope, got {metric_scope!r}")
    if qualification.get("adjudication_applied"):
        failures.append(f"{label} qualification pass must not use adjudication overlays")
    if qualification.get("cwe_complete_negative_labels") is False:
        failures.append(f"{label} qualification pass requires CWE-complete negative labels")
    if qualification.get("labels_complete") is False:
        failures.append(f"{label} qualification pass requires complete labels for all detections")
    if qualification.get("sample_size_passed") is not True:
        failures.append(f"{label} qualification pass requires sample_size_passed=true")
    if qualification.get("point_estimate_passed") is not True:
        failures.append(f"{label} qualification pass requires point_estimate_passed=true")
    if qualification.get("confidence_passed") is not True:
        failures.append(f"{label} qualification pass requires confidence_passed=true")
    if "unlabeled_detection_count" in qualification and int(qualification.get("unlabeled_detection_count") or 0) != 0:
        failures.append(f"{label} qualification pass requires zero unlabeled detections")

    metrics = result.get("metrics") or {}
    if int(metrics.get("fn") or 0) != 0:
        failures.append(f"{label} qualification pass requires observed FN=0, got {metrics.get('fn')}")
    failures.extend(
        check_metric_thresholds(
            result,
            label=f"{label} qualification",
            min_accuracy=min_accuracy,
            min_precision=min_precision,
        )
    )

    thresholds = result.get("thresholds") or (result.get("methodology") or {}).get("thresholds") or {}
    max_fnr = float(thresholds.get("max_false_negative_rate") or thresholds.get("max_fnr") or 0.005)
    max_fpr = float(thresholds.get("max_false_positive_rate") or thresholds.get("max_fpr") or 0.005)
    fnr_upper = qualification.get("false_negative_rate_upper_95")
    fpr_upper = qualification.get("false_positive_rate_upper_95")
    if fnr_upper is None or float(fnr_upper) > max_fnr:
        failures.append(f"{label} qualification pass requires FN upper 95 <= {max_fnr:.6f}, got {fnr_upper}")
    if fpr_upper is None or float(fpr_upper) > max_fpr:
        failures.append(f"{label} qualification pass requires FP upper 95 <= {max_fpr:.6f}, got {fpr_upper}")

    positive_cases = qualification.get("positive_cases")
    negative_cases = qualification.get("negative_cases")
    if positive_cases is not None and int(positive_cases) < 598:
        failures.append(f"{label} qualification pass requires at least 598 positive cases, got {positive_cases}")
    if negative_cases is not None and int(negative_cases) < 598:
        failures.append(f"{label} qualification pass requires at least 598 negative cases, got {negative_cases}")

    adaptive_paths = _find_forbidden_keys(result, _HIGH_STAR_FORBIDDEN_ADAPTIVE_KEYS)
    if adaptive_paths:
        failures.append(f"{label} qualification pass must not contain adaptive overlay fields: " + ", ".join(adaptive_paths[:8]))
    adaptive_scan_modes = [
        path
        for path, value in _iter_json_values(result)
        if path.endswith(".scan_mode") and str(value) == "adaptive_upload"
    ]
    if adaptive_scan_modes:
        failures.append(f"{label} qualification pass must not include adaptive_upload scan_mode: " + ", ".join(adaptive_scan_modes[:8]))

    return failures


def check_metric_thresholds(
    result: dict[str, Any],
    *,
    label: str,
    min_accuracy: float,
    min_precision: float,
) -> list[str]:
    metrics = result.get("metrics") or {}
    failures: list[str] = []
    accuracy = float(metrics.get("accuracy") or 0.0)
    precision = float(metrics.get("precision") or 0.0)
    if accuracy < min_accuracy:
        failures.append(f"{label} accuracy {accuracy:.6f} is below {min_accuracy:.6f}")
    if precision < min_precision:
        failures.append(f"{label} precision {precision:.6f} is below {min_precision:.6f}")
    return failures


def _find_forbidden_keys(value: Any, forbidden_keys: set[str]) -> list[str]:
    matches: list[str] = []
    for path, _ in _iter_json_values(value):
        key = path.rsplit(".", 1)[-1].replace("[]", "").casefold()
        if key in forbidden_keys:
            matches.append(path)
    return matches


def _iter_json_values(value: Any, path: str = "") -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            result.append((child_path, child))
            result.extend(_iter_json_values(child, child_path))
    elif isinstance(value, list):
        for child in value:
            child_path = f"{path}[]" if path else "[]"
            result.append((child_path, child))
            result.extend(_iter_json_values(child, child_path))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
