from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_security_evaluation_gates import (
    check_adjudicated_partial_truth_gate,
    check_adjudication_consistency_gate,
    check_high_star_engineering_corpus_gate,
    check_raw_external_label_gate,
    check_sealed_qualification_integrity_gate,
    main as check_security_evaluation_main,
)


def result_payload(
    *,
    metric_scope: str,
    adjudication_applied: bool,
    qualification_passed: bool = False,
    tp: int = 587,
    fp: int = 30,
    tn: int = 568,
    fn: int = 11,
    accuracy: float = 0.965719,
    precision: float = 0.951378,
) -> dict[str, object]:
    return {
        "metric_scope": metric_scope,
        "qualification": {
            "adjudication_applied": adjudication_applied,
            "passed": qualification_passed,
        },
        "metrics": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "accuracy": accuracy,
            "precision": precision,
        },
    }


def high_star_payload() -> dict[str, object]:
    return {
        "evaluation_policy": {
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
        "summary": {
            "projects": 2,
            "completed": 2,
            "completion_rate": 1.0,
            "parse_error_rate": 0.1,
            "raw_parse_error_rate": 0.2,
            "parse_recovery_rate": 0.5,
        },
        "projects": [
            {"slug": "owner/a", "status": "completed", "parse_error_rate": 0.0},
            {"slug": "owner/b", "status": "completed", "parse_error_rate": 0.1},
        ],
    }


def sealed_qualification_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "metric_scope": "cwe_security_classification",
        "thresholds": {
            "min_accuracy": 0.95,
            "max_false_positive_rate": 0.005,
            "max_false_negative_rate": 0.005,
        },
        "metrics": {
            "tp": 598,
            "fp": 0,
            "tn": 598,
            "fn": 0,
            "accuracy": 1.0,
            "precision": 1.0,
            "recall": 1.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
        },
        "qualification": {
            "passed": True,
            "sample_size_passed": True,
            "negative_label_scope": "cwe_complete",
            "cwe_complete_negative_labels": True,
            "adjudication_applied": False,
            "adjudication_qualification_eligible": True,
            "point_estimate_passed": True,
            "confidence_passed": True,
            "positive_cases": 598,
            "negative_cases": 598,
            "unlabeled_detection_count": 0,
            "false_negative_rate_upper_95": 0.005,
            "false_positive_rate_upper_95": 0.005,
        },
    }
    for key, value in overrides.items():
        if key == "metrics":
            payload["metrics"] = {**payload["metrics"], **value}  # type: ignore[operator]
        elif key == "qualification":
            payload["qualification"] = {**payload["qualification"], **value}  # type: ignore[operator]
        else:
            payload[key] = value
    return payload


def sealed_truth_manifest_payload() -> dict[str, object]:
    return {
        "methodology": {
            "qualification_eligible": True,
            "negative_label_scope": "cwe_complete",
            "cwe_complete_negative_labels": True,
            "seal_status": "sealed",
            "leakage_policy": "labels stay sealed until rules freeze before evaluation",
            "case_label_scope": "cwe_complete",
        },
        "cases": [
            {
                "id": "truth-positive",
                "partition": "qualification",
                "language": "go",
                "vulnerable": True,
                "cwes": ["CWE-89"],
                "code_hash": "a" * 64,
                "source_path": "positive.go",
                "label_evidence": "tainted request value reaches SQL text",
                "label_scope": "cwe_complete",
            },
            {
                "id": "truth-negative",
                "partition": "qualification",
                "language": "go",
                "vulnerable": False,
                "cwes": ["CWE-89"],
                "code_hash": "b" * 64,
                "source_path": "negative.go",
                "label_evidence": "SQL text is constant and parameters are bound",
                "label_scope": "cwe_complete",
            },
        ],
    }


def adjudication_payload() -> dict[str, object]:
    return {
        "metric_scope": "adjudicated_cwe_truth_partial",
        "methodology": {
            "negative_label_scope": "adjudicated_partial",
            "cwe_complete_negative_labels": False,
            "qualification_eligible": False,
        },
        "cases": [
            {
                "id": "case-fn-1",
                "action": "override",
                "vulnerable": False,
                "cwes": ["CWE-89"],
                "classification": "safe_or_bounded_flow",
                "product_action": "do_not_flag",
                "evidence": "query text is constant and all request values are bound parameters",
            }
        ],
    }


def raw_result_with_fn() -> dict[str, object]:
    payload = result_payload(
        metric_scope="external_rule_label_agreement",
        adjudication_applied=False,
        fn=1,
    )
    payload["cases"] = [
        {
            "id": "case-fn-1",
            "cwes": ["CWE-89"],
            "vulnerable": True,
            "detected": False,
            "outcome": "FN",
        }
    ]
    return payload


def adjudicated_result_with_tn() -> dict[str, object]:
    payload = result_payload(
        metric_scope="adjudicated_cwe_truth_partial",
        adjudication_applied=True,
        tn=579,
        fn=0,
        accuracy=0.974916,
    )
    payload["adjudications"] = {"applied": True, "entries": 1, "overridden": 1, "excluded": 0}
    payload["cases"] = [
        {
            "id": "case-fn-1",
            "cwes": ["CWE-89"],
            "vulnerable": False,
            "detected": False,
            "outcome": "TN",
        }
    ]
    return payload


def failure_attribution_payload() -> dict[str, object]:
    return {
        "remaining_false_negatives": [
            {
                "id": "case-fn-1",
                "cwes": ["CWE-89"],
                "classification": "safe_or_bounded_flow",
                "product_action": "do_not_flag",
                "evidence": "query text is constant and all request values are bound parameters",
            }
        ]
    }


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class SecurityEvaluationGateTests(unittest.TestCase):
    def test_raw_external_label_gate_accepts_current_non_regression_baseline(self) -> None:
        failures = check_raw_external_label_gate(
            result_payload(metric_scope="external_rule_label_agreement", adjudication_applied=False),
            min_accuracy=0.95,
            min_precision=0.95,
            min_tp=587,
            max_fp=30,
            max_fn=11,
        )

        self.assertEqual(failures, [])

    def test_raw_external_label_gate_rejects_regressions(self) -> None:
        failures = check_raw_external_label_gate(
            result_payload(
                metric_scope="external_rule_label_agreement",
                adjudication_applied=False,
                tp=586,
                fp=31,
                fn=12,
            ),
            min_accuracy=0.95,
            min_precision=0.95,
            min_tp=587,
            max_fp=30,
            max_fn=11,
        )

        self.assertTrue(any("TP regressed" in failure for failure in failures))
        self.assertTrue(any("FP rose" in failure for failure in failures))
        self.assertTrue(any("FN rose" in failure for failure in failures))

    def test_adjudicated_partial_truth_gate_requires_zero_false_negatives(self) -> None:
        accepted = check_adjudicated_partial_truth_gate(
            result_payload(
                metric_scope="adjudicated_cwe_truth_partial",
                adjudication_applied=True,
                tn=579,
                fn=0,
                accuracy=0.974916,
            ),
            min_accuracy=0.95,
            min_precision=0.95,
        )
        rejected = check_adjudicated_partial_truth_gate(
            result_payload(
                metric_scope="adjudicated_cwe_truth_partial",
                adjudication_applied=True,
                tn=578,
                fn=1,
                accuracy=0.974080,
            ),
            min_accuracy=0.95,
            min_precision=0.95,
        )

        self.assertEqual(accepted, [])
        self.assertTrue(any("FN must remain 0" in failure for failure in rejected))

    def test_adjudicated_partial_truth_gate_rejects_qualification_pass_claim(self) -> None:
        failures = check_adjudicated_partial_truth_gate(
            result_payload(
                metric_scope="adjudicated_cwe_truth_partial",
                adjudication_applied=True,
                qualification_passed=True,
                fn=0,
                accuracy=0.974916,
            ),
            min_accuracy=0.95,
            min_precision=0.95,
        )

        self.assertTrue(any("sealed qualification pass" in failure for failure in failures))

    def test_adjudication_consistency_accepts_current_partial_truth_shape(self) -> None:
        failures = check_adjudication_consistency_gate(
            adjudication_payload(),
            raw_result=raw_result_with_fn(),
            adjudicated_result=adjudicated_result_with_tn(),
            failure_attribution=failure_attribution_payload(),
        )

        self.assertEqual(failures, [])

    def test_adjudication_consistency_rejects_unknown_or_uncovered_cases(self) -> None:
        adjudications = adjudication_payload()
        adjudications["cases"] = [
            {
                **adjudications["cases"][0],  # type: ignore[index]
                "id": "unknown",
                "evidence": "",
                "classification": "unsupported",
            }
        ]

        failures = check_adjudication_consistency_gate(
            adjudications,
            raw_result=raw_result_with_fn(),
            adjudicated_result=adjudicated_result_with_tn(),
            failure_attribution=failure_attribution_payload(),
        )

        self.assertTrue(any("unknown raw cases" in failure for failure in failures))
        self.assertTrue(any("cover exactly the raw external-label FN set" in failure for failure in failures))
        self.assertTrue(any("failure attribution" in failure for failure in failures))
        self.assertTrue(any("classification" in failure for failure in failures))
        self.assertTrue(any("must include evidence" in failure for failure in failures))

    def test_adjudication_consistency_rejects_remaining_false_negative(self) -> None:
        adjudicated = adjudicated_result_with_tn()
        adjudicated["cases"] = [{**adjudicated["cases"][0], "outcome": "FN"}]  # type: ignore[index]
        adjudicated["metrics"] = {**adjudicated["metrics"], "fn": 1}  # type: ignore[operator]

        failures = check_adjudication_consistency_gate(
            adjudication_payload(),
            raw_result=raw_result_with_fn(),
            adjudicated_result=adjudicated,
            failure_attribution=failure_attribution_payload(),
        )

        self.assertTrue(any("remains FN" in failure for failure in failures))
        self.assertTrue(any("FN must be 0" in failure for failure in failures))

    def test_high_star_engineering_gate_accepts_coverage_only_corpus(self) -> None:
        failures = check_high_star_engineering_corpus_gate(high_star_payload(), expected_projects=2)

        self.assertEqual(failures, [])

    def test_high_star_engineering_gate_rejects_truth_metric_leakage(self) -> None:
        payload = high_star_payload()
        payload["summary"] = {**payload["summary"], "accuracy": 0.99}
        payload["projects"] = [
            payload["projects"][0],
            {**payload["projects"][1], "project_overlay": {"fingerprint": "abc"}},
        ]

        failures = check_high_star_engineering_corpus_gate(payload, expected_projects=2)

        self.assertTrue(any("product truth metric fields" in failure for failure in failures))
        self.assertTrue(any("adaptive overlay fields" in failure for failure in failures))

    def test_high_star_engineering_gate_rejects_qualification_claims(self) -> None:
        payload = high_star_payload()
        payload["qualification"] = {"passed": True}
        payload["adjudication"] = {"applied": True}

        failures = check_high_star_engineering_corpus_gate(payload, expected_projects=2)

        self.assertTrue(any("qualification result" in failure for failure in failures))
        self.assertTrue(any("adjudication result" in failure for failure in failures))

    def test_sealed_qualification_integrity_accepts_complete_sealed_pass(self) -> None:
        failures = check_sealed_qualification_integrity_gate(
            sealed_qualification_payload(),
            label="sealed",
            min_accuracy=0.95,
            min_precision=0.95,
        )

        self.assertEqual(failures, [])

    def test_sealed_qualification_integrity_rejects_adjudicated_pass_claim(self) -> None:
        failures = check_sealed_qualification_integrity_gate(
            sealed_qualification_payload(
                metric_scope="adjudicated_cwe_truth_partial",
                qualification={
                    "adjudication_applied": True,
                    "cwe_complete_negative_labels": False,
                },
            ),
            label="sealed",
            min_accuracy=0.95,
            min_precision=0.95,
        )

        self.assertTrue(any("cwe_security_classification" in failure for failure in failures))
        self.assertTrue(any("must not use adjudication" in failure for failure in failures))
        self.assertTrue(any("CWE-complete" in failure for failure in failures))

    def test_sealed_qualification_integrity_rejects_point_estimate_without_confidence(self) -> None:
        failures = check_sealed_qualification_integrity_gate(
            sealed_qualification_payload(
                metrics={"fn": 1, "accuracy": 0.99, "precision": 0.99},
                qualification={
                    "confidence_passed": False,
                    "positive_cases": 120,
                    "false_negative_rate_upper_95": 0.03,
                },
            ),
            label="sealed",
            min_accuracy=0.95,
            min_precision=0.95,
        )

        self.assertTrue(any("confidence_passed=true" in failure for failure in failures))
        self.assertTrue(any("observed FN=0" in failure for failure in failures))
        self.assertTrue(any("at least 598 positive" in failure for failure in failures))
        self.assertTrue(any("FN upper 95" in failure for failure in failures))

    def test_sealed_qualification_integrity_rejects_adaptive_overlay_pass_claim(self) -> None:
        failures = check_sealed_qualification_integrity_gate(
            sealed_qualification_payload(project_overlay={"fingerprint": "abc"}, scan={"scan_mode": "adaptive_upload"}),
            label="sealed",
            min_accuracy=0.95,
            min_precision=0.95,
        )

        self.assertTrue(any("adaptive overlay fields" in failure for failure in failures))
        self.assertTrue(any("adaptive_upload" in failure for failure in failures))

    def test_main_optionally_validates_sealed_truth_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            raw_path = root / "raw.json"
            adjudicated_path = root / "adjudicated.json"
            high_star_path = root / "high-star.json"
            sealed_path = root / "sealed.json"
            adjudication_path = root / "adjudications.json"
            attribution_path = root / "failure-attribution.json"
            write_json(raw_path, raw_result_with_fn())
            write_json(adjudicated_path, adjudicated_result_with_tn())
            write_json(high_star_path, high_star_payload())
            write_json(sealed_path, sealed_truth_manifest_payload())
            write_json(adjudication_path, adjudication_payload())
            write_json(attribution_path, failure_attribution_payload())

            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                status = check_security_evaluation_main(
                    [
                        "--raw",
                        str(raw_path),
                        "--adjudicated",
                        str(adjudicated_path),
                        "--high-star",
                        str(high_star_path),
                        "--adjudications",
                        str(adjudication_path),
                        "--failure-attribution",
                        str(attribution_path),
                        "--high-star-projects",
                        "2",
                        "--sealed-manifest",
                        str(sealed_path),
                        "--sealed-min-positive-cases",
                        "1",
                        "--sealed-min-negative-cases",
                        "1",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertIn("sealed-manifest cases=2", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
