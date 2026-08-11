from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_go

from scripts.go_external_corpus import _code_sample_value, _is_code_sample_slice, _walk


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from scripts import evaluate_go_external_corpus


class GoExternalCorpusTests(unittest.TestCase):
    def test_reconstructs_concatenated_go_sample_as_one_file(self) -> None:
        source = rb'''
package samples
type CodeSample struct{}
var cases = []CodeSample{
    {[]string{`
package main
type Config struct {
    APIKey string ` + "`json:\"api_key\"`" + `
}
func main() {}
`}, 1},
}
'''
        parser = Parser(Language(tree_sitter_go.language()))
        tree = parser.parse(source)
        group = next(
            node
            for node in _walk(tree.root_node)
            if node.type == "composite_literal" and _is_code_sample_slice(node, source)
        )
        body = group.child_by_field_name("body")
        assert body is not None

        code_files, error_count = _code_sample_value(body.named_children[0], source)

        self.assertEqual(error_count, 1)
        self.assertEqual(len(code_files), 1)
        self.assertIn(b'APIKey string `json:"api_key"`', code_files[0])
        self.assertIn(b"func main() {}", code_files[0])

    def test_evaluator_default_uses_migrated_manifest(self) -> None:
        manifest_path = evaluate_go_external_corpus.DEFAULT_MANIFEST
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest_path.name, "go-external-random-598x2-2026-07-24-v2.json")
        self.assertEqual(
            hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "2223c92e57713a16155e9265cdd7eda15df2e35c367aa35b40faa5509303843d",
        )
        self.assertEqual(manifest["migration"]["revision"], "go-string-expression-v2")
        self.assertEqual(manifest["migration"]["changed_gosec_cases"], 24)
        self.assertTrue(manifest["migration"]["selection_ids_preserved"])

    def test_migrated_manifest_preserves_selection_and_labels(self) -> None:
        legacy = json.loads(
            (ROOT / "config" / "evaluation" / "go-external-random-598x2-2026-07-22.json").read_text(
                encoding="utf-8"
            )
        )
        migrated = json.loads(evaluate_go_external_corpus.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        legacy_cases = {case["id"]: case for case in legacy["cases"]}
        migrated_cases = {case["id"]: case for case in migrated["cases"]}

        self.assertEqual(set(legacy_cases), set(migrated_cases))
        self.assertEqual(
            {
                case_id: (
                    case["partition"],
                    case["source"],
                    case["vulnerable"],
                    tuple(case.get("cwes") or []),
                    case.get("source_path"),
                    case.get("line"),
                )
                for case_id, case in legacy_cases.items()
            },
            {
                case_id: (
                    case["partition"],
                    case["source"],
                    case["vulnerable"],
                    tuple(case.get("cwes") or []),
                    case.get("source_path"),
                    case.get("line"),
                )
                for case_id, case in migrated_cases.items()
            },
        )
        changed_case_ids = {
            case_id
            for case_id, case in legacy_cases.items()
            if case.get("code_hash") != migrated_cases[case_id].get("code_hash")
            or case.get("file_count") != migrated_cases[case_id].get("file_count")
        }
        self.assertEqual(changed_case_ids, set(migrated["migration"]["changed_case_ids"]))

    def test_apply_adjudications_overrides_labels_and_preserves_originals(self) -> None:
        cases = [
            {"id": "case-1", "vulnerable": True, "cwes": ["CWE-79"], "partition": "qualification"},
            {"id": "case-2", "vulnerable": False, "cwes": ["CWE-89"], "partition": "qualification"},
            {"id": "case-3", "vulnerable": True, "cwes": ["CWE-22"], "partition": "qualification"},
        ]
        payload = {
            "version": "unit-test",
            "methodology": {"negative_label_scope": "adjudicated_partial"},
            "cases": [
                {
                    "id": "case-1",
                    "action": "override",
                    "vulnerable": False,
                    "cwes": ["CWE-79"],
                    "classification": "label_conflict",
                    "evidence": "unit test",
                },
                {"id": "case-3", "action": "exclude", "evidence": "unit test"},
            ],
        }

        adjusted, summary = evaluate_go_external_corpus._apply_adjudications(cases, payload)

        self.assertEqual(summary["entries"], 2)
        self.assertEqual(summary["overridden"], 1)
        self.assertEqual(summary["excluded"], 1)
        self.assertEqual([case["id"] for case in adjusted], ["case-1", "case-2"])
        self.assertFalse(adjusted[0]["vulnerable"])
        self.assertTrue(adjusted[0]["original_vulnerable"])
        self.assertEqual(adjusted[0]["original_cwes"], ["CWE-79"])
        self.assertEqual(adjusted[0]["adjudication"]["classification"], "label_conflict")

    def test_apply_adjudications_rejects_unknown_cases(self) -> None:
        with self.assertRaises(SystemExit):
            evaluate_go_external_corpus._apply_adjudications(
                [{"id": "case-1", "vulnerable": True, "cwes": ["CWE-79"]}],
                {"cases": [{"id": "missing", "vulnerable": False}]},
            )


if __name__ == "__main__":
    unittest.main()
