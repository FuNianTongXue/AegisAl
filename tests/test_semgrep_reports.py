from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from app.semgrep_tool import (
    DEFAULT_SEMGREP_RULES,
    SemgrepTool,
    _metadata_cwes,
    _best_record_for_scenario,
    _enrich_code_findings,
    _is_review_finding,
    _merge_cross_engine_findings,
    _merge_findings,
    _parse_semgrep_json,
    _semgrep_rules_path,
    _semgrep_severity,
    _severity_from_security_score,
    analyze_static_paths,
)
from app.dependencies import scan_dependency_attachments
from app.graph import KnowledgeSecurityGraph, build_report_conclusion, empty_knowledge_graph
from app.report_subgraph import report_capability_subgraph
from app.reports import (
    ReportStore,
    _build_html_report,
    _markdown_fragment_to_html,
    _parse_report_document,
    _pdf_inline_markdown,
    _report_china_time,
    _sanitize_report_content,
    build_agent_task_markdown_report,
    build_dependency_markdown_report,
    build_report_metrics,
)


class SemgrepToolTests(unittest.TestCase):
    def test_low_confidence_standard_findings_are_review_only_but_recall_findings_remain_primary(self) -> None:
        self.assertTrue(_is_review_finding({"confidence": "low", "rule_profile": "standard"}))
        self.assertTrue(_is_review_finding({"confidence": "high", "rule_profile": "review"}))
        self.assertFalse(_is_review_finding({"confidence": "low", "rule_profile": "recall"}))
        self.assertFalse(_is_review_finding({"confidence": "high", "rule_profile": "standard"}))

    def test_analyze_stops_immediately_when_cancelled(self) -> None:
        attachments = [
            {"file_name": f"src/Service{index}.java", "content": f"class Service{index} {{}}\n"}
            for index in range(16)
        ]
        tool = SemgrepTool()

        result = tool.analyze(
            attachments,
            {"dependencies": []},
            [],
            cancelled=lambda: True,
            language_hint="java",
        )

        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["cli_status"], "cancelled")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["files"], [])
        self.assertIn("静态分析已由用户停止。", " ".join(result["diagnostics"]))

    def test_analyze_honors_cancellation_during_per_file_syntax_phase(self) -> None:
        attachments = [
            {"file_name": f"src/Service{index}.java", "content": f"class Service{index} {{}}\n"}
            for index in range(16)
        ]
        checks = {"count": 0}

        def cancelled() -> bool:
            checks["count"] += 1
            return checks["count"] > 3

        tool = SemgrepTool()
        result = tool.analyze(
            attachments,
            {"dependencies": []},
            [],
            cancelled=cancelled,
            language_hint="java",
        )

        self.assertEqual(result["status"], "cancelled")
        self.assertLess(checks["count"], len(attachments))
        self.assertIn("静态分析已由用户停止。", " ".join(result["diagnostics"]))

    def test_complete_scan_processes_all_attachments(self) -> None:
        attachments = [
            {"file_name": f"src/file-{index}.py", "content": f"value_{index} = {index}\n"}
            for index in range(4)
        ]
        tool = SemgrepTool()

        with (
            patch("app.semgrep_tool.MAX_ASK_ATTACHMENTS", 2),
            patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}),
        ):
            bounded = tool.analyze(attachments, {"dependencies": []}, [])
            complete = tool.analyze(
                attachments,
                {"dependencies": []},
                [],
                include_all_attachments=True,
            )

        self.assertEqual(len(bounded["files"]), 2)
        self.assertEqual(len(complete["files"]), 4)

    def test_complete_cli_scan_disables_process_rule_and_target_size_limits(self) -> None:
        calls: list[dict] = []

        def run(command, **kwargs):
            calls.append({"command": command, **kwargs})
            result_path = Path(command[command.index("--json-output") + 1])
            result_path.write_text('{"results": [], "errors": []}', encoding="utf-8")
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        source = [{"file_name": "src/demo.py", "content": "value = 1\n"}]
        with tempfile.TemporaryDirectory() as temp_dir:
            executable = Path(temp_dir) / "semgrep"
            executable.touch()
            executable.chmod(0o755)
            tool = SemgrepTool(str(executable))
            with patch("app.semgrep_tool.subprocess.run", side_effect=run):
                status, _, _ = tool._run_cli(
                    source,
                    source,
                    {"dependencies": []},
                    [],
                    complete_scan=True,
                )

        command = calls[0]["command"]
        self.assertEqual(status, "completed")
        self.assertIsNone(calls[0]["timeout"])
        self.assertEqual(command[command.index("--timeout") + 1], "0")
        self.assertEqual(command[command.index("--max-target-bytes") + 1], "0")

    def test_semgrep_json_is_mapped_to_ast_cfg_dfg_report_fields(self) -> None:
        source = """import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    String command = request.getParameter("command");
    if (command != null) {
      Runtime.getRuntime().exec(command);
    }
  }
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = Path(temp_dir) / "results.json"
            result_path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "config.semgrep.secflow.java.command-injection",
                                "path": "Demo.java",
                                "start": {"line": 6},
                                "extra": {
                                    "message": "命令注入",
                                    "severity": "ERROR",
                                    "metadata": {
                                        "scenario": "command_execution",
                                        "cwe": ["CWE-78"],
                                        "confidence": "HIGH",
                                    },
                                },
                            }
                        ],
                        "errors": [],
                    }
                ),
                encoding="utf-8",
            )

            findings, diagnostics = _parse_semgrep_json(
                result_path,
                [{"file_name": "Demo.java", "content": source}],
                {"dependencies": []},
                [],
            )

        self.assertEqual(diagnostics, [])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["rule_id"], "secflow.java.command-injection")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["cwes"], ["CWE-78"])
        self.assertEqual(finding["source"]["line"], 4)
        self.assertEqual(finding["sink"]["line"], 6)
        self.assertIn("控制条件", finding["cfg"])
        self.assertIn("source", [item["kind"] for item in finding["path"]])
        self.assertTrue(finding["ast"]["classes"])

    def test_semgrep_severity_and_cwe_metadata_are_normalized(self) -> None:
        self.assertEqual(_severity_from_security_score("9.1"), "CRITICAL")
        self.assertEqual(_severity_from_security_score("7.8"), "HIGH")
        self.assertEqual(_severity_from_security_score("6.1"), "MEDIUM")
        self.assertEqual(_severity_from_security_score("3.1"), "LOW")
        self.assertEqual(_severity_from_security_score("not-a-score"), "UNKNOWN")
        self.assertEqual(_semgrep_severity("ERROR", {}), "HIGH")
        self.assertEqual(_semgrep_severity("WARNING", {}), "MEDIUM")
        self.assertEqual(_metadata_cwes({"cwe": ["CWE-079: XSS", "CWE-79"]}), ["CWE-79"])

    def test_code_scenario_is_not_linked_to_unrelated_dependency_record(self) -> None:
        record = {
            "id": "CVE-2023-24163",
            "title": "Unrelated archive component issue",
            "summary": "A path handling issue in a utility library.",
            "components": [{"ecosystem": "Maven", "name": "cn.hutool:hutool-all"}],
        }

        matched = _best_record_for_scenario(
            [record],
            {"dependencies": [{"ecosystem": "Maven", "name": "cn.hutool:hutool-all", "version": "5.8.40"}]},
            "log_injection_lookup",
            'LOGGER.info("token:{}", token);',
        )

        self.assertEqual(matched, {})

    def test_cli_findings_deduplicate_same_rule_and_location(self) -> None:
        findings = [
            {"rule_id": "java/example", "title": "Path one", "sink": {"file": "Demo.java", "line": 12}},
            {"rule_id": "java/example", "title": "Path two", "sink": {"file": "Demo.java", "line": 12}},
            {"rule_id": "java/other", "title": "Other risk", "sink": {"file": "Demo.java", "line": 12}},
        ]

        merged = _merge_findings(findings)

        self.assertEqual(len(merged), 2)
        self.assertEqual({item["rule_id"] for item in merged}, {"java/example", "java/other"})

    def test_equivalent_cross_engine_findings_deduplicate_by_scenario_and_sink(self) -> None:
        findings = [
            {
                "engine": "primary",
                "scenario": "command_execution",
                "sink": {"file": "Demo.java", "line": 12},
            },
            {
                "engine": "path-analysis",
                "scenario": "command_execution",
                "sink": {"file": "Demo.java", "line": 12},
            },
            {
                "engine": "path-analysis",
                "scenario": "sql_injection",
                "sink": {"file": "Demo.java", "line": 12},
            },
        ]

        merged = _merge_cross_engine_findings(findings)

        self.assertEqual(len(merged), 2)
        self.assertEqual({item["scenario"] for item in merged}, {"command_execution", "sql_injection"})

    def test_cross_engine_deduplication_keeps_richer_interprocedural_path(self) -> None:
        primary = {
            "id": "primary",
            "scenario": "command_execution",
            "sink": {"file": "Demo.java", "line": 12},
            "path": [{"kind": "sink"}],
        }
        interprocedural = {
            "id": "interprocedural",
            "scenario": "command_execution",
            "sink": {"file": "Demo.java", "line": 12},
            "analysis_depth": 1,
            "path": [{"kind": "source"}, {"kind": "call"}, {"kind": "sink"}],
        }

        merged = _merge_cross_engine_findings([primary, interprocedural])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "interprocedural")

    def test_cross_engine_deduplication_prefers_standard_rule_over_recall_rule(self) -> None:
        recall = {
            "rule_id": "secflow.go.recall-dangerous-exec",
            "rule_profile": "recall",
            "scenario": "command_execution",
            "sink": {"file": "app.go", "line": 10},
            "path": [{"kind": "source"}, {"kind": "sink"}],
        }
        standard = {
            "rule_id": "secflow.go.command-injection",
            "rule_profile": "standard",
            "scenario": "command_execution",
            "sink": {"file": "app.go", "line": 10},
            "path": [{"kind": "source"}, {"kind": "sink"}],
        }

        merged = _merge_cross_engine_findings([recall, standard])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["rule_id"], "secflow.go.command-injection")

    def test_finance_transaction_sinks_in_same_method_are_aggregated(self) -> None:
        source = """class WalletService {
  Transaction fundTransfer(String source, String target, Double amount) {
    wallet.setBalance(wallet.getBalance() - amount);
    targetWallet.setBalance(targetWallet.getBalance() + amount);
    transactionDao.save(transaction);
    return transaction;
  }
}
"""
        findings = [
            {
                "id": "f1",
                "rule_id": "secflow.java.finance.money-operation-without-transaction",
                "scenario": "funds_transaction_boundary",
                "title": "资金更新缺少事务边界",
                "sink": {"file": "WalletService.java", "line": 3, "snippet": "wallet.setBalance(wallet.getBalance() - amount);"},
                "path": [{"kind": "sink", "file": "WalletService.java", "line": 3}],
            },
            {
                "id": "f2",
                "rule_id": "secflow.java.finance.money-operation-without-transaction",
                "scenario": "funds_transaction_boundary",
                "title": "资金更新缺少事务边界",
                "sink": {"file": "WalletService.java", "line": 4, "snippet": "targetWallet.setBalance(targetWallet.getBalance() + amount);"},
                "path": [{"kind": "sink", "file": "WalletService.java", "line": 4}],
            },
            {
                "id": "f3",
                "rule_id": "secflow.java.finance.money-operation-without-transaction",
                "scenario": "funds_transaction_boundary",
                "title": "资金更新缺少事务边界",
                "sink": {"file": "WalletService.java", "line": 5, "snippet": "transactionDao.save(transaction);"},
                "path": [{"kind": "sink", "file": "WalletService.java", "line": 5}],
            },
        ]

        enriched = _enrich_code_findings(findings, [{"file_name": "WalletService.java", "content": source}])

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]["aggregation"]["kind"], "finance_method")
        self.assertEqual(enriched[0]["aggregation"]["method"], "fundTransfer")
        self.assertEqual(enriched[0]["aggregation"]["sink_count"], 3)
        self.assertIn("fundTransfer()", enriched[0]["title"])
        self.assertEqual({item["line"] for item in enriched[0]["aggregated_sinks"]}, {3, 4, 5})
        self.assertEqual([item["line"] for item in enriched[0]["path"] if item["kind"] == "sink"], [3, 4, 5])

    def test_finance_transaction_sinks_in_different_methods_are_not_aggregated(self) -> None:
        source = """class WalletService {
  void debit(Double amount) {
    walletRepository.save(wallet);
  }

  void credit(Double amount) {
    walletRepository.save(targetWallet);
  }
}
"""
        findings = [
            {
                "id": "f1",
                "rule_id": "secflow.java.finance.money-operation-without-transaction",
                "scenario": "funds_transaction_boundary",
                "title": "资金更新缺少事务边界",
                "sink": {"file": "WalletService.java", "line": 3, "snippet": "walletRepository.save(wallet);"},
                "path": [{"kind": "sink", "file": "WalletService.java", "line": 3}],
            },
            {
                "id": "f2",
                "rule_id": "secflow.java.finance.money-operation-without-transaction",
                "scenario": "funds_transaction_boundary",
                "title": "资金更新缺少事务边界",
                "sink": {"file": "WalletService.java", "line": 7, "snippet": "walletRepository.save(targetWallet);"},
                "path": [{"kind": "sink", "file": "WalletService.java", "line": 7}],
            },
        ]

        enriched = _enrich_code_findings(findings, [{"file_name": "WalletService.java", "content": source}])

        self.assertEqual(len(enriched), 2)
        self.assertTrue(all("aggregation" not in item for item in enriched))

    def test_finance_endpoint_and_transaction_method_are_aggregated_into_request_chain(self) -> None:
        controller = """class WalletController {
  Transaction WalletTOWalletTransfer(String source, String target, Double amount) {
    return walletService.fundTransfer(source, target, amount);
  }
}
"""
        service = """class WalletService {
  Transaction fundTransfer(String source, String target, Double amount) {
    wallet.setBalance(wallet.getBalance() - amount);
    targetWallet.setBalance(targetWallet.getBalance() + amount);
    transactionDao.save(transaction);
    return transaction;
  }
}
"""
        findings = [
            {
                "id": "i1",
                "rule_id": "secflow.java.finance.missing-idempotency-key",
                "scenario": "idempotency_missing",
                "title": "资金接口缺少幂等键",
                "severity": "MEDIUM",
                "confidence": "medium",
                "sink": {
                    "file": "WalletController.java",
                    "line": 3,
                    "snippet": "return walletService.fundTransfer(source, target, amount);",
                },
                "path": [{"kind": "sink", "file": "WalletController.java", "line": 3}],
            },
            {
                "id": "t1",
                "rule_id": "secflow.java.finance.money-operation-without-transaction",
                "scenario": "funds_transaction_boundary",
                "title": "资金更新缺少事务边界",
                "severity": "MEDIUM",
                "confidence": "medium",
                "sink": {"file": "WalletService.java", "line": 3, "snippet": "wallet.setBalance(wallet.getBalance() - amount);"},
                "path": [{"kind": "sink", "file": "WalletService.java", "line": 3}],
            },
            {
                "id": "t2",
                "rule_id": "secflow.java.finance.money-operation-without-transaction",
                "scenario": "funds_transaction_boundary",
                "title": "资金更新缺少事务边界",
                "severity": "MEDIUM",
                "confidence": "medium",
                "sink": {"file": "WalletService.java", "line": 5, "snippet": "transactionDao.save(transaction);"},
                "path": [{"kind": "sink", "file": "WalletService.java", "line": 5}],
            },
        ]

        enriched = _enrich_code_findings(
            findings,
            [
                {"file_name": "WalletController.java", "content": controller},
                {"file_name": "WalletService.java", "content": service},
            ],
        )

        self.assertEqual(len(enriched), 1)
        chain = enriched[0]
        self.assertEqual(chain["scenario"], "funds_request_chain")
        self.assertEqual(chain["aggregation"]["kind"], "finance_request_chain")
        self.assertEqual(chain["aggregation"]["method"], "fundTransfer")
        self.assertIn("缺少幂等与事务边界", chain["title"])
        self.assertEqual(len(chain["related_findings"]), 2)
        self.assertEqual([item["line"] for item in chain["aggregated_sinks"]], [3, 5])
        self.assertIn("Controller 入口", chain["cfg"])

    def test_internal_fallback_detects_finance_request_chain_without_cli(self) -> None:
        controller = """class WalletController {
  @PutMapping("/fundtran/{sourceMobileNo}/{targetMobileNo}/{amount}/{uniqueId}")
  ResponseEntity<Transaction> WalletTOWalletTransfer(String source, String target, Double amount, String uniqueId) {
    Transaction transaction = walletService.fundTransfer(source, target, amount, uniqueId);
    return new ResponseEntity<Transaction>(transaction, HttpStatus.OK);
  }
}
"""
        service = """class WalletService {
  Transaction fundTransfer(String source, String target, Double amount, String uniqueId) {
    wallet.setBalance(wallet.getBalance() - amount);
    targetWallet.setBalance(targetWallet.getBalance() + amount);
    transactionDao.save(transaction);
    return transaction;
  }
}
"""

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = analyze_static_paths(
                [
                    {"file_name": "src/main/java/WalletController.java", "content": controller},
                    {"file_name": "src/main/java/WalletService.java", "content": service},
                ],
                {"files": [], "dependencies": []},
                [],
            )

        chains = [item for item in result["findings"] if item.get("scenario") == "funds_request_chain"]
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain["aggregation"]["kind"], "finance_request_chain")
        self.assertEqual(chain["aggregation"]["method"], "fundTransfer")
        self.assertEqual([item["line"] for item in chain["aggregated_sinks"]], [3, 4, 5])

    def test_successful_cli_result_ignores_same_method_medium_confidence_supplement(self) -> None:
        java = """
        import javax.servlet.http.HttpServletRequest;
        class Demo {
          void handle(HttpServletRequest request) {
            String msg = request.getParameter("msg");
            logger.info(msg);
          }
        }
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            cli = Path(temp_dir) / "semgrep"
            cli.touch()
            cli.chmod(0o755)
            tool = SemgrepTool(str(cli))
            with patch.object(tool, "_run_cli", return_value=("completed", [], [])):
                result = tool.analyze(
                    [{"file_name": "Demo.java", "content": java}],
                    {"dependencies": []},
                    [],
                )

        self.assertEqual(result["cli_status"], "completed")
        self.assertEqual(result["mode"], "bundled-cli")
        self.assertEqual(result["finding_count"], 0)

    def test_explicit_offline_rule_path_is_preferred(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rules = Path(temp_dir) / "rules.yml"
            rules.write_text("rules: []\n", encoding="utf-8")
            with patch.dict(os.environ, {"SECFLOW_SEMGREP_RULES": str(rules)}):
                resolved = _semgrep_rules_path()

        self.assertEqual(resolved, rules)

    def test_offline_rules_are_bundled_with_the_source_tree(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECFLOW_SEMGREP_RULES", None)
            resolved = _semgrep_rules_path()

        self.assertIsNotNone(resolved)
        self.assertTrue(str(resolved).endswith(DEFAULT_SEMGREP_RULES))

    def test_internal_analyzer_is_available_without_semgrep_cli(self) -> None:
        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            status = SemgrepTool().status()

        self.assertTrue(status["available"])
        self.assertTrue(status["internalAnalyzer"])
        self.assertFalse(status["userInstallRequired"])
        self.assertEqual(status["mode"], "internal")

    def test_weak_random_sampling_context_is_downgraded(self) -> None:
        findings = _enrich_code_findings(
            [
                {
                    "scenario": "weak_random",
                    "title": "安全敏感值使用可预测随机数生成器。",
                    "severity": "MEDIUM",
                    "confidence": "high",
                    "sink": {"file": "Sampler.java", "line": 4, "snippet": "private final Random rand = new Random();"},
                    "path": [{"kind": "sink", "file": "Sampler.java", "line": 4, "label": "随机数生成器"}],
                }
            ],
            [
                {
                    "file_name": "Sampler.java",
                    "content": "import java.util.Random;\nclass Sampler {\n  void sample() {\n    private final Random rand = new Random();\n  }\n}",
                }
            ],
        )

        self.assertEqual(findings[0]["priority"], "low")
        self.assertEqual(findings[0]["confidence"], "low")
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertIn("普通随机", findings[0]["security_context"])

    def test_weak_random_token_context_stays_high_priority(self) -> None:
        findings = _enrich_code_findings(
            [
                {
                    "scenario": "weak_random",
                    "title": "安全敏感值使用可预测随机数生成器。",
                    "severity": "MEDIUM",
                    "confidence": "high",
                    "sink": {"file": "TokenService.java", "line": 4, "snippet": "Random tokenRandom = new Random();"},
                    "path": [{"kind": "sink", "file": "TokenService.java", "line": 4, "label": "随机数生成器"}],
                }
            ],
            [
                {
                    "file_name": "TokenService.java",
                    "content": "import java.util.Random;\nclass TokenService {\n  void issueToken() {\n    Random tokenRandom = new Random();\n  }\n}",
                }
            ],
        )

        self.assertEqual(findings[0]["priority"], "high")
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertIn("安全敏感随机", findings[0]["security_context"])

    def test_weak_random_business_salt_join_is_not_security_sensitive(self) -> None:
        findings = _enrich_code_findings(
            [
                {
                    "scenario": "weak_random",
                    "title": "安全敏感值使用可预测随机数生成器。",
                    "severity": "MEDIUM",
                    "confidence": "high",
                    "sink": {"file": "SaltJoin.java", "line": 4, "snippet": "Random random = new Random(0, factor);"},
                    "path": [{"kind": "sink", "file": "SaltJoin.java", "line": 4, "label": "随机数生成器"}],
                }
            ],
            [
                {
                    "file_name": "SaltJoin.java",
                    "content": "class SaltJoin {\n  void addRandomSlot() {\n    Random random = new Random(0, factor);\n  }\n}",
                }
            ],
        )

        self.assertNotEqual(findings[0]["priority"], "high")
        self.assertNotIn("安全敏感随机", findings[0]["security_context"])

    def test_weak_random_sampling_token_is_low_priority(self) -> None:
        findings = _enrich_code_findings(
            [
                {
                    "scenario": "weak_random",
                    "title": "安全敏感值使用可预测随机数生成器。",
                    "severity": "MEDIUM",
                    "confidence": "high",
                    "sink": {"file": "Sampler.java", "line": 5, "snippet": "private Random randomGenerator = new Random();"},
                    "path": [{"kind": "sink", "file": "Sampler.java", "line": 5, "label": "随机数生成器"}],
                }
            ],
            [
                {
                    "file_name": "Sampler.java",
                    "content": "class Sampler {\n  private long samplingToken = 0;\n  void sample() {\n    private Random randomGenerator = new Random();\n  }\n}",
                }
            ],
        )

        self.assertEqual(findings[0]["priority"], "low")
        self.assertIn("普通随机", findings[0]["security_context"])

    def test_relative_cli_path_is_normalized_before_temporary_working_directory(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            executable = Path(temp_dir) / "scanner"
            executable.touch()
            relative = os.path.relpath(executable, Path.cwd())
            tool = SemgrepTool(relative)

            resolved = tool._cli_path()

            self.assertTrue(Path(resolved).is_absolute())
            self.assertEqual(Path(resolved), executable.resolve())

    def test_fallback_does_not_report_sink_without_source_or_properties_load(self) -> None:
        java = """
        import java.util.Properties;
        class ConfigurationTest {
          void load(Properties props, java.io.Reader reader) throws Exception {
            props.load(reader);
            logger.info("configuration loaded");
          }
        }
        """

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = analyze_static_paths(
                [{"file_name": "ConfigurationTest.java", "content": java}],
                {"dependencies": []},
                [],
            )

        self.assertEqual(result["finding_count"], 0)

    def test_fallback_does_not_treat_domain_statement_or_generic_execute_as_sql(self) -> None:
        java = """
        class PaymentService {
          String query(String tradeNo) {
            Policy.Statement statement = Policy.Statement.builder().build();
            return paymentClient.execute(tradeNo);
          }
        }
        """

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = analyze_static_paths(
                [{"file_name": "PaymentService.java", "content": java}],
                {"dependencies": []},
                [],
            )

        self.assertEqual(result["finding_count"], 0)

    def test_heuristic_finds_source_to_logger_sink_path(self) -> None:
        pom = """
        <project>
          <dependencies>
            <dependency>
              <groupId>org.apache.logging.log4j</groupId>
              <artifactId>log4j-core</artifactId>
              <version>2.14.1</version>
            </dependency>
          </dependencies>
        </project>
        """
        java = """
        import javax.servlet.http.HttpServletRequest;
        import org.apache.logging.log4j.LogManager;
        import org.apache.logging.log4j.Logger;

        class DemoController {
          private static final Logger logger = LogManager.getLogger(DemoController.class);
          void handle(HttpServletRequest request) {
            String msg = request.getParameter("msg");
            if (msg != null) {
              logger.info(msg);
            }
          }
        }
        """
        attachments = [
            {"file_name": "pom.xml", "content": pom},
            {"file_name": "src/main/java/DemoController.java", "content": java},
        ]
        scan = scan_dependency_attachments(attachments)
        records = [
            {
                "id": "CVE-2021-44228",
                "title": "Log4j vulnerable lookup handling",
                "severity": "CRITICAL",
                "summary": "Log4j lookup handling can be reached through logged attacker controlled strings.",
                "code_snippets": ["logger.info(msg);"],
                "matched_dependencies": scan["dependencies"],
            }
        ]

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = analyze_static_paths(attachments, scan, records)

        self.assertGreaterEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["scenario"], "log_injection_lookup")
        self.assertIn("source", [step["kind"] for step in finding["path"]])
        self.assertIn("sink", [step["kind"] for step in finding["path"]])
        self.assertIn("logger.info", finding["sink"]["snippet"])
        self.assertEqual(finding["file"], "src/main/java/DemoController.java")
        self.assertEqual(finding["risk_line"], finding["sink"]["line"])
        self.assertLessEqual(finding["line_start"], finding["risk_line"])
        self.assertGreaterEqual(finding["line_end"], finding["risk_line"])
        self.assertIn("logger.info(msg);", finding["vulnerable_snippet"])
        self.assertIn("safeLogValue", finding["fixed_snippet"])
        self.assertTrue(finding["remediation"])

    def test_vulnerable_maven_fixture_reports_exact_source_lines_and_fixed_code(self) -> None:
        fixture_root = Path(__file__).parents[1] / "test-fixtures" / "vulnerable-maven-sample"
        attachments = [
            {"file_name": "pom.xml", "content": (fixture_root / "pom.xml").read_text(encoding="utf-8")},
            {
                "file_name": "src/main/java/com/secflow/demo/VulnerableDependencyUsage.java",
                "content": (
                    fixture_root / "src/main/java/com/secflow/demo/VulnerableDependencyUsage.java"
                ).read_text(encoding="utf-8"),
            },
        ]
        scan = scan_dependency_attachments(attachments)

        def matched_dependency(fragment: str) -> list[dict[str, object]]:
            return [item for item in scan["dependencies"] if fragment in str(item.get("name") or "")]

        records = [
            {
                "id": "CVE-LOG4J",
                "title": "Log4j 日志处理漏洞",
                "summary": "Log4j lookup logging",
                "components": [{"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}],
                "matched_dependencies": matched_dependency("log4j"),
            },
            {
                "id": "CVE-SNAKEYAML",
                "title": "SnakeYAML 反序列化漏洞",
                "summary": "SnakeYAML unsafe deserialization",
                "components": [{"ecosystem": "Maven", "name": "org.yaml:snakeyaml"}],
                "matched_dependencies": matched_dependency("snakeyaml"),
            },
            {
                "id": "CVE-JACKSON",
                "title": "Jackson 反序列化漏洞",
                "summary": "ObjectMapper unsafe deserialization",
                "components": [{"ecosystem": "Maven", "name": "com.fasterxml.jackson.core:jackson-databind"}],
                "matched_dependencies": matched_dependency("jackson"),
            },
        ]

        with patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = analyze_static_paths(attachments, scan, records)

        findings_by_line = {finding["risk_line"]: finding for finding in result["findings"]}
        self.assertEqual(set(findings_by_line), {24, 30, 40})
        self.assertEqual(findings_by_line[24]["source"]["line"], 21)
        self.assertIn("safeLogValue", findings_by_line[24]["fixed_snippet"])
        self.assertEqual(findings_by_line[30]["source"]["line"], 27)
        self.assertIn("safeYaml.load(yamlText)", findings_by_line[30]["fixed_snippet"])
        self.assertEqual(findings_by_line[40]["source"]["line"], 37)
        self.assertIn("java.util.Map.class", findings_by_line[40]["fixed_snippet"])


class ReportStoreTests(unittest.TestCase):
    def test_report_store_writes_markdown_and_lists_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}):
            store = ReportStore(Path(temp_dir))
            saved = store.save_markdown(
                "依赖漏洞与代码漏洞分析报告",
                "# Demo\n\nsource → sink",
                mode="dependency_vulnerability_report",
                vulnerability_count=1,
                finding_count=1,
            )
            self.assertTrue((Path(temp_dir) / saved["file_name"]).exists())
            self.assertEqual(store.list_reports()[0]["id"], saved["id"])
            detail = store.get_report(saved["id"])
            self.assertIn("source", detail["content"])

    def test_report_localizes_dependency_and_code_finding_severity_labels(self) -> None:
        records = [
            {
                "id": "CVE-2026-10001",
                "title": "Demo dependency vulnerability",
                "severity": "HIGH",
                "summary_zh": "Dependency issue summary",
            }
        ]
        static_analysis = {
            "finding_count": 1,
            "findings": [
                {
                    "id": "finding-1",
                    "title": "Command injection",
                    "severity": "CRITICAL",
                    "file": "demo.py",
                    "risk_line": 7,
                    "vulnerable_snippet": "os.system(command)",
                    "remediation": "Use a safe process API.",
                }
            ],
        }
        arguments = {
            "question": "Scan demo",
            "dependency_scan": {"files": [{"file_name": "demo.py", "kind": "code"}], "dependencies": []},
            "records": records,
            "static_analysis": static_analysis,
            "summary": "Scan completed.",
        }

        chinese = build_dependency_markdown_report(**arguments, language="zh-Hans")
        english = build_dependency_markdown_report(**arguments, language="en")

        self.assertIn("- 严重等级：高危", chinese)
        self.assertIn("- 严重等级：严重", chinese)
        self.assertNotIn("严重等级：HIGH", chinese)
        self.assertNotIn("严重等级：CRITICAL", chinese)
        self.assertIn("- Severity: High", english)
        self.assertIn("- Severity: Critical", english)
        self.assertNotIn("- Severity: HIGH", english)
        self.assertNotIn("- Severity: CRITICAL", english)

    def test_report_store_uses_project_datetime_name_and_exports_three_formats(self) -> None:
        content = build_dependency_markdown_report(
            question="扫描资金项目",
            dependency_scan={
                "files": [
                    {"file_name": "PaymentWalletApplicationAPI/pom.xml", "kind": "pom"},
                    {"file_name": "PaymentWalletApplicationAPI/src/main/java/WalletController.java", "kind": "code"},
                ],
                "dependencies": [],
            },
            records=[],
            static_analysis={"findings": [], "finding_count": 0, "diagnostics": []},
            summary="本次未确认高置信代码风险。",
        )
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}):
            store = ReportStore(Path(temp_dir))
            saved = store.save_markdown(
                "依赖漏洞与代码漏洞分析报告",
                content,
                mode="dependency_vulnerability_report",
                vulnerability_count=0,
                finding_count=0,
                metadata={"files": [{"file_name": "PaymentWalletApplicationAPI/pom.xml", "kind": "pom"}]},
            )

            self.assertRegex(saved["file_name"], r"^PaymentWalletApplicationAPI_\d{8}-\d{6}\.md$")
            self.assertEqual(set(saved["available_formats"]), {"html", "md", "docx", "xlsx", "pdf"})
            md_path, md_name = store.resolve_download(saved["id"])
            html_path, html_name, html_type = store.resolve_download(saved["id"], "html")
            pdf_path, pdf_name, pdf_type = store.resolve_download(saved["id"], "pdf")

            self.assertEqual(md_name, saved["file_name"])
            self.assertTrue(html_name.endswith(".html"))
            self.assertTrue(pdf_name.endswith(".pdf"))
            self.assertEqual(html_type, "text/html; charset=utf-8")
            self.assertEqual(pdf_type, "application/pdf")
            self.assertIn("安全智脑报告", html_path.read_text(encoding="utf-8"))
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))
            self.assertTrue(md_path.read_text(encoding="utf-8").startswith("# "))

    def test_binary_reports_render_mermaid_as_structured_content(self) -> None:
        long_path = "src/main/java/com/example/payment/checkout/OrderController.java:10000"
        markdown = f"""# 项目代码安全扫描报告

## 1. 执行摘要

- 风险位置：`{long_path}`

```mermaid
flowchart LR
  SOURCE["HTTP 请求参数"]
  SINK["OrderController.java:10000"]
  SOURCE -->|污点传播| SINK
```

## 2. 证据代码

```java
 9999 | String command = request.getParameter("command");
10000 | Runtime.getRuntime().exec(commandWithAnIntentionallyLongNameThatMustWrapWithoutBeingClipped);
10001 | audit(command);
```

| 序号 | 生态 | 组件 | 当前版本 | 漏洞编号 | 严重度 | 漏洞描述 | 修复版本 | 情报来源 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Maven | org.example:payment-component-with-a-long-name | 1.0.0 | CVE-2026-10000 | 高危 | 组件存在可被外部输入触发的远程命令执行风险 | 1.0.1 | NVD、GitHub Advisory |
"""
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"},
        ):
            store = ReportStore(Path(temp_dir))
            saved = store.save_markdown(
                "项目代码安全扫描报告",
                markdown,
                mode="code_scan_report",
                vulnerability_count=1,
                finding_count=1,
                metadata={"language": "zh-Hans"},
            )
            md_path, _ = store.resolve_download(saved["id"])
            docx_path, _, _ = store.resolve_download(saved["id"], "docx")
            pdf_path, _, _ = store.resolve_download(saved["id"], "pdf")

            markdown_output = md_path.read_text(encoding="utf-8")
            self.assertIn("```mermaid", markdown_output)
            self.assertIn("flowchart LR", markdown_output)

            with zipfile.ZipFile(docx_path) as archive:
                document_xml = archive.read("word/document.xml")
            root = ElementTree.fromstring(document_xml)
            docx_text = " ".join(root.itertext())
            self.assertNotIn("flowchart LR", docx_text)
            self.assertNotIn("SOURCE -->", docx_text)
            self.assertIn("HTTP 请求参数", docx_text)
            self.assertIn("OrderController.java:10000", docx_text)
            self.assertIn(long_path, docx_text)
            self.assertIn("Runtime.getRuntime().exec", docx_text)

            pdftotext = shutil.which("pdftotext")
            if pdftotext:
                extracted_path = Path(temp_dir) / "report.txt"
                subprocess.run(
                    [pdftotext, "-layout", str(pdf_path), str(extracted_path)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                pdf_text = extracted_path.read_text(encoding="utf-8", errors="replace")
                self.assertNotIn("flowchart LR", pdf_text)
                self.assertNotIn("SOURCE -->", pdf_text)
                self.assertIn("OrderController.java:10000", pdf_text)
                self.assertIn("Runtime.getRuntime().exec", pdf_text)

    def test_identical_upload_fingerprint_reuses_one_downloadable_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}):
            store = ReportStore(Path(temp_dir))
            first = store.save_markdown(
                "完整分析报告",
                "# First",
                mode="dependency_vulnerability_report",
                vulnerability_count=3,
                finding_count=1,
                input_fingerprint="same-upload",
            )
            second = store.save_markdown(
                "完整分析报告",
                "# Duplicate",
                mode="dependency_vulnerability_report",
                vulnerability_count=4,
                finding_count=2,
                input_fingerprint="same-upload",
            )

            self.assertEqual(first["id"], second["id"])
            self.assertEqual(len(store.list_reports()), 1)
            self.assertNotIn("_input_fingerprint", store.list_reports()[0])
            path, file_name = store.resolve_download(first["id"])
            self.assertEqual(path.read_text(encoding="utf-8"), "# Duplicate")
            self.assertEqual(file_name, second["file_name"])

    def test_legacy_report_engine_markers_are_removed_from_detail_and_download(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}):
            store = ReportStore(Path(temp_dir))
            saved = store.save_markdown(
                "历史报告",
                "# Legacy\n\n- 引擎：codeql\n- run_codeql_tool：CodeQL analysis",
                mode="dependency_vulnerability_report",
                vulnerability_count=1,
                finding_count=1,
            )

            store.sanitize_existing_reports()
            detail = store.get_report(saved["id"])
            path, _ = store.resolve_download(saved["id"])
            self.assertNotIn("codeql", detail["content"].lower())
            self.assertNotIn("引擎：", detail["content"])
            self.assertNotIn("codeql", path.read_text(encoding="utf-8").lower())

    def test_report_store_strips_appendix_from_saved_and_downloaded_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}):
            store = ReportStore(Path(temp_dir))
            saved = store.save_markdown(
                "报告",
                "# Demo\n\n## 1. 结论\n\n保留正文。\n\n## 附录\n\n不应保留的调试细节。",
                mode="dependency_vulnerability_report",
                vulnerability_count=0,
                finding_count=0,
            )

            detail = store.get_report(saved["id"])
            path, _ = store.resolve_download(saved["id"])
            self.assertIn("保留正文", detail["content"])
            self.assertNotIn("附录", detail["content"])
            self.assertNotIn("调试细节", path.read_text(encoding="utf-8"))

    def test_downloaded_analysis_report_uses_modern_markdown_style(self) -> None:
        content = build_dependency_markdown_report(
            question="扫描上传目录",
            dependency_scan={
                "files": [
                    {"file_name": "pom.xml", "kind": "pom"},
                    {"file_name": "src/main/java/WalletController.java", "kind": "code"},
                ],
                "dependencies": [],
            },
            records=[],
            static_analysis={"findings": [], "finding_count": 0, "diagnostics": []},
            summary="本次未确认高置信代码风险。",
        )

        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}):
            store = ReportStore(Path(temp_dir))
            saved = store.save_markdown(
                "依赖漏洞与代码漏洞分析报告",
                content,
                mode="dependency_vulnerability_report",
                vulnerability_count=0,
                finding_count=0,
            )

            detail = store.get_report(saved["id"])
            path, _ = store.resolve_download(saved["id"])
            downloaded = path.read_text(encoding="utf-8")

        self.assertEqual(detail["content"], downloaded)
        self.assertIn("<!-- secflow-report-style:v2 -->", downloaded)
        self.assertIn("> 安全智脑根据本次上传与扫描事实自动生成", downloaded)
        self.assertIn("| 扫描项 | 结果 |", downloaded)
        self.assertIn("| 附件数量 | 2 |", downloaded)
        self.assertNotIn("- 附件数量：2", downloaded.split("## 1. 执行摘要", 1)[0])
        self.assertNotIn("附录", downloaded)

    def test_large_scan_scope_is_compact_and_reports_omitted_counts(self) -> None:
        files = [{"file_name": f"src/main/java/Demo{index}.java", "kind": "code"} for index in range(25)]
        dependencies = [
            {
                "ecosystem": "Maven",
                "name": f"org.example:library-{index}",
                "version": "1.0.0",
                "source_file": "pom.xml",
                "confidence": "high",
            }
            for index in range(35)
        ]

        content = build_dependency_markdown_report(
            question="扫描大项目",
            dependency_scan={"files": files, "dependencies": dependencies},
            records=[],
            static_analysis={"findings": [], "finding_count": 0},
            summary="未确认高置信风险。",
        )

        self.assertIn("### 文件构成", content)
        self.assertIn("### 文件样例 (8/25)", content)
        self.assertIn("其余 17 个文件不在正文逐项展开", content)
        self.assertIn("### 识别到的依赖 (10/35)", content)
        self.assertIn("其余 25 个依赖不在正文逐项展开", content)
        self.assertNotIn("Demo24.java", content)
        self.assertNotIn("library-34", content)

    def test_indented_source_sink_fence_renders_as_code_in_html(self) -> None:
        rendered = _markdown_fragment_to_html(
            "完整 Source→Sink 路径：\n- sink: Demo.java:7\n  ```java\n  riskyCall(value);\n  ```"
        )

        self.assertIn("<pre", rendered)
        self.assertIn("riskyCall(value);", rendered)
        self.assertNotIn("<p>```</p>", rendered)

    def test_numbered_code_block_separates_line_numbers_and_wrap_safe_source(self) -> None:
        long_source = "invoke(" + ("x" * 420) + ");"
        rendered = _markdown_fragment_to_html(
            "证据代码片段（第 9999-10001 行，风险点为第 10000 行）：\n"
            "```java\n"
            " 9999 | prepare();\n"
            f"10000 | {long_source}\n"
            "10001 | commit();\n"
            "```"
        )

        self.assertIn('class="numbered-code"', rendered)
        self.assertIn('class="code-row risk"', rendered)
        self.assertIn('<span class="code-line-number" aria-hidden="true">10000</span>', rendered)
        self.assertIn(f'<span class="code-source">{long_source}</span>', rendered)
        self.assertNotIn("10000 |", rendered)

    def test_pdf_path_keeps_file_name_and_line_together(self) -> None:
        rendered = _pdf_inline_markdown("src/main/java/Demo.java:42")

        self.assertEqual(rendered, "src/main/java/Demo.java:42")
        self.assertNotIn("<br/>", rendered)
        self.assertNotIn("&nbsp;", rendered)

    def test_html_report_uses_native_secflow_font_cascade(self) -> None:
        rendered = _build_html_report("# Demo", {"language": "zh-Hans"})

        self.assertIn(
            'font: 14px/1.68 "SF Pro Text", "PingFang SC", "Apple Color Emoji",',
            rendered,
        )
        self.assertLess(rendered.index('"SF Pro Text"'), rendered.index('"PingFang SC"'))
        self.assertLess(rendered.index('"PingFang SC"'), rendered.index('"Apple Color Emoji"'))

    def test_pdf_latin_runs_can_use_native_report_font(self) -> None:
        rendered = _pdf_inline_markdown("安全 SecFlow 2026", "SecFlowLatin")

        self.assertIn('安全<font name="SecFlowLatin"> SecFlow 2026</font>', rendered)

    def test_report_generation_time_uses_china_standard_time(self) -> None:
        self.assertEqual(
            _report_china_time("2026-07-28T06:13:21+00:00"),
            "2026-07-28 14:13",
        )
        self.assertEqual(_report_china_time("2026-07-28 14:13:21 UTC+08:00"), "2026-07-28 14:13")

    def test_agent_execution_events_use_china_time_without_iso_timestamps(self) -> None:
        report = build_agent_task_markdown_report(
            {
                "workspace_name": "demo",
                "workspace_path": "/tmp/demo",
                "workspace_type": "directory",
                "objective": "scan project",
                "events": [
                    {
                        "sequence": 1,
                        "time": "2026-07-30T01:33:17+00:00",
                        "node": "scan_python",
                        "status": "completed",
                        "message": "扫描完成。",
                    }
                ],
                "result": {"languages": [], "language_results": {}},
            },
            mcp_audit={"status": "completed", "fact_count": 1, "invoked_at": "2026-07-30T01:32:45+00:00"},
        )

        self.assertIn("调用时间 2026-07-30 09:32", report)
        self.assertIn("| 1 | 2026-07-30 09:33 | scan_python | completed | 扫描完成。 |", report)
        self.assertNotIn("2026-07-30T01:33:17+00:00", report)
        self.assertNotIn("2026-07-30T01:32:45+00:00", report)

    def test_code_report_removes_file_rule_section_and_visible_scan_mode(self) -> None:
        report = build_agent_task_markdown_report(
            {
                "workspace_name": "demo",
                "workspace_path": "/tmp/demo",
                "workspace_type": "directory",
                "objective": "scan project",
                "events": [],
                "result": {
                    "languages": ["python"],
                    "total_files": 1,
                    "scan_mode": "adaptive_upload",
                    "language_results": {
                        "python": {
                            "file_count": 1,
                            "files": ["app.py"],
                            "rule_files": ["python-security.yml"],
                            "syntax_summary": {},
                            "findings": [],
                        }
                    },
                },
            }
        )

        self.assertNotIn("扫描文件与规则", report)
        self.assertNotIn("扫描模式", report)
        self.assertIn("## 7. 项目自适应与回归审计", report)
        self.assertIn("## 9. 方法与限制", report)

    def test_legacy_report_cleanup_renumbers_sections_and_localizes_time(self) -> None:
        legacy = """# demo 代码安全漏洞扫描报告

- 生成时间：2026-07-28T06:13:21+00:00

## 1. 执行摘要

摘要

## 2. 扫描文件与规则

- 规则文件：`python-security.yml`
- 扫描文件：`app.py`

## 3. 项目自适应与回归审计

- 扫描模式：`adaptive_upload`
- 自适应状态：`completed`
"""

        cleaned = _sanitize_report_content(legacy)

        self.assertIn("2026-07-28 14:13", cleaned)
        self.assertNotIn("扫描文件与规则", cleaned)
        self.assertNotIn("python-security.yml", cleaned)
        self.assertNotIn("扫描模式", cleaned)
        self.assertIn("## 2. 项目自适应与回归审计", cleaned)

    def test_chinese_severity_chart_shows_percentages_without_format_or_mode(self) -> None:
        metadata = {
            "language": "zh-Hans",
            "mode": "agent_static_scan",
            "created_at": "2026-07-28T06:13:21+00:00",
            "report_metrics": {
                "language": "zh-Hans",
                "generated_at": "2026-07-28T06:13:21+00:00",
                "code_findings": 4,
                "total_risks": 4,
                "severity": {"HIGH": 1, "MEDIUM": 3},
            },
        }

        rendered = _build_html_report("# demo 代码安全漏洞扫描报告\n\n## 1. 摘要\n\n完成。", metadata)

        self.assertIn("生成时间: 2026-07-28 14:13", rendered)
        self.assertIn("<b>高危</b><span>1 · 25.0%</span>", rendered)
        self.assertIn("<b>中危</b><span>3 · 75.0%</span>", rendered)
        self.assertNotIn("HTML / PDF / Markdown", rendered)
        self.assertNotIn("agent_static_scan", rendered)

    def test_structured_metrics_drive_english_report_charts(self) -> None:
        record = {
            "id": "CVE-2026-1000",
            "title": "Example issue",
            "severity": "HIGH",
            "summary_zh": "Example issue",
            "components": [],
            "fixed_versions": [],
        }
        dependency_scan = {
            "files": [{"file_name": "pom.xml", "kind": "pom"}],
            "dependencies": [
                {
                    "ecosystem": "Maven",
                    "name": "org.example:demo",
                    "version": "1.0.0",
                    "source_file": "pom.xml",
                }
            ],
        }
        static_analysis = {"findings": [], "finding_count": 0}
        metrics = build_report_metrics(
            dependency_scan=dependency_scan,
            records=[record],
            static_analysis=static_analysis,
            language="en",
        )
        markdown = _sanitize_report_content(
            build_dependency_markdown_report(
                question="Audit dependencies",
                dependency_scan=dependency_scan,
                records=[record],
                static_analysis=static_analysis,
                summary="One issue was confirmed.",
                language="en",
            )
        )
        metadata = {"language": "en", "report_metrics": metrics, "vulnerability_count": 1, "finding_count": 0}

        parsed = _parse_report_document(markdown, metadata)
        rendered = _build_html_report(markdown, metadata)

        self.assertEqual(parsed["metrics"]["attachments"], 1)
        self.assertEqual(parsed["metrics"]["high_risk"], 1)
        self.assertIn("Generated from the facts available", markdown)
        self.assertIn("| Item | Result |", markdown)
        self.assertIn("Critical / high", rendered)
        self.assertIn('lang="en"', rendered)

    def test_dependency_only_conclusion_omits_code_remediation(self) -> None:
        conclusion = build_report_conclusion(
            0,
            0,
            language="zh-Hans",
            has_dependency_scope=True,
            has_code_scope=False,
        )

        self.assertIn("0 条依赖漏洞", conclusion)
        self.assertNotIn("代码漏洞", conclusion)
        self.assertNotIn("行号", conclusion)

    def test_multiple_reports_can_be_deleted_in_one_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}):
            store = ReportStore(Path(temp_dir))
            first = store.save_markdown("报告一", "# One", mode="test", vulnerability_count=1, finding_count=0)
            second = store.save_markdown("报告二", "# Two", mode="test", vulnerability_count=2, finding_count=1)
            first_path, _ = store.resolve_download(first["id"])
            second_path, _ = store.resolve_download(second["id"])

            result = store.delete_reports([first["id"], second["id"], first["id"], "missing-report"])

            self.assertEqual(result["requested"], 3)
            self.assertEqual(result["deleted"], 2)
            self.assertEqual(set(result["deleted_ids"]), {first["id"], second["id"]})
            self.assertEqual(result["missing_ids"], ["missing-report"])
            self.assertEqual(store.list_reports(), [])
            self.assertFalse(first_path.exists())
            self.assertFalse(second_path.exists())

    def test_unavailable_pdf_is_not_advertised_as_a_complete_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}
        ), patch("app.reports._write_pdf_report", side_effect=RuntimeError("PDF backend unavailable")):
            store = ReportStore(Path(temp_dir))
            saved = store.save_markdown(
                "报告",
                "# Demo\n\n正文",
                mode="test",
                vulnerability_count=0,
                finding_count=0,
            )

            self.assertEqual(set(saved["available_formats"]), {"html", "md", "docx", "xlsx"})
            with self.assertRaises(ValueError):
                store.resolve_download(saved["id"], "pdf")

    def test_dependency_report_uses_chinese_fact_description_without_raw_poc_section(self) -> None:
        content = build_dependency_markdown_report(
            question="分析附件",
            dependency_scan={"files": [], "dependencies": []},
            records=[
                {
                    "id": "CVE-2026-9292",
                    "title": "Example issue",
                    "severity": "HIGH",
                    "summary": "## Proof of Concept\nexploit payload and attack steps",
                    "summary_zh": "CVE-2026-9292 是一个高危漏洞，建议核查受影响组件并升级到已确认的安全版本。",
                    "components": [],
                    "fixed_versions": [],
                    "reference_links": [],
                }
            ],
            static_analysis={"findings": [], "diagnostics": []},
            summary="已完成分析。",
        )

        self.assertIn("CVE-2026-9292 是一个高危漏洞", content)
        self.assertNotIn("Proof of Concept", content)
        self.assertNotIn("exploit payload", content)
        self.assertNotIn("CodeQL", content)
        self.assertNotIn("引擎：", content)

    def test_dependency_report_does_not_treat_unknown_versions_as_safe(self) -> None:
        content = build_dependency_markdown_report(
            question="分析附件",
            dependency_scan={
                "files": [{"file_name": "pom.xml", "kind": "pom"}],
                "dependencies": [
                    {
                        "ecosystem": "Maven",
                        "name": "org.example:unknown-version",
                        "version": None,
                        "source_file": "pom.xml",
                        "confidence": "medium",
                    }
                ],
            },
            records=[],
            static_analysis={"findings": [], "diagnostics": []},
            summary="已完成分析。",
        )

        self.assertIn("1 个依赖版本未明确", content)
        self.assertIn("不能据此判定为安全", content)

    def test_code_only_report_omits_dependency_vulnerability_section(self) -> None:
        content = build_dependency_markdown_report(
            question="扫描资金接口代码",
            dependency_scan={"files": [{"file_name": "WalletController.java", "kind": "code"}], "dependencies": []},
            records=[],
            static_analysis={
                "findings": [
                    {
                        "title": "资金接口缺少幂等键",
                        "file": "WalletController.java",
                        "risk_line": 12,
                        "line_start": 10,
                        "line_end": 12,
                        "vulnerable_snippet": "walletService.pay(request);",
                        "fixed_snippet": "String key = request.getHeader(\"Idempotency-Key\");",
                        "path": [],
                    }
                ],
                "diagnostics": [],
            },
            summary="本次仅确认代码风险。",
        )

        self.assertNotIn("依赖漏洞（组件与版本）", content)
        self.assertNotIn("- 识别依赖：0 个", content)
        self.assertIn("代码漏洞（文件、行号与修复代码）", content)
        self.assertIn("WalletController.java:12", content)
        self.assertNotIn("附录", content)

    def test_uploaded_code_without_findings_uses_actual_empty_state(self) -> None:
        content = build_dependency_markdown_report(
            question="扫描资金接口代码",
            dependency_scan={
                "files": [
                    {"file_name": "pom.xml", "kind": "pom"},
                    {"file_name": "src/main/java/WalletController.java", "kind": "code"},
                ],
                "dependencies": [],
            },
            records=[],
            static_analysis={"findings": [], "finding_count": 0, "diagnostics": []},
            summary="本次未确认代码风险。",
        )

        self.assertIn("代码漏洞（文件、行号与修复代码）", content)
        self.assertIn("已对上传源码执行静态路径分析，未确认高置信代码漏洞位置。", content)
        self.assertNotIn("若仅上传构建依赖文件", content)

    def test_dependency_only_report_omits_code_section_even_with_static_diagnostic(self) -> None:
        content = build_dependency_markdown_report(
            question="扫描依赖",
            dependency_scan={
                "files": [{"file_name": "pom.xml", "kind": "pom"}],
                "dependencies": [
                    {
                        "ecosystem": "Maven",
                        "name": "org.example:demo-lib",
                        "version": "1.0.0",
                        "source_file": "pom.xml",
                        "confidence": "high",
                    }
                ],
            },
            records=[],
            static_analysis={
                "findings": [],
                "finding_count": 0,
                "diagnostics": ["未上传代码文件，静态 source/sink 分析已跳过，仅生成依赖情报报告。"],
            },
            summary="本次仅扫描依赖。",
        )

        self.assertIn("依赖漏洞（组件与版本）", content)
        self.assertNotIn("代码漏洞（文件、行号与修复代码）", content)

    def test_report_separates_dependency_and_source_code_vulnerabilities(self) -> None:
        content = build_dependency_markdown_report(
            question="分析附件",
            dependency_scan={
                "files": [
                    {"file_name": "pom.xml", "kind": "pom"},
                    {"file_name": "src/main/java/Demo.java", "kind": "code"},
                ],
                "dependencies": [
                    {
                        "ecosystem": "Maven",
                        "name": "org.example:demo-lib",
                        "version": "1.0.0",
                        "source_file": "pom.xml",
                        "confidence": "high",
                    }
                ],
            },
            records=[
                {
                    "id": "CVE-2026-1000",
                    "title": "依赖组件漏洞",
                    "severity": "HIGH",
                    "summary_zh": "依赖组件存在已确认漏洞。",
                    "components": [
                        {
                            "ecosystem": "Maven",
                            "name": "org.example:demo-lib",
                            "affected": ["< 1.0.1"],
                            "fixed": ["1.0.1"],
                        }
                    ],
                    "fixed_versions": ["1.0.1"],
                    "code_snippets": ["advisoryExample();"],
                }
            ],
            static_analysis={
                "findings": [
                    {
                        "title": "不可信输入到危险调用",
                        "record_id": "CVE-2026-1000",
                        "component": "Maven/org.example:demo-lib 1.0.0",
                        "file": "src/main/java/Demo.java",
                        "risk_line": 42,
                        "line_start": 40,
                        "line_end": 44,
                        "vulnerable_snippet": "String value = request.getParameter(\"value\");\nriskyCall(value);",
                        "fixed_snippet": "String value = validate(request.getParameter(\"value\"));\nsafeCall(value);",
                        "remediation": "校验输入并使用安全调用。",
                        "source": {"file": "src/main/java/Demo.java", "line": 40},
                        "sink": {"file": "src/main/java/Demo.java", "line": 42},
                        "path": [],
                    }
                ],
                "diagnostics": [],
            },
            summary="分析完成。",
        )

        dependency_section, code_section = content.split("## 4. 代码漏洞（文件、行号与修复代码）", 1)
        self.assertIn("## 3. 依赖漏洞（组件与版本）", dependency_section)
        self.assertNotIn("advisoryExample();", dependency_section)
        self.assertIn("风险位置：src/main/java/Demo.java:42", code_section)
        self.assertIn("风险点为第 42 行", code_section)
        self.assertIn("```java", code_section)
        self.assertIn("riskyCall(value);", code_section)
        self.assertIn("修复后的代码", code_section)
        self.assertIn("safeCall(value);", code_section)

    def test_dependency_report_renders_aggregated_finance_sinks(self) -> None:
        content = build_dependency_markdown_report(
            question="分析附件",
            dependency_scan={"files": [{"file_name": "WalletService.java", "kind": "code"}], "dependencies": []},
            records=[],
            static_analysis={
                "findings": [
                    {
                        "title": "资金操作缺少事务边界：fundTransfer() 中 3 个更新点",
                        "file": "WalletService.java",
                        "risk_line": 10,
                        "line_start": 8,
                        "line_end": 14,
                        "confidence": "medium",
                        "vulnerable_snippet": "wallet.setBalance(...);\ntransactionDao.save(transaction);",
                        "fixed_snippet": "@Transactional\npublic Transaction fundTransfer(...) { ... }",
                        "remediation": "把扣款、入账、流水写入放入同一事务边界。",
                        "aggregated_sinks": [
                            {"file": "WalletService.java", "line": 10, "snippet": "wallet.setBalance(...);"},
                            {"file": "WalletService.java", "line": 12, "snippet": "transactionDao.save(transaction);"},
                        ],
                        "path": [],
                    }
                ],
                "diagnostics": [],
            },
            summary="分析完成。",
        )

        self.assertIn("合并的资金更新点", content)
        self.assertIn("WalletService.java:10", content)
        self.assertIn("transactionDao.save(transaction);", content)

    def test_dependency_report_renders_related_request_chain_findings(self) -> None:
        content = build_dependency_markdown_report(
            question="分析附件",
            dependency_scan={"files": [{"file_name": "WalletController.java", "kind": "code"}], "dependencies": []},
            records=[],
            static_analysis={
                "findings": [
                    {
                        "title": "资金请求链路风险：fundTransfer() 缺少幂等与事务边界",
                        "file": "WalletController.java",
                        "risk_line": 12,
                        "line_start": 10,
                        "line_end": 12,
                        "confidence": "medium",
                        "vulnerable_snippet": "walletService.fundTransfer(...);",
                        "fixed_snippet": "String idempotencyKey = request.getHeader(\"Idempotency-Key\");",
                        "remediation": "增加幂等键和事务边界。",
                        "related_findings": [
                            {"title": "资金接口缺少幂等键", "file": "WalletController.java", "line": 12},
                            {
                                "title": "资金操作缺少事务边界：fundTransfer() 中 2 个更新点",
                                "file": "WalletService.java",
                                "line": 30,
                                "aggregation": {"merged_finding_count": 2},
                            },
                        ],
                        "path": [],
                    }
                ],
                "diagnostics": [],
            },
            summary="分析完成。",
        )

        self.assertIn("关联子风险", content)
        self.assertIn("资金接口缺少幂等键", content)
        self.assertIn("WalletService.java:30", content)


class DependencyReportGraphTests(unittest.TestCase):
    def test_dependency_question_generates_markdown_report_summary(self) -> None:
        record = {
            "id": "CVE-2021-44228",
            "title": "Log4j remote code execution",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "summary": "Apache Log4j vulnerable lookup handling.",
            "affected_versions": ["Maven / org.apache.logging.log4j:log4j-core: >= 2.0.0, < 2.15.0"],
            "fixed_versions": ["Maven / org.apache.logging.log4j:log4j-core: 2.15.0"],
            "code_snippets": ["logger.info(msg);"],
            "fixed_code_snippets": ["// upgrade log4j-core to 2.15.0 or later"],
            "reference_links": ["https://example.test/CVE-2021-44228"],
            "components": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "affected": [">= 2.0.0, < 2.15.0"],
                    "fixed": ["2.15.0"],
                }
            ],
            "matched_dependencies": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "version": "2.14.1",
                    "source_file": "pom.xml",
                    "source_type": "pom",
                    "declaration": "org.apache.logging.log4j:log4j-core:2.14.1",
                    "confidence": "high",
                }
            ],
            "updated_at": "2026-07-16T00:00:00+00:00",
        }
        pom = """
        <project>
          <dependencies>
            <dependency>
              <groupId>org.apache.logging.log4j</groupId>
              <artifactId>log4j-core</artifactId>
              <version>2.14.1</version>
            </dependency>
          </dependencies>
        </project>
        """
        java = """
        import javax.servlet.http.HttpServletRequest;
        import org.apache.logging.log4j.LogManager;
        import org.apache.logging.log4j.Logger;
        class DemoController {
          private static final Logger logger = LogManager.getLogger(DemoController.class);
          void handle(HttpServletRequest request) {
            String msg = request.getParameter("msg");
            logger.info(msg);
          }
        }
        """
        graph = KnowledgeSecurityGraph()
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch.dict(os.environ, {"SECFLOW_SEMGREP_DISABLE_CLI": "1", "SECFLOW_STORAGE_MASTER_KEY": "unit-test-report-key"}),
            patch("app.graph.report_store", ReportStore(Path(temp_dir))),
            patch("app.graph.active_model_from_env", return_value=None),
            patch("app.graph.memory_service.build_context", return_value={"enabled": True, "stats": {}, "injectedMessages": []}),
            patch("app.graph.memory_service.add_exchange"),
            patch(
                "app.graph.intelligence_service.query_dependencies",
                return_value={
                    "records": [record],
                    "graph": empty_knowledge_graph("dependency-scan"),
                    "trace": [],
                },
            ),
        ):
            result = graph.invoke(
                "请根据附件生成完整分析报告",
                top_k=5,
                attachments=[
                    {"file_name": "pom.xml", "content": pom},
                    {"file_name": "src/main/java/DemoController.java", "content": java},
                ],
            )

        self.assertEqual(result["mode"], "dependency_vulnerability_report")
        self.assertIn("依赖漏洞明细", result["summary"])
        self.assertIn("代码漏洞明细", result["summary"])
        self.assertIn("src/main/java/DemoController.java:9", result["summary"])
        self.assertIn("风险代码", result["summary"])
        self.assertIn("修复后代码", result["summary"])
        self.assertNotIn("CodeQL", result["summary"])
        self.assertIn("source", result["summary"].lower())
        self.assertEqual(result["interrupt"]["kind"], "report_generation_confirmation")
        generated = report_capability_subgraph.resume(
            result["interrupt"]["thread_id"],
            decision="confirm",
            user_id="default",
            session_id="default",
        )
        self.assertEqual(generated["interrupt"]["kind"], "report_download_confirmation")
        self.assertEqual(generated["report"]["title"], "依赖漏洞与代码漏洞分析报告")
        nodes = [item["node"] for item in generated["trace"]]
        self.assertIn("report.markdown_mcp", nodes)
        self.assertIn("report.word_mcp", nodes)
        self.assertIn("report.pdf_mcp", nodes)
        self.assertIn("report.persist", nodes)
        self.assertIn("report_capability_subgraph", [item["node"] for item in result["trace"]])
        self.assertIn("run_static_path_analysis", [item["node"] for item in result["trace"]])


if __name__ == "__main__":
    unittest.main()
