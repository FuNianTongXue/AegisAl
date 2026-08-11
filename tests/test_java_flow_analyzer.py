from __future__ import annotations

import unittest
from unittest.mock import patch

from app.java_flow_analyzer import JavaFlowAnalyzer, analyze_java_interprocedural


def analyze(source: str) -> dict[str, object]:
    return analyze_java_interprocedural([{"file_name": "src/main/java/Demo.java", "content": source}])


def native_finance_findings(source: str) -> list[dict[str, object]]:
    result = analyze(source)
    return [
        finding
        for finding in result["findings"]
        if finding.get("engine") == "java-native-finance"
    ]


class JavaFlowAnalyzerTests(unittest.TestCase):
    def test_native_finance_findings_survive_generic_flow_timeout(self) -> None:
        source = """
        @RestController class PaymentController {
          PaymentRepository repository;
          @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
            return repository.debit(request.getOrderNo(), request.getAmount());
          }
        }
        """
        analyzer = JavaFlowAnalyzer([{"file_name": "Demo.java", "content": source}])
        with patch.object(analyzer, "_timed_out", side_effect=[False, False, True]):
            result = analyzer.analyze()

        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["engine"], "java-native-finance")

    def test_native_finance_missing_idempotency_is_interprocedural(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              PaymentService service;
              @PostMapping Object pay(@RequestBody PayRequest request) {
                return service.pay(request.getOrderNo(), request.getAmount());
              }
            }
            class PaymentService {
              PaymentRepository repository;
              @Transactional Object pay(String orderNo, BigDecimal amount) {
                return repository.debit(orderNo, amount);
              }
            }
            """
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["scenario"], "idempotency_missing")
        self.assertEqual(findings[0]["semantic_proof"]["risk_kind"], "missing_guard")
        self.assertTrue(findings[0]["semantic_proof"]["interprocedural"])

    def test_native_finance_database_unique_claim_in_transaction_is_safe(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              PaymentService service;
              @PostMapping Object pay(@RequestBody PayRequest request) {
                return service.pay(request.getRequestNo(), request.getAmount());
              }
            }
            class PaymentService {
              IdempotencyRepository idempotencyRepository;
              PaymentRepository repository;
              @Transactional Object pay(String requestNo, BigDecimal amount) {
                idempotencyRepository.insertUnique(requestNo);
                return repository.debit(requestNo, amount);
              }
            }
            """
        )

        self.assertEqual(findings, [])

    def test_native_finance_check_then_act_is_not_accepted_as_idempotent(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              PaymentService service;
              @PostMapping Object pay(@RequestBody PayRequest request) {
                return service.pay(request.getRequestNo(), request.getAmount());
              }
            }
            class PaymentService {
              IdempotencyRepository idempotencyRepository;
              PaymentRepository repository;
              @Transactional Object pay(String requestNo, BigDecimal amount) {
                if (idempotencyRepository.existsByRequestNo(requestNo)) {
                  return idempotencyRepository.findByRequestNo(requestNo);
                }
                return repository.debit(requestNo, amount);
              }
            }
            """
        )

        kinds = {finding["semantic_proof"]["risk_kind"] for finding in findings}
        self.assertIn("check_then_act", kinds)

    def test_native_finance_guard_after_effect_is_reported(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              PaymentService service;
              @PostMapping Object pay(@RequestBody PayRequest request) {
                return service.pay(request.getRequestNo(), request.getAmount());
              }
            }
            class PaymentService {
              IdempotencyRepository idempotencyRepository;
              PaymentRepository repository;
              @Transactional Object pay(String requestNo, BigDecimal amount) {
                Object result = repository.debit(requestNo, amount);
                idempotencyRepository.insertUnique(requestNo);
                return result;
              }
            }
            """
        )

        kinds = {finding["semantic_proof"]["risk_kind"] for finding in findings}
        self.assertIn("guard_after_effect", kinds)

    def test_native_finance_conditional_claim_does_not_dominate_effect(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              PaymentRepository repository;
              IdempotencyRepository idempotencyRepository;
              @PostMapping @Transactional Object pay(@RequestBody PayRequest request, boolean shouldClaim) {
                if (shouldClaim) {
                  idempotencyRepository.insertUnique(request.getRequestNo());
                }
                return repository.debit(request.getRequestNo(), request.getAmount());
              }
            }
            """
        )

        kinds = {finding["semantic_proof"]["risk_kind"] for finding in findings}
        self.assertIn("missing_guard", kinds)

    def test_native_finance_lock_only_is_not_durable_idempotency(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              LockService lockService;
              PaymentRepository repository;
              @PostMapping @Transactional Object pay(@RequestBody PayRequest request) {
                lockService.tryLock(request.getRequestNo());
                return repository.debit(request.getRequestNo(), request.getAmount());
              }
            }
            """
        )

        kinds = {finding["semantic_proof"]["risk_kind"] for finding in findings}
        self.assertIn("non_durable_guard", kinds)

    def test_native_finance_redis_claim_with_result_persistence_is_safe(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              IdempotencyRedis idempotencyRedis;
              PaymentRepository repository;
              @PostMapping @Transactional Object pay(@RequestBody PayRequest request) {
                if (!idempotencyRedis.setIfAbsent(request.getRequestNo())) {
                  return idempotencyRedis.previousResult(request.getRequestNo());
                }
                Object result = repository.debit(request.getRequestNo(), request.getAmount());
                idempotencyRedis.complete(request.getRequestNo(), result);
                return result;
              }
            }
            """
        )

        self.assertEqual(findings, [])

    def test_native_finance_resolves_service_interface_implementation(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class PaymentController {
              PaymentService service;
              @PostMapping Object pay(@RequestBody PayRequest request) {
                return service.pay(request.getRequestNo(), request.getAmount());
              }
            }
            class PaymentServiceImpl {
              IdempotencyRepository idempotencyRepository;
              PaymentRepository repository;
              @Transactional Object pay(String requestNo, BigDecimal amount) {
                idempotencyRepository.insertUnique(requestNo);
                return repository.debit(requestNo, amount);
              }
            }
            """
        )

        self.assertEqual(findings, [])

    def test_native_finance_state_read_then_write_reports_race(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class RefundController {
              RefundService service;
              @PostMapping Object refund(@RequestBody RefundRequest request) {
                return service.refund(request.getRequestNo(), request.getPaymentId());
              }
            }
            class RefundService {
              IdempotencyRepository idempotencyRepository;
              PaymentRepository repository;
              @Transactional Object refund(String requestNo, String paymentId) {
                idempotencyRepository.insertUnique(requestNo);
                Payment payment = repository.findById(paymentId);
                if (!payment.getStatus().equals("PAID")) return payment;
                return repository.refund(paymentId);
              }
            }
            """
        )

        scenarios = {finding["scenario"] for finding in findings}
        self.assertIn("funds_state_transition_race", scenarios)

    def test_native_finance_non_funds_profile_update_is_ignored(self) -> None:
        findings = native_finance_findings(
            """
            @RestController class ProfileController {
              UserRepository repository;
              @PutMapping Object updateProfile(@RequestBody UserProfile profile) {
                return repository.save(profile);
              }
            }
            """
        )

        self.assertEqual(findings, [])

    def test_additional_framework_sources_and_sinks_are_classified(self) -> None:
        result = analyze(
            """
            import java.util.Map;
            import javax.servlet.http.HttpServletRequest;
            import javax.servlet.http.HttpServletResponse;
            import org.springframework.jdbc.core.JdbcTemplate;
            class Controller {
              JdbcTemplate jdbc;
              void command(HttpServletRequest request) {
                ProcessBuilder builder = new ProcessBuilder();
                builder.command(request.getHeader("command"));
              }
              void query(HttpServletRequest request) {
                Map<String, String[]> values = request.getParameterMap();
                jdbc.queryForObject(values.get("query")[0], String.class);
              }
              void render(HttpServletRequest request, HttpServletResponse response) {
                response.getWriter().printf(request.getParameter("value"));
              }
              void remember(HttpServletRequest request) {
                request.getSession().putValue("user", request.getParameter("value"));
              }
            }
            """
        )

        scenarios = {finding["scenario"] for finding in result["findings"]}
        self.assertEqual(
            scenarios,
            {"command_execution", "sql_injection", "cross_site_scripting", "trust_boundary"},
        )

    def test_non_sql_update_method_is_not_classified_as_sql_sink(self) -> None:
        result = analyze(
            """
            import java.security.MessageDigest;
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              MessageDigest digest;
              void hash(HttpServletRequest request) {
                digest.update(request.getParameter("value").getBytes());
              }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)

    def test_parameterized_jdbc_values_are_not_treated_as_sql_structure(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            import org.springframework.jdbc.core.JdbcTemplate;
            class Controller {
              JdbcTemplate jdbc;
              void safeLookup(HttpServletRequest request) {
                jdbc.queryForObject("select name from users where id = ?", String.class, request.getParameter("id"));
                jdbc.update("update users set name = ? where id = ?", request.getParameter("name"), 7);
              }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)

    def test_external_input_reaches_sink_across_methods_and_classes(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              CommandService service;
              void handle(HttpServletRequest request) {
                service.forward(request.getParameter("value"));
              }
            }
            class CommandService {
              void forward(String value) { execute(value); }
              void execute(String value) { Runtime.getRuntime().exec(value); }
            }
            """
        )

        self.assertEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["scenario"], "command_execution")
        self.assertEqual(finding["confidence"], "high")
        self.assertEqual(finding["source"]["line"], 6)
        self.assertEqual(finding["sink"]["line"], 11)
        self.assertEqual(finding["analysis_depth"], 2)
        self.assertGreaterEqual(result["call_edge_count"], 2)

    def test_scenario_sanitizer_stops_propagation(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              void handle(HttpServletRequest request) {
                execute(Integer.parseInt(request.getParameter("value")));
              }
              void execute(int value) {
                Runtime.getRuntime().exec(String.valueOf(value));
              }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)

    def test_ambiguous_project_call_is_not_resolved(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              void handle(HttpServletRequest request) { forward(request.getParameter("value")); }
            }
            class FirstService {
              void forward(String value) { Runtime.getRuntime().exec(value); }
            }
            class SecondService {
              void forward(String value) { Runtime.getRuntime().exec(value); }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["call_edge_count"], 0)

    def test_unknown_receiver_is_not_linked_by_method_name_only(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              ExternalClient client;
              void handle(HttpServletRequest request) {
                client.forward(request.getParameter("value"));
              }
            }
            class UnrelatedService {
              void forward(String value) { Runtime.getRuntime().exec(value); }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["call_edge_count"], 0)

    def test_explicit_object_creation_resolves_project_method(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              void handle(HttpServletRequest request) {
                new CommandService().forward(request.getParameter("value"));
              }
            }
            class CommandService {
              void forward(String value) { Runtime.getRuntime().exec(value); }
            }
            """
        )

        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["confidence"], "high")

    def test_enhanced_for_propagates_collection_element_flow(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              void handle(HttpServletRequest request) {
                String[] values = request.getParameterValues("value");
                for (String value : values) {
                  execute(value);
                }
              }
              void execute(String value) { Runtime.getRuntime().exec(value); }
            }
            """
        )

        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["scenario"], "command_execution")
        self.assertIn("cfg_condition", [step["kind"] for step in result["findings"][0]["path"]])

    def test_constant_safe_branch_overwrites_tainted_value(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              void handle(HttpServletRequest request) {
                String input = request.getParameter("value");
                String selected;
                int threshold = 86;
                if ((7 * 42) - threshold > 200) selected = "constant";
                else selected = input;
                Runtime.getRuntime().exec(selected);
              }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)

    def test_system_property_is_not_treated_as_external_request_input(self) -> None:
        result = analyze(
            """
            class Service {
              void run() {
                Runtime.getRuntime().exec("echo " + System.getProperty("user.dir"));
              }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)

    def test_constant_ternary_selects_safe_value(self) -> None:
        result = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              void handle(HttpServletRequest request) {
                execute(request.getParameter("value"));
              }
              void execute(String input) {
                int offset = 106;
                String selected = (7 * 18) + offset > 200 ? "constant" : input;
                Runtime.getRuntime().exec(selected);
              }
            }
            """
        )

        self.assertEqual(result["finding_count"], 0)

    def test_execute_is_classified_by_receiver_type(self) -> None:
        ssrf = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              HttpClient client;
              void handle(HttpServletRequest request) {
                client.execute(request.getParameter("url"));
              }
            }
            """
        )
        sql = analyze(
            """
            import java.sql.Statement;
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              Statement statement;
              void handle(HttpServletRequest request) throws Exception {
                statement.executeQuery(request.getParameter("query"));
              }
            }
            """
        )
        unrelated = analyze(
            """
            import javax.servlet.http.HttpServletRequest;
            class Controller {
              PaymentClient client;
              void handle(HttpServletRequest request) {
                client.execute(request.getParameter("tradeId"));
              }
            }
            """
        )

        self.assertEqual(ssrf["findings"][0]["scenario"], "ssrf")
        self.assertEqual(sql["findings"][0]["scenario"], "sql_injection")
        self.assertEqual(unrelated["finding_count"], 0)

    def test_large_project_falls_back_to_module_chunking(self) -> None:
        def module_source(class_prefix: str, vulnerable: bool) -> str:
            helpers = "\n".join(f"void helper{i}() {{}}" for i in range(60))
            sink = (
                """
                void handle(javax.servlet.http.HttpServletRequest request) {
                  forward(request.getParameter("cmd"));
                }
                void forward(String cmd) {
                  Runtime.getRuntime().exec(cmd);
                }
                """
                if vulnerable
                else ""
            )
            return f"class {class_prefix}Service {{ {helpers} {sink} }}"

        files = [
            {
                "file_name": "module-a/src/main/java/ModuleAService.java",
                "content": module_source("ModuleA", True),
            },
            {
                "file_name": "module-b/src/main/java/ModuleBService.java",
                "content": module_source("ModuleB", False),
            },
        ]

        with patch.dict(
            "os.environ",
            {
                "SECFLOW_JAVA_FLOW_MAX_METHODS": "100",
                "SECFLOW_JAVA_FLOW_MIN_CHUNK_FILES": "1",
            },
        ):
            result = analyze_java_interprocedural(files)

        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["chunked"])
        self.assertEqual(result["chunk_count"], 2)
        self.assertEqual(result["findings"][0]["scenario"], "command_execution")

    def test_complete_analysis_has_no_time_or_method_limit_and_reaches_fixed_point(self) -> None:
        wrappers = "\n".join(
            f"void level{index}(String value) {{ level{index + 1}(value); }}"
            for index in range(1, 8)
        )
        source = f"""
        import org.springframework.web.bind.annotation.GetMapping;
        import org.springframework.web.bind.annotation.RequestParam;
        class DeepController {{
          @GetMapping void entry(@RequestParam String value) {{ level1(value); }}
          {wrappers}
          void level8(String value) {{ Runtime.getRuntime().exec(value); }}
        }}
        """
        files = [{"file_name": "src/main/java/DeepController.java", "content": source}]

        with patch.dict(
            "os.environ",
            {
                "SECFLOW_JAVA_FLOW_MAX_SECONDS": "2",
                "SECFLOW_JAVA_FLOW_MAX_METHODS": "100",
                "SECFLOW_JAVA_FLOW_MAX_ITERATIONS": "6",
            },
        ):
            bounded = analyze_java_interprocedural(files)
            complete = analyze_java_interprocedural(files, complete_analysis=True)

        self.assertEqual(JavaFlowAnalyzer(files, complete_analysis=True).max_seconds, None)
        self.assertFalse(any(item.get("scenario") == "command_execution" for item in bounded["findings"]))
        self.assertTrue(any(item.get("scenario") == "command_execution" for item in complete["findings"]))
        self.assertGreater(complete["iterations"], 6)
        self.assertEqual(complete["status"], "completed")

    def test_complete_analysis_remains_user_cancellable_without_timeout(self) -> None:
        source = "class Demo { void one() {} void two() {} }"
        checks = 0

        def cancelled() -> bool:
            nonlocal checks
            checks += 1
            return checks >= 3

        result = analyze_java_interprocedural(
            [{"file_name": "Demo.java", "content": source}],
            complete_analysis=True,
            cancelled=cancelled,
        )

        self.assertEqual(result["status"], "cancelled")
        self.assertIn("用户停止", " ".join(result["diagnostics"]))


if __name__ == "__main__":
    unittest.main()
