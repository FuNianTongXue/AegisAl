import XCTest
import WebKit
@testable import SecFlowMac

final class ModelDecodingTests: XCTestCase {
    func testReportDownloadAllFormatsIgnoresEmptyReportObject() throws {
        let json = #"""
        {
          "status": "completed",
          "thread_id": "report-download-all",
          "interrupt": null,
          "summary": "下载制品已准备好。",
          "report": {},
          "artifacts": [{
            "id": "report-artifact-bundle",
            "kind": "report",
            "file_name": "SecFlow-report-bundle.zip",
            "media_type": "application/zip",
            "download_path": "/api/assistant/artifacts/report-artifact-bundle",
            "sha256": "abc123",
            "size": 4096,
            "generated_at": "2026-07-31T03:12:00+00:00"
          }],
          "error": "",
          "answer": null,
          "report_mcp": {},
          "report_mcps": []
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(ReportActionResult.self, from: json)

        XCTAssertNil(result.report)
        XCTAssertEqual(result.artifacts.first?.fileName, "SecFlow-report-bundle.zip")
        XCTAssertEqual(result.artifacts.first?.mediaType, "application/zip")
    }

    func testAssistantDecodesRecoveredProjectScanTask() throws {
        let json = #"""
        {
          "mode": "project_scan",
          "summary": "已恢复源码工作区并创建扫描任务。",
          "fields": {"工作区状态": "已验证可访问"},
          "agent_task": {
            "id": "task-recovered",
            "objective": "我想做代码漏洞的扫描",
            "workspace_path": "/tmp/kafka-4.3.1-src",
            "workspace_name": "kafka-4.3.1-src",
            "workspace_type": "directory",
            "user_id": "analyst",
            "status": "queued",
            "current_node": "queued",
            "languages": [],
            "plan": [],
            "events": [],
            "result": null,
            "report_ready": false,
            "report_decision": "unavailable",
            "report": null,
            "error": "",
            "archived": false,
            "archived_at": null,
            "created_at": "2026-07-30T05:00:00+00:00",
            "updated_at": "2026-07-30T05:00:00+00:00"
          },
          "confidence": 0.98,
          "trace": [],
          "generated_at": "2026-07-30T05:00:00+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertEqual(result.agentTask?.id, "task-recovered")
        XCTAssertEqual(result.agentTask?.workspaceName, "kafka-4.3.1-src")
        XCTAssertEqual(result.agentTask?.status, "queued")
    }

    func testAssistantIgnoresLegacyEmptyComponentDetail() throws {
        let json = #"""
        {
          "mode": "vulnerability_lookup",
          "summary": "CVE 查询完成。",
          "fields": {},
          "component_detail": {},
          "confidence": 0.9,
          "trace": [],
          "generated_at": "2026-07-29T07:34:00+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertNil(result.componentDetail)
        XCTAssertEqual(result.summary, "CVE 查询完成。")
    }

    func testLegacyComponentDetailDefaultsMissingSchemaVersion() throws {
        let json = #"""
        {
          "renderer": "component-vulnerability-detail",
          "component": {"name": "jackson-databind", "version": "2.9.10", "ecosystem": "Maven"},
          "total": 0,
          "preview_count": 0,
          "truncated": false,
          "vulnerabilities": [],
          "generated_at": "2026-07-29T07:34:00+00:00"
        }
        """#.data(using: .utf8)!

        let detail = try JSONDecoder.secFlow.decode(ComponentVulnerabilityDetailPayload.self, from: json)

        XCTAssertEqual(detail.schemaVersion, 1)
        XCTAssertEqual(detail.renderer, "component-vulnerability-detail")
    }

    func testAssistantConversationDecodesProjectAndArchiveState() throws {
        let data = Data(
            """
            {
              "id": "conversation-1",
              "title": "历史安全问题",
              "updated_at": "2026-07-27T12:00:00+00:00",
              "turn_count": 3,
              "project_id": "assistant",
              "project_name": "智能问答",
              "archived": true,
              "archived_at": "2026-07-27T13:00:00+00:00"
            }
            """.utf8
        )

        let conversation = try JSONDecoder.secFlow.decode(AssistantConversationSummary.self, from: data)

        XCTAssertEqual(conversation.projectId, "assistant")
        XCTAssertEqual(conversation.projectName, "智能问答")
        XCTAssertEqual(conversation.turnCount, 3)
        XCTAssertTrue(conversation.archived)
        XCTAssertEqual(conversation.archivedAt, "2026-07-27T13:00:00+00:00")
    }

    func testAssistantConversationExchangeRestoresSecurityAgentMetadata() throws {
        let data = Data(
            #"""
            {
              "id": "msg-1",
              "question": "最近有哪些漏洞？",
              "answer": "已完成查询。",
              "mode": "vulnerability_lookup",
              "confidence": 0.92,
              "fields": {},
              "answer_payload": {
                "mode": "vulnerability_lookup",
                "summary": "已完成查询。",
                "fields": {},
                "evidence_sources": [{"id": "nvd", "status": "success", "count": 3}],
                "token_usage": 4128,
                "confidence": 0.92,
                "trace": [{
                  "node": "query_intelligence",
                  "status": "completed",
                  "message": "查询完成。",
                  "time": "2026-07-28T10:00:01+00:00"
                }],
                "generated_at": "2026-07-28T10:00:02+00:00"
              },
              "timestamp": "2026-07-28T10:00:02+00:00"
            }
            """#.utf8
        )

        let exchange = try JSONDecoder.secFlow.decode(AssistantConversationExchange.self, from: data)

        XCTAssertEqual(exchange.answerPayload?.tokenUsage, 4128)
        XCTAssertEqual(exchange.answerPayload?.trace.first?.node, "query_intelligence")
        XCTAssertEqual(exchange.answerPayload?.evidenceSources.first?.id, "nvd")
    }

    func testAssistantTraceDecodesPromptDiffAndToolCallPresentations() throws {
        let json = #"""
        {
          "mode": "general_security_question",
          "summary": "Done",
          "fields": {},
          "artifacts": [],
          "confidence": 0.9,
          "trace": [
            {
              "node": "call_llm",
              "status": "completed",
              "message": "Model completed",
              "time": "2026-07-27T00:00:00+00:00",
              "presentation": {
                "kind": "prompt_diff",
                "title": "System Prompt Changes",
                "before": "You are a helpful assistant.",
                "after": "You are a senior security engineer."
              }
            },
            {
              "node": "component_query.excel_mcp",
              "status": "completed",
              "message": "Excel generated",
              "time": "2026-07-27T00:00:01+00:00",
              "presentation": {
                "kind": "tool_call",
                "title": "Excel MCP",
                "tool_name": "export_component_vulnerabilities_excel",
                "state": "completed",
                "input": {"name": "demo", "version": "1.0.0"},
                "output": "{\"records\":3}",
                "error": ""
              }
            }
          ],
          "generated_at": "2026-07-27T00:00:02+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertEqual(result.trace[0].presentation?.kind, "prompt_diff")
        XCTAssertEqual(result.trace[0].presentation?.after, "You are a senior security engineer.")
        XCTAssertEqual(result.trace[1].presentation?.toolName, "export_component_vulnerabilities_excel")
        XCTAssertEqual(result.trace[1].presentation?.input?["version"], "1.0.0")
        XCTAssertEqual(result.trace[1].presentation?.state, "completed")
    }

    func testAgentTaskEventDecodesNestedLangGraphPresentation() throws {
        let json = #"""
        {
          "sequence": 4,
          "type": "node.started",
          "node": "synthesize_project_overlay",
          "status": "running",
          "message": "Preparing project overlay",
          "time": "2026-07-27T00:00:00+00:00",
          "data": {
            "iteration": 1,
            "presentation": {
              "kind": "prompt_diff",
              "title": "Project Overlay Prompt Changes",
              "before": "Base prompt",
              "after": "Base prompt plus project skill"
            }
          }
        }
        """#.data(using: .utf8)!

        let event = try JSONDecoder.secFlow.decode(AgentTaskEvent.self, from: json)
        let presentation = try XCTUnwrap(langGraphPresentation(from: event.data))

        XCTAssertEqual(event.data?["iteration"]?.text, "1")
        XCTAssertEqual(presentation.kind, "prompt_diff")
        XCTAssertEqual(presentation.before, "Base prompt")
        XCTAssertEqual(presentation.after, "Base prompt plus project skill")
    }

    func testAssistantDecodesComponentQueryMCPArtifactsAndSankey() throws {
        let json = #"""
        {
          "mode": "component_vulnerability_query",
          "summary": "已核验 PyPI / demo / 2.3.0，确认 1 条漏洞记录。",
          "fields": {"组件名称": "demo", "组件版本": "2.3.0"},
          "vulnerability_card": {},
          "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
          "component_detail": {
            "schema_version": 1,
            "renderer": "component-vulnerability-detail",
            "component": {"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            "total": 1,
            "preview_count": 1,
            "truncated": false,
            "generated_at": "2026-07-26T00:00:00+00:00",
            "vulnerabilities": [{
              "id": "CVE-2026-10001",
              "title": "Demo package command injection",
              "severity": "HIGH",
              "severity_label": "高危",
              "description": "该组件版本存在命令注入风险。",
              "vulnerability_type": "CWE-78",
              "aliases": ["CVE-2026-10001"],
              "cwes": ["CWE-78"],
              "published_at": "2026-07-01T00:00:00+00:00",
              "updated_at": "2026-07-20T00:00:00+00:00",
              "affected_packages": [{
                "name": "demo",
                "ecosystem": "PyPI",
                "affected_versions": ["< 2.4.1"],
                "fixed_versions": ["2.4.1"]
              }],
              "affected_versions": ["< 2.4.1"],
              "fixed_versions": ["2.4.1"],
              "remediation": "建议升级到已确认修复版本：2.4.1",
              "exploit_status": "未明确",
              "exploit_status_code": "unknown",
              "exploit_difficulty": "较低",
              "reference_links": [{"title": "NVD 漏洞详情", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-10001"}],
              "cvss": {
                "score": 8.1,
                "rating": "高危",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "version": "3.1",
                "metrics": [{"key": "AV", "label": "攻击向量", "value": "网络"}]
              }
            }]
          },
          "chart_data": {
            "schema_version": 1,
            "sankey": {
              "nodes": [
                {"id": "c:1", "label": "demo", "type": "component", "column": 0, "ecosystem": "PyPI"},
                {"id": "v:1", "label": "CVE-2026-10001", "type": "vulnerability", "severity": "HIGH", "column": 1}
              ],
              "links": [{"from": "c:1", "to": "v:1", "type": "AFFECTED_BY", "value": 1, "severity": "HIGH"}]
            }
          },
          "artifacts": [{
            "id": "component-xlsx-20260726000000-abcdef123456",
            "kind": "excel",
            "file_name": "SecFlow-PyPI-demo-2.3.0-vulnerabilities.xlsx",
            "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "download_path": "/api/assistant/artifacts/component-xlsx-20260726000000-abcdef123456",
            "sha256": "abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcd",
            "size": 16384,
            "generated_at": "2026-07-26T00:00:00+00:00"
          }],
          "confidence": 0.94,
          "trace": [],
          "generated_at": "2026-07-26T00:00:00+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertEqual(result.mode, "component_vulnerability_query")
        XCTAssertEqual(result.chartData?.sankey?.nodes.count, 2)
        XCTAssertEqual(result.chartData?.sankey?.links.first?.from, "c:1")
        XCTAssertEqual(result.componentDetail?.renderer, "component-vulnerability-detail")
        XCTAssertEqual(result.componentDetail?.vulnerabilities.first?.cvss.metrics.first?.value, "网络")
        XCTAssertEqual(result.componentDetail?.vulnerabilities.first?.referenceLinks.first?.title, "NVD 漏洞详情")
        XCTAssertEqual(result.artifacts.first?.kind, "excel")
        XCTAssertEqual(result.artifacts.first?.fileName, "SecFlow-PyPI-demo-2.3.0-vulnerabilities.xlsx")
    }

    func testAssistantDecodesReportInterruptEnvelope() throws {
        let json = #"""
        {
          "mode": "report_operation",
          "summary": "扫描已完成，是否生成报告？",
          "fields": {"报告操作状态": "interrupted"},
          "vulnerability_card": {},
          "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
          "chart_data": {},
          "artifacts": [],
          "interrupt": {
            "interrupt_id": "interrupt-1",
            "thread_id": "report-thread-1",
            "kind": "report_generation_confirmation",
            "action": "generate",
            "question": "扫描已完成，是否生成报告？",
            "detail": "确认后调用 Report Chart MCP。",
            "options": ["confirm", "cancel"]
          },
          "confidence": 1.0,
          "trace": [],
          "generated_at": "2026-07-26T00:00:00+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertEqual(result.interrupt?.kind, "report_generation_confirmation")
        XCTAssertEqual(result.interrupt?.threadId, "report-thread-1")
        XCTAssertEqual(result.interrupt?.options, ["confirm", "cancel"])
    }

    func testAssistantDecodesComponentExcelDownloadInterrupt() throws {
        let json = #"""
        {
          "mode": "component_vulnerability_catalog",
          "summary": "Excel 已生成，是否选择目录并下载？",
          "fields": {"漏洞数量": "12"},
          "vulnerability_card": {},
          "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
          "chart_data": {},
          "artifacts": [{
            "id": "component-xlsx-20260728000000-abcdef123456",
            "kind": "excel",
            "file_name": "component-vulnerabilities.xlsx",
            "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "download_path": "/api/assistant/artifacts/component-xlsx-20260728000000-abcdef123456",
            "sha256": "abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcd",
            "size": 16384,
            "generated_at": "2026-07-28T00:00:00+00:00"
          }],
          "interrupt": {
            "interrupt_id": "interrupt-excel-2",
            "thread_id": "component-catalog-thread-1",
            "kind": "component_excel_download_confirmation",
            "action": "download_component_catalog_excel",
            "question": "Excel 已生成，是否选择目录并下载？",
            "detail": "component-vulnerabilities.xlsx",
            "options": ["confirm", "cancel"],
            "artifact_ids": ["component-xlsx-20260728000000-abcdef123456"]
          },
          "confidence": 0.95,
          "trace": [],
          "generated_at": "2026-07-28T00:00:00+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertEqual(result.interrupt?.kind, "component_excel_download_confirmation")
        XCTAssertEqual(result.interrupt?.artifactIds, ["component-xlsx-20260728000000-abcdef123456"])
        XCTAssertEqual(result.artifacts.first?.kind, "excel")
    }

    func testAssistantDecodesSBOMDesktopDownloadInterrupt() throws {
        let json = #"""
        {
          "mode": "project_sbom_export",
          "summary": "SBOM Excel 已生成，是否下载到本机桌面？",
          "fields": {"组件数量": "42"},
          "artifacts": [{
            "id": "sbom-xlsx-20260728000000-abcdef123456",
            "kind": "excel",
            "file_name": "SecFlow-payments-SBOM.xlsx",
            "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "download_path": "/api/assistant/artifacts/sbom-xlsx-20260728000000-abcdef123456",
            "sha256": "abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcd",
            "size": 16384,
            "generated_at": "2026-07-28T00:00:00+00:00"
          }],
          "interrupt": {
            "interrupt_id": "interrupt-sbom-3",
            "thread_id": "sbom-thread-1",
            "kind": "sbom_excel_download_confirmation",
            "action": "download_sbom_excel",
            "question": "SBOM Excel 已生成，是否下载到本机桌面？",
            "options": ["confirm", "cancel"],
            "artifact_ids": ["sbom-xlsx-20260728000000-abcdef123456"],
            "destination_hint": "desktop"
          },
          "confidence": 0.96,
          "trace": [],
          "generated_at": "2026-07-28T00:00:00+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertEqual(result.mode, "project_sbom_export")
        XCTAssertEqual(result.interrupt?.destinationHint, "desktop")
        XCTAssertEqual(result.artifacts.first?.fileName, "SecFlow-payments-SBOM.xlsx")
    }

    func testReportDetailDecodesMCPAuditAndCharts() throws {
        let json = #"""
        {
          "id": "report-1",
          "title": "Scan report",
          "file_name": "scan.md",
          "available_formats": ["md", "html", "docx", "pdf"],
          "created_at": "2026-07-26T00:00:00+00:00",
          "mode": "agent_static_scan",
          "vulnerability_count": 0,
          "finding_count": 1,
          "content": "# Scan report",
          "metadata": {
            "report_mcp": {
              "server": "SecFlow Report Chart MCP",
              "tool": "build_scan_report_charts",
              "transport": "in-process",
              "status": "completed",
              "invoked_at": "2026-07-26T00:00:00+00:00",
              "fact_count": 1,
              "renderer": "d3-report-charts",
              "output_sha256": "abcdef"
            },
            "report_mcps": [
              {
                "server": "SecFlow Word MCP",
                "tool": "render_word_report",
                "transport": "in-process",
                "status": "completed",
                "invoked_at": "2026-07-26T00:00:01+00:00",
                "input_sha256": "sourcehash",
                "output_sha256": "wordhash",
                "media_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "artifact_size": 2048,
                "renderer": "python-docx"
              }
            ],
            "report_charts": {
              "schema_version": 1,
              "renderer": "d3-report-charts",
              "severity_ring": [{"id": "high", "label": "High", "value": 1, "severity": "HIGH"}],
              "risk_bars": [{"id": "command", "label": "Command", "value": 1}],
              "sankey_nodes": [
                {"id": "source:demo.py", "label": "demo.py", "type": "source", "column": 0},
                {"id": "finding:1", "label": "Command injection", "type": "finding", "severity": "HIGH", "column": 1}
              ],
              "sankey_links": [
                {"source": "source:demo.py", "target": "finding:1", "type": "CONTAINS", "value": 1, "severity": "HIGH"}
              ],
              "source_kind": "agent_task",
              "fact_count": 1
            }
          }
        }
        """#.data(using: .utf8)!

        let report = try JSONDecoder.secFlow.decode(AnalysisReportDetail.self, from: json)

        XCTAssertEqual(report.metadata?.reportMcp?.status, "completed")
        XCTAssertEqual(report.metadata?.reportMcps?.first?.tool, "render_word_report")
        XCTAssertEqual(report.metadata?.reportMcps?.first?.artifactSize, 2048)
        XCTAssertTrue(report.availableFormats?.contains("docx") == true)
        XCTAssertEqual(report.metadata?.reportCharts?.factCount, 1)
        XCTAssertEqual(report.metadata?.reportCharts?.chartData.sankey?.links.first?.from, "source:demo.py")
    }

    @MainActor
    func testBundledD3SankeyRuntimeRendersInlineSVGNodes() async throws {
        let data = SankeyChartData(
            nodes: [
                ChartNode(id: "c:1", label: "demo", type: "component", severity: nil, column: 0, version: nil, ecosystem: "PyPI"),
                ChartNode(id: "v:1", label: "CVE-2026-10001", type: "vulnerability", severity: "HIGH", column: 1, version: nil, ecosystem: nil),
                ChartNode(id: "f:1", label: "2.4.1", type: "fix", severity: nil, column: 2, version: "2.4.1", ecosystem: nil),
            ],
            links: [
                ChartLink(from: "c:1", to: "v:1", type: "AFFECTED_BY", value: 1, severity: "HIGH"),
                ChartLink(from: "v:1", to: "f:1", type: "FIXED_BY", value: 1, severity: "HIGH"),
            ]
        )
        let chart = D3SankeyChartView(data: data)
        let html = chart.renderedHTML

        XCTAssertFalse(D3SankeyChartView.bundledRuntime.isEmpty)
        XCTAssertTrue(html.contains("d3.sankey"))
        XCTAssertFalse(html.contains("<script src="))

        let webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 800, height: 320))
        webView.loadHTMLString(html, baseURL: nil)
        try await Task.sleep(nanoseconds: 800_000_000)

        let nodeCount = try await evaluateJavaScript("document.querySelectorAll('.node rect').length", in: webView)
        let fallback = try await evaluateJavaScript("document.querySelector('.fallback')?.textContent || ''", in: webView)
        XCTAssertEqual((nodeCount as? NSNumber)?.intValue, 3)
        XCTAssertEqual(fallback as? String, "")
    }

    @MainActor
    private func evaluateJavaScript(_ script: String, in webView: WKWebView) async throws -> Any? {
        try await withCheckedThrowingContinuation { continuation in
            webView.evaluateJavaScript(script) { value, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: value)
                }
            }
        }
    }

    func testLLMConfigDecodesSub2APIResponsesOptions() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "name": "Sub2API",
            "provider": "custom",
            "model": "gpt-5.6-sol",
            "endpoint": "https://carpool.composiastack.com",
            "wire_api": "responses",
            "reasoning_effort": "xhigh",
            "disable_response_storage": true,
            "enabled": true,
            "configured": false,
            "has_api_key": false,
            "api_key_masked": "",
            "message": "API Key 未配置",
            "updated_at": "2026-07-23T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<LLMConfigSnapshot>.self, from: json)

        XCTAssertEqual(envelope.data.name, "Sub2API")
        XCTAssertEqual(envelope.data.provider, "custom")
        XCTAssertEqual(envelope.data.model, "gpt-5.6-sol")
        XCTAssertEqual(envelope.data.wireApi, "responses")
        XCTAssertEqual(envelope.data.reasoningEffort, "xhigh")
        XCTAssertEqual(envelope.data.disableResponseStorage, true)
        XCTAssertFalse(envelope.data.hasApiKey)
    }

    func testServerSentEventParserHandlesKeepaliveAndMultilineData() {
        var parser = ServerSentEventParser()

        XCTAssertNil(parser.consume(line: ": keepalive"))
        XCTAssertNil(parser.consume(line: ""))
        XCTAssertNil(parser.consume(line: "event: trace"))
        XCTAssertNil(parser.consume(line: "data: {\"node\":\"call_llm\","))
        XCTAssertNil(parser.consume(line: "data: \"status\":\"completed\"}"))

        XCTAssertEqual(
            parser.consume(line: ""),
            ServerSentEvent(
                id: nil,
                name: "trace",
                data: "{\"node\":\"call_llm\",\n\"status\":\"completed\"}"
            )
        )
    }

    func testServerSentEventParserHandlesURLSessionLinesWithoutBlankSeparators() {
        var parser = ServerSentEventParser()

        XCTAssertNil(parser.consume(line: "event: trace"))
        XCTAssertNil(parser.consume(line: "data: {\"node\":\"classify_query\"}"))
        XCTAssertEqual(
            parser.consume(line: "event: result"),
            ServerSentEvent(id: nil, name: "trace", data: "{\"node\":\"classify_query\"}")
        )
        XCTAssertNil(parser.consume(line: "data: {\"summary\":\"ok\"}"))
        XCTAssertEqual(
            parser.finish(),
            ServerSentEvent(id: nil, name: "result", data: "{\"summary\":\"ok\"}")
        )
        XCTAssertNil(parser.finish())
    }

    func testServerSentEventParserPreservesEventID() {
        var parser = ServerSentEventParser()

        XCTAssertNil(parser.consume(line: "id: 42"))
        XCTAssertNil(parser.consume(line: "event: node.completed"))
        XCTAssertNil(parser.consume(line: "data: {\"sequence\":42}"))
        XCTAssertEqual(
            parser.consume(line: ""),
            ServerSentEvent(id: "42", name: "node.completed", data: "{\"sequence\":42}")
        )
    }

    func testServerSentEventParserPreservesStreamingMarkdownContent() throws {
        var parser = ServerSentEventParser()

        XCTAssertNil(parser.consume(line: "event: content"))
        XCTAssertNil(parser.consume(line: ##"data: {"delta":"# 漏洞摘要\n\n第一段"}"##))
        let event = try XCTUnwrap(parser.consume(line: ""))
        let payload = try JSONDecoder.secFlow.decode(
            [String: String].self,
            from: Data(event.data.utf8)
        )

        XCTAssertEqual(event.name, "content")
        XCTAssertEqual(payload["delta"], "# 漏洞摘要\n\n第一段")
    }

    func testAssistantDecodesPublicEvidenceSources() throws {
        let json = #"""
        {
          "mode": "vulnerability_lookup",
          "summary": "# 漏洞摘要\n已核验。",
          "fields": {},
          "evidence_sources": [
            {"id": "nvd", "status": "success", "count": 2},
            {"id": "github_advisory", "status": "failed", "count": 0}
          ],
          "token_usage": 4128,
          "artifacts": [],
          "confidence": 0.9,
          "trace": [],
          "generated_at": "2026-07-28T00:00:00+00:00"
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow.decode(AskResult.self, from: json)

        XCTAssertEqual(result.evidenceSources, [
            AssistantEvidenceSource(id: "nvd", status: "success", count: 2),
            AssistantEvidenceSource(id: "github_advisory", status: "failed", count: 0),
        ])
        XCTAssertEqual(result.tokenUsage, 4128)
    }

    @MainActor
    func testLiveAssistantStreamWhenConfigured() async throws {
        guard let serverURL = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_STREAM_TEST_URL"] else {
            throw XCTSkip("SECFLOW_ASSISTANT_STREAM_TEST_URL is not configured")
        }
        let client = try APIClient(serverURL: serverURL)
        var trace: [TraceItem] = []

        let result = try await client.streamAsk(
            AskPayload(
                question: "你是谁？",
                topK: 5,
                userId: "swift-stream-test",
                sessionId: "swift-stream-test",
                responseLanguage: "zh-Hans"
            )
        ) { items in
            trace.append(contentsOf: items)
        }

        XCTAssertEqual(result.mode, "identity")
        XCTAssertEqual(result.summary, "我是小安，您的信息安全专家助手。")
        XCTAssertGreaterThanOrEqual(trace.count, 5)
        XCTAssertEqual(result.trace.last?.node, "persist_memory")
    }

    func testAgentTaskDecodesLanguageSpecificExecutionResult() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "id": "task-1",
            "objective": "扫描项目",
            "workspace_path": "/tmp/demo",
            "workspace_name": "demo",
            "workspace_type": "directory",
            "user_id": "analyst",
            "status": "completed",
            "archived": false,
            "archived_at": null,
            "current_node": "compose_result",
            "languages": ["python"],
            "plan": [{
              "id": "language-python",
              "title": "执行 Python 专属规则和 AST/CFG/DFG 扫描",
              "node": "scan_python",
              "status": "completed",
              "language": "python"
            }],
            "events": [{
              "sequence": 1,
              "type": "node.completed",
              "node": "scan_python",
              "status": "completed",
              "message": "Python 扫描完成",
              "data": {},
              "time": "2026-07-22T10:00:00+00:00"
            }],
            "result": {
              "summary": "扫描完成",
              "scan_mode": "adaptive_upload",
              "languages": ["python"],
              "dependency_count": 3,
              "dependencies": [{
                "ecosystem": "PyPI",
                "name": "requests",
                "version": "2.32.4",
                "source_file": "requirements.txt",
                "source_type": "python_manifest",
                "declaration": "requests==2.32.4",
                "confidence": "high"
              }],
              "total_files": 2,
              "total_findings": 1,
              "language_results": {
                "python": {
                  "language": "python",
                  "status": "completed",
                  "mode": "bundled-cli",
                  "file_count": 2,
                  "files": ["app.py", "service.py"],
                  "rule_files": ["python-security.yml"],
                  "syntax_summary": {
                    "languages": ["python"],
                    "parsed_files": 2,
                    "parse_error_files": 0,
                    "ast_node_count": 40,
                    "cfg_node_count": 8,
                    "cfg_edge_count": 7,
                    "dfg_edge_count": 5
                  },
                  "finding_count": 1,
                  "findings": [{
                    "id": "finding-python",
                    "rule_id": "secflow.python.command-injection",
                    "title": "命令注入",
                    "severity": "HIGH",
                    "file_name": "app.py",
                    "line": 12,
                    "description": "外部输入进入命令执行函数"
                  }],
                  "diagnostics": []
                }
              },
              "project_profile": {
                "scope": "directory",
                "workspace_name": "demo",
                "scope_fingerprint": "scope-sha",
                "languages": ["python"],
                "manifest_files": ["requirements.txt"],
                "build_systems": ["python-requirements"],
                "frameworks": ["requests"],
                "dependency_count": 3,
                "adaptive_enabled": true,
                "evaluation_isolation": false,
                "skill": {
                  "name": "secflow-project-adaptive-scan",
                  "sha256": "skill-sha",
                  "prompt_version": "secflow-project-adaptive-scan-v1"
                }
              },
              "adaptation": {
                "enabled": true,
                "mode": "adaptive_upload",
                "status": "rescanned",
                "attempts": 1,
                "iterations": 1,
                "overlay_fingerprints": ["overlay-sha"],
                "next_action": "",
                "termination_reason": "no_change",
                "skill": {
                  "name": "secflow-project-adaptive-scan",
                  "sha256": "skill-sha",
                  "prompt_version": "secflow-project-adaptive-scan-v1"
                },
                "baseline_metrics": {
                  "findings": 1,
                  "review_findings": 1,
                  "parsed_files": 2,
                  "parse_error_files": 0,
                  "cfg_edges": 7,
                  "dfg_edges": 5
                },
                "current_metrics": {
                  "findings": 1,
                  "review_findings": 0,
                  "parsed_files": 2,
                  "parse_error_files": 0,
                  "cfg_edges": 7,
                  "dfg_edges": 5
                }
              }
            },
            "error": "",
            "created_at": "2026-07-22T10:00:00+00:00",
            "updated_at": "2026-07-22T10:00:01+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<AgentTaskSnapshot>.self, from: json)

        XCTAssertEqual(envelope.data.languages, ["python"])
        XCTAssertEqual(envelope.data.workspaceType, "directory")
        XCTAssertEqual(envelope.data.result?.languageResults["python"]?.ruleFiles, ["python-security.yml"])
        XCTAssertEqual(envelope.data.result?.languageResults["python"]?.syntaxSummary.astNodeCount, 40)
        XCTAssertEqual(envelope.data.result?.languageResults["python"]?.findings.first?.fileName, "app.py")
        XCTAssertEqual(envelope.data.result?.dependencies?.first?.name, "requests")
        XCTAssertEqual(envelope.data.resolvedReportDecision, "unavailable")
        XCTAssertFalse(envelope.data.isReportReady)
        XCTAssertFalse(envelope.data.isArchived)
        XCTAssertEqual(envelope.data.result?.scanMode, "adaptive_upload")
        XCTAssertEqual(envelope.data.result?.projectProfile?.buildSystems, ["python-requirements"])
        XCTAssertEqual(envelope.data.result?.adaptation?.iterations, 1)
        XCTAssertEqual(envelope.data.result?.adaptation?.currentMetrics?.reviewFindings, 0)
        XCTAssertEqual(envelope.data.result?.adaptation?.overlayFingerprints, ["overlay-sha"])

        let completion = AgentTaskEvent(
            sequence: 2,
            type: "task.completed",
            node: "compose_result",
            status: "completed",
            message: "扫描图执行完成",
            time: "2026-07-22T10:00:02+00:00"
        )
        let incrementallyCompleted = envelope.data.applying(event: completion)
        XCTAssertEqual(incrementallyCompleted.events.map(\.sequence), [1, 2])
        XCTAssertFalse(incrementallyCompleted.isReportReady)
        XCTAssertEqual(incrementallyCompleted.applying(event: completion), incrementallyCompleted)
    }

    func testInformationArtworkUsesSharedSourceLogoForMissingCover() {
        XCTAssertEqual(
            informationArtworkRequestTargets(
                itemID: "news-1",
                sourceID: "vendor-source",
                articleImageURL: ""
            ),
            [.source("vendor-source")]
        )
        XCTAssertEqual(
            informationArtworkRequestTargets(
                itemID: "news-2",
                sourceID: "vendor-source",
                articleImageURL: "https://cdn.example.test/cover.png"
            ),
            [.item("news-2"), .source("vendor-source")]
        )
    }

    func testInformationSourceMonogramUsesVendorIdentity() {
        XCTAssertEqual(informationSourceMonogram("数世咨询"), "数世")
        XCTAssertEqual(informationSourceMonogram("Cisco Talos Intelligence"), "CT")
        XCTAssertEqual(informationSourceMonogram("FreeBuf"), "FRE")
        XCTAssertEqual(informationSourceMonogram(""), "RSS")
    }

    func testComponentVulnerabilityResultDecodesExportContract() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "status": "success",
            "query": "demo@2.3.0",
            "component": {"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            "records": [{
              "id": "CVE-2026-10001",
              "title": "Demo issue",
              "severity": "HIGH",
              "cvss_score": 8.1,
              "summary": "Example",
              "affected_versions": ["demo < 2.4.1"],
              "fixed_versions": ["demo 2.4.1"],
              "aliases": [],
              "cwes": ["CWE-78"],
              "components": [{"name": "demo", "ecosystem": "PyPI", "affected": ["< 2.4.1"], "fixed": ["2.4.1"]}],
              "published_at": "2026-07-01T00:00:00+00:00",
              "updated_at": "2026-07-20T00:00:00+00:00"
            }],
            "total": 1,
            "preview_limit": 200,
            "truncated": false,
            "ecosystems": ["PyPI"],
            "graph": {"query": "demo@2.3.0", "nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
            "source": "local-catalog",
            "generated_at": "2026-07-22T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<ComponentVulnerabilityResult>.self, from: json)

        XCTAssertEqual(envelope.data.component.name, "demo")
        XCTAssertEqual(envelope.data.total, 1)
        XCTAssertEqual(envelope.data.records.first?.components?.first?.fixed, ["2.4.1"])
    }

    func testLiveBackendContractWhenConfigured() async throws {
        guard let serverURL = ProcessInfo.processInfo.environment["SECFLOW_INTEGRATION_URL"] else {
            throw XCTSkip("SECFLOW_INTEGRATION_URL is not configured")
        }
        let client = try APIClient(serverURL: serverURL)
        let config = try await client.loadConfig()
        let collectorGraph = try await client.loadCollectorGraph()
        let dashboard = try await client.loadDashboard()
        let sources = try await client.loadIntelligenceSources()
        let intelligence = try await client.queryIntelligence(
            IntelligenceQueryPayload(query: "CVE-2021-44228", limit: 5, responseLanguage: "zh-Hans", sources: nil)
        )
        let result = try await client.collect(id: "cve")

        XCTAssertNotNil(config.runtime)
        XCTAssertEqual(collectorGraph.nodes.first?.id, "validate_config")
        XCTAssertGreaterThanOrEqual(dashboard.vulnerabilityCount, 1)
        XCTAssertFalse(sources.isEmpty)
        XCTAssertGreaterThanOrEqual(intelligence.graph.nodeCount, 1)
        XCTAssertEqual(result.trace.first?.node, "validate_config")
    }

    func testConfigSnapshotDecodesBackendContract() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "collectors": {
              "cve": {
                "id": "cve",
                "name": "CVE Vulnerability Database",
                "enabled": true,
                "api_url": "https://example.test/cves",
                "api_key": "test********key",
                "collection_name": "cve",
                "severity_filter": ["CRITICAL", "HIGH"],
                "dedupe_key": "cve_id",
                "max_results": 20,
                "sync_interval_minutes": 60,
                "last_test": null,
                "last_collect": null
              }
            },
            "records": [{
              "id": "CVE-2026-1000",
              "title": "Example issue",
              "severity": "HIGH",
              "source": "internal",
              "summary": "Example summary",
              "references": [],
              "collection": "cve",
              "updated_at": "2026-07-15T00:00:00+00:00"
            }],
            "stats": {
              "total": 1,
              "by_collection": {"cve": 1},
              "by_severity": {"HIGH": 1}
            },
            "runtime": {
              "llm": {
                "configured": false,
                "provider": "deepseek",
                "model": "deepseek-chat",
                "endpoint": "https://api.deepseek.com/v1",
                "message": "not configured"
              },
              "memory": {
                "enabled": true,
                "backend": "json",
                "historyCount": 2,
                "summaryChars": 0,
                "lastUpdated": "",
                "postgresAvailable": false,
                "postgresError": ""
              }
            }
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<ConfigSnapshot>.self, from: json)
        XCTAssertEqual(envelope.data.stats.total, 1)
        XCTAssertEqual(envelope.data.collectors["cve"]?.apiUrl, "https://example.test/cves")
        XCTAssertEqual(envelope.data.runtime?.memory.historyCount, 2)
    }

    func testSettingsSnapshotDecodesBackendContract() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "profile": {
              "display_name": "李明哲",
              "email": "limingzhe@example.com",
              "phone": "138 **** 6688",
              "department": "网络安全部",
              "role": "安全分析师",
              "employee_id": "SEC-20240315",
              "bio": "安全分析师",
              "avatar_file_name": "avatar.png",
              "avatar_content_type": "image/png",
              "avatar_updated_at": "2026-07-20T00:00:00+00:00",
              "updated_at": "2026-07-20T00:00:00+00:00",
              "avatar_available": true
            },
            "preferences": {
              "language": "zh-Hans",
              "dark_mode": false,
              "font_size": "default",
              "launch_at_login": false,
              "auto_check_updates": true,
              "updated_at": "2026-07-20T00:00:00+00:00"
            },
            "about": {
              "name": "安全智脑",
              "subtitle": "Security AI Assistant",
              "version": "1.2.0",
              "release_channel": "内测版",
              "version_label": "v1.2.0 内测版",
              "latest": true,
              "last_checked_at": "2024-01-15 14:32",
              "copyright": "© 2024 安全智脑 Security AI. All Rights Reserved.",
              "features": ["智能问答", "情报采集"]
            },
            "legal": {
              "terms": {
                "id": "terms",
                "title": "服务协议",
                "heading": "安全智脑服务协议",
                "updated_at": "2026年7月20日",
                "effective_at": "2026年7月20日",
                "intro": "服务协议正文。",
                "sections": [
                  {
                    "heading": "一、协议",
                    "paragraphs": ["协议内容。"]
                  }
                ],
                "revision_updated_at": ""
              },
              "privacy": {
                "id": "privacy",
                "title": "隐私政策",
                "heading": "安全智脑隐私政策",
                "updated_at": "2026年7月20日",
                "effective_at": "2026年7月20日",
                "intro": "隐私政策正文。",
                "sections": [
                  {
                    "heading": "一、隐私",
                    "paragraphs": ["隐私内容。"]
                  }
                ],
                "revision_updated_at": ""
              }
            }
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<SettingsSnapshot>.self, from: json)
        XCTAssertEqual(envelope.data.profile.employeeId, "SEC-20240315")
        XCTAssertTrue(envelope.data.profile.avatarAvailable)
        XCTAssertEqual(envelope.data.preferences.fontSize, "default")
        XCTAssertEqual(envelope.data.about.version, "1.2.0")
        XCTAssertEqual(envelope.data.about.versionLabel, "v1.2.0 内测版")
        XCTAssertEqual(envelope.data.about.features.count, 2)
        XCTAssertEqual(envelope.data.legal?["terms"]?.updatedAt, "2026年7月20日")
        XCTAssertEqual(envelope.data.legal?["privacy"]?.sections.first?.paragraphs.first, "隐私内容。")
    }

    func testAssistantCardAndCollectorTraceDecode() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "mode": "vulnerability_lookup",
            "summary": "处置摘要",
            "fields": {},
            "vulnerability_card": {
              "漏洞编号": "CVE-2026-1000",
              "严重等级": "高危",
              "CVSS评分": 9.8,
              "修复版本": "2.0.1"
            },
            "confidence": 0.9,
            "trace": [{
              "node": "collector.normalize_records",
              "status": "completed",
              "message": "规范化完成",
              "time": "2026-07-15T00:00:00+00:00"
            }],
            "generated_at": "2026-07-15T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<AskResult>.self, from: json)
        XCTAssertEqual(envelope.data.vulnerabilityCard?["漏洞编号"], "CVE-2026-1000")
        XCTAssertEqual(envelope.data.vulnerabilityCard?["CVSS评分"], "9.8")
        XCTAssertEqual(envelope.data.trace.first?.node, "collector.normalize_records")
    }

    func testAssistantDecodesEmptyKnowledgeGraphObject() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "mode": "security_knowledge",
            "summary": "通用安全回答",
            "fields": {},
            "vulnerability_card": {},
            "knowledge_graph": {},
            "confidence": 0.82,
            "trace": [],
            "generated_at": "2026-07-15T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<AskResult>.self, from: json)
        XCTAssertEqual(envelope.data.knowledgeGraph?.nodes, [])
        XCTAssertEqual(envelope.data.knowledgeGraph?.edges, [])
        XCTAssertEqual(envelope.data.knowledgeGraph?.nodeCount, 0)
        XCTAssertEqual(envelope.data.knowledgeGraph?.edgeCount, 0)
    }

    func testAssistantDecodesPartialChartData() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "mode": "dependency_vulnerability_report",
            "summary": "依赖分析完成",
            "fields": {},
            "vulnerability_card": {},
            "chart_data": {
              "schema_version": 1,
              "sankey": {
                "nodes": [],
                "links": []
              }
            },
            "confidence": 0.82,
            "trace": [],
            "generated_at": "2026-07-15T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<AskResult>.self, from: json)
        XCTAssertNotNil(envelope.data.chartData)
        XCTAssertEqual(envelope.data.chartData?.severityRing, [])
        XCTAssertEqual(envelope.data.chartData?.riskBars, [])
        XCTAssertFalse(envelope.data.chartData?.hasContent ?? true)
    }

    func testInformationSnapshotDecodesPublicFeedContract() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "items": [{
              "id": "news-1",
              "source_id": "cisa_kev",
              "source_name": "CISA 已知在野利用目录",
              "source_kind": "kev",
              "title": "CVE-2026-1111 已确认在野利用",
              "summary": "Apply the security update.",
              "url": "https://example.test/CVE-2026-1111",
              "image_url": "",
              "source_image_url": "https://example.test/source.png",
              "published_at": "2026-07-19T00:00:00+00:00",
              "author": "CISA KEV",
              "category": "漏洞披露",
              "tags": ["CVE", "在野利用"],
              "breaking": true
            }],
            "total": 1,
            "available_total": 1,
            "categories": [{"id": "all", "label": "全部", "count": 1}],
            "popular_tags": [{"name": "CVE", "count": 1}],
            "briefs": [],
            "source_summary": {
              "total": 513,
              "enabled": 10,
              "opml_total": 503,
              "opml_enabled": 0,
              "opml_enabled_limit": 50
            },
            "sources": [{
              "id": "cisa_kev",
              "name": "CISA 已知在野利用目录",
              "kind": "kev",
              "website": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
              "region": "国际",
              "group": "精选来源",
              "catalog": "curated",
              "secure_transport": true,
              "enabled": true,
              "status": "ready",
              "item_count": 1,
              "last_updated": "2026-07-19T00:00:00+00:00",
              "last_checked": "2026-07-19T00:00:00+00:00",
              "next_retry_at": "",
              "failure_count": 0,
              "refresh_interval_seconds": 900,
              "message": "已获取 1 条"
            }],
            "updated_at": "2026-07-19T00:00:00+00:00",
            "last_refresh": "2026-07-19T00:00:00+00:00",
            "stale": false,
            "partial": false,
            "message": "正在后台更新资讯，现有内容可继续浏览。",
            "refreshing": true,
            "refresh_started_at": "2026-07-19T00:01:00+00:00",
            "artwork_refreshing": true
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<InformationSnapshot>.self, from: json)

        XCTAssertEqual(envelope.data.items.first?.sourceId, "cisa_kev")
        XCTAssertEqual(envelope.data.items.first?.category, "漏洞披露")
        XCTAssertTrue(envelope.data.items.first?.breaking ?? false)
        XCTAssertEqual(envelope.data.sources.first?.itemCount, 1)
        XCTAssertEqual(envelope.data.sources.first?.region, "国际")
        XCTAssertEqual(envelope.data.sources.first?.resolvedGroup, "精选来源")
        XCTAssertEqual(envelope.data.sourceSummary?.opmlTotal, 503)
        XCTAssertEqual(envelope.data.sourceSummary?.opmlEnabledLimit, 50)
        XCTAssertTrue(envelope.data.isRefreshing)
        XCTAssertTrue(envelope.data.isUpdating)
        XCTAssertEqual(envelope.data.refreshStartedAt, "2026-07-19T00:01:00+00:00")
    }

    func testInformationPollingAcceleratesOnlyDuringRefresh() {
        XCTAssertEqual(informationPollingNanoseconds(refreshing: true), 750_000_000)
        XCTAssertEqual(informationPollingNanoseconds(refreshing: false), 60_000_000_000)
    }

    func testTrialStatusDecodesAndExpiresAtSevenDays() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "enabled": true,
            "usable": true,
            "state": "active",
            "durationHours": 168,
            "startedAt": "2026-07-20T02:00:00Z",
            "expiresAt": "2026-07-27T02:00:00Z",
            "lastSeenAt": "2026-07-20T02:00:00Z",
            "secondsRemaining": 604800,
            "message": "7 天试用版可用。"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<TrialStatusSnapshot>.self, from: json)
        let beforeExpiry = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-27T01:59:59Z"))
        let atExpiry = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-27T02:00:00Z"))

        XCTAssertEqual(envelope.data.durationHours, 168)
        XCTAssertEqual(envelope.data.durationLabel, "7 天")
        XCTAssertTrue(envelope.data.isUsable(at: beforeExpiry))
        XCTAssertFalse(envelope.data.isUsable(at: atExpiry))
        XCTAssertEqual(envelope.data.remainingSeconds(at: beforeExpiry), 1)
    }

    func testSubscriptionCatalogDecodesAndFormatsPrices() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "plans": [{
              "id": "professional_quarterly",
              "name": "专业版",
              "period_name": "季度",
              "billing_period": "quarter",
              "interval_months": 3,
              "price_cents": 6800,
              "original_price_cents": 7500,
              "currency": "CNY",
              "discount_percent": 9,
              "badge": "最受欢迎",
              "description": "性价比之选",
              "features": ["完整代码扫描"],
              "recommended": true
            }],
            "payment_methods": [
              {"id": "alipay", "name": "支付宝"},
              {"id": "wechat", "name": "微信支付"},
              {"id": "unionpay", "name": "银联"}
            ],
            "currency": "CNY"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<SubscriptionCatalog>.self, from: json)
        let plan = try XCTUnwrap(envelope.data.plans.first)

        XCTAssertEqual(plan.priceText, "¥68")
        XCTAssertEqual(plan.monthlyEquivalentText, "¥22.67")
        XCTAssertTrue(plan.recommended)
        XCTAssertEqual(envelope.data.paymentMethods.map(\.id), ["alipay", "wechat", "unionpay"])
    }

    func testSubscriptionCheckoutDoesNotDecodeAsPaidWhenGatewayIsUnconfigured() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "checkout_status": "integration_required",
            "provider_configured": false,
            "payment_url": null,
            "reused": false,
            "order": {
              "id": "ord_test",
              "user_id": "local-user",
              "plan_id": "professional_yearly",
              "plan_name": "专业版",
              "period_name": "年度",
              "payment_method": "alipay",
              "amount_cents": 18800,
              "currency": "CNY",
              "status": "integration_required",
              "provider_transaction_id": null,
              "payment_url": null,
              "created_at": "2026-07-23T10:00:00+00:00",
              "updated_at": "2026-07-23T10:00:00+00:00",
              "paid_at": null
            },
            "message": "支付渠道接口尚未配置，订单已保存但不会激活订阅。"
          }
        }
        """#.data(using: .utf8)!

        let result = try JSONDecoder.secFlow
            .decode(APIEnvelope<SubscriptionCheckoutResult>.self, from: json)
            .data

        XCTAssertEqual(result.checkoutStatus, "integration_required")
        XCTAssertFalse(result.providerConfigured)
        XCTAssertNil(result.paymentUrl)
        XCTAssertEqual(result.order.amountText, "¥188")
        XCTAssertNotEqual(result.order.status, "paid")
    }
}
