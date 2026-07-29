import XCTest
@testable import SecFlowMac

final class AssistantInputTests: XCTestCase {
    func testPunctuationOnlyQuestionIsNotMeaningful() {
        XCTAssertFalse(isMeaningfulAssistantQuestion("?"))
        XCTAssertFalse(isMeaningfulAssistantQuestion("？"))
        XCTAssertFalse(isMeaningfulAssistantQuestion("..."))
    }

    func testSecurityQuestionWithTextOrIdentifierIsMeaningful() {
        XCTAssertTrue(isMeaningfulAssistantQuestion("这个漏洞怎么修复？"))
        XCTAssertTrue(isMeaningfulAssistantQuestion("CVE-2026-55576"))
    }

    func testDesktopArtifactDestinationUsesCurrentUsersSystemDirectory() {
        let destination = automaticAssistantArtifactDestination(
            fileName: "SecFlow-payments-SBOM.xlsx",
            destinationHint: "desktop"
        )

        XCTAssertEqual(destination?.deletingLastPathComponent(), assistantSystemDirectory(for: "desktop"))
        XCTAssertEqual(destination?.lastPathComponent, "SecFlow-payments-SBOM.xlsx")
        XCTAssertNil(automaticAssistantArtifactDestination(fileName: "SBOM.xlsx", destinationHint: "choose"))
    }

    func testArtifactDestinationStripsDirectoryTraversalFromFileName() {
        let destination = automaticAssistantArtifactDestination(
            fileName: "../../SBOM.xlsx",
            destinationHint: "desktop"
        )

        XCTAssertEqual(destination?.lastPathComponent, "SBOM.xlsx")
    }

    func testNaturalInterruptDecisionUnderstandsSystemDirectoriesAndCancellation() {
        XCTAssertEqual(
            assistantNaturalInterruptDecision("下载目录"),
            AssistantNaturalInterruptDecision(confirm: true, destinationHint: "downloads")
        )
        XCTAssertEqual(
            assistantNaturalInterruptDecision("请保存到桌面"),
            AssistantNaturalInterruptDecision(confirm: true, destinationHint: "desktop")
        )
        XCTAssertEqual(
            assistantNaturalInterruptDecision("暂不下载"),
            AssistantNaturalInterruptDecision(confirm: false, destinationHint: nil)
        )
        XCTAssertNil(assistantNaturalInterruptDecision("下载目录是什么"))
    }

    func testMostRecentVulnerabilityIdentifierComesFromVerifiedAnswerCard() {
        let answer = AskResult(
            localSummary: "漏洞已核验",
            mode: "vulnerability_lookup",
            vulnerabilityCard: ["漏洞编号": "CVE-2021-35516"],
            generatedAt: "2026-07-29T09:50:00Z"
        )
        let turns = [ConversationTurn(question: "查询漏洞", answer: answer)]

        XCTAssertEqual(assistantMostRecentVulnerabilityIdentifier(in: turns), "CVE-2021-35516")
    }

    func testConversationTurnCanReferenceWorkspaceTask() {
        let turn = ConversationTurn(
            question: "扫描项目",
            attachmentNames: ["security-service"],
            agentTaskID: "task-123"
        )

        XCTAssertEqual(turn.agentTaskID, "task-123")
        XCTAssertEqual(turn.attachmentNames, ["security-service"])
    }

    @MainActor
    func testNewConversationKeepsPreviousConversationInHistory() {
        let model = AppModel()
        let originalSessionID = model.sessionID
        defer { UserDefaults.standard.set(originalSessionID, forKey: "secflow.sessionID") }
        model.conversationTurns = [ConversationTurn(question: "需要保留的历史问题")]

        model.startNewAssistantConversation(refreshConversations: false)

        XCTAssertNotEqual(model.sessionID, originalSessionID)
        XCTAssertTrue(model.conversationTurns.isEmpty)
        XCTAssertEqual(model.assistantConversations.first?.id, originalSessionID)
        XCTAssertEqual(model.assistantConversations.first?.title, "需要保留的历史问题")
        XCTAssertEqual(model.assistantConversations.first?.turnCount, 1)
    }

    func testOnlyCodeScanTurnsDisplayWorkflowNodes() {
        let ordinary = ConversationTurn(question: "解释一下什么是供应链攻击")
        let scan = ConversationTurn(question: "扫描项目", agentTaskID: "task-1")
        let followUp = ConversationTurn(
            question: "补充修复方案",
            agentTaskID: "task-1",
            showsAgentTaskWorkflow: false
        )

        XCTAssertFalse(assistantDisplaysWorkflowNodes(for: ordinary))
        XCTAssertTrue(assistantDisplaysWorkflowNodes(for: scan))
        XCTAssertFalse(assistantDisplaysWorkflowNodes(for: followUp))
    }

    func testAgentTaskEventTimeUsesChinaTimezoneFormat() {
        XCTAssertEqual(agentTaskDisplayTime("2026-07-29T00:45:50+00:00"), "2026:07:29:08:45")
        XCTAssertEqual(agentTaskDisplayTime("not-a-date"), "not-a-date")
    }

    func testConversationAutoScrollOnlyFollowsWhenBottomIsNearViewport() {
        XCTAssertTrue(assistantConversationIsNearBottom(bottomY: 700, viewportHeight: 720))
        XCTAssertTrue(assistantConversationIsNearBottom(bottomY: 820, viewportHeight: 720))
        XCTAssertFalse(assistantConversationIsNearBottom(bottomY: 900, viewportHeight: 720))
        XCTAssertFalse(assistantConversationIsNearBottom(bottomY: .infinity, viewportHeight: 720))
        XCTAssertFalse(assistantConversationIsNearBottom(bottomY: 700, viewportHeight: 0))
    }

    func testRestoredConversationTurnKeepsStableDatesAndAnswer() throws {
        let payload = #"""
        {
          "id": "msg-1",
          "question": "历史问题",
          "answer": "历史回答",
          "mode": "llm_direct",
          "confidence": 0.88,
          "fields": {"结论": "已恢复"},
          "timestamp": "2026-07-27T10:00:00+00:00"
        }
        """#.data(using: .utf8)!
        let exchange = try JSONDecoder.secFlow.decode(AssistantConversationExchange.self, from: payload)
        let askedAt = Date(timeIntervalSince1970: 1234)
        let turnID = UUID()
        let turn = ConversationTurn(
            id: turnID,
            question: exchange.question,
            askedAt: askedAt,
            responseStartedAt: askedAt,
            answer: AskResult(restored: exchange),
            answeredAt: askedAt
        )

        XCTAssertEqual(turn.id, turnID)
        XCTAssertEqual(turn.askedAt, askedAt)
        XCTAssertEqual(turn.answer?.summary, "历史回答")
        XCTAssertEqual(turn.answer?.fields["结论"], "已恢复")
    }

    func testDroppedCodeFileRemainsTheExactScanScope() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("main.go")
        try Data("package main\n".utf8).write(to: file)

        XCTAssertEqual(try taskWorkspaceRoot(for: file), file.standardizedFileURL)
        XCTAssertEqual(try taskWorkspaceRoot(for: root), root.standardizedFileURL)
    }

    func testUnsupportedDroppedFileIsRejected() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("notes.pdf")
        try Data("not source code".utf8).write(to: file)

        XCTAssertThrowsError(try taskWorkspaceRoot(for: file))
    }

    func testDependencyManifestCanBeAnExactScanScope() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("requirements.txt")
        try Data("requests==2.32.4\n".utf8).write(to: file)

        XCTAssertEqual(try taskWorkspaceRoot(for: file), file.standardizedFileURL)
    }

    func testDotNetAndNativeManifestsCanBeExactScanScopes() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let files = ["App.csproj", "Directory.Packages.props", "packages.lock.json", "openssl.wrap"]

        for name in files {
            let file = root.appendingPathComponent(name)
            try Data("manifest\n".utf8).write(to: file)
            XCTAssertEqual(try taskWorkspaceRoot(for: file), file.standardizedFileURL)
        }
    }

    func testSeverityLabelsAreChineseAndUseDistinctTones() {
        XCTAssertEqual(severityLabel("CRITICAL"), "严重")
        XCTAssertEqual(severityLabel(" high "), "高危")
        XCTAssertEqual(severityLabel("MEDIUM"), "中危")
        XCTAssertEqual(severityLabel("LOW"), "低危")
        XCTAssertEqual(StatusTone.severity("CRITICAL").color, AppPalette.danger)
        XCTAssertEqual(StatusTone.severity("HIGH").color, AppPalette.warning)
        XCTAssertEqual(StatusTone.severity("MEDIUM").color, AppPalette.medium)
        XCTAssertEqual(StatusTone.severity("LOW").color, AppPalette.primary)
    }

    func testExpectedCancellationRecognizesSwiftURLAndFilePickerCancellation() {
        XCTAssertTrue(isExpectedCancellation(CancellationError()))
        XCTAssertTrue(isExpectedCancellation(URLError(.cancelled)))
        XCTAssertTrue(isExpectedCancellation(CocoaError(.userCancelled)))
        XCTAssertFalse(isExpectedCancellation(URLError(.timedOut)))
    }

    func testAssistantComposerSuggestionsFollowCommandPrefixes() {
        XCTAssertEqual(assistantComposerSuggestions(for: "/").map(\.id), ["scan", "cve", "report", "code-review"])
        XCTAssertEqual(assistantComposerSuggestions(for: "/co").map(\.id), ["code-review"])
        XCTAssertEqual(assistantComposerSuggestions(for: "@sec").map(\.id), ["agent"])
        XCTAssertEqual(assistantComposerSuggestions(for: "#漏").map(\.id), ["knowledge"])
        XCTAssertTrue(assistantComposerSuggestions(for: "普通安全问题").isEmpty)
    }

    func testAssistantMarkdownParsesSecurityAnswerBlocks() {
        let markdown = """
        # 漏洞摘要
        > 已核验事实

        | 漏洞 | CVSS |
        | --- | ---: |
        | CVE-2026-1 | 9.8 |

        ```swift
        let safe = true
        ```

        ```mermaid
        flowchart TD
        A[查询] --> B[核验]
        ```
        """

        let blocks = AssistantMarkdownBlock.parse(markdown)

        XCTAssertTrue(blocks.contains(.line("# 漏洞摘要")))
        XCTAssertTrue(blocks.contains(.quote("已核验事实")))
        XCTAssertTrue(blocks.contains(.table(headers: ["漏洞", "CVSS"], rows: [["CVE-2026-1", "9.8"]])))
        XCTAssertTrue(blocks.contains(.code(language: "swift", content: "let safe = true")))
        XCTAssertTrue(blocks.contains(.code(language: "mermaid", content: "flowchart TD\nA[查询] --> B[核验]")))
    }
}
