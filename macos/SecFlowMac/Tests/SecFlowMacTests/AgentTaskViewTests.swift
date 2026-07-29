import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class AgentTaskViewTests: XCTestCase {
    func testCompletedTaskHidesHistoricalRunningHeartbeats() {
        let events = [
            AgentTaskEvent(sequence: 1, type: "node.started", node: "scan_java", status: "running", message: "开始扫描", time: "2026-07-29T10:33:10+00:00"),
            AgentTaskEvent(sequence: 2, type: "node.progress", node: "scan_java", status: "running", message: "已运行 30 秒", time: "2026-07-29T10:33:40+00:00"),
            AgentTaskEvent(sequence: 3, type: "node.completed", node: "scan_java", status: "completed", message: "扫描完成", time: "2026-07-29T10:35:07+00:00"),
            AgentTaskEvent(sequence: 4, type: "task.completed", node: "compose_result", status: "completed", message: "任务完成", time: "2026-07-29T10:35:11+00:00"),
        ]

        XCTAssertEqual(
            visibleAgentTaskEvents(events, taskStatus: "completed").map(\.sequence),
            [3, 4]
        )
    }

    func testRunningTaskShowsOnlyLatestHeartbeatForNode() {
        let events = [
            AgentTaskEvent(sequence: 1, type: "node.started", node: "scan_java", status: "running", message: "开始扫描", time: "2026-07-29T10:33:10+00:00"),
            AgentTaskEvent(sequence: 2, type: "node.progress", node: "scan_java", status: "running", message: "已运行 30 秒", time: "2026-07-29T10:33:40+00:00"),
            AgentTaskEvent(sequence: 3, type: "node.progress", node: "scan_java", status: "running", message: "已运行 60 秒", time: "2026-07-29T10:34:10+00:00"),
        ]

        XCTAssertEqual(
            visibleAgentTaskEvents(events, taskStatus: "running").map(\.sequence),
            [3]
        )
    }

    func testRunningAgentNodeHidesSkillAndPromptContent() {
        let data: [String: JSONValue] = [
            "iteration": .number(1),
            "skill": .string("full skill body"),
            "prompt_version": .string("private-prompt-v1"),
            "system_message": .string("private instructions"),
            "presentation": .object([
                "kind": .string("prompt_diff"),
                "title": .string("Skill prompt"),
                "before": .string("before"),
                "after": .string("full skill body"),
            ]),
        ]

        XCTAssertNil(visibleAgentTaskPresentation(from: data))
        XCTAssertEqual(agentTaskEventFields(data), ["iteration": "1"])
    }

    func testAssistantRegenerationReusesOnlyEligibleConversationQuestions() {
        let turn = ConversationTurn(question: "  分析 CVE-2026-55576  ")
        let taskTurn = ConversationTurn(question: "扫描项目", agentTaskID: "task-1")

        XCTAssertEqual(
            assistantRegenerationQuestion(for: turn, isBusy: false),
            "分析 CVE-2026-55576"
        )
        XCTAssertNil(assistantRegenerationQuestion(for: turn, isBusy: true))
        XCTAssertNil(assistantRegenerationQuestion(for: taskTurn, isBusy: false))
    }

    @MainActor
    func testLangGraphNodeCardsRenderAtChatColumnWidth() throws {
        let model = AppModel()
        let prompt = LangGraphNodePresentation(
            kind: "prompt_diff",
            title: "Project Overlay Prompt Changes",
            toolName: nil,
            state: nil,
            input: nil,
            output: nil,
            error: nil,
            before: "You are a helpful assistant.\nAnswer questions concisely.",
            after: "You are a senior security engineer.\nUse project-specific taint evidence.\nExplain verified source-to-sink paths."
        )
        let toolStates = [
            LangGraphNodePresentation(
                kind: "tool_call",
                title: "Excel MCP",
                toolName: "export_component_vulnerabilities_excel",
                state: "completed",
                input: ["component": "org.example:demo", "version": "2.3.0"],
                output: "Found 5 verified component vulnerabilities and generated the audit workbook.",
                error: nil,
                before: nil,
                after: nil
            ),
            LangGraphNodePresentation(
                kind: "tool_call",
                title: nil,
                toolName: "build_component_sankey",
                state: "running",
                input: nil,
                output: nil,
                error: nil,
                before: nil,
                after: nil
            ),
            LangGraphNodePresentation(
                kind: "tool_call",
                title: nil,
                toolName: "prepare_report_download",
                state: "awaiting-approval",
                input: ["format": "pdf"],
                output: nil,
                error: nil,
                before: nil,
                after: nil
            ),
            LangGraphNodePresentation(
                kind: "tool_call",
                title: nil,
                toolName: "api_request",
                state: "error",
                input: ["endpoint": "https://api.example.test/data"],
                output: nil,
                error: "Connection timeout after 30s",
                before: nil,
                after: nil
            ),
        ]
        let size = NSSize(width: 620, height: 650)
        let content = ScrollView {
            VStack(spacing: 10) {
                LangGraphNodePresentationView(presentation: prompt)
                ForEach(Array(toolStates.enumerated()), id: \.offset) { _, presentation in
                    LangGraphNodePresentationView(presentation: presentation)
                }
            }
            .padding(12)
        }
        .environmentObject(model)
        .frame(width: size.width, height: size.height)
        .background(AppPalette.page)
        let hostingView = NSHostingView(rootView: content)
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 20_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_LANGGRAPH_NODE_CARDS_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testComponentVulnerabilityDetailRendersReferenceLayout() throws {
        let model = AppModel()
        model.previewAppearance(darkMode: false, fontSize: "default")
        let payload = ComponentVulnerabilityDetailPayload(
            schemaVersion: 1,
            renderer: "component-vulnerability-detail",
            component: ComponentVulnerabilityCoordinate(name: "commons-compress", version: "1.21", ecosystem: "Maven"),
            total: 1,
            previewCount: 1,
            truncated: false,
            vulnerabilities: [
                ComponentVulnerabilityDetailItem(
                    id: "CVE-2021-35516",
                    title: "Apache Commons Compress 存在拒绝服务风险",
                    severity: "MEDIUM",
                    severityLabel: "中危",
                    description: "该组件版本需要结合已核验的影响范围和资产暴露情况进行处置。",
                    vulnerabilityType: "CWE-400",
                    aliases: ["CVE-2021-35516"],
                    cwes: ["CWE-400"],
                    publishedAt: "2021-07-13T00:00:00+00:00",
                    updatedAt: "2026-07-29T00:00:00+00:00",
                    affectedPackages: [
                        ComponentDetailAffectedPackage(
                            name: "org.apache.commons:commons-compress",
                            ecosystem: "Maven",
                            affectedVersions: ["[1.6, 1.21)"],
                            fixedVersions: ["1.21"]
                        )
                    ],
                    affectedVersions: ["[1.6, 1.21)"],
                    fixedVersions: ["1.21"],
                    remediation: "建议升级到已确认修复版本：1.21",
                    exploitStatus: "未明确",
                    exploitStatusCode: "unknown",
                    exploitDifficulty: "较低",
                    referenceLinks: [
                        ComponentDetailReference(title: "NVD 漏洞详情", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-35516")
                    ],
                    cvss: ComponentDetailCVSS(
                        score: 7.5,
                        rating: "高危",
                        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        version: "3.1",
                        metrics: [
                            ComponentDetailCVSSMetric(key: "AV", label: "攻击向量", value: "网络"),
                            ComponentDetailCVSSMetric(key: "AC", label: "攻击复杂性", value: "低"),
                            ComponentDetailCVSSMetric(key: "PR", label: "所需权限", value: "无"),
                            ComponentDetailCVSSMetric(key: "UI", label: "用户交互", value: "无"),
                            ComponentDetailCVSSMetric(key: "S", label: "影响范围", value: "不变"),
                            ComponentDetailCVSSMetric(key: "C", label: "机密性影响", value: "无"),
                            ComponentDetailCVSSMetric(key: "I", label: "完整性影响", value: "无"),
                            ComponentDetailCVSSMetric(key: "A", label: "可用性影响", value: "高"),
                        ]
                    )
                )
            ],
            generatedAt: "2026-07-29T00:00:00+00:00"
        )
        let size = NSSize(width: 940, height: 820)
        let hostingView = NSHostingView(
            rootView: ScrollView {
                ComponentVulnerabilityDetailView(payload: payload)
                    .environmentObject(model)
                    .padding(22)
            }
            .appAppearance(model: model)
            .appTypography()
            .frame(width: size.width, height: size.height)
            .background(AppPalette.page)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.25))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 35_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_COMPONENT_DETAIL_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_COMPONENT_DETAIL_DARK_SNAPSHOT"] {
            model.previewAppearance(darkMode: true, fontSize: "default")
            RunLoop.main.run(until: Date().addingTimeInterval(0.25))
            hostingView.layoutSubtreeIfNeeded()
            let darkBitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
            hostingView.cacheDisplay(in: hostingView.bounds, to: darkBitmap)
            let darkPNG = try XCTUnwrap(darkBitmap.representation(using: .png, properties: [:]))

            XCTAssertNotEqual(png, darkPNG)
            try darkPNG.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testAssistantPageRendersUnifiedComposerAtAppWindowSize() throws {
        let model = AppModel()
        model.agentTasks = []
        model.activeAgentTask = nil
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(loadsAgentTasks: false)
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 12_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_COMPOSER_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testAssistantComposerRendersSelectedFilePreview() throws {
        let model = AppModel()
        model.agentTasks = []
        model.activeAgentTask = nil
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(
                loadsAgentTasks: false,
                initialTaskWorkspacePath: #filePath
            )
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 12_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_ATTACHMENT_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testAssistantPageRendersLiveAnswerProcessingTimeline() throws {
        let model = AppModel()
        model.profileSettings = sampleProfile()
        model.profileAvatarImageData = try sampleAvatarData()
        model.isAsking = true
        model.activeTrace = sampleAssistantTrace()
        model.conversationTurns = [
            ConversationTurn(
                question: "请分析 CVE-2026-55576 的影响范围和修复建议",
                processingTrace: sampleAssistantTrace()
            )
        ]
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(loadsAgentTasks: false)
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 18_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_PROCESS_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testAssistantPageRendersCompletedAnswerProcessSummary() throws {
        let model = AppModel()
        var turn = ConversationTurn(question: "如何修复这个依赖漏洞？")
        turn.answer = try sampleAssistantAnswer()
        turn.answeredAt = turn.askedAt.addingTimeInterval(12)
        model.conversationTurns = [turn]
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(loadsAgentTasks: false)
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 15_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_COMPLETE_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testAssistantPageRendersLongConversationHistoryWithoutEmptyViewport() throws {
        let model = AppModel()
        let answer = try sampleAssistantAnswer()
        model.conversationTurns = (0..<80).map { index in
            var turn = ConversationTurn(
                question: "历史问题 \(index + 1)：请说明这项安全风险的影响和修复建议。"
            )
            turn.answer = answer
            turn.answeredAt = turn.askedAt.addingTimeInterval(2)
            return turn
        }
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(loadsAgentTasks: false)
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.25))
        hostingView.layoutSubtreeIfNeeded()

        let conversationScrollView = try XCTUnwrap(
            descendantScrollViews(of: hostingView)
                .filter { ($0.documentView?.bounds.height ?? 0) > $0.contentView.bounds.height * 3 }
                .max { ($0.documentView?.bounds.height ?? 0) < ($1.documentView?.bounds.height ?? 0) }
        )
        let documentHeight = try XCTUnwrap(conversationScrollView.documentView?.bounds.height)
        let maximumOffset = max(0, documentHeight - conversationScrollView.contentView.bounds.height)
        conversationScrollView.contentView.scroll(to: NSPoint(x: 0, y: maximumOffset * 0.5))
        conversationScrollView.reflectScrolledClipView(conversationScrollView.contentView)
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()

        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 18_000)
    }

    @MainActor
    func testAssistantPageRendersErrorBubbleActions() throws {
        let model = AppModel()
        var turn = ConversationTurn(question: "分析当前依赖风险")
        turn.errorMessage = "模型服务暂时不可用，请稍后重试。"
        turn.answeredAt = Date()
        turn.processingTrace = sampleAssistantTrace()
        model.conversationTurns = [turn]
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(loadsAgentTasks: false)
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 15_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_ERROR_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testAssistantPageRendersComponentQuerySankeyAndExcelArtifact() throws {
        let model = AppModel()
        var turn = ConversationTurn(question: "查询 PyPI demo 2.3.0 组件漏洞")
        turn.answer = try sampleComponentQueryAnswer()
        turn.answeredAt = turn.askedAt.addingTimeInterval(4)
        model.conversationTurns = [turn]
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(loadsAgentTasks: false)
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.8))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 24_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_COMPONENT_QUERY_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testCompletedTaskRendersInsideAssistantConversation() throws {
        let model = AppModel()
        model.profileSettings = sampleProfile()
        model.profileAvatarImageData = try sampleAvatarData()
        XCTAssertEqual(model.currentProfileDisplayName, "测试用户")
        let task = sampleTask()
        model.agentTasks = [task]
        model.activeAgentTask = task
        model.conversationTurns = [
            ConversationTurn(
                question: task.objective,
                attachmentNames: [task.workspaceName],
                agentTaskID: task.id
            )
        ]
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AssistantView(loadsAgentTasks: false)
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        defer { window.close() }

        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 20_000)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ASSISTANT_TASK_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    private func sampleProfile() -> UserProfileSettingsSnapshot {
        UserProfileSettingsSnapshot(
            displayName: "测试用户",
            email: "analyst@example.test",
            phone: "",
            department: "安全研发",
            role: "安全分析师",
            employeeId: "",
            bio: "",
            avatarFileName: "avatar.png",
            avatarContentType: "image/png",
            avatarUpdatedAt: "2026-07-22T12:00:00+00:00",
            updatedAt: "2026-07-22T12:00:00+00:00",
            avatarAvailable: true
        )
    }

    private func sampleAssistantTrace() -> [TraceItem] {
        [
            TraceItem(
                node: "classify_query",
                status: "completed",
                message: "已识别为漏洞查询。",
                time: "2026-07-22T10:00:00+00:00"
            ),
            TraceItem(
                node: "load_memory_context",
                status: "completed",
                message: "已召回长期记忆：历史 8 条，相关 2 条。",
                time: "2026-07-22T10:00:01+00:00"
            ),
            TraceItem(
                node: "query_intelligence",
                status: "completed",
                message: "实时接口返回 3 条归并记录。",
                time: "2026-07-22T10:00:02+00:00"
            ),
            TraceItem(
                node: "enrich_knowledge_graph",
                status: "warning",
                message: "已关联 6 个图节点和 8 条边。",
                time: "2026-07-22T10:00:03+00:00"
            ),
        ]
    }

    private func sampleAssistantAnswer() throws -> AskResult {
        let json = #"""
        {
          "mode": "llm_direct",
          "summary": "建议先确认受影响组件的实际版本，再升级到厂商确认的安全版本，并在测试环境完成兼容性与回归验证。",
          "fields": {},
          "vulnerability_card": {},
          "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
          "chart_data": {},
          "confidence": 0.86,
          "trace": [
            {"node": "classify_query", "status": "completed", "message": "已识别问题意图。", "time": "2026-07-22T10:00:00+00:00"},
            {"node": "load_memory_context", "status": "completed", "message": "已加载长期记忆。", "time": "2026-07-22T10:00:01+00:00"},
            {"node": "call_llm", "status": "completed", "message": "模型调用成功。", "time": "2026-07-22T10:00:10+00:00"},
            {"node": "compose_answer", "status": "completed", "message": "已生成最终回答。", "time": "2026-07-22T10:00:11+00:00"},
            {"node": "persist_memory", "status": "completed", "message": "已写入长期记忆。", "time": "2026-07-22T10:00:12+00:00"}
          ],
          "generated_at": "2026-07-22T10:00:12+00:00"
        }
        """#.data(using: .utf8)!
        return try JSONDecoder.secFlow.decode(AskResult.self, from: json)
    }

    private func sampleComponentQueryAnswer() throws -> AskResult {
        let json = #"""
        {
          "mode": "component_vulnerability_query",
          "summary": "已核验 PyPI / demo / 2.3.0，确认 1 条影响当前版本的漏洞记录：\n- CVE-2026-10001 | 高危 | 修复: 2.4.1",
          "fields": {"组件名称": "demo", "组件版本": "2.3.0", "确认漏洞数量": "1"},
          "vulnerability_card": {},
          "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
          "chart_data": {
            "schema_version": 1,
            "sankey": {
              "nodes": [
                {"id": "c:1", "label": "demo", "type": "component", "column": 0, "ecosystem": "PyPI"},
                {"id": "v:1", "label": "CVE-2026-10001", "type": "vulnerability", "severity": "HIGH", "column": 1},
                {"id": "f:1", "label": "2.4.1", "type": "fix", "column": 2, "version": "2.4.1"}
              ],
              "links": [
                {"from": "c:1", "to": "v:1", "type": "AFFECTED_BY", "value": 1, "severity": "HIGH"},
                {"from": "v:1", "to": "f:1", "type": "FIXED_BY", "value": 1, "severity": "HIGH"}
              ]
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
          "trace": [
            {"node": "component_query.parse_coordinates", "status": "completed", "message": "已识别组件坐标。", "time": "2026-07-26T00:00:00+00:00"},
            {"node": "component_query.query_vulnerabilities", "status": "completed", "message": "组件版本核验完成。", "time": "2026-07-26T00:00:01+00:00"},
            {"node": "component_query.excel_mcp", "status": "completed", "message": "已生成 Excel。", "time": "2026-07-26T00:00:02+00:00"},
            {"node": "component_query.d3_sankey_mcp", "status": "completed", "message": "已生成桑基图。", "time": "2026-07-26T00:00:03+00:00"}
          ],
          "generated_at": "2026-07-26T00:00:04+00:00"
        }
        """#.data(using: .utf8)!
        return try JSONDecoder.secFlow.decode(AskResult.self, from: json)
    }

    private func sampleAvatarData() throws -> Data {
        let pixels = 64
        let bitmap = try XCTUnwrap(
            NSBitmapImageRep(
                bitmapDataPlanes: nil,
                pixelsWide: pixels,
                pixelsHigh: pixels,
                bitsPerSample: 8,
                samplesPerPixel: 4,
                hasAlpha: true,
                isPlanar: false,
                colorSpaceName: .deviceRGB,
                bytesPerRow: 0,
                bitsPerPixel: 0
            )
        )
        let context = try XCTUnwrap(NSGraphicsContext(bitmapImageRep: bitmap))
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        NSColor.systemPink.setFill()
        NSBezierPath(rect: NSRect(x: 0, y: 0, width: pixels, height: pixels)).fill()
        NSGraphicsContext.restoreGraphicsState()
        return try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
    }

    private func sampleTask() -> AgentTaskSnapshot {
        let syntax = AgentSyntaxSummary(
            languages: ["python"],
            parsedFiles: 12,
            parseErrorFiles: 0,
            astNodeCount: 1_284,
            cfgNodeCount: 188,
            cfgEdgeCount: 231,
            dfgEdgeCount: 146
        )
        let python = AgentLanguageScanResult(
            language: "python",
            status: "completed",
            mode: "bundled-cli",
            fileCount: 12,
            files: ["app/main.py", "app/service.py"],
            ruleFiles: ["python-security.yml"],
            syntaxSummary: syntax,
            findingCount: 1,
            findings: [
                AgentFindingSummary(
                    id: "finding-python",
                    ruleId: "secflow.python.command-injection",
                    title: "命令注入风险",
                    severity: "HIGH",
                    fileName: "app/service.py",
                    line: 48,
                    description: "外部输入未经约束进入命令执行函数。"
                )
            ],
            reviewFindingCount: 0,
            reviewFindings: [],
            diagnostics: []
        )
        return AgentTaskSnapshot(
            id: "task-preview",
            objective: "扫描当前项目并按语言汇总代码风险",
            workspacePath: "/Users/analyst/Projects/security-service",
            workspaceName: "security-service",
            workspaceType: "directory",
            userId: "analyst",
            status: "completed",
            currentNode: "compose_result",
            languages: ["python"],
            plan: [
                AgentTaskPlanStep(id: "inspect", title: "检查工作区与识别语言", node: "inspect_workspace", status: "completed", language: ""),
                AgentTaskPlanStep(id: "dependencies", title: "识别项目依赖与组件", node: "scan_dependencies", status: "completed", language: ""),
                AgentTaskPlanStep(id: "language-python", title: "执行 Python 专属规则和 AST/CFG/DFG 扫描", node: "scan_python", status: "completed", language: "python"),
                AgentTaskPlanStep(id: "verify", title: "验证并汇总扫描结果", node: "verify_results", status: "completed", language: ""),
            ],
            events: [
                AgentTaskEvent(sequence: 1, type: "task.started", node: "inspect_workspace", status: "completed", message: "已纳入 12 个源文件和 1 个项目清单。", time: "2026-07-22T10:00:00+00:00"),
                AgentTaskEvent(sequence: 2, type: "languages.detected", node: "detect_languages", status: "completed", message: "项目语言识别完成：Python。", time: "2026-07-22T10:00:01+00:00"),
                AgentTaskEvent(sequence: 3, type: "node.completed", node: "scan_python", status: "completed", message: "Python 扫描完成：12 个文件，1 条发现。", time: "2026-07-22T10:00:02+00:00"),
            ],
            result: AgentTaskResult(
                summary: "已按 Python 分派专属扫描节点，完成 12 个源文件的规则扫描与 AST/CFG/DFG 分析，识别 8 个依赖组件和 1 条代码风险。",
                scanMode: "adaptive_upload",
                languages: ["python"],
                dependencyCount: 8,
                dependencies: [
                    AgentDependencySummary(
                        ecosystem: "PyPI",
                        name: "requests",
                        version: "2.32.4",
                        sourceFile: "requirements.txt",
                        sourceType: "python_manifest",
                        declaration: "requests==2.32.4",
                        confidence: "high"
                    ),
                ],
                totalFiles: 12,
                totalFindings: 1,
                totalReviewFindings: 0,
                languageResults: ["python": python],
                projectProfile: AgentProjectProfile(
                    scope: "directory",
                    workspaceName: "security-service",
                    scopeFingerprint: "project-scope-fingerprint",
                    languages: ["python"],
                    manifestFiles: ["requirements.txt"],
                    buildSystems: ["python-requirements"],
                    frameworks: ["requests"],
                    dependencyCount: 8,
                    adaptiveEnabled: true,
                    evaluationIsolation: false,
                    skill: AgentAdaptiveSkill(
                        name: "secflow-project-adaptive-scan",
                        sha256: "skill-sha256",
                        promptVersion: "secflow-project-adaptive-scan-v1"
                    )
                ),
                adaptation: AgentAdaptationSummary(
                    enabled: true,
                    mode: "adaptive_upload",
                    status: "no_change",
                    attempts: 1,
                    iterations: 0,
                    overlayFingerprints: [],
                    nextAction: "",
                    terminationReason: "no_change",
                    skill: AgentAdaptiveSkill(
                        name: "secflow-project-adaptive-scan",
                        sha256: "skill-sha256",
                        promptVersion: "secflow-project-adaptive-scan-v1"
                    ),
                    baselineMetrics: AgentAdaptationMetrics(
                        findings: 1,
                        reviewFindings: 0,
                        parsedFiles: 12,
                        parseErrorFiles: 0,
                        cfgEdges: 231,
                        dfgEdges: 146
                    ),
                    currentMetrics: AgentAdaptationMetrics(
                        findings: 1,
                        reviewFindings: 0,
                        parsedFiles: 12,
                        parseErrorFiles: 0,
                        cfgEdges: 231,
                        dfgEdges: 146
                    )
                )
            ),
            reportDecision: "pending",
            report: nil,
            error: "",
            archived: false,
            archivedAt: nil,
            createdAt: "2026-07-22T10:00:00+00:00",
            updatedAt: "2026-07-22T10:00:02+00:00"
        )
    }

    private func nonWhitePixelCount(_ bitmap: NSBitmapImageRep) -> Int {
        var count = 0
        for y in stride(from: 0, to: bitmap.pixelsHigh, by: 4) {
            for x in stride(from: 0, to: bitmap.pixelsWide, by: 4) {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { continue }
                if color.redComponent < 0.97 || color.greenComponent < 0.97 || color.blueComponent < 0.97 {
                    count += 16
                }
            }
        }
        return count
    }

    private func descendantScrollViews(of view: NSView) -> [NSScrollView] {
        let current = view as? NSScrollView
        return [current].compactMap { $0 } + view.subviews.flatMap(descendantScrollViews)
    }
}
