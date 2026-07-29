import AppKit
import Combine
import SwiftUI
import XCTest
@testable import SecFlowMac

final class WorkspaceShellViewTests: XCTestCase {
    @MainActor
    func testCollapsedSidebarContainsNativeWindowControlsWithoutReplacingFullscreenAction() throws {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        let controls = try [
            NSWindow.ButtonType.closeButton,
            .miniaturizeButton,
            .zoomButton,
        ].map { type in
            try XCTUnwrap(window.standardWindowButton(type))
        }
        let trailingEdge = try controls.map { button in
            let parent = try XCTUnwrap(button.superview)
            return parent.convert(button.frame, to: nil).maxX
        }.max() ?? 0
        let fullscreenButton = try XCTUnwrap(window.standardWindowButton(.zoomButton))

        XCTAssertGreaterThanOrEqual(WorkspaceSidebarLayout.collapsedWidth, trailingEdge + 3)
        XCTAssertTrue(fullscreenButton.isEnabled)
        XCTAssertFalse(fullscreenButton.isHidden)
        XCTAssertNotNil(fullscreenButton.action)
    }

    @MainActor
    func testWindowChromeSuppressesDynamicProviderTitle() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Sub2API"
        window.subtitle = "GPT-5.6 Sol"

        clearNativeWindowTitle(window)

        XCTAssertEqual(window.title, "")
        XCTAssertEqual(window.subtitle, "")
        XCTAssertEqual(window.titleVisibility, .hidden)
    }

    @MainActor
    func testWorkspaceRendersCodexStyleSidebarAtAppWindowSize() throws {
        let model = AppModel()
        model.agentTasks = []
        model.archivedAgentTasks = []
        model.activeAgentTask = nil
        let navigation = WorkspaceNavigationModel(isSidebarCollapsed: false)
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: WorkspaceShellView(loadsData: false)
                .environmentObject(model)
                .environmentObject(navigation)
                .environmentObject(InformationPanelPresenter())
                .preferredColorScheme(.light)
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
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 18_000)
        XCTAssertEqual(bitmap.pixelsWide, Int(size.width * window.backingScaleFactor))
        assertSidebarUsesBlueVibrancy(
            bitmap,
            width: WorkspaceSidebarLayout.expandedWidth,
            scale: window.backingScaleFactor
        )
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_WORKSPACE_SIDEBAR_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testNewTaskNavigationResetsToAssistant() {
        let navigation = WorkspaceNavigationModel()

        navigation.startNewTask()

        XCTAssertEqual(navigation.destination, .assistant)
        XCTAssertEqual(navigation.newTaskRequest, 1)
    }

    @MainActor
    func testSidebarExpandsOnHoverAndCollapsesOnExitWithoutChangingDestination() {
        let navigation = WorkspaceNavigationModel(isSidebarCollapsed: true)
        var navigationChangeCount = 0
        let observation = navigation.objectWillChange.sink {
            navigationChangeCount += 1
        }
        defer { observation.cancel() }

        navigation.setSidebarHovered(true)
        XCTAssertFalse(navigation.isSidebarCollapsed)
        XCTAssertEqual(navigation.destination, .assistant)
        XCTAssertEqual(navigationChangeCount, 0)

        navigation.setSidebarHovered(false)
        XCTAssertTrue(navigation.isSidebarCollapsed)
        XCTAssertEqual(navigation.destination, .assistant)
        XCTAssertEqual(navigationChangeCount, 0)
        XCTAssertEqual(WorkspaceSidebarLayout.collapsedWidth, 72)
    }

    @MainActor
    func testProjectRenameRejectsBlankNamesAndPersistsByProjectID() throws {
        let suiteName = "WorkspaceShellViewTests.projectRename.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let navigation = WorkspaceNavigationModel(
            isSidebarCollapsed: false,
            projectNames: [:],
            defaults: defaults
        )

        XCTAssertFalse(navigation.renameProject(id: "/tmp/sample-project", to: "   "))
        XCTAssertEqual(
            navigation.projectName(id: "/tmp/sample-project", fallback: "sample-project"),
            "sample-project"
        )
        XCTAssertTrue(navigation.renameProject(id: "/tmp/sample-project", to: "  支付安全平台  "))

        let restored = WorkspaceNavigationModel(isSidebarCollapsed: false, defaults: defaults)
        XCTAssertEqual(
            restored.projectName(id: "/tmp/sample-project", fallback: "sample-project"),
            "支付安全平台"
        )
    }

    @MainActor
    func testConversationHistoryIsRepresentedAsAssistantProjectAndArchivedCollection() {
        let model = AppModel()
        model.assistantConversations = [
            AssistantConversationSummary(
                id: "active-conversation",
                title: "活动对话",
                updatedAt: "2026-07-27T12:00:00+00:00",
                turnCount: 2
            )
        ]
        model.archivedAssistantConversations = [
            AssistantConversationSummary(
                id: "archived-conversation",
                title: "已归档对话",
                updatedAt: "2026-07-27T11:00:00+00:00",
                turnCount: 1,
                archived: true,
                archivedAt: "2026-07-27T12:30:00+00:00"
            )
        ]

        XCTAssertEqual(model.assistantConversations.first?.projectId, "assistant")
        XCTAssertEqual(model.assistantConversations.first?.projectName, "智能问答")
        XCTAssertFalse(model.assistantConversations.first?.archived ?? true)
        XCTAssertTrue(model.archivedAssistantConversations.first?.archived ?? false)
    }

    @MainActor
    func testWorkspaceRendersCollapsedSidebarAtMinimumWindowSize() throws {
        let model = AppModel()
        model.agentTasks = []
        model.archivedAgentTasks = []
        model.activeAgentTask = nil
        let navigation = WorkspaceNavigationModel(isSidebarCollapsed: true)
        let size = NSSize(width: 960, height: 620)
        let hostingView = NSHostingView(
            rootView: WorkspaceShellView(loadsData: false)
                .environmentObject(model)
                .environmentObject(navigation)
                .environmentObject(InformationPanelPresenter())
                .preferredColorScheme(.light)
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
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 12_000)
        XCTAssertEqual(bitmap.pixelsWide, Int(size.width * window.backingScaleFactor))
        assertSidebarUsesBlueVibrancy(
            bitmap,
            width: WorkspaceSidebarLayout.collapsedWidth,
            scale: window.backingScaleFactor
        )
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_WORKSPACE_COLLAPSED_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
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

    private func assertSidebarUsesBlueVibrancy(
        _ bitmap: NSBitmapImageRep,
        width: CGFloat,
        scale: CGFloat,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let inset = max(4, Int(8 * scale))
        let maxX = min(bitmap.pixelsWide - inset, Int(width * scale) - inset)
        let minY = Int(Double(bitmap.pixelsHigh) * 0.48)
        let maxY = Int(Double(bitmap.pixelsHigh) * 0.72)
        var red: [Int] = []
        var green: [Int] = []
        var blue: [Int] = []

        for y in stride(from: minY, to: maxY, by: 8) {
            for x in stride(from: inset, to: maxX, by: 8) {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { continue }
                red.append(Int((color.redComponent * 255).rounded()))
                green.append(Int((color.greenComponent * 255).rounded()))
                blue.append(Int((color.blueComponent * 255).rounded()))
            }
        }

        XCTAssertFalse(red.isEmpty, file: file, line: line)
        let medianRed = median(red)
        let medianGreen = median(green)
        let medianBlue = median(blue)
        XCTAssertGreaterThan(medianRed, 170, file: file, line: line)
        XCTAssertLessThan(medianBlue, 252, file: file, line: line)
        XCTAssertGreaterThan(medianGreen, medianRed + 5, file: file, line: line)
        XCTAssertGreaterThan(medianBlue, medianGreen + 4, file: file, line: line)
    }

    private func median(_ values: [Int]) -> Int {
        let sorted = values.sorted()
        return sorted[sorted.count / 2]
    }
}
