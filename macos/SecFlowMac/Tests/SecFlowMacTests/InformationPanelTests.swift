import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class InformationPanelTests: XCTestCase {
    @MainActor
    func testInformationUsesIndependentFloatingPanel() throws {
        let presenter = InformationPanelPresenter()
        presenter.show(model: AppModel())
        let panel = try XCTUnwrap(presenter.panel)
        defer { presenter.close() }

        XCTAssertTrue(panel.isFloatingPanel)
        XCTAssertFalse(panel.hidesOnDeactivate)
        XCTAssertTrue(panel.styleMask.contains(.nonactivatingPanel))
        XCTAssertFalse(panel.styleMask.contains(.titled))
        XCTAssertFalse(panel.styleMask.contains(.resizable))
        XCTAssertEqual(panel.level, .floating)
        XCTAssertEqual(panel.contentMinSize, InformationPanelMetrics.defaultSize)
        XCTAssertEqual(panel.contentMaxSize, InformationPanelMetrics.defaultSize)
        XCTAssertFalse(panel.isMovable)
        XCTAssertTrue(panel.collectionBehavior.contains(.canJoinAllSpaces))
        XCTAssertTrue(panel.collectionBehavior.contains(.stationary))
    }

    @MainActor
    func testInformationPanelRendersCompactTicker() throws {
        let model = AppModel()
        model.information = sampleInformation()

        let size = InformationPanelMetrics.defaultSize
        let rendered = try renderInformationPanel(
            model: model,
            size: size,
            snapshotEnvironmentKey: "SECFLOW_INFORMATION_PANEL_SNAPSHOT"
        )

        XCTAssertGreaterThan(nonWhitePixelCount(rendered.bitmap), 120_000)
        XCTAssertEqual(rendered.bitmap.pixelsWide, Int(size.width * rendered.scale))
        XCTAssertEqual(rendered.bitmap.pixelsHigh, Int(size.height * rendered.scale))
    }

    @MainActor
    func testInformationPanelRendersCompactTickerInDarkMode() throws {
        let model = AppModel()
        model.information = sampleInformation()

        let size = InformationPanelMetrics.defaultSize
        let rendered = try renderInformationPanel(
            model: model,
            size: size,
            snapshotEnvironmentKey: "SECFLOW_INFORMATION_PANEL_DARK_SNAPSHOT",
            colorScheme: .dark
        )

        XCTAssertGreaterThan(nonWhitePixelCount(rendered.bitmap), 120_000)
        XCTAssertEqual(rendered.bitmap.pixelsWide, Int(size.width * rendered.scale))
        XCTAssertEqual(rendered.bitmap.pixelsHigh, Int(size.height * rendered.scale))
    }

    func testInformationPanelAnchorsBelowMenuBarButton() {
        let frame = informationPopoverFrame(
            visibleFrame: NSRect(x: 100, y: 40, width: 1400, height: 900),
            buttonFrame: NSRect(x: 780, y: 930, width: 24, height: 24),
            panelSize: NSSize(width: 280, height: 650),
            margin: 8
        )

        XCTAssertEqual(frame, NSRect(x: 652, y: 285, width: 280, height: 650))
    }

    func testInformationPopoverShapeIncludesMenuBarPointer() {
        let path = InformationPopoverShape().path(in: NSRect(x: 0, y: 0, width: 280, height: 650))
        XCTAssertEqual(path.boundingRect.minY, 0, accuracy: 0.01)
        XCTAssertEqual(path.boundingRect.maxY, 650, accuracy: 0.01)
    }

    func testInformationPanelUsesCompactWidth() {
        XCTAssertEqual(InformationPanelMetrics.defaultSize.width, 340)
        XCTAssertEqual(
            InformationPanelMetrics.statusItemAutosaveName,
            "ai.secflow.knowledge-assistant.information"
        )
    }

    func testInformationFeedScrollsToTopOnlyWhenHeadlineChanges() {
        XCTAssertTrue(
            informationFeedShouldScrollToTop(
                previousHeadlineID: "old-headline",
                currentHeadlineID: "new-headline"
            )
        )
        XCTAssertFalse(
            informationFeedShouldScrollToTop(
                previousHeadlineID: "same-headline",
                currentHeadlineID: "same-headline"
            )
        )
        XCTAssertFalse(
            informationFeedShouldScrollToTop(
                previousHeadlineID: "old-headline",
                currentHeadlineID: nil
            )
        )
    }

    func testInformationItemsSortByAbsolutePublishTimeAndRemoveDuplicates() {
        let earlierInUTC = informationItem(
            id: "same-item",
            sourceID: "source-a",
            sourceName: "来源 A",
            title: "北京时间较晚但 UTC 较早",
            summary: "",
            publishedAt: "2026-07-29T00:30:00+08:00",
            category: "行业动态",
            tags: [],
            breaking: false
        )
        let latest = informationItem(
            id: "latest-item",
            sourceID: "source-b",
            sourceName: "来源 B",
            title: "真正最新资讯",
            summary: "",
            publishedAt: "2026-07-28T18:00:00Z",
            category: "行业动态",
            tags: [],
            breaking: false
        )

        let sorted = informationItemsNewestFirst([earlierInUTC, latest, earlierInUTC])

        XCTAssertEqual(sorted.map(\.id), ["latest-item", "same-item"])
    }

    @MainActor
    func testInformationSourceManagerMatchesCompactDarkPanel() throws {
        let model = AppModel()
        model.information = sampleInformation()
        let size = InformationPanelMetrics.defaultSize
        let hostingView = NSHostingView(
            rootView: InformationPopoverSourceManagerView(onBack: {}, onClose: {})
                .environmentObject(model)
                .preferredColorScheme(.dark)
                .appTypography()
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

        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.25))
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_INFORMATION_SOURCE_MANAGER_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 120_000)
        XCTAssertEqual(bitmap.pixelsWide, Int(size.width * window.backingScaleFactor))
    }

    @MainActor
    func testForcedInformationRefreshPollsUntilBackgroundWorkCompletes() async throws {
        var refreshing = sampleInformation()
        refreshing.refreshing = true
        var enrichingArtwork = sampleInformation()
        enrichingArtwork.artworkRefreshing = true
        let completed = sampleInformation()
        var responses = [enrichingArtwork, completed]
        var updates: [InformationSnapshot] = []

        let result = try await resolveInformationRefresh(
            initial: refreshing,
            maximumPollCount: 4,
            pollIntervalNanoseconds: 0,
            load: { responses.removeFirst() },
            onUpdate: { updates.append($0) }
        )

        XCTAssertEqual(result, completed)
        XCTAssertEqual(updates, [enrichingArtwork, completed])
        XCTAssertTrue(responses.isEmpty)
    }

    @MainActor
    func testForcedInformationRefreshWaitsWhenInitialResponseHasNotStartedYet() async throws {
        let previous = sampleInformation(lastRefresh: "2026-07-26T08:30:00+08:00")
        var refreshing = previous
        refreshing.refreshing = true
        let completed = sampleInformation(lastRefresh: "2026-07-26T09:00:00+08:00")
        var responses = [refreshing, completed]

        let result = try await resolveInformationRefresh(
            initial: previous,
            previousLastRefresh: previous.lastRefresh,
            maximumPollCount: 4,
            pollIntervalNanoseconds: 0,
            load: { responses.removeFirst() },
            onUpdate: { _ in }
        )

        XCTAssertEqual(result, completed)
        XCTAssertTrue(responses.isEmpty)
    }

    @MainActor
    private func renderInformationPanel(
        model: AppModel,
        size: NSSize,
        snapshotEnvironmentKey: String,
        colorScheme: ColorScheme = .light
    ) throws -> (bitmap: NSBitmapImageRep, scale: CGFloat) {
        let hostingView = NSHostingView(
            rootView: InformationPopoverView(onClose: {})
                .environmentObject(model)
                .preferredColorScheme(colorScheme)
                .appTypography()
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
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        if let snapshotPath = ProcessInfo.processInfo.environment[snapshotEnvironmentKey] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
        return (bitmap, window.backingScaleFactor)
    }

    private func sampleInformation(
        lastRefresh: String = "2026-07-26T09:00:00+08:00"
    ) -> InformationSnapshot {
        let items = [
            informationItem(
                id: "news-1",
                sourceID: "cisa_kev",
                sourceName: "CISA KEV",
                title: "正式开源！美团 LongCat-2.0 同步开放国产卡推理代码",
                summary: "官方目录新增高风险漏洞，建议优先核查受影响资产并完成安全更新。",
                publishedAt: "2026-07-26T08:45:00+08:00",
                category: "漏洞披露",
                tags: ["CVE", "在野利用"],
                breaking: true
            ),
            informationItem(
                id: "news-2",
                sourceID: "freebuf",
                sourceName: "FreeBuf",
                title: "开源供应链安全治理实践更新",
                summary: "从依赖清单、制品签名到持续监测梳理企业落地路径。",
                publishedAt: "2026-07-26T07:20:00+08:00",
                category: "供应链安全",
                tags: ["供应链", "SBOM"],
                breaking: false
            ),
            informationItem(
                id: "news-3",
                sourceID: "microsoft_security",
                sourceName: "Microsoft Security",
                title: "云环境身份攻击检测指南发布",
                summary: "指南覆盖异常令牌使用、权限提升以及跨租户访问的检测思路。",
                publishedAt: "2026-07-25T22:10:00+08:00",
                category: "云安全",
                tags: ["身份安全", "云安全"],
                breaking: false
            ),
            informationItem(
                id: "news-4",
                sourceID: "opml_wechat_security",
                sourceName: "安全研究社",
                title: "大模型应用的数据边界与审计策略",
                summary: "结合实际案例讨论提示注入、敏感数据泄露和调用链审计。",
                publishedAt: "2026-07-25T18:30:00+08:00",
                category: "AI 安全",
                tags: ["大模型", "数据安全"],
                breaking: false
            ),
        ]
        return InformationSnapshot(
            items: items,
            total: items.count,
            availableTotal: items.count,
            categories: [
                InformationCategory(id: "all", label: "全部", count: items.count),
                InformationCategory(id: "vulnerability", label: "漏洞披露", count: 1),
                InformationCategory(id: "supply-chain", label: "供应链安全", count: 1),
                InformationCategory(id: "cloud", label: "云安全", count: 1),
                InformationCategory(id: "ai", label: "AI 安全", count: 1),
            ],
            popularTags: [
                InformationTag(name: "CVE", count: 8),
                InformationTag(name: "供应链", count: 5),
                InformationTag(name: "云安全", count: 4),
                InformationTag(name: "大模型", count: 3),
            ],
            briefs: Array(items.prefix(3)),
            sources: [
                informationSource(id: "cisa_kev", name: "CISA KEV", group: "精选来源"),
                informationSource(id: "freebuf", name: "FreeBuf", group: "精选来源"),
                informationSource(id: "microsoft_security", name: "Microsoft Security", group: "安全 RSS"),
                informationSource(id: "opml_wechat_security", name: "安全研究社", group: "微信公众号"),
            ],
            sourceSummary: InformationSourceSummary(
                total: 4,
                enabled: 4,
                opmlTotal: 2,
                opmlEnabled: 2,
                opmlEnabledLimit: 50
            ),
            updatedAt: "2026-07-26T09:00:00+08:00",
            lastRefresh: lastRefresh,
            stale: false,
            partial: false,
            message: "已更新"
        )
    }

    private func informationItem(
        id: String,
        sourceID: String,
        sourceName: String,
        title: String,
        summary: String,
        publishedAt: String,
        category: String,
        tags: [String],
        breaking: Bool
    ) -> InformationItem {
        InformationItem(
            id: id,
            sourceId: sourceID,
            sourceName: sourceName,
            sourceKind: "rss",
            title: title,
            summary: summary,
            url: "https://example.test/\(id)",
            imageUrl: "",
            sourceImageUrl: nil,
            publishedAt: publishedAt,
            author: sourceName,
            category: category,
            tags: tags,
            breaking: breaking
        )
    }

    private func informationSource(id: String, name: String, group: String) -> InformationSource {
        InformationSource(
            id: id,
            name: name,
            kind: "rss",
            website: "https://example.test/\(id)",
            region: "全球",
            group: group,
            catalog: "curated",
            secureTransport: true,
            enabled: true,
            status: "ready",
            itemCount: 1,
            lastUpdated: "2026-07-26T09:00:00+08:00",
            lastChecked: "2026-07-26T09:00:00+08:00",
            nextRetryAt: nil,
            failureCount: 0,
            refreshIntervalSeconds: 900,
            message: "正常"
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
}
