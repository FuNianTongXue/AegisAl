import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class DashboardWindowTests: XCTestCase {
    @MainActor
    func testDashboardPresenterReusesIndependentWindow() throws {
        let model = AppModel()
        let informationPanel = InformationPanelPresenter()
        let presenter = DashboardWindowPresenter()

        presenter.show(model: model, informationPanel: informationPanel)
        let window = try XCTUnwrap(presenter.window)
        defer { presenter.close() }

        XCTAssertEqual(window.contentMinSize, DashboardWindowMetrics.minSize)
        XCTAssertTrue(window.styleMask.contains(.resizable))
        XCTAssertTrue(window.styleMask.contains(.closable))

        presenter.show(model: model, informationPanel: informationPanel)
        XCTAssertTrue(window === presenter.window)
    }

    @MainActor
    func testDashboardWindowContentRendersReferenceLayout() throws {
        let model = AppModel()
        model.dashboard = try sampleDashboard()
        let informationPanel = InformationPanelPresenter()
        let size = DashboardWindowMetrics.defaultSize
        let hostingView = NSHostingView(
            rootView: DashboardView()
                .environmentObject(model)
                .environmentObject(informationPanel)
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
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        hostingView.layoutSubtreeIfNeeded()

        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 20_000)
        XCTAssertGreaterThan(lightOpaquePixelCount(bitmap), 20_000)
        let labels = descendants(of: NSTextField.self, in: hostingView).map(\.stringValue)
        XCTAssertTrue(labels.contains { $0.contains("漏洞情报总览") })
        XCTAssertTrue(labels.contains { $0.contains("不包含代码扫描结果") })
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_DASHBOARD_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    private func sampleDashboard() throws -> DashboardSnapshot {
        let data = Data(
            #"{"vulnerabilityCount":482,"highRiskCount":127,"queryCount":31,"graphNodeCount":2140,"severity":{"CRITICAL":24,"HIGH":103,"MEDIUM":211,"LOW":144},"recentRecords":[],"sources":[],"persistence":"ready","generatedAt":"2026-07-26T08:00:00Z","scope":"all","rangeStart":null,"rangeEnd":null,"catalogStatus":"ready","catalogProgress":100,"catalogCount":482}"#.utf8
        )
        return try JSONDecoder().decode(DashboardSnapshot.self, from: data)
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

    private func lightOpaquePixelCount(_ bitmap: NSBitmapImageRep) -> Int {
        var count = 0
        for y in stride(from: 0, to: bitmap.pixelsHigh, by: 4) {
            for x in stride(from: 0, to: bitmap.pixelsWide, by: 4) {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { continue }
                if color.alphaComponent > 0.9,
                   color.redComponent > 0.75,
                   color.greenComponent > 0.75,
                   color.blueComponent > 0.75 {
                    count += 16
                }
            }
        }
        return count
    }

    private func descendants<T: NSView>(of type: T.Type, in root: NSView) -> [T] {
        root.subviews.flatMap { child in
            (child as? T).map { [$0] } ?? descendants(of: type, in: child)
        }
    }
}
