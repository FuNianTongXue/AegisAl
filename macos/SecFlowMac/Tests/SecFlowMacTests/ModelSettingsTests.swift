import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class ModelSettingsTests: XCTestCase {
    @MainActor
    func testModelSettingsRendersAtMinimumWindowSize() throws {
        let size = NSSize(
            width: SettingsWindowMetrics.defaultSize.width,
            height: SettingsWindowMetrics.defaultSize.height
        )
        let hostingView = NSHostingView(
            rootView: SettingsView(initialSection: .modelConfig, loadsData: false)
                .environmentObject(AppModel())
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

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 25_000)
        XCTAssertEqual(bitmap.pixelsWide, Int(size.width * window.backingScaleFactor))
        XCTAssertEqual(bitmap.pixelsHigh, Int(size.height * window.backingScaleFactor))
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_MODEL_SETTINGS_SNAPSHOT"] {
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
}
