import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class AppearanceSettingsTests: XCTestCase {
    func testFontSizeValuesMapToIncreasingDynamicTypeSizes() {
        XCTAssertEqual(AppInterfaceFontSize.resolve("small"), .small)
        XCTAssertEqual(AppInterfaceFontSize.resolve("default"), .default)
        XCTAssertEqual(AppInterfaceFontSize.resolve("large"), .large)
        XCTAssertEqual(AppInterfaceFontSize.resolve("unexpected"), .default)
        XCTAssertEqual(AppInterfaceFontSize.small.dynamicTypeSize, .large)
        XCTAssertEqual(AppInterfaceFontSize.default.dynamicTypeSize, .xLarge)
        XCTAssertEqual(AppInterfaceFontSize.large.dynamicTypeSize, .xxLarge)
    }

    func testAppearancePreferencesPersistLocally() throws {
        let suiteName = "SecFlowMacTests.Appearance.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        XCTAssertEqual(
            AppAppearancePreferences.load(defaults: defaults),
            AppAppearancePreferences(darkMode: false, fontSize: .default)
        )

        let expected = AppAppearancePreferences(darkMode: true, fontSize: .large)
        expected.persist(defaults: defaults)

        XCTAssertEqual(AppAppearancePreferences.load(defaults: defaults), expected)
    }

    func testAppearanceSwitchUsesExplicitLightAndDarkSchemes() {
        XCTAssertEqual(appColorScheme(darkMode: false), .light)
        XCTAssertEqual(appColorScheme(darkMode: true), .dark)
    }

    @MainActor
    func testSettingsWindowTitleBarTracksAppearanceSwitch() throws {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )

        configureSettingsWindowAppearance(window, darkMode: true)
        XCTAssertEqual(
            window.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]),
            .darkAqua
        )

        configureSettingsWindowAppearance(window, darkMode: false)
        XCTAssertEqual(
            window.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]),
            .aqua
        )
    }

    @MainActor
    func testSettingsRendersDarkModeAndLargeTypography() throws {
        let original = AppAppearancePreferences.load()
        defer { original.persist() }

        let light = try renderSettings(darkMode: false, fontSize: .default)
        let lightLarge = try renderSettings(darkMode: false, fontSize: .large)
        let darkLarge = try renderSettings(darkMode: true, fontSize: .large)

        XCTAssertGreaterThan(light.averageLuminance, darkLarge.averageLuminance + 0.22)
        XCTAssertGreaterThan(pixelDifference(light.png, lightLarge.png), 1_000)

        if let outputDirectory = ProcessInfo.processInfo.environment["SECFLOW_APPEARANCE_SNAPSHOT_DIR"] {
            let root = URL(fileURLWithPath: outputDirectory, isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            try light.png.write(to: root.appendingPathComponent("settings-light-default.png"), options: .atomic)
            try darkLarge.png.write(to: root.appendingPathComponent("settings-dark-large.png"), options: .atomic)
        }
    }

    @MainActor
    private func renderSettings(
        darkMode: Bool,
        fontSize: AppInterfaceFontSize
    ) throws -> (png: Data, averageLuminance: Double) {
        let model = AppModel()
        model.previewAppearance(darkMode: darkMode, fontSize: fontSize.rawValue)
        let size = SettingsWindowMetrics.defaultSize
        let hostingView = NSHostingView(
            rootView: SettingsView(initialSection: .general, loadsData: false)
                .environmentObject(model)
                .appAppearance(model: model)
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
        return (
            png,
            averageLuminance(in: bitmap)
        )
    }

    private func pixelDifference(_ first: Data, _ second: Data) -> Int {
        guard let lhs = NSBitmapImageRep(data: first),
              let rhs = NSBitmapImageRep(data: second),
              lhs.pixelsWide == rhs.pixelsWide,
              lhs.pixelsHigh == rhs.pixelsHigh
        else { return 0 }
        var difference = 0
        for y in stride(from: 0, to: lhs.pixelsHigh, by: 4) {
            for x in stride(from: 0, to: lhs.pixelsWide, by: 4) {
                guard let a = lhs.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB),
                      let b = rhs.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB)
                else { continue }
                if abs(a.redComponent - b.redComponent) > 0.03
                    || abs(a.greenComponent - b.greenComponent) > 0.03
                    || abs(a.blueComponent - b.blueComponent) > 0.03
                {
                    difference += 16
                }
            }
        }
        return difference
    }

    private func averageLuminance(in bitmap: NSBitmapImageRep) -> Double {
        var total = 0.0
        var samples = 0
        for y in stride(from: 0, to: bitmap.pixelsHigh, by: 8) {
            for x in stride(from: 0, to: bitmap.pixelsWide, by: 8) {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB),
                      color.alphaComponent > 0.8
                else { continue }
                total += 0.2126 * color.redComponent + 0.7152 * color.greenComponent + 0.0722 * color.blueComponent
                samples += 1
            }
        }
        return samples > 0 ? total / Double(samples) : 0
    }
}
