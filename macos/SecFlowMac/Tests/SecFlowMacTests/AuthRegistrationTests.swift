import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class AuthRegistrationTests: XCTestCase {
    func testRegistrationRequiresBothDocumentsAndExplicitAgreement() {
        let values = (
            email: "analyst@example.com",
            password: "secure123",
            confirmPassword: "secure123"
        )

        XCTAssertFalse(
            RegistrationRules.canRegister(
                email: values.email,
                password: values.password,
                confirmPassword: values.confirmPassword,
                termsRead: false,
                privacyRead: false,
                accepted: true
            )
        )
        XCTAssertFalse(
            RegistrationRules.canRegister(
                email: values.email,
                password: values.password,
                confirmPassword: values.confirmPassword,
                termsRead: true,
                privacyRead: false,
                accepted: true
            )
        )
        XCTAssertFalse(
            RegistrationRules.canRegister(
                email: values.email,
                password: values.password,
                confirmPassword: values.confirmPassword,
                termsRead: true,
                privacyRead: true,
                accepted: false
            )
        )
        XCTAssertTrue(
            RegistrationRules.canRegister(
                email: values.email,
                password: values.password,
                confirmPassword: values.confirmPassword,
                termsRead: true,
                privacyRead: true,
                accepted: true
            )
        )
    }

    func testLegalDocumentEndRequiresViewportAndBottomThreshold() {
        XCTAssertFalse(RegistrationRules.hasReachedDocumentEnd(bottomPosition: 500, viewportHeight: 0))
        XCTAssertFalse(RegistrationRules.hasReachedDocumentEnd(bottomPosition: 621, viewportHeight: 600))
        XCTAssertTrue(RegistrationRules.hasReachedDocumentEnd(bottomPosition: 620, viewportHeight: 600))
        XCTAssertTrue(RegistrationRules.hasReachedDocumentEnd(bottomPosition: 580, viewportHeight: 600))
    }

    @MainActor
    func testRegistrationFormRendersAtAppWindowSize() throws {
        let model = AppModel()
        model.authScreen = .register
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: AuthView()
                .environmentObject(model)
                .frame(width: size.width, height: size.height)
        )
        let window = host(hostingView, size: size)
        defer { window.close() }

        let png = try renderPNG(hostingView, size: size)
        XCTAssertGreaterThan(nonWhitePixelCount(hostingView), 20_000)

        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_REGISTRATION_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    func testLegalDocumentSheetRendersAndUnlocksAfterActualScroll() throws {
        var reachedBottom = false
        let size = NSSize(width: 720, height: 680)
        let hostingView = NSHostingView(
            rootView: RegistrationLegalDocumentSheet(
                document: .terms,
                backendDocument: nil,
                alreadyRead: false,
                onReachedBottom: { reachedBottom = true },
                onRead: {}
            )
            .environmentObject(AppModel())
            .frame(width: size.width, height: size.height)
        )
        let window = host(hostingView, size: size)
        defer { window.close() }

        let png = try renderPNG(hostingView, size: size)
        let scrollViews = descendants(of: NSScrollView.self, in: hostingView)
        let scrollView = try XCTUnwrap(
            scrollViews.max {
                ($0.documentView?.bounds.height ?? 0) < ($1.documentView?.bounds.height ?? 0)
            }
        )
        XCTAssertFalse(reachedBottom)

        let documentHeight = scrollView.documentView?.bounds.height ?? 0
        scrollView.contentView.scroll(
            to: NSPoint(
                x: 0,
                y: max(0, documentHeight - scrollView.contentView.bounds.height)
            )
        )
        scrollView.reflectScrolledClipView(scrollView.contentView)
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        hostingView.layoutSubtreeIfNeeded()

        XCTAssertTrue(reachedBottom)
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_LEGAL_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    @MainActor
    private func host(_ hostingView: NSView, size: NSSize) -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        return window
    }

    @MainActor
    private func renderPNG(_ hostingView: NSHostingView<some View>, size: NSSize) throws -> Data {
        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        return try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
    }

    @MainActor
    private func nonWhitePixelCount(_ hostingView: NSView) -> Int {
        guard let bitmap = hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds) else { return 0 }
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
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

    @MainActor
    private func descendants<T: NSView>(of type: T.Type, in root: NSView) -> [T] {
        root.subviews.flatMap { child in
            (child as? T).map { [$0] } ?? descendants(of: type, in: child)
        }
    }
}
