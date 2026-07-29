import AppKit
import CoreText
import XCTest
@testable import SecFlowMac

final class TypographyTests: XCTestCase {
    func testNativeSystemFontUsesRequestedGlyphCascade() {
        let baseFont = NSFont.systemFont(ofSize: 15) as CTFont

        XCTAssertTrue(resolvedPostScriptName(for: "SecFlow", baseFont: baseFont).contains("SF"))
        XCTAssertTrue(resolvedPostScriptName(for: "安全扫描", baseFont: baseFont).contains("PingFang"))
        XCTAssertTrue(resolvedPostScriptName(for: "🔒", baseFont: baseFont).contains("AppleColorEmoji"))
    }

    func testWebFontCascadeMatchesNativeTypography() {
        let family = AppTypography.webFontFamily

        XCTAssertTrue(family.hasPrefix("\"SF Pro Text\""))
        XCTAssertTrue(family.contains("\"PingFang SC\""))
        XCTAssertTrue(family.contains("\"Apple Color Emoji\""))
        XCTAssertFalse(family.contains("Inter"))
    }

    private func resolvedPostScriptName(for value: String, baseFont: CTFont) -> String {
        let range = CFRange(location: 0, length: (value as NSString).length)
        let resolved = CTFontCreateForString(baseFont, value as CFString, range)
        return CTFontCopyPostScriptName(resolved) as String
    }
}
