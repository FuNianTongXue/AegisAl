import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class FirstRunSecurityTests: XCTestCase {
    @MainActor
    func testEmbeddedBackendDoesNotInheritDeveloperLLMEnvironment() {
        var source = [
            "PATH": "/usr/bin",
            "HOME": "/tmp/example-home",
        ]
        for key in LocalBackendManager.isolatedLLMEnvironmentKeys {
            source[key] = "developer-secret-or-setting"
        }

        let isolated = LocalBackendManager.isolatedBackendEnvironment(from: source)

        XCTAssertEqual(isolated["PATH"], "/usr/bin")
        XCTAssertEqual(isolated["HOME"], "/tmp/example-home")
        for key in LocalBackendManager.isolatedLLMEnvironmentKeys {
            XCTAssertNil(isolated[key], "\(key) must not reach the packaged backend")
        }
    }

    @MainActor
    func testPostLoginWizardRendersProfileStep() throws {
        let size = NSSize(width: 1100, height: 720)
        let hostingView = NSHostingView(
            rootView: PostLoginSetupView()
                .environmentObject(AppModel())
                .frame(width: size.width, height: size.height)
        )
        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 20_000)

        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_ONBOARDING_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    func testSetupStartsWithProfileForANewAccount() {
        let profile = makeProfile(email: "other@example.com", updatedAt: "2026-07-28T10:00:00Z")
        XCTAssertEqual(
            PostLoginSetupRules.firstIncompleteStep(
                profile: profile,
                userID: "analyst@example.com",
                llmConfig: makeLLMConfig(configured: true, hasApiKey: true)
            ),
            1
        )
    }

    func testSetupRequiresExplicitlySavedProfileAndRole() {
        let unsavedProfile = makeProfile(email: "analyst@example.com", updatedAt: "")
        let missingRole = makeProfile(email: "analyst@example.com", role: "", updatedAt: "2026-07-28T10:00:00Z")

        XCTAssertFalse(PostLoginSetupRules.isProfileComplete(unsavedProfile, userID: "analyst@example.com"))
        XCTAssertFalse(PostLoginSetupRules.isProfileComplete(missingRole, userID: "analyst@example.com"))
    }

    func testCompletedProfileResumesAtModelConfiguration() {
        let profile = makeProfile(email: "analyst@example.com", updatedAt: "2026-07-28T10:00:00Z")
        XCTAssertEqual(
            PostLoginSetupRules.firstIncompleteStep(
                profile: profile,
                userID: "ANALYST@example.com",
                llmConfig: makeLLMConfig(configured: false, hasApiKey: false)
            ),
            3
        )
    }

    func testCompletedProfileAndModelSkipSetup() {
        let profile = makeProfile(email: "analyst@example.com", updatedAt: "2026-07-28T10:00:00Z")
        XCTAssertNil(
            PostLoginSetupRules.firstIncompleteStep(
                profile: profile,
                userID: "analyst@example.com",
                llmConfig: makeLLMConfig(configured: true, hasApiKey: true)
            )
        )
    }

    private func makeProfile(
        email: String,
        role: String = "安全分析师",
        updatedAt: String
    ) -> UserProfileSettingsSnapshot {
        UserProfileSettingsSnapshot(
            displayName: "小安",
            email: email,
            phone: "",
            department: "安全研发部",
            role: role,
            employeeId: "",
            bio: "",
            avatarFileName: "",
            avatarContentType: "",
            avatarUpdatedAt: "",
            updatedAt: updatedAt,
            avatarAvailable: false
        )
    }

    private func makeLLMConfig(configured: Bool, hasApiKey: Bool) -> LLMConfigSnapshot {
        LLMConfigSnapshot(
            name: nil,
            provider: "openai",
            catalogProvider: "openai",
            model: "gpt-5.4",
            endpoint: "https://api.openai.com/v1",
            wireApi: nil,
            reasoningEffort: nil,
            disableResponseStorage: nil,
            enabled: configured,
            configured: configured,
            hasApiKey: hasApiKey,
            apiKeyMasked: nil,
            message: nil,
            updatedAt: nil
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
