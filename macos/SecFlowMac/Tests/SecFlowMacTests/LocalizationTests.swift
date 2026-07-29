import XCTest
@testable import SecFlowMac

@MainActor
final class LocalizationTests: XCTestCase {
    func testWorkspaceSidebarMatchesPrimaryTaskActions() {
        XCTAssertEqual(
            WorkspaceSidebarItem.allCases.map { $0.title(.zhHans) },
            ["新建任务"]
        )
        XCTAssertEqual(WorkspaceSidebarItem.allCases.map { $0.title(.en) }, ["New task"])
        XCTAssertEqual(localizedUI("重命名项目", language: .en), "Rename project")
    }

    func testLogManagementLivesInSettings() {
        XCTAssertTrue(SettingsSection.allCases.contains(.logs))
        XCTAssertEqual(localizedUI("日志管理", language: .en), "Log management")
        XCTAssertEqual(localizedUI("日志管理", language: .ja), "ログ管理")
        XCTAssertEqual(localizedUI("日志管理", language: .ko), "로그 관리")
    }

    func testDashboardIsExplicitlyVulnerabilityIntelligence() {
        XCTAssertEqual(localized(.navOverview, language: .zhHans), "漏洞情报总览")
        XCTAssertEqual(localized(.navOverview, language: .en), "Vulnerability Intelligence")
        XCTAssertEqual(localized(.navOverview, language: .ja), "脆弱性インテリジェンス")
        XCTAssertEqual(localized(.navOverview, language: .ko), "취약점 인텔리전스")
        XCTAssertTrue(
            localizedUI(
                "情报数据：CVE/GHSA 等已收录漏洞，不包含代码扫描结果",
                language: .en
            ).contains("code scan findings are excluded")
        )
    }

    func testLangGraphNodePresentationControlsAreLocalized() {
        XCTAssertEqual(localizedUI("提示词变更", language: .en), "Prompt changes")
        XCTAssertEqual(localizedUI("系统提示词变更", language: .en), "System prompt changes")
        XCTAssertEqual(localizedUI("复制调整后的提示词", language: .ja), "更新後のプロンプトをコピー")
        XCTAssertEqual(localizedUI("等待确认", language: .ko), "승인 대기")
    }

    override func tearDown() {
        UserDefaults.standard.removeObject(forKey: "secflow.appLanguage")
        super.tearDown()
    }

    func testLanguageSelectionIsPersisted() {
        UserDefaults.standard.set(AppLanguage.en.rawValue, forKey: "secflow.appLanguage")

        XCTAssertEqual(AppLanguage.storedValue(), .en)
        XCTAssertEqual(localized(.navReports, language: .en), "Reports")
        XCTAssertEqual(localized(.navReports, language: .zhHans), "报告中心")
    }

    func testSupportedSettingsLanguagesExposeApiCodes() {
        XCTAssertEqual(AppLanguage.allCases.map(\.apiCode), [
            "zh-Hans",
            "zh-Hant",
            "en",
            "ko",
            "ja",
            "es",
            "fr",
            "de",
            "it",
            "ru",
        ])
        XCTAssertEqual(AppLanguage(apiCode: "zh-Hant"), .zhHant)
        XCTAssertEqual(AppLanguage(apiCode: "fr-FR"), .fr)
        XCTAssertEqual(AppLanguage(apiCode: "ru_RU"), .ru)
    }

    func testSecurityAgentExperienceIsLocalizedForEverySupportedLanguage() {
        for language in AppLanguage.allCases {
            XCTAssertFalse(localizedUI("AI 正在分析", language: language).isEmpty)
            XCTAssertFalse(localizedUI("Sources", language: language).isEmpty)
            XCTAssertFalse(localizedUI("停止分析", language: language).isEmpty)
            XCTAssertFalse(localizedUI("%d 个工具", language: language, 4).isEmpty)
            XCTAssertFalse(localizedUI("扫描所选项目的完整代码和依赖风险", language: language).isEmpty)
        }
        XCTAssertEqual(localizedUI("AI 正在分析", language: .en), "AI is analyzing")
        XCTAssertEqual(localizedUI("%d 条结果", language: .de, 3), "3 Ergebnisse")
        XCTAssertEqual(localizedUI("停止分析", language: .ja), "分析を停止")
    }

    func testAppVersionUsesSharedBundleValue() {
        XCTAssertEqual(localized(.appVersion, language: .zhHans), AppBrand.versionLabel)
        XCTAssertEqual(localized(.appVersion, language: .en), AppBrand.versionLabel)
    }

    func testAppModelStoresSelectedLanguage() {
        let model = AppModel()

        model.setLanguage(.es)

        XCTAssertEqual(model.appLanguage, .es)
        XCTAssertEqual(UserDefaults.standard.string(forKey: "secflow.appLanguage"), AppLanguage.es.rawValue)
        XCTAssertEqual(model.text(.settings), "Settings")
    }
}
