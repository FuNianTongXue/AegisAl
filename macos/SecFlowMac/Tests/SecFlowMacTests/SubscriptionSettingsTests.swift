import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class SubscriptionSettingsTests: XCTestCase {
    func testSubscriptionPlanVisualsFollowBillingPeriodAndRecommendation() {
        let plans = sampleCatalog().plans

        XCTAssertEqual(SubscriptionPlanVisuals.symbolName(for: plans[0]), "bolt.fill")
        XCTAssertEqual(SubscriptionPlanVisuals.symbolName(for: plans[1]), "sparkles")
        XCTAssertEqual(SubscriptionPlanVisuals.symbolName(for: plans[2]), "arrow.down.to.line")
        XCTAssertTrue(plans[1].recommended)
    }

    func testSubscriptionPlansExposeCompleteFeatureLists() {
        let plans = sampleCatalog().plans

        XCTAssertTrue(plans.allSatisfy { $0.features.count == 3 })
        XCTAssertTrue(plans.allSatisfy { $0.features.contains("完整代码扫描") })
        XCTAssertTrue(plans.allSatisfy { $0.features.contains("智能问答与报告") })
        XCTAssertTrue(plans.allSatisfy { $0.features.contains("漏洞情报与组件查询") })
    }

    @MainActor
    func testSubscriptionSettingsRendersAtMinimumWindowSize() throws {
        let model = AppModel()
        model.profileSettings = UserProfileSettingsSnapshot(
            displayName: "李明哲",
            email: "analyst@example.test",
            phone: "",
            department: "网络安全部",
            role: "安全分析师",
            employeeId: "SEC-1",
            bio: "",
            avatarFileName: "",
            avatarContentType: "",
            avatarUpdatedAt: "",
            updatedAt: "",
            avatarAvailable: false
        )
        model.subscriptionCatalog = sampleCatalog()
        model.currentSubscription = sampleSubscription()
        model.subscriptionUsage = sampleUsage()
        model.subscriptionOrders = sampleOrders()

        let size = NSSize(
            width: SettingsWindowMetrics.defaultSize.width,
            height: SettingsWindowMetrics.defaultSize.height
        )
        let hostingView = NSHostingView(
            rootView: SettingsView(initialSection: .subscription, loadsData: false)
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
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))

        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 25_000)
        XCTAssertEqual(bitmap.pixelsWide, Int(size.width * window.backingScaleFactor))
        XCTAssertEqual(bitmap.pixelsHigh, Int(size.height * window.backingScaleFactor))
        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_SUBSCRIPTION_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    private func sampleCatalog() -> SubscriptionCatalog {
        SubscriptionCatalog(
            plans: [
                SubscriptionPlan(
                    id: "professional_monthly", name: "专业版", periodName: "月度",
                    billingPeriod: "month", intervalMonths: 1, priceCents: 2500,
                    originalPriceCents: 2500, currency: "CNY", discountPercent: 0,
                    badge: "灵活订阅", description: "按月使用，随时可取消自动续费",
                    features: ["完整代码扫描", "智能问答与报告", "漏洞情报与组件查询"], recommended: false
                ),
                SubscriptionPlan(
                    id: "professional_quarterly", name: "专业版", periodName: "季度",
                    billingPeriod: "quarter", intervalMonths: 3, priceCents: 6800,
                    originalPriceCents: 7500, currency: "CNY", discountPercent: 9,
                    badge: "最受欢迎", description: "性价比之选，适合持续安全分析",
                    features: ["完整代码扫描", "智能问答与报告", "漏洞情报与组件查询"], recommended: true
                ),
                SubscriptionPlan(
                    id: "professional_yearly", name: "专业版", periodName: "年度",
                    billingPeriod: "year", intervalMonths: 12, priceCents: 18800,
                    originalPriceCents: 30000, currency: "CNY", discountPercent: 37,
                    badge: "长期优惠", description: "最超值，适合团队与高频使用",
                    features: ["完整代码扫描", "智能问答与报告", "漏洞情报与组件查询"], recommended: false
                ),
            ],
            paymentMethods: [
                SubscriptionPaymentMethod(id: "alipay", name: "支付宝"),
                SubscriptionPaymentMethod(id: "wechat", name: "微信支付"),
                SubscriptionPaymentMethod(id: "unionpay", name: "银联"),
            ],
            currency: "CNY"
        )
    }

    private func sampleSubscription() -> SubscriptionSnapshot {
        SubscriptionSnapshot(
            userId: "local-user", planId: "professional_yearly", planName: "专业版",
            periodName: "年度", status: "active", autoRenew: true,
            cancelAtPeriodEnd: false, currentPeriodStart: "2026-07-23T00:00:00+00:00",
            currentPeriodEnd: "2027-07-23T00:00:00+00:00", paymentMethod: "alipay",
            latestOrderId: "ord_1", canceledAt: nil, cancelReason: "",
            updatedAt: "2026-07-23T00:00:00+00:00"
        )
    }

    private func sampleUsage() -> SubscriptionUsageSnapshot {
        SubscriptionUsageSnapshot(
            userId: "local-user",
            periodStart: "2026-07-01T00:00:00+00:00",
            periodEnd: "2026-08-01T00:00:00+00:00",
            metrics: [SubscriptionUsageMetric(id: "code_scans", label: "代码扫描", used: 4, limit: 20, unit: "次")],
            updatedAt: "2026-07-23T00:00:00+00:00"
        )
    }

    private func sampleOrders() -> [SubscriptionOrder] {
        [
            SubscriptionOrder(
                id: "ord_1", userId: "local-user", planId: "professional_yearly",
                planName: "专业版", periodName: "年度", paymentMethod: "alipay",
                amountCents: 18800, currency: "CNY", status: "paid",
                providerTransactionId: "tx_1", paymentUrl: nil,
                createdAt: "2026-07-23T00:00:00+00:00",
                updatedAt: "2026-07-23T00:00:00+00:00",
                paidAt: "2026-07-23T00:00:00+00:00"
            )
        ]
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
