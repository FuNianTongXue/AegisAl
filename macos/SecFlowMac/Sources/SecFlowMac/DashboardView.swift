import Foundation
import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var informationPanel: InformationPanelPresenter

    @State private var selectedTimePreset: DashboardTimePreset = .all
    @State private var isTimePresetPopoverPresented = false
    @State private var isApplyingTimePreset = false

    private var isRefreshing: Bool {
        model.busyActions.contains("dashboard-batch") || model.busyActions.contains("dashboard-filter")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                dashboardHeader
                advancedStats
                metricsGrid
                dashboardContent
            }
            .padding(.horizontal, 24)
            .padding(.top, 46)
            .padding(.bottom, 24)
            .frame(maxWidth: 1240)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .appTypography()
        .textSelection(.enabled)
        .onAppear { synchronizeTimeFilter() }
        .onChange(of: model.dashboardRange) { _, _ in synchronizeTimeFilter() }
    }

    private var dashboardHeader: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text(model.text(.navOverview))
                    .font(AppTypography.pageTitle)
                    .foregroundStyle(AppPalette.text)
                Text(dashboardScopeText)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
                Label(
                    model.uiText("情报数据：CVE/GHSA 等已收录漏洞，不包含代码扫描结果"),
                    systemImage: "antenna.radiowaves.left.and.right"
                )
                .font(AppTypography.caption)
                .foregroundStyle(AppPalette.primaryStrong)
                HStack(spacing: 12) {
                    Label(lastUpdatedText, systemImage: "clock")
                    Label(
                        catalogStatusText,
                        systemImage: catalogIsReady ? "externaldrive.fill.badge.checkmark" : "externaldrive.badge.timemachine"
                    )
                    .foregroundStyle(catalogIsReady ? AppPalette.success : AppPalette.primary)
                }
                .font(AppTypography.caption)
                .foregroundStyle(AppPalette.textSubtle)
            }

            Spacer(minLength: 12)

            dashboardTimeToolbar
        }
    }

    private var dashboardTimeToolbar: some View {
        HStack(spacing: 8) {
            Button {
                isTimePresetPopoverPresented.toggle()
            } label: {
                HStack(spacing: 8) {
                    if isRefreshing || isApplyingTimePreset {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Image(systemName: "calendar")
                            .font(AppTypography.system(size: 13, weight: .semibold))
                            .foregroundStyle(AppPalette.textMuted)
                    }

                    Text(selectedTimePreset.title(model.appLanguage))
                        .font(AppTypography.bodyMedium)
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)

                    Image(systemName: "chevron.down")
                        .font(AppTypography.system(size: 9, weight: .bold))
                        .foregroundStyle(AppPalette.textSubtle)
                }
                .padding(.horizontal, 12)
                .frame(height: 32)
                .background(AppPalette.card)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .stroke(AppPalette.border.opacity(0.86))
                }
            }
            .buttonStyle(.plain)
            .disabled(isRefreshing || isApplyingTimePreset)
            .popover(isPresented: $isTimePresetPopoverPresented, arrowEdge: .top) {
                timePresetPopover
            }
            .help(model.text(.dateRangeHelp))

            Button {
                informationPanel.show(model: model)
            } label: {
                Image(systemName: "newspaper")
                    .font(AppTypography.system(size: 14, weight: .semibold))
                    .foregroundStyle(AppPalette.textMuted)
                    .frame(width: 32, height: 32)
                    .background(AppPalette.card)
                    .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 7, style: .continuous)
                            .stroke(AppPalette.border.opacity(0.86))
                    }
            }
            .buttonStyle(.plain)
            .help(model.text(.navInformation))
        }
    }

    private var timePresetPopover: some View {
        VStack(spacing: 4) {
            ForEach(DashboardTimePreset.menuOptions) { preset in
                Button {
                    isTimePresetPopoverPresented = false
                    Task { await applyTimePreset(preset) }
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: selectedTimePreset == preset ? "checkmark" : preset.systemImage)
                            .font(AppTypography.system(size: 12, weight: .semibold))
                            .foregroundStyle(selectedTimePreset == preset ? AppPalette.primary : AppPalette.textMuted)
                            .frame(width: 16)
                        Text(preset.title(model.appLanguage))
                            .font(AppTypography.bodyMedium)
                            .foregroundStyle(AppPalette.text)
                        Spacer(minLength: 8)
                    }
                    .padding(.horizontal, 10)
                    .frame(height: 32)
                    .background(selectedTimePreset == preset ? AppPalette.selectedStrong.opacity(0.78) : Color.clear)
                    .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(8)
        .frame(width: 168)
        .background(AppPalette.card)
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.82))
        }
    }

    private var metricsGrid: some View {
        LazyVGrid(
            columns: Array(repeating: GridItem(.flexible(minimum: 150), spacing: 12), count: 4),
            alignment: .leading,
            spacing: 12
        ) {
            DashboardMetricCard(
                label: model.uiText("严重漏洞"),
                value: severityCount("CRITICAL"),
                color: AppPalette.danger,
                detail: sharePercentageText(for: "CRITICAL")
            )
            DashboardMetricCard(
                label: model.uiText("高危漏洞"),
                value: severityCount("HIGH"),
                color: AppPalette.warning,
                detail: sharePercentageText(for: "HIGH")
            )
            DashboardMetricCard(
                label: model.uiText("中危漏洞"),
                value: severityCount("MEDIUM"),
                color: AppPalette.medium,
                detail: sharePercentageText(for: "MEDIUM")
            )
            DashboardMetricCard(
                label: model.uiText("低危漏洞"),
                value: severityCount("LOW"),
                color: AppPalette.success,
                detail: sharePercentageText(for: "LOW")
            )
        }
    }

    private var advancedStats: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 12) {
                DashboardRiskOverviewPanel(
                    total: vulnerabilityCount,
                    metrics: severityMetrics
                )
                .frame(minWidth: 520, maxWidth: .infinity, minHeight: 326)

                VStack(spacing: 12) {
                    DashboardPrimaryGoalCard(
                        controlPercentage: criticalControlPercentage,
                        criticalCount: severityCount("CRITICAL")
                    )
                    DashboardHighRiskSummaryCard(
                        highRiskCount: severityCount("CRITICAL") + severityCount("HIGH"),
                        total: vulnerabilityCount
                    )
                }
                .frame(width: 318)
            }

            VStack(spacing: 12) {
                DashboardRiskOverviewPanel(total: vulnerabilityCount, metrics: severityMetrics)
                    .frame(minHeight: 326)
                HStack(spacing: 12) {
                    DashboardPrimaryGoalCard(
                        controlPercentage: criticalControlPercentage,
                        criticalCount: severityCount("CRITICAL")
                    )
                    DashboardHighRiskSummaryCard(
                        highRiskCount: severityCount("CRITICAL") + severityCount("HIGH"),
                        total: vulnerabilityCount
                    )
                }
            }
        }
    }

    private var dashboardContent: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 16) {
                RecentVulnerabilityCard(records: recentRecords)
                    .frame(minWidth: 560)
                quickStatsColumn
                    .frame(width: 320)
            }

            VStack(spacing: 16) {
                RecentVulnerabilityCard(records: recentRecords)
                quickStatsColumn
            }
        }
    }

    private var quickStatsColumn: some View {
        VStack(spacing: 16) {
            PriorityRiskCard(records: recentRecords)
        }
    }

    private var vulnerabilityCount: Int {
        model.dashboard?.vulnerabilityCount ?? 0
    }

    private var recentRecords: [IntelligenceRecord] {
        (model.dashboard?.recentRecords ?? []).filter { isKnownSeverity($0.severity) }
    }

    private var lastUpdatedText: String {
        guard let generatedAt = model.dashboard?.generatedAt, !generatedAt.isEmpty else {
            return model.uiText("等待首次批计算")
        }
        return model.uiText("最近更新：%@", dashboardDateTime(generatedAt, locale: model.appLanguage.locale))
    }

    private var dashboardScopeText: String {
        guard model.dashboard?.scope == "range",
              let start = model.dashboard?.rangeStart,
              let end = model.dashboard?.rangeEnd
        else {
            return model.uiText("累计漏洞情报风险态势，后台持续增量更新")
        }
        return model.uiText("%@ 至 %@ 发布的漏洞情报风险态势", start, end)
    }

    private var catalogIsReady: Bool {
        model.dashboard?.catalogStatus == "ready"
    }

    private var catalogStatusText: String {
        if catalogIsReady {
            return model.uiText("本地漏洞情报目录已就绪，共 %d 条", model.dashboard?.catalogCount ?? vulnerabilityCount)
        }
        let progress = model.dashboard?.catalogProgress ?? 0
        return progress > 0
            ? model.uiText("正在构建本地漏洞情报目录 %d%%", progress)
            : model.uiText("正在准备本地漏洞情报目录")
    }

    private func synchronizeTimeFilter() {
        selectedTimePreset = DashboardTimePreset.matching(model.dashboardRange)
    }

    private func applyTimePreset(_ preset: DashboardTimePreset) async {
        isApplyingTimePreset = true
        selectedTimePreset = preset
        if let range = preset.range() {
            await model.applyDashboardRange(startDate: range.start, endDate: range.end)
        } else {
            await model.refreshDashboardBatch()
        }
        selectedTimePreset = DashboardTimePreset.matching(model.dashboardRange)
        isApplyingTimePreset = false
    }

    private func severityCount(_ key: String) -> Int {
        model.dashboard?.severity[key] ?? 0
    }

    private var severityMetrics: [DashboardSeverityMetric] {
        [
            DashboardSeverityMetric(key: "CRITICAL", label: model.uiText("严重"), value: severityCount("CRITICAL"), color: AppPalette.danger),
            DashboardSeverityMetric(key: "HIGH", label: model.uiText("高危"), value: severityCount("HIGH"), color: AppPalette.warning),
            DashboardSeverityMetric(key: "MEDIUM", label: model.uiText("中危"), value: severityCount("MEDIUM"), color: AppPalette.medium),
            DashboardSeverityMetric(key: "LOW", label: model.uiText("低危"), value: severityCount("LOW"), color: AppPalette.success),
        ]
    }

    private var criticalControlPercentage: Int {
        guard vulnerabilityCount > 0 else { return 100 }
        let criticalShare = Double(severityCount("CRITICAL")) / Double(vulnerabilityCount)
        return max(0, min(100, Int(((1 - criticalShare) * 100).rounded())))
    }

    private func shareText(for key: String) -> String {
        guard vulnerabilityCount > 0 else { return model.uiText("占全部漏洞 0%") }
        let percentage = Int((Double(severityCount(key)) / Double(vulnerabilityCount) * 100).rounded())
        return model.uiText("占全部漏洞 %d%%", percentage)
    }

    private func sharePercentageText(for key: String) -> String {
        guard vulnerabilityCount > 0 else { return "0%" }
        let percentage = Double(severityCount(key)) / Double(vulnerabilityCount) * 100
        return String(format: "%.1f%%", percentage)
    }
}

private enum DashboardTimePreset: String, Identifiable, Hashable {
    case all
    case last7Days
    case last30Days
    case last90Days
    case thisYear
    case custom

    static let menuOptions: [DashboardTimePreset] = [
        .all,
        .last7Days,
        .last30Days,
        .last90Days,
        .thisYear
    ]

    var id: String { rawValue }

    func title(_ language: AppLanguage) -> String {
        switch self {
        case .all: return localizedUI("全部时间", language: language)
        case .last7Days: return localizedUI("最近 7 天", language: language)
        case .last30Days: return localizedUI("最近 30 天", language: language)
        case .last90Days: return localizedUI("最近 90 天", language: language)
        case .thisYear: return localizedUI("今年", language: language)
        case .custom: return localizedUI("自定义范围", language: language)
        }
    }

    var systemImage: String {
        switch self {
        case .all: return "clock.arrow.circlepath"
        case .last7Days, .last30Days, .last90Days, .thisYear, .custom: return "calendar"
        }
    }

    func range(
        relativeTo referenceDate: Date = Date(),
        calendar: Calendar = Calendar(identifier: .gregorian)
    ) -> DashboardDateRange? {
        let today = calendar.startOfDay(for: referenceDate)
        switch self {
        case .all, .custom:
            return nil
        case .last7Days:
            return rangeEndingToday(dayCount: 7, today: today, calendar: calendar)
        case .last30Days:
            return rangeEndingToday(dayCount: 30, today: today, calendar: calendar)
        case .last90Days:
            return rangeEndingToday(dayCount: 90, today: today, calendar: calendar)
        case .thisYear:
            let year = calendar.component(.year, from: today)
            let start = calendar.date(from: DateComponents(year: year, month: 1, day: 1)) ?? today
            return DashboardDateRange(start: start, end: today)
        }
    }

    static func matching(
        _ range: DashboardDateRange?,
        relativeTo referenceDate: Date = Date(),
        calendar: Calendar = Calendar(identifier: .gregorian)
    ) -> DashboardTimePreset {
        guard let range else { return .all }
        let start = calendar.startOfDay(for: range.start)
        let end = calendar.startOfDay(for: range.end)

        for preset in menuOptions where preset != .all {
            guard let presetRange = preset.range(relativeTo: referenceDate, calendar: calendar) else { continue }
            if calendar.isDate(start, inSameDayAs: presetRange.start),
               calendar.isDate(end, inSameDayAs: presetRange.end) {
                return preset
            }
        }

        return .custom
    }

    private func rangeEndingToday(dayCount: Int, today: Date, calendar: Calendar) -> DashboardDateRange {
        let offset = max(dayCount - 1, 0)
        let start = calendar.date(byAdding: .day, value: -offset, to: today) ?? today
        return DashboardDateRange(start: start, end: today)
    }
}

private struct DashboardRiskOverviewPanel: View {
    @EnvironmentObject private var model: AppModel
    let total: Int
    let metrics: [DashboardSeverityMetric]

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.uiText("漏洞情报风险态势"))
                        .font(AppTypography.sectionTitle)
                    Text(model.uiText("按已收录漏洞情报的严重等级统计"))
                        .font(AppTypography.label)
                        .foregroundStyle(AppPalette.textSubtle)
                }

                Spacer(minLength: 12)

                VStack(alignment: .trailing, spacing: 3) {
                    Text(total.formatted())
                        .font(AppTypography.sectionTitle.monospacedDigit())
                    Text(model.uiText("漏洞总数"))
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
            }

            DashboardRiskTrendChart(metrics: metrics)
                .frame(maxWidth: .infinity, minHeight: 226)
        }
        .padding(22)
        .frame(maxWidth: .infinity, minHeight: 326, alignment: .topLeading)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }
}

private struct DashboardRiskTrendChart: View {
    let metrics: [DashboardSeverityMetric]

    var body: some View {
        VStack(spacing: 10) {
            GeometryReader { geometry in
                let points = chartPoints(in: geometry.size)

                ZStack {
                    ForEach(0..<4, id: \.self) { index in
                        Path { path in
                            let y = geometry.size.height * CGFloat(index) / 3
                            path.move(to: CGPoint(x: 0, y: y))
                            path.addLine(to: CGPoint(x: geometry.size.width, y: y))
                        }
                        .stroke(AppPalette.border.opacity(0.62), style: StrokeStyle(lineWidth: 1, dash: [2, 4]))
                    }

                    if let first = points.first, let last = points.last {
                        Path { path in
                            path.move(to: CGPoint(x: first.x, y: geometry.size.height))
                            points.forEach { path.addLine(to: $0) }
                            path.addLine(to: CGPoint(x: last.x, y: geometry.size.height))
                            path.closeSubpath()
                        }
                        .fill(
                            LinearGradient(
                                colors: [AppPalette.primary.opacity(0.18), AppPalette.primary.opacity(0.01)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )

                        Path { path in
                            path.move(to: first)
                            for point in points.dropFirst() {
                                path.addLine(to: point)
                            }
                        }
                        .stroke(AppPalette.primary, style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))

                        ForEach(Array(points.enumerated()), id: \.offset) { index, point in
                            Circle()
                                .fill(metrics[index].color)
                                .frame(width: 8, height: 8)
                                .overlay(Circle().stroke(AppPalette.card, lineWidth: 2))
                                .position(point)
                        }
                    }
                }
            }

            HStack(spacing: 0) {
                ForEach(metrics) { metric in
                    VStack(spacing: 3) {
                        Text(metric.label)
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                        Text(metric.value.formatted())
                            .font(AppTypography.label.monospacedDigit())
                            .foregroundStyle(metric.color)
                    }
                    .frame(maxWidth: .infinity)
                }
            }
        }
    }

    private func chartPoints(in size: CGSize) -> [CGPoint] {
        guard !metrics.isEmpty else { return [] }
        let maximum = max(metrics.map(\.value).max() ?? 0, 1)
        let horizontalInset: CGFloat = 18
        let verticalInset: CGFloat = 16
        let usableWidth = max(size.width - horizontalInset * 2, 1)
        let usableHeight = max(size.height - verticalInset * 2, 1)

        return metrics.enumerated().map { index, metric in
            let xFraction = metrics.count == 1 ? 0.5 : CGFloat(index) / CGFloat(metrics.count - 1)
            let yFraction = CGFloat(metric.value) / CGFloat(maximum)
            return CGPoint(
                x: horizontalInset + usableWidth * xFraction,
                y: verticalInset + usableHeight * (1 - yFraction)
            )
        }
    }
}

private struct DashboardPrimaryGoalCard: View {
    @EnvironmentObject private var model: AppModel
    let controlPercentage: Int
    let criticalCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(model.uiText("情报关注指标"))
                .font(AppTypography.label)
                .foregroundStyle(Color.white.opacity(0.55))
            Text(model.uiText("控制严重级漏洞情报占比"))
                .font(AppTypography.sectionTitle)
                .foregroundStyle(Color.white)
                .padding(.top, 8)

            Spacer(minLength: 12)

            HStack(alignment: .firstTextBaseline) {
                Text("\(controlPercentage)%")
                    .font(AppTypography.system(size: 34, weight: .semibold))
                    .monospacedDigit()
                    .foregroundStyle(Color.white)
                Spacer()
                Text(model.uiText("目标：95%"))
                    .font(AppTypography.caption)
                    .foregroundStyle(Color.white.opacity(0.62))
            }

            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.white.opacity(0.15))
                    Capsule()
                        .fill(Color.white)
                        .frame(width: geometry.size.width * CGFloat(controlPercentage) / 100)
                }
            }
            .frame(height: 5)
            .padding(.top, 8)

            Text(model.uiText("当前严重级漏洞情报 %d 条", criticalCount))
                .font(AppTypography.caption)
                .foregroundStyle(Color.white.opacity(0.55))
                .padding(.top, 8)
        }
        .padding(22)
        .frame(maxWidth: .infinity, minHeight: 160, alignment: .topLeading)
        .background(AppPalette.brandNavy)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct DashboardHighRiskSummaryCard: View {
    @EnvironmentObject private var model: AppModel
    let highRiskCount: Int
    let total: Int

    private var percentage: Int {
        guard total > 0 else { return 0 }
        return Int((Double(highRiskCount) / Double(total) * 100).rounded())
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.shield")
                    .font(AppTypography.system(size: 16, weight: .medium))
                    .foregroundStyle(AppPalette.text)
                Text(model.uiText("高危漏洞情报摘要"))
                    .font(AppTypography.sectionTitle)
            }

            Text(model.uiText("已收录严重与高危漏洞情报共 %d 条，占全部情报漏洞的 %d%%。", highRiskCount, percentage))
                .font(AppTypography.body)
                .foregroundStyle(AppPalette.textMuted)
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 0)
        }
        .padding(22)
        .frame(maxWidth: .infinity, minHeight: 154, alignment: .topLeading)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }
}

private struct DashboardMetricCard: View {
    let label: String
    let value: Int
    let color: Color
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(label.uppercased())
                .font(AppTypography.label)
                .foregroundStyle(AppPalette.textSubtle)
                .lineLimit(1)

            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(value.formatted())
                    .font(AppTypography.metric.monospacedDigit())
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.72)

                Spacer(minLength: 4)
                Text(detail)
                    .font(AppTypography.label.monospacedDigit())
                    .foregroundStyle(color)
                    .lineLimit(1)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, minHeight: 104, alignment: .leading)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }
}

private struct RecentVulnerabilityCard: View {
    @EnvironmentObject private var model: AppModel
    let records: [IntelligenceRecord]

    var body: some View {
        Panel {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(model.uiText("最新漏洞情报"))
                            .font(AppTypography.headline)
                        Text(model.uiText("最近一次情报目录更新收录的漏洞记录"))
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                    }
                    Spacer()
                }

                if records.isEmpty {
                    ContentUnavailableView(
                        model.uiText("暂无漏洞情报"),
                        systemImage: "shield.slash",
                        description: Text(model.uiText("情报目录更新后将在这里显示最新漏洞。"))
                    )
                    .frame(minHeight: 310)
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(records.prefix(5).enumerated()), id: \.element.id) { index, record in
                            VulnerabilityActivityRow(record: record)
                            if index < min(records.count, 5) - 1 {
                                Divider()
                                    .padding(.leading, 50)
                            }
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct VulnerabilityActivityRow: View {
    @EnvironmentObject private var model: AppModel
    let record: IntelligenceRecord

    private var color: Color {
        severityColor(record.severity)
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: severityIcon(record.severity))
                .font(AppTypography.system(size: 15, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 38, height: 38)
                .background(color.opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            VStack(alignment: .leading, spacing: 4) {
                Text(record.title.isEmpty ? model.uiText("未提供漏洞标题") : record.title)
                    .font(AppTypography.callout.weight(.medium))
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)
                    .truncationMode(.tail)
                HStack(spacing: 8) {
                    Text(record.id)
                        .font(AppTypography.caption.monospaced().weight(.semibold))
                        .foregroundStyle(AppPalette.primary)
                    Text("·")
                        .foregroundStyle(AppPalette.textSubtle)
                    Text(model.uiText("发布于 %@", dashboardDate(record.publishedAt, language: model.appLanguage)))
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                .lineLimit(1)
            }
            .layoutPriority(1)

            Spacer(minLength: 8)

            StatusBadge(text: severityLabel(record.severity, language: model.appLanguage), tone: .severity(record.severity))
                .fixedSize(horizontal: true, vertical: false)
                .layoutPriority(2)
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 2)
        .contentShape(Rectangle())
    }
}

private struct DashboardRiskChartsPanel: View {
    @EnvironmentObject private var model: AppModel
    let total: Int
    let severity: [String: Int]

    private var metrics: [DashboardSeverityMetric] {
        [
            DashboardSeverityMetric(
                key: "CRITICAL",
                label: model.uiText("严重"),
                value: count("CRITICAL"),
                color: AppPalette.danger
            ),
            DashboardSeverityMetric(
                key: "HIGH",
                label: model.uiText("高危"),
                value: count("HIGH"),
                color: AppPalette.warning
            ),
            DashboardSeverityMetric(
                key: "MEDIUM",
                label: model.uiText("中危"),
                value: count("MEDIUM"),
                color: AppPalette.medium
            ),
            DashboardSeverityMetric(
                key: "LOW",
                label: model.uiText("低危"),
                value: count("LOW"),
                color: AppPalette.success
            )
        ]
    }

    var body: some View {
        Panel {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(model.uiText("漏洞情报风险图表"))
                            .font(AppTypography.headline)
                        Text(model.uiText("按严重等级展示环形图与柱状图"))
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                    }
                    Spacer()
                    HStack(spacing: 8) {
                        Image(systemName: "chart.pie.fill")
                            .foregroundStyle(AppPalette.primary)
                        Text(total.formatted())
                            .font(AppTypography.callout.monospacedDigit().weight(.semibold))
                            .foregroundStyle(AppPalette.text)
                    }
                    .padding(.horizontal, 10)
                    .frame(height: 30)
                    .background(AppPalette.selectedStrong.opacity(0.72))
                    .clipShape(Capsule())
                }

                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .center, spacing: 24) {
                        DashboardSeverityRing(metrics: metrics, total: total)
                            .frame(width: 270, height: 220)
                        DashboardSeverityBarChart(metrics: metrics)
                            .frame(minWidth: 440, maxWidth: .infinity, minHeight: 220)
                    }

                    VStack(spacing: 18) {
                        DashboardSeverityRing(metrics: metrics, total: total)
                            .frame(height: 210)
                        DashboardSeverityBarChart(metrics: metrics)
                            .frame(height: 220)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func count(_ key: String) -> Int {
        severity[key] ?? 0
    }
}

private struct DashboardSeverityMetric: Identifiable {
    let key: String
    let label: String
    let value: Int
    let color: Color

    var id: String { key }
}

private struct DashboardSeverityRing: View {
    @EnvironmentObject private var model: AppModel
    let metrics: [DashboardSeverityMetric]
    let total: Int

    private var visibleMetrics: [DashboardSeverityMetric] {
        metrics.filter { $0.value > 0 }
    }

    private var chartTotal: Int {
        max(1, visibleMetrics.reduce(0) { $0 + $1.value })
    }

    var body: some View {
        HStack(spacing: 18) {
            ZStack {
                Circle()
                    .stroke(AppPalette.cardMuted, lineWidth: 22)

                if visibleMetrics.isEmpty {
                    Circle()
                        .trim(from: 0, to: 1)
                        .stroke(AppPalette.primary.opacity(0.32), style: StrokeStyle(lineWidth: 22, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                } else {
                    ForEach(Array(visibleMetrics.enumerated()), id: \.element.id) { index, metric in
                        Circle()
                            .trim(from: ringStart(for: index), to: ringEnd(for: index))
                            .stroke(metric.color, style: StrokeStyle(lineWidth: 22, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                    }
                }

                VStack(spacing: 2) {
                    Text(total.formatted())
                        .font(AppTypography.system(size: 26, weight: .bold, design: .rounded).monospacedDigit())
                        .foregroundStyle(AppPalette.text)
                        .minimumScaleFactor(0.58)
                        .lineLimit(1)
                    Text(model.uiText("漏洞总数"))
                        .font(AppTypography.caption2.weight(.medium))
                        .foregroundStyle(AppPalette.textMuted)
                }
                .frame(width: 110)
            }
            .frame(width: 154, height: 154)

            VStack(alignment: .leading, spacing: 9) {
                ForEach(metrics) { metric in
                    HStack(spacing: 8) {
                        Circle()
                            .fill(metric.color)
                            .frame(width: 8, height: 8)
                        Text(metric.label)
                            .font(AppTypography.caption.weight(.medium))
                            .foregroundStyle(AppPalette.text)
                        Spacer(minLength: 4)
                        Text(metric.value.formatted())
                            .font(AppTypography.caption.monospacedDigit().weight(.semibold))
                            .foregroundStyle(AppPalette.textMuted)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func ringStart(for index: Int) -> CGFloat {
        CGFloat(visibleMetrics.prefix(index).reduce(0) { $0 + $1.value }) / CGFloat(chartTotal)
    }

    private func ringEnd(for index: Int) -> CGFloat {
        CGFloat(visibleMetrics.prefix(index + 1).reduce(0) { $0 + $1.value }) / CGFloat(chartTotal)
    }
}

private struct DashboardSeverityBarChart: View {
    @EnvironmentObject private var model: AppModel
    let metrics: [DashboardSeverityMetric]

    private var maxValue: Int {
        max(1, metrics.map(\.value).max() ?? 1)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(model.uiText("风险柱状图"))
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Spacer()
                Text(model.uiText("按漏洞数量排序"))
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }

            HStack(alignment: .bottom, spacing: 18) {
                ForEach(metrics) { metric in
                    VStack(spacing: 9) {
                        Text(metric.value.formatted())
                            .font(AppTypography.caption.monospacedDigit().weight(.semibold))
                            .foregroundStyle(AppPalette.text)

                        GeometryReader { proxy in
                            let height = max(8, proxy.size.height * CGFloat(metric.value) / CGFloat(maxValue))
                            ZStack(alignment: .bottom) {
                                RoundedRectangle(cornerRadius: 8, style: .continuous)
                                    .fill(AppPalette.cardMuted)
                                RoundedRectangle(cornerRadius: 8, style: .continuous)
                                    .fill(
                                        LinearGradient(
                                            colors: [
                                                metric.color.opacity(0.82),
                                                metric.key == "CRITICAL" ? AppPalette.danger : AppPalette.primary
                                            ],
                                            startPoint: .bottom,
                                            endPoint: .top
                                        )
                                    )
                                    .frame(height: height)
                            }
                        }
                        .frame(height: 130)

                        HStack(spacing: 5) {
                            Circle()
                                .fill(metric.color)
                                .frame(width: 7, height: 7)
                            Text(metric.label)
                                .font(AppTypography.caption.weight(.medium))
                                .foregroundStyle(AppPalette.textMuted)
                                .lineLimit(1)
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
            }

            HStack(spacing: 8) {
                Image(systemName: "arrow.up.right.circle.fill")
                    .foregroundStyle(AppPalette.primary)
                Text(model.uiText("数据来自本地漏洞情报目录，不包含代码扫描结果，并随发布日期范围更新"))
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
                    .lineLimit(2)
                Spacer(minLength: 0)
            }
            .padding(10)
            .background(AppPalette.primary.opacity(0.055))
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
    }
}

private struct RiskProgressRow: View {
    let label: String
    let value: Int
    let total: Int
    let color: Color

    private var progress: Double {
        guard total > 0 else { return 0 }
        return min(max(Double(value) / Double(total), 0), 1)
    }

    var body: some View {
        VStack(spacing: 7) {
            HStack {
                HStack(spacing: 7) {
                    Circle()
                        .fill(color)
                        .frame(width: 7, height: 7)
                    Text(label)
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
                Text("\(value.formatted()) · \(Int((progress * 100).rounded()))%")
                    .font(AppTypography.caption.monospacedDigit().weight(.semibold))
                    .foregroundStyle(AppPalette.text)
            }
            ProgressView(value: progress)
                .progressViewStyle(.linear)
                .tint(color)
        }
    }
}

private struct PriorityRiskCard: View {
    @EnvironmentObject private var model: AppModel
    let records: [IntelligenceRecord]

    private var priorityRecords: [IntelligenceRecord] {
        let knownRecords = records.filter { isKnownSeverity($0.severity) }
        let highRisk = knownRecords.filter { normalizedSeverity($0.severity) == "CRITICAL" || normalizedSeverity($0.severity) == "HIGH" }
        return Array((highRisk.isEmpty ? knownRecords : highRisk).prefix(4))
    }

    var body: some View {
        Panel {
            VStack(alignment: .leading, spacing: 14) {
                Text(model.uiText("重点漏洞情报"))
                    .font(AppTypography.headline)

                if priorityRecords.isEmpty {
                    Text(model.uiText("暂无需要优先关注的漏洞情报"))
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                        .frame(maxWidth: .infinity, minHeight: 80, alignment: .center)
                } else {
                    ForEach(priorityRecords) { record in
                        HStack(spacing: 10) {
                            RoundedRectangle(cornerRadius: 2)
                                .fill(severityColor(record.severity))
                                .frame(width: 4, height: 26)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(record.id)
                                    .font(AppTypography.caption.monospaced().weight(.semibold))
                                    .foregroundStyle(AppPalette.text)
                                    .lineLimit(1)
                                Text(record.title.isEmpty ? model.uiText("未提供漏洞标题") : record.title)
                                    .font(AppTypography.caption2)
                                    .foregroundStyle(AppPalette.textMuted)
                                    .lineLimit(1)
                            }
                            Spacer(minLength: 4)
                            Text(priorityValue(record))
                                .font(AppTypography.caption.monospacedDigit().weight(.semibold))
                                .foregroundStyle(severityColor(record.severity))
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func priorityValue(_ record: IntelligenceRecord) -> String {
        if let score = record.cvssScore {
            return String(format: "%.1f", score)
        }
        return severityLabel(record.severity, language: model.appLanguage)
    }
}

private func severityColor(_ value: String) -> Color {
    switch normalizedSeverity(value) {
    case "CRITICAL", "SEVERE", "严重": AppPalette.danger
    case "HIGH", "高危": AppPalette.warning
    case "MEDIUM", "MODERATE", "中危": AppPalette.medium
    case "LOW", "低危": AppPalette.success
    default: AppPalette.textSubtle
    }
}

private func severityIcon(_ value: String) -> String {
    switch normalizedSeverity(value) {
    case "CRITICAL", "SEVERE", "严重": "exclamationmark.octagon.fill"
    case "HIGH", "高危": "exclamationmark.triangle.fill"
    case "MEDIUM", "MODERATE", "中危": "exclamationmark.circle.fill"
    case "LOW", "低危": "info.circle.fill"
    default: "questionmark.circle.fill"
    }
}

private func isKnownSeverity(_ value: String) -> Bool {
    ["CRITICAL", "SEVERE", "HIGH", "MEDIUM", "MODERATE", "LOW", "严重", "高危", "中危", "低危"]
        .contains(normalizedSeverity(value))
}

private func normalizedSeverity(_ value: String) -> String {
    value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
}

private func dashboardDate(_ value: String?, language: AppLanguage) -> String {
    guard let value, !value.isEmpty else { return localizedUI("时间未知", language: language) }
    return dashboardDateTime(value, includeTime: false, locale: language.locale)
}

private func dashboardDateTime(_ value: String, includeTime: Bool = true, locale: Locale) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    guard let date else {
        return String(value.prefix(includeTime ? 16 : 10)).replacingOccurrences(of: "T", with: " ")
    }

    let style = Date.FormatStyle(
        date: .abbreviated,
        time: includeTime ? .shortened : .omitted
    )
    .locale(locale)
    return date.formatted(style)
}
