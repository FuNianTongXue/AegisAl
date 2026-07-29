import SwiftUI

private enum InformationPopoverSection: String, CaseIterable, Identifiable {
    case discover
    case latest
    case breaking

    var id: String { rawValue }

    @MainActor
    func title(_ model: AppModel) -> String {
        switch self {
        case .discover: model.uiText("发现")
        case .latest: model.uiText("最新")
        case .breaking: model.uiText("快讯")
        }
    }
}

struct InformationPopoverView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL

    let onClose: () -> Void

    @State private var selectedSection: InformationPopoverSection = .discover
    @State private var hoveredItemID: String?
    @State private var isLivePollingEnabled = true
    @State private var isManualRefreshActive = false
    @State private var lastManualRefreshCompletedAt: Date?
    @State private var showingSourceManager = false

    private var isRefreshing: Bool {
        isManualRefreshActive
            || model.busyActions.contains("information-refresh")
            || model.information?.isUpdating == true
    }

    var body: some View {
        let shape = InformationPopoverShape()
        ZStack {
            shape.fill(AppPalette.page)

            VStack(spacing: 0) {
                Color.clear.frame(height: InformationPopoverShape.arrowHeight)
                if showingSourceManager {
                    InformationPopoverSourceManagerView(
                        onBack: {
                            withAnimation(.easeInOut(duration: 0.2)) {
                                showingSourceManager = false
                            }
                        },
                        onClose: onClose
                    )
                    .transition(.move(edge: .trailing).combined(with: .opacity))
                } else {
                    header
                    feed
                    footer
                }
            }
        }
        .frame(
            width: InformationPanelMetrics.defaultSize.width,
            height: InformationPanelMetrics.defaultSize.height
        )
        .clipShape(shape)
        .overlay {
            shape.stroke(AppPalette.border, lineWidth: 1)
        }
        .contentShape(shape)
        .onExitCommand(perform: onClose)
        .task(id: isLivePollingEnabled) {
            guard isLivePollingEnabled else { return }
            await runPollingLoop()
        }
        .onChange(of: selectedSection) { _, _ in hoveredItemID = nil }
    }

    private var header: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 10) {
                Spacer(minLength: 0)

                headerButton(
                    systemName: isLivePollingEnabled ? "circle.dotted" : "circle",
                    help: model.uiText(isLivePollingEnabled ? "暂停轮询" : "继续轮询")
                ) {
                    isLivePollingEnabled.toggle()
                }

                headerButton(
                    systemName: "gearshape",
                    help: model.uiText("管理订阅来源")
                ) {
                    showingSourceManager = true
                }
            }
            .padding(.horizontal, 16)
            .frame(height: 44)

            HStack(spacing: 0) {
                ForEach(InformationPopoverSection.allCases) { section in
                    Button {
                        withAnimation(.easeInOut(duration: 0.18)) {
                            selectedSection = section
                        }
                    } label: {
                        VStack(spacing: 5) {
                            Text(section.title(model))
                                .font(AppTypography.system(size: 13, weight: .bold))
                                .foregroundStyle(
                                    selectedSection == section
                                        ? AppPalette.sidebarText
                                        : AppPalette.sidebarTextMuted
                                )
                            Capsule()
                                .fill(selectedSection == section ? AppPalette.primaryStrong : Color.clear)
                                .frame(width: 18, height: 2)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .frame(height: 40)
        }
        .background(AppPalette.sidebar)
    }

    private var feed: some View {
        Group {
            if displayedItems.isEmpty {
                emptyState
            } else {
                ScrollViewReader { proxy in
                    ScrollView(.vertical, showsIndicators: false) {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            Color.clear
                                .frame(height: 0)
                                .id("information-feed-top")
                            ForEach(displayedItems) { item in
                                imageTile(item)
                                    .id(item.id)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .onChange(of: model.information?.lastRefresh) { oldValue, newValue in
                        guard let oldValue, let newValue, oldValue != newValue else { return }
                        withAnimation(.easeOut(duration: 0.22)) {
                            proxy.scrollTo("information-feed-top", anchor: .top)
                        }
                    }
                    .onChange(of: displayedItems.first?.id) { oldValue, newValue in
                        guard informationFeedShouldScrollToTop(
                            previousHeadlineID: oldValue,
                            currentHeadlineID: newValue
                        ) else { return }
                        hoveredItemID = nil
                        withAnimation(.easeOut(duration: 0.22)) {
                            proxy.scrollTo("information-feed-top", anchor: .top)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
    }

    private func imageTile(_ item: InformationItem) -> some View {
        Button { open(item) } label: {
            ZStack(alignment: .bottomLeading) {
                InformationArtwork(item: item, cornerRadius: 0)
                    .frame(maxWidth: .infinity)
                    .frame(height: 190)

                LinearGradient(
                    colors: [
                        .clear,
                        Color.black.opacity(hoveredItemID == item.id ? 0.92 : 0.78),
                    ],
                    startPoint: .center,
                    endPoint: .bottom
                )
                .allowsHitTesting(false)

                VStack(alignment: .leading, spacing: 6) {
                    Text(item.title)
                        .font(AppTypography.system(size: 14, weight: .bold))
                        .foregroundStyle(.white)
                        .lineLimit(3)
                        .multilineTextAlignment(.leading)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    HStack(spacing: 6) {
                        Text(item.sourceName)
                            .lineLimit(1)
                        if !item.category.isEmpty {
                            Text("·")
                            Text(item.category)
                                .lineLimit(1)
                        }
                    }
                    .font(AppTypography.caption)
                    .foregroundStyle(Color.white.opacity(0.74))
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 14)
                .padding(.bottom, 13)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .frame(height: 190)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { isInside in
            hoveredItemID = isInside ? item.id : nil
        }
        .help(item.title)
    }

    private var footer: some View {
        HStack(spacing: 12) {
            Button {
                Task { await performManualRefresh() }
            } label: {
                Group {
                    if isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(AppTypography.system(size: 15, weight: .semibold))
                    }
                }
                .foregroundStyle(.white)
                .frame(width: 38, height: 38)
                .background(AppPalette.primaryStrong)
                .clipShape(Circle())
                .shadow(color: AppPalette.primary.opacity(0.22), radius: 5, y: 2)
            }
            .buttonStyle(.plain)
            .disabled(isRefreshing)
            .help(model.uiText("刷新最新资讯"))

            VStack(alignment: .leading, spacing: 2) {
                Text(refreshStatusTitle)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.sidebarText)
                    .lineLimit(1)
                Text(model.information?.message ?? model.uiText("点击刷新最新资讯"))
                    .font(AppTypography.caption2)
                    .foregroundStyle(AppPalette.sidebarTextMuted)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(height: 66)
        .background {
            Rectangle()
                .fill(AppPalette.sidebar)
        }
    }

    private var refreshStatusTitle: String {
        if isRefreshing {
            return model.uiText("正在实时刷新")
        }
        if lastManualRefreshCompletedAt != nil {
            return model.uiText("刚刚已更新")
        }
        return model.uiText("实时资讯")
    }

    private func headerButton(
        systemName: String,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(AppTypography.system(size: 18, weight: .medium))
                .foregroundStyle(AppPalette.sidebarTextMuted)
                .frame(width: 28, height: 28)
        }
        .buttonStyle(.plain)
        .help(help)
    }

    private var displayedItems: [InformationItem] {
        guard let snapshot = model.information else { return [] }
        switch selectedSection {
        case .discover:
            return Array(informationItemsNewestFirst(snapshot.briefs + snapshot.items).prefix(40))
        case .latest:
            return Array(informationItemsNewestFirst(snapshot.items).prefix(40))
        case .breaking:
            let breaking = informationItemsNewestFirst(snapshot.items.filter(\.breaking))
            if !breaking.isEmpty { return Array(breaking.prefix(40)) }
            return Array(
                informationItemsNewestFirst(snapshot.items.filter { $0.category == "漏洞披露" })
                    .prefix(40)
            )
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            if isRefreshing {
                ProgressView().controlSize(.large)
            } else {
                Image(systemName: "photo.on.rectangle.angled")
                    .font(AppTypography.system(size: 26, weight: .light))
            }
            Text(isRefreshing ? model.uiText("正在接入公开安全资讯") : model.uiText("暂无重点资讯"))
                .font(AppTypography.callout.weight(.medium))
        }
        .foregroundStyle(AppPalette.textMuted)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func open(_ item: InformationItem) {
        guard let url = URL(string: item.url) else { return }
        openURL(url)
    }

    @MainActor
    private func performManualRefresh() async {
        guard !isManualRefreshActive else { return }
        isManualRefreshActive = true
        withAnimation(.easeInOut(duration: 0.18)) {
            selectedSection = .latest
        }
        let refreshed = await model.refreshInformation(force: true)
        isManualRefreshActive = false
        if refreshed {
            lastManualRefreshCompletedAt = Date()
        }
    }

    private func runPollingLoop() async {
        if model.information == nil {
            await model.refreshInformation()
        }
        while !Task.isCancelled {
            let interval = informationPollingNanoseconds(refreshing: model.information?.isUpdating == true)
            try? await Task.sleep(nanoseconds: interval)
            guard !Task.isCancelled else { return }
            await model.refreshInformation()
        }
    }
}

func informationFeedShouldScrollToTop(
    previousHeadlineID: String?,
    currentHeadlineID: String?
) -> Bool {
    guard let currentHeadlineID, !currentHeadlineID.isEmpty else { return false }
    return previousHeadlineID != currentHeadlineID
}

func informationItemsNewestFirst(_ items: [InformationItem]) -> [InformationItem] {
    let sorted = items.sorted { lhs, rhs in
        let lhsDate = informationPopoverDate(lhs.publishedAt) ?? .distantPast
        let rhsDate = informationPopoverDate(rhs.publishedAt) ?? .distantPast
        if lhsDate != rhsDate { return lhsDate > rhsDate }
        return lhs.id > rhs.id
    }
    var seenIDs: Set<String> = []
    return sorted.filter { seenIDs.insert($0.id).inserted }
}

private func informationPopoverDate(_ value: String) -> Date? {
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
}

struct InformationPopoverSourceManagerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL

    let onBack: () -> Void
    let onClose: () -> Void

    @State private var query = ""
    @State private var selectedGroup = "全部"

    private var isRefreshing: Bool {
        model.busyActions.contains("information-refresh") || model.information?.isUpdating == true
    }

    var body: some View {
        VStack(spacing: 0) {
            managerHeader
            ScrollView(.vertical, showsIndicators: false) {
                LazyVStack(alignment: .leading, spacing: 10) {
                    filterCard
                    sourceSummary
                    ForEach(filteredSources) { source in
                        sourceRow(source)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            managerFooter
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .onChange(of: selectedGroup) { _, _ in
            if !groupNames.contains(selectedGroup) {
                selectedGroup = "全部"
            }
        }
    }

    private var managerHeader: some View {
        ZStack {
            HStack {
                managerIconButton(
                    systemName: "chevron.left",
                    help: model.uiText("返回资讯")
                ) {
                    onBack()
                }
                Spacer()
                managerIconButton(
                    systemName: "power",
                    help: model.uiText("关闭")
                ) {
                    onClose()
                }
            }

            VStack(spacing: 2) {
                Text(model.uiText("来源管理"))
                    .font(AppTypography.system(size: 20, weight: .bold))
                    .foregroundStyle(AppPalette.sidebarText)
                Text(model.uiText("%d 个来源 · %d 个已启用", sources.count, enabledSourceCount))
                    .font(AppTypography.caption2.monospacedDigit())
                    .foregroundStyle(AppPalette.sidebarTextMuted)
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 66)
        .background(AppPalette.sidebar)
    }

    private var filterCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 9) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(AppPalette.textMuted)
                TextField(model.uiText("搜索来源名称"), text: $query)
                    .textFieldStyle(.plain)
                    .foregroundStyle(AppPalette.text)
                if !query.isEmpty {
                    Button { query = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(AppPalette.textMuted)
                    }
                    .buttonStyle(.plain)
                    .help(model.uiText("清除搜索"))
                }
            }
            .padding(.horizontal, 11)
            .frame(height: 36)
            .background(AppPalette.cardMuted)
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.border)
            }

            Picker(model.uiText("来源分组"), selection: $selectedGroup) {
                ForEach(groupNames, id: \.self) { group in
                    Text(model.uiText(group)).tag(group)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            HStack(spacing: 10) {
                Label(
                    isRefreshing ? model.uiText("检测中") : model.uiText("检测已启用"),
                    systemImage: "waveform.path.ecg"
                )
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)

                Spacer()

                Button {
                    Task { await model.refreshInformation(force: true) }
                } label: {
                    Group {
                        if isRefreshing {
                            ProgressView().controlSize(.mini).tint(AppPalette.primaryStrong)
                        } else {
                            Image(systemName: "arrow.clockwise")
                        }
                    }
                    .frame(width: 30, height: 28)
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppPalette.primaryStrong)
                .background(AppPalette.selected)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                .disabled(isRefreshing)
                .help(model.uiText("刷新最新资讯"))
            }
        }
        .padding(12)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }

    private var sourceSummary: some View {
        HStack(spacing: 8) {
            Image(systemName: "dot.radiowaves.left.and.right")
                .foregroundStyle(AppPalette.primaryStrong)
            Text(model.uiText(selectedGroup))
                .font(AppTypography.callout.weight(.bold))
            Text("\(filteredSources.count)")
                .font(AppTypography.caption.monospacedDigit())
                .foregroundStyle(AppPalette.textMuted)
            Spacer()
        }
        .padding(.horizontal, 2)
    }

    private func sourceRow(_ source: InformationSource) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(popoverSourceColor(source.id).opacity(0.18))
                    .frame(width: 38, height: 38)
                    .overlay {
                        Image(systemName: popoverSourceIcon(source.id))
                            .font(AppTypography.system(size: 14, weight: .semibold))
                            .foregroundStyle(popoverSourceColor(source.id))
                    }

                VStack(alignment: .leading, spacing: 3) {
                    Text(source.name)
                        .font(AppTypography.callout.weight(.semibold))
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)
                    HStack(spacing: 5) {
                        Circle()
                            .fill(popoverSourceStatusColor(source.status))
                            .frame(width: 6, height: 6)
                        Text(model.uiText(popoverSourceStatusLabel(source.status)))
                        Text("·")
                        Text(model.uiText("%d 条", source.itemCount))
                    }
                    .font(AppTypography.caption2)
                    .foregroundStyle(AppPalette.textMuted)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                if model.busyActions.contains("information-source:\(source.id)") {
                    ProgressView().controlSize(.mini).tint(AppPalette.primaryStrong)
                        .frame(width: 38)
                } else {
                    Toggle("", isOn: Binding(
                        get: { source.enabled },
                        set: { enabled in
                            Task { await model.setInformationSource(id: source.id, enabled: enabled) }
                        }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .frame(width: 38)
                }
            }

            HStack(spacing: 8) {
                Text(source.message.isEmpty ? source.website : source.message)
                    .font(AppTypography.caption2)
                    .foregroundStyle(
                        source.status == "error"
                            ? AppPalette.warning
                            : AppPalette.textMuted
                    )
                    .lineLimit(2)
                    .frame(maxWidth: .infinity, alignment: .leading)

                sourceActionButton(
                    systemName: "waveform.path.ecg",
                    busy: model.busyActions.contains("information-source-test:\(source.id)"),
                    help: model.uiText("检测来源")
                ) {
                    Task { await model.testInformationSource(id: source.id) }
                }

                sourceActionButton(
                    systemName: "arrow.up.right.square",
                    help: model.uiText("打开来源网站")
                ) {
                    if let url = URL(string: source.website) {
                        openURL(url)
                    }
                }
            }
        }
        .padding(12)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }

    private func managerIconButton(
        systemName: String,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(AppTypography.system(size: 18, weight: .medium))
                .foregroundStyle(AppPalette.sidebarTextMuted)
                .frame(width: 34, height: 34)
        }
        .buttonStyle(.plain)
        .help(help)
    }

    private func sourceActionButton(
        systemName: String,
        busy: Bool = false,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Group {
                if busy {
                    ProgressView().controlSize(.mini).tint(AppPalette.primaryStrong)
                } else {
                    Image(systemName: systemName)
                }
            }
            .foregroundStyle(AppPalette.textMuted)
            .frame(width: 28, height: 28)
            .background(AppPalette.cardMuted)
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .buttonStyle(.plain)
        .disabled(busy)
        .help(help)
    }

    private var managerFooter: some View {
        HStack(spacing: 12) {
            Label(
                model.uiText("OPML 已启用 %d/%d", enabledOPMLCount, opmlEnabledLimit),
                systemImage: "doc.text"
            )
            Spacer()
            Text(model.uiText("已启用 %d", enabledSourceCount))
        }
        .font(AppTypography.caption2)
        .foregroundStyle(AppPalette.sidebarTextMuted)
        .padding(.horizontal, 14)
        .frame(height: 40)
        .background(AppPalette.sidebar)
    }

    private var sources: [InformationSource] {
        model.information?.sources ?? []
    }

    private var groupNames: [String] {
        ["全部"] + ["精选来源", "微信公众号", "安全 RSS"].filter { group in
            sources.contains { $0.resolvedGroup == group }
        }
    }

    private var filteredSources: [InformationSource] {
        let cleanQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return sources.filter { source in
            let groupMatches = selectedGroup == "全部" || source.resolvedGroup == selectedGroup
            let queryMatches = cleanQuery.isEmpty
                || source.name.localizedCaseInsensitiveContains(cleanQuery)
                || source.website.localizedCaseInsensitiveContains(cleanQuery)
            return groupMatches && queryMatches
        }
    }

    private var enabledSourceCount: Int { sources.filter(\.enabled).count }

    private var enabledOPMLCount: Int {
        model.information?.sourceSummary?.opmlEnabled
            ?? sources.filter { $0.isBundledOPML && $0.enabled }.count
    }

    private var opmlEnabledLimit: Int {
        model.information?.sourceSummary?.opmlEnabledLimit ?? 50
    }
}

private func popoverSourceColor(_ sourceID: String) -> Color {
    let normalized = sourceID.lowercased()
    if normalized.contains("cisa") { return AppPalette.danger }
    if normalized.contains("freebuf") { return AppPalette.success }
    if normalized.contains("github") { return AppPalette.text }
    if normalized.contains("wechat") { return Color(red: 0.10, green: 0.78, blue: 0.42) }
    return AppPalette.primaryStrong
}

private func popoverSourceIcon(_ sourceID: String) -> String {
    let normalized = sourceID.lowercased()
    if normalized.contains("cisa") { return "shield.fill" }
    if normalized.contains("github") { return "chevron.left.forwardslash.chevron.right" }
    if normalized.contains("wechat") { return "message.fill" }
    return "newspaper.fill"
}

private func popoverSourceStatusColor(_ status: String) -> Color {
    switch status.lowercased() {
    case "ok", "ready", "success": AppPalette.success
    case "error", "failed": AppPalette.warning
    case "refreshing", "running": AppPalette.primaryStrong
    default: AppPalette.textMuted
    }
}

private func popoverSourceStatusLabel(_ status: String) -> String {
    switch status.lowercased() {
    case "ok", "ready", "success": "正常"
    case "error", "failed": "异常"
    case "refreshing", "running": "检测中"
    default: "等待"
    }
}

struct InformationPopoverShape: Shape {
    static let arrowHeight: CGFloat = 15

    func path(in rect: CGRect) -> Path {
        let radius: CGFloat = 20
        let arrowHalfWidth: CGFloat = 18
        let centerX = rect.midX
        let top = Self.arrowHeight
        var path = Path()

        path.move(to: CGPoint(x: radius, y: top))
        path.addLine(to: CGPoint(x: centerX - arrowHalfWidth, y: top))
        path.addCurve(
            to: CGPoint(x: centerX - 7, y: 7),
            control1: CGPoint(x: centerX - 13, y: top),
            control2: CGPoint(x: centerX - 11, y: 9)
        )
        path.addQuadCurve(
            to: CGPoint(x: centerX, y: 0),
            control: CGPoint(x: centerX - 3, y: 2)
        )
        path.addQuadCurve(
            to: CGPoint(x: centerX + 7, y: 7),
            control: CGPoint(x: centerX + 3, y: 2)
        )
        path.addCurve(
            to: CGPoint(x: centerX + arrowHalfWidth, y: top),
            control1: CGPoint(x: centerX + 11, y: 9),
            control2: CGPoint(x: centerX + 13, y: top)
        )
        path.addLine(to: CGPoint(x: rect.maxX - radius, y: top))
        path.addQuadCurve(
            to: CGPoint(x: rect.maxX, y: top + radius),
            control: CGPoint(x: rect.maxX, y: top)
        )
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - radius))
        path.addQuadCurve(
            to: CGPoint(x: rect.maxX - radius, y: rect.maxY),
            control: CGPoint(x: rect.maxX, y: rect.maxY)
        )
        path.addLine(to: CGPoint(x: radius, y: rect.maxY))
        path.addQuadCurve(
            to: CGPoint(x: 0, y: rect.maxY - radius),
            control: CGPoint(x: 0, y: rect.maxY)
        )
        path.addLine(to: CGPoint(x: 0, y: top + radius))
        path.addQuadCurve(
            to: CGPoint(x: radius, y: top),
            control: CGPoint(x: 0, y: top)
        )
        path.closeSubpath()
        return path
    }
}
