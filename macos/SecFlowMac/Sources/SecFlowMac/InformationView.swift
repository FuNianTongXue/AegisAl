import AppKit
import SwiftUI

struct InformationTickerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL

    let onClose: () -> Void

    @State private var selectedIndex = 0
    @State private var isPointerInside = false
    @State private var isAutoPlaying = true
    @State private var showingSourceManager = false

    private var isRefreshing: Bool {
        model.busyActions.contains("information-refresh") || model.information?.isUpdating == true
    }

    var body: some View {
        VStack(spacing: 0) {
            tickerHeader
            Divider().overlay(Color.white.opacity(0.10))

            if let selectedItem {
                hero(item: selectedItem)
                    .padding(10)
                    .padding(.bottom, 2)

                Divider()
                    .overlay(Color.white.opacity(0.08))
                    .padding(.horizontal, 10)

                VStack(spacing: 0) {
                    ForEach(Array(upcomingItems.enumerated()), id: \.element.id) { index, item in
                        tickerRow(item)
                            .frame(maxHeight: .infinity)
                        if index < upcomingItems.count - 1 {
                            Divider()
                                .overlay(Color.white.opacity(0.07))
                                .padding(.leading, 88)
                        }
                    }
                }
                .frame(maxHeight: .infinity, alignment: .top)
            } else {
                emptyState
                    .frame(maxHeight: .infinity)
            }

            tickerFooter
        }
        .frame(
            width: InformationPanelMetrics.defaultSize.width,
            height: InformationPanelMetrics.defaultSize.height
        )
        .foregroundStyle(Color.white)
        .background {
            ZStack {
                Rectangle().fill(.ultraThinMaterial)
                Color(red: 0.075, green: 0.078, blue: 0.086).opacity(0.88)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.white.opacity(0.14), lineWidth: 1)
        }
        .contentShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .onHover { isPointerInside = $0 }
        .task { await runPollingLoop() }
        .task(id: tickerItems.map(\.id)) { await runRotationLoop() }
        .onChange(of: tickerItems.map(\.id)) { _, _ in selectedIndex = 0 }
        .sheet(isPresented: $showingSourceManager) {
            InformationSourceManagerView()
                .environmentObject(model)
                .frame(width: 760, height: 620)
        }
    }

    private var tickerHeader: some View {
        HStack(spacing: 9) {
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(Color.white.opacity(0.10))
                .frame(width: 30, height: 30)
                .overlay {
                    Image(systemName: "newspaper.fill")
                        .font(AppTypography.system(size: 13, weight: .semibold))
                        .foregroundStyle(AppPalette.primary)
                }

            VStack(alignment: .leading, spacing: 1) {
                Text("SECFLOW")
                    .font(AppTypography.system(size: 12, weight: .bold))
                Text(model.text(.navInformation))
                    .font(AppTypography.system(size: 10, weight: .medium))
                    .foregroundStyle(Color.white.opacity(0.58))
            }

            Spacer(minLength: 4)

            HStack(spacing: 5) {
                Circle()
                    .fill(isRefreshing ? AppPalette.warning : AppPalette.success)
                    .frame(width: 6, height: 6)
                Text(isRefreshing ? model.uiText("更新中") : model.uiText("实时"))
                    .font(AppTypography.system(size: 10, weight: .semibold))
                    .foregroundStyle(Color.white.opacity(0.62))
                    .lineLimit(1)
            }

            tickerIconButton(
                systemName: "slider.horizontal.3",
                help: model.uiText("管理订阅来源")
            ) {
                showingSourceManager = true
            }

            tickerIconButton(
                systemName: "arrow.clockwise",
                help: model.uiText("刷新最新资讯"),
                disabled: isRefreshing
            ) {
                Task { await model.refreshInformation(force: true) }
            }

            tickerIconButton(systemName: "xmark", help: model.uiText("关闭"), action: onClose)
        }
        .padding(.horizontal, 12)
        .frame(height: 52)
        .background(Color.black.opacity(0.15))
    }

    private func hero(item: InformationItem) -> some View {
        Button { open(item) } label: {
            ZStack(alignment: .bottomLeading) {
                InformationArtwork(item: item)
                    .frame(maxWidth: .infinity)
                    .frame(height: 226)

                LinearGradient(
                    colors: [.clear, Color.black.opacity(0.24), Color.black.opacity(0.92)],
                    startPoint: .top,
                    endPoint: .bottom
                )

                VStack(alignment: .leading, spacing: 7) {
                    HStack(spacing: 6) {
                        if item.breaking {
                            tickerBadge(model.uiText("快讯"), color: AppPalette.danger)
                        }
                        tickerBadge(item.category, color: categoryColor(item.category))
                        Spacer()
                        Text("\(normalizedIndex + 1)/\(tickerItems.count)")
                            .font(AppTypography.caption2.monospacedDigit().weight(.semibold))
                            .foregroundStyle(Color.white.opacity(0.66))
                    }

                    Text(item.title)
                        .font(AppTypography.system(size: 17, weight: .bold))
                        .foregroundStyle(.white)
                        .lineLimit(3)
                        .multilineTextAlignment(.leading)

                    HStack(spacing: 6) {
                        Text(item.sourceName)
                            .fontWeight(.semibold)
                            .lineLimit(1)
                        Text("·")
                        Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                            .lineLimit(1)
                    }
                    .font(AppTypography.caption)
                    .foregroundStyle(Color.white.opacity(0.70))
                }
                .padding(13)
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(Color.white.opacity(0.13))
            }
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(.plain)
        .help(model.uiText("在浏览器中打开"))
    }

    private func tickerRow(_ item: InformationItem) -> some View {
        Button {
            if let index = tickerItems.firstIndex(where: { $0.id == item.id }) {
                withAnimation(.easeInOut(duration: 0.22)) { selectedIndex = index }
            }
        } label: {
            HStack(spacing: 10) {
                InformationArtwork(item: item, compact: true)
                    .frame(width: 68, height: 52)
                    .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))

                VStack(alignment: .leading, spacing: 5) {
                    Text(item.title)
                        .font(AppTypography.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.white.opacity(0.90))
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)

                    HStack(spacing: 5) {
                        Text(item.sourceName)
                            .lineLimit(1)
                        Text("·")
                        Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                            .lineLimit(1)
                    }
                    .font(AppTypography.system(size: 10, weight: .medium))
                    .foregroundStyle(Color.white.opacity(0.48))
                }

                Spacer(minLength: 2)
                Image(systemName: "chevron.right")
                    .font(AppTypography.system(size: 9, weight: .bold))
                    .foregroundStyle(Color.white.opacity(0.28))
            }
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, minHeight: 70, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(item.title)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            if isRefreshing {
                ProgressView()
                    .controlSize(.large)
                    .tint(.white)
            } else {
                Image(systemName: "newspaper")
                    .font(AppTypography.system(size: 28, weight: .light))
                    .foregroundStyle(Color.white.opacity(0.42))
            }
            Text(isRefreshing ? model.uiText("正在接入公开安全资讯") : model.uiText("暂无重点资讯"))
                .font(AppTypography.callout.weight(.medium))
                .foregroundStyle(Color.white.opacity(0.58))
        }
    }

    private var tickerFooter: some View {
        HStack(spacing: 8) {
            Text("\(model.information?.availableTotal ?? 0)")
                .font(AppTypography.caption.monospacedDigit().weight(.bold))
                .foregroundStyle(Color.white.opacity(0.78))
            Text(model.uiText("条资讯"))
                .font(AppTypography.caption)
                .foregroundStyle(Color.white.opacity(0.46))

            Spacer()

            tickerIconButton(
                systemName: "chevron.left",
                help: model.uiText("上一条重点资讯"),
                disabled: tickerItems.count < 2
            ) {
                moveSelection(by: -1)
            }

            tickerIconButton(
                systemName: isAutoPlaying ? "pause.fill" : "play.fill",
                help: model.uiText(isAutoPlaying ? "暂停轮播" : "继续轮播"),
                disabled: tickerItems.count < 2
            ) {
                isAutoPlaying.toggle()
            }

            tickerIconButton(
                systemName: "chevron.right",
                help: model.uiText("下一条重点资讯"),
                disabled: tickerItems.count < 2
            ) {
                moveSelection(by: 1)
            }
        }
        .padding(.horizontal, 12)
        .frame(height: 46)
        .background(Color.black.opacity(0.18))
        .overlay(alignment: .top) {
            Divider().overlay(Color.white.opacity(0.09))
        }
    }

    private func tickerIconButton(
        systemName: String,
        help: String,
        disabled: Bool = false,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Group {
                if systemName == "arrow.clockwise" && isRefreshing {
                    ProgressView().controlSize(.mini)
                } else {
                    Image(systemName: systemName)
                        .font(AppTypography.system(size: 10, weight: .semibold))
                }
            }
            .frame(width: 26, height: 26)
            .foregroundStyle(Color.white.opacity(disabled ? 0.24 : 0.70))
            .background(Color.white.opacity(disabled ? 0.025 : 0.065))
            .clipShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .help(help)
    }

    private func tickerBadge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(AppTypography.system(size: 9, weight: .bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .frame(height: 19)
            .background(color.opacity(0.90))
            .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
    }

    private var tickerItems: [InformationItem] {
        Array((model.information?.items ?? []).prefix(12))
    }

    private var normalizedIndex: Int {
        guard !tickerItems.isEmpty else { return 0 }
        return min(max(selectedIndex, 0), tickerItems.count - 1)
    }

    private var selectedItem: InformationItem? {
        guard tickerItems.indices.contains(normalizedIndex) else { return nil }
        return tickerItems[normalizedIndex]
    }

    private var upcomingItems: [InformationItem] {
        guard tickerItems.count > 1 else { return [] }
        let count = min(3, tickerItems.count - 1)
        return (1...count).map { tickerItems[(normalizedIndex + $0) % tickerItems.count] }
    }

    private func moveSelection(by offset: Int) {
        guard tickerItems.count > 1 else { return }
        withAnimation(.easeInOut(duration: 0.22)) {
            selectedIndex = (normalizedIndex + offset + tickerItems.count) % tickerItems.count
        }
    }

    private func open(_ item: InformationItem) {
        guard let url = URL(string: item.url) else { return }
        openURL(url)
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

    private func runRotationLoop() async {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: informationRotationNanoseconds())
            guard !Task.isCancelled else { return }
            guard isAutoPlaying, !isPointerInside, tickerItems.count > 1 else { continue }
            moveSelection(by: 1)
        }
    }
}

struct InformationView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL

    @State private var searchText = ""
    @State private var selectedCategory = "全部"
    @State private var sortMode: InformationSortMode = .latest
    @State private var visibleCount = 14
    @State private var selectedFeatureIndex = 0
    @State private var showingSourceManager = false

    private var isRefreshing: Bool {
        model.busyActions.contains("information-refresh") || model.information?.isUpdating == true
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header
                    .padding(.horizontal, 24)
                    .padding(.top, 20)
                    .padding(.bottom, 16)

                Divider().overlay(AppPalette.border)

                categoryBar
                    .padding(.horizontal, 24)

                Divider().overlay(AppPalette.border)

                content
                    .padding(24)
            }
            .frame(maxWidth: 1380)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .defaultScrollAnchor(.top)
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .task {
            if model.information == nil {
                await model.refreshInformation()
            }
            while !Task.isCancelled {
                let interval = informationPollingNanoseconds(
                    refreshing: model.information?.isUpdating == true
                )
                try? await Task.sleep(nanoseconds: interval)
                guard !Task.isCancelled else { return }
                await model.refreshInformation()
            }
        }
        .onChange(of: searchText) { _, _ in resetFeedPosition() }
        .onChange(of: selectedCategory) { _, _ in resetFeedPosition() }
        .onChange(of: sortMode) { _, _ in resetFeedPosition() }
        .sheet(isPresented: $showingSourceManager) {
            InformationSourceManagerView()
                .environmentObject(model)
        }
    }

    private var header: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center, spacing: 20) {
                titleBlock
                Spacer(minLength: 24)
                toolbar
            }

            VStack(alignment: .leading, spacing: 12) {
                titleBlock
                toolbar
            }
        }
    }

    private var titleBlock: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(AppPalette.brandNavy)
                .frame(width: 42, height: 42)
                .overlay {
                    Image(systemName: "newspaper.fill")
                        .font(AppTypography.system(size: 17, weight: .semibold))
                        .foregroundStyle(AppPalette.onBrand)
                }

            VStack(alignment: .leading, spacing: 2) {
                Text(model.text(.navInformation))
                    .font(AppTypography.system(size: 22, weight: .bold))
                    .foregroundStyle(AppPalette.text)
                Text(model.uiText("安全情报 · 实时聚合"))
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textSubtle)
            }

            HStack(spacing: 6) {
                if isRefreshing {
                    ProgressView().controlSize(.mini)
                } else {
                    Circle()
                        .fill(model.information?.partial == true ? AppPalette.warning : AppPalette.success)
                        .frame(width: 7, height: 7)
                }
                Text(isRefreshing ? model.uiText("实时更新中") : updateStatus)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(model.information?.partial == true ? AppPalette.warning : AppPalette.success)
                    .lineLimit(1)
            }
            .padding(.horizontal, 10)
            .frame(height: 26)
            .background((model.information?.partial == true ? AppPalette.warning : AppPalette.success).opacity(0.10))
            .clipShape(Capsule())
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(AppPalette.textSubtle)
                TextField(model.uiText("搜索资讯关键词"), text: $searchText)
                    .textFieldStyle(.plain)
                    .font(AppTypography.callout)
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                    .buttonStyle(.plain)
                    .help(model.uiText("清除搜索"))
                }
            }
            .padding(.horizontal, 11)
            .frame(width: 280, height: 36)
            .background(AppPalette.card)
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.border)
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            Menu {
                ForEach(InformationSortMode.allCases) { mode in
                    Button {
                        sortMode = mode
                    } label: {
                        Label(mode.title(model), systemImage: sortMode == mode ? "checkmark" : mode.icon)
                    }
                }
            } label: {
                Image(systemName: sortMode.icon)
                    .frame(width: 36, height: 36)
                    .foregroundStyle(AppPalette.textMuted)
                    .background(AppPalette.card)
                    .overlay {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .stroke(AppPalette.border)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help(sortMode.title(model))

            Button {
                Task { await model.refreshInformation(force: true) }
            } label: {
                Group {
                    if isRefreshing {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .frame(width: 36, height: 36)
                .background(AppPalette.card)
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(AppPalette.border)
                }
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            .buttonStyle(.plain)
            .disabled(isRefreshing)
            .help(model.uiText("刷新最新资讯"))

            Button {
                showingSourceManager = true
            } label: {
                Image(systemName: "slider.horizontal.3")
                    .frame(width: 36, height: 36)
                    .background(AppPalette.card)
                    .overlay {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .stroke(AppPalette.border)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            .buttonStyle(.plain)
            .help(model.uiText("管理订阅来源"))
        }
    }

    private var categoryBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 22) {
                ForEach(categories) { category in
                    Button {
                        selectedCategory = category.label
                    } label: {
                        VStack(spacing: 0) {
                            HStack(spacing: 6) {
                                Text(category.label)
                                if category.count > 0 {
                                    Text("\(category.count)")
                                        .font(AppTypography.caption2.monospacedDigit().weight(.semibold))
                                        .foregroundStyle(
                                            selectedCategory == category.label
                                                ? AppPalette.primaryStrong
                                                : AppPalette.textSubtle
                                        )
                                }
                            }
                            .font(AppTypography.callout.weight(selectedCategory == category.label ? .semibold : .medium))
                            .foregroundStyle(selectedCategory == category.label ? AppPalette.text : AppPalette.textMuted)
                            .frame(height: 49)

                            Rectangle()
                                .fill(selectedCategory == category.label ? AppPalette.primaryStrong : Color.clear)
                                .frame(height: 2)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .frame(height: 51)
    }

    private var content: some View {
        HStack(alignment: .top, spacing: 20) {
            VStack(alignment: .leading, spacing: 22) {
                spotlightSection
                newsFeed
            }
                .frame(minWidth: 0, maxWidth: .infinity)
            sideColumn
                .frame(width: 286)
        }
    }

    private var spotlightSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Text(model.uiText("重点关注"))
                    .font(AppTypography.headline)
                Text("\(featuredItems.count)")
                    .font(AppTypography.caption2.monospacedDigit().weight(.bold))
                    .foregroundStyle(AppPalette.textSubtle)
                    .padding(.horizontal, 7)
                    .frame(height: 20)
                    .background(AppPalette.cardMuted)
                    .clipShape(Capsule())
                Spacer()
                HStack(spacing: 6) {
                    Button { moveFeature(by: -1) } label: {
                        Image(systemName: "chevron.left")
                            .frame(width: 30, height: 30)
                    }
                    .help(model.uiText("上一条重点资讯"))

                    Button { moveFeature(by: 1) } label: {
                        Image(systemName: "chevron.right")
                            .frame(width: 30, height: 30)
                    }
                    .help(model.uiText("下一条重点资讯"))
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppPalette.textMuted)
                .background(AppPalette.card)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .stroke(AppPalette.border)
                }
                .disabled(featuredItems.count <= 1)
            }

            if featuredItems.isEmpty {
                ContentUnavailableView(
                    model.uiText("暂无重点资讯"),
                    systemImage: "newspaper",
                    description: Text(model.uiText("刷新或调整筛选条件"))
                )
                .frame(maxWidth: .infinity, minHeight: 244)
            } else {
                InformationStoryStack(
                    items: featuredItems,
                    selectedIndex: $selectedFeatureIndex,
                    open: open
                )
            }
        }
    }

    @ViewBuilder
    private var newsFeed: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Label(model.uiText("全部动态"), systemImage: "text.justify.left")
                    .font(AppTypography.headline)
                    .foregroundStyle(AppPalette.text)
                Spacer()
                Text("\(filteredItems.count)")
                    .font(AppTypography.caption.monospacedDigit().weight(.bold))
                    .foregroundStyle(AppPalette.textMuted)
                    .padding(.horizontal, 8)
                    .frame(height: 24)
                    .background(AppPalette.cardMuted)
                    .clipShape(Capsule())
            }
            .padding(.horizontal, 16)
            .frame(height: 48)

            Divider().overlay(AppPalette.border)

            if isRefreshing && model.information == nil {
                VStack(spacing: 12) {
                    ProgressView().controlSize(.large)
                    Text(model.uiText("正在接入公开安全资讯"))
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                }
                .frame(maxWidth: .infinity, minHeight: 260)
            } else if visibleItems.isEmpty {
                ContentUnavailableView(
                    model.uiText("未找到匹配资讯"),
                    systemImage: "newspaper",
                    description: Text(model.uiText("调整分类或搜索关键词"))
                )
                .frame(maxWidth: .infinity, minHeight: 280)
            } else {
                ForEach(Array(visibleItems.enumerated()), id: \.element.id) { index, item in
                    InformationEditorialRow(
                        item: item,
                        open: { open(item) },
                        filterSource: { searchText = item.sourceName },
                        filterTag: { tag in searchText = tag }
                    )
                    if index < visibleItems.count - 1 {
                        Divider()
                            .padding(.leading, 66)
                    }
                }

                if filteredItems.count > visibleItems.count {
                    Divider().overlay(AppPalette.border)
                    Button {
                        visibleCount += 12
                    } label: {
                        Label(model.uiText("加载更多"), systemImage: "chevron.down")
                            .font(AppTypography.callout.weight(.semibold))
                            .frame(maxWidth: .infinity, minHeight: 38)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(AppPalette.primaryStrong)
                }
            }
        }
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.9))
        }
    }

    private var sideColumn: some View {
        VStack(spacing: 14) {
            briefingPanel
            popularTagsPanel
            sourcePanel
        }
    }

    private var popularTagsPanel: some View {
        VStack(alignment: .leading, spacing: 13) {
            Label(model.uiText("热门主题"), systemImage: "number")
                .font(AppTypography.headline)
                .foregroundStyle(AppPalette.text)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 72), spacing: 7)], alignment: .leading, spacing: 7) {
                ForEach(model.information?.popularTags ?? []) { tag in
                    Button {
                        searchText = tag.name
                    } label: {
                        HStack(spacing: 5) {
                            Text(tag.name)
                                .lineLimit(1)
                            Text("\(tag.count)")
                                .font(AppTypography.caption2.monospacedDigit())
                                .opacity(0.72)
                        }
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(tagColor(tag.name))
                        .padding(.horizontal, 8)
                        .frame(minHeight: 28)
                        .frame(maxWidth: .infinity)
                        .background(tagColor(tag.name).opacity(0.09))
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(16)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }

    private var briefingPanel: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "bolt.fill")
                    .foregroundStyle(AppPalette.warning)
                Text(model.uiText("实时快讯"))
                    .font(AppTypography.headline)
                    .foregroundStyle(AppPalette.onBrand)
                Spacer()
                HStack(spacing: 5) {
                    Circle()
                        .fill(AppPalette.danger)
                        .frame(width: 6, height: 6)
                    Text("LIVE")
                        .font(AppTypography.caption2.monospaced().weight(.bold))
                        .foregroundStyle(AppPalette.onBrandMuted)
                }
            }
            .padding(.bottom, 12)

            ForEach(Array((model.information?.briefs ?? []).prefix(4).enumerated()), id: \.element.id) { index, item in
                Button { open(item) } label: {
                    HStack(alignment: .top, spacing: 10) {
                        Text(String(format: "%02d", index + 1))
                            .font(AppTypography.caption.monospacedDigit().weight(.bold))
                            .foregroundStyle(categoryColor(item.category))
                            .frame(width: 22, alignment: .leading)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.title)
                                .font(AppTypography.caption.weight(.semibold))
                                .foregroundStyle(AppPalette.onBrand)
                                .multilineTextAlignment(.leading)
                                .lineLimit(2)
                            HStack(spacing: 5) {
                                Text(item.category)
                                Text("·")
                                Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                            }
                            .font(AppTypography.caption2)
                            .foregroundStyle(AppPalette.onBrandMuted)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 10)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                if index < min((model.information?.briefs.count ?? 0), 4) - 1 {
                    Divider().overlay(Color.white.opacity(0.10))
                }
            }
        }
        .padding(16)
        .background(AppPalette.brandNavy)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(Color.white.opacity(0.08))
        }
        .shadow(color: AppPalette.brandNavy.opacity(0.16), radius: 18, y: 8)
    }

    private var sourcePanel: some View {
        VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Label(model.uiText("订阅来源"), systemImage: "dot.radiowaves.left.and.right")
                        .font(AppTypography.headline)
                        .foregroundStyle(AppPalette.text)
                    Spacer(minLength: 6)
                    Button {
                        showingSourceManager = true
                    } label: {
                        Image(systemName: "slider.horizontal.3")
                            .frame(width: 28, height: 28)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(AppPalette.primaryStrong)
                    .background(AppPalette.selected)
                    .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    .help(model.uiText("管理订阅来源"))
                }

                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text("\(enabledSourceCount)")
                        .font(AppTypography.title2.weight(.bold))
                        .foregroundStyle(AppPalette.primaryStrong)
                    Text("/ \(model.information?.sources.count ?? 0)")
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.textSubtle)
                    Spacer()
                    Text(model.uiText("已启用"))
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                }

                ForEach(sourceGroupSummary, id: \.name) { group in
                    HStack(spacing: 8) {
                        Image(systemName: sourceGroupIcon(group.name))
                            .font(AppTypography.system(size: 11, weight: .semibold))
                            .foregroundStyle(sourceGroupColor(group.name))
                            .frame(width: 18)
                        Text(group.name)
                            .font(AppTypography.caption.weight(.medium))
                            .foregroundStyle(AppPalette.textMuted)
                            .lineLimit(1)
                        Spacer()
                        Text("\(group.enabled)/\(group.total)")
                            .font(AppTypography.caption2.monospacedDigit().weight(.semibold))
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                }

                Button {
                    showingSourceManager = true
                } label: {
                    Label(model.uiText("管理来源"), systemImage: "list.bullet.rectangle")
                        .font(AppTypography.caption.weight(.semibold))
                        .frame(maxWidth: .infinity, minHeight: 32)
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppPalette.primaryStrong)
                .background(AppPalette.selected.opacity(0.72))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .padding(16)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }

    private var featuredItems: [InformationItem] {
        Array(filteredItems.prefix(3))
    }

    private func moveFeature(by offset: Int) {
        guard !featuredItems.isEmpty else { return }
        selectedFeatureIndex = (selectedFeatureIndex + offset + featuredItems.count) % featuredItems.count
    }

    private func resetFeedPosition() {
        visibleCount = 14
        selectedFeatureIndex = 0
    }

    private var enabledSourceCount: Int {
        model.information?.sources.filter(\.enabled).count ?? 0
    }

    private var sourceGroupSummary: [(name: String, enabled: Int, total: Int)] {
        let sources = model.information?.sources ?? []
        return ["精选来源", "微信公众号", "安全 RSS"].compactMap { name in
            let matches = sources.filter { $0.resolvedGroup == name }
            guard !matches.isEmpty else { return nil }
            return (name, matches.filter(\.enabled).count, matches.count)
        }
    }

    private var categories: [InformationCategory] {
        let loaded = model.information?.categories ?? []
        if loaded.contains(where: { $0.label == selectedCategory }) || selectedCategory == "全部" {
            return loaded
        }
        return [InformationCategory(id: "all", label: "全部", count: model.information?.availableTotal ?? 0)] + loaded
    }

    private var filteredItems: [InformationItem] {
        var result = model.information?.items ?? []
        if selectedCategory != "全部" {
            result = result.filter { $0.category == selectedCategory }
        }
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !query.isEmpty {
            result = result.filter { item in
                item.title.localizedCaseInsensitiveContains(query)
                    || item.summary.localizedCaseInsensitiveContains(query)
                    || item.sourceName.localizedCaseInsensitiveContains(query)
                    || item.tags.contains { $0.localizedCaseInsensitiveContains(query) }
            }
        }
        switch sortMode {
        case .latest:
            result.sort { $0.publishedAt > $1.publishedAt }
        case .source:
            result.sort {
                $0.sourceName == $1.sourceName ? $0.publishedAt > $1.publishedAt : $0.sourceName < $1.sourceName
            }
        }
        return result
    }

    private var visibleItems: [InformationItem] {
        Array(filteredItems.prefix(visibleCount))
    }

    private var updateStatus: String {
        guard let value = model.information?.updatedAt, !value.isEmpty else {
            return model.uiText("等待更新")
        }
        return model.uiText("实时已更新")
    }

    private func open(_ item: InformationItem) {
        guard let url = URL(string: item.url) else { return }
        openURL(url)
    }
}

struct InformationSourceManagerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    @State private var query = ""
    @State private var selectedGroup = "全部"
    @State private var selectedIDs: Set<String> = []

    private let maximumBatchSelection = 50

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(AppPalette.border)
            filters
            selectionToolbar
            Divider().overlay(AppPalette.border)
            sourceList
            Divider().overlay(AppPalette.border)
            footer
        }
        .frame(minWidth: 760, idealWidth: 860, minHeight: 560, idealHeight: 660)
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .onChange(of: selectedGroup) { _, _ in selectedIDs.removeAll() }
        .onChange(of: query) { _, _ in selectedIDs.removeAll() }
    }

    private var header: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(AppPalette.primary.opacity(0.12))
                Image(systemName: "dot.radiowaves.left.and.right")
                    .font(AppTypography.system(size: 16, weight: .semibold))
                    .foregroundStyle(AppPalette.primaryStrong)
            }
            .frame(width: 38, height: 38)

            VStack(alignment: .leading, spacing: 2) {
                Text(model.uiText("来源管理"))
                    .font(AppTypography.title3.weight(.bold))
                Text(model.uiText("%d 个来源 · %d 个已启用", sources.count, enabledSourceCount))
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textSubtle)
            }
            Spacer()
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
                    .frame(width: 32, height: 32)
            }
            .buttonStyle(.plain)
            .foregroundStyle(AppPalette.textMuted)
            .background(AppPalette.cardMuted)
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .help(model.uiText("关闭"))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
    }

    private var filters: some View {
        VStack(spacing: 12) {
            HStack(spacing: 10) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(AppPalette.textSubtle)
                    TextField(model.uiText("搜索来源名称"), text: $query)
                        .textFieldStyle(.plain)
                    if !query.isEmpty {
                        Button { query = "" } label: {
                            Image(systemName: "xmark.circle.fill")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(AppPalette.textSubtle)
                        .help(model.uiText("清除搜索"))
                    }
                }
                .padding(.horizontal, 11)
                .frame(minWidth: 240, maxWidth: .infinity, minHeight: 36)
                .background(AppPalette.card)
                .overlay {
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .stroke(AppPalette.border)
                }
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))

                Button {
                    Task { await model.refreshInformation(force: true) }
                } label: {
                    Group {
                        if model.busyActions.contains("information-refresh") {
                            ProgressView().controlSize(.small)
                        } else {
                            Label(model.uiText("检测已启用"), systemImage: "waveform.path.ecg")
                        }
                    }
                    .font(AppTypography.callout.weight(.semibold))
                    .frame(minWidth: 120, minHeight: 36)
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppPalette.primaryStrong)
                .background(AppPalette.selected)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                .disabled(model.busyActions.contains("information-refresh"))
            }

            Picker(model.uiText("来源分组"), selection: $selectedGroup) {
                ForEach(groupNames, id: \.self) { group in
                    Text(model.uiText(group)).tag(group)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var selectionToolbar: some View {
        HStack(spacing: 8) {
            Button {
                selectCurrentResults()
            } label: {
                Label(model.uiText("选择当前"), systemImage: "checklist")
            }
            .disabled(filteredSources.isEmpty)

            Button {
                selectedIDs.removeAll()
            } label: {
                Label(model.uiText("清除选择"), systemImage: "xmark.circle")
            }
            .disabled(selectedIDs.isEmpty)

            Spacer()

            Text(model.uiText("已选择 %d", selectedIDs.count))
                .font(AppTypography.caption.monospacedDigit().weight(.semibold))
                .foregroundStyle(AppPalette.textSubtle)

            Button {
                updateSelection(enabled: false)
            } label: {
                Label(model.uiText("暂停"), systemImage: "pause.circle")
            }
            .disabled(selectedIDs.isEmpty || batchBusy)

            Button {
                updateSelection(enabled: true)
            } label: {
                Group {
                    if batchBusy {
                        ProgressView().controlSize(.small)
                    } else {
                        Label(model.uiText("启用"), systemImage: "checkmark.circle")
                    }
                }
            }
            .disabled(selectedIDs.isEmpty || batchBusy || selectionWouldExceedOPMLLimit)
            .buttonStyle(.borderedProminent)
            .tint(AppPalette.primaryStrong)
        }
        .font(AppTypography.caption.weight(.semibold))
        .buttonStyle(.bordered)
        .controlSize(.small)
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .background(AppPalette.cardMuted.opacity(0.55))
    }

    @ViewBuilder
    private var sourceList: some View {
        if filteredSources.isEmpty {
            ContentUnavailableView(
                model.uiText("未找到来源"),
                systemImage: "dot.radiowaves.left.and.right",
                description: Text(model.uiText("调整搜索词或来源分组"))
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                    ForEach(groupedSources, id: \.name) { section in
                        Section {
                            ForEach(section.sources) { source in
                                sourceRow(source)
                                Divider()
                                    .overlay(AppPalette.border.opacity(0.65))
                                    .padding(.leading, 70)
                            }
                        } header: {
                            HStack(spacing: 8) {
                                Image(systemName: sourceGroupIcon(section.name))
                                    .foregroundStyle(sourceGroupColor(section.name))
                                Text(model.uiText(section.name))
                                    .font(AppTypography.caption.weight(.bold))
                                Text("\(section.sources.count)")
                                    .font(AppTypography.caption2.monospacedDigit())
                                    .foregroundStyle(AppPalette.textSubtle)
                                Spacer()
                            }
                            .padding(.horizontal, 20)
                            .frame(height: 32)
                            .background(AppPalette.page.opacity(0.97))
                        }
                    }
                }
            }
        }
    }

    private func sourceRow(_ source: InformationSource) -> some View {
        HStack(spacing: 10) {
            Button {
                toggleSelection(source.id)
            } label: {
                Image(systemName: selectedIDs.contains(source.id) ? "checkmark.square.fill" : "square")
                    .font(AppTypography.system(size: 16, weight: .medium))
                    .foregroundStyle(selectedIDs.contains(source.id) ? AppPalette.primaryStrong : AppPalette.textSubtle)
                    .frame(width: 24, height: 34)
            }
            .buttonStyle(.plain)
            .disabled(!selectedIDs.contains(source.id) && selectedIDs.count >= maximumBatchSelection)
            .help(model.uiText("选择来源"))

            ZStack {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(sourceColor(source.id).opacity(0.12))
                Image(systemName: sourceIcon(source.id))
                    .font(AppTypography.system(size: 12, weight: .semibold))
                    .foregroundStyle(sourceColor(source.id))
            }
            .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(source.name)
                        .font(AppTypography.callout.weight(.semibold))
                        .lineLimit(1)
                    if source.secureTransport == false {
                        Image(systemName: "lock.slash")
                            .font(AppTypography.caption2)
                            .foregroundStyle(AppPalette.warning)
                            .help(model.uiText("该来源使用 HTTP"))
                    }
                }
                HStack(spacing: 5) {
                    Text(source.region)
                    Text("·")
                    Text(model.uiText("%d 条", source.itemCount))
                    if !source.message.isEmpty {
                        Text("·")
                        Text(source.message)
                            .lineLimit(1)
                    }
                }
                .font(AppTypography.caption2)
                .foregroundStyle(source.status == "error" ? AppPalette.warning : AppPalette.textSubtle)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            sourceStatus(source)

            Button {
                Task { await model.testInformationSource(id: source.id) }
            } label: {
                if model.busyActions.contains("information-source-test:\(source.id)") {
                    ProgressView().controlSize(.mini)
                        .frame(width: 28, height: 28)
                } else {
                    Image(systemName: "waveform.path.ecg")
                        .frame(width: 28, height: 28)
                }
            }
            .buttonStyle(.plain)
            .foregroundStyle(AppPalette.textMuted)
            .background(AppPalette.cardMuted)
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            .help(model.uiText("检测来源"))

            Button {
                if let url = URL(string: source.website) { openURL(url) }
            } label: {
                Image(systemName: "arrow.up.right.square")
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.plain)
            .foregroundStyle(AppPalette.textMuted)
            .help(model.uiText("打开来源网站"))

            if model.busyActions.contains("information-source:\(source.id)") {
                ProgressView().controlSize(.mini)
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
        .padding(.horizontal, 20)
        .frame(minHeight: 58)
        .contentShape(Rectangle())
    }

    private func sourceStatus(_ source: InformationSource) -> some View {
        HStack(spacing: 5) {
            Circle()
                .fill(sourceStatusColor(source.status))
                .frame(width: 6, height: 6)
            Text(model.uiText(sourceStatusLabel(source.status)))
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
        }
        .frame(width: 64, alignment: .leading)
    }

    private var footer: some View {
        HStack(spacing: 14) {
            Label(
                model.uiText("OPML 已启用 %d/%d", enabledOPMLCount, opmlEnabledLimit),
                systemImage: "doc.text"
            )
            Label(
                model.uiText("微信公众号 %d", sources.filter { $0.resolvedGroup == "微信公众号" }.count),
                systemImage: "message.fill"
            )
            Spacer()
            Text(model.uiText("单次最多选择 %d 个来源", maximumBatchSelection))
        }
        .font(AppTypography.caption)
        .foregroundStyle(AppPalette.textSubtle)
        .padding(.horizontal, 20)
        .frame(height: 44)
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

    private var groupedSources: [(name: String, sources: [InformationSource])] {
        let order = ["精选来源", "微信公众号", "安全 RSS"]
        return order.compactMap { group in
            let matches = filteredSources.filter { $0.resolvedGroup == group }
            return matches.isEmpty ? nil : (group, matches)
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

    private var batchBusy: Bool {
        model.busyActions.contains("information-sources-batch")
    }

    private var selectionWouldExceedOPMLLimit: Bool {
        let enabledIDs = Set(sources.filter { $0.isBundledOPML && $0.enabled }.map(\.id))
        let selectedOPMLIDs = Set(sources.filter { $0.isBundledOPML && selectedIDs.contains($0.id) }.map(\.id))
        return enabledIDs.union(selectedOPMLIDs).count > opmlEnabledLimit
    }

    private func selectCurrentResults() {
        selectedIDs = Set(filteredSources.prefix(maximumBatchSelection).map(\.id))
    }

    private func toggleSelection(_ id: String) {
        if selectedIDs.contains(id) {
            selectedIDs.remove(id)
        } else if selectedIDs.count < maximumBatchSelection {
            selectedIDs.insert(id)
        }
    }

    private func updateSelection(enabled: Bool) {
        let ids = Array(selectedIDs)
        Task {
            await model.setInformationSources(ids: ids, enabled: enabled)
            selectedIDs.removeAll()
        }
    }
}

// Native adaptation of Dub.co's Sidebar News, the most-bookmarked news
// component in 21st.dev's News category at the time of implementation.
private struct InformationStoryStack: View {
    let items: [InformationItem]
    @Binding var selectedIndex: Int
    let open: (InformationItem) -> Void

    @State private var isHovered = false

    private var normalizedIndex: Int {
        guard !items.isEmpty else { return 0 }
        return min(max(selectedIndex, 0), items.count - 1)
    }

    var body: some View {
        ZStack(alignment: .top) {
            ForEach(Array(items.indices.reversed()), id: \.self) { depth in
                let actualIndex = (normalizedIndex + depth) % items.count
                let item = items[actualIndex]
                let verticalOrder = items.count - 1 - depth

                Button {
                    if depth == 0 {
                        open(item)
                    } else {
                        withAnimation(.spring(response: 0.34, dampingFraction: 0.86)) {
                            selectedIndex = actualIndex
                        }
                    }
                } label: {
                    InformationSpotlightCard(item: item)
                }
                .buttonStyle(.plain)
                .scaleEffect(1 - CGFloat(depth) * 0.028, anchor: .top)
                .offset(y: CGFloat(verticalOrder) * (isHovered ? 20 : 12))
                .opacity(1 - CGFloat(depth) * 0.12)
                .zIndex(Double(items.count - depth))
            }
        }
        .frame(maxWidth: .infinity, minHeight: 278, maxHeight: 278, alignment: .top)
        .contentShape(Rectangle())
        .onHover { hovering in
            withAnimation(.spring(response: 0.36, dampingFraction: 0.84)) {
                isHovered = hovering
            }
        }
        .onChange(of: items.map(\.id)) { _, _ in
            selectedIndex = 0
        }
    }
}

private struct InformationSpotlightCard: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem

    var body: some View {
        HStack(spacing: 0) {
            InformationArtwork(item: item)
                .informationArtworkFrame(width: 218, height: 238)

            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 7) {
                    if item.breaking {
                        InformationBadge(text: model.uiText("快讯"), color: AppPalette.danger)
                    }
                    InformationBadge(text: item.category, color: categoryColor(item.category))
                    Spacer(minLength: 4)
                    Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                        .font(AppTypography.caption2)
                        .foregroundStyle(AppPalette.textSubtle)
                }

                Text(item.title)
                    .font(AppTypography.system(size: 21, weight: .bold))
                    .foregroundStyle(AppPalette.text)
                    .multilineTextAlignment(.leading)
                    .lineLimit(3)

                if !item.summary.isEmpty {
                    Text(item.summary)
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                        .multilineTextAlignment(.leading)
                        .lineLimit(3)
                }

                Spacer(minLength: 2)

                HStack(spacing: 8) {
                    InformationSourceLine(item: item)
                    Spacer(minLength: 6)
                    Image(systemName: "arrow.up.right")
                        .font(AppTypography.system(size: 11, weight: .bold))
                        .foregroundStyle(AppPalette.primaryStrong)
                        .frame(width: 28, height: 28)
                        .background(AppPalette.selected)
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                }
            }
            .padding(18)
        }
        .frame(maxWidth: .infinity, minHeight: 238, maxHeight: 238, alignment: .leading)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
        .shadow(color: AppPalette.brandNavy.opacity(0.12), radius: 18, y: 8)
        .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .help(model.uiText("在浏览器中打开"))
    }
}

private struct InformationEditorialRow: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem
    let open: () -> Void
    let filterSource: () -> Void
    let filterTag: (String) -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Button(action: open) {
                HStack(alignment: .top, spacing: 11) {
                    sourceMark
                    content
                    if hasArtwork {
                        InformationArtwork(item: item)
                            .informationArtworkFrame(width: 86, height: 66)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(model.uiText("在浏览器中打开"))

            Menu {
                Button(action: open) {
                    Label(model.uiText("在浏览器中打开"), systemImage: "safari")
                }
                Button(action: filterSource) {
                    Label(model.uiText("按来源"), systemImage: "square.stack.3d.up")
                }
                if let firstTag = item.tags.first {
                    Button { filterTag(firstTag) } label: {
                        Label(firstTag, systemImage: "number")
                    }
                }
            } label: {
                Image(systemName: "ellipsis")
                    .font(AppTypography.system(size: 13, weight: .semibold))
                    .foregroundStyle(AppPalette.textSubtle)
                    .frame(width: 28, height: 28)
                    .background(isHovered ? AppPalette.cardMuted : Color.clear)
                    .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help(model.uiText("更多操作"))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 13)
        .background(isHovered ? AppPalette.selected.opacity(0.40) : Color.clear)
        .animation(.easeOut(duration: 0.14), value: isHovered)
        .onHover { isHovered = $0 }
    }

    private var sourceMark: some View {
        Circle()
            .fill(sourceColor(item.sourceId))
            .frame(width: 38, height: 38)
            .overlay {
                Image(systemName: sourceIcon(item.sourceId))
                    .font(AppTypography.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
            }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 7) {
                Text(item.sourceName)
                    .font(AppTypography.caption2.weight(.bold))
                    .foregroundStyle(sourceColor(item.sourceId))
                    .lineLimit(1)
                Text("·")
                    .foregroundStyle(AppPalette.textSubtle)
                Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                    .font(AppTypography.caption2)
                    .foregroundStyle(AppPalette.textSubtle)
                    .lineLimit(1)
                Spacer(minLength: 4)
            }

            HStack(alignment: .firstTextBaseline, spacing: 7) {
                Text(item.title)
                    .font(AppTypography.callout.weight(item.breaking ? .bold : .semibold))
                    .foregroundStyle(AppPalette.text)
                    .multilineTextAlignment(.leading)
                    .lineLimit(2)
                if item.breaking {
                    Circle()
                        .fill(AppPalette.danger)
                        .frame(width: 7, height: 7)
                        .accessibilityLabel(model.uiText("快讯"))
                }
            }

            if !item.summary.isEmpty {
                Text(item.summary)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
                    .multilineTextAlignment(.leading)
                    .lineLimit(1)
            }

            HStack(spacing: 7) {
                InformationBadge(text: item.category, color: categoryColor(item.category))
                ForEach(item.tags.prefix(2), id: \.self) { tag in
                    Text("#\(tag)")
                        .font(AppTypography.caption2)
                        .foregroundStyle(AppPalette.textSubtle)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var hasArtwork: Bool {
        !item.imageUrl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

private struct FeaturedInformationCard: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 16) {
                InformationArtwork(item: item)
                    .informationArtworkFrame(width: 220, height: 150)
                bodyContent
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(AppPalette.selectedStrong.opacity(0.66))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.primary.opacity(0.24))
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(.plain)
        .help(model.uiText("在浏览器中打开"))
    }

    private var bodyContent: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 7) {
                if item.breaking {
                    InformationBadge(text: model.uiText("快讯"), color: AppPalette.danger)
                }
                InformationBadge(text: item.category, color: categoryColor(item.category))
                Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                    .font(AppTypography.caption2)
                    .foregroundStyle(AppPalette.textSubtle)
            }
            Text(item.title)
                .font(AppTypography.title3.weight(.bold))
                .foregroundStyle(AppPalette.text)
                .multilineTextAlignment(.leading)
                .lineLimit(3)
            if !item.summary.isEmpty {
                Text(item.summary)
                    .font(AppTypography.callout)
                    .foregroundStyle(AppPalette.textMuted)
                    .multilineTextAlignment(.leading)
                    .lineLimit(3)
            }
            Spacer(minLength: 0)
            InformationSourceLine(item: item)
        }
        .frame(maxWidth: .infinity, minHeight: 132, alignment: .leading)
    }
}

private struct InformationNewsCard: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .center, spacing: 14) {
                InformationArtwork(item: item)
                    .informationArtworkFrame(width: 164, height: 108)
                VStack(alignment: .leading, spacing: 7) {
                    HStack(spacing: 7) {
                        InformationBadge(text: item.category, color: categoryColor(item.category))
                        Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                            .font(AppTypography.caption2)
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                    Text(item.title)
                        .font(AppTypography.headline)
                        .foregroundStyle(AppPalette.text)
                        .multilineTextAlignment(.leading)
                        .lineLimit(2)
                    if !item.summary.isEmpty {
                        Text(item.summary)
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                            .multilineTextAlignment(.leading)
                            .lineLimit(2)
                    }
                    InformationSourceLine(item: item)
                }
                .frame(maxWidth: .infinity, minHeight: 108, alignment: .leading)
            }
            .padding(13)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(AppPalette.card)
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.9))
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(.plain)
        .help(model.uiText("在浏览器中打开"))
    }
}

private extension View {
    func informationArtworkFrame(width: CGFloat, height: CGFloat) -> some View {
        frame(width: width, height: height)
            .clipped()
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}

struct InformationArtwork: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem
    var compact = false
    var cornerRadius: CGFloat = 7
    @State private var loadedImage: NSImage?
    @State private var loadedSourceFallback = false

    var body: some View {
        Group {
            if let loadedImage {
                if loadedSourceFallback {
                    sourceArtwork(loadedImage)
                } else {
                    Image(nsImage: loadedImage)
                        .resizable()
                        .scaledToFill()
                }
            } else {
                placeholder
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .clipped()
        .background(categoryColor(item.category).opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        .task(id: imageRequestKey) {
            await loadImage()
        }
    }

    private var placeholder: some View {
        ZStack {
            sourceColor(item.sourceId).opacity(0.10)
            if compact {
                Text(informationSourceMonogram(item.sourceName))
                    .font(AppTypography.system(size: 12, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(width: 36, height: 36)
                    .background(sourceColor(item.sourceId))
                    .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            } else {
                VStack(spacing: 8) {
                    Text(informationSourceMonogram(item.sourceName))
                        .font(AppTypography.headline.weight(.bold))
                        .foregroundStyle(.white)
                        .frame(width: 48, height: 48)
                        .background(sourceColor(item.sourceId))
                        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                    Text(item.sourceName)
                        .font(AppTypography.caption2.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                        .lineLimit(1)
                }
                .padding(14)
            }
        }
    }

    private func sourceArtwork(_ image: NSImage) -> some View {
        ZStack {
            categoryColor(item.category).opacity(0.10)
            if compact {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 48, maxHeight: 34)
                    .padding(8)
            } else {
                VStack(spacing: 9) {
                    Image(nsImage: image)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 86, maxHeight: 48)
                    Text(item.sourceName)
                        .font(AppTypography.caption2.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                        .lineLimit(1)
                }
                .padding(18)
            }
        }
    }

    private var imageRequestKey: String {
        "\(model.serverURL)|\(item.id)|\(item.imageUrl)|\(item.sourceImageUrl ?? "")"
    }

    private func loadImage() async {
        await MainActor.run {
            loadedImage = nil
            loadedSourceFallback = false
        }
        guard let baseURL = URL(string: model.serverURL) else { return }

        for target in informationArtworkRequestTargets(
            itemID: item.id,
            sourceID: item.sourceId,
            articleImageURL: item.imageUrl
        ) {
            guard let url = target.proxyURL(baseURL: baseURL) else { continue }
            if let cached = await InformationArtworkImageLoader.shared.image(
                for: url,
                forceSourceFallback: target.isSourceLogo
            ) {
                await apply(cached)
                return
            }
        }

        if let sourceImageURL = item.sourceImageUrl.flatMap(URL.init(string:)),
           ["http", "https"].contains(sourceImageURL.scheme?.lowercased() ?? ""),
           let cached = await InformationArtworkImageLoader.shared.image(
               for: sourceImageURL,
               forceSourceFallback: true
           ) {
            await apply(cached)
        }
    }

    private func apply(_ cached: InformationCachedImage) async {
        guard !Task.isCancelled else { return }
        await MainActor.run {
            loadedImage = cached.image
            loadedSourceFallback = cached.sourceFallback
        }
    }
}

enum InformationArtworkRequestTarget: Equatable {
    case item(String)
    case source(String)

    var isSourceLogo: Bool {
        if case .source = self { return true }
        return false
    }

    func proxyURL(baseURL: URL) -> URL? {
        let identifier: String
        let route: String
        switch self {
        case let .item(value):
            identifier = value
            route = "images"
        case let .source(value):
            identifier = value
            route = "source-images"
        }
        guard let encoded = identifier.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else {
            return nil
        }
        return baseURL.appending(path: "api/information/\(route)/\(encoded)")
    }
}

func informationPollingNanoseconds(refreshing: Bool) -> UInt64 {
    refreshing ? 750_000_000 : 60_000_000_000
}

func informationRotationNanoseconds() -> UInt64 {
    8_000_000_000
}

func informationArtworkRequestTargets(
    itemID: String,
    sourceID: String,
    articleImageURL: String
) -> [InformationArtworkRequestTarget] {
    let sourceTarget = InformationArtworkRequestTarget.source(sourceID)
    if articleImageURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        return [sourceTarget]
    }
    return [.item(itemID), sourceTarget]
}

private final class InformationCachedImage: @unchecked Sendable {
    let image: NSImage
    let sourceFallback: Bool

    init(image: NSImage, sourceFallback: Bool) {
        self.image = image
        self.sourceFallback = sourceFallback
    }
}

private actor InformationArtworkImageLoader {
    static let shared = InformationArtworkImageLoader()

    private var inFlight: [URL: Task<(InformationCachedImage, Int)?, Never>] = [:]
    private var failedUntil: [URL: Date] = [:]

    func image(for url: URL, forceSourceFallback: Bool) async -> InformationCachedImage? {
        if let cached = InformationImageCache.shared.object(forKey: url as NSURL) {
            return cached
        }
        if let retryAt = failedUntil[url], retryAt > Date() {
            return nil
        }
        if let existing = inFlight[url] {
            return await existing.value?.0
        }

        let task = Task<(InformationCachedImage, Int)?, Never> {
            var request = URLRequest(url: url, cachePolicy: .returnCacheDataElseLoad, timeoutInterval: 8)
            request.setValue(
                "image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8",
                forHTTPHeaderField: "Accept"
            )
            let host = url.host?.lowercased() ?? ""
            if host.contains("qpic.cn") || host.contains("qlogo.cn") {
                request.setValue("https://mp.weixin.qq.com/", forHTTPHeaderField: "Referer")
            }
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                guard
                    let http = response as? HTTPURLResponse,
                    (200..<300).contains(http.statusCode),
                    !data.isEmpty,
                    data.count <= 8_000_000,
                    let image = NSImage(data: data)
                else { return nil }
                let isSourceLogo = forceSourceFallback
                    || http.value(forHTTPHeaderField: "X-SecFlow-Image-Kind") == "source"
                return (
                    InformationCachedImage(image: image, sourceFallback: isSourceLogo),
                    data.count
                )
            } catch {
                return nil
            }
        }
        inFlight[url] = task
        let result = await task.value
        inFlight[url] = nil
        if let (cached, cost) = result {
            failedUntil[url] = nil
            InformationImageCache.shared.setObject(cached, forKey: url as NSURL, cost: cost)
            return cached
        }
        failedUntil[url] = Date().addingTimeInterval(300)
        return nil
    }
}

private enum InformationImageCache {
    static let shared: NSCache<NSURL, InformationCachedImage> = {
        let cache = NSCache<NSURL, InformationCachedImage>()
        cache.countLimit = 120
        cache.totalCostLimit = 96 * 1_024 * 1_024
        return cache
    }()
}

private struct InformationSourceLine: View {
    let item: InformationItem

    var body: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(sourceColor(item.sourceId))
                .frame(width: 20, height: 20)
                .overlay {
                    Image(systemName: sourceIcon(item.sourceId))
                        .font(AppTypography.system(size: 9, weight: .bold))
                        .foregroundStyle(.white)
                }
            Text(item.sourceName)
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .lineLimit(1)
            if !item.author.isEmpty, item.author != item.sourceName {
                Text("· \(item.author)")
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textSubtle)
                    .lineLimit(1)
            }
        }
    }
}

private struct InformationBadge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(AppTypography.caption2.weight(.bold))
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .frame(height: 22)
            .background(color.opacity(0.11))
            .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
    }
}

private enum InformationSortMode: String, CaseIterable, Identifiable {
    case latest
    case source

    var id: String { rawValue }
    var icon: String { self == .latest ? "clock" : "square.stack.3d.up" }

    @MainActor func title(_ model: AppModel) -> String {
        self == .latest ? model.uiText("最新发布") : model.uiText("按来源")
    }
}

private func relativeTime(_ value: String, locale: Locale) -> String {
    guard let date = informationDate(value) else { return value }
    let formatter = RelativeDateTimeFormatter()
    formatter.locale = locale
    formatter.unitsStyle = .short
    return formatter.localizedString(for: date, relativeTo: Date())
}

private func informationDate(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = formatter.date(from: value) { return date }
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: value)
}

private func categoryColor(_ category: String) -> Color {
    switch category {
    case "全部": return AppPalette.primaryStrong
    case "AI 安全": return AppPalette.primaryStrong
    case "大模型": return Color(red: 0.55, green: 0.28, blue: 0.82)
    case "漏洞披露": return AppPalette.danger
    case "数据安全": return AppPalette.success
    case "政策法规": return Color(red: 0.63, green: 0.31, blue: 0.76)
    case "云安全": return Color(red: 0.13, green: 0.45, blue: 0.82)
    case "供应链安全": return Color(red: 0.89, green: 0.48, blue: 0.10)
    case "攻击技术": return AppPalette.warning
    default: return AppPalette.textMuted
    }
}

private func sourceColor(_ sourceID: String) -> Color {
    if sourceID.hasPrefix("opml_wechat_") {
        return AppPalette.success
    }
    if sourceID.hasPrefix("opml_rss_") {
        return AppPalette.primaryStrong
    }
    switch sourceID {
    case "cisa_advisories", "cisa_kev": return AppPalette.danger
    case "freebuf": return AppPalette.primaryStrong
    case "aliyun_xz": return Color(red: 0.96, green: 0.43, blue: 0.08)
    case "tencent_security", "tencent_xlab": return Color(red: 0.00, green: 0.48, blue: 0.78)
    case "microsoft_security": return Color(red: 0.00, green: 0.47, blue: 0.74)
    case "talos": return Color(red: 0.96, green: 0.55, blue: 0.04)
    case "portswigger_research": return Color(red: 0.88, green: 0.31, blue: 0.08)
    case "sans_isc": return AppPalette.warning
    default: return AppPalette.primaryStrong
    }
}

private func sourceIcon(_ sourceID: String) -> String {
    if sourceID.hasPrefix("opml_wechat_") {
        return "message.fill"
    }
    if sourceID.hasPrefix("opml_rss_") {
        return "dot.radiowaves.left.and.right"
    }
    switch sourceID {
    case "cisa_advisories", "cisa_kev": return "shield.fill"
    case "freebuf": return "newspaper.fill"
    case "aliyun_xz": return "cloud.fill"
    case "tencent_security", "tencent_xlab": return "shield.lefthalf.filled"
    case "microsoft_security": return "building.2.fill"
    case "talos": return "scope"
    case "portswigger_research": return "flask.fill"
    case "sans_isc": return "waveform.path.ecg"
    default: return "network"
    }
}

func informationSourceMonogram(_ sourceName: String) -> String {
    let clean = sourceName.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !clean.isEmpty else { return "RSS" }
    let containsCJK = clean.unicodeScalars.contains { scalar in
        (0x3400...0x4DBF).contains(scalar.value) || (0x4E00...0x9FFF).contains(scalar.value)
    }
    if containsCJK {
        return String(clean.filter { !$0.isWhitespace }.prefix(2))
    }
    let words = clean.split { character in
        character.isWhitespace || character == "-" || character == "_" || character == "."
    }
    if words.count >= 2 {
        return words.prefix(2).compactMap(\.first).map(String.init).joined().uppercased()
    }
    return String(clean.prefix(3)).uppercased()
}

private func sourceGroupIcon(_ group: String) -> String {
    switch group {
    case "精选来源": return "star.fill"
    case "微信公众号": return "message.fill"
    case "安全 RSS": return "dot.radiowaves.left.and.right"
    default: return "square.grid.2x2"
    }
}

private func sourceGroupColor(_ group: String) -> Color {
    switch group {
    case "精选来源": return AppPalette.warning
    case "微信公众号": return AppPalette.success
    case "安全 RSS": return AppPalette.primaryStrong
    default: return AppPalette.textMuted
    }
}

private func sourceStatusColor(_ status: String) -> Color {
    switch status {
    case "ready": return AppPalette.success
    case "error": return AppPalette.warning
    default: return AppPalette.textSubtle
    }
}

private func sourceStatusLabel(_ status: String) -> String {
    switch status {
    case "ready": return "正常"
    case "error": return "异常"
    default: return "未检测"
    }
}

private func tagColor(_ tag: String) -> Color {
    let palette: [Color] = [
        AppPalette.primaryStrong,
        AppPalette.danger,
        AppPalette.warning,
        AppPalette.success,
        Color(red: 0.55, green: 0.28, blue: 0.82),
        Color(red: 0.13, green: 0.45, blue: 0.82),
    ]
    return palette[abs(tag.hashValue) % palette.count]
}
