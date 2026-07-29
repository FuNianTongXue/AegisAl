import SwiftUI

struct RecordsView: View {
    @EnvironmentObject private var model: AppModel
    private let showsHeader: Bool

    @State private var query = ""
    @State private var selectedLogID: String?

    init(showsHeader: Bool = true) {
        self.showsHeader = showsHeader
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if showsHeader {
                    PageHeader(model.uiText("日志管理"), subtitle: model.uiText("仅保存和展示 API 查询日志，不保存漏洞明细数据")) {
                        StatusBadge(text: model.uiText("%d 条日志", logs.count), tone: .info)
                    }
                }

                Panel {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 10) {
                            Image(systemName: "magnifyingglass")
                                .foregroundStyle(AppPalette.textMuted)
                            TextField(model.uiText("搜索查询内容、状态或执行节点"), text: $query)
                                .textFieldStyle(.plain)
                                .foregroundStyle(AppPalette.text)
                            if !query.isEmpty {
                                Button {
                                    query = ""
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(AppPalette.textSubtle)
                            }
                        }
                        .padding(.horizontal, 12)
                        .frame(height: 38)
                        .background(AppPalette.cardMuted)
                        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))

                        QueryLogTable(logs: filteredLogs, selectedLogID: selectedLogID) { log in
                            selectedLogID = logID(log)
                        }
                    }
                }

                if let selectedLog {
                    Panel {
                        QueryLogDetail(log: selectedLog)
                    }
                }
            }
            .padding(28)
            .frame(maxWidth: 1180)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .textSelection(.enabled)
        .onAppear(perform: selectDefaultLog)
        .onChange(of: model.queryLogs.map(\.generatedAt).joined(separator: "|")) { _, _ in
            selectDefaultLog()
        }
    }

    private var logs: [IntelligenceQueryResult] {
        model.queryLogs.isEmpty ? (model.intelligenceResult.map { [$0] } ?? []) : model.queryLogs
    }

    private var filteredLogs: [IntelligenceQueryResult] {
        guard !query.isEmpty else { return logs }
        let term = query.lowercased()
        return logs.filter { log in
            log.query.lowercased().contains(term)
                || log.status.lowercased().contains(term)
                || log.trace.contains { item in
                    nodeLabel(item.node, language: model.appLanguage).lowercased().contains(term)
                        || item.message.lowercased().contains(term)
                        || item.status.lowercased().contains(term)
                }
        }
    }

    private var selectedLog: IntelligenceQueryResult? {
        logs.first { logID($0) == selectedLogID }
    }

    private func selectDefaultLog() {
        guard selectedLogID == nil || selectedLog == nil else { return }
        selectedLogID = logs.first.map(logID)
    }
}

private struct QueryLogTable: View {
    @EnvironmentObject private var model: AppModel
    let logs: [IntelligenceQueryResult]
    let selectedLogID: String?
    let select: (IntelligenceQueryResult) -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                header(model.uiText("查询内容"))
                header(model.uiText("状态"), width: 82)
                header(model.uiText("返回数"), width: 70)
                header(model.uiText("图谱"), width: 88)
                header(model.uiText("时间"), width: 150)
            }
            .padding(.horizontal, 12)
            .frame(height: 38)
            .background(AppPalette.cardMuted)

            if logs.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "clock.badge.questionmark")
                        .font(AppTypography.title2)
                        .foregroundStyle(AppPalette.textSubtle)
                    Text(model.uiText("暂无查询日志"))
                        .font(AppTypography.headline)
                        .foregroundStyle(AppPalette.text)
                    Text(model.uiText("通过智能问答触发漏洞查询后，这里只记录查询日志。"))
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                }
                .frame(maxWidth: .infinity)
                .frame(height: 190)
            } else {
                ForEach(logs, id: \.logIdentity) { log in
                    Button {
                        select(log)
                    } label: {
                        QueryLogRow(log: log, isSelected: selectedLogID == log.logIdentity)
                    }
                    .buttonStyle(.plain)
                    Divider()
                }
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .stroke(AppPalette.border)
        }
    }

    private func header(_ text: String, width: CGFloat? = nil) -> some View {
        Text(text)
            .font(AppTypography.caption.weight(.semibold))
            .foregroundStyle(AppPalette.textMuted)
            .frame(width: width, alignment: .leading)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: .leading)
    }
}

private struct QueryLogRow: View {
    @EnvironmentObject private var model: AppModel
    let log: IntelligenceQueryResult
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(log.query)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)
                Text(sourceSummary)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            StatusBadge(text: statusText, tone: StatusTone.operation(log.status))
                .frame(width: 82, alignment: .leading)
            Text("\(log.records.count)")
                .font(AppTypography.caption.monospacedDigit().weight(.semibold))
                .foregroundStyle(AppPalette.text)
                .frame(width: 70, alignment: .leading)
            Text(model.uiText("%d 个节点", log.graph.nodeCount))
                .font(AppTypography.caption.monospacedDigit())
                .foregroundStyle(AppPalette.textMuted)
                .frame(width: 88, alignment: .leading)
            Text(log.generatedAt)
                .font(AppTypography.caption.monospacedDigit())
                .foregroundStyle(AppPalette.textMuted)
                .lineLimit(1)
                .frame(width: 150, alignment: .leading)
        }
        .padding(.horizontal, 12)
        .frame(height: 58)
        .background(isSelected ? AppPalette.selectedStrong : AppPalette.card)
        .contentShape(Rectangle())
    }

    private var statusText: String {
        log.status == "success" ? model.uiText("完成") : statusLabel(log.status, language: model.appLanguage)
    }

    private var sourceSummary: String {
        return model.uiText("%d 个执行节点 · 后端固定情报接口", log.trace.count)
    }
}

private struct QueryLogDetail: View {
    @EnvironmentObject private var model: AppModel
    let log: IntelligenceQueryResult
    @State private var expandedCardIDs: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(model.uiText("查询日志详情"))
                        .font(AppTypography.headline)
                    Text(log.query)
                        .font(AppTypography.title3.weight(.semibold))
                        .foregroundStyle(AppPalette.text)
                }
                Spacer()
                StatusBadge(text: statusText, tone: StatusTone.operation(log.status))
            }

            VStack(spacing: 12) {
                LogDisclosureCard(
                    title: model.uiText("查询摘要"),
                    preview: "\(statusText) · \(log.generatedAt)",
                    icon: "doc.text.magnifyingglass",
                    accent: StatusTone.operation(log.status).color,
                    isExpanded: expansionBinding(for: "summary")
                ) {
                    VStack(spacing: 10) {
                        LogInfoRow(title: model.uiText("查询内容"), value: log.query)
                        LogInfoRow(title: model.uiText("查询状态"), value: statusText)
                        LogInfoRow(title: model.uiText("执行时间"), value: log.generatedAt)
                        LogInfoRow(title: model.uiText("数据策略"), value: log.persistence == "api-only" ? model.uiText("仅保留查询日志，不保存漏洞明细") : log.persistence)
                    }
                }

                LogDisclosureCard(
                    title: model.uiText("统计概览"),
                    preview: model.uiText("返回 %d 条 · 图谱 %d 节点 / %d 关系 · 本地写入 %d", log.records.count, log.graph.nodeCount, log.graph.edgeCount, log.persisted.inserted + log.persisted.updated),
                    icon: "chart.bar.doc.horizontal",
                    accent: AppPalette.primary,
                    isExpanded: expansionBinding(for: "metrics")
                ) {
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                        LogFact(title: model.uiText("返回记录"), value: "\(log.records.count)")
                        LogFact(title: model.uiText("图谱节点"), value: "\(log.graph.nodeCount)")
                        LogFact(title: model.uiText("图谱关系"), value: "\(log.graph.edgeCount)")
                        LogFact(title: model.uiText("本地写入"), value: "\(log.persisted.inserted + log.persisted.updated)")
                    }
                }

                LogDisclosureCard(
                    title: model.uiText("图谱概览"),
                    preview: graphPreview,
                    icon: "point.3.connected.trianglepath.dotted",
                    accent: AppPalette.primaryStrong,
                    isExpanded: expansionBinding(for: "graph")
                ) {
                    VStack(alignment: .leading, spacing: 14) {
                        if log.graph.nodes.isEmpty {
                            Text(model.uiText("暂无图谱节点"))
                                .font(AppTypography.callout)
                                .foregroundStyle(AppPalette.textMuted)
                        } else {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(model.uiText("图谱节点"))
                                    .font(AppTypography.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.textMuted)
                                FlowLayout(spacing: 8, lineSpacing: 8) {
                                    ForEach(log.graph.nodes) { node in
                                        GraphNodeToken(node: node)
                                    }
                                }
                            }
                        }

                        if !log.graph.edges.isEmpty {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(model.uiText("图谱关系"))
                                    .font(AppTypography.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.textMuted)
                                VStack(spacing: 7) {
                                    ForEach(log.graph.edges) { edge in
                                        GraphEdgeSummary(edge: edge, nodes: log.graph.nodes)
                                    }
                                }
                            }
                        }
                    }
                }

                LogDisclosureCard(
                    title: model.uiText("执行日志"),
                    preview: tracePreview,
                    icon: "list.bullet.clipboard",
                    accent: AppPalette.success,
                    isExpanded: expansionBinding(for: "trace")
                ) {
                    TraceView(trace: log.trace)
                        .frame(minHeight: 180)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var statusText: String {
        log.status == "success" ? model.uiText("完成") : statusLabel(log.status, language: model.appLanguage)
    }

    private var graphPreview: String {
        guard !log.graph.nodes.isEmpty else { return model.uiText("暂无图谱节点") }
        let firstNodes = log.graph.nodes.prefix(3).map(\.label).joined(separator: "、")
        let suffix = model.uiText("%d 个节点", log.graph.nodes.count)
        return model.uiText("%@ · %@ / %d 条关系", firstNodes, suffix, log.graph.edgeCount)
    }

    private var tracePreview: String {
        guard let first = log.trace.first else { return model.uiText("暂无执行日志") }
        return model.uiText("%@ · 共 %d 个执行节点", nodeLabel(first.node, language: model.appLanguage), log.trace.count)
    }

    private func expansionBinding(for id: String) -> Binding<Bool> {
        let scopedID = "\(log.logIdentity)|\(id)"
        return Binding(
            get: { expandedCardIDs.contains(scopedID) },
            set: { isExpanded in
                if isExpanded {
                    expandedCardIDs.insert(scopedID)
                } else {
                    expandedCardIDs.remove(scopedID)
                }
            }
        )
    }
}

private struct LogFact: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(AppTypography.caption)
                .foregroundStyle(AppPalette.textMuted)
            Text(value)
                .font(AppTypography.title3.monospacedDigit().weight(.bold))
                .foregroundStyle(AppPalette.text)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.cardMuted)
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}

private struct LogDisclosureCard<Content: View>: View {
    let title: String
    let preview: String
    let icon: String
    let accent: Color
    @Binding var isExpanded: Bool
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(alignment: .top, spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(accent.opacity(0.12))
                            .frame(width: 34, height: 34)
                        Image(systemName: icon)
                            .font(AppTypography.callout.weight(.semibold))
                            .foregroundStyle(accent)
                    }

                    VStack(alignment: .leading, spacing: 5) {
                        Text(title)
                            .font(AppTypography.callout.weight(.semibold))
                            .foregroundStyle(AppPalette.text)
                        if !isExpanded {
                            Text(preview)
                                .font(AppTypography.caption)
                                .foregroundStyle(AppPalette.textMuted)
                                .lineLimit(2)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    Spacer(minLength: 8)
                    Image(systemName: "chevron.down")
                        .font(AppTypography.caption.weight(.bold))
                        .foregroundStyle(AppPalette.textSubtle)
                        .rotationEffect(.degrees(isExpanded ? 180 : 0))
                        .padding(.top, 8)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                Divider()
                    .padding(.vertical, 12)
                content
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.cardMuted.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(AppPalette.border.opacity(0.82))
        }
    }
}

private struct LogInfoRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 14) {
            Text(title)
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .frame(width: 74, alignment: .leading)
            Text(value)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.text)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .background(AppPalette.card.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct GraphNodeToken: View {
    @EnvironmentObject private var model: AppModel
    let node: KnowledgeNode

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: logNodeIcon(node.type))
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(logNodeColor(node.type))
            Text(node.label)
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.text)
                .lineLimit(1)
            Text(logNodeTypeLabel(node.type, language: model.appLanguage))
                .font(AppTypography.caption2)
                .foregroundStyle(AppPalette.textMuted)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 6)
        .background(logNodeColor(node.type).opacity(0.08))
        .clipShape(Capsule())
        .overlay {
            Capsule()
                .stroke(logNodeColor(node.type).opacity(0.16))
        }
    }
}

private struct GraphEdgeSummary: View {
    @EnvironmentObject private var model: AppModel
    let edge: KnowledgeEdge
    let nodes: [KnowledgeNode]

    var body: some View {
        HStack(spacing: 8) {
            Text(nodeLabel(for: edge.source))
                .lineLimit(1)
            Image(systemName: "arrow.right")
                .font(AppTypography.caption2.weight(.bold))
                .foregroundStyle(AppPalette.textSubtle)
            Text(localizedUI(edge.label.isEmpty ? edge.type : edge.label, language: model.appLanguage))
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.primary)
                .lineLimit(1)
            Image(systemName: "arrow.right")
                .font(AppTypography.caption2.weight(.bold))
                .foregroundStyle(AppPalette.textSubtle)
            Text(nodeLabel(for: edge.target))
                .lineLimit(1)
        }
        .font(AppTypography.caption)
        .foregroundStyle(AppPalette.text)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 11)
        .padding(.vertical, 8)
        .background(AppPalette.card.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private func nodeLabel(for id: String) -> String {
        nodes.first { $0.id == id }?.label ?? id
    }
}

private struct FlowLayout: Layout {
    let spacing: CGFloat
    let lineSpacing: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        let rows = rows(in: subviews, maxWidth: maxWidth)
        let width = maxWidth.isFinite ? maxWidth : rows.map(\.width).max() ?? 0
        return CGSize(width: width, height: rows.reduce(CGFloat.zero) { $0 + $1.height } + CGFloat(max(rows.count - 1, 0)) * lineSpacing)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let rows = rows(in: subviews, maxWidth: bounds.width)
        var y = bounds.minY
        for row in rows {
            var x = bounds.minX
            for item in row.items {
                subviews[item.index].place(
                    at: CGPoint(x: x, y: y),
                    anchor: .topLeading,
                    proposal: ProposedViewSize(item.size)
                )
                x += item.size.width + spacing
            }
            y += row.height + lineSpacing
        }
    }

    private func rows(in subviews: Subviews, maxWidth: CGFloat) -> [FlowRow] {
        var rows: [FlowRow] = []
        var current = FlowRow()
        for index in subviews.indices {
            let size = subviews[index].sizeThatFits(.unspecified)
            let proposedWidth = current.items.isEmpty ? size.width : current.width + spacing + size.width
            if proposedWidth > maxWidth, !current.items.isEmpty {
                rows.append(current)
                current = FlowRow()
            }
            current.append(FlowItem(index: index, size: size), spacing: spacing)
        }
        if !current.items.isEmpty {
            rows.append(current)
        }
        return rows
    }
}

private struct FlowRow {
    var items: [FlowItem] = []
    var width: CGFloat = 0
    var height: CGFloat = 0

    mutating func append(_ item: FlowItem, spacing: CGFloat) {
        width += items.isEmpty ? item.size.width : spacing + item.size.width
        height = max(height, item.size.height)
        items.append(item)
    }
}

private struct FlowItem {
    let index: Int
    let size: CGSize
}

private func logNodeColor(_ type: String) -> Color {
    switch type {
    case "vulnerability": .red
    case "component": AppPalette.primary
    case "weakness": .orange
    case "fix": .green
    case "advisory": AppPalette.primaryStrong
    default: .gray
    }
}

private func logNodeIcon(_ type: String) -> String {
    switch type {
    case "vulnerability": "ladybug.fill"
    case "component": "shippingbox.fill"
    case "weakness": "bolt.fill"
    case "fix": "checkmark.shield.fill"
    case "advisory": "link"
    default: "circle.fill"
    }
}

private func logNodeTypeLabel(_ type: String, language: AppLanguage) -> String {
    localizedUI(["vulnerability": "漏洞", "component": "组件", "weakness": "弱点", "fix": "修复版本", "advisory": "关联公告"][type] ?? type, language: language)
}

private func logID(_ log: IntelligenceQueryResult) -> String {
    log.logIdentity
}

private extension IntelligenceQueryResult {
    var logIdentity: String {
        "\(generatedAt)|\(query)"
    }
}
