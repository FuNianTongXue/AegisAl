import AppKit
import SwiftUI
import UniformTypeIdentifiers

private enum KnowledgeLookupMode: String, CaseIterable, Identifiable {
    case component
    case vulnerability

    var id: String { rawValue }
}

struct KnowledgeGraphView: View {
    @EnvironmentObject private var model: AppModel
    @State private var lookupMode: KnowledgeLookupMode = .component
    @State private var query = "CVE-2021-44228"
    @State private var componentName = "org.apache.logging.log4j:log4j-core"
    @State private var componentVersion = "2.14.1"
    @State private var ecosystem = "Maven"
    @State private var selectedNodeID: String?

    private let ecosystems = ["Maven", "npm", "PyPI", "Go", "crates.io", "NuGet", "RubyGems", "Packagist"]

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 14) {
                    Text(model.uiText("组件查询"))
                        .font(AppTypography.title2.bold())
                        .foregroundStyle(AppPalette.text)
                    Picker("", selection: $lookupMode) {
                        Text(model.uiText("组件版本")).tag(KnowledgeLookupMode.component)
                        Text(model.uiText("漏洞编号")).tag(KnowledgeLookupMode.vulnerability)
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    .frame(width: 230)
                    Spacer()
                    if lookupMode == .component, let result = model.componentVulnerabilityResult {
                        StatusBadge(text: model.uiText("%d 条漏洞", result.total), tone: result.total > 0 ? .warning : .neutral)
                        if result.truncated {
                            StatusBadge(text: model.uiText("导出达到上限"), tone: .warning)
                        }
                    }
                    if lookupMode == .vulnerability, canExportVulnerability {
                        StatusBadge(
                            text: model.uiText("%d 个涉及组件", vulnerabilityComponentCount),
                            tone: vulnerabilityComponentCount > 0 ? .warning : .neutral
                        )
                    }
                    Button(action: exportExcel) {
                        Label(model.uiText("下载全量 Excel"), systemImage: "arrow.down.doc")
                    }
                    .buttonStyle(SecondaryActionButtonStyle())
                    .disabled(exportDisabled)
                }

                if lookupMode == .component {
                    HStack(spacing: 10) {
                        Picker(model.uiText("生态系统"), selection: $ecosystem) {
                            ForEach(ecosystems, id: \.self) { value in
                                Text(value).tag(value)
                            }
                        }
                        .pickerStyle(.menu)
                        .frame(width: 150)

                        graphSearchField(
                            icon: "shippingbox",
                            placeholder: model.uiText("组件名称"),
                            text: $componentName,
                            width: 360,
                            submit: queryComponent
                        )
                        graphSearchField(
                            icon: "number",
                            placeholder: model.uiText("明确版本"),
                            text: $componentVersion,
                            width: 180,
                            submit: queryComponent
                        )
                        Spacer()
                        Button(action: queryComponent) {
                            Label(model.uiText("查询组件漏洞"), systemImage: "arrow.triangle.branch")
                        }
                        .buttonStyle(PrimaryActionButtonStyle())
                        .disabled(
                            componentName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                || componentVersion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                || model.isBusy("component-vulnerability-query")
                        )
                    }
                } else {
                    HStack(spacing: 10) {
                        graphSearchField(
                            icon: "magnifyingglass",
                            placeholder: model.uiText("输入 CVE 编号，生成漏洞知识图谱"),
                            text: $query,
                            width: 520,
                            submit: queryVulnerability
                        )
                        Spacer()
                        Button(action: queryVulnerability) {
                            Label(model.uiText("查询漏洞"), systemImage: "exclamationmark.shield")
                        }
                        .buttonStyle(PrimaryActionButtonStyle())
                        .disabled(query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.isBusy("intelligence-query"))
                    }
                }
            }
            .padding(22)
            Divider()
            HSplitView {
                Group {
                    if let graph = model.knowledgeGraph, !graph.nodes.isEmpty {
                        KnowledgeSankeyCanvas(graph: graph, selectedNodeID: $selectedNodeID)
                    } else {
                        ContentUnavailableView(model.uiText("暂无桑基图"), systemImage: "arrow.triangle.branch")
                    }
                }
                .frame(minWidth: 560, maxWidth: .infinity, maxHeight: .infinity)
                GraphInspector(graph: model.knowledgeGraph, selectedNodeID: selectedNodeID)
                    .frame(minWidth: 290, idealWidth: 330, maxWidth: 380)
            }
        }
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
    }

    private func graphSearchField(
        icon: String,
        placeholder: String,
        text: Binding<String>,
        width: CGFloat,
        submit: @escaping () -> Void
    ) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(AppPalette.textMuted)
            TextField(placeholder, text: text)
                .textFieldStyle(.plain)
                .foregroundStyle(AppPalette.text)
                .onSubmit(submit)
        }
        .padding(.horizontal, 11)
        .frame(width: width, height: 38)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .stroke(AppPalette.border)
        }
    }

    private func queryComponent() {
        selectedNodeID = nil
        Task {
            await model.queryComponentVulnerabilities(
                name: componentName,
                version: componentVersion,
                ecosystem: ecosystem
            )
        }
    }

    private func queryVulnerability() {
        selectedNodeID = nil
        Task { await model.queryIntelligence(query: query) }
    }

    private func exportExcel() {
        if lookupMode == .vulnerability {
            exportVulnerabilityComponents()
            return
        }
        let panel = NSSavePanel()
        panel.title = model.uiText("下载组件漏洞 Excel")
        let stem = "\(ecosystem)-\(componentName)-\(componentVersion)"
            .replacingOccurrences(of: "[^A-Za-z0-9._-]+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        panel.nameFieldStringValue = "SecFlow-\(stem.isEmpty ? "component" : stem)-vulnerabilities.xlsx"
        panel.canCreateDirectories = true
        if let xlsx = UTType(filenameExtension: "xlsx") {
            panel.allowedContentTypes = [xlsx]
        }
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        Task {
            await model.downloadComponentVulnerabilities(
                name: componentName,
                version: componentVersion,
                ecosystem: ecosystem,
                to: destination
            )
        }
    }

    private func exportVulnerabilityComponents() {
        let cleanIdentifier = query.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        let panel = NSSavePanel()
        panel.title = model.uiText("下载漏洞组件 Excel")
        let stem = cleanIdentifier
            .replacingOccurrences(of: "[^A-Za-z0-9._-]+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        panel.nameFieldStringValue = "SecFlow-\(stem.isEmpty ? "vulnerability" : stem)-component-ranges.xlsx"
        panel.canCreateDirectories = true
        if let xlsx = UTType(filenameExtension: "xlsx") {
            panel.allowedContentTypes = [xlsx]
        }
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        Task {
            await model.downloadVulnerabilityComponents(identifier: cleanIdentifier, to: destination)
        }
    }

    private var canExportVulnerability: Bool {
        guard let result = model.intelligenceResult, !result.records.isEmpty else { return false }
        let cleanQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return result.query.caseInsensitiveCompare(cleanQuery) == .orderedSame
    }

    private var vulnerabilityComponentCount: Int {
        guard canExportVulnerability else { return 0 }
        return model.intelligenceResult?.records.reduce(0) { $0 + ($1.components?.count ?? 0) } ?? 0
    }

    private var exportDisabled: Bool {
        switch lookupMode {
        case .component:
            return model.componentVulnerabilityResult == nil
                || model.isBusy("component-vulnerability-query")
                || model.isBusy("component-vulnerability-export")
        case .vulnerability:
            return !canExportVulnerability
                || model.isBusy("intelligence-query")
                || model.isBusy("vulnerability-component-export")
        }
    }
}

private struct KnowledgeSankeyCanvas: View {
    @EnvironmentObject private var model: AppModel
    let graph: KnowledgeGraphPayload
    @Binding var selectedNodeID: String?

    var body: some View {
        ZStack(alignment: .bottomLeading) {
            D3SankeyChartView(
                data: sankeyData,
                selectedNodeID: selectedNodeID,
                onSelect: { selectedNodeID = $0 }
            )
            GraphLegend()
                .padding(14)
        }
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.9))
        }
        .padding(22)
        .onAppear(perform: selectPrimaryNode)
        .onChange(of: graphSignature) { _, _ in selectPrimaryNode() }
    }

    private var graphSignature: String {
        "\(graph.nodes.map(\.id).joined(separator: "|"))::\(graph.edges.map(\.id).joined(separator: "|"))"
    }

    private var sankeyData: SankeyChartData {
        let nodesByID = Dictionary(uniqueKeysWithValues: graph.nodes.map { ($0.id, $0) })
        let nodes = graph.nodes.map { node in
            ChartNode(
                id: node.id,
                label: node.label,
                type: node.type,
                severity: node.metadata["severity"]?.text,
                column: column(for: node.type),
                version: node.type == "fix" ? node.label : nil,
                ecosystem: node.metadata["ecosystem"]?.text
            )
        }
        let links = graph.edges.map { edge in
            let sourceSeverity = nodesByID[edge.source]?.metadata["severity"]?.text
            let targetSeverity = nodesByID[edge.target]?.metadata["severity"]?.text
            return ChartLink(
                from: edge.source,
                to: edge.target,
                type: edge.type,
                value: 1,
                severity: sourceSeverity ?? targetSeverity
            )
        }
        return SankeyChartData(nodes: nodes, links: links)
    }

    private func column(for type: String) -> Int {
        switch type {
        case "vulnerability": 0
        case "fix": 2
        default: 1
        }
    }

    private func selectPrimaryNode() {
        guard selectedNodeID == nil || !graph.nodes.contains(where: { $0.id == selectedNodeID }) else { return }
        selectedNodeID = graph.nodes.first { $0.type == "vulnerability" }?.id ?? graph.nodes.first?.id
    }
}

private struct GraphCanvas: View {
    @EnvironmentObject private var model: AppModel
    let graph: KnowledgeGraphPayload
    @Binding var selectedNodeID: String?
    @State private var scale: CGFloat = 1
    @State private var committedScale: CGFloat = 1
    @State private var offset: CGSize = .zero
    @State private var committedOffset: CGSize = .zero

    private let minScale: CGFloat = 0.42
    private let maxScale: CGFloat = 2.4

    var body: some View {
        GeometryReader { proxy in
            let positions = graphPositions(nodes: graph.nodes, edges: graph.edges, size: proxy.size)
            let activeNodeID = selectedNodeID ?? primaryNodeID
            ZStack(alignment: .topLeading) {
                GraphGrid(scale: scale, offset: offset)
                    .contentShape(Rectangle())
                    .gesture(panGesture)

                Canvas { context, _ in
                    for edge in graph.edges {
                        guard let startPoint = positions[edge.source], let endPoint = positions[edge.target] else { continue }
                        let start = transformed(startPoint, in: proxy.size)
                        let end = transformed(endPoint, in: proxy.size)
                        let connected = isEdge(edge, connectedTo: activeNodeID)
                        let color = connected ? AppPalette.primary.opacity(0.48) : AppPalette.textSubtle.opacity(0.2)
                        let distance = max(hypot(end.x - start.x, end.y - start.y), 1)
                        let curve = min(42, distance * 0.14) * edgeCurveSign(edge.id)
                        let mid = CGPoint(x: (start.x + end.x) / 2, y: (start.y + end.y) / 2)
                        let normal = CGPoint(x: -(end.y - start.y) / distance, y: (end.x - start.x) / distance)
                        let control = CGPoint(x: mid.x + normal.x * curve, y: mid.y + normal.y * curve)
                        var path = Path()
                        path.move(to: start)
                        path.addQuadCurve(to: end, control: control)
                        context.stroke(path, with: .color(color), lineWidth: connected ? 2.2 : 1.15)

                        if scale > 0.72, connected, !edge.label.isEmpty {
                            let labelPoint = CGPoint(x: (mid.x + control.x) / 2, y: (mid.y + control.y) / 2)
                            context.draw(
                                Text(graphEdgeLabel(edge, language: model.appLanguage))
                                    .font(AppTypography.caption2.weight(.semibold))
                                    .foregroundColor(AppPalette.textMuted),
                                at: labelPoint
                            )
                        }
                    }
                }
                .allowsHitTesting(false)

                ForEach(graph.nodes) { node in
                    if let position = positions[node.id] {
                        Button {
                            withAnimation(.spring(response: 0.24, dampingFraction: 0.82)) {
                                selectedNodeID = node.id
                            }
                        } label: {
                            ForceGraphNodeView(node: node, isSelected: activeNodeID == node.id, zoomScale: scale)
                        }
                        .buttonStyle(.plain)
                        .position(transformed(position, in: proxy.size))
                    }
                }

                GraphCanvasToolbar(
                    scale: scale,
                    zoomIn: { zoom(by: 1.18) },
                    zoomOut: { zoom(by: 0.84) },
                    reset: { resetViewport() }
                )
                .padding(14)

                GraphLegend()
                    .padding(14)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomLeading)

                Text(model.uiText("拖动画布移动 · 双指捏合或按钮缩放"))
                    .font(AppTypography.caption2.weight(.semibold))
                    .foregroundStyle(AppPalette.textMuted)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(.ultraThinMaterial, in: Capsule())
                    .overlay { Capsule().stroke(AppPalette.border.opacity(0.7)) }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .topTrailing)
            }
            .simultaneousGesture(zoomGesture)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.9))
            }
            .shadow(color: Color.black.opacity(0.04), radius: 18, y: 8)
            .padding(22)
            .onChange(of: graphSignature) { _, _ in
                resetViewport(animated: false)
            }
        }
    }

    private var graphSignature: String {
        "\(graph.nodes.map(\.id).joined(separator: "|"))::\(graph.edges.map(\.id).joined(separator: "|"))"
    }

    private var primaryNodeID: String? {
        graph.nodes.first { $0.type == "vulnerability" }?.id ?? graph.nodes.first?.id
    }

    private var panGesture: some Gesture {
        DragGesture(minimumDistance: 2)
            .onChanged { value in
                offset = CGSize(
                    width: committedOffset.width + value.translation.width,
                    height: committedOffset.height + value.translation.height
                )
            }
            .onEnded { _ in
                committedOffset = offset
            }
    }

    private var zoomGesture: some Gesture {
        MagnificationGesture()
            .onChanged { value in
                scale = clamp(committedScale * value, minScale, maxScale)
            }
            .onEnded { _ in
                committedScale = scale
            }
    }

    private func zoom(by multiplier: CGFloat) {
        withAnimation(.spring(response: 0.24, dampingFraction: 0.86)) {
            let next = clamp(scale * multiplier, minScale, maxScale)
            scale = next
            committedScale = next
        }
    }

    private func resetViewport(animated: Bool = true) {
        let changes = {
            scale = 1
            committedScale = 1
            offset = .zero
            committedOffset = .zero
        }
        if animated {
            withAnimation(.spring(response: 0.28, dampingFraction: 0.86), changes)
        } else {
            changes()
        }
    }

    private func transformed(_ point: CGPoint, in size: CGSize) -> CGPoint {
        CGPoint(
            x: size.width / 2 + offset.width + point.x * scale,
            y: size.height / 2 + offset.height + point.y * scale
        )
    }

    private func isEdge(_ edge: KnowledgeEdge, connectedTo nodeID: String?) -> Bool {
        guard let nodeID else { return false }
        return edge.source == nodeID || edge.target == nodeID
    }

    private func graphPositions(nodes: [KnowledgeNode], edges: [KnowledgeEdge], size: CGSize) -> [String: CGPoint] {
        guard !nodes.isEmpty else { return [:] }
        let primary = primaryNodeID ?? nodes[0].id
        var positions: [String: CGPoint] = [:]
        let density = min(1.65, 1 + CGFloat(nodes.count) * 0.035)
        for (index, node) in nodes.enumerated() {
            if node.id == primary {
                positions[node.id] = .zero
                continue
            }
            let radius = baseRadius(for: node.type, canvasSize: size) * density
            let baseAngle = -CGFloat.pi / 2 + CGFloat(index) * 2.399963229728653
            let jitter = (stableFraction(node.id) - 0.5) * 0.52
            let angle = baseAngle + jitter
            positions[node.id] = CGPoint(x: cos(angle) * radius, y: sin(angle) * radius)
        }

        let nodeByID = Dictionary(uniqueKeysWithValues: nodes.map { ($0.id, $0) })
        for iteration in 0..<82 {
            var displacement = Dictionary(uniqueKeysWithValues: nodes.map { ($0.id, CGVector.zero) })

            for i in 0..<nodes.count {
                for j in (i + 1)..<nodes.count {
                    let a = nodes[i].id
                    let b = nodes[j].id
                    guard let pa = positions[a], let pb = positions[b] else { continue }
                    var dx = pa.x - pb.x
                    var dy = pa.y - pb.y
                    var distance = sqrt(dx * dx + dy * dy)
                    if distance < 0.01 {
                        dx = stableFraction(a) - 0.5
                        dy = stableFraction(b) - 0.5
                        distance = max(sqrt(dx * dx + dy * dy), 0.01)
                    }
                    let force = min(90, 16000 / max(distance * distance, 1))
                    let fx = dx / distance * force
                    let fy = dy / distance * force
                    displacement[a, default: .zero].dx += fx
                    displacement[a, default: .zero].dy += fy
                    displacement[b, default: .zero].dx -= fx
                    displacement[b, default: .zero].dy -= fy
                }
            }

            for edge in edges {
                guard let source = positions[edge.source], let target = positions[edge.target] else { continue }
                let dx = target.x - source.x
                let dy = target.y - source.y
                let distance = max(sqrt(dx * dx + dy * dy), 1)
                let sourceType = nodeByID[edge.source]?.type ?? ""
                let targetType = nodeByID[edge.target]?.type ?? ""
                let desired = desiredEdgeLength(sourceType: sourceType, targetType: targetType)
                let force = (distance - desired) * 0.042
                let fx = dx / distance * force
                let fy = dy / distance * force
                if edge.source != primary {
                    displacement[edge.source, default: .zero].dx += fx
                    displacement[edge.source, default: .zero].dy += fy
                }
                if edge.target != primary {
                    displacement[edge.target, default: .zero].dx -= fx
                    displacement[edge.target, default: .zero].dy -= fy
                }
            }

            let temperature = max(0.12, 1 - CGFloat(iteration) / 82)
            for node in nodes where node.id != primary {
                guard var point = positions[node.id] else { continue }
                var vector = displacement[node.id] ?? .zero
                vector.dx += -point.x * 0.014
                vector.dy += -point.y * 0.014
                point.x += clamp(vector.dx, -24, 24) * temperature
                point.y += clamp(vector.dy, -24, 24) * temperature
                positions[node.id] = point
            }
        }
        return positions
    }

    private func baseRadius(for type: String, canvasSize: CGSize) -> CGFloat {
        let canvasRadius = max(150, min(canvasSize.width, canvasSize.height) * 0.24)
        switch type {
        case "weakness": return canvasRadius * 0.72
        case "component": return canvasRadius
        case "fix": return canvasRadius * 1.28
        case "advisory": return canvasRadius * 1.12
        default: return canvasRadius * 0.9
        }
    }

    private func desiredEdgeLength(sourceType: String, targetType: String) -> CGFloat {
        if sourceType == "component" || targetType == "component" { return 175 }
        if sourceType == "fix" || targetType == "fix" { return 145 }
        if sourceType == "advisory" || targetType == "advisory" { return 190 }
        return 150
    }
}

private func graphEdgeLabel(_ edge: KnowledgeEdge, language: AppLanguage) -> String {
    localizedUI(edge.label.isEmpty ? edge.type : edge.label, language: language)
}

private struct GraphGrid: View {
    let scale: CGFloat
    let offset: CGSize

    var body: some View {
        Canvas { context, size in
            let background = Path(CGRect(origin: .zero, size: size))
            context.fill(background, with: .linearGradient(
                Gradient(colors: [AppPalette.card, AppPalette.cardMuted.opacity(0.55)]),
                startPoint: .zero,
                endPoint: CGPoint(x: size.width, y: size.height)
            ))

            let spacing = max(24, min(90, 46 * scale))
            let startX = offset.width.truncatingRemainder(dividingBy: spacing)
            let startY = offset.height.truncatingRemainder(dividingBy: spacing)
            var grid = Path()
            for x in stride(from: startX, through: size.width, by: spacing) {
                grid.move(to: CGPoint(x: x, y: 0))
                grid.addLine(to: CGPoint(x: x, y: size.height))
            }
            for y in stride(from: startY, through: size.height, by: spacing) {
                grid.move(to: CGPoint(x: 0, y: y))
                grid.addLine(to: CGPoint(x: size.width, y: y))
            }
            context.stroke(grid, with: .color(AppPalette.border.opacity(0.34)), lineWidth: 0.7)

            let center = CGPoint(x: size.width / 2 + offset.width, y: size.height / 2 + offset.height)
            let glow = Path(ellipseIn: CGRect(x: center.x - 155 * scale, y: center.y - 155 * scale, width: 310 * scale, height: 310 * scale))
            context.fill(glow, with: .radialGradient(
                Gradient(colors: [AppPalette.primary.opacity(0.11), .clear]),
                center: center,
                startRadius: 0,
                endRadius: 180 * scale
            ))
        }
    }
}

private struct ForceGraphNodeView: View {
    let node: KnowledgeNode
    let isSelected: Bool
    let zoomScale: CGFloat

    private var color: Color { nodeColor(node.type) }
    private var nodeSize: CGFloat { node.type == "vulnerability" ? 74 : 54 }
    private var visualScale: CGFloat { clamp(zoomScale, 0.76, 1.18) }

    var body: some View {
        VStack(spacing: 6) {
            ZStack {
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color.white.opacity(0.32), color.opacity(0.96), color.opacity(0.78)],
                            center: .topLeading,
                            startRadius: 4,
                            endRadius: nodeSize
                        )
                    )
                Image(systemName: nodeIcon(node.type))
                    .font(AppTypography.system(size: node.type == "vulnerability" ? 20 : 15, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: nodeSize, height: nodeSize)
            .overlay {
                Circle()
                    .stroke(isSelected ? Color.white : Color.white.opacity(0.54), lineWidth: isSelected ? 4 : 1.4)
            }
            .overlay {
                Circle()
                    .stroke(color.opacity(isSelected ? 0.5 : 0.22), lineWidth: isSelected ? 10 : 4)
                    .blur(radius: isSelected ? 7 : 5)
            }
            .shadow(color: color.opacity(isSelected ? 0.42 : 0.2), radius: isSelected ? 18 : 10, y: isSelected ? 8 : 5)

            Text(node.label)
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(AppPalette.text)
                .lineLimit(2)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(.ultraThinMaterial, in: Capsule())
                .overlay { Capsule().stroke(AppPalette.border.opacity(isSelected ? 0.95 : 0.55)) }
                .opacity(zoomScale > 0.5 ? 1 : 0)
        }
        .scaleEffect(visualScale)
        .animation(.spring(response: 0.22, dampingFraction: 0.84), value: isSelected)
        .contentShape(Rectangle())
    }
}

private struct GraphCanvasToolbar: View {
    @EnvironmentObject private var model: AppModel
    let scale: CGFloat
    let zoomIn: () -> Void
    let zoomOut: () -> Void
    let reset: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            GraphToolButton(systemImage: "minus.magnifyingglass", action: zoomOut, help: model.uiText("缩小"))
            Text("\(Int(scale * 100))%")
                .font(AppTypography.caption.monospacedDigit().weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .frame(width: 48)
            GraphToolButton(systemImage: "plus.magnifyingglass", action: zoomIn, help: model.uiText("放大"))
            Divider().frame(height: 18)
            GraphToolButton(systemImage: "scope", action: reset, help: model.uiText("居中"))
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(.ultraThinMaterial, in: Capsule())
        .overlay { Capsule().stroke(AppPalette.border.opacity(0.82)) }
        .shadow(color: Color.black.opacity(0.05), radius: 10, y: 4)
    }
}

private struct GraphToolButton: View {
    let systemImage: String
    let action: () -> Void
    let help: String

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(AppTypography.caption.weight(.bold))
                .foregroundStyle(AppPalette.text)
                .frame(width: 24, height: 24)
                .background(AppPalette.card.opacity(0.72), in: Circle())
        }
        .buttonStyle(.plain)
        .help(help)
    }
}

private struct GraphLegend: View {
    @EnvironmentObject private var model: AppModel
    private let items: [(type: String, label: String)] = [
        ("vulnerability", "漏洞"),
        ("component", "组件"),
        ("weakness", "弱点"),
        ("fix", "修复"),
        ("advisory", "公告"),
    ]

    var body: some View {
        HStack(spacing: 10) {
            ForEach(items, id: \.type) { item in
                HStack(spacing: 5) {
                    Circle()
                        .fill(nodeColor(item.type))
                        .frame(width: 8, height: 8)
                    Text(model.uiText(item.label))
                        .font(AppTypography.caption2.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(.ultraThinMaterial, in: Capsule())
        .overlay { Capsule().stroke(AppPalette.border.opacity(0.72)) }
    }
}

private func clamp(_ value: CGFloat, _ lower: CGFloat, _ upper: CGFloat) -> CGFloat {
    min(max(value, lower), upper)
}

private func stableFraction(_ value: String) -> CGFloat {
    var hash: UInt64 = 1469598103934665603
    for scalar in value.unicodeScalars {
        hash ^= UInt64(scalar.value)
        hash = hash &* 1099511628211
    }
    return CGFloat(hash % 10_000) / 10_000
}

private func edgeCurveSign(_ value: String) -> CGFloat {
    stableFraction(value) >= 0.5 ? 1 : -1
}

private struct GraphInspector: View {
    @EnvironmentObject private var model: AppModel
    let graph: KnowledgeGraphPayload?
    let selectedNodeID: String?
    @State private var expandedCardIDs: Set<String> = []

    private var selected: KnowledgeNode? {
        graph?.nodes.first { $0.id == selectedNodeID } ?? graph?.nodes.first { $0.type == "vulnerability" }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let node = selected {
                    Panel {
                        VStack(alignment: .leading, spacing: 16) {
                            HStack(alignment: .top, spacing: 12) {
                                ZStack {
                                    Circle()
                                        .fill(nodeColor(node.type).opacity(0.13))
                                        .frame(width: 42, height: 42)
                                    Image(systemName: nodeIcon(node.type))
                                        .foregroundStyle(nodeColor(node.type))
                                        .font(AppTypography.title2)
                                }
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(node.label)
                                        .font(AppTypography.headline)
                                        .foregroundStyle(AppPalette.text)
                                    Text(typeLabel(node.type, language: model.appLanguage))
                                        .font(AppTypography.caption)
                                        .foregroundStyle(AppPalette.textMuted)
                                }
                                Spacer(minLength: 0)
                            }

                            let facts = summaryFacts(for: node)
                            if !facts.isEmpty {
                                HStack(spacing: 8) {
                                    ForEach(facts) { fact in
                                        MetadataFactPill(fact: fact)
                                    }
                                }
                            }

                            let cards = metadataCards(for: node)
                            if cards.isEmpty {
                                Text(model.uiText("暂无更多详情"))
                                    .font(AppTypography.callout)
                                    .foregroundStyle(AppPalette.textMuted)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(12)
                                    .background(AppPalette.cardMuted)
                                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                            } else {
                                VStack(spacing: 10) {
                                    ForEach(cards) { card in
                                        ExpandableMetadataCard(
                                            card: card,
                                            isExpanded: expansionBinding(for: "\(node.id)|\(card.id)")
                                        )
                                    }
                                }
                            }
                        }
                    }
                    Panel {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(model.uiText("关联实体")).font(AppTypography.headline)
                            ForEach(relatedNodes(to: node)) { related in
                                HStack {
                                    Image(systemName: nodeIcon(related.type)).foregroundStyle(nodeColor(related.type))
                                    VStack(alignment: .leading) {
                                        Text(related.label).font(AppTypography.callout.weight(.semibold))
                                        Text(typeLabel(related.type, language: model.appLanguage)).font(AppTypography.caption).foregroundStyle(AppPalette.textMuted)
                                    }
                                    Spacer()
                                }
                                .padding(9).background(AppPalette.cardMuted).clipShape(RoundedRectangle(cornerRadius: 6))
                            }
                        }
                    }
                } else {
                    ContentUnavailableView(model.uiText("选择图节点"), systemImage: "cursorarrow.click")
                }
            }
            .padding(16)
        }
        .textSelection(.enabled)
    }

    private func relatedNodes(to node: KnowledgeNode) -> [KnowledgeNode] {
        guard let graph else { return [] }
        let ids = Set(graph.edges.compactMap { edge in
            if edge.source == node.id { return edge.target }
            if edge.target == node.id { return edge.source }
            return nil
        })
        return graph.nodes.filter { ids.contains($0.id) }
    }

    private func summaryFacts(for node: KnowledgeNode) -> [MetadataFact] {
        var facts: [MetadataFact] = []
        if let score = cleanMetadataValue("cvss_score", from: node) {
            facts.append(MetadataFact(id: "cvss_score", title: "CVSS", value: score, tone: .neutral))
        }
        if let severity = cleanMetadataValue("severity_zh", from: node) ?? cleanMetadataValue("severity", from: node) {
            facts.append(MetadataFact(id: "severity", title: model.uiText("严重等级"), value: severityLabel(severity, language: model.appLanguage), tone: StatusTone.severity(severity)))
        }
        return facts
    }

    private func metadataCards(for node: KnowledgeNode) -> [MetadataCard] {
        let preferredKeys: [String]
        switch node.type {
        case "vulnerability":
            preferredKeys = [
                "summary_zh",
                "summary",
                "mitigation_zh",
                "remediation_zh",
                "affected_versions",
                "fixed_versions",
                "reference_links",
                "title",
                "aliases",
                "cwes",
                "published_at",
                "updated_at",
            ]
        case "component":
            preferredKeys = ["ecosystem", "affected", "fixed"]
        case "fix":
            preferredKeys = ["component"]
        default:
            preferredKeys = node.metadata.keys.sorted()
        }

        var cards: [MetadataCard] = []
        var used = Set<String>()
        for key in preferredKeys {
            appendMetadataCard(key, from: node, to: &cards, used: &used)
        }
        for key in node.metadata.keys.sorted() where !used.contains(key) {
            appendMetadataCard(key, from: node, to: &cards, used: &used)
        }
        return cards
    }

    private func appendMetadataCard(
        _ key: String,
        from node: KnowledgeNode,
        to cards: inout [MetadataCard],
        used: inout Set<String>
    ) {
        guard !used.contains(key) else { return }
        if ["severity", "severity_zh", "cvss_score"].contains(key) {
            used.insert(key)
            return
        }
        if key == "severity", node.metadata["severity_zh"]?.text.isEmpty == false {
            used.insert(key)
            return
        }
        if key == "summary", node.metadata["summary_zh"]?.text.isEmpty == false {
            used.insert(key)
            return
        }
        guard let rawValue = node.metadata[key] else {
            used.insert(key)
            return
        }
        let raw = rawValue.text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else {
            used.insert(key)
            return
        }
        let value = metadataValue(key, raw, language: model.appLanguage)
        guard !value.isEmpty else {
            used.insert(key)
            return
        }
        cards.append(
            MetadataCard(
                id: key,
                title: metadataLabel(key, language: model.appLanguage),
                icon: metadataIcon(key),
                value: value,
                items: metadataItems(key, rawValue: rawValue, formattedValue: value),
                isLinkList: isReferenceKey(key)
            )
        )
        used.insert(key)
    }

    private func cleanMetadataValue(_ key: String, from node: KnowledgeNode) -> String? {
        guard let raw = node.metadata[key]?.text.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        let value = metadataValue(key, raw, language: model.appLanguage)
        return value.isEmpty ? nil : value
    }

    private func expansionBinding(for id: String) -> Binding<Bool> {
        Binding(
            get: { expandedCardIDs.contains(id) },
            set: { isExpanded in
                if isExpanded {
                    expandedCardIDs.insert(id)
                } else {
                    expandedCardIDs.remove(id)
                }
            }
        )
    }
}

private struct MetadataFact: Identifiable {
    let id: String
    let title: String
    let value: String
    let tone: StatusTone
}

private struct MetadataFactPill: View {
    let fact: MetadataFact

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(fact.title)
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
            Text(fact.value)
                .font(AppTypography.callout.weight(.semibold))
                .foregroundStyle(fact.tone.color)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .background(fact.tone.color.opacity(0.09))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(fact.tone.color.opacity(0.18))
        }
    }
}

private struct MetadataCard: Identifiable, Equatable {
    let id: String
    let title: String
    let icon: String
    let value: String
    let items: [String]
    let isLinkList: Bool

    var preview: String {
        let compact = value
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "  ", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard compact.count > 78 else { return compact }
        let end = compact.index(compact.startIndex, offsetBy: 78)
        return "\(compact[..<end])…"
    }
}

private struct ExpandableMetadataCard: View {
    let card: MetadataCard
    @Binding var isExpanded: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(alignment: .top, spacing: 11) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(cardAccent.opacity(0.12))
                            .frame(width: 30, height: 30)
                        Image(systemName: card.icon)
                            .font(AppTypography.caption.weight(.semibold))
                            .foregroundStyle(cardAccent)
                    }
                    VStack(alignment: .leading, spacing: 5) {
                        Text(card.title)
                            .font(AppTypography.callout.weight(.semibold))
                            .foregroundStyle(AppPalette.text)
                        if !isExpanded {
                            Text(card.preview)
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
                        .padding(.top, 6)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                Divider()
                    .padding(.vertical, 11)
                expandedContent
            }
        }
        .padding(13)
        .background(AppPalette.cardMuted.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(AppPalette.border.opacity(0.82))
        }
    }

    @ViewBuilder
    private var expandedContent: some View {
        if card.isLinkList && !card.items.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(card.items, id: \.self) { item in
                    if let url = URL(string: item), let scheme = url.scheme, ["http", "https"].contains(scheme.lowercased()) {
                        Link(destination: url) {
                            HStack(alignment: .firstTextBaseline, spacing: 7) {
                                Image(systemName: "arrow.up.right.square")
                                    .font(AppTypography.caption)
                                Text(item)
                                    .font(AppTypography.caption)
                                    .lineLimit(2)
                            }
                            .foregroundStyle(AppPalette.primary)
                        }
                    } else {
                        Text(item)
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.text)
                    }
                }
            }
        } else {
            Text(card.value)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.text)
                .lineSpacing(4)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var cardAccent: Color {
        switch card.id {
        case "summary", "summary_zh":
            return AppPalette.primary
        case "mitigation_zh":
            return AppPalette.warning
        case "remediation_zh", "fixed_versions", "fixed":
            return AppPalette.success
        case "affected_versions", "affected":
            return AppPalette.danger
        case "reference_links", "references":
            return AppPalette.primaryStrong
        default:
            return AppPalette.textMuted
        }
    }
}

private func nodeColor(_ type: String) -> Color {
    switch type {
    case "vulnerability": .red
    case "component": AppPalette.primary
    case "weakness": .orange
    case "fix": .green
    case "advisory": AppPalette.primaryStrong
    default: .gray
    }
}

private func nodeIcon(_ type: String) -> String {
    switch type {
    case "vulnerability": "ladybug.fill"
    case "component": "shippingbox.fill"
    case "weakness": "bolt.fill"
    case "fix": "checkmark.shield.fill"
    case "advisory": "link"
    default: "circle.fill"
    }
}

private func typeLabel(_ type: String, language: AppLanguage) -> String {
    let value = ["vulnerability": "漏洞", "component": "组件", "weakness": "弱点", "fix": "修复版本", "advisory": "关联公告"][type] ?? type
    return localizedUI(value, language: language)
}

private func metadataLabel(_ key: String, language: AppLanguage) -> String {
    let value = [
        "severity": "严重等级",
        "severity_zh": "严重等级",
        "cvss_score": "CVSS",
        "title": "名称",
        "summary": "描述",
        "summary_zh": "描述",
        "mitigation_zh": "缓释措施",
        "remediation_zh": "修复方式",
        "ecosystem": "生态",
        "affected": "影响范围",
        "affected_versions": "影响范围",
        "fixed": "修复版本",
        "fixed_versions": "修复版本",
        "component": "组件",
        "reference_links": "来源链接",
        "references": "来源链接",
        "aliases": "关联编号",
        "cwes": "弱点类型",
        "published_at": "发布时间",
        "updated_at": "更新时间",
    ][key] ?? key
    return localizedUI(value, language: language)
}

private func metadataIcon(_ key: String) -> String {
    [
        "title": "text.alignleft",
        "summary": "doc.text",
        "summary_zh": "doc.text",
        "mitigation_zh": "shield.lefthalf.filled",
        "remediation_zh": "checkmark.shield",
        "affected": "exclamationmark.triangle",
        "affected_versions": "exclamationmark.triangle",
        "fixed": "wrench.and.screwdriver",
        "fixed_versions": "wrench.and.screwdriver",
        "ecosystem": "circle.hexagongrid",
        "component": "shippingbox",
        "reference_links": "link",
        "references": "link",
        "aliases": "number",
        "cwes": "bolt",
        "published_at": "calendar.badge.plus",
        "updated_at": "clock.arrow.circlepath",
    ][key] ?? "info.circle"
}

private func metadataValue(_ key: String, _ value: String, language: AppLanguage) -> String {
    switch key {
    case "severity":
        return severityLabel(value, language: language)
    case "affected", "fixed", "affected_versions", "fixed_versions", "aliases", "cwes", "reference_links", "references":
        return normalizedListText(value, separator: isReferenceKey(key) ? "\n" : "、")
    default:
        return value
    }
}

private func metadataItems(_ key: String, rawValue: JSONValue, formattedValue: String) -> [String] {
    guard isListMetadataKey(key) else { return [] }
    let values: [String]
    switch rawValue {
    case let .array(items):
        values = items.map(\.text)
    default:
        values = formattedValue
            .split(whereSeparator: { ["\n", "、", ","].contains(String($0)) })
            .map(String.init)
    }
    return values
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
}

private func isListMetadataKey(_ key: String) -> Bool {
    [
        "affected",
        "fixed",
        "affected_versions",
        "fixed_versions",
        "aliases",
        "cwes",
        "reference_links",
        "references",
    ].contains(key)
}

private func isReferenceKey(_ key: String) -> Bool {
    ["reference_links", "references"].contains(key)
}

private func normalizedListText(_ value: String, separator: String) -> String {
    let cleaned = value
        .replacingOccurrences(of: "[", with: "")
        .replacingOccurrences(of: "]", with: "")
        .replacingOccurrences(of: "\"", with: "")
    return cleaned
        .split(separator: ",")
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
        .joined(separator: separator)
}
