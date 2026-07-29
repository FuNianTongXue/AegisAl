import AppKit
import CryptoKit
import SwiftUI
import UniformTypeIdentifiers

struct AssistantComposerSuggestion: Identifiable, Equatable {
    let id: String
    let label: String
    let detail: String
    let icon: String
    let replacement: String
}

func assistantComposerSuggestions(for input: String) -> [AssistantComposerSuggestion] {
    let clean = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    let values = [
        AssistantComposerSuggestion(id: "scan", label: "/scan", detail: "完整项目扫描", icon: "shield.lefthalf.filled", replacement: "扫描所选项目的完整代码和依赖风险"),
        AssistantComposerSuggestion(id: "cve", label: "/cve", detail: "漏洞核验", icon: "magnifyingglass", replacement: "查询漏洞编号 "),
        AssistantComposerSuggestion(id: "report", label: "/report", detail: "生成安全报告", icon: "doc.badge.plus", replacement: "根据当前扫描结果生成安全报告"),
        AssistantComposerSuggestion(id: "code-review", label: "/code-review", detail: "代码安全审查", icon: "chevron.left.forwardslash.chevron.right", replacement: "对所选项目进行完整代码安全审查"),
        AssistantComposerSuggestion(id: "agent", label: "@Security Agent", detail: "安全分析智能体", icon: "person.badge.shield.checkmark", replacement: "请由 Security Agent 分析："),
        AssistantComposerSuggestion(id: "knowledge", label: "#漏洞知识库", detail: "可信漏洞事实", icon: "books.vertical", replacement: "基于漏洞知识库核验："),
    ]
    guard clean.hasPrefix("/") || clean.hasPrefix("@") || clean.hasPrefix("#"), !clean.contains(" ") else { return [] }
    return values.filter { $0.label.lowercased().hasPrefix(clean) }
}

struct AssistantComposerSuggestionsView: View {
    @EnvironmentObject private var model: AppModel
    let suggestions: [AssistantComposerSuggestion]
    let select: (AssistantComposerSuggestion) -> Void

    var body: some View {
        if !suggestions.isEmpty {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 7) {
                    ForEach(suggestions) { suggestion in
                        Button { select(suggestion) } label: {
                            HStack(spacing: 7) {
                                Image(systemName: suggestion.icon)
                                    .foregroundStyle(AppPalette.primaryStrong)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(suggestion.label)
                                        .font(AppTypography.caption.weight(.semibold))
                                        .foregroundStyle(AppPalette.text)
                                    Text(model.uiText(suggestion.detail))
                                        .font(AppTypography.caption2)
                                        .foregroundStyle(AppPalette.textMuted)
                                }
                            }
                            .padding(.horizontal, 9)
                            .frame(height: 42)
                            .background(AppPalette.cardMuted.opacity(0.78))
                            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 14)
            }
            .padding(.top, 10)
            .accessibilityIdentifier("assistant-command-suggestions")
        }
    }
}

struct AssistantSecurityStatusBar: View {
    @EnvironmentObject private var model: AppModel
    let answer: AskResult
    let trace: [TraceItem]
    let startedAt: Date
    let endedAt: Date

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 13) { statusItems }
            VStack(alignment: .leading, spacing: 8) { statusItems }
        }
        .font(AppTypography.caption)
        .foregroundStyle(AppPalette.textMuted)
        .frame(maxWidth: 690, alignment: .leading)
        .accessibilityIdentifier("assistant-security-status")
    }

    @ViewBuilder
    private var statusItems: some View {
        HStack(spacing: 7) {
            Image(systemName: "checkmark.shield.fill")
                .foregroundStyle(AppPalette.success)
            Text(model.uiText("Security Agent"))
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.text)
        }
        Text(modelName)
            .font(AppTypography.caption.weight(.medium))
            .lineLimit(1)
        AssistantStatusMetric(icon: "wrench.and.screwdriver", value: model.uiText("%d 个工具", toolCount))
        if mcpCount > 0 {
            AssistantStatusMetric(icon: "point.3.connected.trianglepath.dotted", value: model.uiText("%d 个 MCP", mcpCount))
        }
        AssistantStatusMetric(icon: "clock", value: elapsedText)
        if answer.tokenUsage > 0 {
            AssistantStatusMetric(icon: "number", value: model.uiText("%d Tokens", answer.tokenUsage))
        }
        if knowledgeHits > 0 {
            AssistantStatusMetric(icon: "books.vertical", value: model.uiText("%d 个知识命中", knowledgeHits))
        }
    }

    private var modelName: String {
        let configured = model.llmConfig?.model.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return configured.isEmpty ? model.uiText("安全分析模型") : configured
    }

    private var toolCount: Int {
        trace.filter { $0.presentation?.kind == "tool_call" }.count
    }

    private var mcpCount: Int {
        trace.filter { item in
            item.node.localizedCaseInsensitiveContains("mcp")
                || (item.presentation?.toolName?.localizedCaseInsensitiveContains("mcp") ?? false)
        }.count
    }

    private var knowledgeHits: Int {
        answer.knowledgeGraph?.nodes.count ?? 0
    }

    private var elapsedText: String {
        String(format: "%.1fs", max(0, endedAt.timeIntervalSince(startedAt)))
    }
}

struct AssistantSecurityWorkingHeader: View {
    @EnvironmentObject private var model: AppModel
    let trace: [TraceItem]
    let startedAt: Date
    let currentDate: Date

    var body: some View {
        HStack(spacing: 10) {
            ProgressView()
                .controlSize(.small)
                .tint(AppPalette.primaryStrong)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.uiText("AI 正在分析"))
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Text(detail)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
                    .lineLimit(1)
            }
            Spacer(minLength: 10)
            Text(String(format: "%.1fs", max(0, currentDate.timeIntervalSince(startedAt))))
                .font(AppTypography.caption.monospacedDigit())
                .foregroundStyle(AppPalette.textSubtle)
        }
        .frame(maxWidth: 690, alignment: .leading)
        .accessibilityIdentifier("assistant-working-status")
    }

    private var detail: String {
        guard let latest = trace.last else { return model.uiText("正在启动安全分析流程") }
        return model.localizedMessage(latest.message) ?? latest.message
    }
}

private struct AssistantStatusMetric: View {
    let icon: String
    let value: String

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: icon)
            Text(value).lineLimit(1)
        }
    }
}

struct AssistantThinkingPanel: View {
    @EnvironmentObject private var model: AppModel
    let trace: [TraceItem]
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.18)) { isExpanded.toggle() }
            } label: {
                HStack(spacing: 9) {
                    Image(systemName: "brain.head.profile")
                        .foregroundStyle(AppPalette.primaryStrong)
                    Text(model.uiText("Thinking"))
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.text)
                    Text(model.uiText("高层任务"))
                        .font(AppTypography.caption2)
                        .foregroundStyle(AppPalette.textSubtle)
                    Spacer()
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(AppTypography.caption2.weight(.semibold))
                        .foregroundStyle(AppPalette.textSubtle)
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(highLevelTasks.enumerated()), id: \.offset) { _, task in
                        Label(task, systemImage: "checkmark")
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                    }
                }
                .padding(12)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .frame(maxWidth: 690, alignment: .leading)
        .background(AppPalette.card.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.82))
        }
        .accessibilityIdentifier("assistant-thinking-panel")
    }

    private var highLevelTasks: [String] {
        var seen = Set<String>()
        return trace.compactMap { item in
            let label = nodeLabel(item.node, language: model.appLanguage)
            guard seen.insert(label).inserted else { return nil }
            return label
        }
    }
}

struct AssistantSourcesPanel: View {
    @EnvironmentObject private var model: AppModel
    let answer: AskResult
    @State private var isExpanded = false

    var body: some View {
        if !sources.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                Button {
                    withAnimation(.easeInOut(duration: 0.18)) { isExpanded.toggle() }
                } label: {
                    HStack(spacing: 9) {
                        Image(systemName: "link")
                            .foregroundStyle(AppPalette.primaryStrong)
                        Text(model.uiText("Sources"))
                            .font(AppTypography.caption.weight(.semibold))
                            .foregroundStyle(AppPalette.text)
                        Text("\(sources.count)")
                            .font(AppTypography.caption2.weight(.semibold))
                            .foregroundStyle(AppPalette.textMuted)
                        Spacer()
                        Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                            .font(AppTypography.caption2.weight(.semibold))
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 40)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                if isExpanded {
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(sources) { source in
                            Link(destination: source.url) {
                                HStack(spacing: 9) {
                                    Image(systemName: source.status == "failed" ? "exclamationmark.circle" : "arrow.up.right.square")
                                        .foregroundStyle(source.status == "failed" ? AppPalette.warning : AppPalette.primaryStrong)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(source.name)
                                            .font(AppTypography.caption.weight(.semibold))
                                            .foregroundStyle(AppPalette.text)
                                        Text(source.count.map { model.uiText("%d 条结果", $0) } ?? source.detail)
                                            .font(AppTypography.caption2)
                                            .foregroundStyle(AppPalette.textMuted)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                }
                            }
                        }
                    }
                    .padding(12)
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }
            }
            .frame(maxWidth: 690, alignment: .leading)
            .background(AppPalette.card.opacity(0.72))
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.82))
            }
            .accessibilityIdentifier("assistant-sources-panel")
        }
    }

    private var sources: [AssistantDisplaySource] {
        var output: [AssistantDisplaySource] = answer.evidenceSources.compactMap(AssistantDisplaySource.init)
        for reference in answer.componentDetail?.vulnerabilities.flatMap(\.referenceLinks) ?? [] {
            guard let url = URL(string: reference.url),
                  ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
                  !output.contains(where: { $0.url == url })
            else { continue }
            output.append(
                AssistantDisplaySource(
                    id: reference.url,
                    name: reference.title,
                    url: url,
                    status: "success",
                    detail: reference.url
                )
            )
        }
        let text = [answer.summary, answer.vulnerabilityCard?["参考链接"] ?? ""].joined(separator: "\n")
        for rawURL in assistantURLs(in: text) {
            guard let url = URL(string: rawURL), !output.contains(where: { $0.url == url }) else { continue }
            output.append(
                AssistantDisplaySource(
                    id: rawURL,
                    name: url.host ?? model.uiText("参考来源"),
                    url: url,
                    status: "success",
                    detail: rawURL
                )
            )
        }
        return output
    }
}

private struct AssistantDisplaySource: Identifiable {
    let id: String
    let name: String
    let url: URL
    let status: String
    let detail: String
    let count: Int?

    init?(source: AssistantEvidenceSource) {
        let metadata: (String, String)
        switch source.id {
        case "nvd": metadata = ("NVD", "https://nvd.nist.gov/vuln/search")
        case "github_advisory": metadata = ("GitHub Advisory", "https://github.com/advisories")
        case "osv": metadata = ("OSV", "https://osv.dev")
        default: return nil
        }
        guard let url = URL(string: metadata.1) else { return nil }
        id = source.id
        name = metadata.0
        self.url = url
        status = source.status
        detail = source.status.capitalized
        count = source.status == "success" ? source.count : nil
    }

    init(id: String, name: String, url: URL, status: String, detail: String) {
        self.id = id
        self.name = name
        self.url = url
        self.status = status
        self.detail = detail
        count = nil
    }
}

private func assistantURLs(in text: String) -> [String] {
    guard let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) else { return [] }
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    var seen = Set<String>()
    return detector.matches(in: text, options: [], range: range).compactMap { result in
        guard let url = result.url,
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              seen.insert(url.absoluteString).inserted
        else { return nil }
        return url.absoluteString
    }
}

struct AssistantResponseSkeleton: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            SkeletonLine(width: 210)
            SkeletonLine(width: 610)
            SkeletonLine(width: 530)
            SkeletonLine(width: 360)
        }
        .padding(18)
        .frame(maxWidth: 690, minHeight: 132, alignment: .leading)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.9))
        }
        .accessibilityIdentifier("assistant-response-skeleton")
    }
}

private struct SkeletonLine: View {
    let width: CGFloat

    var body: some View {
        TimelineView(.animation(minimumInterval: 0.2)) { context in
            let phase = context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.6) / 1.6
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .fill(AppPalette.cardMuted)
                .overlay(AppPalette.primary.opacity(0.035 + 0.055 * phase))
                .frame(maxWidth: width, minHeight: 11, maxHeight: 11)
        }
    }
}

struct AssistantMarkdownView: View {
    let blocks: [AssistantMarkdownBlock]

    init(markdown: String) {
        blocks = AssistantMarkdownBlock.parse(markdown)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            ForEach(Array(blocks.enumerated()), id: \.offset) { _, block in
                switch block {
                case let .line(value): AssistantMarkdownLine(value: value)
                case let .quote(value): AssistantMarkdownQuote(value: value)
                case .rule: Divider()
                case let .table(headers, rows): AssistantMarkdownTable(headers: headers, rows: rows)
                case let .code(language, content): AssistantCodeBlock(language: language, content: content)
                case let .image(alt, url): AssistantMarkdownImage(alt: alt, url: url)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .textSelection(.enabled)
    }
}

enum AssistantMarkdownBlock: Equatable {
    case line(String)
    case quote(String)
    case rule
    case table(headers: [String], rows: [[String]])
    case code(language: String, content: String)
    case image(alt: String, url: String)

    static func parse(_ markdown: String) -> [AssistantMarkdownBlock] {
        var blocks: [AssistantMarkdownBlock] = []
        var codeLanguage = ""
        var codeLines: [String] = []
        var inCode = false
        var tableRows: [[String]] = []

        func flushTable() {
            guard !tableRows.isEmpty else { return }
            blocks.append(.table(headers: tableRows[0], rows: Array(tableRows.dropFirst())))
            tableRows = []
        }

        for line in markdown.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("```") {
                flushTable()
                if inCode {
                    blocks.append(.code(language: codeLanguage, content: codeLines.joined(separator: "\n")))
                    codeLanguage = ""
                    codeLines = []
                } else {
                    codeLanguage = String(trimmed.dropFirst(3)).trimmingCharacters(in: .whitespaces)
                }
                inCode.toggle()
                continue
            }
            if inCode {
                codeLines.append(line)
                continue
            }
            if trimmed.hasPrefix("|"), trimmed.hasSuffix("|") {
                let cells = assistantTableCells(trimmed)
                let separator = !cells.isEmpty && cells.allSatisfy { cell in
                    !cell.isEmpty && cell.allSatisfy { $0 == "-" || $0 == ":" || $0.isWhitespace }
                }
                if !separator { tableRows.append(cells) }
                continue
            }
            flushTable()
            if trimmed == "---" {
                blocks.append(.rule)
            } else if trimmed.hasPrefix("> ") {
                blocks.append(.quote(String(trimmed.dropFirst(2))))
            } else if let image = assistantMarkdownImage(trimmed) {
                blocks.append(.image(alt: image.0, url: image.1))
            } else if !trimmed.isEmpty {
                blocks.append(.line(line))
            }
        }
        flushTable()
        if inCode, !codeLines.isEmpty {
            blocks.append(.code(language: codeLanguage, content: codeLines.joined(separator: "\n")))
        }
        return blocks
    }
}

private struct AssistantMarkdownLine: View {
    let value: String
    private var trimmed: String { value.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        if let heading = headingValue {
            Text(inlineMarkdown(heading.text))
                .font(heading.font)
                .foregroundStyle(AppPalette.text)
                .padding(.top, heading.level == 1 ? 2 : 0)
        } else if let item = listItem {
            HStack(alignment: .top, spacing: 8) {
                Text(item.marker)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.primaryStrong)
                    .frame(minWidth: 12, alignment: .trailing)
                Text(inlineMarkdown(item.text))
                    .font(AppTypography.callout)
                    .foregroundStyle(AppPalette.text)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else {
            Text(inlineMarkdown(trimmed))
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.text)
                .lineSpacing(4)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var headingValue: (level: Int, text: String, font: Font)? {
        let count = trimmed.prefix(while: { $0 == "#" }).count
        guard (1...4).contains(count), trimmed.dropFirst(count).first == " " else { return nil }
        let text = String(trimmed.dropFirst(count + 1))
        let font: Font = count == 1 ? .title3.weight(.semibold) : (count == 2 ? .headline : .callout.weight(.semibold))
        return (count, text, font)
    }

    private var listItem: (marker: String, text: String)? {
        if trimmed.hasPrefix("- ") || trimmed.hasPrefix("* ") {
            return ("•", String(trimmed.dropFirst(2)))
        }
        guard let dot = trimmed.firstIndex(of: "."), dot != trimmed.startIndex else { return nil }
        let number = trimmed[..<dot]
        guard number.allSatisfy(\.isNumber) else { return nil }
        let after = trimmed.index(after: dot)
        guard after < trimmed.endIndex, trimmed[after] == " " else { return nil }
        return (String(number) + ".", String(trimmed[trimmed.index(after: after)...]))
    }
}

private struct AssistantMarkdownQuote: View {
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 2).fill(AppPalette.primaryStrong).frame(width: 3)
            Text(inlineMarkdown(value))
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.textMuted)
                .lineSpacing(3)
        }
        .padding(.vertical, 7)
        .padding(.horizontal, 10)
        .background(AppPalette.primary.opacity(0.055))
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
    }
}

private struct AssistantMarkdownTable: View {
    let headers: [String]
    let rows: [[String]]

    var body: some View {
        ScrollView(.horizontal, showsIndicators: true) {
            VStack(spacing: 0) {
                row(headers, header: true)
                ForEach(Array(rows.enumerated()), id: \.offset) { _, values in
                    Divider()
                    row(values, header: false)
                }
            }
            .frame(minWidth: 620)
        }
        .background(AppPalette.cardMuted.opacity(0.45))
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 6, style: .continuous).stroke(AppPalette.border)
        }
    }

    private func row(_ values: [String], header: Bool) -> some View {
        let count = max(headers.count, values.count)
        return HStack(alignment: .top, spacing: 0) {
            ForEach(0..<count, id: \.self) { index in
                Text(inlineMarkdown(index < values.count ? values[index] : ""))
                    .font(header ? .caption.weight(.semibold) : .caption)
                    .foregroundStyle(header ? AppPalette.text : AppPalette.textMuted)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .frame(width: max(120, 620 / CGFloat(max(1, count))), alignment: .leading)
                    .background(header ? AppPalette.cardMuted : Color.clear)
            }
        }
    }
}

private struct AssistantCodeBlock: View {
    @EnvironmentObject private var model: AppModel
    let language: String
    let content: String
    @State private var copied = false

    var body: some View {
        if language.lowercased() == "mermaid", let flow = AssistantMermaidFlow(content: content) {
            AssistantMermaidView(flow: flow)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text(language.isEmpty ? model.uiText("代码") : language)
                        .font(AppTypography.caption2.monospaced().weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                    Spacer()
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(content, forType: .string)
                        copied = true
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                            .font(AppTypography.caption)
                            .foregroundStyle(copied ? AppPalette.success : AppPalette.textMuted)
                            .frame(width: 24, height: 24)
                    }
                    .buttonStyle(.plain)
                    .help(model.uiText(copied ? "已复制" : "复制代码"))
                }
                .padding(.horizontal, 10)
                .frame(height: 34)
                .background(AppPalette.cardMuted)
                Divider()
                ScrollView(.horizontal, showsIndicators: true) {
                    Text(content)
                        .font(AppTypography.caption.monospaced())
                        .foregroundStyle(AppPalette.text)
                        .lineSpacing(3)
                        .padding(12)
                        .frame(minWidth: 610, alignment: .leading)
                }
            }
            .background(AppPalette.cardMuted)
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous).stroke(AppPalette.border)
            }
        }
    }
}

private struct AssistantMermaidFlow {
    let nodes: [String]

    init?(content: String) {
        var output: [String] = []
        for line in content.components(separatedBy: .newlines) where line.contains("-->") {
            for token in line.components(separatedBy: "-->") {
                let label = assistantMermaidLabel(token)
                if !label.isEmpty, output.last != label { output.append(label) }
            }
        }
        guard output.count >= 2 else { return nil }
        nodes = output
    }
}

private struct AssistantMermaidView: View {
    @EnvironmentObject private var model: AppModel
    let flow: AssistantMermaidFlow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(model.uiText("流程图"), systemImage: "point.3.connected.trianglepath.dotted")
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
            VStack(spacing: 7) {
                ForEach(Array(flow.nodes.enumerated()), id: \.offset) { index, node in
                    Text(node)
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.text)
                        .padding(.horizontal, 12)
                        .frame(minHeight: 34)
                        .frame(maxWidth: .infinity)
                        .background(index == flow.nodes.count - 1 ? AppPalette.success.opacity(0.09) : AppPalette.primary.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    if index < flow.nodes.count - 1 {
                        Image(systemName: "arrow.down")
                            .font(AppTypography.caption.weight(.semibold))
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                }
            }
        }
        .padding(12)
        .background(AppPalette.cardMuted.opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 7, style: .continuous).stroke(AppPalette.border)
        }
    }
}

private struct AssistantMarkdownImage: View {
    let alt: String
    let url: String

    var body: some View {
        if let remoteURL = URL(string: url) {
            AsyncImage(url: remoteURL) { phase in
                switch phase {
                case let .success(image): image.resizable().scaledToFit()
                case .failure: Label(alt, systemImage: "photo.badge.exclamationmark")
                default: ProgressView().controlSize(.small)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 80, maxHeight: 300)
            .accessibilityLabel(alt)
        }
    }
}

private func inlineMarkdown(_ value: String) -> AttributedString {
    (try? AttributedString(
        markdown: value,
        options: AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
    )) ?? AttributedString(value)
}

private func assistantTableCells(_ value: String) -> [String] {
    value.dropFirst().dropLast().split(separator: "|", omittingEmptySubsequences: false).map {
        $0.trimmingCharacters(in: .whitespaces)
    }
}

private func assistantMarkdownImage(_ value: String) -> (String, String)? {
    guard value.hasPrefix("!["), let close = value.firstIndex(of: "]") else { return nil }
    let afterClose = value.index(after: close)
    guard afterClose < value.endIndex, value[afterClose] == "(" , value.hasSuffix(")") else { return nil }
    let alt = String(value[value.index(value.startIndex, offsetBy: 2)..<close])
    let urlStart = value.index(after: afterClose)
    return (alt, String(value[urlStart..<value.index(before: value.endIndex)]))
}

private func assistantMermaidLabel(_ raw: String) -> String {
    var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if value.lowercased().hasPrefix("flowchart") || value.lowercased().hasPrefix("graph ") { return "" }
    if let open = value.firstIndex(where: { $0 == "[" || $0 == "{" || $0 == "(" }),
       let close = value.lastIndex(where: { $0 == "]" || $0 == "}" || $0 == ")" }),
       open < close {
        value = String(value[value.index(after: open)..<close])
    }
    return value.trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
}

enum AssistantMessageExportFormat: String, CaseIterable, Identifiable {
    case markdown
    case pdf
    case word

    var id: String { rawValue }

    var label: String {
        switch self {
        case .markdown: "Markdown"
        case .pdf: "PDF"
        case .word: "Word"
        }
    }

    var fileExtension: String {
        switch self {
        case .markdown: "md"
        case .pdf: "pdf"
        case .word: "doc"
        }
    }
}

@MainActor
func exportAssistantMessage(
    _ text: String,
    format: AssistantMessageExportFormat,
    title: String = "导出回答"
) throws {
    let panel = NSSavePanel()
    panel.title = title
    panel.nameFieldStringValue = "secflow-answer.\(format.fileExtension)"
    panel.canCreateDirectories = true
    if let type = UTType(filenameExtension: format.fileExtension) {
        panel.allowedContentTypes = [type]
    }
    guard panel.runModal() == .OK, let url = panel.url else { return }

    switch format {
    case .markdown:
        try Data(text.utf8).write(to: url, options: .atomic)
    case .pdf:
        let view = assistantExportTextView(text)
        try view.dataWithPDF(inside: view.bounds).write(to: url, options: .atomic)
    case .word:
        let attributed = NSAttributedString(string: text, attributes: [
            .font: NSFont.systemFont(ofSize: 12),
            .foregroundColor: NSColor.labelColor,
        ])
        let data = try attributed.data(
            from: NSRange(location: 0, length: attributed.length),
            documentAttributes: [.documentType: NSAttributedString.DocumentType(rawValue: "NSDocFormatTextDocumentType")]
        )
        try data.write(to: url, options: .atomic)
    }
}

@MainActor
func shareAssistantMessage(_ text: String) {
    guard let view = NSApp.keyWindow?.contentView else { return }
    NSSharingServicePicker(items: [text]).show(
        relativeTo: NSRect(x: view.bounds.midX, y: view.bounds.midY, width: 1, height: 1),
        of: view,
        preferredEdge: .minY
    )
}

enum AssistantMessageBookmarkStore {
    private static let key = "secflow.assistant.bookmarked-message-ids"

    static func identifier(for text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func contains(_ text: String) -> Bool {
        Set(UserDefaults.standard.stringArray(forKey: key) ?? []).contains(identifier(for: text))
    }

    static func set(_ bookmarked: Bool, text: String) {
        var values = Set(UserDefaults.standard.stringArray(forKey: key) ?? [])
        let id = identifier(for: text)
        if bookmarked { values.insert(id) } else { values.remove(id) }
        UserDefaults.standard.set(values.sorted(), forKey: key)
    }
}

@MainActor
private func assistantExportTextView(_ text: String) -> NSTextView {
    let width: CGFloat = 612
    let storage = NSTextStorage(attributedString: NSAttributedString(string: text, attributes: [
        .font: NSFont.systemFont(ofSize: 12),
        .foregroundColor: NSColor.labelColor,
    ]))
    let layout = NSLayoutManager()
    let container = NSTextContainer(containerSize: NSSize(width: width - 72, height: .greatestFiniteMagnitude))
    container.widthTracksTextView = true
    layout.addTextContainer(container)
    storage.addLayoutManager(layout)
    layout.ensureLayout(for: container)
    let height = max(792, layout.usedRect(for: container).height + 72)
    let view = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: height), textContainer: container)
    view.textContainerInset = NSSize(width: 36, height: 36)
    view.drawsBackground = true
    view.backgroundColor = .white
    return view
}
