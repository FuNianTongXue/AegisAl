import AppKit
import SwiftUI

struct ReportsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var isSelecting = false
    @State private var selectedReportIDs: Set<String> = []
    @State private var isShowingDeleteConfirmation = false
    @State private var pendingDownloadInterrupt: ReportInterruptEnvelope?
    @State private var pendingDownloadFormat: ReportDownloadFormat?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(model.uiText("报告中心"), subtitle: model.uiText("上传项目清单与代码后，系统会分别展示依赖漏洞，以及 AST/CFG/DFG 路径中的具体漏洞位置和修复代码。")) {
                Button {
                    Task { await model.loadReports() }
                } label: {
                    Label(model.uiText("刷新"), systemImage: "arrow.clockwise")
                }
                .buttonStyle(SecondaryActionButtonStyle())
            }

            HStack(alignment: .top, spacing: 18) {
                reportList
                    .frame(width: 320)

                reportDetail
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(28)
        .background(AppPalette.page)
        .task {
            if model.reports.isEmpty {
                await model.loadReports()
            }
        }
        .alert(model.uiText("删除选中的 %d 份报告？", selectedReportIDs.count), isPresented: $isShowingDeleteConfirmation) {
            Button(model.uiText("取消"), role: .cancel) {}
            Button(model.uiText("删除"), role: .destructive) {
                let reportIDs = selectedReportIDs
                Task {
                    let deleted = await model.deleteReports(ids: reportIDs)
                    if deleted > 0 {
                        selectedReportIDs.removeAll()
                        isSelecting = false
                    }
                }
            }
        } message: {
            Text(model.uiText("报告文件和对应记录会被永久删除，此操作无法撤销。"))
        }
        .alert(
            pendingDownloadInterrupt?.question ?? model.uiText("确认下载报告？"),
            isPresented: Binding(
                get: { pendingDownloadInterrupt != nil },
                set: { if !$0 { pendingDownloadInterrupt = nil } }
            )
        ) {
            Button(model.uiText("取消"), role: .cancel) {
                resumePendingDownload(confirm: false)
            }
            Button(model.uiText("确认下载")) {
                resumePendingDownload(confirm: true)
            }
        } message: {
            Text(pendingDownloadInterrupt?.detail ?? model.uiText("确认后才会准备本次下载制品。"))
        }
    }

    private var reportList: some View {
        Panel {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text(model.uiText("分析报告"))
                        .font(AppTypography.headline)
                    Spacer()
                    if isSelecting {
                        Button(selectedReportIDs.count == model.reports.count ? model.uiText("取消全选") : model.uiText("全选")) {
                            if selectedReportIDs.count == model.reports.count {
                                selectedReportIDs.removeAll()
                            } else {
                                selectedReportIDs = Set(model.reports.map(\.id))
                            }
                        }
                        .buttonStyle(.plain)

                        Button(model.uiText("取消")) {
                            selectedReportIDs.removeAll()
                            isSelecting = false
                        }
                        .buttonStyle(.plain)

                        Button {
                            isShowingDeleteConfirmation = true
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(selectedReportIDs.isEmpty ? AppPalette.textSubtle : Color.red)
                        .disabled(selectedReportIDs.isEmpty || model.busyActions.contains("delete-reports"))
                        .help(model.uiText("删除选中的报告"))
                    } else {
                        Button {
                            requestAllReportsDownload()
                        } label: {
                            Image(systemName: "arrow.down.square.stack")
                        }
                        .buttonStyle(.plain)
                        .disabled(model.reports.isEmpty || model.busyActions.contains("report-action-start"))
                        .help(model.uiText("下载所有报告"))
                        Button(model.uiText("选择")) {
                            isSelecting = true
                            selectedReportIDs.removeAll()
                        }
                        .buttonStyle(.plain)
                        .disabled(model.reports.isEmpty)
                    }
                    StatusBadge(text: "\(model.reports.count)", tone: .info)
                }

                if model.reports.isEmpty {
                    ContentUnavailableView(model.uiText("暂无分析报告"), systemImage: "doc.text.magnifyingglass")
                        .frame(maxWidth: .infinity, minHeight: 260)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 10) {
                            ForEach(model.reports) { report in
                                Button {
                                    if isSelecting {
                                        toggleSelection(report.id)
                                    } else {
                                        Task { await model.openReport(report) }
                                    }
                                } label: {
                                    ReportRow(
                                        report: report,
                                        isSelected: isSelecting ? selectedReportIDs.contains(report.id) : model.selectedReport?.id == report.id,
                                        isSelectionMode: isSelecting,
                                        isMarked: selectedReportIDs.contains(report.id)
                                    )
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var reportDetail: some View {
        if let report = model.selectedReport {
            Panel {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(report.title)
                                .font(AppTypography.title3.weight(.semibold))
                                .foregroundStyle(AppPalette.text)
                            Text("\(report.fileName) · \(report.createdAt)")
                                .font(AppTypography.caption)
                                .foregroundStyle(AppPalette.textMuted)
                        }
                        Spacer()
                        Menu {
                            ForEach(report.downloadFormats) { format in
                                Button {
                                    requestDownload(report, format: format)
                                } label: {
                                    Label(format.downloadLabel(using: model), systemImage: format.systemImage)
                                }
                            }
                            Divider()
                            Button {
                                requestDownload(report, allFormats: true)
                            } label: {
                                Label(model.uiText("下载全部格式"), systemImage: "archivebox")
                            }
                        } label: {
                            Label(model.uiText("下载报告"), systemImage: "arrow.down.doc")
                        }
                        .buttonStyle(PrimaryActionButtonStyle())
                        .disabled(model.busyActions.contains("download-report:\(report.id)"))
                        Button {
                            copy(report.content)
                            model.statusMessage = model.uiText("报告 Markdown 已复制")
                        } label: {
                            Label(model.uiText("复制 Markdown"), systemImage: "doc.on.doc")
                        }
                        .buttonStyle(SecondaryActionButtonStyle())
                    }

                    HStack(spacing: 8) {
                        StatusBadge(text: model.uiText("依赖漏洞 %d", report.vulnerabilityCount), tone: report.vulnerabilityCount > 0 ? .warning : .neutral)
                        StatusBadge(text: model.uiText("代码漏洞 %d", report.findingCount), tone: report.findingCount > 0 ? .info : .neutral)
                        ForEach(report.downloadFormats) { format in
                            StatusBadge(text: format.label, tone: .good)
                        }
                    }

                    Divider()

                    MarkdownReportBody(
                        content: report.content,
                        mcpAudit: report.metadata?.reportMcp,
                        mcpAudits: report.metadata?.reportMcps ?? [],
                        reportCharts: report.metadata?.reportCharts
                    )
                        .id(report.id)
                }
            }
        } else {
            Panel {
                ContentUnavailableView(model.uiText("请选择报告"), systemImage: "doc.richtext")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    private func copy(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    private func requestDownload(
        _ report: AnalysisReportDetail,
        format: ReportDownloadFormat? = nil,
        allFormats: Bool = false
    ) {
        Task { @MainActor in
            let formats = allFormats ? ReportDownloadFormat.allCases : [format ?? .pdf]
            guard let result = await model.startReportDownload(
                reportIDs: [report.id],
                formats: formats,
                allFormats: allFormats
            ), let interrupt = result.interrupt else { return }
            pendingDownloadFormat = allFormats ? nil : format
            pendingDownloadInterrupt = interrupt
        }
    }

    private func requestAllReportsDownload() {
        Task { @MainActor in
            guard let result = await model.startReportDownload(
                reportIDs: model.reports.map(\.id),
                formats: ReportDownloadFormat.allCases,
                allReports: true
            ), let interrupt = result.interrupt else { return }
            pendingDownloadFormat = nil
            pendingDownloadInterrupt = interrupt
        }
    }

    private func resumePendingDownload(confirm: Bool) {
        guard let interrupt = pendingDownloadInterrupt else { return }
        let format = pendingDownloadFormat
        pendingDownloadInterrupt = nil
        pendingDownloadFormat = nil
        Task { @MainActor in
            guard let answer = await model.resumeReportInterrupt(interrupt, confirm: confirm, format: format),
                  confirm,
                  let artifact = answer.artifacts.first
            else { return }
            saveArtifact(artifact)
        }
    }

    private func saveArtifact(_ artifact: AssistantArtifact) {
        let panel = NSSavePanel()
        panel.title = model.uiText("下载分析报告")
        panel.nameFieldStringValue = artifact.fileName
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        Task { await model.downloadAssistantArtifact(artifact, to: destination) }
    }

    private func toggleSelection(_ reportID: String) {
        if selectedReportIDs.contains(reportID) {
            selectedReportIDs.remove(reportID)
        } else {
            selectedReportIDs.insert(reportID)
        }
    }
}

private extension AnalysisReportDetail {
    var downloadFormats: [ReportDownloadFormat] {
        guard let availableFormats, !availableFormats.isEmpty else {
            return ReportDownloadFormat.allCases
        }
        let values = Set(availableFormats.map { $0.lowercased() })
        return ReportDownloadFormat.allCases.filter { values.contains($0.rawValue) }
    }

    func downloadFileName(for format: ReportDownloadFormat) -> String {
        let url = URL(fileURLWithPath: fileName)
        let stem = url.deletingPathExtension().lastPathComponent.isEmpty ? id : url.deletingPathExtension().lastPathComponent
        return "\(stem).\(format.fileExtension)"
    }
}

private extension ReportDownloadFormat {
    var systemImage: String {
        switch self {
        case .markdown: "doc.text"
        case .html: "globe"
        case .word: "doc.text.fill"
        case .pdf: "doc.richtext"
        }
    }

    @MainActor
    func downloadLabel(using model: AppModel) -> String {
        switch self {
        case .markdown: model.uiText("下载 Markdown")
        case .html: model.uiText("下载 HTML")
        case .word: model.uiText("下载 Word")
        case .pdf: model.uiText("下载 PDF")
        }
    }
}

private struct ReportRow: View {
    @EnvironmentObject private var model: AppModel
    let report: AnalysisReportSummary
    let isSelected: Bool
    let isSelectionMode: Bool
    let isMarked: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                Image(systemName: isSelectionMode ? (isMarked ? "checkmark.circle.fill" : "circle") : "doc.text.magnifyingglass")
                    .foregroundStyle(AppPalette.primary)
                    .frame(width: 20)
                VStack(alignment: .leading, spacing: 3) {
                    Text(report.title)
                        .font(AppTypography.callout.weight(.semibold))
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(2)
                    Text(report.createdAt)
                        .font(AppTypography.caption2.monospacedDigit())
                        .foregroundStyle(AppPalette.textSubtle)
                }
                Spacer()
            }

            HStack(spacing: 6) {
                StatusBadge(text: model.uiText("依赖漏洞 %d", report.vulnerabilityCount), tone: report.vulnerabilityCount > 0 ? .warning : .neutral)
                StatusBadge(text: model.uiText("代码漏洞 %d", report.findingCount), tone: report.findingCount > 0 ? .info : .neutral)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(isSelected ? AppPalette.selectedStrong : AppPalette.cardMuted.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(isSelected ? AppPalette.primary.opacity(0.55) : AppPalette.border.opacity(0.65))
        }
    }
}

struct ReportMarkdownDocument: Equatable {
    let title: String
    let overview: String
    let sections: [ReportMarkdownSection]

    init(markdown: String, language: AppLanguage = .zhHans) {
        var documentTitle = localizedUI("分析报告", language: language)
        var overviewLines: [String] = []
        var sections: [ReportMarkdownSection] = []
        var sectionTitle: String?
        var sectionLines: [String] = []
        var entries: [ReportMarkdownEntry] = []
        var entryTitle: String?
        var entryLines: [String] = []
        var isInsideCodeFence = false

        func flushEntry() {
            guard let currentTitle = entryTitle else { return }
            entries.append(
                ReportMarkdownEntry(
                    id: "entry-\(sections.count)-\(entries.count)",
                    title: cleanReportHeading(currentTitle),
                    content: joinedReportLines(entryLines)
                )
            )
            entryTitle = nil
            entryLines = []
        }

        func flushSection() {
            flushEntry()
            guard let currentTitle = sectionTitle else { return }
            sections.append(
                ReportMarkdownSection(
                    id: "section-\(sections.count)",
                    title: cleanReportHeading(currentTitle),
                    content: joinedReportLines(sectionLines),
                    entries: entries
                )
            )
            sectionTitle = nil
            sectionLines = []
            entries = []
        }

        for line in markdown.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let isFence = trimmed.hasPrefix("```")

            if !isInsideCodeFence, trimmed.hasPrefix("### ") {
                flushEntry()
                entryTitle = String(trimmed.dropFirst(4))
                continue
            }
            if !isInsideCodeFence, trimmed.hasPrefix("## ") {
                flushSection()
                sectionTitle = String(trimmed.dropFirst(3))
                continue
            }
            if !isInsideCodeFence, trimmed.hasPrefix("# "), sectionTitle == nil {
                documentTitle = cleanReportHeading(String(trimmed.dropFirst(2)))
                continue
            }

            if entryTitle != nil {
                entryLines.append(line)
            } else if sectionTitle != nil {
                sectionLines.append(line)
            } else {
                overviewLines.append(line)
            }

            if isFence {
                isInsideCodeFence.toggle()
            }
        }
        flushSection()

        title = documentTitle
        overview = joinedReportLines(overviewLines)
        self.sections = sections
    }
}

struct ReportMarkdownSection: Equatable, Identifiable {
    let id: String
    let title: String
    let content: String
    let entries: [ReportMarkdownEntry]

    func preview(language: AppLanguage) -> String {
        if !content.isEmpty {
            return reportPreview(content)
        }
        let entryTitles = entries.prefix(3).map(\.title).joined(separator: "、")
        return entryTitles.isEmpty ? localizedUI("点击查看详细内容", language: language) : entryTitles
    }
}

struct ReportMarkdownEntry: Equatable, Identifiable {
    let id: String
    let title: String
    let content: String

    var preview: String { reportPreview(content) }
}

enum ReportMarkdownBlock: Equatable {
    case line(String)
    case quote(String)
    case rule
    case table(headers: [String], rows: [[String]])
    case code(language: String, content: String)

    static func parse(_ markdown: String) -> [ReportMarkdownBlock] {
        var blocks: [ReportMarkdownBlock] = []
        var codeLanguage = ""
        var codeLines: [String] = []
        var isInsideCodeFence = false
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
                if isInsideCodeFence {
                    blocks.append(.code(language: codeLanguage, content: codeLines.joined(separator: "\n")))
                    codeLanguage = ""
                    codeLines = []
                } else {
                    codeLanguage = String(trimmed.dropFirst(3)).trimmingCharacters(in: .whitespaces)
                }
                isInsideCodeFence.toggle()
                continue
            }

            if isInsideCodeFence {
                codeLines.append(line)
                continue
            }
            if trimmed.hasPrefix("<!-- secflow-report-style:") {
                continue
            }
            if trimmed.hasPrefix("|"), trimmed.hasSuffix("|") {
                let cells = parseReportTableRow(trimmed)
                let isSeparator = !cells.isEmpty && cells.allSatisfy { cell in
                    !cell.isEmpty && cell.allSatisfy { $0 == "-" || $0 == ":" || $0.isWhitespace }
                }
                if !isSeparator {
                    tableRows.append(cells)
                }
                continue
            }
            flushTable()
            if trimmed == "---" {
                blocks.append(.rule)
            } else if trimmed.hasPrefix("> ") {
                blocks.append(.quote(String(trimmed.dropFirst(2))))
            } else if !trimmed.isEmpty {
                blocks.append(.line(line))
            }
        }

        flushTable()
        if isInsideCodeFence, !codeLines.isEmpty {
            blocks.append(.code(language: codeLanguage, content: codeLines.joined(separator: "\n")))
        }
        return blocks
    }
}

struct MarkdownReportBody: View {
    @EnvironmentObject private var model: AppModel
    let content: String
    let mcpAudit: ReportMCPAudit?
    let mcpAudits: [ReportMCPAudit]
    let reportCharts: ScanReportCharts?
    @State private var expandedSectionIDs: Set<String> = []
    @State private var expandedEntryIDs: Set<String> = []

    init(
        content: String,
        mcpAudit: ReportMCPAudit? = nil,
        mcpAudits: [ReportMCPAudit] = [],
        reportCharts: ScanReportCharts? = nil
    ) {
        self.content = content
        self.mcpAudit = mcpAudit
        self.mcpAudits = mcpAudits
        self.reportCharts = reportCharts
    }

    var body: some View {
        let document = ReportMarkdownDocument(markdown: content, language: model.appLanguage)
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 12) {
                let visibleAudits = mcpAudits.isEmpty ? mcpAudit.map { [$0] } ?? [] : mcpAudits
                ForEach(Array(visibleAudits.enumerated()), id: \.offset) { _, audit in
                    ReportMCPAuditCard(audit: audit)
                }

                if let reportCharts, reportCharts.chartData.hasContent {
                    DependencyChartsView(chartData: reportCharts.chartData, presentation: .scanReport)
                }

                if !document.overview.isEmpty {
                    ReportOverviewCard(title: document.title, content: document.overview)
                }

                ForEach(document.sections) { section in
                    ReportSectionCard(
                        section: section,
                        isExpanded: expansionBinding(for: section.id, in: $expandedSectionIDs),
                        expandedEntryIDs: $expandedEntryIDs
                    )
                }
            }
            .padding(.trailing, 8)
            .padding(.bottom, 4)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            guard expandedSectionIDs.isEmpty, expandedEntryIDs.isEmpty else { return }
            for section in document.sections where isCodeEvidenceSection(section.title) {
                expandedSectionIDs.insert(section.id)
                if let firstEntry = section.entries.first {
                    expandedEntryIDs.insert("\(section.id)-\(firstEntry.id)")
                }
            }
        }
    }

    private func isCodeEvidenceSection(_ title: String) -> Bool {
        title.contains("代码风险")
            || title.contains("代码漏洞")
            || title.localizedCaseInsensitiveContains("code finding")
            || title.contains("コード脆弱性")
            || title.contains("코드 취약점")
    }
}

private struct ReportMCPAuditCard: View {
    @EnvironmentObject private var model: AppModel
    let audit: ReportMCPAudit

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: audit.isCompleted ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .font(AppTypography.title3)
                .foregroundStyle(audit.isCompleted ? AppPalette.success : AppPalette.warning)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(model.uiText("MCP 报告工具"))
                        .font(AppTypography.headline)
                        .foregroundStyle(AppPalette.text)
                    StatusBadge(
                        text: model.uiText(audit.isCompleted ? "已调用" : "调用失败"),
                        tone: audit.isCompleted ? .good : .warning
                    )
                }
                Text("\(audit.server) / \(audit.tool)")
                    .font(AppTypography.callout.monospaced())
                    .foregroundStyle(AppPalette.textMuted)
                    .textSelection(.enabled)
                Text(auditSummary)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textSubtle)
                if let digest = audit.outputSha256, !digest.isEmpty {
                    Text("SHA-256 \(digest)")
                        .font(AppTypography.caption2.monospaced())
                        .foregroundStyle(AppPalette.textSubtle)
                        .lineLimit(1)
                        .textSelection(.enabled)
                }
                if let error = audit.error, !error.isEmpty {
                    Text(error)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.warning)
                        .textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.cardMuted.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke((audit.isCompleted ? AppPalette.success : AppPalette.warning).opacity(0.32))
        }
    }

    private var auditSummary: String {
        if let size = audit.artifactSize, let mediaType = audit.mediaType, !mediaType.isEmpty {
            return "\(mediaType) · \(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)) · \(audit.invokedAt)"
        }
        return model.uiText("处理事实 %d 条 · %@", audit.factCount ?? 0, audit.invokedAt)
    }
}

private struct ReportOverviewCard: View {
    @EnvironmentObject private var model: AppModel
    let title: String
    let content: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ReportCardTitle(
                title: model.uiText("报告概览"),
                preview: title,
                icon: "doc.text.magnifyingglass",
                accent: AppPalette.primary,
                accessory: nil,
                isExpanded: nil
            )
            Divider()
            ReportMarkdownContent(markdown: content)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.cardMuted.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.82))
        }
    }
}

private struct ReportSectionCard: View {
    @EnvironmentObject private var model: AppModel
    let section: ReportMarkdownSection
    @Binding var isExpanded: Bool
    @Binding var expandedEntryIDs: Set<String>

    private var style: ReportSectionStyle { ReportSectionStyle(title: section.title) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                    isExpanded.toggle()
                }
            } label: {
                ReportCardTitle(
                    title: section.title,
                    preview: section.preview(language: model.appLanguage),
                    icon: style.icon,
                    accent: style.accent,
                    accessory: section.entries.isEmpty ? nil : model.uiText("%d 项", section.entries.count),
                    isExpanded: isExpanded
                )
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                Divider()
                    .padding(.vertical, 12)

                VStack(alignment: .leading, spacing: 10) {
                    if !section.content.isEmpty {
                        ReportMarkdownContent(markdown: section.content)
                    }

                    ForEach(section.entries) { entry in
                        ReportEntryCard(
                            entry: entry,
                            accent: style.accent,
                            isExpanded: expansionBinding(for: "\(section.id)-\(entry.id)", in: $expandedEntryIDs)
                        )
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(isExpanded ? AppPalette.card.opacity(0.92) : AppPalette.cardMuted.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(isExpanded ? style.accent.opacity(0.32) : AppPalette.border.opacity(0.82))
        }
    }
}

private struct ReportEntryCard: View {
    let entry: ReportMarkdownEntry
    let accent: Color
    @Binding var isExpanded: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.spring(response: 0.24, dampingFraction: 0.88)) {
                    isExpanded.toggle()
                }
            } label: {
                ReportCardTitle(
                    title: entry.title,
                    preview: entry.preview,
                    icon: "doc.text",
                    accent: accent,
                    accessory: nil,
                    isExpanded: isExpanded
                )
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                Divider()
                    .padding(.vertical, 11)
                ReportMarkdownContent(markdown: entry.content)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.cardMuted.opacity(0.66))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(isExpanded ? accent.opacity(0.30) : AppPalette.border.opacity(0.76))
        }
    }
}

private struct ReportCardTitle: View {
    let title: String
    let preview: String
    let icon: String
    let accent: Color
    let accessory: String?
    let isExpanded: Bool?

    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(accent.opacity(0.12))
                    .frame(width: 32, height: 32)
                Image(systemName: icon)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(accent)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                    .fixedSize(horizontal: false, vertical: true)
                if isExpanded != true, !preview.isEmpty {
                    Text(preview)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Spacer(minLength: 8)
            if let accessory {
                Text(accessory)
                    .font(AppTypography.caption2.weight(.semibold))
                    .foregroundStyle(accent)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 4)
                    .background(accent.opacity(0.10))
                    .clipShape(Capsule())
            }
            if let isExpanded {
                Image(systemName: "chevron.down")
                    .font(AppTypography.caption.weight(.bold))
                    .foregroundStyle(AppPalette.textSubtle)
                    .rotationEffect(.degrees(isExpanded ? 180 : 0))
                    .padding(.top, 7)
            }
        }
    }
}

private struct ReportMarkdownContent: View {
    let blocks: [ReportMarkdownBlock]

    init(markdown: String) {
        blocks = ReportMarkdownBlock.parse(markdown)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(Array(blocks.enumerated()), id: \.offset) { _, block in
                switch block {
                case let .line(line):
                    ReportMarkdownLine(line: line)
                case let .quote(value):
                    ReportMarkdownQuote(value: value)
                case .rule:
                    Divider()
                case let .table(headers, rows):
                    ReportMarkdownTable(headers: headers, rows: rows)
                case let .code(language, content):
                    ReportCodeBlock(language: language, content: content)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .textSelection(.enabled)
    }
}

private struct ReportMarkdownQuote: View {
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 2, style: .continuous)
                .fill(AppPalette.primary)
                .frame(width: 3)
            Text((try? AttributedString(markdown: value)) ?? AttributedString(value))
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.textMuted)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 10)
        .background(AppPalette.primary.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
    }
}

private struct ReportMarkdownTable: View {
    let headers: [String]
    let rows: [[String]]

    var body: some View {
        VStack(spacing: 0) {
            tableRow(headers, isHeader: true)
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                Divider()
                tableRow(row, isHeader: false)
            }
        }
        .background(AppPalette.card.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .stroke(AppPalette.border.opacity(0.82))
        }
    }

    private func tableRow(_ values: [String], isHeader: Bool) -> some View {
        HStack(alignment: .top, spacing: 0) {
            ForEach(Array(normalized(values).enumerated()), id: \.offset) { index, value in
                tableCell(value, index: index, isHeader: isHeader)
            }
        }
    }

    @ViewBuilder
    private func tableCell(_ value: String, index: Int, isHeader: Bool) -> some View {
        let text = Text((try? AttributedString(markdown: value)) ?? AttributedString(value))
            .font(isHeader ? .caption.weight(.semibold) : .caption)
            .foregroundStyle(isHeader ? AppPalette.text : AppPalette.textMuted)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(isHeader ? AppPalette.cardMuted : Color.clear)
        if index == 0 {
            text.frame(width: 150, alignment: .leading)
        } else {
            text.frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func normalized(_ values: [String]) -> [String] {
        let count = max(headers.count, values.count)
        return (0..<count).map { index in index < values.count ? values[index] : "" }
    }
}

private struct ReportMarkdownLine: View {
    let line: String

    private var trimmed: String { line.trimmingCharacters(in: .whitespaces) }
    private var indentation: CGFloat { line.hasPrefix("  ") ? 18 : 0 }

    var body: some View {
        if trimmed.hasPrefix("- ") {
            let value = String(trimmed.dropFirst(2))
            HStack(alignment: .top, spacing: 8) {
                Circle()
                    .fill(AppPalette.primary.opacity(0.72))
                    .frame(width: 5, height: 5)
                    .padding(.top, 7)
                reportInlineText(value)
            }
            .padding(.leading, indentation)
        } else {
            reportInlineText(trimmed)
        }
    }

    @ViewBuilder
    private func reportInlineText(_ value: String) -> some View {
        if let url = URL(string: value), let scheme = url.scheme, ["http", "https"].contains(scheme.lowercased()) {
            Link(destination: url) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: "arrow.up.right.square")
                        .font(AppTypography.caption)
                    Text(value)
                        .font(AppTypography.callout)
                        .lineLimit(3)
                }
                .foregroundStyle(AppPalette.primaryStrong)
            }
        } else if let markdown = try? AttributedString(markdown: value) {
            Text(markdown)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.text)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text(value)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.text)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct ReportCodeBlock: View {
    @EnvironmentObject private var model: AppModel
    let language: String
    let content: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(language.isEmpty ? model.uiText("代码") : language.uppercased())
                    .font(AppTypography.caption2.weight(.semibold))
                    .foregroundStyle(AppPalette.onBrandMuted)
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(content, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.onBrand)
                }
                .buttonStyle(.plain)
                .help(model.uiText("复制代码"))
            }

            ScrollView(.horizontal) {
                Text(content)
                    .font(AppTypography.caption.monospaced())
                    .foregroundStyle(AppPalette.onBrand)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: true, vertical: true)
            }
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.brandNavyDeep)
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}

private struct ReportSectionStyle {
    let icon: String
    let accent: Color

    init(title: String) {
        if title.contains("执行") || title.localizedCaseInsensitiveContains("execution") || title.contains("実行") || title.contains("실행") {
            icon = "list.bullet.rectangle"
            accent = AppPalette.primary
        } else if title.contains("附件") || title.contains("扫描范围") || title.contains("依赖清单") || title.localizedCaseInsensitiveContains("scope") || title.localizedCaseInsensitiveContains("attachment") || title.contains("添付") || title.contains("파일") {
            icon = "shippingbox"
            accent = AppPalette.primaryStrong
        } else if title.contains("依赖漏洞") || title.contains("漏洞命中") || title.localizedCaseInsensitiveContains("dependency vulnerabil") || title.contains("依存関係脆弱性") || title.contains("의존성 취약점") {
            icon = "exclamationmark.shield"
            accent = AppPalette.warning
        } else if title.contains("代码漏洞") || title.contains("代码路径") || title.localizedCaseInsensitiveContains("code finding") || title.contains("コード脆弱性") || title.contains("코드 취약점") {
            icon = "chevron.left.forwardslash.chevron.right"
            accent = AppPalette.danger
        } else if title.contains("运行") {
            icon = "gauge.with.dots.needle.67percent"
            accent = AppPalette.textMuted
        } else if title.contains("结论") {
            icon = "checkmark.shield"
            accent = AppPalette.success
        } else {
            icon = "doc.text"
            accent = AppPalette.primary
        }
    }
}

private func expansionBinding(for id: String, in values: Binding<Set<String>>) -> Binding<Bool> {
    Binding(
        get: { values.wrappedValue.contains(id) },
        set: { isExpanded in
            if isExpanded {
                values.wrappedValue.insert(id)
            } else {
                values.wrappedValue.remove(id)
            }
        }
    )
}

private func cleanReportHeading(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let separator = trimmed.firstIndex(of: ".") else { return trimmed }
    let prefix = trimmed[..<separator]
    guard !prefix.isEmpty, prefix.allSatisfy(\.isNumber) else { return trimmed }
    return trimmed[trimmed.index(after: separator)...].trimmingCharacters(in: .whitespaces)
}

private func parseReportTableRow(_ value: String) -> [String] {
    let placeholder = "\u{0000}SECFLOW_PIPE\u{0000}"
    return value
        .trimmingCharacters(in: CharacterSet(charactersIn: "|"))
        .replacingOccurrences(of: "\\|", with: placeholder)
        .split(separator: "|", omittingEmptySubsequences: false)
        .map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: placeholder, with: "|")
        }
}

private func joinedReportLines(_ lines: [String]) -> String {
    var normalized = lines
    while normalized.first?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true {
        normalized.removeFirst()
    }
    while normalized.last?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true {
        normalized.removeLast()
    }
    return normalized.joined(separator: "\n")
}

private func reportPreview(_ markdown: String) -> String {
    let values = markdown.components(separatedBy: .newlines).compactMap { line -> String? in
        var value = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              !value.hasPrefix("```"),
              !value.hasPrefix("|"),
              !value.hasPrefix("<!-- secflow-report-style:"),
              value != "---"
        else { return nil }
        if value.hasPrefix("- ") {
            value = String(value.dropFirst(2))
        }
        value = value.replacingOccurrences(of: "**", with: "").replacingOccurrences(of: "`", with: "")
        return value.isEmpty ? nil : value
    }
    let combined = values.prefix(2).joined(separator: " · ")
    guard combined.count > 120 else { return combined }
    return String(combined.prefix(120)) + "…"
}
