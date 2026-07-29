import AppKit
import SwiftUI

struct AgentTaskView: View {
    @EnvironmentObject private var model: AppModel
    let task: AgentTaskSnapshot

    var body: some View {
        taskConversationCard(task)
            .foregroundStyle(AppPalette.text)
    }

    private func taskConversationCard(_ task: AgentTaskSnapshot) -> some View {
        HStack(alignment: .top, spacing: 12) {
            AppBrandLogo(size: 34, shadow: false)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(AppBrand.chineseName)
                .accessibilityIdentifier("assistant-brand-avatar")

            VStack(spacing: 0) {
                taskHeader(task)
                Divider()
                VStack(alignment: .leading, spacing: 18) {
                    if !task.error.isEmpty {
                        Label(task.error, systemImage: "exclamationmark.triangle.fill")
                            .font(AppTypography.callout)
                            .foregroundStyle(AppPalette.danger)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(AppPalette.danger.opacity(0.08))
                            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                    }
                    if let result = task.result {
                        taskSummary(result)
                        adaptiveScanSection(result)
                    }
                    if task.isReportReady {
                        reportDecisionSection(task)
                    }
                    if !task.languages.isEmpty {
                        languageStrip(task.languages)
                    }
                    if !task.plan.isEmpty {
                        planSection(task.plan)
                    }
                    if let result = task.result {
                        languageResults(result)
                        dependenciesSection(result)
                        findingsSection(result)
                        reviewFindingsSection(result)
                    }
                    if !task.events.isEmpty {
                        eventsSection(task)
                    }
                }
                .padding(18)
            }
            .frame(maxWidth: 940, alignment: .leading)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(AppPalette.border)
            }

            Spacer(minLength: 90)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func taskHeader(_ task: AgentTaskSnapshot) -> some View {
        HStack(spacing: 14) {
            Image(systemName: agentTaskStatusIcon(task.status))
                .font(AppTypography.title3)
                .foregroundStyle(agentTaskStatusColor(task.status))
            VStack(alignment: .leading, spacing: 3) {
                Text(task.objective)
                    .font(AppTypography.headline.weight(.bold))
                    .lineLimit(2)
                Label(task.workspacePath, systemImage: task.workspaceType == "file" ? "doc.text" : "folder")
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            AgentTaskStatusBadge(status: task.status)
            if task.isActive {
                Button {
                    Task { await model.cancelAgentTask(id: task.id) }
                } label: {
                    Label(model.uiText("停止"), systemImage: "stop.fill")
                }
                .buttonStyle(.bordered)
                .disabled(model.busyActions.contains("agent-task-cancel:\(task.id)"))
            } else if task.canResume {
                Button {
                    Task {
                        await model.resumeAgentTask(id: task.id)
                        await model.followAgentTask(id: task.id)
                    }
                } label: {
                    Label(model.uiText("重新执行"), systemImage: "arrow.clockwise")
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(model.busyActions.contains("agent-task-resume:\(task.id)"))
            }
        }
        .padding(.horizontal, 22)
        .frame(minHeight: 72)
    }

    private func taskSummary(_ result: AgentTaskResult) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(model.uiText("执行摘要"))
                .font(AppTypography.headline)
            Text(result.summary)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.textMuted)
                .textSelection(.enabled)
            HStack(spacing: 24) {
                taskMetric(model.uiText("文件"), value: result.totalFiles)
                taskMetric(model.uiText("依赖"), value: result.dependencyCount)
                taskMetric(model.uiText("风险"), value: result.totalFindings)
                if let count = result.totalReviewFindings, count > 0 {
                    taskMetric(model.uiText("待复核"), value: count)
                }
            }
        }
        .padding(.bottom, 4)
    }

    private func taskMetric(_ title: String, value: Int) -> some View {
        HStack(spacing: 6) {
            Text("\(value)").font(AppTypography.headline.monospacedDigit())
            Text(title).font(AppTypography.caption).foregroundStyle(AppPalette.textMuted)
        }
    }

    @ViewBuilder
    private func adaptiveScanSection(_ result: AgentTaskResult) -> some View {
        if let adaptation = result.adaptation {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .foregroundStyle(AppPalette.primary)
                    Text(model.uiText("自适应扫描子图"))
                        .font(AppTypography.headline)
                    Spacer()
                    StatusBadge(
                        text: model.uiText(adaptationStatusLabel(adaptation.status)),
                        tone: adaptationStatusTone(adaptation.status)
                    )
                }

                HStack(spacing: 5) {
                    adaptiveStage("静态规则", icon: "checklist")
                    adaptiveStageDivider
                    adaptiveStage("AST/CFG/DFG", icon: "point.3.filled.connected.trianglepath.dotted")
                    adaptiveStageDivider
                    adaptiveStage("污点证据", icon: "arrow.triangle.branch")
                    adaptiveStageDivider
                    adaptiveStage("项目 Overlay", icon: "slider.horizontal.3")
                    adaptiveStageDivider
                    adaptiveStage("差分重扫", icon: "arrow.clockwise")
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                HStack(spacing: 20) {
                    Label(
                        model.uiText(scanModeLabel(result.scanMode ?? adaptation.mode)),
                        systemImage: (result.scanMode ?? adaptation.mode) == "adaptive_upload" ? "folder.badge.gearshape" : "lock.shield"
                    )
                    Label(
                        model.uiText("模型尝试 %d/3", adaptation.attempts ?? 0),
                        systemImage: "brain.head.profile"
                    )
                    Label(
                        model.uiText("重扫 %d/3", adaptation.iterations ?? 0),
                        systemImage: "arrow.clockwise"
                    )
                }
                .font(AppTypography.caption.weight(.medium))
                .foregroundStyle(AppPalette.textMuted)

                if adaptation.baselineMetrics != nil || adaptation.currentMetrics != nil {
                    VStack(spacing: 6) {
                        if let metrics = adaptation.baselineMetrics {
                            adaptationMetricsRow(model.uiText("基线"), metrics: metrics)
                        }
                        if let metrics = adaptation.currentMetrics {
                            adaptationMetricsRow(model.uiText("当前"), metrics: metrics)
                        }
                    }
                }

                if let profile = result.projectProfile {
                    VStack(alignment: .leading, spacing: 5) {
                        if let buildSystems = profile.buildSystems, !buildSystems.isEmpty {
                            adaptiveMetadataRow(
                                model.uiText("构建系统"),
                                value: buildSystems.joined(separator: " · ")
                            )
                        }
                        if let frameworks = profile.frameworks, !frameworks.isEmpty {
                            adaptiveMetadataRow(
                                model.uiText("项目依赖画像"),
                                value: frameworks.prefix(8).joined(separator: " · ")
                            )
                        }
                    }
                }

                if let fingerprint = adaptation.overlayFingerprints?.last, !fingerprint.isEmpty {
                    VStack(alignment: .leading, spacing: 5) {
                        adaptiveAuditRow(model.uiText("Overlay 指纹"), value: fingerprint)
                    }
                }
            }
            .padding(13)
            .background(AppPalette.cardMuted)
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.border)
            }
            .accessibilityIdentifier("agent-task-adaptive-scan-section")
        }
    }

    private func adaptiveStage(_ title: String, icon: String) -> some View {
        Label(model.uiText(title), systemImage: icon)
            .font(AppTypography.caption2.weight(.semibold))
            .foregroundStyle(AppPalette.textMuted)
            .padding(.horizontal, 7)
            .frame(height: 28)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .stroke(AppPalette.border)
            }
    }

    private var adaptiveStageDivider: some View {
        Image(systemName: "chevron.right")
            .font(AppTypography.caption2.weight(.bold))
            .foregroundStyle(AppPalette.textSubtle)
    }

    private func adaptationMetricsRow(_ title: String, metrics: AgentAdaptationMetrics) -> some View {
        HStack(spacing: 12) {
            Text(title)
                .font(AppTypography.caption.weight(.semibold))
                .frame(width: 38, alignment: .leading)
            adaptationMetric(model.uiText("风险"), metrics.findings)
            adaptationMetric(model.uiText("待复核"), metrics.reviewFindings)
            adaptationMetric(model.uiText("解析缺口"), metrics.parseErrorFiles)
            adaptationMetric("CFG", metrics.cfgEdges)
            adaptationMetric("DFG", metrics.dfgEdges)
            Spacer()
        }
        .font(AppTypography.caption.monospacedDigit())
    }

    private func adaptationMetric(_ title: String, _ value: Int?) -> some View {
        HStack(spacing: 4) {
            Text(title).foregroundStyle(AppPalette.textMuted)
            Text("\(value ?? 0)").fontWeight(.semibold)
        }
    }

    private func adaptiveMetadataRow(_ title: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(title)
                .font(AppTypography.caption.weight(.semibold))
                .frame(width: 86, alignment: .leading)
            Text(value)
                .font(AppTypography.caption)
                .foregroundStyle(AppPalette.textMuted)
                .lineLimit(2)
                .textSelection(.enabled)
        }
    }

    private func adaptiveAuditRow(_ title: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(title)
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .frame(width: 86, alignment: .leading)
            Text(value)
                .font(AppTypography.caption2.monospaced())
                .foregroundStyle(AppPalette.textSubtle)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    @ViewBuilder
    private func reportDecisionSection(_ task: AgentTaskSnapshot) -> some View {
        let isBusy = model.busyActions.contains("agent-task-report:\(task.id)")
        switch task.resolvedReportDecision {
        case "generated":
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(AppTypography.title3)
                    .foregroundStyle(AppPalette.success)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.uiText("报告已生成"))
                        .font(AppTypography.callout.weight(.semibold))
                    Text(task.report?.fileName ?? model.uiText("完整分析报告已写入报告中心"))
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                        .textSelection(.enabled)
                }
                Spacer()
                if task.reportInterrupt?.kind == "report_download_confirmation" {
                    Menu {
                        ForEach(ReportDownloadFormat.allCases) { format in
                            Button {
                                confirmTaskReportDownload(task, format: format)
                            } label: {
                                Text(model.uiText("确认下载 %@", format.label))
                            }
                        }
                        Divider()
                        Button(model.uiText("暂不下载")) {
                            Task { _ = await model.confirmAgentTaskReportDownload(id: task.id, format: .pdf, confirm: false) }
                        }
                    } label: {
                        Label(model.uiText("确认下载"), systemImage: "arrow.down.doc")
                    }
                    .buttonStyle(PrimaryActionButtonStyle())
                    .disabled(model.busyActions.contains("agent-task-report-download:\(task.id)"))
                }
            }
            .padding(13)
            .background(AppPalette.success.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        case "declined":
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "list.bullet.rectangle")
                    .font(AppTypography.title3)
                    .foregroundStyle(AppPalette.primary)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.uiText("已跳过报告生成"))
                        .font(AppTypography.callout.weight(.semibold))
                    Text(model.uiText("以下为本次任务的完整扫描结果"))
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
            }
            .padding(13)
            .background(AppPalette.primary.opacity(0.07))
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        default:
            HStack(alignment: .center, spacing: 14) {
                Image(systemName: "doc.badge.plus")
                    .font(AppTypography.title2)
                    .foregroundStyle(AppPalette.primary)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.uiText("扫描已完成，是否生成完整分析报告？"))
                        .font(AppTypography.callout.weight(.semibold))
                    Text(model.uiText("报告将生成 Markdown、HTML 和 PDF，并写入报告中心。"))
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer(minLength: 16)
                if isBusy {
                    ProgressView()
                        .controlSize(.small)
                }
                Button {
                    Task { await model.decideAgentTaskReport(id: task.id, generate: false) }
                } label: {
                    Text(model.uiText("暂不生成"))
                }
                .buttonStyle(.bordered)
                .disabled(isBusy)
                Button {
                    Task { await model.decideAgentTaskReport(id: task.id, generate: true) }
                } label: {
                    Label(model.uiText("生成报告"), systemImage: "doc.badge.plus")
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(isBusy)
            }
            .padding(14)
            .background(AppPalette.primary.opacity(0.07))
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.primary.opacity(0.18))
            }
        }
    }

    private func languageStrip(_ languages: [String]) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(model.uiText("项目语言"))
                .font(AppTypography.headline)
            HStack(spacing: 8) {
                ForEach(languages, id: \.self) { language in
                    Label(agentLanguageLabel(language), systemImage: agentLanguageIcon(language))
                        .font(AppTypography.caption.weight(.semibold))
                        .padding(.horizontal, 9)
                        .padding(.vertical, 5)
                        .background(AppPalette.primary.opacity(0.10))
                        .clipShape(Capsule())
                }
            }
        }
    }

    private func planSection(_ plan: [AgentTaskPlanStep]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(model.uiText("执行计划"))
                .font(AppTypography.headline)
            VStack(spacing: 0) {
                ForEach(Array(plan.enumerated()), id: \.element.id) { index, step in
                    HStack(spacing: 11) {
                        planStepIcon(step.status)
                            .frame(width: 20, height: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(step.title)
                                .font(AppTypography.callout.weight(.medium))
                            Text(step.node)
                                .font(AppTypography.caption2.monospaced())
                                .foregroundStyle(AppPalette.textSubtle)
                        }
                        Spacer()
                    }
                    .padding(.vertical, 9)
                    if index < plan.count - 1 { Divider() }
                }
            }
        }
    }

    @ViewBuilder
    private func planStepIcon(_ status: String) -> some View {
        if status == "running" {
            ProgressView().controlSize(.small)
        } else {
            Image(systemName: status == "completed" ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(status == "completed" ? AppPalette.success : AppPalette.textSubtle)
        }
    }

    private func languageResults(_ result: AgentTaskResult) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(model.uiText("语言扫描结果"))
                .font(AppTypography.headline)
            VStack(spacing: 0) {
                ForEach(sortedLanguageResults(result), id: \.language) { item in
                    HStack(spacing: 12) {
                        Image(systemName: agentLanguageIcon(item.language))
                            .foregroundStyle(AppPalette.primary)
                            .frame(width: 22)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(agentLanguageLabel(item.language))
                                .font(AppTypography.callout.weight(.semibold))
                            Text(item.ruleFiles.joined(separator: " · "))
                                .font(AppTypography.caption2.monospaced())
                                .foregroundStyle(AppPalette.textSubtle)
                                .lineLimit(1)
                        }
                        Spacer()
                        Text(model.uiText("%d 文件", item.fileCount)).font(AppTypography.caption)
                        Text(model.uiText("%d 风险", item.findingCount))
                            .font(AppTypography.caption.weight(.semibold))
                            .foregroundStyle(item.findingCount > 0 ? AppPalette.warning : AppPalette.success)
                        if let count = item.reviewFindingCount, count > 0 {
                            Text(model.uiText("%d 待复核", count))
                                .font(AppTypography.caption)
                                .foregroundStyle(AppPalette.textMuted)
                        }
                        Text("AST \(item.syntaxSummary.astNodeCount) · CFG \(item.syntaxSummary.cfgEdgeCount) · DFG \(item.syntaxSummary.dfgEdgeCount)")
                            .font(AppTypography.caption2.monospacedDigit())
                            .foregroundStyle(AppPalette.textMuted)
                    }
                    .padding(.vertical, 10)
                    Divider()
                }
            }
        }
    }

    @ViewBuilder
    private func dependenciesSection(_ result: AgentTaskResult) -> some View {
        let dependencies = result.dependencies ?? []
        if !dependencies.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(model.uiText("依赖组件明细"))
                        .font(AppTypography.headline)
                    Spacer()
                    Text(model.uiText("共 %d 个", dependencies.count))
                        .font(AppTypography.caption.monospacedDigit())
                        .foregroundStyle(AppPalette.textMuted)
                }
                LazyVStack(spacing: 0) {
                    ForEach(dependencies) { dependency in
                        HStack(alignment: .top, spacing: 11) {
                            Text(dependency.ecosystem.isEmpty ? "-" : dependency.ecosystem)
                                .font(AppTypography.caption2.weight(.semibold))
                                .foregroundStyle(AppPalette.primary)
                                .frame(width: 68, alignment: .leading)
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(alignment: .firstTextBaseline, spacing: 7) {
                                    Text(dependency.name)
                                        .font(AppTypography.callout.weight(.semibold))
                                        .textSelection(.enabled)
                                    Text(dependency.version.isEmpty ? model.uiText("版本未指定") : dependency.version)
                                        .font(AppTypography.caption.monospaced())
                                        .foregroundStyle(dependency.version.isEmpty ? AppPalette.warning : AppPalette.textMuted)
                                }
                                if !dependency.sourceFile.isEmpty {
                                    Label(dependency.sourceFile, systemImage: "doc.text")
                                        .font(AppTypography.caption2.monospaced())
                                        .foregroundStyle(AppPalette.textMuted)
                                        .textSelection(.enabled)
                                }
                                if !dependency.declaration.isEmpty {
                                    Text(dependency.declaration)
                                        .font(AppTypography.caption2.monospaced())
                                        .foregroundStyle(AppPalette.textSubtle)
                                        .textSelection(.enabled)
                                }
                            }
                            Spacer(minLength: 12)
                            Text(dependency.confidence.uppercased())
                                .font(AppTypography.caption2.weight(.semibold))
                                .foregroundStyle(AppPalette.textSubtle)
                        }
                        .padding(.vertical, 8)
                        Divider()
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func findingsSection(_ result: AgentTaskResult) -> some View {
        let findings = sortedLanguageResults(result).flatMap { item in
            item.findings.map { (language: item.language, finding: $0) }
        }
        if !findings.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text(model.uiText("代码风险"))
                    .font(AppTypography.headline)
                ForEach(Array(findings.enumerated()), id: \.element.finding.id) { _, item in
                    HStack(alignment: .top, spacing: 11) {
                        Image(systemName: "exclamationmark.shield.fill")
                            .foregroundStyle(AppPalette.warning)
                            .frame(width: 22)
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(item.finding.title)
                                    .font(AppTypography.callout.weight(.semibold))
                                Spacer()
                                StatusBadge(
                                    text: severityLabel(item.finding.severity),
                                    tone: .severity(item.finding.severity)
                                )
                            }
                            if let file = item.finding.fileName {
                                Text(file + (item.finding.line.map { ":\($0)" } ?? ""))
                                    .font(AppTypography.caption.monospaced())
                                    .foregroundStyle(AppPalette.textMuted)
                                    .textSelection(.enabled)
                            }
                            if let description = item.finding.description, !description.isEmpty {
                                Text(description)
                                    .font(AppTypography.caption)
                                    .foregroundStyle(AppPalette.textMuted)
                                    .lineLimit(3)
                            }
                        }
                    }
                    .padding(.vertical, 8)
                    Divider()
                }
            }
        }
    }

    @ViewBuilder
    private func reviewFindingsSection(_ result: AgentTaskResult) -> some View {
        let findings = sortedLanguageResults(result).flatMap { item in
            (item.reviewFindings ?? []).map { (language: item.language, finding: $0) }
        }
        if !findings.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text(model.uiText("待人工复核"))
                    .font(AppTypography.headline)
                ForEach(Array(findings.enumerated()), id: \.element.finding.id) { _, item in
                    HStack(alignment: .top, spacing: 11) {
                        Image(systemName: "doc.text.magnifyingglass")
                            .foregroundStyle(AppPalette.primary)
                            .frame(width: 22)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.finding.title)
                                .font(AppTypography.callout.weight(.semibold))
                            if let file = item.finding.fileName {
                                Text(file + (item.finding.line.map { ":\($0)" } ?? ""))
                                    .font(AppTypography.caption.monospaced())
                                    .foregroundStyle(AppPalette.textMuted)
                                    .textSelection(.enabled)
                            }
                        }
                        Spacer()
                        Text(agentLanguageLabel(item.language))
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                    }
                    .padding(.vertical, 8)
                    Divider()
                }
            }
        }
    }

    private func eventsSection(_ task: AgentTaskSnapshot) -> some View {
        let allEvents = Array(task.events.suffix(120))
        let visibleEvents = Array(
            visibleAgentTaskEvents(allEvents, taskStatus: task.status).suffix(12)
        )
        return VStack(alignment: .leading, spacing: 10) {
            Text(model.uiText("执行记录"))
                .font(AppTypography.headline)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(visibleEvents) { event in
                    let index = allEvents.firstIndex(where: { $0.id == event.id }) ?? 0
                    taskEventRow(event, index: index, events: allEvents)
                }
            }
        }
    }

    @ViewBuilder
    private func taskEventRow(_ event: AgentTaskEvent, index: Int, events: [AgentTaskEvent]) -> some View {
        if let presentation = visibleAgentTaskPresentation(from: event.data) {
            taskEventPresentation(presentation, event: event)
        } else if let toolName = agentTaskToolName(event.node) {
            let inputEvent = event.type == "node.started"
                ? event
                : precedingToolStart(for: event, before: index, events: events)
            let state = event.type == "node.started" ? "running" : agentTaskToolState(event.status)
            let presentation = LangGraphNodePresentation(
                kind: "tool_call",
                title: nodeLabel(event.node, language: model.appLanguage),
                toolName: toolName,
                state: state,
                input: agentTaskEventFields(inputEvent?.data),
                output: state == "error" ? nil : agentTaskEventOutput(event),
                error: state == "error" ? event.message : nil,
                before: nil,
                after: nil
            )
            taskEventPresentation(presentation, event: event)
        } else {
            HStack(alignment: .top, spacing: 11) {
                Circle()
                    .fill(agentTaskStatusColor(event.status))
                    .frame(width: 8, height: 8)
                    .padding(.top, 5)
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(event.node)
                            .font(AppTypography.caption.weight(.semibold).monospaced())
                        Spacer()
                        Text(agentTaskDisplayTime(event.time))
                            .font(AppTypography.caption2.monospacedDigit())
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                    Text(event.message)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                        .textSelection(.enabled)
                }
                .padding(.bottom, 11)
            }
        }
    }

    private func taskEventPresentation(
        _ presentation: LangGraphNodePresentation,
        event: AgentTaskEvent
    ) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            LangGraphNodePresentationView(presentation: presentation)
                .environmentObject(model)
            HStack(spacing: 8) {
                Text(event.node)
                    .font(AppTypography.caption2.monospaced())
                    .foregroundStyle(AppPalette.textSubtle)
                Spacer(minLength: 8)
                Text(agentTaskDisplayTime(event.time))
                    .font(AppTypography.caption2.monospacedDigit())
                    .foregroundStyle(AppPalette.textSubtle)
            }
            .padding(.horizontal, 2)
        }
        .padding(.bottom, 11)
        .accessibilityIdentifier("agent-task-node-presentation-\(event.sequence)")
    }

    private func precedingToolStart(
        for event: AgentTaskEvent,
        before index: Int,
        events: [AgentTaskEvent]
    ) -> AgentTaskEvent? {
        guard index > 0 else { return nil }
        for candidate in events[..<index].reversed() where candidate.node == event.node {
            if candidate.type == "node.started" { return candidate }
        }
        return nil
    }

    private func sortedLanguageResults(_ result: AgentTaskResult) -> [AgentLanguageScanResult] {
        result.languages.compactMap { result.languageResults[$0] }
    }

    private func confirmTaskReportDownload(_ task: AgentTaskSnapshot, format: ReportDownloadFormat) {
        Task { @MainActor in
            guard let artifact = await model.confirmAgentTaskReportDownload(id: task.id, format: format) else { return }
            let panel = NSSavePanel()
            panel.title = model.uiText("下载分析报告")
            panel.nameFieldStringValue = artifact.fileName
            panel.canCreateDirectories = true
            guard panel.runModal() == .OK, let destination = panel.url else { return }
            await model.downloadAssistantArtifact(artifact, to: destination)
        }
    }
}

func visibleAgentTaskEvents(
    _ events: [AgentTaskEvent],
    taskStatus: String
) -> [AgentTaskEvent] {
    let taskIsTerminal = ["completed", "failed", "cancelled", "interrupted"].contains(taskStatus)
    return events.enumerated().compactMap { index, event in
        let isTransient = event.type == "node.started" || event.type == "node.progress"
        guard isTransient else { return event }
        if taskIsTerminal { return nil }
        guard index + 1 < events.count else { return event }
        let hasLaterNodeState = events[(index + 1)...].contains { candidate in
            candidate.node == event.node
                && (candidate.type == "node.started"
                    || candidate.type == "node.progress"
                    || candidate.type == "node.completed"
                    || candidate.type == "verification.completed"
                    || ["completed", "failed", "error", "warning"].contains(candidate.status))
        }
        return hasLaterNodeState ? nil : event
    }
}

func agentTaskDisplayTime(_ value: String) -> String {
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let date = fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value) else {
        return value
    }
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "zh_CN")
    formatter.calendar = Calendar(identifier: .gregorian)
    formatter.timeZone = TimeZone(identifier: "Asia/Shanghai")
    formatter.dateFormat = "yyyy:MM:dd:HH:mm"
    return formatter.string(from: date)
}

private struct AgentTaskStatusBadge: View {
    @EnvironmentObject private var model: AppModel
    let status: String

    var body: some View {
        Label(model.uiText(agentTaskStatusLabel(status)), systemImage: agentTaskStatusIcon(status))
            .font(AppTypography.caption.weight(.semibold))
            .foregroundStyle(agentTaskStatusColor(status))
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(agentTaskStatusColor(status).opacity(0.10))
            .clipShape(Capsule())
    }
}

private func scanModeLabel(_ mode: String?) -> String {
    switch mode {
    case "adaptive_upload": return "上传项目隔离模式"
    case "frozen_evaluation": return "冻结评测模式"
    default: return "扫描模式"
    }
}

private func adaptationStatusLabel(_ status: String?) -> String {
    switch status {
    case "pending": return "等待执行"
    case "overlay_ready": return "Overlay 已就绪"
    case "rescanned": return "差分重扫完成"
    case "no_change": return "无需调整"
    case "max_iterations": return "达到轮次上限"
    case "disabled": return "评测隔离"
    case "skipped": return "模型不可用"
    case "failed", "rejected": return "调整未应用"
    default: return status ?? "状态未知"
    }
}

private func adaptationStatusTone(_ status: String?) -> StatusTone {
    switch status {
    case "no_change", "rescanned": return .good
    case "overlay_ready", "pending": return .info
    case "max_iterations", "skipped": return .warning
    case "failed", "rejected": return .critical
    default: return .neutral
    }
}

private func agentTaskStatusLabel(_ status: String) -> String {
    switch status {
    case "queued": return "排队中"
    case "running": return "执行中"
    case "cancelling": return "正在停止"
    case "completed": return "已完成"
    case "failed": return "失败"
    case "cancelled": return "已停止"
    case "interrupted": return "已中断"
    default: return status
    }
}

private func agentTaskStatusIcon(_ status: String) -> String {
    switch status {
    case "queued": return "clock"
    case "running", "cancelling": return "progress.indicator"
    case "completed": return "checkmark.circle.fill"
    case "failed": return "xmark.octagon.fill"
    case "cancelled", "interrupted": return "stop.circle.fill"
    default: return "circle"
    }
}

private func agentTaskStatusColor(_ status: String) -> Color {
    switch status {
    case "completed": return AppPalette.success
    case "failed": return AppPalette.danger
    case "cancelled", "interrupted", "cancelling": return AppPalette.warning
    case "running": return AppPalette.primary
    default: return AppPalette.textMuted
    }
}

private func agentLanguageLabel(_ language: String) -> String {
    switch language {
    case "java": return "Java"
    case "python": return "Python"
    case "go": return "Go"
    case "c": return "C"
    case "cpp": return "C++"
    case "csharp": return "C#"
    case "rust": return "Rust"
    case "solidity": return "Solidity"
    default: return language.uppercased()
    }
}

private func agentLanguageIcon(_ language: String) -> String {
    switch language {
    case "python": return "chevron.left.forwardslash.chevron.right"
    case "go": return "arrow.triangle.branch"
    case "rust", "c", "cpp", "csharp": return "gearshape.2"
    case "solidity": return "cube.transparent"
    default: return "curlybraces"
    }
}

private func agentTaskToolName(_ node: String) -> String? {
    if node.hasPrefix("scan_") {
        return "\(node)_static_semantic_scan"
    }
    switch node {
    case "scan_dependencies": return "scan_dependency_manifests"
    case "fuse_analysis_evidence": return "fuse_analysis_evidence"
    case "synthesize_project_overlay": return "synthesize_project_overlay"
    case "rescan_project_overlay": return "rescan_project_overlay"
    case "report.chart_mcp": return "build_scan_report_charts"
    case "report.prepare_download": return "prepare_report_download"
    default: return nil
    }
}

private func agentTaskToolState(_ status: String) -> String {
    switch status.lowercased() {
    case "failed", "error", "warning": "error"
    case "running", "active": "running"
    default: "completed"
    }
}

func visibleAgentTaskPresentation(from data: [String: JSONValue]?) -> LangGraphNodePresentation? {
    guard let presentation = langGraphPresentation(from: data), presentation.kind != "prompt_diff" else {
        return nil
    }
    return presentation
}

func agentTaskEventFields(_ data: [String: JSONValue]?) -> [String: String]? {
    let values = (data ?? [:])
        .filter { key, _ in
            let normalized = key.lowercased().replacingOccurrences(of: "-", with: "_")
            return normalized != "presentation"
                && !normalized.contains("skill")
                && !normalized.contains("prompt")
                && !normalized.contains("instruction")
                && normalized != "system_message"
        }
        .mapValues { value in
            let text = value.text
            return text.count > 700 ? String(text.prefix(699)) + "…" : text
        }
    return values.isEmpty ? nil : values
}

private func agentTaskEventOutput(_ event: AgentTaskEvent) -> String {
    let fields = agentTaskEventFields(event.data) ?? [:]
    guard !fields.isEmpty else { return event.message }
    let details = fields.keys.sorted().map { "\($0): \(fields[$0] ?? "")" }.joined(separator: "\n")
    return "\(event.message)\n\(details)"
}
