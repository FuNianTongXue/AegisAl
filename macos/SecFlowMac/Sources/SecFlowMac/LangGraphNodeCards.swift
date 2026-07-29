import AppKit
import SwiftUI

struct LangGraphNodePresentationView: View {
    @EnvironmentObject private var model: AppModel
    let presentation: LangGraphNodePresentation

    @ViewBuilder
    var body: some View {
        switch presentation.kind {
        case "prompt_diff":
            if let before = presentation.before, let after = presentation.after {
                LangGraphPromptDiffCard(
                    title: model.uiText(presentation.title ?? "提示词变更"),
                    before: before,
                    after: after
                )
            }
        case "tool_call":
            LangGraphToolCallCard(presentation: presentation)
        default:
            EmptyView()
        }
    }
}

struct LangGraphPromptDiffCard: View {
    @EnvironmentObject private var model: AppModel
    let title: String
    let before: String
    let after: String

    @State private var mode: PromptDiffMode = .unified
    @State private var didCopy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 9) {
                Image(systemName: "text.badge.plus")
                    .font(AppTypography.system(size: 13, weight: .semibold))
                    .foregroundStyle(AppPalette.primaryStrong)
                    .frame(width: 22, height: 22)

                Text(title)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)

                Spacer(minLength: 8)

                Picker("", selection: $mode) {
                    Image(systemName: "list.bullet.rectangle").tag(PromptDiffMode.unified)
                    Image(systemName: "rectangle.split.2x1").tag(PromptDiffMode.split)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 76)
                .help(model.uiText("切换提示词差异视图"))

                Button(action: copyAfter) {
                    Image(systemName: didCopy ? "checkmark" : "doc.on.doc")
                        .font(AppTypography.system(size: 12, weight: .semibold))
                        .foregroundStyle(didCopy ? AppPalette.success : AppPalette.textMuted)
                        .frame(width: 26, height: 26)
                }
                .buttonStyle(.plain)
                .help(model.uiText("复制调整后的提示词"))
                .accessibilityIdentifier("langgraph-prompt-diff-copy")
            }
            .padding(.horizontal, 11)
            .frame(minHeight: 42)
            .background(AppPalette.cardMuted.opacity(0.72))

            Divider()

            Group {
                switch mode {
                case .unified:
                    unifiedDiff
                case .split:
                    splitDiff
                }
            }
            .padding(10)
        }
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
        .accessibilityIdentifier("langgraph-prompt-diff")
    }

    private var unifiedDiff: some View {
        ScrollView(.horizontal, showsIndicators: true) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(promptDiffRows(before: before, after: after).enumerated()), id: \.offset) { _, row in
                    HStack(alignment: .top, spacing: 8) {
                        Text(row.kind.marker)
                            .font(AppTypography.caption2.monospaced().weight(.semibold))
                            .foregroundStyle(row.kind.foreground)
                            .frame(width: 11, alignment: .center)
                        Text(row.text.isEmpty ? " " : row.text)
                            .font(AppTypography.caption2.monospaced())
                            .foregroundStyle(AppPalette.text)
                            .textSelection(.enabled)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .frame(minWidth: 610, alignment: .leading)
                    .background(row.kind.background)
                }
            }
        }
        .background(AppPalette.cardMuted)
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
    }

    private var splitDiff: some View {
        HStack(alignment: .top, spacing: 8) {
            PromptCodePane(title: model.uiText("调整前"), text: before, tint: AppPalette.danger)
            PromptCodePane(title: model.uiText("调整后"), text: after, tint: AppPalette.success)
        }
    }

    private func copyAfter() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(after, forType: .string)
        didCopy = true
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            didCopy = false
        }
    }
}

struct LangGraphToolCallCard: View {
    @EnvironmentObject private var model: AppModel
    let presentation: LangGraphNodePresentation
    @State private var isExpanded: Bool

    init(presentation: LangGraphNodePresentation) {
        self.presentation = presentation
        _isExpanded = State(initialValue: false)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                guard hasContent else { return }
                withAnimation(.easeInOut(duration: 0.16)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 9) {
                    stateIcon
                        .frame(width: 21, height: 21)

                    Text(presentation.toolName ?? presentation.title ?? model.uiText("工具调用"))
                        .font(AppTypography.caption.weight(.semibold).monospaced())
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)

                    Spacer(minLength: 8)

                    Text(model.uiText(toolStateLabel(state)))
                        .font(AppTypography.caption2.weight(.semibold))
                        .foregroundStyle(stateTone)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(stateTone.opacity(0.10))
                        .clipShape(Capsule())

                    if hasContent {
                        Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                            .font(AppTypography.caption2.weight(.semibold))
                            .foregroundStyle(AppPalette.textSubtle)
                            .frame(width: 16)
                    }
                }
                .padding(.horizontal, 11)
                .frame(minHeight: 40)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded && hasContent {
                Divider()
                VStack(alignment: .leading, spacing: 9) {
                    if let input = presentation.input, !input.isEmpty {
                        toolSection(model.uiText("输入"), icon: "arrow.right.to.line") {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(input.keys.sorted(), id: \.self) { key in
                                    HStack(alignment: .top, spacing: 8) {
                                        Text(key)
                                            .foregroundStyle(AppPalette.textSubtle)
                                            .frame(width: 118, alignment: .leading)
                                        Text(input[key] ?? "")
                                            .foregroundStyle(AppPalette.text)
                                            .textSelection(.enabled)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                    .font(AppTypography.caption2.monospaced())
                                }
                            }
                        }
                    }

                    if let output = presentation.output, !output.isEmpty {
                        toolSection(model.uiText("输出"), icon: "arrow.left.to.line") {
                            ToolOutputBlock(text: output, tone: AppPalette.success)
                        }
                    }

                    if let error = presentation.error, !error.isEmpty {
                        toolSection(model.uiText("错误"), icon: "exclamationmark.triangle") {
                            ToolOutputBlock(text: error, tone: AppPalette.danger)
                        }
                    }
                }
                .padding(10)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(stateTone.opacity(state == "completed" ? 0.22 : 0.38))
        }
        .accessibilityIdentifier("langgraph-tool-call")
    }

    private var state: String {
        presentation.state ?? "completed"
    }

    private var hasContent: Bool {
        !(presentation.input ?? [:]).isEmpty
            || !(presentation.output ?? "").isEmpty
            || !(presentation.error ?? "").isEmpty
    }

    @ViewBuilder
    private var stateIcon: some View {
        if state == "running" {
            ProgressView().controlSize(.mini).tint(AppPalette.primary)
        } else {
            Image(systemName: toolStateIcon(state))
                .font(AppTypography.system(size: 12, weight: .semibold))
                .foregroundStyle(stateTone)
        }
    }

    private var stateTone: Color {
        switch state {
        case "running": AppPalette.primary
        case "awaiting-approval": AppPalette.warning
        case "error": AppPalette.danger
        default: AppPalette.success
        }
    }

    private func toolSection<Content: View>(
        _ title: String,
        icon: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: icon)
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
            content()
        }
    }
}

private struct PromptCodePane: View {
    let title: String
    let text: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title)
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(tint)
                .padding(.horizontal, 8)
                .frame(maxWidth: .infinity, minHeight: 28, alignment: .leading)
                .background(tint.opacity(0.07))
            Divider()
            ScrollView(.horizontal, showsIndicators: true) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(promptLines(text).enumerated()), id: \.offset) { index, line in
                        HStack(alignment: .top, spacing: 7) {
                            Text("\(index + 1)")
                                .foregroundStyle(AppPalette.textSubtle)
                                .frame(width: 24, alignment: .trailing)
                            Text(line.isEmpty ? " " : line)
                                .foregroundStyle(AppPalette.text)
                                .textSelection(.enabled)
                        }
                        .font(AppTypography.caption2.monospaced())
                    }
                }
                .padding(8)
                .frame(minWidth: 286, alignment: .leading)
            }
        }
        .background(AppPalette.cardMuted)
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .stroke(tint.opacity(0.18))
        }
        .frame(maxWidth: .infinity)
    }
}

private struct ToolOutputBlock: View {
    let text: String
    let tone: Color

    var body: some View {
        Text(text)
            .font(AppTypography.caption2.monospaced())
            .foregroundStyle(AppPalette.text)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(tone.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .stroke(tone.opacity(0.14))
            }
    }
}

private enum PromptDiffMode: String, CaseIterable, Identifiable {
    case unified
    case split

    var id: String { rawValue }
}

private enum PromptDiffKind {
    case context
    case removal
    case insertion

    var marker: String {
        switch self {
        case .context: " "
        case .removal: "-"
        case .insertion: "+"
        }
    }

    var foreground: Color {
        switch self {
        case .context: AppPalette.textSubtle
        case .removal: AppPalette.danger
        case .insertion: AppPalette.success
        }
    }

    var background: Color {
        switch self {
        case .context: Color.clear
        case .removal: AppPalette.danger.opacity(0.07)
        case .insertion: AppPalette.success.opacity(0.07)
        }
    }
}

private struct PromptDiffRow {
    let kind: PromptDiffKind
    let text: String
}

private func promptDiffRows(before: String, after: String) -> [PromptDiffRow] {
    let left = Array(promptLines(before).prefix(320))
    let right = Array(promptLines(after).prefix(320))
    var lengths = Array(
        repeating: Array(repeating: 0, count: right.count + 1),
        count: left.count + 1
    )

    if !left.isEmpty && !right.isEmpty {
        for leftIndex in stride(from: left.count - 1, through: 0, by: -1) {
            for rightIndex in stride(from: right.count - 1, through: 0, by: -1) {
                if left[leftIndex] == right[rightIndex] {
                    lengths[leftIndex][rightIndex] = lengths[leftIndex + 1][rightIndex + 1] + 1
                } else {
                    lengths[leftIndex][rightIndex] = max(
                        lengths[leftIndex + 1][rightIndex],
                        lengths[leftIndex][rightIndex + 1]
                    )
                }
            }
        }
    }

    var rows: [PromptDiffRow] = []
    var leftIndex = 0
    var rightIndex = 0
    while leftIndex < left.count || rightIndex < right.count {
        if leftIndex < left.count, rightIndex < right.count, left[leftIndex] == right[rightIndex] {
            rows.append(PromptDiffRow(kind: .context, text: left[leftIndex]))
            leftIndex += 1
            rightIndex += 1
        } else if rightIndex >= right.count
                    || (leftIndex < left.count
                        && lengths[leftIndex + 1][rightIndex] >= lengths[leftIndex][rightIndex + 1]) {
            rows.append(PromptDiffRow(kind: .removal, text: left[leftIndex]))
            leftIndex += 1
        } else {
            rows.append(PromptDiffRow(kind: .insertion, text: right[rightIndex]))
            rightIndex += 1
        }
    }
    return rows
}

private func promptLines(_ value: String) -> [String] {
    value.components(separatedBy: .newlines)
}

private func toolStateLabel(_ state: String) -> String {
    switch state {
    case "running": "运行中"
    case "awaiting-approval": "等待确认"
    case "error": "失败"
    default: "已完成"
    }
}

private func toolStateIcon(_ state: String) -> String {
    switch state {
    case "awaiting-approval": "hand.raised.fill"
    case "error": "exclamationmark.triangle.fill"
    default: "checkmark"
    }
}

func langGraphPresentation(from data: [String: JSONValue]?) -> LangGraphNodePresentation? {
    guard case let .object(raw)? = data?["presentation"],
          case let .string(kind)? = raw["kind"]
    else { return nil }
    let input: [String: String]?
    if case let .object(values)? = raw["input"] {
        input = values.mapValues(\.text)
    } else {
        input = nil
    }
    return LangGraphNodePresentation(
        kind: kind,
        title: raw["title"]?.text,
        toolName: raw["tool_name"]?.text,
        state: raw["state"]?.text,
        input: input,
        output: raw["output"]?.text,
        error: raw["error"]?.text,
        before: raw["before"]?.text,
        after: raw["after"]?.text
    )
}
