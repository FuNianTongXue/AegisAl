import AppKit
import SwiftUI
import UniformTypeIdentifiers

private let taskSourceExtensions: Set<String> = [
    "java", "py", "go", "c", "h", "cc", "cpp", "cxx", "hh", "hpp", "hxx", "cs", "rs", "sol",
]

private let taskManifestFileNames: Set<String> = [
    "pom.xml", "libs.versions.toml", "gradle.properties",
    "requirements.txt", "pyproject.toml", "pipfile", "poetry.lock",
    "go.mod", "go.sum", "cmakelists.txt", "conanfile.txt", "vcpkg.json",
    "conan.lock", "vcpkg-configuration.json", "meson.build",
    "directory.packages.props", "directory.build.props", "packages.lock.json", "packages.config", "project.assets.json",
    "cargo.toml", "cargo.lock", "foundry.toml", "remappings.txt", "package.json",
    "hardhat.config.js", "hardhat.config.ts", "truffle-config.js",
]

private let taskManifestExtensions: Set<String> = [
    "xml", "gradle", "kts", "properties", "txt", "toml", "lock", "mod", "sum", "json", "js", "ts",
    "csproj", "props", "config", "wrap",
]

private let taskWorkspaceContentTypes: [UTType] = {
    var types: [UTType] = [.folder, .item]
    for ext in taskSourceExtensions.union(taskManifestExtensions).sorted() {
        if let type = UTType(filenameExtension: ext), !types.contains(type) {
            types.append(type)
        }
    }
    return types
}()

private struct AssistantConversationScrollObserver: NSViewRepresentable {
    let scrollRequest: Int
    let onFollowingChange: (Bool) -> Void

    func makeNSView(context: Context) -> AssistantConversationScrollObservationView {
        let view = AssistantConversationScrollObservationView()
        view.onFollowingChange = onFollowingChange
        view.requestScrollToBottom(scrollRequest)
        return view
    }

    func updateNSView(_ nsView: AssistantConversationScrollObservationView, context: Context) {
        nsView.onFollowingChange = onFollowingChange
        nsView.installIfNeeded()
        nsView.requestScrollToBottom(scrollRequest)
    }
}

private final class AssistantConversationScrollObservationView: NSView {
    var onFollowingChange: ((Bool) -> Void)?

    private weak var observedScrollView: NSScrollView?
    private var boundsObserver: NSObjectProtocol?
    private var lastReportedValue: Bool?
    private var pendingReportedValue: Bool?
    private var reportIsScheduled = false
    private var lastScrollRequest = 0
    private var pendingScrollRequest: Int?
    private var scrollIsScheduled = false

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        DispatchQueue.main.async { [weak self] in
            self?.installIfNeeded()
        }
    }

    func installIfNeeded() {
        guard let scrollView = enclosingScrollView else { return }
        guard observedScrollView !== scrollView else { return }

        removeObservation()
        observedScrollView = scrollView
        scrollView.contentView.postsBoundsChangedNotifications = true
        boundsObserver = NotificationCenter.default.addObserver(
            forName: NSView.boundsDidChangeNotification,
            object: scrollView.contentView,
            queue: .main
        ) { [weak self] _ in
            self?.reportCurrentPosition()
        }
        reportCurrentPosition()
    }

    func requestScrollToBottom(_ request: Int) {
        guard request > 0, request != lastScrollRequest else { return }
        lastScrollRequest = request
        pendingScrollRequest = request
        scheduleScrollIfNeeded()
    }

    private func scheduleScrollIfNeeded() {
        guard pendingScrollRequest != nil, !scrollIsScheduled else { return }
        scrollIsScheduled = true
        DispatchQueue.main.async { [weak self] in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.scrollIsScheduled = false
                self.installIfNeeded()
                guard self.pendingScrollRequest != nil else { return }
                self.pendingScrollRequest = nil
                self.scrollToBottom()
            }
        }
    }

    private func scrollToBottom() {
        guard let scrollView = observedScrollView else { return }
        scrollToVisible(bounds.insetBy(dx: 0, dy: -1))
        scrollView.reflectScrolledClipView(scrollView.contentView)
        reportCurrentPosition()
    }

    private func reportCurrentPosition() {
        guard let scrollView = observedScrollView,
              let documentView = scrollView.documentView
        else { return }
        let followsBottom = assistantConversationScrollFollowState(
            documentMaxY: documentView.bounds.maxY,
            visibleMaxY: scrollView.documentVisibleRect.maxY,
            currentlyFollowing: lastReportedValue
        )
        guard followsBottom != lastReportedValue else { return }
        lastReportedValue = followsBottom
        pendingReportedValue = followsBottom
        guard !reportIsScheduled else { return }
        reportIsScheduled = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.reportIsScheduled = false
            guard let value = self.pendingReportedValue else { return }
            self.pendingReportedValue = nil
            self.onFollowingChange?(value)
        }
    }

    private func removeObservation() {
        if let boundsObserver {
            NotificationCenter.default.removeObserver(boundsObserver)
        }
        boundsObserver = nil
        observedScrollView = nil
        lastReportedValue = nil
        pendingReportedValue = nil
    }

    deinit {
        removeObservation()
    }
}

func assistantConversationIsNearBottom(
    bottomY: CGFloat,
    viewportHeight: CGFloat,
    tolerance: CGFloat = 120
) -> Bool {
    guard bottomY.isFinite, viewportHeight > 0 else { return false }
    return bottomY <= viewportHeight + tolerance
}

func assistantConversationScrollIsNearBottom(
    documentMaxY: CGFloat,
    visibleMaxY: CGFloat,
    tolerance: CGFloat = 120
) -> Bool {
    guard documentMaxY.isFinite, visibleMaxY.isFinite else { return false }
    return documentMaxY - visibleMaxY <= tolerance
}

func assistantConversationScrollFollowState(
    documentMaxY: CGFloat,
    visibleMaxY: CGFloat,
    currentlyFollowing: Bool?,
    tolerance: CGFloat = 120,
    hysteresis: CGFloat = 24
) -> Bool {
    guard documentMaxY.isFinite, visibleMaxY.isFinite else {
        return currentlyFollowing ?? false
    }
    let distance = documentMaxY - visibleMaxY
    guard let currentlyFollowing else { return distance <= tolerance }
    let threshold = currentlyFollowing ? tolerance + hysteresis : tolerance - hysteresis
    return distance <= threshold
}

func isMeaningfulAssistantQuestion(_ value: String) -> Bool {
    value.unicodeScalars.contains { CharacterSet.alphanumerics.contains($0) }
}

func assistantSystemDirectory(
    for destinationHint: String?,
    fileManager: FileManager = .default
) -> URL? {
    switch destinationHint?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
    case "desktop":
        return fileManager.urls(for: .desktopDirectory, in: .userDomainMask).first
    case "downloads":
        return fileManager.urls(for: .downloadsDirectory, in: .userDomainMask).first
    case "documents":
        return fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
    default:
        return nil
    }
}

func automaticAssistantArtifactDestination(
    fileName: String,
    destinationHint: String?,
    fileManager: FileManager = .default
) -> URL? {
    guard let directory = assistantSystemDirectory(for: destinationHint, fileManager: fileManager) else { return nil }
    let safeName = (fileName as NSString).lastPathComponent
    guard !safeName.isEmpty, safeName != ".", safeName != ".." else { return nil }
    return directory.appendingPathComponent(safeName, isDirectory: false)
}

struct AssistantNaturalInterruptDecision: Equatable {
    let confirm: Bool
    let destinationHint: String?
}

func assistantNaturalInterruptDecision(_ value: String) -> AssistantNaturalInterruptDecision? {
    let normalized = value
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
        .replacingOccurrences(of: " ", with: "")
    guard !normalized.isEmpty else { return nil }

    let cancellationPhrases: Set<String> = [
        "取消", "不要", "不用", "暂不", "暂不生成", "暂不下载", "否", "no", "cancel",
    ]
    if cancellationPhrases.contains(normalized) {
        return AssistantNaturalInterruptDecision(confirm: false, destinationHint: nil)
    }

    let destinations: [(String, [String])] = [
        ("downloads", ["下载目录", "下载文件夹", "downloads", "downloadsfolder"]),
        ("desktop", ["桌面", "desktop"]),
        ("documents", ["文稿目录", "文档目录", "documents", "documentsfolder"]),
    ]
    let hasDestinationAction = ["下载到", "保存到", "放到", "saveto", "downloadto"].contains(where: normalized.contains)
    for (hint, phrases) in destinations {
        if phrases.contains(normalized) || (hasDestinationAction && phrases.contains(where: normalized.contains)) {
            return AssistantNaturalInterruptDecision(confirm: true, destinationHint: hint)
        }
    }

    let confirmationPhrases: Set<String> = [
        "确认", "确定", "是", "好", "好的", "可以", "继续", "生成", "下载", "确认生成", "确认下载", "yes", "ok",
    ]
    guard confirmationPhrases.contains(normalized) else { return nil }
    return AssistantNaturalInterruptDecision(confirm: true, destinationHint: nil)
}

func assistantMostRecentVulnerabilityIdentifier(in turns: [ConversationTurn]) -> String? {
    let pattern = try? NSRegularExpression(pattern: #"\b(?:CVE-\d{4}-\d{4,8}|GHSA-[A-Za-z0-9-]+)\b"#)
    for turn in turns.reversed() {
        guard let card = turn.answer?.vulnerabilityCard else { continue }
        let candidate = card["漏洞编号"] ?? card["Vulnerability ID"] ?? ""
        let range = NSRange(candidate.startIndex..<candidate.endIndex, in: candidate)
        guard let match = pattern?.firstMatch(in: candidate, range: range),
              let swiftRange = Range(match.range, in: candidate)
        else { continue }
        return String(candidate[swiftRange]).uppercased()
    }
    return nil
}

struct AssistantView: View {
    @EnvironmentObject private var model: AppModel
    private let loadsAgentTasks: Bool
    private let newTaskRequest: Int
    @State private var question = ""
    @State private var askTask: Task<Void, Never>?
    @State private var workspaceActionTask: Task<Void, Never>?
    @State private var taskWorkspacePath = ""
    @State private var isSelectingTaskWorkspace = false
    @State private var isTaskDropTargeted = false
    @State private var taskScrollRequest = 0
    @State private var followsConversationBottom = true
    @FocusState private var isComposerFocused: Bool

    init(
        loadsAgentTasks: Bool = true,
        initialTaskWorkspacePath: String = "",
        newTaskRequest: Int = 0
    ) {
        self.loadsAgentTasks = loadsAgentTasks
        self.newTaskRequest = newTaskRequest
        _taskWorkspacePath = State(initialValue: initialTaskWorkspacePath)
    }

    var body: some View {
        FeatureStoreObserver(
            assistant: model.assistantStore,
            agentTasks: model.agentTaskStore
        ) {
            assistantContent
        }
    }

    private var assistantContent: some View {
        VStack(spacing: 0) {
            if let task = model.activeAgentTask {
                contextHeader(for: task)
            }
            conversation
            composer
        }
        .background { AppWorkspaceBackground() }
        .foregroundStyle(AppPalette.text)
        .fileImporter(
            isPresented: $isSelectingTaskWorkspace,
            allowedContentTypes: taskWorkspaceContentTypes,
            allowsMultipleSelection: false,
            onCompletion: selectTaskWorkspace
        )
        .task {
            guard loadsAgentTasks else { return }
            await model.loadAgentTasks()
        }
        .task(id: model.activeAgentTask?.id) {
            guard let task = model.activeAgentTask, task.isActive else { return }
            await model.followAgentTask(id: task.id)
        }
        .onAppear {
            guard model.activeAgentTask == nil else { return }
            isComposerFocused = true
        }
        .onChange(of: newTaskRequest) { _, _ in
            question = ""
            taskWorkspacePath = ""
            isComposerFocused = true
        }
    }

    private func contextHeader(for task: AgentTaskSnapshot) -> some View {
        HStack(spacing: 16) {
            Spacer()
            Label(model.uiText(taskHistoryStatusLabel(task.status)), systemImage: taskHistoryStatusIcon(task.status))
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(taskHistoryStatusColor(task.status))
        }
        .padding(.horizontal, 30)
        .frame(height: 54)
        .background(.ultraThinMaterial)
        .background(AppPalette.page.opacity(0.24))
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(AppPalette.separator.opacity(0.36))
                .frame(height: 1)
        }
    }

    private var conversation: some View {
        ScrollView {
            LazyVStack(spacing: 24) {
                if model.conversationTurns.isEmpty && !model.isAsking {
                    Color.clear.frame(height: 260)
                }

                ForEach(model.conversationTurns) { turn in
                    AssistantConversationTurnRow(
                        turn: turn,
                        task: turn.agentTaskID.flatMap { taskID in
                            model.allAgentTasks.first(where: { $0.id == taskID })
                        },
                        isRegenerateDisabled: model.isAsking || askTask != nil || workspaceActionTask != nil,
                        onRegenerate: { regenerate(turn.id) },
                        onContinue: {
                            question = model.uiText("请继续回答，并补充尚未覆盖的风险与修复建议。")
                            isComposerFocused = true
                        },
                        onInterruptDecision: { interrupt, confirm, format in
                            handleInterruptDecision(
                                turnID: turn.id,
                                interrupt: interrupt,
                                confirm: confirm,
                                format: format
                            )
                        }
                    )
                    .id(turn.id)
                }

                AssistantConversationScrollObserver(
                    scrollRequest: taskScrollRequest,
                    onFollowingChange: { followsBottom in
                    if followsBottom != followsConversationBottom {
                        followsConversationBottom = followsBottom
                    }
                })
                .frame(height: 1)
            }
            .padding(.horizontal, 30)
            .padding(.top, 12)
            .padding(.bottom, 20)
            .frame(maxWidth: 1160)
            .frame(maxWidth: .infinity)
        }
        .onChange(of: model.sessionID) { _, _ in
            followsConversationBottom = true
            requestConversationScroll()
        }
        .onChange(of: model.conversationTurns.count) { _, _ in
            requestConversationScrollIfFollowing()
        }
        .onChange(of: model.isAsking) { _, _ in
            requestConversationScrollIfFollowing()
        }
        .onChange(of: model.activeTrace.count) { _, _ in
            requestConversationScrollIfFollowing()
        }
        .onChange(of: model.activeAgentTask?.updatedAt) { _, _ in
            requestConversationScrollIfFollowing()
        }
    }

    private func requestConversationScrollIfFollowing() {
        guard followsConversationBottom else { return }
        requestConversationScroll()
    }

    private func requestConversationScroll() {
        taskScrollRequest &+= 1
    }

    private var composer: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                if !taskWorkspacePath.isEmpty {
                    WorkspaceTaskChip(path: taskWorkspacePath) {
                        withAnimation(.easeOut(duration: 0.16)) {
                            taskWorkspacePath = ""
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.top, 12)
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }

                AssistantComposerSuggestionsView(
                    suggestions: assistantComposerSuggestions(for: question),
                    select: { suggestion in
                        question = model.uiText(suggestion.replacement)
                        isComposerFocused = true
                    }
                )

                TextField(
                    model.uiText(
                        taskWorkspacePath.isEmpty
                            ? "输入安全问题，获取智能分析…"
                            : "例如：扫描当前所选内容并汇总代码风险"
                    ),
                    text: $question,
                    axis: .vertical
                )
                .textFieldStyle(.plain)
                .font(AppTypography.body)
                .foregroundStyle(AppPalette.text)
                .lineLimit(1...5)
                .focused($isComposerFocused)
                .padding(.horizontal, 16)
                .padding(.top, taskWorkspacePath.isEmpty ? 15 : 10)
                .padding(.bottom, 11)
                .onSubmit(submit)
                .accessibilityIdentifier("assistant-prompt-field")

                HStack(spacing: 10) {
                    Button {
                        isSelectingTaskWorkspace = true
                    } label: {
                        Image(systemName: "plus")
                            .font(AppTypography.system(size: 15, weight: .semibold))
                            .foregroundStyle(taskWorkspacePath.isEmpty ? AppPalette.text : AppPalette.primaryStrong)
                            .frame(width: 34, height: 34)
                            .background(
                                Circle().fill(
                                    isTaskDropTargeted
                                        ? AppPalette.primary.opacity(0.16)
                                        : AppPalette.cardMuted
                                )
                            )
                            .overlay {
                                Circle().stroke(
                                    isTaskDropTargeted ? AppPalette.primary : AppPalette.border.opacity(0.9)
                                )
                            }
                    }
                    .buttonStyle(.plain)
                    .help(model.uiText("选择或拖入项目目录、代码文件"))
                    .accessibilityIdentifier("assistant-task-workspace-button")

                    Spacer(minLength: 12)

                    Button(action: model.isAsking ? cancelCurrentRequest : submit) {
                        HStack(spacing: 7) {
                            Image(systemName: model.isAsking ? "stop.fill" : "arrow.up")
                                .font(AppTypography.system(size: 14, weight: .bold))
                            if model.isAsking {
                                Text(model.uiText("停止分析"))
                                    .font(AppTypography.caption.weight(.semibold))
                            }
                        }
                        .foregroundStyle(model.isAsking || canSubmit ? Color.white : AppPalette.textSubtle)
                        .frame(width: model.isAsking ? 104 : 36, height: 36)
                        .background {
                            Capsule().fill(
                                model.isAsking
                                    ? AppPalette.brandNavy
                                    : (canSubmit ? AppPalette.primary : AppPalette.cardMuted)
                            )
                        }
                        .overlay {
                            if !model.isAsking && !canSubmit {
                                Capsule().stroke(AppPalette.border.opacity(0.9))
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(!model.isAsking && !canSubmit)
                    .help(
                        model.isAsking
                            ? model.uiText("停止生成")
                            : model.uiText(taskWorkspacePath.isEmpty ? "发送" : "开始执行")
                    )
                    .accessibilityIdentifier("assistant-submit-button")
                }
                .padding(.horizontal, 10)
                .padding(.bottom, 10)
            }
            .frame(minHeight: 108)
            .liquidGlassSurface(
                cornerRadius: 18,
                tint: isTaskDropTargeted ? AppPalette.primary.opacity(0.55) : AppPalette.controlBackground
            )
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(
                        isTaskDropTargeted ? AppPalette.primary : AppPalette.separator.opacity(0.72),
                        lineWidth: isTaskDropTargeted ? 1.5 : 1
                    )
            }
            .shadow(color: Color.black.opacity(0.055), radius: 16, y: 6)
            .frame(maxWidth: 1100)
            .contentShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .onDrop(
                of: [UTType.fileURL.identifier],
                isTargeted: $isTaskDropTargeted,
                perform: handleTaskWorkspaceDrop
            )
            .accessibilityIdentifier("assistant-prompt-composer")
        }
        .padding(.horizontal, 30)
        .padding(.bottom, 18)
        .background { AppWorkspaceBackground() }
    }

    private var canSubmit: Bool {
        if !taskWorkspacePath.isEmpty {
            return isMeaningfulAssistantQuestion(question)
                && workspaceActionTask == nil
                && !model.busyActions.contains("workspace-action-start")
        }
        if let task = model.activeAgentTask {
            return task.result != nil
                && isMeaningfulAssistantQuestion(question)
                && workspaceActionTask == nil
                && !model.busyActions.contains("task-action-start")
        }
        return isMeaningfulAssistantQuestion(question) && !model.isAsking
    }

    private func submit() {
        if !taskWorkspacePath.isEmpty {
            submitAgentTask()
            return
        }
        if let task = model.activeAgentTask {
            submitAgentTaskAction(task)
            return
        }
        let visibleQuestion = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard canSubmit else {
            if !visibleQuestion.isEmpty {
                model.errorMessage = model.uiText("请输入包含文字或数字的具体安全问题")
            }
            return
        }

        if submitNaturalAssistantContinuation(visibleQuestion) {
            return
        }

        let turn = ConversationTurn(question: visibleQuestion)
        followsConversationBottom = true
        model.conversationTurns.append(turn)
        question = ""

        startAssistantRequest(turnID: turn.id, question: visibleQuestion)
    }

    private func regenerate(_ turnID: UUID) {
        guard askTask == nil,
              let index = model.conversationTurns.firstIndex(where: { $0.id == turnID }),
              let visibleQuestion = assistantRegenerationQuestion(
                  for: model.conversationTurns[index],
                  isBusy: model.isAsking
              )
        else { return }

        model.conversationTurns[index].answer = nil
        model.conversationTurns[index].answeredAt = nil
        model.conversationTurns[index].errorMessage = nil
        model.conversationTurns[index].processingTrace = []
        model.conversationTurns[index].streamedAnswer = ""
        model.conversationTurns[index].responseStartedAt = Date()
        followsConversationBottom = true
        startAssistantRequest(turnID: turnID, question: visibleQuestion)
    }

    private func startAssistantRequest(turnID: UUID, question: String) {
        guard askTask == nil else { return }
        askTask = Task { @MainActor in
            defer { askTask = nil }
            let result = await model.ask(
                question: question,
                topK: 8,
                onTrace: { items in
                    guard let index = model.conversationTurns.firstIndex(where: { $0.id == turnID }) else { return }
                    model.conversationTurns[index].processingTrace = mergingTraceItems(
                        model.conversationTurns[index].processingTrace,
                        updates: items
                    )
                },
                onContent: { delta in
                    guard let index = model.conversationTurns.firstIndex(where: { $0.id == turnID }) else { return }
                    model.conversationTurns[index].streamedAnswer.append(delta)
                }
            )
            guard let index = model.conversationTurns.firstIndex(where: { $0.id == turnID }) else { return }
            model.conversationTurns[index].answeredAt = Date()
            if let result {
                model.conversationTurns[index].answer = result
                model.conversationTurns[index].streamedAnswer = result.summary
                if let task = result.agentTask {
                    model.conversationTurns[index].agentTaskID = task.id
                    model.conversationTurns[index].showsAgentTaskWorkflow = true
                    taskScrollRequest += 1
                }
            } else {
                model.conversationTurns[index].errorMessage = model.errorMessage ?? model.uiText("本地安全分析暂时不可用。")
            }
        }
    }

    private func cancelCurrentRequest() {
        askTask?.cancel()
    }

    private func handleInterruptDecision(
        turnID: UUID,
        interrupt: ReportInterruptEnvelope,
        confirm: Bool,
        format: ReportDownloadFormat?,
        requestedDestinationHint: String? = nil
    ) {
        Task { @MainActor in
            var effectiveConfirmation = confirm
            var destination: URL?
            var pendingArtifact: AssistantArtifact?
            if ["component_excel_download_confirmation", "sbom_excel_download_confirmation"].contains(interrupt.kind), confirm {
                pendingArtifact = componentExcelArtifact(for: turnID, interrupt: interrupt)
                if let pendingArtifact {
                    destination = automaticAssistantArtifactDestination(
                        fileName: pendingArtifact.fileName,
                        destinationHint: requestedDestinationHint ?? interrupt.destinationHint
                    ) ?? chooseExcelArtifactDestination(for: pendingArtifact)
                    effectiveConfirmation = destination != nil
                } else {
                    effectiveConfirmation = false
                    model.errorMessage = model.uiText("未找到等待下载的组件漏洞 Excel")
                }
            }

            guard let resumed = await model.resumeAssistantInterrupt(
                interrupt,
                confirm: effectiveConfirmation,
                format: format
            ), let index = model.conversationTurns.firstIndex(where: { $0.id == turnID })
            else { return }
            model.conversationTurns[index].answer = resumed
            model.conversationTurns[index].answeredAt = Date()

            if effectiveConfirmation,
               let requestedDestinationHint,
               let nextInterrupt = resumed.interrupt,
               ["component_excel_download_confirmation", "sbom_excel_download_confirmation"].contains(nextInterrupt.kind),
               let artifact = resumed.artifacts.first(where: { artifact in
                   let artifactIDs = Set(nextInterrupt.artifactIds ?? [])
                   return artifact.kind == "excel" && (artifactIDs.isEmpty || artifactIDs.contains(artifact.id))
               }),
               let chainedDestination = automaticAssistantArtifactDestination(
                   fileName: artifact.fileName,
                   destinationHint: requestedDestinationHint
               )
            {
                guard let completed = await model.resumeAssistantInterrupt(
                    nextInterrupt,
                    confirm: true,
                    format: nil
                ) else { return }
                model.conversationTurns[index].answer = completed
                model.conversationTurns[index].answeredAt = Date()
                let artifactIDs = Set(nextInterrupt.artifactIds ?? [])
                let completedArtifact = completed.artifacts.first(where: {
                    artifactIDs.isEmpty || artifactIDs.contains($0.id)
                }) ?? artifact
                await model.downloadAssistantArtifact(completedArtifact, to: chainedDestination)
                return
            }

            guard effectiveConfirmation, let destination else { return }
            let artifactIDs = Set(interrupt.artifactIds ?? [])
            let artifact = resumed.artifacts.first(where: { artifactIDs.isEmpty || artifactIDs.contains($0.id) })
                ?? pendingArtifact
            if let artifact {
                let saved = await model.downloadAssistantArtifact(artifact, to: destination)
                if !saved,
                   automaticAssistantArtifactDestination(
                       fileName: artifact.fileName,
                       destinationHint: requestedDestinationHint ?? interrupt.destinationHint
                   ) != nil,
                   let fallback = chooseExcelArtifactDestination(for: artifact) {
                    await model.downloadAssistantArtifact(artifact, to: fallback)
                }
            }
        }
    }

    private func submitNaturalAssistantContinuation(_ visibleQuestion: String) -> Bool {
        guard let decision = assistantNaturalInterruptDecision(visibleQuestion) else { return false }

        if let pendingTurn = model.conversationTurns.reversed().first(where: { $0.answer?.interrupt != nil }),
           let interrupt = pendingTurn.answer?.interrupt
        {
            question = ""
            handleInterruptDecision(
                turnID: pendingTurn.id,
                interrupt: interrupt,
                confirm: decision.confirm,
                format: nil,
                requestedDestinationHint: decision.destinationHint
            )
            return true
        }

        guard decision.confirm,
              let destinationHint = decision.destinationHint,
              let identifier = assistantMostRecentVulnerabilityIdentifier(in: model.conversationTurns),
              let destination = automaticAssistantArtifactDestination(
                  fileName: "\(identifier)_组件漏洞清单.xlsx",
                  destinationHint: destinationHint
              )
        else { return false }

        let turn = ConversationTurn(question: visibleQuestion)
        followsConversationBottom = true
        model.conversationTurns.append(turn)
        question = ""
        askTask = Task { @MainActor in
            defer { askTask = nil }
            let saved = await model.downloadVulnerabilityComponents(identifier: identifier, to: destination)
            guard let index = model.conversationTurns.firstIndex(where: { $0.id == turn.id }) else { return }
            model.conversationTurns[index].answeredAt = Date()
            if saved {
                let generatedAt = ISO8601DateFormatter().string(from: Date())
                let summary = model.uiText("Excel 已保存到 %@", destination.path)
                let trace = TraceItem(
                    node: "vulnerability_component_export",
                    status: "completed",
                    message: summary,
                    time: generatedAt
                )
                model.conversationTurns[index].processingTrace = [trace]
                model.conversationTurns[index].streamedAnswer = summary
                model.conversationTurns[index].answer = AskResult(
                    localSummary: summary,
                    mode: "vulnerability_component_export",
                    fields: [
                        "漏洞编号": identifier,
                        "下载路径": destination.path,
                        "文件状态": "已写入并校验",
                    ],
                    trace: [trace],
                    generatedAt: generatedAt
                )
            } else {
                model.conversationTurns[index].errorMessage = model.errorMessage ?? model.uiText("Excel 生成或保存失败。")
            }
        }
        return true
    }

    private func componentExcelArtifact(
        for turnID: UUID,
        interrupt: ReportInterruptEnvelope
    ) -> AssistantArtifact? {
        guard let answer = model.conversationTurns.first(where: { $0.id == turnID })?.answer else { return nil }
        let artifactIDs = Set(interrupt.artifactIds ?? [])
        return answer.artifacts.first { artifact in
            artifact.kind == "excel" && (artifactIDs.isEmpty || artifactIDs.contains(artifact.id))
        }
    }

    private func excelArtifactDestination(
        for artifact: AssistantArtifact,
        interrupt: ReportInterruptEnvelope
    ) -> URL? {
        automaticAssistantArtifactDestination(
            fileName: artifact.fileName,
            destinationHint: interrupt.destinationHint
        ) ?? chooseExcelArtifactDestination(for: artifact)
    }

    private func chooseExcelArtifactDestination(for artifact: AssistantArtifact) -> URL? {
        let panel = NSSavePanel()
        panel.title = model.uiText(
            artifact.fileName.localizedCaseInsensitiveContains("SBOM")
                ? "下载项目 SBOM Excel"
                : "下载组件漏洞 Excel"
        )
        panel.nameFieldStringValue = artifact.fileName
        panel.canCreateDirectories = true
        if let xlsx = UTType(filenameExtension: "xlsx") {
            panel.allowedContentTypes = [xlsx]
        }
        return panel.runModal() == .OK ? panel.url : nil
    }

    private func submitAgentTask() {
        let objective = question.trimmingCharacters(in: .whitespacesAndNewlines)
        let workspacePath = taskWorkspacePath
        guard workspaceActionTask == nil else { return }
        guard isMeaningfulAssistantQuestion(objective),
              !workspacePath.isEmpty
        else {
            model.errorMessage = model.uiText("请输入包含文字或数字的具体安全问题")
            return
        }

        workspaceActionTask = Task { @MainActor in
            defer { workspaceActionTask = nil }
            guard let result = await model.startAssistantWorkspaceAction(
                objective: objective,
                workspacePath: workspacePath
            ) else { return }
            followsConversationBottom = true
            if let task = result.task {
                model.conversationTurns.append(
                    ConversationTurn(
                        question: objective,
                        attachmentNames: [task.workspaceName],
                        agentTaskID: task.id
                    )
                )
            } else if let answer = result.answer {
                model.conversationTurns.append(
                    ConversationTurn(
                        question: objective,
                        attachmentNames: [(workspacePath as NSString).lastPathComponent],
                        streamedAnswer: answer.summary,
                        answer: answer,
                        answeredAt: Date(),
                        processingTrace: answer.trace
                    )
                )
            }
            question = ""
            taskWorkspacePath = ""
        }
    }

    private func submitAgentTaskAction(_ task: AgentTaskSnapshot) {
        let objective = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard workspaceActionTask == nil,
              task.result != nil,
              isMeaningfulAssistantQuestion(objective)
        else { return }

        let turn = ConversationTurn(
            question: objective,
            attachmentNames: [task.workspaceName],
            agentTaskID: task.id,
            showsAgentTaskWorkflow: false
        )
        model.conversationTurns.append(turn)
        question = ""
        followsConversationBottom = true

        workspaceActionTask = Task { @MainActor in
            defer { workspaceActionTask = nil }
            let result = await model.startAssistantTaskAction(
                objective: objective,
                taskID: task.id
            )
            guard let index = model.conversationTurns.firstIndex(where: { $0.id == turn.id }) else { return }
            guard let result else {
                model.conversationTurns[index].errorMessage = model.errorMessage ?? model.uiText("任务操作暂时不可用。")
                return
            }
            if let rescanned = result.task {
                model.conversationTurns[index].agentTaskID = rescanned.id
                model.conversationTurns[index].showsAgentTaskWorkflow = true
            } else if let answer = result.answer {
                model.conversationTurns[index].streamedAnswer = answer.summary
                model.conversationTurns[index].answer = answer
                model.conversationTurns[index].answeredAt = Date()
                model.conversationTurns[index].processingTrace = answer.trace
            }
            taskScrollRequest += 1
        }
    }

    private func selectTaskWorkspace(_ result: Result<[URL], Error>) {
        do {
            guard let url = try result.get().first else { return }
            try setTaskWorkspace(from: url)
        } catch {
            guard !isExpectedCancellation(error) else { return }
            model.errorMessage = model.uiText("读取所选范围失败：%@", error.localizedDescription)
        }
    }

    private func handleTaskWorkspaceDrop(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first(where: {
            $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
        }) else { return false }

        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, error in
            DispatchQueue.main.async {
                if let error {
                    guard !isExpectedCancellation(error) else { return }
                    model.errorMessage = model.uiText("读取所选范围失败：%@", error.localizedDescription)
                    return
                }
                guard let url = taskDropURL(from: item) else {
                    model.errorMessage = model.uiText("请选择项目目录或支持的代码文件")
                    return
                }
                do {
                    try setTaskWorkspace(from: url)
                } catch {
                    model.errorMessage = model.uiText("读取所选范围失败：%@", error.localizedDescription)
                }
            }
        }
        return true
    }

    private func setTaskWorkspace(from url: URL) throws {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        taskWorkspacePath = try taskWorkspaceRoot(for: url).path
        model.errorMessage = nil
    }

}

private struct AssistantConversationTurnRow: View {
    let turn: ConversationTurn
    let task: AgentTaskSnapshot?
    let isRegenerateDisabled: Bool
    let onRegenerate: () -> Void
    let onContinue: () -> Void
    let onInterruptDecision: (ReportInterruptEnvelope, Bool, ReportDownloadFormat?) -> Void

    var body: some View {
        VStack(spacing: 24) {
            UserBubble(turn: turn)

            if assistantDisplaysWorkflowNodes(for: turn), let task {
                AgentTaskView(task: task)
                    .id("task-\(task.id)")
                    .accessibilityIdentifier("assistant-agent-task-card")
            } else if assistantDisplaysWorkflowNodes(for: turn) {
                AssistantLoadingBubble(
                    trace: turn.processingTrace,
                    startedAt: turn.responseStartedAt,
                    streamedText: turn.streamedAnswer
                )
            } else if let answer = turn.answer {
                AssistantBubble(
                    answer: answer,
                    trace: turn.processingTrace.isEmpty ? answer.trace : turn.processingTrace,
                    startedAt: turn.responseStartedAt,
                    timestamp: turn.answeredAt ?? turn.askedAt,
                    isRegenerateDisabled: isRegenerateDisabled,
                    onRegenerate: onRegenerate,
                    onContinue: onContinue,
                    onInterruptDecision: onInterruptDecision
                )
            } else if let error = turn.errorMessage {
                VStack(alignment: .leading, spacing: 10) {
                    if !turn.processingTrace.isEmpty {
                        HStack(alignment: .top, spacing: 12) {
                            Color.clear.frame(width: 34, height: 1)
                            AssistantProcessPanel(
                                trace: turn.processingTrace,
                                startedAt: turn.responseStartedAt,
                                endedAt: turn.answeredAt ?? Date(),
                                phase: .failed,
                                initiallyExpanded: false
                            )
                            Spacer()
                        }
                    }
                    AssistantErrorBubble(
                        message: error,
                        timestamp: turn.answeredAt ?? turn.askedAt,
                        isRegenerateDisabled: isRegenerateDisabled,
                        onRegenerate: onRegenerate
                    )
                }
            } else {
                AssistantLoadingBubble(
                    trace: turn.processingTrace,
                    startedAt: turn.responseStartedAt,
                    streamedText: turn.streamedAnswer
                )
            }
        }
    }
}

func assistantRegenerationQuestion(for turn: ConversationTurn, isBusy: Bool) -> String? {
    let question = turn.question.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !isBusy,
          turn.agentTaskID == nil,
          isMeaningfulAssistantQuestion(question)
    else { return nil }
    return question
}

func assistantDisplaysWorkflowNodes(for turn: ConversationTurn) -> Bool {
    turn.agentTaskID != nil && turn.showsAgentTaskWorkflow
}

func taskWorkspaceRoot(for url: URL) throws -> URL {
    let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
    guard values.isSymbolicLink != true else {
        throw CocoaError(.fileReadNoPermission)
    }
    if values.isDirectory == true {
        return url.standardizedFileURL
    }
    let lowerName = url.lastPathComponent.lowercased()
    let lowerExtension = url.pathExtension.lowercased()
    let isSupportedFile = taskSourceExtensions.contains(lowerExtension)
        || taskManifestFileNames.contains(lowerName)
        || lowerName.hasSuffix(".gradle")
        || lowerName.hasSuffix(".gradle.kts")
        || lowerName.hasSuffix(".csproj")
        || lowerName.hasSuffix(".wrap")
    guard values.isRegularFile == true, isSupportedFile
    else {
        throw CocoaError(.fileReadUnsupportedScheme)
    }
    return url.standardizedFileURL
}

private func taskDropURL(from item: NSSecureCoding?) -> URL? {
    if let url = item as? URL {
        return url
    }
    if let url = item as? NSURL {
        return url as URL
    }
    if let data = item as? Data, let text = String(data: data, encoding: .utf8) {
        return URL(string: text.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    if let text = item as? String {
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return URL(string: clean) ?? URL(fileURLWithPath: clean)
    }
    return nil
}

struct TaskHistoryRow: View {
    @EnvironmentObject private var model: AppModel
    let task: AgentTaskSnapshot
    let selected: Bool
    var dark = false
    let onSelect: () -> Void
    let onArchive: () -> Void
    let onDelete: () -> Void
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 5) {
            Button(action: onSelect) {
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: taskHistoryStatusIcon(task.status))
                        .font(AppTypography.system(size: 12, weight: .semibold))
                        .foregroundStyle(taskHistoryStatusColor(task.status))
                        .frame(width: 17, height: 17)
                        .padding(.top, 2)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(task.objective)
                            .font(AppTypography.caption.weight(.semibold))
                            .foregroundStyle(dark ? AppPalette.onBrand : AppPalette.text)
                            .lineLimit(2)
                            .multilineTextAlignment(.leading)
                        HStack(spacing: 5) {
                            Text(task.workspaceName)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer(minLength: 4)
                            Text(taskHistoryRelativeTime(task.updatedAt, locale: model.appLanguage.locale))
                                .lineLimit(1)
                        }
                        .font(AppTypography.caption2)
                        .foregroundStyle(dark ? AppPalette.onBrandMuted : AppPalette.textSubtle)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            HStack(spacing: 1) {
                if task.canArchiveOrDelete {
                    Button(action: onArchive) {
                        Image(systemName: task.isArchived ? "tray.and.arrow.up" : "archivebox")
                            .frame(width: 21, height: 22)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(dark ? AppPalette.onBrandMuted : AppPalette.textMuted)
                    .help(model.uiText(task.isArchived ? "恢复任务" : "归档任务"))
                    .disabled(model.busyActions.contains("agent-task-archive:\(task.id)"))
                    Button(action: onDelete) {
                        Image(systemName: "trash")
                            .frame(width: 21, height: 22)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(AppPalette.danger)
                    .help(model.uiText("删除任务"))
                    .disabled(model.busyActions.contains("agent-task-delete:\(task.id)"))
                }
            }
            .frame(width: 44)
            .opacity((hovering || selected) && task.canArchiveOrDelete ? 1 : 0)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 8)
        .frame(minHeight: 60)
        .background(
            selected
                ? (dark ? Color.white.opacity(0.13) : AppPalette.selectedStrong)
                : (hovering ? (dark ? Color.white.opacity(0.07) : AppPalette.card) : Color.clear)
        )
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .onHover { hovering = $0 }
        .contextMenu {
            if task.canArchiveOrDelete {
                Button(action: onArchive) {
                    Label(
                        model.uiText(task.isArchived ? "恢复任务" : "归档任务"),
                        systemImage: task.isArchived ? "tray.and.arrow.up" : "archivebox"
                    )
                }
                Divider()
                Button(role: .destructive, action: onDelete) {
                    Label(model.uiText("删除任务"), systemImage: "trash")
                }
            } else {
                Text(model.uiText("请先停止任务"))
            }
        }
        .accessibilityIdentifier("assistant-task-history-row-\(task.id)")
    }
}

func taskHistoryStatusLabel(_ status: String) -> String {
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

func taskHistoryStatusIcon(_ status: String) -> String {
    switch status {
    case "queued": return "clock"
    case "running", "cancelling": return "progress.indicator"
    case "completed": return "checkmark.circle.fill"
    case "failed": return "xmark.octagon.fill"
    case "cancelled", "interrupted": return "stop.circle.fill"
    default: return "circle"
    }
}

private func taskHistoryStatusColor(_ status: String) -> Color {
    switch status {
    case "completed": return AppPalette.success
    case "failed": return AppPalette.danger
    case "cancelled", "interrupted", "cancelling": return AppPalette.warning
    case "running": return AppPalette.primary
    default: return AppPalette.textMuted
    }
}

private func taskHistoryRelativeTime(_ value: String, locale: Locale) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    guard let date else { return String(value.prefix(10)) }
    let relative = RelativeDateTimeFormatter()
    relative.locale = locale
    relative.unitsStyle = .short
    return relative.localizedString(for: date, relativeTo: Date())
}

private struct WorkspaceTaskChip: View {
    @EnvironmentObject private var model: AppModel
    let path: String
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: workspaceTaskIcon(path: path))
                .font(AppTypography.system(size: 17, weight: .medium))
                .foregroundStyle(AppPalette.primaryStrong)
                .frame(width: 38, height: 38)
                .background(AppPalette.selectedStrong.opacity(0.82))
                .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))

            VStack(alignment: .leading, spacing: 2) {
                Text(URL(fileURLWithPath: path).lastPathComponent)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(model.uiText(workspaceTaskIsDirectory(path: path) ? "扫描目录" : "扫描文件"))
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }

            Spacer(minLength: 8)

            Button(action: onRemove) {
                Image(systemName: "xmark")
                    .font(AppTypography.system(size: 10, weight: .bold))
                    .foregroundStyle(AppPalette.textMuted)
                    .frame(width: 24, height: 24)
                    .background(AppPalette.cardMuted)
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)
            .help(model.uiText("取消"))
        }
        .frame(maxWidth: 420)
        .accessibilityIdentifier("assistant-workspace-preview")
    }
}

private func workspaceTaskIcon(path: String) -> String {
    workspaceTaskIsDirectory(path: path) ? "folder.badge.gearshape" : "doc.badge.gearshape"
}

private func workspaceTaskIsDirectory(path: String) -> Bool {
    var isDirectory: ObjCBool = false
    return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) && isDirectory.boolValue
}

private struct UserBubble: View {
    @EnvironmentObject private var model: AppModel
    let turn: ConversationTurn

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Spacer(minLength: 150)
            VStack(alignment: .trailing, spacing: 5) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(turn.question)
                        .textSelection(.enabled)
                    if !turn.attachmentNames.isEmpty {
                        VStack(alignment: .leading, spacing: 5) {
                            ForEach(turn.attachmentNames, id: \.self) { attachmentName in
                                Label(
                                    attachmentName,
                                    systemImage: turn.agentTaskID == nil ? "doc.text" : "folder"
                                )
                                    .font(AppTypography.caption)
                                    .lineLimit(1)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 5)
                                    .background(Color.white.opacity(0.16))
                                    .clipShape(RoundedRectangle(cornerRadius: 5))
                            }
                        }
                    }
                }
                .font(AppTypography.callout.weight(.medium))
                .foregroundStyle(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .frame(maxWidth: 620, alignment: .leading)
                .background(AppPalette.brandNavy)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(Color.white.opacity(0.12), lineWidth: 1)
                }
                .shadow(color: AppPalette.brandNavy.opacity(0.12), radius: 8, y: 3)
                .accessibilityIdentifier("assistant-user-message")

                Text(turn.askedAt.chatTime)
                    .font(AppTypography.caption2)
                    .foregroundStyle(AppPalette.textMuted)
            }
            AppUserAvatar(
                displayName: model.currentProfileDisplayName,
                imageData: model.profileAvatarImageData,
                size: 32
            )
        }
    }
}

private struct AssistantBubble: View {
    @EnvironmentObject private var model: AppModel
    let answer: AskResult
    let trace: [TraceItem]
    let startedAt: Date
    let timestamp: Date
    let isRegenerateDisabled: Bool
    let onRegenerate: () -> Void
    let onContinue: () -> Void
    let onInterruptDecision: (ReportInterruptEnvelope, Bool, ReportDownloadFormat?) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            AssistantAvatar()
            VStack(alignment: .leading, spacing: 10) {
                AssistantSecurityStatusBar(
                    answer: answer,
                    trace: trace,
                    startedAt: startedAt,
                    endedAt: timestamp
                )

                if !trace.isEmpty {
                    AssistantProcessPanel(
                        trace: trace,
                        startedAt: startedAt,
                        endedAt: timestamp,
                        phase: .completed,
                        initiallyExpanded: false
                    )
                    AssistantThinkingPanel(trace: trace)
                }

                VStack(alignment: .leading, spacing: 12) {
                    if let interrupt = answer.interrupt {
                        ReportInterruptCard(
                            interrupt: interrupt,
                            isBusy: model.busyActions.contains("report-interrupt:\(interrupt.interruptId)"),
                            decide: { confirm, format in
                                onInterruptDecision(interrupt, confirm, format)
                            }
                        )
                        if !answer.summary.isEmpty { Divider() }
                    }
                    if ["dependency_vulnerability_report", "component_vulnerability_query"].contains(answer.mode) {
                        RichAnswerText(text: answer.summary)
                        if let componentDetail = answer.componentDetail,
                           componentDetail.renderer == "component-vulnerability-detail"
                        {
                            Divider()
                            ComponentVulnerabilityDetailView(payload: componentDetail)
                        }
                        if !answer.artifacts.isEmpty {
                            artifactRows
                        }
                        if let chartData = answer.chartData, chartData.hasContent {
                            Divider()
                            DependencyChartsView(
                                chartData: chartData,
                                presentation: answer.mode == "component_vulnerability_query" ? .componentVulnerability : .dependency
                            )
                        }
                        if let card = answer.vulnerabilityCard, !card.isEmpty {
                            Divider()
                            vulnerabilityReport(card)
                        }
                    } else if let card = answer.vulnerabilityCard, !card.isEmpty {
                        vulnerabilityReport(card)
                    } else {
                        RichAnswerText(text: answer.summary)
                        if !answer.artifacts.isEmpty {
                            artifactRows
                        }
                    }
                }
                .padding(18)
                .frame(maxWidth: usesWideLayout ? 980 : 690, alignment: .leading)
                .background(AppPalette.card)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(AppPalette.border.opacity(0.9), lineWidth: 1)
                }
                .shadow(color: Color.black.opacity(0.045), radius: 10, y: 3)
                .textSelection(.enabled)
                .accessibilityIdentifier("assistant-received-message")

                AssistantSourcesPanel(answer: answer)

                HStack(alignment: .center) {
                    MessageActions(
                        text: answer.summary,
                        isRegenerateDisabled: isRegenerateDisabled,
                        onRegenerate: onRegenerate,
                        onContinue: onContinue
                    )
                    Spacer()
                    Text(timestamp.chatTime)
                        .font(AppTypography.caption2)
                        .foregroundStyle(AppPalette.textMuted)
                }
            }
            .frame(maxWidth: usesWideLayout ? 980 : 690, alignment: .leading)
            Spacer(minLength: 120)
        }
    }

    private var usesWideLayout: Bool {
        answer.chartData?.hasContent == true || answer.componentDetail != nil
    }

    @ViewBuilder
    private var artifactRows: some View {
        Divider()
        ForEach(answer.artifacts) { artifact in
            AssistantArtifactRow(
                artifact: artifact,
                isDownloading: model.isBusy("assistant-artifact:\(artifact.id)"),
                download: { saveArtifact(artifact) }
            )
        }
    }

    @ViewBuilder
    private func vulnerabilityReport(_ card: [String: String]) -> some View {
        Text(model.uiText("%@ 漏洞分析报告", card["漏洞编号"] ?? model.uiText("漏洞")))
            .font(AppTypography.headline)
        Divider()

        VulnerabilityDescriptionField(
            value: card["漏洞描述"] ?? answer.summary,
            score: card["CVSS评分"],
            severity: card["严重等级"]
        )

        VStack(alignment: .leading, spacing: 6) {
            if !componentNodes.isEmpty {
                Text(model.uiText("根据知识图谱分析，您的系统中以下组件可能受到影响："))
            }
        }
        .font(AppTypography.callout)

        VStack(spacing: 8) {
            if let value = normalizedCardValue("组件版本范围", from: card) {
                VulnerabilityReportField(title: model.uiText("组件版本范围"), value: value, icon: "shippingbox", tone: AppPalette.primary)
            }
            if let value = normalizedCardValue("涉及版本", from: card) {
                VulnerabilityReportField(title: model.uiText("涉及版本"), value: value, icon: "exclamationmark.triangle", tone: AppPalette.warning)
            }
            if let value = normalizedCardValue("修复版本", from: card) {
                VulnerabilityReportField(title: model.uiText("修复版本"), value: value, icon: "checkmark.shield", tone: AppPalette.success)
            }
        }

        ForEach(Array(componentNodes.prefix(5).enumerated()), id: \.element.id) { index, node in
            ImpactComponentRow(node: node, critical: index == 0)
        }

        if let solution = card["修复方案"], !solution.isEmpty {
            VulnerabilityReportField(title: model.uiText("修复方案"), value: solution, icon: "wrench.and.screwdriver", tone: AppPalette.success)
        }

        if let mitigation = card["缓释措施"], !mitigation.isEmpty {
            VulnerabilityReportField(title: model.uiText("缓释措施"), value: mitigation, icon: "shield.lefthalf.filled", tone: AppPalette.warning)
        }

        if let references = normalizedCardValue("参考链接", from: card) {
            VulnerabilityReferenceLinks(value: references)
        }

        if let code = normalizedCardValue("代码片段", from: card) {
            VulnerabilityCodeSnippet(title: model.uiText("代码片段"), code: code, tone: AppPalette.danger)
        }

        if let fixedCode = normalizedCardValue("修复代码片段", from: card) {
            VulnerabilityCodeSnippet(title: model.uiText("修复代码片段"), code: fixedCode, tone: AppPalette.success)
        }
    }

    private var componentNodes: [KnowledgeNode] {
        answer.knowledgeGraph?.nodes.filter { $0.type == "component" } ?? []
    }

    private func normalizedCardValue(_ key: String, from card: [String: String]) -> String? {
        guard let value = card[key]?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty,
              !isPlaceholderCardValue(value)
        else {
            return nil
        }
        return value
    }

    private func isPlaceholderCardValue(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return [
            "未明确",
            "未知",
            "Not specified",
            "Unknown",
            "未指定",
            "不明",
            "명확하지 않음",
            "알 수 없음",
            "未在漏洞记录中找到可核验代码片段",
            "未在漏洞记录中找到可核验修复代码片段",
            "No verifiable code snippet was found in the vulnerability record",
            "No verifiable fixed code snippet was found in the vulnerability record",
            "脆弱性レコード内に検証済みコード片は見つかりませんでした",
            "脆弱性レコード内に検証済み修正コード片は見つかりませんでした",
            "취약점 기록에서 검증 가능한 코드 조각을 찾지 못했습니다",
            "취약점 기록에서 검증 가능한 수정 코드 조각을 찾지 못했습니다",
        ].contains(normalized)
    }

    private func saveArtifact(_ artifact: AssistantArtifact) {
        let panel = NSSavePanel()
        panel.title = artifact.kind == "report"
            ? model.uiText("下载分析报告")
            : model.uiText(
                artifact.fileName.localizedCaseInsensitiveContains("SBOM")
                    ? "下载项目 SBOM Excel"
                    : "下载组件漏洞 Excel"
            )
        panel.nameFieldStringValue = artifact.fileName
        panel.canCreateDirectories = true
        if artifact.kind != "report", let xlsx = UTType(filenameExtension: "xlsx") {
            panel.allowedContentTypes = [xlsx]
        }
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        Task { await model.downloadAssistantArtifact(artifact, to: destination) }
    }
}

private struct ReportInterruptCard: View {
    @EnvironmentObject private var model: AppModel
    let interrupt: ReportInterruptEnvelope
    let isBusy: Bool
    let decide: (Bool, ReportDownloadFormat?) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: interruptIcon)
                .font(AppTypography.title3)
                .foregroundStyle(AppPalette.primary)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 5) {
                Text(interrupt.question)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                if let detail = interrupt.detail, !detail.isEmpty {
                    Text(detail)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Text("Interrupt · \(interrupt.interruptId.prefix(12))")
                    .font(AppTypography.caption2.monospaced())
                    .foregroundStyle(AppPalette.textSubtle)
            }
            Spacer(minLength: 16)
            if isBusy {
                ProgressView().controlSize(.small)
            } else if isDownloadConfirmation {
                Button(model.uiText("暂不下载")) { decide(false, nil) }
                    .buttonStyle(.bordered)
                if ["component_excel_download_confirmation", "sbom_excel_download_confirmation"].contains(interrupt.kind) {
                    Button { decide(true, nil) } label: {
                        Label(
                            model.uiText(interrupt.destinationHint == "desktop" ? "下载到桌面" : "选择目录并下载"),
                            systemImage: "arrow.down.doc"
                        )
                    }
                    .buttonStyle(PrimaryActionButtonStyle())
                } else if interrupt.allowFormatSelection == false {
                    Button { decide(true, nil) } label: {
                        Label(model.uiText("确认下载"), systemImage: "arrow.down.doc")
                    }
                    .buttonStyle(PrimaryActionButtonStyle())
                } else {
                    Menu {
                        ForEach(availableFormats) { format in
                            Button(model.uiText("确认下载 %@", format.label)) {
                                decide(true, format)
                            }
                        }
                    } label: {
                        Label(model.uiText("确认下载"), systemImage: "arrow.down.doc")
                    }
                    .buttonStyle(PrimaryActionButtonStyle())
                }
            } else if interrupt.kind == "sbom_vulnerability_match_confirmation" {
                Button(model.uiText("仅导出 SBOM")) { decide(false, nil) }
                    .buttonStyle(.bordered)
                Button { decide(true, nil) } label: {
                    Label(model.uiText("匹配漏洞情报"), systemImage: "shield.lefthalf.filled")
                }
                .buttonStyle(PrimaryActionButtonStyle())
            } else {
                Button(model.uiText("暂不生成")) { decide(false, nil) }
                    .buttonStyle(.bordered)
                Button { decide(true, nil) } label: {
                    Label(
                        model.uiText(["component_excel_generation_confirmation", "sbom_excel_generation_confirmation"].contains(interrupt.kind) ? "生成 Excel" : "生成报告"),
                        systemImage: ["component_excel_generation_confirmation", "sbom_excel_generation_confirmation"].contains(interrupt.kind) ? "tablecells" : "doc.badge.plus"
                    )
                }
                .buttonStyle(PrimaryActionButtonStyle())
            }
        }
        .padding(13)
        .background(AppPalette.primary.opacity(0.07))
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }

    private var availableFormats: [ReportDownloadFormat] {
        let values = Set((interrupt.formats ?? []).map { $0.lowercased() })
        guard !values.isEmpty else { return ReportDownloadFormat.allCases }
        return ReportDownloadFormat.allCases.filter { values.contains($0.rawValue) }
    }

    private var isDownloadConfirmation: Bool {
        ["report_download_confirmation", "component_excel_download_confirmation", "sbom_excel_download_confirmation"].contains(interrupt.kind)
    }

    private var interruptIcon: String {
        switch interrupt.kind {
        case "component_excel_generation_confirmation": "tablecells"
        case "sbom_excel_generation_confirmation": "tablecells.badge.ellipsis"
        case "sbom_vulnerability_match_confirmation": "shield.lefthalf.filled"
        case "report_generation_confirmation": "doc.badge.plus"
        default: "arrow.down.doc"
        }
    }
}

private struct AssistantArtifactRow: View {
    @EnvironmentObject private var model: AppModel
    let artifact: AssistantArtifact
    let isDownloading: Bool
    let download: () -> Void

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: artifact.kind == "report" ? "doc.richtext" : "tablecells")
                .font(AppTypography.system(size: 16, weight: .semibold))
                .foregroundStyle(AppPalette.success)
                .frame(width: 36, height: 36)
                .background(AppPalette.success.opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            VStack(alignment: .leading, spacing: 2) {
                Text(artifact.fileName)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(ByteCountFormatter.string(fromByteCount: Int64(artifact.size), countStyle: .file))
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }

            Spacer(minLength: 12)

            Button(action: download) {
                if isDownloading {
                    ProgressView().controlSize(.small)
                } else {
                    Label(
                        artifact.kind == "report" ? model.uiText("下载报告") : model.uiText("下载全量 Excel"),
                        systemImage: "arrow.down.doc"
                    )
                }
            }
            .buttonStyle(SecondaryActionButtonStyle())
            .disabled(isDownloading)
            .accessibilityIdentifier("assistant-artifact-download")
        }
        .accessibilityIdentifier("assistant-excel-artifact")
    }
}

private struct AssistantLoadingBubble: View {
    @EnvironmentObject private var model: AppModel
    let trace: [TraceItem]
    let startedAt: Date
    let streamedText: String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.5)) { context in
            HStack(alignment: .top, spacing: 12) {
                AssistantAvatar()
                VStack(alignment: .leading, spacing: 10) {
                    AssistantSecurityWorkingHeader(
                        trace: trace,
                        startedAt: startedAt,
                        currentDate: context.date
                    )
                    AssistantProcessPanel(
                        trace: trace,
                        startedAt: startedAt,
                        endedAt: context.date,
                        phase: .running,
                        initiallyExpanded: true
                    )
                    if streamedText.isEmpty {
                        AssistantResponseSkeleton()
                    } else {
                        VStack(alignment: .leading, spacing: 10) {
                            AssistantMarkdownView(markdown: streamedText)
                            HStack(spacing: 7) {
                                ProgressView().controlSize(.mini)
                                Text(model.uiText("正在输出"))
                                    .font(AppTypography.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.primaryStrong)
                            }
                        }
                        .padding(18)
                        .frame(maxWidth: 690, alignment: .leading)
                        .background(AppPalette.card)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(AppPalette.border.opacity(0.9))
                        }
                    }
                }
                .frame(maxWidth: 690, alignment: .leading)
                Spacer()
            }
        }
        .accessibilityIdentifier("assistant-loading-message")
    }
}

private struct AssistantErrorBubble: View {
    let message: String
    let timestamp: Date
    let isRegenerateDisabled: Bool
    let onRegenerate: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            AssistantAvatar()
            VStack(alignment: .leading, spacing: 10) {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(AppTypography.callout)
                    .foregroundStyle(AppPalette.danger)
                    .padding(16)
                    .frame(maxWidth: 690, alignment: .leading)
                    .background(AppPalette.danger.opacity(0.07))
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .stroke(AppPalette.danger.opacity(0.2), lineWidth: 1)
                    }
                    .accessibilityIdentifier("assistant-error-message")
                HStack {
                    MessageActions(
                        text: message,
                        isRegenerateDisabled: isRegenerateDisabled,
                        onRegenerate: onRegenerate
                    )
                    Spacer()
                    Text(timestamp.chatTime)
                        .font(AppTypography.caption2)
                        .foregroundStyle(AppPalette.textMuted)
                }
            }
            .frame(maxWidth: 690, alignment: .leading)
            Spacer()
        }
    }
}

private enum AssistantProcessPhase: Equatable {
    case running
    case completed
    case failed
}

private struct AssistantProcessPanel: View {
    @EnvironmentObject private var model: AppModel
    let trace: [TraceItem]
    let startedAt: Date
    let endedAt: Date
    let phase: AssistantProcessPhase
    @State private var isExpanded: Bool

    init(
        trace: [TraceItem],
        startedAt: Date,
        endedAt: Date,
        phase: AssistantProcessPhase,
        initiallyExpanded: Bool = true
    ) {
        self.trace = trace
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.phase = phase
        _isExpanded = State(initialValue: initiallyExpanded)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.18)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 11) {
                    phaseIcon
                        .frame(width: 22, height: 22)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(summaryText)
                            .font(AppTypography.callout.weight(.semibold))
                            .foregroundStyle(AppPalette.text)
                        Text(detailText)
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                            .lineLimit(1)
                    }

                    Spacer(minLength: 12)
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                        .frame(width: 24, height: 24)
                        .background(AppPalette.cardMuted.opacity(0.7))
                        .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("assistant-process-summary")
            .help(model.uiText(isExpanded ? "收起处理过程" : "查看处理过程"))

            if isExpanded {
                Divider()
                AssistantProcessTimeline(
                    trace: trace,
                    startedAt: startedAt,
                    isRunning: phase == .running
                )
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .frame(maxWidth: 690, alignment: .leading)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(AppPalette.border)
        }
        .accessibilityIdentifier("assistant-process-panel")
    }

    @ViewBuilder
    private var phaseIcon: some View {
        switch phase {
        case .running:
            ProgressView()
                .controlSize(.small)
                .tint(AppPalette.primary)
        case .completed:
            Image(systemName: trace.contains(where: { $0.status.lowercased() == "warning" })
                ? "exclamationmark.circle.fill"
                : "checkmark.circle.fill")
                .font(AppTypography.system(size: 18, weight: .semibold))
                .foregroundStyle(trace.contains(where: { $0.status.lowercased() == "warning" }) ? AppPalette.warning : AppPalette.success)
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(AppTypography.system(size: 18, weight: .semibold))
                .foregroundStyle(AppPalette.danger)
        }
    }

    private var elapsedSeconds: Int {
        max(0, Int(endedAt.timeIntervalSince(startedAt)))
    }

    private var summaryText: String {
        switch phase {
        case .running:
            model.uiText("正在处理 · %d 个步骤 · %d 秒", trace.count, elapsedSeconds)
        case .completed:
            model.uiText("已完成 · %d 个步骤 · %d 秒", trace.count, elapsedSeconds)
        case .failed:
            model.uiText("处理失败 · %d 个步骤 · %d 秒", trace.count, elapsedSeconds)
        }
    }

    private var detailText: String {
        if let latest = trace.last {
            return model.localizedMessage(latest.message) ?? latest.message
        }
        return phase == .running ? model.uiText("正在启动分析流程") : model.uiText("处理过程暂无可用步骤")
    }
}

private struct AssistantProcessTimeline: View {
    @EnvironmentObject private var model: AppModel
    let trace: [TraceItem]
    let startedAt: Date
    let isRunning: Bool
    @State private var expandedStepIDs: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(trace.enumerated()), id: \.element.id) { index, item in
                HStack(alignment: .top, spacing: 12) {
                    ZStack(alignment: .top) {
                        if index < trace.count - 1 || isRunning {
                            Rectangle()
                                .fill(AppPalette.border.opacity(0.8))
                                .frame(width: 2)
                                .padding(.top, 23)
                                .frame(maxHeight: .infinity)
                        }
                        stepIcon(for: item)
                    }
                    .frame(width: 24)

                    VStack(alignment: .leading, spacing: 0) {
                        Button {
                            withAnimation(.easeInOut(duration: 0.18)) {
                                toggleStep(item.id)
                            }
                        } label: {
                            HStack(spacing: 8) {
                                Text(nodeLabel(item.node, language: model.appLanguage))
                                    .font(AppTypography.callout.weight(stepTitleWeight(item.status)))
                                    .foregroundStyle(stepTitleColor(item.status))
                                    .lineLimit(2)
                                Spacer(minLength: 8)
                                if let duration = stepDuration(at: index) {
                                    Text(duration)
                                        .font(AppTypography.caption2.monospacedDigit())
                                        .foregroundStyle(AppPalette.textSubtle)
                                }
                                Image(systemName: expandedStepIDs.contains(item.id) ? "chevron.down" : "chevron.right")
                                    .font(AppTypography.caption2.weight(.semibold))
                                    .foregroundStyle(AppPalette.textSubtle)
                                    .frame(width: 16)
                            }
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("assistant-workflow-step-\(index)")

                        if expandedStepIDs.contains(item.id) {
                            HStack(alignment: .top, spacing: 9) {
                                Rectangle()
                                    .fill(StatusTone.operation(item.status).color.opacity(0.7))
                                    .frame(width: 2)
                                VStack(alignment: .leading, spacing: 7) {
                                    HStack(spacing: 7) {
                                        Image(systemName: workflowNodeIcon(item.node))
                                            .foregroundStyle(StatusTone.operation(item.status).color)
                                        Text(model.localizedMessage(item.message) ?? item.message)
                                            .font(AppTypography.caption)
                                            .foregroundStyle(AppPalette.textMuted)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                    if let presentation = item.presentation {
                                        LangGraphNodePresentationView(presentation: presentation)
                                            .environmentObject(model)
                                            .padding(.top, 2)
                                    }
                                    HStack(spacing: 8) {
                                        Text(item.node)
                                            .font(AppTypography.caption2.monospaced())
                                            .foregroundStyle(AppPalette.textSubtle)
                                            .textSelection(.enabled)
                                        Spacer(minLength: 8)
                                        Text(traceTime(item.time))
                                            .font(AppTypography.caption2.monospacedDigit())
                                            .foregroundStyle(AppPalette.textSubtle)
                                    }
                                }
                            }
                            .padding(.leading, 7)
                            .padding(.top, 7)
                            .transition(.opacity.combined(with: .move(edge: .top)))
                            .accessibilityIdentifier("assistant-workflow-step-detail-\(index)")
                        }
                    }
                    .padding(.bottom, 14)
                    Spacer(minLength: 0)
                }
            }

            if isRunning {
                HStack(alignment: .center, spacing: 10) {
                    ProgressView().controlSize(.mini)
                        .frame(width: 24, height: 24)
                    Text(trace.isEmpty ? model.uiText("正在启动分析流程") : model.uiText("正在继续处理"))
                        .font(AppTypography.callout.weight(.semibold))
                        .foregroundStyle(AppPalette.primary)
                }
            }
        }
        .accessibilityIdentifier("assistant-process-timeline")
    }

    private func stepIcon(for item: TraceItem) -> some View {
        let tone = StatusTone.operation(item.status).color
        let symbol: String
        switch item.status.lowercased() {
        case "running", "active": symbol = workflowNodeIcon(item.node)
        case "failed", "error": symbol = "xmark"
        case "warning": symbol = "exclamationmark"
        case "pending", "queued", "graph-node": symbol = workflowNodeIcon(item.node)
        default: symbol = "checkmark"
        }
        return Image(systemName: symbol)
            .font(AppTypography.system(size: 10, weight: .semibold))
            .foregroundStyle(tone)
            .frame(width: 22, height: 22)
            .background(tone.opacity(0.12))
            .clipShape(Circle())
            .overlay {
                Circle().stroke(tone.opacity(0.18), lineWidth: 1)
            }
    }

    private func toggleStep(_ id: String) {
        if expandedStepIDs.contains(id) {
            expandedStepIDs.remove(id)
        } else {
            expandedStepIDs.insert(id)
        }
    }

    private func stepDuration(at index: Int) -> String? {
        guard trace.indices.contains(index), let end = workflowTraceDate(trace[index].time) else { return nil }
        let start: Date?
        if index == 0 {
            start = startedAt <= end ? startedAt : nil
        } else {
            start = workflowTraceDate(trace[index - 1].time)
        }
        guard let start else { return nil }
        let interval = end.timeIntervalSince(start)
        guard interval >= 0, interval < 3_600 else { return nil }
        if interval < 0.05 { return "<0.1s" }
        return String(format: "%.1fs", interval)
    }

    private func traceTime(_ value: String) -> String {
        workflowTraceDate(value)?.formatted(date: .omitted, time: .standard) ?? value
    }

    private func stepTitleWeight(_ status: String) -> Font.Weight {
        switch status.lowercased() {
        case "running", "active", "failed", "error", "warning": .semibold
        default: .medium
        }
    }

    private func stepTitleColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "failed", "error": AppPalette.danger
        case "warning": AppPalette.warning
        case "running", "active": AppPalette.primary
        default: AppPalette.text
        }
    }
}

private func workflowTraceDate(_ value: String) -> Date? {
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
}

private func workflowNodeIcon(_ node: String) -> String {
    switch node {
    case "classify_query": "magnifyingglass"
    case "load_memory_context", "persist_memory": "externaldrive"
    case "component_query.parse_coordinates": "shippingbox"
    case "component_query.query_vulnerabilities", "query_intelligence", "query_sources", "collector.query_api": "shield.lefthalf.filled"
    case "component_query.excel_mcp": "tablecells"
    case "component_query.d3_sankey_mcp", "enrich_knowledge_graph": "point.3.connected.trianglepath.dotted"
    case "run_static_path_analysis": "chevron.left.forwardslash.chevron.right"
    case "call_llm": "brain.head.profile"
    case "compose_answer", "component_query.compose_result", "compose_result": "text.page"
    default: "gearshape.2"
    }
}

private struct AssistantAvatar: View {
    var body: some View {
        AppBrandLogo(size: 34, shadow: false)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(AppBrand.chineseName)
            .accessibilityIdentifier("assistant-brand-avatar")
    }
}

private struct VulnerabilityReportField: View {
    let title: String
    let value: String
    let icon: String
    let tone: Color

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(tone)
                .frame(width: 22, height: 22)
                .background(tone.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.textMuted)
                Text(value)
                    .font(AppTypography.callout)
                    .foregroundStyle(AppPalette.text)
                    .lineSpacing(3)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tone.opacity(0.055))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(tone.opacity(0.18))
        }
    }
}

private struct VulnerabilityDescriptionField: View {
    @EnvironmentObject private var model: AppModel
    let value: String
    let score: String?
    let severity: String?

    @State private var isExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Button {
                withAnimation(.easeInOut(duration: 0.16)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(AppTypography.caption.weight(.bold))
                        .foregroundStyle(AppPalette.textMuted)
                        .frame(width: 12)
                    Text(model.uiText("漏洞描述"))
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                    Spacer()
                    if let score, !score.isEmpty {
                        Text("CVSS \(score) · \(severityText)")
                            .font(AppTypography.caption.weight(.semibold))
                            .foregroundStyle(StatusTone.severity(severity ?? "").color)
                    }
                }
            }
            .buttonStyle(.plain)

            Text(value)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.text)
                .lineSpacing(4)
                .lineLimit(isExpanded ? nil : 3)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.primary.opacity(0.045))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.primary.opacity(0.14))
        }
    }

    private var severityText: String {
        guard let severity, !severity.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return model.uiText("风险待核验")
        }
        return severityLabel(severity, language: model.appLanguage)
    }
}

private struct VulnerabilityCodeSnippet: View {
    let title: String
    let code: String
    let tone: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: "chevron.left.forwardslash.chevron.right")
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(tone)
            Text(code)
                .font(AppTypography.caption.monospaced())
                .foregroundStyle(AppPalette.text)
                .lineSpacing(3)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(AppPalette.cardMuted)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(tone.opacity(0.22))
                }
        }
    }
}

private struct VulnerabilityReferenceLinks: View {
    @EnvironmentObject private var model: AppModel
    let value: String

    private var links: [String] {
        let separators = CharacterSet(charactersIn: "\n,，；; ")
        return value
            .components(separatedBy: separators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.hasPrefix("http://") || $0.hasPrefix("https://") }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(model.uiText("参考链接"), systemImage: "link")
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)

            if links.isEmpty {
                Text(value)
                    .font(AppTypography.callout)
                    .foregroundStyle(AppPalette.textMuted)
            } else {
                VStack(alignment: .leading, spacing: 7) {
                    ForEach(links, id: \.self) { item in
                        if let url = URL(string: item) {
                            Link(destination: url) {
                                HStack(alignment: .firstTextBaseline, spacing: 7) {
                                    Image(systemName: "arrow.up.right.square")
                                        .font(AppTypography.caption)
                                    Text(item)
                                        .font(AppTypography.caption)
                                        .lineLimit(2)
                                }
                                .foregroundStyle(AppPalette.primary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
            }
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.primary.opacity(0.055))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.primary.opacity(0.18))
        }
    }
}

private struct ImpactComponentRow: View {
    @EnvironmentObject private var model: AppModel
    let node: KnowledgeNode
    let critical: Bool

    private var tone: Color { critical ? .red : .orange }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.circle")
                .foregroundStyle(tone)
            Text(node.label)
                .font(AppTypography.callout.weight(.semibold))
                .foregroundStyle(tone)
                .lineLimit(1)
            Spacer(minLength: 12)
            Text(affectedLabel)
                .font(AppTypography.caption)
                .foregroundStyle(AppPalette.textMuted)
                .lineLimit(1)
        }
        .padding(.horizontal, 12)
        .frame(minHeight: 40)
        .background(tone.opacity(0.055))
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .stroke(tone.opacity(0.24))
        }
    }

    private var affectedLabel: String {
        let value = node.metadata["affected"]?.text ?? ""
        return value.isEmpty ? model.uiText("受影响版本待核验") : model.uiText("影响 %@", value)
    }
}

private struct MessageActions: View {
    @EnvironmentObject private var model: AppModel
    let text: String
    let isRegenerateDisabled: Bool
    let onRegenerate: () -> Void
    var onContinue: (() -> Void)? = nil
    @State private var copied = false
    @State private var bookmarked: Bool

    init(
        text: String,
        isRegenerateDisabled: Bool,
        onRegenerate: @escaping () -> Void,
        onContinue: (() -> Void)? = nil
    ) {
        self.text = text
        self.isRegenerateDisabled = isRegenerateDisabled
        self.onRegenerate = onRegenerate
        self.onContinue = onContinue
        _bookmarked = State(initialValue: AssistantMessageBookmarkStore.contains(text))
    }

    var body: some View {
        HStack(spacing: 4) {
            ChatBubbleActionButton(
                systemName: copied ? "checkmark" : "doc.on.doc",
                help: copied ? model.uiText("已复制") : model.uiText("复制"),
                accessibilityIdentifier: "assistant-copy-response",
                disabled: text.isEmpty
            ) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                copied = true
            }

            ChatBubbleActionButton(
                systemName: "arrow.clockwise",
                help: model.uiText("重新生成"),
                accessibilityIdentifier: "assistant-regenerate-response",
                disabled: isRegenerateDisabled,
                action: onRegenerate
            )

            if let onContinue {
                ChatBubbleActionButton(
                    systemName: "text.append",
                    help: model.uiText("继续回答"),
                    accessibilityIdentifier: "assistant-continue-response",
                    disabled: isRegenerateDisabled,
                    action: onContinue
                )
            }

            Menu {
                ForEach(AssistantMessageExportFormat.allCases) { format in
                    Button(model.uiText("导出 %@", format.label)) {
                        do {
                            try exportAssistantMessage(
                                text,
                                format: format,
                                title: model.uiText("导出回答")
                            )
                        } catch {
                            model.errorMessage = model.uiText("导出回答失败：%@", error.localizedDescription)
                        }
                    }
                }
            } label: {
                Image(systemName: "arrow.down.doc")
                    .font(AppTypography.system(size: 12, weight: .medium))
                    .foregroundStyle(AppPalette.textMuted)
                    .frame(width: 28, height: 28)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .frame(width: 28)
            .help(model.uiText("导出回答"))
            .accessibilityIdentifier("assistant-export-response")

            ChatBubbleActionButton(
                systemName: "square.and.arrow.up",
                help: model.uiText("分享"),
                accessibilityIdentifier: "assistant-share-response",
                disabled: text.isEmpty
            ) {
                shareAssistantMessage(text)
            }

            ChatBubbleActionButton(
                systemName: bookmarked ? "bookmark.fill" : "bookmark",
                help: model.uiText(bookmarked ? "取消收藏" : "收藏"),
                accessibilityIdentifier: "assistant-bookmark-response",
                disabled: text.isEmpty
            ) {
                bookmarked.toggle()
                AssistantMessageBookmarkStore.set(bookmarked, text: text)
            }
        }
        .onChange(of: text) { _, newValue in
            copied = false
            bookmarked = AssistantMessageBookmarkStore.contains(newValue)
        }
    }
}

private struct ChatBubbleActionButton: View {
    let systemName: String
    let help: String
    let accessibilityIdentifier: String
    var disabled = false
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(AppTypography.system(size: 12, weight: .medium))
                .foregroundStyle(disabled ? AppPalette.textSubtle : AppPalette.textMuted)
                .frame(width: 28, height: 28)
                .background(isHovered && !disabled ? AppPalette.cardMuted : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .help(help)
        .accessibilityLabel(help)
        .accessibilityIdentifier(accessibilityIdentifier)
        .onHover { isHovered = $0 }
    }
}

private struct RichAnswerText: View {
    let text: String

    var body: some View {
        AssistantMarkdownView(markdown: text)
    }
}

private extension Date {
    var chatTime: String {
        formatted(date: .omitted, time: .shortened)
    }
}
