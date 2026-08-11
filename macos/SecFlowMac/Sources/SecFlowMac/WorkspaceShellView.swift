import AppKit
import SwiftUI

enum WorkspaceDestination: Equatable {
    case assistant
}

enum WorkspaceSidebarItem: CaseIterable, Identifiable {
    case newTask

    var id: Self { self }

    var icon: String {
        switch self {
        case .newTask: "square.and.pencil"
        }
    }

    func title(_ language: AppLanguage) -> String {
        switch self {
        case .newTask: localizedUI("新建任务", language: language)
        }
    }
}

enum WorkspaceSidebarLayout {
    static let expandedWidth: CGFloat = 264
    // Keeps all three native traffic-light buttons inside the navigation rail.
    static let collapsedWidth: CGFloat = 72
    static let animationDuration: Double = 0.18
}

@MainActor
final class WorkspaceSidebarPresentationModel: ObservableObject {
    @Published private(set) var isCollapsed: Bool

    init(isCollapsed: Bool = true) {
        self.isCollapsed = isCollapsed
    }

    func setHovered(_ isHovered: Bool) {
        let shouldCollapse = !isHovered
        guard shouldCollapse != isCollapsed else { return }
        isCollapsed = shouldCollapse
    }
}

@MainActor
final class WorkspaceNavigationModel: ObservableObject {
    static let projectNamesKey = "secflow.workspaceProjectNames"

    @Published var destination: WorkspaceDestination = .assistant
    @Published private(set) var newTaskRequest = 0
    @Published private(set) var projectNames: [String: String]
    let sidebarPresentation: WorkspaceSidebarPresentationModel
    private let defaults: UserDefaults

    var isSidebarCollapsed: Bool { sidebarPresentation.isCollapsed }

    init(
        isSidebarCollapsed: Bool? = nil,
        projectNames: [String: String]? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.defaults = defaults
        self.sidebarPresentation = WorkspaceSidebarPresentationModel(
            isCollapsed: isSidebarCollapsed ?? true
        )
        self.projectNames = projectNames
            ?? defaults.dictionary(forKey: Self.projectNamesKey) as? [String: String]
            ?? [:]
    }

    func show(_ destination: WorkspaceDestination) {
        self.destination = destination
    }

    func startNewTask() {
        destination = .assistant
        newTaskRequest &+= 1
    }

    func setSidebarHovered(_ isHovered: Bool) {
        sidebarPresentation.setHovered(isHovered)
    }

    func projectName(id: String, fallback: String) -> String {
        projectNames[id] ?? fallback
    }

    @discardableResult
    func renameProject(id: String, to candidate: String) -> Bool {
        let name = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !name.isEmpty else { return false }
        projectNames[id] = name
        defaults.set(projectNames, forKey: Self.projectNamesKey)
        return true
    }
}

private struct WorkspaceProjectGroup: Identifiable {
    let id: String
    let title: String
    let tasks: [AgentTaskSnapshot]
}

private struct WorkspaceProjectRenameRequest: Identifiable {
    let id: String
    let title: String
}

struct WorkspaceShellView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var navigation: WorkspaceNavigationModel

    @State private var collapsedProjectIDs: Set<String> = []
    @State private var isArchiveExpanded = false
    @State private var pendingTaskDeletion: AgentTaskSnapshot?
    @State private var pendingConversationDeletion: AssistantConversationSummary?
    @State private var pendingProjectRename: WorkspaceProjectRenameRequest?
    @State private var projectRenameDraft = ""
    @State private var isUserFooterHovered = false

    private let loadsData: Bool
    init(loadsData: Bool = true) {
        self.loadsData = loadsData
    }

    var body: some View {
        FeatureStoreObserver(
            assistant: model.assistantStore,
            agentTasks: model.agentTaskStore
        ) {
            workspaceContent
        }
    }

    private var workspaceContent: some View {
        ZStack(alignment: .leading) {
            HStack(spacing: 0) {
                Color.clear
                    .frame(width: WorkspaceSidebarLayout.collapsedWidth)

                detailContent
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .layoutPriority(1)
            }

            WorkspaceSidebarHoverContainer(presentation: navigation.sidebarPresentation) { isCollapsed in
                sidebar(isCollapsed: isCollapsed)
            }
            .zIndex(1)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background {
            AppWorkspaceBackground()
                .ignoresSafeArea(.container, edges: .top)
        }
        .task {
            guard loadsData else { return }
            if model.config == nil { await model.refreshAll() }
            Task { await model.refreshDashboardBatch() }
            await model.runDashboardAutoRefreshLoop()
        }
        .task {
            guard loadsData else { return }
            await model.loadAgentTasks()
        }
        .task {
            guard loadsData else { return }
            await model.loadAssistantConversations()
        }
        .alert(
            model.uiText("永久删除任务？"),
            isPresented: Binding(
                get: { pendingTaskDeletion != nil },
                set: { if !$0 { pendingTaskDeletion = nil } }
            ),
            presenting: pendingTaskDeletion
        ) { task in
            Button(model.uiText("取消"), role: .cancel) {
                pendingTaskDeletion = nil
            }
            Button(model.uiText("删除"), role: .destructive) {
                pendingTaskDeletion = nil
                Task { await model.deleteAgentTask(id: task.id) }
            }
        } message: { task in
            Text(model.uiText("任务“%@”及其加密执行记录会被永久删除，此操作无法撤销。", task.objective))
        }
        .alert(
            model.uiText("永久删除对话？"),
            isPresented: Binding(
                get: { pendingConversationDeletion != nil },
                set: { if !$0 { pendingConversationDeletion = nil } }
            ),
            presenting: pendingConversationDeletion
        ) { conversation in
            Button(model.uiText("取消"), role: .cancel) {
                pendingConversationDeletion = nil
            }
            Button(model.uiText("删除"), role: .destructive) {
                pendingConversationDeletion = nil
                Task { await model.deleteAssistantConversation(id: conversation.id) }
            }
        } message: { conversation in
            Text(model.uiText("对话“%@”会从本机长期记忆中永久删除，此操作无法撤销。", conversation.title))
        }
        .alert(
            model.uiText("重命名项目"),
            isPresented: Binding(
                get: { pendingProjectRename != nil },
                set: { if !$0 { pendingProjectRename = nil } }
            ),
            presenting: pendingProjectRename
        ) { project in
            TextField(model.uiText("项目名称"), text: $projectRenameDraft)
            Button(model.uiText("取消"), role: .cancel) {
                pendingProjectRename = nil
            }
            Button(model.uiText("重命名")) {
                if navigation.renameProject(id: project.id, to: projectRenameDraft) {
                    pendingProjectRename = nil
                }
            }
            .disabled(projectRenameDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        } message: { project in
            Text(model.uiText("为“%@”输入新的项目名称。", project.title))
        }
    }

    private var detailContent: some View {
        VStack(spacing: 0) {
            if let error = model.errorMessage {
                ErrorBanner(message: error) { model.errorMessage = nil }
                    .padding(.horizontal, 20)
                    .padding(.top, 12)
            }

            AssistantView(
                loadsAgentTasks: false,
                newTaskRequest: navigation.newTaskRequest
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background { AppWorkspaceBackground() }
        .foregroundStyle(AppPalette.text)
    }

    private func sidebar(isCollapsed: Bool) -> some View {
        VStack(spacing: 0) {
            sidebarHeader(isCollapsed: isCollapsed)

            VStack(alignment: .leading, spacing: 2) {
                ForEach(WorkspaceSidebarItem.allCases) { item in
                    sidebarButton(item, isCollapsed: isCollapsed)
                }
            }
            .padding(.horizontal, 8)
            .padding(.bottom, 12)

            Divider()
                .overlay(AppPalette.separator.opacity(0.42))
                .opacity(isCollapsed ? 0 : 1)

            ScrollView(.vertical, showsIndicators: false) {
                LazyVStack(alignment: .leading, spacing: 14) {
                    projectsSection
                    archiveSection
                }
                .padding(.horizontal, 9)
                .padding(.vertical, 14)
            }
            .opacity(isCollapsed ? 0 : 1)
            .allowsHitTesting(!isCollapsed)
            .accessibilityHidden(isCollapsed)

            Divider().overlay(AppPalette.separator.opacity(0.42))

            userFooter(isCollapsed: isCollapsed)
        }
        .foregroundStyle(AppPalette.sidebarText)
        .appTypography()
        .accessibilityIdentifier("workspace-sidebar")
    }

    private func sidebarHeader(isCollapsed: Bool) -> some View {
        HStack(spacing: 10) {
            AppBrandLogo(size: 30, shadow: false)
            Group {
                Text(model.text(.appName))
                    .font(AppTypography.sidebarBrandTitle)
                    .foregroundStyle(AppPalette.sidebarText)
                    .lineLimit(1)
                Spacer(minLength: 8)
                if model.busyActions.contains("agent-tasks") {
                    ProgressView()
                        .controlSize(.small)
                        .tint(AppPalette.brandCyan)
                }
            }
            .opacity(isCollapsed ? 0 : 1)
        }
        .padding(.leading, 21)
        .padding(.trailing, 14)
        .padding(.top, 24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(minHeight: 70)
        .help(model.text(.appName))
        .accessibilityIdentifier("workspace-sidebar-brand")
    }

    private func sidebarButton(_ item: WorkspaceSidebarItem, isCollapsed: Bool) -> some View {
        let title = item.title(model.appLanguage)
        return Button {
            selectSidebarItem(item)
        } label: {
            WorkspaceSidebarLabel(
                title: title,
                icon: item.icon,
                active: isSelected(item),
                compact: isCollapsed
            )
        }
        .buttonStyle(.plain)
        .help(title)
        .accessibilityLabel(title)
    }

    private func selectSidebarItem(_ item: WorkspaceSidebarItem) {
        switch item {
        case .newTask:
            model.startNewAssistantConversation()
            navigation.startNewTask()
        }
    }

    private func isSelected(_ item: WorkspaceSidebarItem) -> Bool {
        switch item {
        case .newTask:
            navigation.destination == .assistant
                && model.activeAgentTask == nil
                && model.conversationTurns.isEmpty
        }
    }

    private var projectGroups: [WorkspaceProjectGroup] {
        Dictionary(grouping: model.agentTasks, by: \AgentTaskSnapshot.workspacePath)
            .map { path, tasks in
                WorkspaceProjectGroup(
                    id: path,
                    title: navigation.projectName(
                        id: path,
                        fallback: tasks.first?.workspaceName ?? URL(fileURLWithPath: path).lastPathComponent
                    ),
                    tasks: tasks.sorted { $0.updatedAt > $1.updatedAt }
                )
            }
            .sorted {
                ($0.tasks.first?.updatedAt ?? "") > ($1.tasks.first?.updatedAt ?? "")
            }
    }

    private var projectsSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 7) {
                Image(systemName: "folder")
                Text(model.uiText("项目"))
                Spacer(minLength: 6)
                Button {
                    Task {
                        await model.loadAgentTasks()
                        await model.loadAssistantConversations(reportErrors: true)
                    }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .frame(width: 24, height: 24)
                }
                .buttonStyle(.plain)
                .help(model.uiText("刷新任务"))
            }
            .font(AppTypography.sidebarIdentity)
            .foregroundStyle(AppPalette.sidebarTextMuted)
            .padding(.horizontal, 7)

            if model.assistantConversations.isEmpty && projectGroups.isEmpty {
                SidebarEmptyRow(title: model.uiText("暂无项目"), icon: "folder.badge.plus")
            } else {
                if !model.assistantConversations.isEmpty {
                    assistantConversationProject
                }
                ForEach(projectGroups) { project in
                    projectGroup(project)
                }
            }
        }
    }

    private var assistantConversationProject: some View {
        let projectID = "assistant-conversations-project"
        let defaultTitle = model.uiText(model.assistantConversations.first?.projectName ?? "智能问答")
        let title = navigation.projectName(id: projectID, fallback: defaultTitle)
        return VStack(alignment: .leading, spacing: 4) {
            Button {
                if collapsedProjectIDs.contains(projectID) {
                    collapsedProjectIDs.remove(projectID)
                } else {
                    collapsedProjectIDs.insert(projectID)
                }
            } label: {
                HStack(spacing: 7) {
                    Image(systemName: collapsedProjectIDs.contains(projectID) ? "chevron.right" : "chevron.down")
                        .font(AppTypography.system(size: 9, weight: .bold))
                        .frame(width: 10)
                    Image(systemName: "folder.fill")
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                    Text(title)
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    Text("\(model.assistantConversations.count)")
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                }
                .font(AppTypography.sidebarIdentity)
                .foregroundStyle(AppPalette.sidebarText)
                .padding(.horizontal, 7)
                .frame(maxWidth: .infinity, minHeight: 30, alignment: .leading)
            }
            .buttonStyle(.plain)
            .contextMenu {
                Button {
                    beginRenamingProject(id: projectID, title: title)
                } label: {
                    Label(model.uiText("重命名项目"), systemImage: "pencil")
                }
            }

            if !collapsedProjectIDs.contains(projectID) {
                ForEach(model.assistantConversations) { conversation in
                    conversationRow(conversation, archived: false)
                }
            }
        }
    }

    private func conversationRow(
        _ conversation: AssistantConversationSummary,
        archived: Bool
    ) -> some View {
        AssistantConversationHistoryRow(
            conversation: conversation,
            selected: navigation.destination == .assistant
                && model.activeAgentTask == nil
                && model.sessionID == conversation.id,
            isLoading: model.busyActions.contains("assistant-conversation:\(conversation.id)"),
            archived: archived,
            onSelect: { showConversation(conversation) },
            onArchive: {
                Task { await model.archiveAssistantConversation(id: conversation.id, archived: !archived) }
            },
            onDelete: { pendingConversationDeletion = conversation }
        )
    }

    private func projectGroup(_ project: WorkspaceProjectGroup) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Button {
                if collapsedProjectIDs.contains(project.id) {
                    collapsedProjectIDs.remove(project.id)
                } else {
                    collapsedProjectIDs.insert(project.id)
                }
            } label: {
                HStack(spacing: 7) {
                    Image(systemName: collapsedProjectIDs.contains(project.id) ? "chevron.right" : "chevron.down")
                        .font(AppTypography.system(size: 9, weight: .bold))
                        .frame(width: 10)
                    Image(systemName: "folder.fill")
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                    Text(project.title)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 6)
                    Text("\(project.tasks.count)")
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                }
                .font(AppTypography.sidebarIdentity)
                .foregroundStyle(AppPalette.sidebarText)
                .padding(.horizontal, 7)
                .frame(maxWidth: .infinity, minHeight: 30, alignment: .leading)
            }
            .buttonStyle(.plain)
            .contextMenu {
                Button {
                    beginRenamingProject(id: project.id, title: project.title)
                } label: {
                    Label(model.uiText("重命名项目"), systemImage: "pencil")
                }
            }

            if !collapsedProjectIDs.contains(project.id) {
                ForEach(project.tasks) { task in
                    TaskHistoryRow(
                        task: task,
                        selected: navigation.destination == .assistant && model.activeAgentTask?.id == task.id,
                        dark: true,
                        onSelect: { showTask(task) },
                        onArchive: {
                            Task { await model.archiveAgentTask(id: task.id, archived: true) }
                        },
                        onDelete: { pendingTaskDeletion = task }
                    )
                }
            }
        }
    }

    private var archiveSection: some View {
        VStack(alignment: .leading, spacing: 5) {
            Button {
                isArchiveExpanded.toggle()
            } label: {
                HStack(spacing: 7) {
                    Image(systemName: isArchiveExpanded ? "chevron.down" : "chevron.right")
                        .font(AppTypography.system(size: 9, weight: .bold))
                        .frame(width: 10)
                    Image(systemName: "archivebox")
                    Text(model.uiText("归档"))
                    Spacer(minLength: 6)
                    Text("\(model.archivedAgentTasks.count + model.archivedAssistantConversations.count)")
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                }
                .font(AppTypography.sidebarIdentity)
                .foregroundStyle(AppPalette.sidebarTextMuted)
                .padding(.horizontal, 7)
                .frame(maxWidth: .infinity, minHeight: 30, alignment: .leading)
            }
            .buttonStyle(.plain)

            if isArchiveExpanded {
                if model.archivedAgentTasks.isEmpty && model.archivedAssistantConversations.isEmpty {
                    SidebarEmptyRow(title: model.uiText("暂无归档内容"), icon: "archivebox")
                } else {
                    ForEach(model.archivedAssistantConversations) { conversation in
                        conversationRow(conversation, archived: true)
                    }
                    ForEach(model.archivedAgentTasks) { task in
                        TaskHistoryRow(
                            task: task,
                            selected: navigation.destination == .assistant && model.activeAgentTask?.id == task.id,
                            dark: true,
                            onSelect: { showTask(task) },
                            onArchive: {
                                Task { await model.archiveAgentTask(id: task.id, archived: false) }
                            },
                            onDelete: { pendingTaskDeletion = task }
                        )
                    }
                }
            }
        }
    }

    private func showTask(_ task: AgentTaskSnapshot) {
        model.openAgentTaskConversation(task)
        navigation.show(.assistant)
    }

    private func showConversation(_ conversation: AssistantConversationSummary) {
        navigation.show(.assistant)
        Task { await model.openAssistantConversation(conversation) }
    }

    private func beginRenamingProject(id: String, title: String) {
        projectRenameDraft = title
        pendingProjectRename = WorkspaceProjectRenameRequest(id: id, title: title)
    }

    private func userFooter(isCollapsed: Bool) -> some View {
        ZStack(alignment: .leading) {
            HStack(spacing: 9) {
                AppUserAvatar(
                    displayName: model.currentProfileDisplayName,
                    imageData: model.profileAvatarImageData,
                    size: 32
                )

                VStack(alignment: .leading, spacing: 1) {
                    Text(model.currentProfileDisplayName)
                        .font(AppTypography.sidebarIdentity)
                        .foregroundStyle(AppPalette.sidebarText)
                    Text(sidebarProfileRole)
                        .font(AppTypography.sidebarIdentityCaption)
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                }
                .lineLimit(1)
                .layoutPriority(1)

                Spacer(minLength: 2)

                Button { model.signOut() } label: {
                    Image(systemName: "rectangle.portrait.and.arrow.right")
                        .frame(width: 28, height: 28)
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppPalette.sidebarTextMuted)
                .opacity(isUserFooterHovered ? 1 : 0.55)
                .help(model.text(.signOut))
            }
            .padding(.horizontal, 20)
            .opacity(isCollapsed ? 0 : 1)
            .allowsHitTesting(!isCollapsed)

            Button { model.signOut() } label: {
                Image(systemName: "rectangle.portrait.and.arrow.right")
                    .frame(width: WorkspaceSidebarLayout.collapsedWidth, height: 30)
            }
            .buttonStyle(.plain)
            .foregroundStyle(AppPalette.sidebarTextMuted)
            .help(model.text(.signOut))
            .opacity(isCollapsed ? 1 : 0)
            .allowsHitTesting(isCollapsed)
        }
        .background(isUserFooterHovered && !isCollapsed ? AppPalette.sidebarHover.opacity(0.74) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .padding(.horizontal, isCollapsed ? 0 : 8)
        .padding(.bottom, 10)
        .frame(minHeight: 52)
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.18)) {
                isUserFooterHovered = hovering
            }
        }
    }

    private var sidebarProfileRole: String {
        let value = model.profileSettings?.role.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return value.isEmpty ? model.uiText("安全分析师") : value
    }
}

private struct WorkspaceSidebarLabel: View {
    let title: String
    let icon: String
    let active: Bool
    let compact: Bool
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(AppTypography.system(size: 14, weight: .semibold))
                .frame(width: 19, height: 19)
            Group {
                Text(title)
                    .font(AppTypography.sidebarItem)
                    .lineLimit(1)
                Spacer(minLength: 0)
            }
            .opacity(compact ? 0 : 1)
        }
        .foregroundStyle(active ? AppPalette.sidebarText : AppPalette.sidebarTextMuted)
        .padding(.leading, compact ? 18.5 : 18)
        .padding(.trailing, 18)
        .frame(
            maxWidth: .infinity,
            minHeight: 36,
            alignment: .leading
        )
        .background(
            active
                ? AppPalette.sidebarSelected
                : (hovering ? AppPalette.sidebarHover.opacity(0.82) : Color.clear)
        )
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .contentShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .onHover { value in
            withAnimation(.easeInOut(duration: 0.16)) {
                hovering = value
            }
        }
    }
}

private struct WorkspaceSidebarHoverContainer<Content: View>: View {
    @ObservedObject var presentation: WorkspaceSidebarPresentationModel
    @ViewBuilder let content: (Bool) -> Content

    init(
        presentation: WorkspaceSidebarPresentationModel,
        @ViewBuilder content: @escaping (Bool) -> Content
    ) {
        self.presentation = presentation
        self.content = content
    }

    var body: some View {
        content(presentation.isCollapsed)
            .frame(width: WorkspaceSidebarLayout.expandedWidth)
            .frame(width: currentWidth, alignment: .leading)
            .frame(maxHeight: .infinity)
            .clipped()
            .background {
                SidebarGlassBackground()
                    .ignoresSafeArea(.container, edges: .top)
            }
            .shadow(
                color: Color.black.opacity(presentation.isCollapsed ? 0 : 0.10),
                radius: 14,
                x: 4,
                y: 0
            )
            .contentShape(Rectangle())
            .onHover(perform: presentation.setHovered)
            .animation(
                .easeOut(duration: WorkspaceSidebarLayout.animationDuration),
                value: presentation.isCollapsed
            )
    }

    private var currentWidth: CGFloat {
        presentation.isCollapsed
            ? WorkspaceSidebarLayout.collapsedWidth
            : WorkspaceSidebarLayout.expandedWidth
    }
}

private struct SidebarEmptyRow: View {
    let title: String
    let icon: String

    var body: some View {
        Label(title, systemImage: icon)
            .font(AppTypography.caption)
            .foregroundStyle(AppPalette.sidebarTextMuted)
            .padding(.horizontal, 8)
            .frame(maxWidth: .infinity, minHeight: 34, alignment: .leading)
    }
}

private struct AssistantConversationHistoryRow: View {
    @EnvironmentObject private var model: AppModel
    let conversation: AssistantConversationSummary
    let selected: Bool
    let isLoading: Bool
    let archived: Bool
    let onSelect: () -> Void
    let onArchive: () -> Void
    let onDelete: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: onSelect) {
            HStack(alignment: .top, spacing: 9) {
                if isLoading {
                    ProgressView()
                        .controlSize(.mini)
                        .frame(width: 17, height: 17)
                        .padding(.top, 2)
                } else {
                    Image(systemName: "bubble.left")
                        .font(AppTypography.system(size: 12, weight: .semibold))
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                        .frame(width: 17, height: 17)
                        .padding(.top, 2)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(conversation.title)
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.sidebarText)
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)
                    HStack(spacing: 5) {
                        Text(model.uiText("%d 条问答", conversation.turnCount))
                        Spacer(minLength: 4)
                        Text(conversationRelativeTime(conversation.updatedAt, locale: model.appLanguage.locale))
                            .lineLimit(1)
                    }
                    .font(AppTypography.caption2)
                    .foregroundStyle(AppPalette.sidebarTextMuted)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, minHeight: 58, alignment: .leading)
            .background(
                selected
                    ? AppPalette.sidebarSelected
                    : (hovering ? AppPalette.sidebarHover : Color.clear)
            )
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .contextMenu {
            Button(action: onArchive) {
                Label(
                    model.uiText(archived ? "恢复对话" : "归档对话"),
                    systemImage: archived ? "tray.and.arrow.up" : "archivebox"
                )
            }
            .disabled(model.busyActions.contains("assistant-conversation-archive:\(conversation.id)"))
            Divider()
            Button(role: .destructive, action: onDelete) {
                Label(model.uiText("删除对话"), systemImage: "trash")
            }
            .disabled(model.busyActions.contains("assistant-conversation-delete:\(conversation.id)"))
        }
        .accessibilityIdentifier("assistant-conversation-history-row-\(conversation.id)")
    }
}

private func conversationRelativeTime(_ value: String, locale: Locale) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    guard let date else { return String(value.prefix(10)) }
    let relative = RelativeDateTimeFormatter()
    relative.locale = locale
    relative.unitsStyle = .short
    return relative.localizedString(for: date, relativeTo: Date())
}
