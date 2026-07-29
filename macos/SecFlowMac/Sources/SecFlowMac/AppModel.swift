import Foundation

func isExpectedCancellation(_ error: Error) -> Bool {
    if error is CancellationError {
        return true
    }
    let nsError = error as NSError
    if nsError.domain == NSURLErrorDomain,
       nsError.code == URLError.Code.cancelled.rawValue {
        return true
    }
    return nsError.domain == NSCocoaErrorDomain
        && nsError.code == CocoaError.Code.userCancelled.rawValue
}

@MainActor
func resolveInformationRefresh(
    initial: InformationSnapshot,
    previousLastRefresh: String? = nil,
    maximumPollCount: Int = 80,
    pollIntervalNanoseconds: UInt64 = 750_000_000,
    load: () async throws -> InformationSnapshot,
    onUpdate: (InformationSnapshot) -> Void
) async throws -> InformationSnapshot {
    var snapshot = initial
    var pollCount = 0
    var observedUpdating = snapshot.isUpdating
    while pollCount < maximumPollCount {
        let refreshTimestampChanged = previousLastRefresh.map { snapshot.lastRefresh != $0 } ?? true
        if !snapshot.isUpdating && (observedUpdating || refreshTimestampChanged) {
            break
        }
        try await Task.sleep(nanoseconds: pollIntervalNanoseconds)
        try Task.checkCancellation()
        snapshot = try await load()
        observedUpdating = observedUpdating || snapshot.isUpdating
        onUpdate(snapshot)
        pollCount += 1
    }
    return snapshot
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var serverURL: String
    @Published var config: ConfigSnapshot?
    @Published var runtime: RuntimeStatus?
    @Published var trialStatus: TrialStatusSnapshot?
    @Published var llmConfig: LLMConfigSnapshot?
    @Published var llmModelCatalog: LLMModelCatalog?
    @Published var dashboard: DashboardSnapshot?
    @Published var dashboardRange: DashboardDateRange?
    @Published var intelligenceSources: [IntelligenceSource] = []
    @Published var intelligenceResult: IntelligenceQueryResult?
    @Published var componentVulnerabilityResult: ComponentVulnerabilityResult?
    @Published var queryLogs: [IntelligenceQueryResult] = []
    @Published var information: InformationSnapshot?
    @Published var settings: SettingsSnapshot?
    @Published var profileSettings: UserProfileSettingsSnapshot?
    @Published var preferenceSettings: AppPreferenceSettingsSnapshot?
    @Published var aboutSettings: AboutSettingsSnapshot?
    @Published var legalDocuments: [String: LegalDocumentSnapshot] = [:]
    @Published var profileAvatarImageData: Data?
    @Published var subscriptionCatalog: SubscriptionCatalog?
    @Published var currentSubscription: SubscriptionSnapshot?
    @Published var subscriptionUsage: SubscriptionUsageSnapshot?
    @Published var subscriptionOrders: [SubscriptionOrder] = []
    @Published var knowledgeGraph: KnowledgeGraphPayload?
    @Published var assistantGraph: GraphSpec?
    @Published var collectorGraph: GraphSpec?
    @Published var answer: AskResult?
    @Published var conversationTurns: [ConversationTurn] = []
    @Published var assistantConversations: [AssistantConversationSummary] = []
    @Published var archivedAssistantConversations: [AssistantConversationSummary] = []
    @Published var agentTasks: [AgentTaskSnapshot] = []
    @Published var archivedAgentTasks: [AgentTaskSnapshot] = []
    @Published var activeAgentTask: AgentTaskSnapshot?
    @Published var reports: [AnalysisReportSummary] = []
    @Published var selectedReport: AnalysisReportDetail?
    @Published var activeTrace: [TraceItem] = []
    @Published var isRefreshing = false
    @Published var isAsking = false
    @Published var busyActions: Set<String> = []
    @Published var errorMessage: String?
    @Published var statusMessage: String?
    @Published var isAuthenticated: Bool
    @Published var authScreen: AuthScreen = .login
    @Published var initialSetupState: InitialSetupState = .loading
    @Published var appLanguage: AppLanguage
    @Published var darkModeEnabled: Bool
    @Published var interfaceFontSize: AppInterfaceFontSize

    @Published var userID: String
    @Published private(set) var sessionID: String

    private let localBackend = LocalBackendManager.shared
    private var assistantConversationCache: [String: [ConversationTurn]] = [:]

    var dataDirectoryURL: URL { localBackend.dataDirectoryURL }
    var allAgentTasks: [AgentTaskSnapshot] { agentTasks + archivedAgentTasks }
    var currentProfileDisplayName: String {
        let value = profileSettings?.displayName.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !value.isEmpty { return value }
        let localName = userID.split(separator: "@").first.map(String.init) ?? ""
        return localName.isEmpty || localName == "local-user" ? uiText("本机用户") : localName
    }

    init() {
        let appearance = AppAppearancePreferences.load()
        serverURL = LocalBackendManager.shared.baseURLString
        UserDefaults.standard.removeObject(forKey: "secflow.serverURL")
        userID = UserDefaults.standard.string(forKey: "secflow.userID") ?? "local-user"
        appLanguage = AppLanguage.storedValue()
        darkModeEnabled = appearance.darkMode
        interfaceFontSize = appearance.fontSize
        isAuthenticated = ProcessInfo.processInfo.environment["SECFLOW_SKIP_AUTH"] == "1"
        if let stored = UserDefaults.standard.string(forKey: "secflow.sessionID") {
            sessionID = stored
        } else {
            let value = UUID().uuidString
            UserDefaults.standard.set(value, forKey: "secflow.sessionID")
            sessionID = value
        }
    }

    func refreshAll() async {
        isRefreshing = true
        errorMessage = nil
        defer { isRefreshing = false }
        do {
            let client = try await connectedClient()
            trialStatus = try await client.loadTrialStatus()
            if let trialStatus, !trialStatus.isUsable(at: Date()) {
                initialSetupState = .failed(trialStatus.message)
                return
            }
            async let configRequest = client.loadConfig()
            async let llmConfigRequest: LLMConfigSnapshot? = try? await client.loadLLMConfig()
            async let graphRequest: GraphSpec? = try? await client.loadGraph()
            async let collectorGraphRequest: GraphSpec? = try? await client.loadCollectorGraph()
            async let dashboardRequest: DashboardSnapshot? = try? await client.loadDashboard()
            async let recentRequest: [IntelligenceQueryResult]? = try? await client.loadRecentIntelligence()
            async let reportsRequest: [AnalysisReportSummary]? = try? await client.loadReports()
            async let settingsRequest: SettingsSnapshot? = try? await client.loadSettings()
            async let conversationsRequest: [AssistantConversationSummary]? = try? await client.loadAssistantConversations(
                userID: userID
            )
            async let archivedConversationsRequest: [AssistantConversationSummary]? = try? await client.loadAssistantConversations(
                userID: userID,
                archived: true
            )

            let loadedConfig = try await configRequest
            let loadedLLMConfig = await llmConfigRequest
            let loadedSettings = await settingsRequest
            config = loadedConfig
            llmConfig = loadedLLMConfig
            if let loadedSettings {
                applySettingsSnapshot(loadedSettings)
            } else {
                profileSettings = nil
            }
            updateInitialSetupState()
            assistantGraph = await graphRequest
            collectorGraph = await collectorGraphRequest
            dashboard = (await dashboardRequest) ?? loadedConfig.dashboard

            if let snapshotRuntime = loadedConfig.runtime {
                runtime = snapshotRuntime
            } else {
                runtime = try? await client.loadRuntime()
            }
            intelligenceSources = dashboard?.sources ?? []
            if let recent = await recentRequest {
                queryLogs = recent
                if let latest = recent.first {
                    intelligenceResult = latest
                    knowledgeGraph = latest.graph
                }
            }
            reports = (await reportsRequest) ?? reports
            if let loadedConversations = await conversationsRequest {
                mergeAssistantConversations(
                    loadedConversations,
                    archivedConversationIDs: Set((await archivedConversationsRequest)?.map(\.id) ?? [])
                )
            }
            if let loadedArchivedConversations = await archivedConversationsRequest {
                archivedAssistantConversations = loadedArchivedConversations
            }
            if let loadedSettings {
                profileAvatarImageData = loadedSettings.profile.avatarAvailable ? (try? await client.downloadProfileAvatar()) : nil
            }
            statusMessage = uiText("本机数据服务已连接")
        } catch {
            guard !isExpectedCancellation(error) else { return }
            presentError(error)
            if initialSetupState == .loading {
                initialSetupState = .failed(errorMessage ?? localizedError(error))
            }
        }
    }

    func refreshTrialStatus() async {
        do {
            let client = try await connectedClient()
            trialStatus = try await client.loadTrialStatus()
        } catch {
            if trialStatus == nil {
                presentError(error)
            }
        }
    }

    func runTrialStatusLoop() async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
            } catch {
                return
            }
            await refreshTrialStatus()
        }
    }

    func refreshDashboardSnapshot() async {
        do {
            let client = try await connectedClient()
            let range = dashboardRangeStrings
            async let dashboardRequest = client.loadDashboard(startDate: range.start, endDate: range.end)
            async let recentRequest: [IntelligenceQueryResult]? = try? await client.loadRecentIntelligence()

            dashboard = try await dashboardRequest
            if let recent = await recentRequest {
                queryLogs = recent
                if let latest = recent.first {
                    intelligenceResult = latest
                    knowledgeGraph = latest.graph
                }
            }
        } catch {
            if dashboard == nil {
                presentError(error)
            }
        }
    }

    func loadLLMConfig() async {
        do {
            let client = try await connectedClient()
            llmConfig = try await client.loadLLMConfig()
            updateInitialSetupState()
            runtime = try? await client.loadRuntime()
        } catch {
            presentError(error)
        }
    }

    func testLLMConfig(_ payload: LLMConfigPayload) async -> LLMTestResult? {
        busyActions.insert("llm-test")
        errorMessage = nil
        defer { busyActions.remove("llm-test") }
        do {
            let client = try await connectedClient()
            let result = try await client.testLLMConfig(payload)
            statusMessage = localizedMessage(result.message)
            return result
        } catch {
            presentError(error)
            return nil
        }
    }

    func saveLLMConfig(_ payload: LLMConfigPayload) async {
        busyActions.insert("llm-save")
        errorMessage = nil
        defer { busyActions.remove("llm-save") }
        do {
            let client = try await connectedClient()
            llmConfig = try await client.saveLLMConfig(payload)
            updateInitialSetupState()
            runtime = try? await client.loadRuntime()
            config = try? await client.loadConfig()
            statusMessage = payload.enabled ? uiText("大模型配置已保存并启用") : uiText("大模型连接已断开")
        } catch {
            presentError(error)
        }
    }

    func loadLLMModels(_ payload: LLMModelsPayload) async {
        busyActions.insert("llm-models")
        errorMessage = nil
        defer { busyActions.remove("llm-models") }
        do {
            let client = try await connectedClient()
            llmModelCatalog = try await client.loadLLMModels(payload)
            statusMessage = localizedMessage(llmModelCatalog?.message)
        } catch {
            presentError(error)
        }
    }

    func loadSettings() async {
        busyActions.insert("settings-load")
        errorMessage = nil
        defer { busyActions.remove("settings-load") }
        do {
            let client = try await connectedClient()
            let loadedSettings = try await client.loadSettings()
            applySettingsSnapshot(loadedSettings)
            updateInitialSetupState()
            profileAvatarImageData = loadedSettings.profile.avatarAvailable ? (try? await client.downloadProfileAvatar()) : nil
        } catch {
            presentError(error)
        }
    }

    @discardableResult
    func saveProfileSettings(_ payload: UserProfileSettingsPayload) async -> Bool {
        busyActions.insert("settings-profile-save")
        errorMessage = nil
        defer { busyActions.remove("settings-profile-save") }
        do {
            let client = try await connectedClient()
            profileSettings = try await client.saveProfileSettings(payload)
            settings = rebuildSettingsSnapshot()
            updateInitialSetupState()
            statusMessage = uiText("用户资料已保存")
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    @discardableResult
    func uploadProfileAvatar(_ payload: AvatarUploadPayload) async -> Bool {
        busyActions.insert("settings-avatar-upload")
        errorMessage = nil
        defer { busyActions.remove("settings-avatar-upload") }
        do {
            let client = try await connectedClient()
            profileSettings = try await client.uploadProfileAvatar(payload)
            profileAvatarImageData = try? await client.downloadProfileAvatar()
            settings = rebuildSettingsSnapshot()
            statusMessage = uiText("头像已上传")
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    @discardableResult
    func deleteProfileAvatar() async -> Bool {
        busyActions.insert("settings-avatar-delete")
        errorMessage = nil
        defer { busyActions.remove("settings-avatar-delete") }
        do {
            let client = try await connectedClient()
            profileSettings = try await client.deleteProfileAvatar()
            profileAvatarImageData = nil
            settings = rebuildSettingsSnapshot()
            statusMessage = uiText("头像已移除")
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    @discardableResult
    func savePreferenceSettings(_ payload: AppPreferenceSettingsPayload) async -> Bool {
        busyActions.insert("settings-preferences-save")
        errorMessage = nil
        defer { busyActions.remove("settings-preferences-save") }
        do {
            let client = try await connectedClient()
            preferenceSettings = try await client.savePreferenceSettings(payload)
            applyAppearancePreferences(
                darkMode: preferenceSettings?.darkMode ?? payload.darkMode,
                fontSize: preferenceSettings?.fontSize ?? payload.fontSize
            )
            if let language = AppLanguage(apiCode: preferenceSettings?.language ?? payload.language) {
                setLanguage(language)
            }
            settings = rebuildSettingsSnapshot()
            statusMessage = uiText("通用设置已保存")
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    func loadLegalDocuments() async {
        busyActions.insert("settings-legal-load")
        errorMessage = nil
        defer { busyActions.remove("settings-legal-load") }
        do {
            let client = try await connectedClient()
            legalDocuments = try await client.loadLegalDocuments()
            settings = rebuildSettingsSnapshot()
        } catch {
            presentError(error)
        }
    }

    func loadLegalDocument(id: String) async {
        busyActions.insert("settings-legal-load:\(id)")
        errorMessage = nil
        defer { busyActions.remove("settings-legal-load:\(id)") }
        do {
            let client = try await connectedClient()
            let document = try await client.loadLegalDocument(id: id)
            legalDocuments[document.id] = document
            settings = rebuildSettingsSnapshot()
        } catch {
            presentError(error)
        }
    }

    func loadSubscriptionData() async {
        busyActions.insert("subscription-load")
        errorMessage = nil
        defer { busyActions.remove("subscription-load") }
        do {
            let client = try await connectedClient()
            async let catalogRequest = client.loadSubscriptionCatalog()
            async let currentRequest = client.loadCurrentSubscription(userID: userID)
            async let usageRequest = client.loadSubscriptionUsage(userID: userID)
            async let ordersRequest = client.loadSubscriptionOrders(userID: userID)

            let (catalog, current, usage, history) = try await (
                catalogRequest,
                currentRequest,
                usageRequest,
                ordersRequest
            )
            subscriptionCatalog = catalog
            currentSubscription = current
            subscriptionUsage = usage
            subscriptionOrders = history.orders
        } catch {
            guard !isExpectedCancellation(error) else { return }
            presentError(error)
        }
    }

    @discardableResult
    func checkoutSubscription(planID: String, paymentMethod: String) async -> SubscriptionCheckoutResult? {
        busyActions.insert("subscription-checkout")
        errorMessage = nil
        defer { busyActions.remove("subscription-checkout") }
        do {
            let client = try await connectedClient()
            let result = try await client.checkoutSubscription(
                SubscriptionCheckoutPayload(
                    userId: userID,
                    planId: planID,
                    paymentMethod: paymentMethod,
                    idempotencyKey: UUID().uuidString
                )
            )
            currentSubscription = try await client.loadCurrentSubscription(userID: userID)
            subscriptionOrders = (try await client.loadSubscriptionOrders(userID: userID)).orders
            statusMessage = localizedMessage(result.message)
            return result
        } catch {
            guard !isExpectedCancellation(error) else { return nil }
            presentError(error)
            return nil
        }
    }

    @discardableResult
    func cancelCurrentSubscription(reason: String? = nil) async -> Bool {
        busyActions.insert("subscription-cancel")
        errorMessage = nil
        defer { busyActions.remove("subscription-cancel") }
        do {
            let client = try await connectedClient()
            currentSubscription = try await client.cancelSubscription(
                SubscriptionCancelPayload(userId: userID, reason: reason)
            )
            statusMessage = uiText("已取消自动续费，当前权益可使用至本周期结束。")
            return true
        } catch {
            guard !isExpectedCancellation(error) else { return false }
            presentError(error)
            return false
        }
    }

    func refreshDashboardBatch(startDate: Date? = nil, endDate: Date? = nil) async {
        busyActions.insert("dashboard-batch")
        defer { busyActions.remove("dashboard-batch") }
        do {
            let client = try await connectedClient()
            let requestedRange: DashboardDateRange?
            if let startDate, let endDate {
                requestedRange = DashboardDateRange(
                    start: min(startDate, endDate),
                    end: max(startDate, endDate)
                )
            } else {
                requestedRange = nil
            }
            let strings = dashboardRangeStrings(for: requestedRange)
            if let cachedDashboard = try? await client.loadDashboard(startDate: strings.start, endDate: strings.end) {
                dashboard = cachedDashboard
                dashboardRange = requestedRange
            }
            dashboard = try await client.refreshDashboardBatch(
                DashboardRefreshPayload(startDate: strings.start, endDate: strings.end)
            )
            dashboardRange = requestedRange
            if let recent = try? await client.loadRecentIntelligence() {
                queryLogs = recent
            }
            statusMessage = requestedRange == nil
                ? uiText("漏洞情报总览已更新累计数据")
                : uiText("漏洞情报总览已按发布日期范围更新")
        } catch {
            presentError(error)
        }
    }

    func applyDashboardRange(startDate: Date, endDate: Date) async {
        let previousRange = dashboardRange
        dashboardRange = DashboardDateRange(
            start: min(startDate, endDate),
            end: max(startDate, endDate)
        )
        busyActions.insert("dashboard-filter")
        do {
            let client = try await connectedClient()
            let range = dashboardRangeStrings
            dashboard = try await client.loadDashboard(startDate: range.start, endDate: range.end)
            statusMessage = uiText("漏洞情报总览已切换到所选发布日期范围")
        } catch {
            dashboardRange = previousRange
            presentError(error)
        }
        busyActions.remove("dashboard-filter")
    }

    func runDashboardAutoRefreshLoop() async {
        var tick = 0
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: 60_000_000_000)
            } catch {
                return
            }
            tick += 1
            if tick % 15 == 0 && dashboardRange == nil {
                await refreshDashboardBatch()
            } else {
                await refreshDashboardSnapshot()
            }
        }
    }

    @discardableResult
    func ask(
        question: String,
        topK: Int,
        onTrace: ((TraceItem) -> Void)? = nil,
        onContent: ((String) -> Void)? = nil
    ) async -> AskResult? {
        let cleanQuestion = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanQuestion.isEmpty else { return nil }
        let requestSessionID = sessionID
        isAsking = true
        errorMessage = nil
        activeTrace = []
        defer { isAsking = false }
        do {
            let client = try await connectedClient()
            let result = try await client.streamAsk(
                AskPayload(
                    question: cleanQuestion,
                    topK: topK,
                    userId: userID,
                    sessionId: requestSessionID,
                    responseLanguage: appLanguage.apiCode
                )
            ) { [weak self] item in
                guard let self else { return }
                if self.sessionID == requestSessionID,
                   !self.activeTrace.contains(where: { $0.id == item.id }) {
                    self.activeTrace.append(item)
                }
                onTrace?(item)
            } onContent: { delta in
                onContent?(delta)
            }
            if sessionID == requestSessionID {
                answer = result
                activeTrace = result.trace
                knowledgeGraph = result.knowledgeGraph
            }
            if let report = result.report {
                reports.removeAll { $0.id == report.id }
                reports.insert(report, at: 0)
            }
            Task { await refreshStateAfterAnswer() }
            return result
        } catch is CancellationError {
            errorMessage = uiText("已停止生成")
        } catch let error as URLError where error.code == .cancelled {
            errorMessage = uiText("已停止生成")
        } catch {
            presentError(error)
        }
        return nil
    }

    @discardableResult
    func resumeAssistantInterrupt(
        _ interrupt: ReportInterruptEnvelope,
        confirm: Bool,
        format: ReportDownloadFormat? = nil
    ) async -> AskResult? {
        let action = "report-interrupt:\(interrupt.interruptId)"
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let result = try await client.resumeAssistantInterrupt(
                ReportActionResumePayload(
                    threadId: interrupt.threadId,
                    interruptId: interrupt.interruptId,
                    decision: confirm ? "confirm" : "cancel",
                    format: format?.rawValue,
                    userId: userID,
                    sessionId: sessionID
                )
            )
            if let report = result.report {
                reports.removeAll { $0.id == report.id }
                reports.insert(report, at: 0)
            }
            if let answer = result.answer {
                self.answer = answer
                return answer
            }
        } catch {
            presentError(error)
        }
        return nil
    }

    @discardableResult
    func resumeReportInterrupt(
        _ interrupt: ReportInterruptEnvelope,
        confirm: Bool,
        format: ReportDownloadFormat? = nil
    ) async -> AskResult? {
        await resumeAssistantInterrupt(interrupt, confirm: confirm, format: format)
    }

    func startReportDownload(
        reportIDs: [String],
        formats: [ReportDownloadFormat],
        allReports: Bool = false,
        allFormats: Bool = false
    ) async -> ReportActionResult? {
        busyActions.insert("report-action-start")
        errorMessage = nil
        defer { busyActions.remove("report-action-start") }
        do {
            let client = try await connectedClient()
            return try await client.startReportAction(
                ReportActionPayload(
                    action: allReports ? "download_all" : (allFormats ? "download_report_all_formats" : "download_report"),
                    reportIds: reportIDs,
                    formats: formats.map(\.rawValue),
                    userId: userID,
                    sessionId: sessionID,
                    responseLanguage: appLanguage.apiCode
                )
            )
        } catch {
            presentError(error)
            return nil
        }
    }

    @discardableResult
    func createAgentTask(objective: String, workspacePath: String) async -> AgentTaskSnapshot? {
        busyActions.insert("agent-task-create")
        errorMessage = nil
        defer { busyActions.remove("agent-task-create") }
        do {
            let client = try await connectedClient()
            let task = try await client.createAgentTask(
                AgentTaskCreatePayload(
                    objective: objective.trimmingCharacters(in: .whitespacesAndNewlines),
                    workspacePath: workspacePath,
                    userId: userID
                )
            )
            upsertAgentTask(task)
            activeAgentTask = task
            return task
        } catch {
            presentError(error)
            return nil
        }
    }

    @discardableResult
    func startAssistantWorkspaceAction(
        objective: String,
        workspacePath: String
    ) async -> AssistantWorkspaceActionResult? {
        busyActions.insert("workspace-action-start")
        errorMessage = nil
        defer { busyActions.remove("workspace-action-start") }
        do {
            let client = try await connectedClient()
            let result = try await client.startAssistantWorkspaceAction(
                AssistantWorkspaceActionPayload(
                    objective: objective.trimmingCharacters(in: .whitespacesAndNewlines),
                    workspacePath: workspacePath,
                    userId: userID,
                    sessionId: sessionID,
                    responseLanguage: appLanguage.apiCode
                )
            )
            if let task = result.task {
                upsertAgentTask(task)
                activeAgentTask = task
            }
            if let answer = result.answer {
                self.answer = answer
            }
            return result
        } catch {
            presentError(error)
            return nil
        }
    }

    @discardableResult
    func startAssistantTaskAction(
        objective: String,
        taskID: String
    ) async -> AssistantWorkspaceActionResult? {
        busyActions.insert("task-action-start")
        errorMessage = nil
        defer { busyActions.remove("task-action-start") }
        do {
            let client = try await connectedClient()
            let result = try await client.startAssistantTaskAction(
                taskID: taskID,
                AssistantTaskActionPayload(
                    objective: objective.trimmingCharacters(in: .whitespacesAndNewlines),
                    userId: userID,
                    sessionId: sessionID,
                    responseLanguage: appLanguage.apiCode
                )
            )
            if let task = result.task {
                upsertAgentTask(task)
                activeAgentTask = task
            }
            if let answer = result.answer {
                self.answer = answer
                activeTrace = answer.trace
                knowledgeGraph = answer.knowledgeGraph
            }
            return result
        } catch {
            presentError(error)
            return nil
        }
    }

    func loadAgentTasks() async {
        busyActions.insert("agent-tasks")
        defer { busyActions.remove("agent-tasks") }
        do {
            let client = try await connectedClient()
            async let currentRequest = client.loadAgentTasks(userID: userID)
            async let archivedRequest = client.loadAgentTasks(userID: userID, archived: true)
            agentTasks = try await currentRequest
            archivedAgentTasks = try await archivedRequest
            if let activeID = activeAgentTask?.id {
                activeAgentTask = allAgentTasks.first { $0.id == activeID } ?? activeAgentTask
            }
        } catch {
            presentError(error)
        }
    }

    @discardableResult
    func refreshAgentTask(id: String, reportErrors: Bool = false) async -> AgentTaskSnapshot? {
        do {
            let client = try await connectedClient()
            let task = try await client.loadAgentTask(id: id, userID: userID)
            upsertAgentTask(task)
            if activeAgentTask?.id == id { activeAgentTask = task }
            return task
        } catch {
            if reportErrors { presentError(error) }
            return nil
        }
    }

    func followAgentTask(id: String) async {
        while !Task.isCancelled {
            guard let task = await refreshAgentTask(id: id) else {
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                continue
            }
            if !task.isActive { return }
            do {
                try await Task.sleep(nanoseconds: 700_000_000)
            } catch {
                return
            }
        }
    }

    func selectAgentTask(_ task: AgentTaskSnapshot?) {
        activeAgentTask = task
    }

    func startNewAssistantConversation(refreshConversations: Bool = true) {
        cacheCurrentAssistantConversation()
        activeAgentTask = nil
        conversationTurns = []
        activeTrace = []
        answer = nil
        errorMessage = nil
        sessionID = UUID().uuidString
        UserDefaults.standard.set(sessionID, forKey: "secflow.sessionID")
        if refreshConversations {
            Task { await loadAssistantConversations() }
        }
    }

    func loadAssistantConversations(reportErrors: Bool = false) async {
        busyActions.insert("assistant-conversations")
        defer { busyActions.remove("assistant-conversations") }
        do {
            let client = try await connectedClient()
            async let activeRequest = client.loadAssistantConversations(userID: userID)
            async let archivedRequest = client.loadAssistantConversations(userID: userID, archived: true)
            let active = try await activeRequest
            let archived = try await archivedRequest
            archivedAssistantConversations = archived
            mergeAssistantConversations(
                active,
                archivedConversationIDs: Set(archived.map(\.id))
            )
        } catch {
            if reportErrors || assistantConversations.isEmpty {
                presentError(error)
            }
        }
    }

    func openAssistantConversation(_ conversation: AssistantConversationSummary) async {
        cacheCurrentAssistantConversation()
        activeAgentTask = nil
        activeTrace = []
        answer = nil
        errorMessage = nil
        sessionID = conversation.id
        UserDefaults.standard.set(sessionID, forKey: "secflow.sessionID")
        conversationTurns = assistantConversationCache[conversation.id] ?? []
        answer = conversationTurns.last?.answer

        let action = "assistant-conversation:\(conversation.id)"
        busyActions.insert(action)
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let detail = try await client.loadAssistantConversation(id: conversation.id, userID: userID)
            let restoredTurns = restoredConversationTurns(detail.exchanges)
            assistantConversationCache[conversation.id] = restoredTurns
            guard sessionID == conversation.id, activeAgentTask == nil else { return }
            conversationTurns = restoredTurns
            answer = restoredTurns.last?.answer
        } catch {
            if conversationTurns.isEmpty {
                presentError(error)
            }
        }
    }

    func archiveAssistantConversation(id: String, archived: Bool) async {
        let action = "assistant-conversation-archive:\(id)"
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let conversation = try await client.archiveAssistantConversation(
                id: id,
                userID: userID,
                archived: archived
            )
            assistantConversations.removeAll { $0.id == id }
            archivedAssistantConversations.removeAll { $0.id == id }
            if conversation.archived {
                archivedAssistantConversations.insert(conversation, at: 0)
            } else {
                assistantConversations.insert(conversation, at: 0)
            }
            if archived, activeAgentTask == nil, sessionID == id {
                conversationTurns = []
                startNewAssistantConversation(refreshConversations: false)
            }
        } catch {
            presentError(error)
        }
    }

    @discardableResult
    func deleteAssistantConversation(id: String) async -> Bool {
        let action = "assistant-conversation-delete:\(id)"
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let result = try await client.deleteAssistantConversation(id: id, userID: userID)
            guard result.deleted else { return false }
            assistantConversations.removeAll { $0.id == id }
            archivedAssistantConversations.removeAll { $0.id == id }
            assistantConversationCache.removeValue(forKey: id)
            if activeAgentTask == nil, sessionID == id {
                conversationTurns = []
                startNewAssistantConversation(refreshConversations: false)
            }
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    func openAgentTaskConversation(_ task: AgentTaskSnapshot) {
        activeAgentTask = task
        activeTrace = []
        answer = nil
        errorMessage = nil
        conversationTurns = [
            ConversationTurn(
                question: task.objective,
                attachmentNames: [task.workspaceName],
                agentTaskID: task.id
            )
        ]
    }

    func cancelAgentTask(id: String) async {
        busyActions.insert("agent-task-cancel:\(id)")
        defer { busyActions.remove("agent-task-cancel:\(id)") }
        do {
            let client = try await connectedClient()
            let task = try await client.cancelAgentTask(id: id, userID: userID)
            upsertAgentTask(task)
            activeAgentTask = task
        } catch {
            presentError(error)
        }
    }

    func resumeAgentTask(id: String) async {
        busyActions.insert("agent-task-resume:\(id)")
        defer { busyActions.remove("agent-task-resume:\(id)") }
        do {
            let client = try await connectedClient()
            let task = try await client.resumeAgentTask(id: id, userID: userID)
            upsertAgentTask(task)
            activeAgentTask = task
        } catch {
            presentError(error)
        }
    }

    func decideAgentTaskReport(id: String, generate: Bool) async {
        let action = "agent-task-report:\(id)"
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let task = try await client.decideAgentTaskReport(id: id, userID: userID, generate: generate)
            upsertAgentTask(task)
            if activeAgentTask?.id == id { activeAgentTask = task }
            if generate {
                reports = try await client.loadReports()
            }
        } catch {
            presentError(error)
        }
    }

    func confirmAgentTaskReportDownload(
        id: String,
        format: ReportDownloadFormat,
        confirm: Bool = true
    ) async -> AssistantArtifact? {
        let action = "agent-task-report-download:\(id)"
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let result = try await client.decideAgentTaskReportDownload(
                id: id,
                userID: userID,
                confirm: confirm,
                format: format
            )
            upsertAgentTask(result.task)
            if activeAgentTask?.id == id { activeAgentTask = result.task }
            return result.artifact
        } catch {
            presentError(error)
            return nil
        }
    }

    func archiveAgentTask(id: String, archived: Bool) async {
        let action = "agent-task-archive:\(id)"
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let task = try await client.archiveAgentTask(id: id, userID: userID, archived: archived)
            upsertAgentTask(task)
            if activeAgentTask?.id == id { activeAgentTask = task }
        } catch {
            presentError(error)
        }
    }

    @discardableResult
    func deleteAgentTask(id: String) async -> Bool {
        let action = "agent-task-delete:\(id)"
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let result = try await client.deleteAgentTask(id: id, userID: userID)
            guard result.deleted else { return false }
            agentTasks.removeAll { $0.id == id }
            archivedAgentTasks.removeAll { $0.id == id }
            conversationTurns.removeAll { $0.agentTaskID == id }
            if activeAgentTask?.id == id { activeAgentTask = nil }
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    private func upsertAgentTask(_ task: AgentTaskSnapshot) {
        agentTasks.removeAll { $0.id == task.id }
        archivedAgentTasks.removeAll { $0.id == task.id }
        if task.isArchived {
            archivedAgentTasks.insert(task, at: 0)
        } else {
            agentTasks.insert(task, at: 0)
        }
    }

    private func refreshStateAfterAnswer() async {
        do {
            let client = try await connectedClient()
            let range = dashboardRangeStrings
            async let runtimeRequest: RuntimeStatus? = try? await client.loadRuntime()
            async let dashboardRequest: DashboardSnapshot? = try? await client.loadDashboard(startDate: range.start, endDate: range.end)
            async let recentRequest: [IntelligenceQueryResult]? = try? await client.loadRecentIntelligence()
            async let reportsRequest: [AnalysisReportSummary]? = try? await client.loadReports()
            async let conversationsRequest: [AssistantConversationSummary]? = try? await client.loadAssistantConversations(
                userID: userID
            )
            async let archivedConversationsRequest: [AssistantConversationSummary]? = try? await client.loadAssistantConversations(
                userID: userID,
                archived: true
            )

            runtime = await runtimeRequest
            if let snapshot = await dashboardRequest {
                dashboard = snapshot
            }
            if let recent = await recentRequest {
                queryLogs = recent
            }
            if let loadedReports = await reportsRequest {
                reports = loadedReports
            }
            if let loadedConversations = await conversationsRequest {
                mergeAssistantConversations(
                    loadedConversations,
                    archivedConversationIDs: Set((await archivedConversationsRequest)?.map(\.id) ?? [])
                )
            }
            if let loadedArchivedConversations = await archivedConversationsRequest {
                archivedAssistantConversations = loadedArchivedConversations
            }
        } catch {
            if dashboard == nil {
                presentError(error)
            }
        }
    }

    func loadReports() async {
        busyActions.insert("reports")
        errorMessage = nil
        defer { busyActions.remove("reports") }
        do {
            let client = try await connectedClient()
            reports = try await client.loadReports()
            if selectedReport == nil, let first = reports.first {
                selectedReport = try? await client.loadReport(id: first.id)
            }
        } catch {
            presentError(error)
        }
    }

    @discardableResult
    func refreshInformation(force: Bool = false) async -> Bool {
        let action = "information-refresh"
        guard !busyActions.contains(action) else { return false }
        busyActions.insert(action)
        errorMessage = nil
        defer { busyActions.remove(action) }
        do {
            let client = try await connectedClient()
            let previousLastRefresh = information?.lastRefresh
            var snapshot = force ? try await client.refreshInformation() : try await client.loadInformation()
            information = snapshot
            if force {
                snapshot = try await followInformationRefresh(
                    using: client,
                    initial: snapshot,
                    previousLastRefresh: previousLastRefresh
                )
                information = snapshot
            }
            statusMessage = localizedMessage(information?.message)
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    private func followInformationRefresh(
        using client: APIClient,
        initial: InformationSnapshot,
        previousLastRefresh: String?
    ) async throws -> InformationSnapshot {
        try await resolveInformationRefresh(
            initial: initial,
            previousLastRefresh: previousLastRefresh,
            load: { try await client.loadInformation() }
        ) { [weak self] snapshot in
            guard let self else { return }
            self.information = snapshot
            self.statusMessage = self.localizedMessage(snapshot.message)
        }
    }

    func setInformationSource(id: String, enabled: Bool) async {
        let key = "information-source:\(id)"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            _ = try await client.updateInformationSource(id: id, enabled: enabled)
            information = try await client.loadInformation()
            statusMessage = enabled ? uiText("资讯来源已启用，刷新后获取内容") : uiText("资讯来源已暂停")
        } catch {
            presentError(error)
        }
    }

    func setInformationSources(ids: [String], enabled: Bool) async {
        guard !ids.isEmpty else { return }
        let key = "information-sources-batch"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            _ = try await client.updateInformationSources(ids: ids, enabled: enabled)
            information = try await client.loadInformation()
            statusMessage = enabled
                ? uiText("已批量启用资讯来源，刷新后获取内容")
                : uiText("已批量暂停资讯来源")
        } catch {
            presentError(error)
        }
    }

    func testInformationSource(id: String) async {
        let key = "information-source-test:\(id)"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            let source = try await client.testInformationSource(id: id)
            information = try await client.loadInformation()
            statusMessage = localizedMessage(source.message)
        } catch {
            presentError(error)
        }
    }

    func openReport(_ report: AnalysisReportSummary) async {
        busyActions.insert("report:\(report.id)")
        errorMessage = nil
        defer { busyActions.remove("report:\(report.id)") }
        do {
            let client = try await connectedClient()
            selectedReport = try await client.loadReport(id: report.id)
        } catch {
            presentError(error)
        }
    }

    func downloadReport(_ report: AnalysisReportDetail, to destination: URL, format: ReportDownloadFormat = .markdown) async {
        busyActions.insert("download-report:\(report.id)")
        errorMessage = nil
        defer { busyActions.remove("download-report:\(report.id)") }
        do {
            let client = try await connectedClient()
            let data = try await client.downloadReport(id: report.id, format: format)
            try data.write(to: destination, options: .atomic)
            statusMessage = uiText("报告已保存到 %@", destination.lastPathComponent)
        } catch {
            presentError(error)
        }
    }

    @discardableResult
    func deleteReports(ids: Set<String>) async -> Int {
        guard !ids.isEmpty else { return 0 }
        busyActions.insert("delete-reports")
        errorMessage = nil
        defer { busyActions.remove("delete-reports") }
        do {
            let client = try await connectedClient()
            let result = try await client.deleteReports(ids: ids.sorted())
            reports = try await client.loadReports()
            if let selectedReport, ids.contains(selectedReport.id) {
                self.selectedReport = nil
            }
            if self.selectedReport == nil, let first = reports.first {
                self.selectedReport = try? await client.loadReport(id: first.id)
            }
            statusMessage = uiText("已删除 %d 份报告", result.deleted)
            return result.deleted
        } catch {
            presentError(error)
            return 0
        }
    }

    private var dashboardRangeStrings: (start: String?, end: String?) {
        dashboardRangeStrings(for: dashboardRange)
    }

    private func dashboardRangeStrings(for range: DashboardDateRange?) -> (start: String?, end: String?) {
        guard let range else { return (nil, nil) }
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        formatter.dateFormat = "yyyy-MM-dd"
        return (formatter.string(from: range.start), formatter.string(from: range.end))
    }

    func saveCollector(id: String, update: CollectorUpdate) async {
        await performCollectorAction(key: "save:\(id)") { client in
            let result = try await client.saveCollector(id: id, update: update)
            self.statusMessage = self.localizedMessage(result.message)
        }
    }

    func testCollector(id: String) async {
        await performCollectorAction(key: "test:\(id)") { client in
            let result = try await client.testCollector(id: id)
            self.statusMessage = self.localizedMessage(result.message) ?? result.status ?? self.uiText("连接测试已完成")
        }
    }

    func collect(id: String) async {
        await performCollectorAction(key: "collect:\(id)") { client in
            let result = try await client.collect(id: id)
            self.statusMessage = self.localizedMessage(result.message)
            self.activeTrace = result.trace
            let range = self.dashboardRangeStrings
            self.dashboard = try? await client.loadDashboard(startDate: range.start, endDate: range.end)
        }
    }

    func queryIntelligence(query: String, limit: Int = 10) async {
        let cleanQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanQuery.isEmpty else { return }
        busyActions.insert("intelligence-query")
        errorMessage = nil
        do {
            let client = try await connectedClient()
            let result = try await client.queryIntelligence(
                IntelligenceQueryPayload(query: cleanQuery, limit: limit, responseLanguage: appLanguage.apiCode, sources: nil)
            )
            intelligenceResult = result
            knowledgeGraph = result.graph
            activeTrace = result.trace
            rememberQueryLog(result)
            let range = dashboardRangeStrings
            dashboard = try? await client.loadDashboard(startDate: range.start, endDate: range.end)
            config = try? await client.loadConfig()
            statusMessage = uiText("API 返回 %d 条漏洞记录", result.records.count)
        } catch {
            presentError(error)
        }
        busyActions.remove("intelligence-query")
    }

    func queryComponentVulnerabilities(name: String, version: String, ecosystem: String?) async {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanVersion = version.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanEcosystem = ecosystem?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty, !cleanVersion.isEmpty else {
            errorMessage = uiText("请输入组件名称和明确版本")
            return
        }
        let key = "component-vulnerability-query"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            let result = try await client.queryComponentVulnerabilities(
                ComponentVulnerabilityPayload(
                    name: cleanName,
                    version: cleanVersion,
                    ecosystem: cleanEcosystem?.isEmpty == false ? cleanEcosystem : nil,
                    includeRealtime: true
                )
            )
            componentVulnerabilityResult = result
            knowledgeGraph = result.graph
            statusMessage = uiText("匹配到 %d 条组件漏洞", result.total)
        } catch {
            presentError(error)
        }
    }

    func downloadComponentVulnerabilities(
        name: String,
        version: String,
        ecosystem: String?,
        to destination: URL
    ) async {
        let cleanEcosystem = ecosystem?.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = "component-vulnerability-export"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            let data = try await client.downloadComponentVulnerabilities(
                ComponentVulnerabilityPayload(
                    name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                    version: version.trimmingCharacters(in: .whitespacesAndNewlines),
                    ecosystem: cleanEcosystem?.isEmpty == false ? cleanEcosystem : nil,
                    includeRealtime: true
                )
            )
            try data.write(to: destination, options: .atomic)
            statusMessage = uiText("Excel 已保存到 %@", destination.lastPathComponent)
        } catch {
            presentError(error)
        }
    }

    @discardableResult
    func downloadVulnerabilityComponents(identifier: String, to destination: URL) async -> Bool {
        let cleanIdentifier = identifier.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !cleanIdentifier.isEmpty else {
            errorMessage = uiText("请输入有效的 CVE 或 GHSA 漏洞编号")
            return false
        }
        let key = "vulnerability-component-export"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            let data = try await client.downloadVulnerabilityComponents(
                VulnerabilityComponentExportPayload(identifier: cleanIdentifier)
            )
            try data.write(to: destination, options: .atomic)
            statusMessage = uiText("Excel 已保存到 %@", destination.lastPathComponent)
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    @discardableResult
    func downloadAssistantArtifact(_ artifact: AssistantArtifact, to destination: URL) async -> Bool {
        let key = "assistant-artifact:\(artifact.id)"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            let data = try await client.downloadAssistantArtifact(
                id: artifact.id,
                mediaType: artifact.mediaType
            )
            try data.write(to: destination, options: .atomic)
            statusMessage = artifact.kind == "excel"
                ? uiText("Excel 已保存到 %@", destination.lastPathComponent)
                : uiText("文件已保存到 %@", destination.lastPathComponent)
            return true
        } catch {
            presentError(error)
            return false
        }
    }

    func enterWorkspace(email: String) {
        let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        userID = normalized.isEmpty ? "local-user" : normalized
        UserDefaults.standard.set(userID, forKey: "secflow.userID")
        profileSettings = nil
        profileAvatarImageData = nil
        initialSetupState = .loading
        isAuthenticated = true
    }

    func signOut() {
        isAuthenticated = false
        authScreen = .login
        profileSettings = nil
        profileAvatarImageData = nil
        initialSetupState = .loading
    }

    func showGraph(_ graph: GraphSpec?) {
        activeTrace = (graph?.nodes ?? []).map {
            TraceItem(node: $0.id, status: "graph-node", message: $0.label, time: graph?.name ?? "")
        }
    }

    func isBusy(_ key: String) -> Bool {
        busyActions.contains(key)
    }

    func text(_ key: L10nKey) -> String {
        localized(key, language: appLanguage)
    }

    func uiText(_ text: String, _ arguments: CVarArg...) -> String {
        localizedUI(text, language: appLanguage, arguments: arguments)
    }

    func localizedMessage(_ message: String?) -> String? {
        guard let message else { return nil }
        let clean = message.trimmingCharacters(in: .whitespacesAndNewlines)
        return clean.isEmpty ? nil : localizedBackendDetail(clean)
    }

    private func presentError(_ error: Error) {
        guard !isExpectedCancellation(error) else { return }
        errorMessage = localizedError(error)
    }

    private func localizedError(_ error: Error) -> String {
        if let apiError = error as? APIClientError {
            switch apiError {
            case .invalidServerURL:
                return uiText("服务地址无效，请在设置中填写完整的 http 或 https 地址。")
            case .invalidResponse:
                return uiText("服务返回了无法识别的响应。")
            case let .decoding(detail):
                return uiText("本地数据解析失败：%@", detail)
            case let .server(status, message):
                return "HTTP \(status)：\(localizedBackendDetail(message))"
            case let .stream(message):
                return localizedBackendDetail(message)
            case let .request(id, path, elapsedSeconds, message):
                return uiText(
                    "请求失败 [%@ · %d 秒 · %@]：%@",
                    path,
                    elapsedSeconds,
                    id,
                    localizedBackendDetail(message)
                )
            }
        }
        if let backendError = error as? LocalBackendError {
            switch backendError {
            case .executableMissing:
                return uiText("应用内本地服务缺失，请重新安装 SecFlow。")
            case let .unavailable(detail):
                return uiText("本地服务启动失败：%@", localizedBackendDetail(detail))
            }
        }
        return localizedBackendDetail(error.localizedDescription)
    }

    private func localizedBackendDetail(_ message: String) -> String {
        let clean = message.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean == "服务地址无效，请在设置中填写完整的 http 或 https 地址。" {
            return uiText("服务地址无效，请在设置中填写完整的 http 或 https 地址。")
        }
        if clean == "服务返回了无法识别的响应。" {
            return uiText("服务返回了无法识别的响应。")
        }
        if clean == "应用内本地服务缺失，请重新安装 SecFlow。" {
            return uiText("应用内本地服务缺失，请重新安装 SecFlow。")
        }
        if clean == "模型配置已启用。" {
            return uiText("模型配置已启用。")
        }
        if clean == "模型配置已保存，尚未启用。" {
            return uiText("模型配置已保存，尚未启用。")
        }
        if clean == "未配置可用模型。" {
            return uiText("未配置可用模型。")
        }
        if clean == "模型接口返回格式不符合 OpenAI Chat Completions。" {
            return uiText("模型接口返回格式不符合 OpenAI Chat Completions。")
        }
        if clean == "当前模型未返回可用结果。" {
            return uiText("当前模型未返回可用结果。")
        }
        if clean == "模型接口调用成功。" {
            return uiText("模型接口调用成功。")
        }
        if clean == "填入 API Key 后，可从厂商模型接口同步真实模型列表。" {
            return uiText("填入 API Key 后，可从厂商模型接口同步真实模型列表。")
        }
        if clean == "API 地址需要包含 http:// 或 https://，当前显示内置推荐模型。" {
            return uiText("API 地址需要包含 http:// 或 https://，当前显示内置推荐模型。")
        }
        if clean == "厂商接口未返回可用模型，已使用内置推荐模型。" {
            return uiText("厂商接口未返回可用模型，已使用内置推荐模型。")
        }
        if clean == "已从厂商模型接口同步模型列表。" {
            return uiText("已从厂商模型接口同步模型列表。")
        }
        if clean == "固定接口可访问。" {
            return uiText("固定接口可访问。")
        }
        if clean == "查询完成" {
            return uiText("查询完成")
        }
        if clean == "查询失败" {
            return uiText("查询失败")
        }
        if clean == "部分完成" {
            return uiText("部分完成")
        }
        if clean == "等待查询" {
            return uiText("等待查询")
        }
        if let value = clean.removingKnownPrefix("模型接口请求失败：", suffix: "") {
            return uiText("模型接口请求失败：%@", value)
        }
        if let value = clean.removingKnownPrefix("厂商模型列表同步失败，已使用内置推荐模型：", suffix: "") {
            return uiText("厂商模型列表同步失败，已使用内置推荐模型：%@", value)
        }
        if let value = clean.removingKnownPrefix("开发服务 ", suffix: " 无法连接。") {
            return uiText("开发服务 %@ 无法连接。", value)
        }
        if let value = clean.removingKnownPrefix("", suffix: " 的接口地址需要包含 http:// 或 https://。") {
            return uiText("%@ 的接口地址需要包含 http:// 或 https://。", value)
        }
        if let value = clean.removingKnownPrefix("进程已退出，请查看 ", suffix: "。") {
            return uiText("进程已退出，请查看 %@。", value)
        }
        if let value = clean.removingKnownPrefix("等待本地服务就绪超时，请查看 ", suffix: "。") {
            return uiText("等待本地服务就绪超时，请查看 %@。", value)
        }
        return clean
    }

    func setLanguage(_ language: AppLanguage) {
        appLanguage = language
        UserDefaults.standard.set(language.rawValue, forKey: "secflow.appLanguage")
        statusMessage = "\(localized(.interfaceLanguage, language: language))：\(language.displayName)"
    }

    func previewAppearance(darkMode: Bool, fontSize: String) {
        applyAppearancePreferences(darkMode: darkMode, fontSize: fontSize)
    }

    private func applySettingsSnapshot(_ snapshot: SettingsSnapshot) {
        settings = snapshot
        profileSettings = snapshot.profile
        preferenceSettings = snapshot.preferences
        aboutSettings = snapshot.about
        legalDocuments = snapshot.legal ?? legalDocuments
        applyAppearancePreferences(
            darkMode: snapshot.preferences.darkMode,
            fontSize: snapshot.preferences.fontSize
        )
        if let language = AppLanguage(apiCode: snapshot.preferences.language), language != appLanguage {
            appLanguage = language
            UserDefaults.standard.set(language.rawValue, forKey: "secflow.appLanguage")
        }
    }


    private func applyAppearancePreferences(darkMode: Bool, fontSize: String) {
        let preferences = AppAppearancePreferences(
            darkMode: darkMode,
            fontSize: AppInterfaceFontSize.resolve(fontSize)
        )
        darkModeEnabled = preferences.darkMode
        interfaceFontSize = preferences.fontSize
        preferences.persist()
    }

    private func rebuildSettingsSnapshot() -> SettingsSnapshot? {
        guard let profileSettings, let preferenceSettings, let aboutSettings else {
            return settings
        }
        return SettingsSnapshot(
            profile: profileSettings,
            preferences: preferenceSettings,
            about: aboutSettings,
            legal: legalDocuments.isEmpty ? settings?.legal : legalDocuments
        )
    }

    private func rememberQueryLog(_ result: IntelligenceQueryResult) {
        queryLogs.removeAll { $0.generatedAt == result.generatedAt && $0.query == result.query }
        queryLogs.insert(result, at: 0)
        if queryLogs.count > 30 {
            queryLogs = Array(queryLogs.prefix(30))
        }
    }

    private func performCollectorAction(
        key: String,
        operation: (APIClient) async throws -> Void
    ) async {
        busyActions.insert(key)
        errorMessage = nil
        do {
            let client = try await connectedClient()
            try await operation(client)
            config = try await client.loadConfig()
        } catch {
            presentError(error)
        }
        busyActions.remove(key)
    }

    private func connectedClient() async throws -> APIClient {
        try await localBackend.ensureReady()
        return try APIClient(serverURL: serverURL)
    }

    private func cacheCurrentAssistantConversation() {
        guard activeAgentTask == nil else { return }
        let turns = conversationTurns.filter { $0.agentTaskID == nil }
        guard !turns.isEmpty else { return }
        assistantConversationCache[sessionID] = turns
        guard !archivedAssistantConversations.contains(where: { $0.id == sessionID }) else { return }
        guard let summary = assistantConversationSummary(sessionID: sessionID, turns: turns) else { return }
        assistantConversations.removeAll { $0.id == summary.id }
        assistantConversations.insert(summary, at: 0)
    }

    private func mergeAssistantConversations(
        _ loaded: [AssistantConversationSummary],
        archivedConversationIDs: Set<String> = []
    ) {
        var conversations = Dictionary(uniqueKeysWithValues: loaded.map { ($0.id, $0) })
        for (cachedSessionID, turns) in assistantConversationCache
        where conversations[cachedSessionID] == nil && !archivedConversationIDs.contains(cachedSessionID) {
            conversations[cachedSessionID] = assistantConversationSummary(
                sessionID: cachedSessionID,
                turns: turns
            )
        }
        assistantConversations = conversations.values.sorted {
            if $0.updatedAt == $1.updatedAt { return $0.id > $1.id }
            return $0.updatedAt > $1.updatedAt
        }
    }

    private func assistantConversationSummary(
        sessionID: String,
        turns: [ConversationTurn]
    ) -> AssistantConversationSummary? {
        guard let first = turns.first else { return nil }
        let updatedAt = turns.compactMap { $0.answeredAt ?? $0.askedAt }.max() ?? first.askedAt
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return AssistantConversationSummary(
            id: sessionID,
            title: first.question,
            updatedAt: formatter.string(from: updatedAt),
            turnCount: turns.count
        )
    }

    private func restoredConversationTurns(
        _ exchanges: [AssistantConversationExchange]
    ) -> [ConversationTurn] {
        exchanges.map { exchange in
            let fallbackTimestamp = assistantConversationDate(exchange.timestamp) ?? Date()
            let answer = exchange.answerPayload ?? AskResult(restored: exchange)
            let traceStartedAt = answer.trace.first.flatMap { assistantConversationDate($0.time) }
            let traceEndedAt = answer.trace.last.flatMap { assistantConversationDate($0.time) }
            let generatedAt = assistantConversationDate(answer.generatedAt)
            let responseStartedAt = traceStartedAt ?? fallbackTimestamp
            let answeredAt = traceEndedAt ?? generatedAt ?? fallbackTimestamp
            return ConversationTurn(
                question: exchange.question,
                askedAt: responseStartedAt,
                responseStartedAt: responseStartedAt,
                answer: answer,
                answeredAt: answeredAt,
                processingTrace: answer.trace
            )
        }
    }

    private func assistantConversationDate(_ value: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }

    private func updateInitialSetupState() {
        guard PostLoginSetupRules.isProfileComplete(profileSettings, userID: userID) else {
            initialSetupState = .required
            return
        }
        guard let llmConfig else {
            initialSetupState = .required
            return
        }
        initialSetupState = llmConfig.configured && llmConfig.hasApiKey ? .ready : .required
    }
}

private extension String {
    func removingKnownPrefix(_ prefix: String, suffix: String) -> String? {
        guard hasPrefix(prefix), hasSuffix(suffix), count >= prefix.count + suffix.count else {
            return nil
        }
        return String(dropFirst(prefix.count).dropLast(suffix.count))
    }
}

enum AuthScreen {
    case login
    case register
}

enum InitialSetupState: Equatable {
    case loading
    case required
    case ready
    case failed(String)
}

extension AppLanguage {
    init?(apiCode: String) {
        switch apiCode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "zh-hans", "zh_cn", "zh-cn", "zh", "zhhans":
            self = .zhHans
        case "zh-hant", "zh_tw", "zh-tw", "zh-hk", "zh_hk", "zhtw", "zhhant", "traditional-chinese":
            self = .zhHant
        case "en", "en_us", "en-us", "english":
            self = .en
        case "ko", "ko_kr", "ko-kr", "kr", "korean":
            self = .ko
        case "ja", "ja_jp", "ja-jp", "jp", "japanese":
            self = .ja
        case "es", "es_es", "es-es", "spanish", "español":
            self = .es
        case "fr", "fr_fr", "fr-fr", "french", "français":
            self = .fr
        case "de", "de_de", "de-de", "german", "deutsch":
            self = .de
        case "it", "it_it", "it-it", "italian", "italiano":
            self = .it
        case "ru", "ru_ru", "ru-ru", "russian", "русский":
            self = .ru
        default:
            return nil
        }
    }
}
