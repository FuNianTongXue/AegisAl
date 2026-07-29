import Foundation

enum APIClientError: LocalizedError {
    case invalidServerURL
    case invalidResponse
    case decoding(String)
    case server(status: Int, message: String)
    case stream(String)
    case request(id: String, path: String, elapsedSeconds: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .invalidServerURL:
            return "服务地址无效，请在设置中填写完整的 http 或 https 地址。"
        case .invalidResponse:
            return "服务返回了无法识别的响应。"
        case let .decoding(detail):
            return "本地数据解析失败：\(detail)"
        case let .server(status, message):
            return "HTTP \(status)：\(message)"
        case let .stream(message):
            return message
        case let .request(id, path, elapsedSeconds, message):
            return "请求失败 [\(path) · \(elapsedSeconds)s · \(id)]：\(message)"
        }
    }
}

struct APIClient {
    let baseURL: URL

    init(serverURL: String) throws {
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil
        else {
            throw APIClientError.invalidServerURL
        }
        baseURL = url
    }

    func loadConfig() async throws -> ConfigSnapshot {
        try await request("api/config")
    }

    func loadRuntime() async throws -> RuntimeStatus {
        try await request("api/system/runtime")
    }

    func loadTrialStatus() async throws -> TrialStatusSnapshot {
        try await request("api/trial/status")
    }

    func loadLLMConfig() async throws -> LLMConfigSnapshot {
        try await request("api/llm/config")
    }

    func saveLLMConfig(_ payload: LLMConfigPayload) async throws -> LLMConfigSnapshot {
        try await request("api/llm/config", method: "PATCH", body: payload)
    }

    func testLLMConfig(_ payload: LLMConfigPayload) async throws -> LLMTestResult {
        try await request("api/llm/test", method: "POST", body: payload)
    }

    func loadLLMModels(_ payload: LLMModelsPayload) async throws -> LLMModelCatalog {
        try await request("api/llm/models", method: "POST", body: payload)
    }

    func loadSettings() async throws -> SettingsSnapshot {
        try await request("api/settings")
    }

    func loadProfileSettings() async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile")
    }

    func saveProfileSettings(_ payload: UserProfileSettingsPayload) async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile", method: "PATCH", body: payload)
    }

    func uploadProfileAvatar(_ payload: AvatarUploadPayload) async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile/avatar", method: "POST", body: payload, timeoutInterval: 90)
    }

    func deleteProfileAvatar() async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile/avatar", method: "DELETE")
    }

    func downloadProfileAvatar() async throws -> Data {
        let url = baseURL.appending(path: "api/settings/profile/avatar")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 65
        request.setValue("image/*", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        return data
    }

    func loadPreferenceSettings() async throws -> AppPreferenceSettingsSnapshot {
        try await request("api/settings/preferences")
    }

    func savePreferenceSettings(_ payload: AppPreferenceSettingsPayload) async throws -> AppPreferenceSettingsSnapshot {
        try await request("api/settings/preferences", method: "PATCH", body: payload)
    }

    func loadLegalDocuments() async throws -> [String: LegalDocumentSnapshot] {
        try await request("api/settings/legal")
    }

    func loadLegalDocument(id: String) async throws -> LegalDocumentSnapshot {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request("api/settings/legal/\(cleanID)")
    }

    func loadSubscriptionCatalog() async throws -> SubscriptionCatalog {
        try await request("api/subscriptions/plans")
    }

    func loadCurrentSubscription(userID: String) async throws -> SubscriptionSnapshot {
        try await request(
            "api/subscriptions/current",
            queryItems: [URLQueryItem(name: "user_id", value: userID)]
        )
    }

    func loadSubscriptionUsage(userID: String) async throws -> SubscriptionUsageSnapshot {
        try await request(
            "api/subscriptions/usage",
            queryItems: [URLQueryItem(name: "user_id", value: userID)]
        )
    }

    func loadSubscriptionOrders(userID: String) async throws -> SubscriptionOrderHistory {
        try await request(
            "api/subscriptions/orders",
            queryItems: [URLQueryItem(name: "user_id", value: userID)]
        )
    }

    func checkoutSubscription(_ payload: SubscriptionCheckoutPayload) async throws -> SubscriptionCheckoutResult {
        try await request("api/subscriptions/checkout", method: "POST", body: payload)
    }

    func cancelSubscription(_ payload: SubscriptionCancelPayload) async throws -> SubscriptionSnapshot {
        try await request("api/subscriptions/cancel", method: "POST", body: payload)
    }

    func loadGraph() async throws -> GraphSpec {
        try await request("api/langgraph/assistant")
    }

    func loadCollectorGraph() async throws -> GraphSpec {
        try await request("api/langgraph/collectors")
    }

    func loadDashboard(startDate: String? = nil, endDate: String? = nil) async throws -> DashboardSnapshot {
        var queryItems: [URLQueryItem] = []
        if let startDate, let endDate {
            queryItems = [
                URLQueryItem(name: "start_date", value: startDate),
                URLQueryItem(name: "end_date", value: endDate),
            ]
        }
        return try await request("api/dashboard", queryItems: queryItems)
    }

    func refreshDashboardBatch(_ payload: DashboardRefreshPayload) async throws -> DashboardSnapshot {
        try await request("api/dashboard/refresh", method: "POST", body: payload)
    }

    func loadIntelligenceSources() async throws -> [IntelligenceSource] {
        try await request("api/intelligence/sources")
    }

    func loadRecentIntelligence() async throws -> [IntelligenceQueryResult] {
        try await request("api/intelligence/recent")
    }

    func queryIntelligence(_ payload: IntelligenceQueryPayload) async throws -> IntelligenceQueryResult {
        try await request("api/intelligence/query", method: "POST", body: payload)
    }

    func queryComponentVulnerabilities(_ payload: ComponentVulnerabilityPayload) async throws -> ComponentVulnerabilityResult {
        try await request("api/components/vulnerabilities/query", method: "POST", body: payload, timeoutInterval: 90)
    }

    func downloadComponentVulnerabilities(_ payload: ComponentVulnerabilityPayload) async throws -> Data {
        let url = baseURL.appending(path: "api/components/vulnerabilities/export")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 180
        request.httpBody = try JSONEncoder.secFlow.encode(payload)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            forHTTPHeaderField: "Accept"
        )
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        return data
    }

    func downloadVulnerabilityComponents(_ payload: VulnerabilityComponentExportPayload) async throws -> Data {
        let url = baseURL.appending(path: "api/vulnerabilities/components/export")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 180
        request.httpBody = try JSONEncoder.secFlow.encode(payload)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            forHTTPHeaderField: "Accept"
        )
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        return data
    }

    func downloadAssistantArtifact(id: String, mediaType: String) async throws -> Data {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        let url = baseURL.appending(path: "api/assistant/artifacts/\(cleanID)")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 180
        request.setValue(mediaType, forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        return data
    }

    func loadInformation(refresh: Bool = false) async throws -> InformationSnapshot {
        try await request(
            "api/information",
            queryItems: refresh ? [URLQueryItem(name: "refresh", value: "true")] : [],
            cachePolicy: .reloadIgnoringLocalCacheData
        )
    }

    func refreshInformation() async throws -> InformationSnapshot {
        try await request("api/information/refresh", method: "POST")
    }

    func updateInformationSource(id: String, enabled: Bool) async throws -> InformationSource {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/information/sources/\(cleanID)",
            method: "PATCH",
            body: InformationSourceUpdate(enabled: enabled)
        )
    }

    func updateInformationSources(ids: [String], enabled: Bool) async throws -> [InformationSource] {
        try await request(
            "api/information/sources",
            method: "PATCH",
            body: InformationSourcesUpdate(sourceIds: ids, enabled: enabled)
        )
    }

    func testInformationSource(id: String) async throws -> InformationSource {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request("api/information/sources/\(cleanID)/test", method: "POST")
    }

    func ask(_ payload: AskPayload) async throws -> AskResult {
        try await request("api/assistant/questions", method: "POST", body: payload, timeoutInterval: 90)
    }

    func streamAsk(
        _ payload: AskPayload,
        onTrace: @escaping @MainActor (TraceItem) -> Void,
        onContent: @escaping @MainActor (String) -> Void = { _ in }
    ) async throws -> AskResult {
        let url = baseURL.appending(path: "api/assistant/questions/stream")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 180
        request.httpBody = try JSONEncoder.secFlow.encode(payload)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")

        let (bytes, response) = try await URLSession.shared.bytes(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            throw APIClientError.server(
                status: http.statusCode,
                message: HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            )
        }

        func handle(_ event: ServerSentEvent) async throws -> AskResult? {
            switch event.name {
            case "trace":
                do {
                    let item = try JSONDecoder.secFlow.decode(TraceItem.self, from: Data(event.data.utf8))
                    await onTrace(item)
                    return nil
                } catch {
                    throw APIClientError.decoding(String(describing: error))
                }
            case "content":
                do {
                    let payload = try JSONDecoder.secFlow.decode(
                        AssistantStreamContentPayload.self,
                        from: Data(event.data.utf8)
                    )
                    await onContent(payload.delta)
                    return nil
                } catch {
                    throw APIClientError.decoding(String(describing: error))
                }
            case "result":
                do {
                    return try JSONDecoder.secFlow.decode(AskResult.self, from: Data(event.data.utf8))
                } catch {
                    throw APIClientError.decoding(String(describing: error))
                }
            case "error":
                let payload = try? JSONDecoder.secFlow.decode(
                    AssistantStreamErrorPayload.self,
                    from: Data(event.data.utf8)
                )
                throw APIClientError.stream(payload?.message ?? "智能分析流异常结束。")
            default:
                return nil
            }
        }

        var parser = ServerSentEventParser()
        for try await line in bytes.lines {
            try Task.checkCancellation()
            guard let event = parser.consume(line: line) else { continue }
            if let result = try await handle(event) {
                return result
            }
        }
        if let event = parser.finish(), let result = try await handle(event) {
            return result
        }
        throw APIClientError.stream("智能分析连接已提前结束，请重试。")
    }

    func loadAssistantConversations(
        userID: String,
        limit: Int = 30,
        archived: Bool = false
    ) async throws -> [AssistantConversationSummary] {
        try await request(
            "api/assistant/conversations",
            queryItems: [
                URLQueryItem(name: "user_id", value: userID),
                URLQueryItem(name: "limit", value: String(limit)),
                URLQueryItem(name: "archived", value: archived ? "true" : "false"),
            ]
        )
    }

    func loadAssistantConversation(
        id: String,
        userID: String
    ) async throws -> AssistantConversationDetail {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/assistant/conversations/\(cleanID)",
            queryItems: [URLQueryItem(name: "user_id", value: userID)]
        )
    }

    func archiveAssistantConversation(
        id: String,
        userID: String,
        archived: Bool
    ) async throws -> AssistantConversationSummary {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/assistant/conversations/\(cleanID)/archive",
            method: "POST",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: JSONEncoder.secFlow.encode(AssistantConversationArchivePayload(archived: archived))
        )
    }

    func deleteAssistantConversation(
        id: String,
        userID: String
    ) async throws -> AssistantConversationDeleteResult {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/assistant/conversations/\(cleanID)",
            method: "DELETE",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: nil
        )
    }

    func createAgentTask(_ payload: AgentTaskCreatePayload) async throws -> AgentTaskSnapshot {
        try await request("api/agent/tasks", method: "POST", body: payload, timeoutInterval: 90)
    }

    func startAssistantWorkspaceAction(
        _ payload: AssistantWorkspaceActionPayload
    ) async throws -> AssistantWorkspaceActionResult {
        try await request("api/assistant/workspace-actions", method: "POST", body: payload, timeoutInterval: 900)
    }

    func startAssistantTaskAction(
        taskID: String,
        _ payload: AssistantTaskActionPayload
    ) async throws -> AssistantWorkspaceActionResult {
        let cleanID = taskID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? taskID
        return try await request(
            "api/assistant/tasks/\(cleanID)/actions",
            method: "POST",
            body: payload,
            timeoutInterval: 180
        )
    }

    func loadAgentTasks(
        userID: String,
        limit: Int = 30,
        archived: Bool = false
    ) async throws -> [AgentTaskSnapshot] {
        try await request(
            "api/agent/tasks",
            queryItems: [
                URLQueryItem(name: "user_id", value: userID),
                URLQueryItem(name: "limit", value: String(limit)),
                URLQueryItem(name: "archived", value: archived ? "true" : "false"),
            ]
        )
    }

    func loadAgentTask(id: String, userID: String) async throws -> AgentTaskSnapshot {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/agent/tasks/\(cleanID)",
            queryItems: [URLQueryItem(name: "user_id", value: userID)]
        )
    }

    func cancelAgentTask(id: String, userID: String) async throws -> AgentTaskSnapshot {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/agent/tasks/\(cleanID)/cancel",
            method: "POST",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: nil
        )
    }

    func resumeAgentTask(id: String, userID: String) async throws -> AgentTaskSnapshot {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/agent/tasks/\(cleanID)/resume",
            method: "POST",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: nil
        )
    }

    func decideAgentTaskReport(id: String, userID: String, generate: Bool) async throws -> AgentTaskSnapshot {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/agent/tasks/\(cleanID)/report-decision",
            method: "POST",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: JSONEncoder.secFlow.encode(AgentTaskReportDecisionPayload(generate: generate)),
            timeoutInterval: 180
        )
    }

    func decideAgentTaskReportDownload(
        id: String,
        userID: String,
        confirm: Bool,
        format: ReportDownloadFormat
    ) async throws -> AgentTaskReportDownloadDecisionResult {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/agent/tasks/\(cleanID)/report-download-decision",
            method: "POST",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: JSONEncoder.secFlow.encode(
                AgentTaskReportDownloadDecisionPayload(confirm: confirm, format: format.rawValue)
            ),
            timeoutInterval: 180
        )
    }

    func archiveAgentTask(id: String, userID: String, archived: Bool) async throws -> AgentTaskSnapshot {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/agent/tasks/\(cleanID)/archive",
            method: "POST",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: JSONEncoder.secFlow.encode(AgentTaskArchivePayload(archived: archived))
        )
    }

    func deleteAgentTask(id: String, userID: String) async throws -> AgentTaskDeleteResult {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/agent/tasks/\(cleanID)",
            method: "DELETE",
            queryItems: [URLQueryItem(name: "user_id", value: userID)],
            bodyData: nil
        )
    }

    func loadReports() async throws -> [AnalysisReportSummary] {
        try await request("api/reports")
    }

    func startReportAction(_ payload: ReportActionPayload) async throws -> ReportActionResult {
        try await request("api/reports/actions", method: "POST", body: payload, timeoutInterval: 180)
    }

    func resumeReportAction(_ payload: ReportActionResumePayload) async throws -> ReportActionResult {
        try await resumeAssistantInterrupt(payload)
    }

    func resumeAssistantInterrupt(_ payload: ReportActionResumePayload) async throws -> ReportActionResult {
        try await request("api/assistant/interrupts/resume", method: "POST", body: payload, timeoutInterval: 900)
    }

    func loadReport(id: String) async throws -> AnalysisReportDetail {
        try await request("api/reports/\(id)")
    }

    func downloadReport(id: String, format: ReportDownloadFormat = .markdown) async throws -> Data {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        var components = URLComponents(
            url: baseURL.appending(path: "api/reports/\(cleanID)/download"),
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [URLQueryItem(name: "format", value: format.rawValue)]
        guard let url = components?.url else {
            throw APIClientError.invalidServerURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 65
        request.setValue(format.acceptHeader, forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        return data
    }

    func deleteReports(ids: [String]) async throws -> ReportDeleteResult {
        try await request("api/reports", method: "DELETE", body: ReportDeletePayload(reportIds: ids))
    }

    func saveCollector(id: String, update: CollectorUpdate) async throws -> SaveCollectorResult {
        try await request("api/config/\(id)", method: "PATCH", body: update)
    }

    func testCollector(id: String) async throws -> OperationSummary {
        try await request("api/config/\(id)/test", method: "POST")
    }

    func collect(id: String) async throws -> CollectionResult {
        try await request("api/collect/\(id)", method: "POST")
    }

    private func request<Value: Decodable>(
        _ path: String,
        method: String = "GET",
        queryItems: [URLQueryItem] = [],
        cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy
    ) async throws -> Value {
        try await request(
            path,
            method: method,
            queryItems: queryItems,
            bodyData: nil,
            cachePolicy: cachePolicy
        )
    }

    private func request<Value: Decodable, Body: Encodable>(
        _ path: String,
        method: String,
        body: Body,
        timeoutInterval: TimeInterval = 65
    ) async throws -> Value {
        try await request(
            path,
            method: method,
            queryItems: [],
            bodyData: JSONEncoder.secFlow.encode(body),
            timeoutInterval: timeoutInterval
        )
    }

    private func request<Value: Decodable>(
        _ path: String,
        method: String,
        queryItems: [URLQueryItem],
        bodyData: Data?,
        timeoutInterval: TimeInterval = 65,
        cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy
    ) async throws -> Value {
        let cleanPath = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        var components = URLComponents(
            url: baseURL.appending(path: cleanPath),
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = queryItems.isEmpty ? nil : queryItems
        guard let url = components?.url else {
            throw APIClientError.invalidServerURL
        }
        var request = URLRequest(url: url, cachePolicy: cachePolicy, timeoutInterval: timeoutInterval)
        let requestID = UUID().uuidString
        let startedAt = Date()
        request.httpMethod = method
        request.setValue(requestID, forHTTPHeaderField: "X-Request-ID")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if cachePolicy == .reloadIgnoringLocalCacheData {
            request.setValue("no-cache, no-store", forHTTPHeaderField: "Cache-Control")
            request.setValue("no-cache", forHTTPHeaderField: "Pragma")
        }
        if let bodyData {
            request.httpBody = bodyData
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch let error as URLError {
            let elapsed = max(0, Int(Date().timeIntervalSince(startedAt)))
            let message = error.code == .timedOut
                ? "请求超时，可以重试。"
                : error.localizedDescription
            throw APIClientError.request(
                id: requestID,
                path: cleanPath,
                elapsedSeconds: elapsed,
                message: message
            )
        }
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        do {
            return try JSONDecoder.secFlow.decode(APIEnvelope<Value>.self, from: data).data
        } catch {
            throw APIClientError.decoding(String(describing: error))
        }
    }
}

private struct ErrorPayload: Decodable {
    let detail: String?
    let message: String?

    var resolvedMessage: String {
        detail ?? message ?? "服务请求失败。"
    }
}

private struct AssistantStreamErrorPayload: Decodable {
    let message: String
}

private struct AssistantStreamContentPayload: Decodable {
    let delta: String
}

struct ServerSentEvent: Equatable {
    let name: String
    let data: String
}

struct ServerSentEventParser {
    private var eventName = "message"
    private var dataLines: [String] = []

    mutating func consume(line: String) -> ServerSentEvent? {
        if line.isEmpty {
            return finish()
        }
        guard !line.hasPrefix(":") else { return nil }
        if line.hasPrefix("event:") {
            let pending = finish()
            eventName = String(line.dropFirst("event:".count)).trimmingCharacters(in: .whitespaces)
            return pending
        } else if line.hasPrefix("data:") {
            var value = String(line.dropFirst("data:".count))
            if value.first == " " {
                value.removeFirst()
            }
            dataLines.append(value)
        }
        return nil
    }

    mutating func finish() -> ServerSentEvent? {
        guard !dataLines.isEmpty else {
            eventName = "message"
            return nil
        }
        let event = ServerSentEvent(name: eventName, data: dataLines.joined(separator: "\n"))
        eventName = "message"
        dataLines.removeAll(keepingCapacity: true)
        return event
    }
}
