import Foundation

struct APIEnvelope<Value: Decodable>: Decodable {
    let status: String
    let message: String
    let data: Value
}

struct ConfigSnapshot: Decodable {
    let collectors: [String: CollectorConfig]
    let records: [VulnerabilityRecord]
    let stats: VulnerabilityStats
    let runtime: RuntimeStatus?
    let dashboard: DashboardSnapshot?
}

struct CollectorConfig: Codable, Identifiable, Equatable {
    let id: String
    let name: String
    var enabled: Bool
    var apiUrl: String
    var apiKey: String?
    var token: String?
    var collectionName: String
    var severityFilter: [String]
    var ecosystem: String?
    var maxResults: Int
    var syncIntervalMinutes: Int
    var lastTest: OperationSummary?
    var lastCollect: OperationSummary?
}

struct OperationSummary: Codable, Equatable {
    let status: String?
    let message: String?
    let inserted: Int?
    let fetched: Int?
    let checkedAt: String?
}

struct VulnerabilityRecord: Codable, Identifiable, Equatable {
    let id: String
    let title: String
    let severity: String
    let cvssScore: Double?
    let source: String?
    let summary: String?
    let affectedVersions: [String]?
    let fixedVersions: [String]?
    let references: [String]?
    let collection: String?
    let publishedAt: String?
    let updatedAt: String
}

struct VulnerabilityStats: Codable, Equatable {
    let total: Int
    let byCollection: [String: Int]
    let bySeverity: [String: Int]
}

struct RuntimeStatus: Codable, Equatable {
    let llm: LLMRuntime
    let memory: MemoryRuntime
}

struct TrialStatusSnapshot: Codable, Equatable {
    let enabled: Bool
    let usable: Bool
    let state: String
    let durationHours: Int
    let startedAt: String?
    let expiresAt: String?
    let lastSeenAt: String?
    let secondsRemaining: Int?
    let message: String

    func isUsable(at date: Date) -> Bool {
        guard enabled else { return true }
        guard usable else { return false }
        guard let expirationDate else { return usable }
        return date < expirationDate
    }

    func remainingSeconds(at date: Date) -> Int {
        guard let expirationDate else { return max(0, secondsRemaining ?? 0) }
        return max(0, Int(expirationDate.timeIntervalSince(date).rounded(.up)))
    }

    var startedDate: Date? { Self.parseDate(startedAt) }
    var expirationDate: Date? { Self.parseDate(expiresAt) }
    var durationLabel: String {
        if durationHours.isMultiple(of: 24) {
            return "\(durationHours / 24) 天"
        }
        return "\(durationHours) 小时"
    }

    private static func parseDate(_ value: String?) -> Date? {
        guard let value else { return nil }
        return ISO8601DateFormatter().date(from: value)
    }
}

struct LLMRuntime: Codable, Equatable {
    let configured: Bool
    let provider: String?
    let model: String?
    let endpoint: String?
    let message: String?
}

struct MemoryRuntime: Codable, Equatable {
    let backend: String
    let historyCount: Int
    let configured: Bool?
    let message: String?
}

struct LLMConfigSnapshot: Codable, Equatable {
    let name: String?
    let provider: String
    let catalogProvider: String?
    let model: String
    let endpoint: String?
    let wireApi: String?
    let reasoningEffort: String?
    let disableResponseStorage: Bool?
    let enabled: Bool
    let configured: Bool
    let hasApiKey: Bool
    let apiKeyMasked: String?
    let message: String?
    let updatedAt: String?
}

struct LLMConfigPayload: Encodable {
    let provider: String
    let catalogProvider: String?
    let model: String
    let endpoint: String?
    let apiKey: String?
    let enabled: Bool
    let maxTokens: Int
    let temperature: Double
    let topP: Double
    let timeoutMs: Int
    let wireApi: String?
    let reasoningEffort: String?
    let disableResponseStorage: Bool?

    init(
        provider: String,
        catalogProvider: String? = nil,
        model: String,
        endpoint: String?,
        apiKey: String?,
        enabled: Bool,
        maxTokens: Int,
        temperature: Double,
        topP: Double,
        timeoutMs: Int,
        wireApi: String? = nil,
        reasoningEffort: String? = nil,
        disableResponseStorage: Bool? = nil
    ) {
        self.provider = provider
        self.catalogProvider = catalogProvider
        self.model = model
        self.endpoint = endpoint
        self.apiKey = apiKey
        self.enabled = enabled
        self.maxTokens = maxTokens
        self.temperature = temperature
        self.topP = topP
        self.timeoutMs = timeoutMs
        self.wireApi = wireApi
        self.reasoningEffort = reasoningEffort
        self.disableResponseStorage = disableResponseStorage
    }
}

struct LLMModelsPayload: Encodable {
    let provider: String
    let catalogProvider: String
    let endpoint: String?
    let apiKey: String?
    let timeoutMs: Int
}

struct LLMModelCatalog: Decodable, Equatable {
    let provider: String
    let source: String
    let models: [LLMRemoteModel]
    let message: String?
}

struct LLMRemoteModel: Decodable, Identifiable, Equatable {
    let id: String
    let name: String?
    let description: String?
}

struct LLMTestResult: Decodable, Equatable {
    let status: String
    let message: String
    let latencyMs: Int?
    let provider: String
    let model: String
    let configured: Bool
}

struct SettingsSnapshot: Decodable, Equatable {
    let profile: UserProfileSettingsSnapshot
    let preferences: AppPreferenceSettingsSnapshot
    let about: AboutSettingsSnapshot
    let legal: [String: LegalDocumentSnapshot]?
}

struct UserProfileSettingsSnapshot: Codable, Equatable {
    let displayName: String
    let email: String
    let phone: String
    let department: String
    let role: String
    let employeeId: String
    let bio: String
    let avatarFileName: String
    let avatarContentType: String
    let avatarUpdatedAt: String
    let updatedAt: String
    let avatarAvailable: Bool
}

struct UserProfileSettingsPayload: Encodable {
    let displayName: String
    let email: String
    let phone: String
    let department: String
    let role: String
    let employeeId: String
    let bio: String
}

struct AvatarUploadPayload: Encodable {
    let fileName: String
    let contentBase64: String
    let contentType: String?
}

struct AppPreferenceSettingsSnapshot: Codable, Equatable {
    let language: String
    let darkMode: Bool
    let fontSize: String
    let launchAtLogin: Bool
    let autoCheckUpdates: Bool
    let updatedAt: String
}

struct AppPreferenceSettingsPayload: Encodable {
    let language: String
    let darkMode: Bool
    let fontSize: String
    let launchAtLogin: Bool
    let autoCheckUpdates: Bool
}

struct AboutSettingsSnapshot: Decodable, Equatable {
    let name: String
    let subtitle: String
    let version: String
    let releaseChannel: String?
    let versionLabel: String?
    let latest: Bool
    let lastCheckedAt: String
    let copyright: String
    let features: [String]
}

struct LegalDocumentSnapshot: Codable, Equatable, Identifiable {
    let id: String
    let title: String
    let heading: String
    let updatedAt: String
    let effectiveAt: String
    let intro: String
    let sections: [LegalDocumentSectionSnapshot]
    let revisionUpdatedAt: String?
}

struct LegalDocumentSectionSnapshot: Codable, Equatable {
    let heading: String
    let paragraphs: [String]
}

struct SubscriptionCatalog: Decodable, Equatable {
    let plans: [SubscriptionPlan]
    let paymentMethods: [SubscriptionPaymentMethod]
    let currency: String
}

struct SubscriptionPlan: Codable, Equatable, Identifiable {
    let id: String
    let name: String
    let periodName: String
    let billingPeriod: String
    let intervalMonths: Int
    let priceCents: Int
    let originalPriceCents: Int
    let currency: String
    let discountPercent: Int
    let badge: String
    let description: String
    let features: [String]
    let recommended: Bool

    var priceText: String { Self.currencyText(cents: priceCents) }

    var monthlyEquivalentText: String {
        guard intervalMonths > 0 else { return priceText }
        return Self.currencyText(cents: Int((Double(priceCents) / Double(intervalMonths)).rounded()))
    }

    private static func currencyText(cents: Int) -> String {
        if cents.isMultiple(of: 100) {
            return "¥\(cents / 100)"
        }
        return String(format: "¥%.2f", Double(cents) / 100.0)
    }
}

struct SubscriptionPaymentMethod: Codable, Equatable, Identifiable {
    let id: String
    let name: String
}

struct SubscriptionSnapshot: Decodable, Equatable {
    let userId: String
    let planId: String
    let planName: String
    let periodName: String
    let status: String
    let autoRenew: Bool
    let cancelAtPeriodEnd: Bool
    let currentPeriodStart: String?
    let currentPeriodEnd: String?
    let paymentMethod: String?
    let latestOrderId: String?
    let canceledAt: String?
    let cancelReason: String
    let updatedAt: String

    var isActive: Bool { status == "active" }
}

struct SubscriptionUsageSnapshot: Decodable, Equatable {
    let userId: String
    let periodStart: String
    let periodEnd: String
    let metrics: [SubscriptionUsageMetric]
    let updatedAt: String
}

struct SubscriptionUsageMetric: Decodable, Equatable, Identifiable {
    let id: String
    let label: String
    let used: Int
    let limit: Int
    let unit: String

    var progress: Double {
        guard limit > 0 else { return 0 }
        return min(1, max(0, Double(used) / Double(limit)))
    }
}

struct SubscriptionOrderHistory: Decodable, Equatable {
    let orders: [SubscriptionOrder]
    let total: Int
}

struct SubscriptionOrder: Decodable, Equatable, Identifiable {
    let id: String
    let userId: String
    let planId: String
    let planName: String
    let periodName: String
    let paymentMethod: String
    let amountCents: Int
    let currency: String
    let status: String
    let providerTransactionId: String?
    let paymentUrl: String?
    let createdAt: String
    let updatedAt: String
    let paidAt: String?

    var amountText: String {
        if amountCents.isMultiple(of: 100) {
            return "¥\(amountCents / 100)"
        }
        return String(format: "¥%.2f", Double(amountCents) / 100.0)
    }
}

struct SubscriptionCheckoutPayload: Encodable {
    let userId: String
    let planId: String
    let paymentMethod: String
    let idempotencyKey: String
}

struct SubscriptionCheckoutResult: Decodable, Equatable {
    let checkoutStatus: String
    let providerConfigured: Bool
    let paymentUrl: String?
    let reused: Bool
    let order: SubscriptionOrder
    let message: String
}

struct SubscriptionCancelPayload: Encodable {
    let userId: String
    let reason: String?
}

struct AskResult: Decodable, Equatable {
    let mode: String
    let summary: String
    let fields: [String: String]
    let vulnerabilityCard: [String: String]?
    let knowledgeGraph: KnowledgeGraphPayload?
    let componentDetail: ComponentVulnerabilityDetailPayload?
    let evidenceSources: [AssistantEvidenceSource]
    let chartData: DependencyChartData?
    let artifacts: [AssistantArtifact]
    let report: AnalysisReportSummary?
    let interrupt: ReportInterruptEnvelope?
    let agentTask: AgentTaskSnapshot?
    let tokenUsage: Int
    let confidence: Double
    let trace: [TraceItem]
    let generatedAt: String

    private enum CodingKeys: String, CodingKey {
        case mode
        case summary
        case fields
        case vulnerabilityCard
        case knowledgeGraph
        case componentDetail
        case evidenceSources
        case chartData
        case artifacts
        case report
        case interrupt
        case agentTask
        case tokenUsage
        case confidence
        case trace
        case generatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decode(String.self, forKey: .mode)
        summary = try container.decode(String.self, forKey: .summary)
        fields = try container.decodeIfPresent([String: JSONValue].self, forKey: .fields)?
            .mapValues(\.text) ?? [:]
        vulnerabilityCard = try container.decodeIfPresent([String: JSONValue].self, forKey: .vulnerabilityCard)?
            .mapValues(\.text)
        knowledgeGraph = try container.decodeIfPresent(KnowledgeGraphPayload.self, forKey: .knowledgeGraph)
        // Component detail is optional enrichment. Legacy responses may contain
        // an empty object, which must not make the complete assistant answer fail.
        componentDetail = try? container.decode(ComponentVulnerabilityDetailPayload.self, forKey: .componentDetail)
        evidenceSources = try container.decodeIfPresent([AssistantEvidenceSource].self, forKey: .evidenceSources) ?? []
        chartData = try container.decodeIfPresent(DependencyChartData.self, forKey: .chartData)
        artifacts = try container.decodeIfPresent([AssistantArtifact].self, forKey: .artifacts) ?? []
        // Download-only report actions may return a legacy empty object because
        // they prepare an existing artifact instead of creating a new report.
        report = try? container.decode(AnalysisReportSummary.self, forKey: .report)
        interrupt = try container.decodeIfPresent(ReportInterruptEnvelope.self, forKey: .interrupt)
        agentTask = try container.decodeIfPresent(AgentTaskSnapshot.self, forKey: .agentTask)
        tokenUsage = try container.decodeIfPresent(Int.self, forKey: .tokenUsage) ?? 0
        confidence = try container.decode(Double.self, forKey: .confidence)
        trace = try container.decode([TraceItem].self, forKey: .trace)
        generatedAt = try container.decode(String.self, forKey: .generatedAt)
    }

    init(restored exchange: AssistantConversationExchange) {
        mode = exchange.mode.isEmpty ? "llm_direct" : exchange.mode
        summary = exchange.answer
        fields = exchange.fields
        vulnerabilityCard = nil
        knowledgeGraph = nil
        componentDetail = nil
        evidenceSources = []
        chartData = nil
        artifacts = []
        report = nil
        interrupt = nil
        agentTask = nil
        tokenUsage = 0
        confidence = exchange.confidence
        trace = []
        generatedAt = exchange.timestamp
    }

    init(
        localSummary summary: String,
        mode: String,
        fields: [String: String] = [:],
        vulnerabilityCard: [String: String]? = nil,
        trace: [TraceItem] = [],
        generatedAt: String
    ) {
        self.mode = mode
        self.summary = summary
        self.fields = fields
        self.vulnerabilityCard = vulnerabilityCard
        knowledgeGraph = nil
        componentDetail = nil
        evidenceSources = []
        chartData = nil
        artifacts = []
        report = nil
        interrupt = nil
        agentTask = nil
        tokenUsage = 0
        confidence = 1
        self.trace = trace
        self.generatedAt = generatedAt
    }
}

struct ComponentVulnerabilityDetailPayload: Decodable, Equatable {
    let schemaVersion: Int
    let renderer: String
    let component: ComponentVulnerabilityCoordinate
    let total: Int
    let previewCount: Int
    let truncated: Bool
    let vulnerabilities: [ComponentVulnerabilityDetailItem]
    let generatedAt: String
}

extension ComponentVulnerabilityDetailPayload {
    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case renderer
        case component
        case total
        case previewCount
        case truncated
        case vulnerabilities
        case generatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        renderer = try container.decode(String.self, forKey: .renderer)
        component = try container.decode(ComponentVulnerabilityCoordinate.self, forKey: .component)
        total = try container.decode(Int.self, forKey: .total)
        previewCount = try container.decode(Int.self, forKey: .previewCount)
        truncated = try container.decode(Bool.self, forKey: .truncated)
        vulnerabilities = try container.decode([ComponentVulnerabilityDetailItem].self, forKey: .vulnerabilities)
        generatedAt = try container.decode(String.self, forKey: .generatedAt)
    }
}

struct ComponentVulnerabilityDetailItem: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let severity: String
    let severityLabel: String
    let description: String
    let vulnerabilityType: String
    let aliases: [String]
    let cwes: [String]
    let publishedAt: String
    let updatedAt: String
    let affectedPackages: [ComponentDetailAffectedPackage]
    let affectedVersions: [String]
    let fixedVersions: [String]
    let remediation: String
    let exploitStatus: String
    let exploitStatusCode: String
    let exploitDifficulty: String
    let referenceLinks: [ComponentDetailReference]
    let cvss: ComponentDetailCVSS
}

struct ComponentDetailAffectedPackage: Decodable, Equatable, Identifiable {
    let name: String
    let ecosystem: String
    let affectedVersions: [String]
    let fixedVersions: [String]

    var id: String {
        [ecosystem, name, affectedVersions.joined(separator: ","), fixedVersions.joined(separator: ",")]
            .joined(separator: ":")
    }
}

struct ComponentDetailReference: Decodable, Equatable, Identifiable {
    let title: String
    let url: String

    var id: String { url }
}

struct ComponentDetailCVSS: Decodable, Equatable {
    let score: Double?
    let rating: String
    let vector: String
    let version: String
    let metrics: [ComponentDetailCVSSMetric]
}

struct ComponentDetailCVSSMetric: Decodable, Equatable, Identifiable {
    let key: String
    let label: String
    let value: String

    var id: String { key }
}

struct AssistantEvidenceSource: Decodable, Equatable, Identifiable {
    let id: String
    let status: String
    let count: Int
}

struct ReportInterruptEnvelope: Codable, Equatable, Identifiable {
    let interruptId: String
    let threadId: String
    let kind: String
    let action: String
    let question: String
    let detail: String?
    let options: [String]
    let reportIds: [String]?
    let artifactIds: [String]?
    let formats: [String]?
    let allowFormatSelection: Bool?
    let destinationHint: String?

    var id: String { interruptId }
}

struct ReportActionPayload: Encodable {
    let action: String
    let reportIds: [String]
    let formats: [String]
    let userId: String
    let sessionId: String
    let responseLanguage: String
}

struct ReportActionResumePayload: Encodable {
    let threadId: String
    let interruptId: String?
    let decision: String
    let format: String?
    let userId: String
    let sessionId: String
}

struct ReportActionResult: Decodable, Equatable {
    let status: String
    let threadId: String
    let interrupt: ReportInterruptEnvelope?
    let summary: String
    let report: AnalysisReportSummary?
    let artifacts: [AssistantArtifact]
    let error: String
    let answer: AskResult?
    let reportMcp: ReportMCPAudit?
    let reportMcps: [ReportMCPAudit]?

    private enum CodingKeys: String, CodingKey {
        case status
        case threadId
        case interrupt
        case summary
        case report
        case artifacts
        case error
        case answer
        case reportMcp
        case reportMcps
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        threadId = try container.decode(String.self, forKey: .threadId)
        interrupt = try container.decodeIfPresent(ReportInterruptEnvelope.self, forKey: .interrupt)
        summary = try container.decode(String.self, forKey: .summary)
        report = try? container.decode(AnalysisReportSummary.self, forKey: .report)
        artifacts = try container.decodeIfPresent([AssistantArtifact].self, forKey: .artifacts) ?? []
        error = try container.decodeIfPresent(String.self, forKey: .error) ?? ""
        answer = try container.decodeIfPresent(AskResult.self, forKey: .answer)
        reportMcp = try? container.decode(ReportMCPAudit.self, forKey: .reportMcp)
        reportMcps = try container.decodeIfPresent([ReportMCPAudit].self, forKey: .reportMcps)
    }
}

struct AssistantArtifact: Decodable, Equatable, Identifiable {
    let id: String
    let kind: String
    let fileName: String
    let mediaType: String
    let downloadPath: String
    let sha256: String
    let size: Int
    let generatedAt: String
}

struct DependencyChartData: Codable, Equatable {
    let schemaVersion: Int?
    let sankey: SankeyChartData?
    let severityRing: [ChartMetric]
    let riskBars: [ChartMetric]
    let dag: DAGChartData?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case sankey
        case severityRing
        case riskBars
        case dag
    }

    init(
        schemaVersion: Int? = nil,
        sankey: SankeyChartData? = nil,
        severityRing: [ChartMetric] = [],
        riskBars: [ChartMetric] = [],
        dag: DAGChartData? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.sankey = sankey
        self.severityRing = severityRing
        self.riskBars = riskBars
        self.dag = dag
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion)
        sankey = try container.decodeIfPresent(SankeyChartData.self, forKey: .sankey)
        severityRing = try container.decodeIfPresent([ChartMetric].self, forKey: .severityRing) ?? []
        riskBars = try container.decodeIfPresent([ChartMetric].self, forKey: .riskBars) ?? []
        dag = try container.decodeIfPresent(DAGChartData.self, forKey: .dag)
    }

    var hasContent: Bool {
        !(sankey?.nodes.isEmpty ?? true)
            || !severityRing.isEmpty
            || !riskBars.isEmpty
            || !(dag?.nodes.isEmpty ?? true)
    }
}

struct SankeyChartData: Codable, Equatable {
    let nodes: [ChartNode]
    let links: [ChartLink]
}

struct DAGChartData: Codable, Equatable {
    let nodes: [ChartNode]
    let edges: [ChartLink]
}

struct ChartNode: Codable, Equatable, Identifiable {
    let id: String
    let label: String
    let type: String
    let severity: String?
    let column: Int?
    let version: String?
    let ecosystem: String?
}

struct ChartLink: Codable, Equatable, Identifiable {
    let from: String
    let to: String
    let type: String?
    let value: Int
    let severity: String?

    var id: String { "\(from)|\(type ?? "edge")|\(to)" }
}

struct ChartMetric: Codable, Equatable, Identifiable {
    let id: String
    let label: String?
    let key: String?
    let value: Int

    private enum CodingKeys: String, CodingKey {
        case id
        case label
        case key
        case value
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        key = try container.decodeIfPresent(String.self, forKey: .key)
        label = try container.decodeIfPresent(String.self, forKey: .label)
        value = try container.decodeIfPresent(Int.self, forKey: .value) ?? 0
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? key ?? label ?? UUID().uuidString
    }
}

struct AnalysisReportSummary: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let fileName: String
    let availableFormats: [String]?
    let createdAt: String
    let mode: String
    let vulnerabilityCount: Int
    let findingCount: Int
}

struct AnalysisReportDetail: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let fileName: String
    let availableFormats: [String]?
    let createdAt: String
    let mode: String
    let vulnerabilityCount: Int
    let findingCount: Int
    let content: String
    let metadata: AnalysisReportMetadata?
}

struct AnalysisReportMetadata: Decodable, Equatable {
    let reportCharts: ScanReportCharts?
    let reportMcp: ReportMCPAudit?
    let reportMcps: [ReportMCPAudit]?
}

struct ReportMCPAudit: Decodable, Equatable {
    let server: String
    let tool: String
    let transport: String
    let status: String
    let invokedAt: String
    let factCount: Int?
    let renderer: String?
    let inputSha256: String?
    let outputSha256: String?
    let mediaType: String?
    let artifactSize: Int?
    let error: String?

    var isCompleted: Bool { status.lowercased() == "completed" }
}

struct ScanReportCharts: Decodable, Equatable {
    let schemaVersion: Int
    let renderer: String
    let severityRing: [ChartMetric]
    let riskBars: [ChartMetric]
    let sankeyNodes: [ChartNode]
    let sankeyLinks: [ScanReportChartLink]
    let sourceKind: String
    let factCount: Int

    var chartData: DependencyChartData {
        DependencyChartData(
            schemaVersion: schemaVersion,
            sankey: SankeyChartData(
                nodes: sankeyNodes,
                links: sankeyLinks.map {
                    ChartLink(from: $0.source, to: $0.target, type: $0.type, value: $0.value, severity: $0.severity)
                }
            ),
            severityRing: severityRing,
            riskBars: riskBars
        )
    }
}

struct ScanReportChartLink: Decodable, Equatable {
    let source: String
    let target: String
    let type: String?
    let value: Int
    let severity: String?
}

enum ReportDownloadFormat: String, CaseIterable, Identifiable {
    case markdown = "md"
    case html
    case word = "docx"
    case pdf

    var id: String { rawValue }

    var label: String {
        switch self {
        case .markdown: "Markdown"
        case .html: "HTML"
        case .word: "Word"
        case .pdf: "PDF"
        }
    }

    var fileExtension: String {
        switch self {
        case .markdown: "md"
        case .html: "html"
        case .word: "docx"
        case .pdf: "pdf"
        }
    }

    var acceptHeader: String {
        switch self {
        case .markdown: "text/markdown"
        case .html: "text/html"
        case .word: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        case .pdf: "application/pdf"
        }
    }
}

struct ReportDeletePayload: Encodable {
    let reportIds: [String]
}

struct ReportDeleteResult: Decodable, Equatable {
    let requested: Int
    let deleted: Int
    let deletedIds: [String]
    let missingIds: [String]
}

struct AssistantConversationSummary: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let updatedAt: String
    let turnCount: Int
    let projectId: String
    let projectName: String
    let archived: Bool
    let archivedAt: String?

    init(
        id: String,
        title: String,
        updatedAt: String,
        turnCount: Int,
        projectId: String = "assistant",
        projectName: String = "智能问答",
        archived: Bool = false,
        archivedAt: String? = nil
    ) {
        self.id = id
        self.title = title
        self.updatedAt = updatedAt
        self.turnCount = turnCount
        self.projectId = projectId
        self.projectName = projectName
        self.archived = archived
        self.archivedAt = archivedAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case updatedAt
        case turnCount
        case projectId
        case projectName
        case archived
        case archivedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        updatedAt = try container.decode(String.self, forKey: .updatedAt)
        turnCount = try container.decode(Int.self, forKey: .turnCount)
        projectId = try container.decodeIfPresent(String.self, forKey: .projectId) ?? "assistant"
        projectName = try container.decodeIfPresent(String.self, forKey: .projectName) ?? "智能问答"
        archived = try container.decodeIfPresent(Bool.self, forKey: .archived) ?? false
        archivedAt = try container.decodeIfPresent(String.self, forKey: .archivedAt)
    }
}

struct AssistantConversationDetail: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let updatedAt: String
    let exchanges: [AssistantConversationExchange]
}

struct AssistantConversationExchange: Decodable, Equatable, Identifiable {
    let id: String
    let question: String
    let answer: String
    let mode: String
    let confidence: Double
    let fields: [String: String]
    let answerPayload: AskResult?
    let timestamp: String

    private enum CodingKeys: String, CodingKey {
        case id
        case question
        case answer
        case mode
        case confidence
        case fields
        case answerPayload
        case timestamp
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        question = try container.decode(String.self, forKey: .question)
        answer = try container.decode(String.self, forKey: .answer)
        mode = try container.decodeIfPresent(String.self, forKey: .mode) ?? "llm_direct"
        confidence = try container.decodeIfPresent(Double.self, forKey: .confidence) ?? 0
        fields = try container.decodeIfPresent([String: JSONValue].self, forKey: .fields)?
            .mapValues(\.text) ?? [:]
        answerPayload = try container.decodeIfPresent(AskResult.self, forKey: .answerPayload)
        timestamp = try container.decode(String.self, forKey: .timestamp)
    }
}

struct AssistantConversationArchivePayload: Encodable {
    let archived: Bool
}

struct AssistantConversationDeleteResult: Decodable, Equatable {
    let id: String
    let title: String
    let deleted: Bool
    let deletedTurnCount: Int
}

struct ConversationTurn: Identifiable, Equatable {
    let id: UUID
    let question: String
    let attachmentNames: [String]
    var agentTaskID: String?
    var showsAgentTaskWorkflow: Bool
    let askedAt: Date
    var responseStartedAt: Date
    var streamedAnswer: String
    var answer: AskResult?
    var answeredAt: Date?
    var errorMessage: String?
    var processingTrace: [TraceItem]

    var attachmentName: String? { attachmentNames.first }

    init(
        id: UUID = UUID(),
        question: String,
        attachmentName: String? = nil,
        attachmentNames: [String]? = nil,
        agentTaskID: String? = nil,
        showsAgentTaskWorkflow: Bool? = nil,
        askedAt: Date = Date(),
        responseStartedAt: Date? = nil,
        streamedAnswer: String = "",
        answer: AskResult? = nil,
        answeredAt: Date? = nil,
        errorMessage: String? = nil,
        processingTrace: [TraceItem] = []
    ) {
        self.id = id
        self.question = question
        self.agentTaskID = agentTaskID
        self.showsAgentTaskWorkflow = showsAgentTaskWorkflow ?? (agentTaskID != nil)
        if let attachmentNames {
            self.attachmentNames = attachmentNames
        } else if let attachmentName {
            self.attachmentNames = [attachmentName]
        } else {
            self.attachmentNames = []
        }
        self.processingTrace = processingTrace
        self.askedAt = askedAt
        self.responseStartedAt = responseStartedAt ?? askedAt
        self.streamedAnswer = streamedAnswer
        self.answer = answer
        self.answeredAt = answeredAt
        self.errorMessage = errorMessage
    }
}

struct TraceItem: Codable, Equatable, Identifiable {
    var traceId: String? = nil
    let node: String
    let status: String
    let message: String
    let time: String
    var presentation: LangGraphNodePresentation? = nil

    var id: String {
        let stableID = traceId?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return stableID.isEmpty ? "\(node)|\(time)|\(message)" : stableID
    }
}

struct LangGraphNodePresentation: Codable, Equatable {
    let kind: String
    let title: String?
    let toolName: String?
    let state: String?
    let input: [String: String]?
    let output: String?
    let error: String?
    let before: String?
    let after: String?
}

struct GraphSpec: Decodable, Equatable {
    let name: String
    let nodes: [WorkflowNode]
    let edges: [WorkflowEdge]
}

struct WorkflowNode: Decodable, Equatable, Identifiable {
    let id: String
    let label: String
}

struct WorkflowEdge: Decodable, Equatable, Identifiable {
    let source: String
    let target: String
    let label: String

    var id: String { "\(source)|\(target)|\(label)" }
}

struct CollectionResult: Decodable, Equatable {
    let status: String
    let message: String
    let inserted: Int
    let fetched: Int
    let records: [VulnerabilityRecord]
    let years: [Int]
    let errors: [String]
    let trace: [TraceItem]
}

struct SaveCollectorResult: Decodable {
    let collector: CollectorConfig
    let message: String
}

struct CollectorUpdate: Encodable {
    let enabled: Bool
    let apiUrl: String
    let apiKey: String?
    let token: String?
    let collectionName: String
    let severityFilter: [String]
    let ecosystem: String?
    let maxResults: Int
    let syncIntervalMinutes: Int
}

struct AskPayload: Encodable {
    let question: String
    let topK: Int
    let userId: String
    let sessionId: String
    let responseLanguage: String
}

struct AgentTaskCreatePayload: Encodable {
    let objective: String
    let workspacePath: String
    let userId: String
}

struct AssistantWorkspaceActionPayload: Encodable {
    let objective: String
    let workspacePath: String
    let userId: String
    let sessionId: String
    let responseLanguage: String
}

struct AssistantTaskActionPayload: Encodable {
    let objective: String
    let userId: String
    let sessionId: String
    let responseLanguage: String
}

struct AssistantWorkspaceActionResult: Decodable, Equatable {
    let kind: String
    let answer: AskResult?
    let task: AgentTaskSnapshot?
}

struct AgentTaskReportDecisionPayload: Encodable {
    let generate: Bool
}

struct AgentTaskReportDownloadDecisionPayload: Encodable {
    let confirm: Bool
    let format: String
}

struct AgentTaskReportDownloadDecisionResult: Decodable, Equatable {
    let task: AgentTaskSnapshot
    let artifact: AssistantArtifact?
}

struct AgentTaskArchivePayload: Encodable {
    let archived: Bool
}

struct AgentTaskDeleteResult: Decodable, Equatable {
    let id: String
    let deleted: Bool
}

struct AgentTaskSnapshot: Decodable, Equatable, Identifiable {
    let id: String
    let objective: String
    let workspacePath: String
    let workspaceName: String
    let workspaceType: String?
    let userId: String
    let status: String
    let currentNode: String
    let languages: [String]
    let plan: [AgentTaskPlanStep]
    let events: [AgentTaskEvent]
    let result: AgentTaskResult?
    var reportReady: Bool? = nil
    let reportDecision: String?
    let report: AnalysisReportSummary?
    var reportInterrupt: ReportInterruptEnvelope? = nil
    var reportDownloadArtifact: AssistantArtifact? = nil
    let error: String
    let archived: Bool?
    let archivedAt: String?
    let createdAt: String
    let updatedAt: String

    var isActive: Bool { ["queued", "running", "cancelling"].contains(status) }
    var canResume: Bool { ["failed", "cancelled", "interrupted"].contains(status) }
    var isArchived: Bool { archived ?? false }
    var canArchiveOrDelete: Bool { ["completed", "failed", "cancelled", "interrupted"].contains(status) }
    var isReportReady: Bool {
        if let reportReady { return reportReady }
        return status == "completed"
            && result != nil
            && !plan.isEmpty
            && plan.allSatisfy { ["completed", "skipped"].contains($0.status) }
            && events.contains { $0.type == "task.completed" && $0.status == "completed" }
    }
    var resolvedReportDecision: String {
        if let reportDecision, !reportDecision.isEmpty { return reportDecision }
        return isReportReady ? "pending" : "unavailable"
    }

    func applying(event: AgentTaskEvent) -> AgentTaskSnapshot {
        guard !events.contains(where: { $0.sequence == event.sequence }) else { return self }

        var updatedEvents = events
        updatedEvents.append(event)
        updatedEvents.sort { $0.sequence < $1.sequence }
        if updatedEvents.count > 500 {
            updatedEvents.removeFirst(updatedEvents.count - 500)
        }

        let planStatus: String? = switch event.type {
        case "node.started": "running"
        case "node.completed", "verification.completed": "completed"
        case "node.failed": "failed"
        default: nil
        }
        let updatedPlan = plan.map { step in
            guard let planStatus, step.node == event.node else { return step }
            return AgentTaskPlanStep(
                id: step.id,
                title: step.title,
                node: step.node,
                status: planStatus,
                language: step.language
            )
        }
        let updatedStatus: String = switch event.type {
        case "task.created", "task.resumed": "queued"
        case "task.started": "running"
        case "task.cancelling": "cancelling"
        case "task.completed": "completed"
        case "task.failed": "failed"
        case "task.cancelled": "cancelled"
        case "task.interrupted": "interrupted"
        default: status
        }

        return AgentTaskSnapshot(
            id: id,
            objective: objective,
            workspacePath: workspacePath,
            workspaceName: workspaceName,
            workspaceType: workspaceType,
            userId: userId,
            status: updatedStatus,
            currentNode: event.node.isEmpty ? currentNode : event.node,
            languages: languages,
            plan: updatedPlan,
            events: updatedEvents,
            result: result,
            reportReady: updatedStatus == "completed" ? false : reportReady,
            reportDecision: reportDecision,
            report: report,
            reportInterrupt: reportInterrupt,
            reportDownloadArtifact: reportDownloadArtifact,
            error: event.type == "task.failed" ? event.message : error,
            archived: archived,
            archivedAt: archivedAt,
            createdAt: createdAt,
            updatedAt: event.time
        )
    }
}

struct AgentTaskPlanStep: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let node: String
    let status: String
    let language: String
}

struct AgentTaskEvent: Decodable, Equatable, Identifiable {
    let sequence: Int
    let type: String
    let node: String
    let status: String
    let message: String
    let time: String
    var data: [String: JSONValue]? = nil

    var id: Int { sequence }
}

struct AgentTaskResult: Decodable, Equatable {
    let summary: String
    let scanMode: String?
    let languages: [String]
    let dependencyCount: Int
    let dependencies: [AgentDependencySummary]?
    let totalFiles: Int
    let totalFindings: Int
    let totalReviewFindings: Int?
    let languageResults: [String: AgentLanguageScanResult]
    let projectProfile: AgentProjectProfile?
    let adaptation: AgentAdaptationSummary?
}

struct AgentProjectProfile: Decodable, Equatable {
    let scope: String?
    let workspaceName: String?
    let scopeFingerprint: String?
    let languages: [String]?
    let manifestFiles: [String]?
    let buildSystems: [String]?
    let frameworks: [String]?
    let dependencyCount: Int?
    let adaptiveEnabled: Bool?
    let evaluationIsolation: Bool?
    let skill: AgentAdaptiveSkill?
}

struct AgentAdaptiveSkill: Decodable, Equatable {
    let name: String?
    let sha256: String?
    let promptVersion: String?
}

struct AgentAdaptationMetrics: Decodable, Equatable {
    let findings: Int?
    let reviewFindings: Int?
    let parsedFiles: Int?
    let parseErrorFiles: Int?
    let cfgEdges: Int?
    let dfgEdges: Int?
}

struct AgentAdaptationSummary: Decodable, Equatable {
    let enabled: Bool?
    let mode: String?
    let status: String?
    let attempts: Int?
    let iterations: Int?
    let overlayFingerprints: [String]?
    let nextAction: String?
    let terminationReason: String?
    let skill: AgentAdaptiveSkill?
    let baselineMetrics: AgentAdaptationMetrics?
    let currentMetrics: AgentAdaptationMetrics?
}

struct AgentDependencySummary: Decodable, Equatable, Identifiable {
    let ecosystem: String
    let name: String
    let version: String
    let sourceFile: String
    let sourceType: String
    let declaration: String
    let confidence: String

    var id: String { "\(ecosystem)|\(name)|\(version)|\(sourceFile)|\(declaration)" }
}

struct AgentLanguageScanResult: Decodable, Equatable {
    let language: String
    let status: String
    let mode: String
    let fileCount: Int
    let files: [String]
    let ruleFiles: [String]
    let syntaxSummary: AgentSyntaxSummary
    let findingCount: Int
    let findings: [AgentFindingSummary]
    let reviewFindingCount: Int?
    let reviewFindings: [AgentFindingSummary]?
    let diagnostics: [String]
}

struct AgentFindingSummary: Decodable, Equatable, Identifiable {
    let id: String
    let ruleId: String?
    let title: String
    let severity: String
    let fileName: String?
    let line: Int?
    let description: String?
}

struct AgentSyntaxSummary: Decodable, Equatable {
    let languages: [String]
    let parsedFiles: Int
    let parseErrorFiles: Int
    let astNodeCount: Int
    let cfgNodeCount: Int
    let cfgEdgeCount: Int
    let dfgEdgeCount: Int
}

struct IntelligenceQueryPayload: Encodable {
    let query: String
    let limit: Int
    let responseLanguage: String?
    let sources: [String]?
}

struct ComponentVulnerabilityPayload: Encodable {
    let name: String
    let version: String
    let ecosystem: String?
    let includeRealtime: Bool
}

struct VulnerabilityComponentExportPayload: Encodable {
    let identifier: String
}

struct ComponentVulnerabilityCoordinate: Decodable, Equatable {
    let name: String
    let version: String
    let ecosystem: String
}

struct ComponentVulnerabilityResult: Decodable, Equatable {
    let status: String
    let query: String
    let component: ComponentVulnerabilityCoordinate
    let records: [IntelligenceRecord]
    let total: Int
    let previewLimit: Int
    let truncated: Bool
    let ecosystems: [String]
    let graph: KnowledgeGraphPayload
    let source: String
    let generatedAt: String
}

struct IntelligenceQueryResult: Decodable, Equatable {
    let status: String
    let query: String
    let records: [IntelligenceRecord]
    let graph: KnowledgeGraphPayload
    let sourceStatus: [IntelligenceSource]
    let trace: [TraceItem]
    let persistence: String
    let persisted: PersistenceSummary
    let generatedAt: String
}

struct PersistenceSummary: Decodable, Equatable {
    let inserted: Int
    let updated: Int
}

struct IntelligenceRecord: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let severity: String
    let cvssScore: Double?
    let summary: String?
    let affectedVersions: [String]?
    let fixedVersions: [String]?
    let aliases: [String]?
    let cwes: [String]?
    let components: [AffectedComponent]?
    let publishedAt: String?
    let updatedAt: String?
}

struct AffectedComponent: Decodable, Equatable, Identifiable {
    let name: String
    let ecosystem: String
    let affected: [String]
    let fixed: [String]

    var id: String { "\(ecosystem):\(name)" }
}

struct KnowledgeGraphPayload: Decodable, Equatable {
    let query: String?
    let nodes: [KnowledgeNode]
    let edges: [KnowledgeEdge]
    let nodeCount: Int
    let edgeCount: Int

    private enum CodingKeys: String, CodingKey {
        case query
        case nodes
        case edges
        case nodeCount
        case edgeCount
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        query = try container.decodeIfPresent(String.self, forKey: .query)
        nodes = try container.decodeIfPresent([KnowledgeNode].self, forKey: .nodes) ?? []
        edges = try container.decodeIfPresent([KnowledgeEdge].self, forKey: .edges) ?? []
        nodeCount = try container.decodeIfPresent(Int.self, forKey: .nodeCount) ?? nodes.count
        edgeCount = try container.decodeIfPresent(Int.self, forKey: .edgeCount) ?? edges.count
    }
}

struct KnowledgeNode: Decodable, Equatable, Identifiable {
    let id: String
    let label: String
    let type: String
    let metadata: [String: JSONValue]
}

struct KnowledgeEdge: Decodable, Equatable, Identifiable {
    let id: String
    let source: String
    let target: String
    let type: String
    let label: String
}

struct DashboardSnapshot: Decodable, Equatable {
    let vulnerabilityCount: Int
    let highRiskCount: Int
    let queryCount: Int
    let graphNodeCount: Int
    let severity: [String: Int]
    let recentRecords: [IntelligenceRecord]
    let sources: [IntelligenceSource]
    let persistence: String
    let generatedAt: String
    let scope: String?
    let rangeStart: String?
    let rangeEnd: String?
    let catalogStatus: String?
    let catalogProgress: Int?
    let catalogCount: Int?
}

struct DashboardRefreshPayload: Encodable {
    let startDate: String?
    let endDate: String?
}

struct DashboardDateRange: Equatable {
    let start: Date
    let end: Date
}

struct IntelligenceSource: Decodable, Equatable, Identifiable {
    let id: String
    let name: String?
    let kind: String?
    let enabled: Bool?
    let status: String
    let count: Int?
    let lastCount: Int?
    let message: String?
}

struct InformationSnapshot: Decodable, Equatable {
    let items: [InformationItem]
    let total: Int
    let availableTotal: Int
    let categories: [InformationCategory]
    let popularTags: [InformationTag]
    let briefs: [InformationItem]
    let sources: [InformationSource]
    let sourceSummary: InformationSourceSummary?
    let updatedAt: String
    let lastRefresh: String
    let stale: Bool
    let partial: Bool
    let message: String
    var refreshing: Bool? = nil
    var refreshStartedAt: String? = nil
    var artworkRefreshing: Bool? = nil

    var isRefreshing: Bool { refreshing ?? false }
    var isUpdating: Bool { isRefreshing || artworkRefreshing == true }
}

struct InformationSourceSummary: Decodable, Equatable {
    let total: Int
    let enabled: Int
    let opmlTotal: Int
    let opmlEnabled: Int
    let opmlEnabledLimit: Int
}

struct InformationItem: Decodable, Equatable, Identifiable {
    let id: String
    let sourceId: String
    let sourceName: String
    let sourceKind: String
    let title: String
    let summary: String
    let url: String
    let imageUrl: String
    let sourceImageUrl: String?
    let publishedAt: String
    let author: String
    let category: String
    let tags: [String]
    let breaking: Bool
}

struct InformationCategory: Decodable, Equatable, Identifiable {
    let id: String
    let label: String
    let count: Int
}

struct InformationTag: Decodable, Equatable, Identifiable {
    let name: String
    let count: Int

    var id: String { name }
}

struct InformationSource: Decodable, Equatable, Identifiable {
    let id: String
    let name: String
    let kind: String
    let website: String
    let region: String
    let group: String?
    let catalog: String?
    let secureTransport: Bool?
    let enabled: Bool
    let status: String
    let itemCount: Int
    let lastUpdated: String
    let lastChecked: String?
    let nextRetryAt: String?
    let failureCount: Int?
    let refreshIntervalSeconds: Int?
    let message: String

    var resolvedGroup: String { group ?? "精选来源" }
    var isBundledOPML: Bool { catalog == "chinese-security-rss" }
}

struct InformationSourceUpdate: Encodable {
    let enabled: Bool
}

struct InformationSourcesUpdate: Encodable {
    let sourceIds: [String]
    let enabled: Bool
}

enum JSONValue: Decodable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else { self = .object(try container.decode([String: JSONValue].self)) }
    }

    var text: String {
        switch self {
        case let .string(value): value
        case let .number(value): String(format: "%g", value)
        case let .bool(value): value ? "true" : "false"
        case let .array(values): values.map(\.text).joined(separator: ", ")
        case let .object(value): value.map { "\($0.key): \($0.value.text)" }.joined(separator: ", ")
        case .null: ""
        }
    }
}

extension JSONDecoder {
    static var secFlow: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }
}

extension JSONEncoder {
    static var secFlow: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return encoder
    }
}
