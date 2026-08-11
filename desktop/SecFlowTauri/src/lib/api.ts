import type {
  AgentTask,
  AgentTaskEvent,
  ApiEnvelope,
  AskResult,
  ConversationDetail,
  ConversationSummary,
  ClientCapabilityCatalog,
  DashboardSnapshot,
  HealthSnapshot,
  InformationSnapshot,
  InformationSource,
  IntelligenceSource,
  LlmConfig,
  ModelUsageSnapshot,
  ReportSummary,
  SettingsSnapshot,
  TraceItem,
  TrialStatus,
  UserProfile,
  VulnerabilityRecord,
  WorkspaceActionResult,
} from "../types";

const defaultBaseUrl = import.meta.env.DEV ? window.location.origin : "http://127.0.0.1:18781";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status = 0,
  ) {
    super(message);
  }
}

export class SecFlowApi {
  readonly baseUrl: string;

  constructor(baseUrl = import.meta.env.VITE_SECFLOW_SERVER_URL || defaultBaseUrl) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private url(path: string, query?: Record<string, string | number | boolean | undefined>) {
    const value = new URL(path.replace(/^\//, ""), `${this.baseUrl}/`);
    Object.entries(query || {}).forEach(([key, item]) => {
      if (item !== undefined) value.searchParams.set(key, String(item));
    });
    return value;
  }

  async raw(path: string, init: RequestInit = {}, query?: Record<string, string | number | boolean | undefined>) {
    const response = await fetch(this.url(path, query), init);
    if (!response.ok) {
      let message = response.statusText;
      try {
        const payload = await response.json();
        message = apiErrorMessage(payload.detail ?? payload.message, message);
      } catch {
        // Keep the HTTP status text when the response is not JSON.
      }
      throw new ApiError(message, response.status);
    }
    return response;
  }

  async request<T>(
    path: string,
    init: RequestInit = {},
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await this.raw(path, { ...init, headers }, query);
    const payload = (await response.json()) as ApiEnvelope<T> | T;
    return "data" in (payload as ApiEnvelope<T>) ? (payload as ApiEnvelope<T>).data : (payload as T);
  }

  health() {
    return this.request<HealthSnapshot>("/health");
  }

  trialStatus() {
    return this.request<TrialStatus>("/api/trial/status");
  }

  async settings(userId: string) {
    return normalizeSettings(await this.request<SettingsSnapshot>("/api/settings", {}, { user_id: userId }));
  }

  saveProfile(userId: string, profile: UserProfile) {
    return this.request<UserProfile>(
      "/api/settings/profile",
      { method: "PATCH", body: JSON.stringify(profile) },
      { user_id: userId },
    );
  }

  uploadProfileAvatar(userId: string, fileName: string, contentBase64: string, contentType: string) {
    return this.request<UserProfile>(
      "/api/settings/profile/avatar",
      { method: "POST", body: JSON.stringify({ file_name: fileName, content_base64: contentBase64, content_type: contentType }) },
      { user_id: userId },
    );
  }

  removeProfileAvatar(userId: string) {
    return this.request<UserProfile>(
      "/api/settings/profile/avatar",
      { method: "DELETE" },
      { user_id: userId },
    );
  }

  profileAvatarUrl(userId: string, version = "") {
    return this.url("/api/settings/profile/avatar", { user_id: userId, v: version || undefined }).toString();
  }

  savePreferences(preferences: SettingsSnapshot["preferences"]) {
    return this.request<SettingsSnapshot["preferences"]>("/api/settings/preferences", {
      method: "PATCH",
      body: JSON.stringify(preferences),
    });
  }

  async llmConfig(userId: string) {
    return normalizeLlmConfig(await this.request<LlmConfig>("/api/llm/config", {}, { user_id: userId }));
  }

  modelUsage(userId: string, days: 7 | 30) {
    return this.request<ModelUsageSnapshot>("/api/usage/model", {}, { user_id: userId, days });
  }

  capabilities() {
    return this.request<ClientCapabilityCatalog>("/api/system/capabilities");
  }

  async saveLlmConfig(userId: string, config: LlmConfig) {
    const result = await this.request<LlmConfig>(
      "/api/llm/config",
      { method: "PATCH", body: JSON.stringify(llmConfigPayload(config)) },
      { user_id: userId },
    );
    return normalizeLlmConfig(result);
  }

  async testLlmConfig(userId: string, config: LlmConfig) {
    const result = await this.request<{
      status?: string;
      message?: string;
      latency_ms?: number;
      provider?: string;
      model?: string;
      configured?: boolean;
    }>(
      "/api/llm/test",
      { method: "POST", body: JSON.stringify(llmConfigPayload(config)) },
      { user_id: userId },
    );
    if (result.status !== "success" || result.configured === false) {
      throw new ApiError(result.message || "模型连接测试失败");
    }
    return result;
  }

  modelCatalog(userId: string, config: Partial<LlmConfig>) {
    return this.request<{ models: Array<{ id: string; name?: string }> }>(
      "/api/llm/models",
      { method: "POST", body: JSON.stringify(llmCatalogPayload(config)) },
      { user_id: userId },
    );
  }

  tasks(userId: string, archived = false) {
    return this.request<AgentTask[]>("/api/agent/tasks", {}, { user_id: userId, archived, limit: 100 });
  }

  task(taskId: string, userId: string) {
    return this.request<AgentTask>(`/api/agent/tasks/${encodeURIComponent(taskId)}`, {}, { user_id: userId });
  }

  workspaceAction(objective: string, workspacePath: string, userId: string, sessionId = "default", responseLanguage?: string) {
    return this.request<WorkspaceActionResult>("/api/assistant/workspace-actions", {
      method: "POST",
      body: JSON.stringify({ objective, workspace_path: workspacePath, user_id: userId, session_id: sessionId, ...(responseLanguage ? { response_language: responseLanguage } : {}) }),
    });
  }

  taskAction(taskId: string, objective: string, userId: string, sessionId = "default", responseLanguage?: string) {
    return this.request<WorkspaceActionResult>(`/api/assistant/tasks/${encodeURIComponent(taskId)}/actions`, {
      method: "POST",
      body: JSON.stringify({ objective, user_id: userId, session_id: sessionId, ...(responseLanguage ? { response_language: responseLanguage } : {}) }),
    });
  }

  taskMutation(taskId: string, action: "cancel" | "resume", userId: string) {
    return this.request<AgentTask>(
      `/api/agent/tasks/${encodeURIComponent(taskId)}/${action}`,
      { method: "POST" },
      { user_id: userId },
    );
  }

  archiveTask(taskId: string, userId: string, archived: boolean) {
    return this.request<AgentTask>(
      `/api/agent/tasks/${encodeURIComponent(taskId)}/archive`,
      { method: "POST", body: JSON.stringify({ archived }) },
      { user_id: userId },
    );
  }

  deleteTask(taskId: string, userId: string) {
    return this.request<{ id: string }>(
      `/api/agent/tasks/${encodeURIComponent(taskId)}`,
      { method: "DELETE" },
      { user_id: userId },
    );
  }

  decideReport(taskId: string, userId: string, generate: boolean, responseLanguage?: string) {
    return this.request<AgentTask>(
      `/api/agent/tasks/${encodeURIComponent(taskId)}/report-decision`,
      { method: "POST", body: JSON.stringify({ generate, ...(responseLanguage ? { response_language: responseLanguage } : {}) }) },
      { user_id: userId },
    );
  }

  decideReportDownload(taskId: string, userId: string, confirm: boolean, format: string) {
    return this.request<{ task: AgentTask; artifact?: Record<string, unknown> }>(
      `/api/agent/tasks/${encodeURIComponent(taskId)}/report-download-decision`,
      { method: "POST", body: JSON.stringify({ confirm, format }) },
      { user_id: userId },
    );
  }

  conversations(userId: string, archived = false) {
    return this.request<ConversationSummary[]>("/api/assistant/conversations", {}, {
      user_id: userId,
      archived,
      limit: 100,
    });
  }

  conversation(sessionId: string, userId: string) {
    return this.request<ConversationDetail>(
      `/api/assistant/conversations/${encodeURIComponent(sessionId)}`,
      {},
      { user_id: userId },
    );
  }

  archiveConversation(sessionId: string, userId: string, archived: boolean) {
    return this.request<ConversationSummary>(
      `/api/assistant/conversations/${encodeURIComponent(sessionId)}/archive`,
      { method: "POST", body: JSON.stringify({ archived }) },
      { user_id: userId },
    );
  }

  deleteConversation(sessionId: string, userId: string) {
    return this.request<{ id: string }>(
      `/api/assistant/conversations/${encodeURIComponent(sessionId)}`,
      { method: "DELETE" },
      { user_id: userId },
    );
  }

  clearShortTermSession(sessionId: string, userId: string) {
    return this.request<{ session_id: string; cleared_turn_count: number }>(
      `/api/assistant/short-term-sessions/${encodeURIComponent(sessionId)}`,
      { method: "DELETE" },
      { user_id: userId },
    );
  }

  async dashboard() {
    return normalizeDashboard(await this.request<Record<string, unknown>>("/api/dashboard"));
  }

  intelligenceSources() {
    return this.request<IntelligenceSource[]>("/api/intelligence/sources");
  }

  async vulnerabilities() {
    const result = await this.request<VulnerabilityRecord[] | { records?: VulnerabilityRecord[] }>("/api/vulnerabilities");
    const records = Array.isArray(result) ? result : result.records || [];
    return records.map(normalizeVulnerability);
  }

  async information(refresh = false) {
    return normalizeInformation(await this.request<InformationSnapshot>("/api/information", {}, { refresh }));
  }

  informationImageUrl(itemId: string) {
    return this.url(`/api/information/images/${encodeURIComponent(itemId)}`).toString();
  }

  informationSourceImageUrl(sourceId: string) {
    return this.url(`/api/information/source-images/${encodeURIComponent(sourceId)}`).toString();
  }

  async refreshInformation() {
    const requested = normalizeInformation(
      await this.request<InformationSnapshot>("/api/information/refresh", { method: "POST" }),
    );
    let latest = normalizeInformation(await this.request<InformationSnapshot>("/api/information"));
    for (let attempt = 0; attempt < 20 && latest.refreshing; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      latest = normalizeInformation(await this.request<InformationSnapshot>("/api/information"));
    }
    return latest.items.length ? latest : requested;
  }

  updateInformationSource(sourceId: string, enabled: boolean) {
    return this.request<InformationSource>(`/api/information/sources/${encodeURIComponent(sourceId)}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    });
  }

  updateInformationSources(sourceIds: string[], enabled: boolean) {
    return this.request<InformationSource[]>("/api/information/sources", {
      method: "PATCH",
      body: JSON.stringify({ source_ids: sourceIds, enabled }),
    });
  }

  testInformationSource(sourceId: string) {
    return this.request<InformationSource>(`/api/information/sources/${encodeURIComponent(sourceId)}/test`, {
      method: "POST",
    });
  }

  reports() {
    return this.request<ReportSummary[]>("/api/reports");
  }

  resumeReportAction(payload: {
    thread_id: string;
    interrupt_id?: string;
    decision: "confirm" | "cancel";
    format?: string;
    user_id: string;
    session_id: string;
    response_language?: string;
  }) {
    return this.request<{ answer?: AskResult } & Record<string, unknown>>("/api/reports/actions/resume", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  resumeAssistantInterrupt(payload: {
    thread_id: string;
    interrupt_id?: string;
    decision: "confirm" | "cancel";
    format?: string;
    user_id: string;
    session_id: string;
    response_language?: string;
  }) {
    return this.request<{ answer?: AskResult } & Record<string, unknown>>("/api/assistant/interrupts/resume", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  artifactUrl(downloadPath: string) {
    return String(this.url(downloadPath));
  }

  async streamQuestion(
    body: Record<string, unknown>,
    callbacks: { onTrace: (trace: TraceItem) => void; onContent: (delta: string) => void },
    signal?: AbortSignal,
  ): Promise<AskResult> {
    const response = await this.raw("/api/assistant/questions/stream", {
      method: "POST",
      headers: { Accept: "text/event-stream", "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
    const result = await parseEventStream<AskResult>(response, (event, data) => {
      if (event === "trace") callbacks.onTrace(JSON.parse(data) as TraceItem);
      if (event === "content") callbacks.onContent((JSON.parse(data) as { delta: string }).delta || "");
    });
    return normalizeAskResult(result);
  }

  async streamTaskEvents(
    taskId: string,
    userId: string,
    after: number,
    onEvent: (event: AgentTaskEvent) => void,
    signal?: AbortSignal,
  ) {
    const response = await this.raw(
      `/api/agent/tasks/${encodeURIComponent(taskId)}/events`,
      { headers: { Accept: "text/event-stream", "Last-Event-ID": String(after) }, signal },
      { user_id: userId, after },
    );
    return parseEventStream<AgentTaskEvent | null>(response, (_event, data) => {
      const value = JSON.parse(data) as AgentTaskEvent;
      onEvent(value);
    }, null);
  }
}

function apiErrorMessage(value: unknown, fallback: string): string {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (Array.isArray(value)) {
    const messages = value.map((item) => apiErrorMessage(item, "")).filter(Boolean);
    return messages.join("；") || fallback;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return apiErrorMessage(record.msg ?? record.message ?? record.detail, fallback);
  }
  return fallback;
}

async function parseEventStream<T = AskResult>(
  response: Response,
  onEvent: (event: string, data: string) => void,
  emptyResult?: T,
): Promise<T> {
  if (!response.body) throw new ApiError("服务未返回事件流。", response.status);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result = emptyResult as T;
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const blocks = buffer.split(/\r?\n\r?\n/);
    buffer = blocks.pop() || "";
    for (const block of blocks) {
      let event = "message";
      const lines: string[] = [];
      block.split(/\r?\n/).forEach((line) => {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        if (line.startsWith("data:")) lines.push(line.slice(5).trimStart());
      });
      if (!lines.length) continue;
      const data = lines.join("\n");
      if (event === "result") result = JSON.parse(data) as T;
      else if (event === "error") {
        const value = JSON.parse(data) as { message?: string };
        throw new ApiError(value.message || "事件流异常结束。");
      } else onEvent(event, data);
    }
    if (done) break;
  }
  return result;
}

export const api = new SecFlowApi();

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" ? (value as Record<string, unknown>) : {};

function normalizeSettings(value: SettingsSnapshot): SettingsSnapshot {
  return {
    ...value,
    profile: value.profile || { display_name: "", email: "", department: "", role: "" },
    preferences: {
      language: value.preferences?.language || "zh-Hans",
      dark_mode: Boolean(value.preferences?.dark_mode),
      font_size: value.preferences?.font_size || "default",
      launch_at_login: Boolean(value.preferences?.launch_at_login),
      auto_check_updates: value.preferences?.auto_check_updates !== false,
    },
  };
}

function normalizeLlmConfig(value: LlmConfig): LlmConfig {
  return {
    ...value,
    endpoint: value.endpoint || "",
    max_tokens: Number(value.max_tokens || 1800),
    timeout_ms: Number(value.timeout_ms || 60000),
    api_key_configured: Boolean(value.api_key_configured || value.has_api_key || value.configured),
  };
}

function llmConfigPayload(config: LlmConfig) {
  return {
    provider: config.provider,
    catalog_provider: config.catalog_provider || undefined,
    model: config.model,
    endpoint: config.endpoint || undefined,
    api_key: config.api_key || undefined,
    enabled: config.enabled !== false,
    max_tokens: config.max_tokens,
    temperature: config.temperature ?? 0.25,
    top_p: config.top_p ?? 0.9,
    timeout_ms: config.timeout_ms,
    wire_api: config.wire_api,
    reasoning_effort: config.reasoning_effort,
    disable_response_storage: config.disable_response_storage,
  };
}

function llmCatalogPayload(config: Partial<LlmConfig>) {
  return {
    provider: config.provider || "openai",
    catalog_provider: config.catalog_provider || undefined,
    endpoint: config.endpoint || undefined,
    api_key: config.api_key || undefined,
    timeout_ms: config.timeout_ms || 30000,
  };
}

function normalizeAskResult(value: AskResult): AskResult {
  const summary = String(value?.answer || value?.summary || "分析已完成。");
  return { ...value, answer: summary, summary };
}

function normalizeDashboard(value: Record<string, unknown>): DashboardSnapshot {
  const severity = asRecord(value.severity);
  const records = (Array.isArray(value.recent_records) ? value.recent_records : []).map(normalizeVulnerability);
  const trendValue = Array.isArray(value.recent_update_trend)
    ? value.recent_update_trend
    : Array.isArray(value.trend) ? value.trend : [];
  const trend = trendValue
    .map((item) => asRecord(item))
    .map((item) => ({ date: String(item.date || "").slice(0, 10), count: Number(item.count || 0) }))
    .filter((item) => item.date)
    .sort((left, right) => left.date.localeCompare(right.date));
  return {
    records,
    stats: {
      total: Number(value.vulnerability_count || records.length),
      critical: Number(severity.CRITICAL || severity.critical || 0),
      high: Number(severity.HIGH || severity.high || 0),
      medium: Number(severity.MEDIUM || severity.medium || 0),
      low: Number(severity.LOW || severity.low || 0),
      kev: Number(value.known_exploited_count ?? value.kev_count ?? 0),
      poc: Number(value.poc_count ?? value.exploited_count ?? 0),
    },
    trend,
    sources: Array.isArray(value.sources) ? value.sources.map((source) => {
      const item = asRecord(source);
      return { name: String(item.name || item.id || "情报来源"), count: Number(item.count || 0) };
    }) : [],
    catalog_status: String(value.catalog_status || "pending"),
    catalog_progress: Number(value.catalog_progress || 0),
    catalog_count: Number(value.catalog_count || value.vulnerability_count || records.length),
    catalog_error: String(value.catalog_error || ""),
  };
}

function normalizeVulnerability(value: VulnerabilityRecord): VulnerabilityRecord {
  const raw = asRecord(value);
  const components = Array.isArray(raw.components) ? raw.components.map(asRecord) : [];
  return {
    ...value,
    id: String(raw.id || "UNKNOWN"),
    title: String(raw.title || raw.id || "未命名漏洞"),
    description: String(raw.description || raw.summary || ""),
    severity: String(raw.severity || "UNKNOWN"),
    cvss: raw.cvss == null && raw.cvss_score == null ? undefined : Number(raw.cvss ?? raw.cvss_score),
    source: String(raw.source || "公开情报"),
    affected_products: Array.isArray(raw.affected_products)
      ? raw.affected_products.map(String)
      : components.map((item) => String(item.name || "")).filter(Boolean),
    references: Array.isArray(raw.references)
      ? raw.references.map(String)
      : Array.isArray(raw.reference_links) ? raw.reference_links.map(String) : [],
  };
}

function normalizeInformation(value: InformationSnapshot): InformationSnapshot {
  return {
    ...value,
    items: Array.isArray(value?.items) ? value.items : [],
    sources: Array.isArray(value?.sources) ? value.sources : [],
  };
}
