export type JsonObject = Record<string, unknown>;

export interface ApiEnvelope<T> {
  status: "success" | "error";
  message: string;
  data: T;
}

export interface HealthSnapshot {
  ok: boolean;
  service: string;
  contract_version: string;
  task_execution: {
    mode: string;
    configured_workers: number;
    running_workers: number;
  };
}

export interface TrialStatus {
  enabled: boolean;
  usable: boolean;
  state: "disabled" | "active" | "expired" | "tampered" | "clock_rollback" | string;
  durationHours: number;
  startedAt?: string;
  expiresAt?: string;
  lastSeenAt?: string;
  secondsRemaining?: number | null;
  message: string;
}

export interface UserProfile {
  display_name: string;
  email: string;
  department: string;
  role: string;
  phone?: string;
  employee_id?: string;
  bio?: string;
  avatar_available?: boolean;
  avatar_file_name?: string;
  avatar_content_type?: string;
  avatar_updated_at?: string;
  updated_at?: string;
}

export interface PreferenceSettings {
  language: string;
  dark_mode: boolean;
  font_size: "small" | "default" | "large";
  emoji_mode?: "off" | "moderate" | "active";
  launch_at_login?: boolean;
  auto_check_updates?: boolean;
}

export interface SettingsSnapshot {
  profile: UserProfile;
  preferences: PreferenceSettings;
  about?: JsonObject;
}

export interface ClientCapabilityCatalog {
  schema_version: string;
  generated_at: string;
  platform: { system: string; architecture: string; adapter: string };
  summary: { agent_count: number; mcp_server_count: number; mcp_tool_count: number; skill_count: number };
  agents: Array<{ agent_id: string; label: string; description?: string; capabilities?: string[] }>;
  mcp_servers: Array<{
    id: string;
    name: string;
    transport: string;
    tool_count: number;
    tools: Array<{ name: string; description?: string }>;
  }>;
  skills: Array<{ id: string; name: string; description: string; source: string }>;
}

export interface LlmConfig {
  name?: string;
  provider: string;
  catalog_provider?: string;
  endpoint: string;
  model: string;
  max_tokens: number;
  timeout_ms: number;
  enabled?: boolean;
  temperature?: number;
  top_p?: number;
  wire_api?: "chat" | "responses";
  reasoning_effort?: ReasoningEffort;
  reasoning_options?: ReasoningOption[];
  disable_response_storage?: boolean;
  configured?: boolean;
  has_api_key?: boolean;
  api_key_configured?: boolean;
  api_key?: string;
  clear_api_key?: boolean;
}

export type ReasoningEffort = "none" | "low" | "medium" | "high" | "xhigh" | "max";

export interface ReasoningOption {
  value: ReasoningEffort;
  fixed?: boolean;
}

export interface ModelUsageSnapshot {
  range_days: 7 | 30;
  totals: {
    input_tokens: number;
    output_tokens: number;
    total_tokens: number;
    call_count: number;
  };
  conversation_count: number;
  message_count: number;
  active_days: number;
  current_streak: number;
  most_used_model: {
    provider: string;
    model: string;
    tokens: number;
    share: number;
  };
  daily: Array<{
    date: string;
    input_tokens: number;
    output_tokens: number;
    total_tokens: number;
    calls: number;
    messages: number;
  }>;
  heatmap: Array<{ date: string; count: number; level: number }>;
  updated_at: string;
}

export interface AgentPlanStep {
  node: string;
  title?: string;
  status: "pending" | "running" | "completed" | "failed" | "warning";
}

export interface AgentTaskEvent {
  sequence: number;
  type: string;
  node: string;
  status: string;
  message: string;
  data?: JsonObject;
  time: string;
}

export interface AgentTask {
  id: string;
  objective: string;
  workspace_path: string;
  workspace_name: string;
  workspace_type?: string;
  user_id: string;
  session_id?: string;
  status: string;
  current_node: string;
  languages: string[];
  plan: AgentPlanStep[];
  events: AgentTaskEvent[];
  result?: JsonObject;
  report_ready: boolean;
  report_decision?: string;
  report?: ReportSummary;
  error?: string;
  archived?: boolean;
  run_number?: number;
  created_at: string;
  updated_at: string;
}

export interface ConversationSummary {
  id: string;
  session_id?: string;
  title: string;
  preview?: string;
  project_id?: string;
  project_name?: string;
  archived?: boolean;
  updated_at: string;
}

export interface ConversationExchange {
  id: string;
  question: string;
  answer: string;
  created_at?: string;
  result?: AskResult;
  /** Current backend persistence field; `result` is retained for old stores. */
  answer_payload?: AskResult;
}

export interface ConversationDetail extends ConversationSummary {
  exchanges: ConversationExchange[];
}

export interface EvidenceSource {
  id?: string;
  title: string;
  url?: string;
  source?: string;
}

export interface TraceItem {
  id?: string;
  node: string;
  title?: string;
  status: string;
  message?: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  tool_name?: string;
  input?: JsonObject;
  output?: unknown;
  error?: string;
  presentation?: JsonObject;
}

export interface AssistantArtifact {
  id: string;
  file_name: string;
  media_type: string;
  format?: string;
  size?: number;
  kind?: string;
  status?: string;
  generated_at?: string;
  download_path?: string;
  sha256?: string;
}

export interface AssistantInterrupt {
  interrupt_id: string;
  kind: string;
  message: string;
  options?: string[];
  payload?: JsonObject;
  thread_id?: string;
  question?: string;
  detail?: string;
  action?: string;
  formats?: string[];
  report_ids?: string[];
  allow_format_selection?: boolean;
  user_id?: string;
  session_id?: string;
}

export interface AssistantDataTableColumn {
  key: string;
  label: string;
  kind?: "date" | "link" | "number" | "status" | "tags" | "text";
  editable?: boolean;
}

export interface AssistantDataTable {
  id?: string;
  type?: "table" | "data-table" | "records-table" | string;
  title?: string;
  caption?: string;
  columns: Array<AssistantDataTableColumn | string>;
  rows: Array<JsonObject | unknown[]>;
  total?: number;
  edited?: boolean;
}

export interface AskResult {
  answer: string;
  summary?: string;
  session_id?: string;
  model?: string;
  provider?: string;
  trace?: TraceItem[];
  evidence_sources?: EvidenceSource[];
  sources?: EvidenceSource[];
  fields?: JsonObject;
  records?: JsonObject[];
  cards?: JsonObject[];
  table?: AssistantDataTable;
  tables?: AssistantDataTable[];
  /** User-edited display snapshots; original translated evidence remains unchanged. */
  structured_data_edits?: AssistantDataTable[];
  exchange_id?: string;
  artifacts?: AssistantArtifact[];
  interrupt?: AssistantInterrupt;
  report?: ReportSummary;
  knowledge_graph?: JsonObject;
  vulnerability_card?: JsonObject;
  component_detail?: JsonObject;
  usage?: { input_tokens?: number; output_tokens?: number; total_tokens?: number };
  token_usage?: number;
  elapsed_ms?: number;
  [key: string]: unknown;
}

export interface WorkspaceActionResult {
  kind: string;
  task?: AgentTask;
  answer?: AskResult;
  interrupt?: AssistantInterrupt;
  [key: string]: unknown;
}

export interface ReportSummary {
  id: string;
  title: string;
  created_at: string;
  formats?: string[];
  available_formats?: string[];
  file_name?: string;
  file_names?: Record<string, string>;
  metadata?: JsonObject;
}

export interface DashboardSnapshot {
  records: VulnerabilityRecord[];
  stats: {
    total?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    kev?: number;
    poc?: number;
    exploited?: number;
    [key: string]: unknown;
  };
  trend?: Array<{ date: string; count: number }>;
  sources?: Array<{ name: string; count: number }>;
  catalog_status?: "pending" | "building" | "retrying" | "ready" | string;
  catalog_progress?: number;
  catalog_count?: number;
  catalog_error?: string;
  response_language?: VulnerabilityContentLanguage;
  translation_status?: VulnerabilityTranslationStatus;
  translation_progress?: number;
  translation_count?: number;
  translation_ready_count?: number;
  translation_error?: string;
}

export type VulnerabilityContentLanguage = "zh-Hans" | "zh-Hant" | "en" | "mixed" | "unknown";

export type VulnerabilityTranslationStatus =
  | "translated"
  | "translating"
  | "pending"
  | "retrying"
  | "failed"
  | "passthrough"
  | "original"
  | "not_required"
  | "unknown";

export interface VulnerabilityRecord {
  id: string;
  title: string;
  title_original?: string;
  title_zh?: string;
  title_zh_hant?: string;
  description?: string;
  description_original?: string;
  description_zh?: string;
  description_zh_hant?: string;
  summary?: string;
  summary_original?: string;
  summary_zh?: string;
  summary_zh_hant?: string;
  severity?: string;
  cvss?: number;
  cvss_score?: number;
  source?: string;
  published_at?: string;
  updated_at?: string;
  affected_products?: string[];
  affected_versions?: string[];
  fixed_versions?: string[];
  aliases?: string[];
  cwes?: string[];
  references?: string[];
  content_language?: VulnerabilityContentLanguage;
  translation_status?: VulnerabilityTranslationStatus;
  [key: string]: unknown;
}

export interface InformationItem {
  id: string;
  title: string;
  summary?: string;
  source_id?: string;
  source_name?: string;
  published_at?: string;
  url?: string;
  image_url?: string;
  source_image_url?: string;
  source_image_version?: string;
}

export interface InformationSnapshot {
  items: InformationItem[];
  sources?: InformationSource[];
  source_summary?: {
    total: number;
    enabled: number;
    opml_total: number;
    opml_enabled: number;
    opml_enabled_limit: number;
  };
  total?: number;
  available_total?: number;
  refreshing?: boolean;
  refreshed_at?: string;
  response_language?: "zh-Hans" | "zh-Hant" | "en";
}

export interface IntelligenceSource {
  id: "nvd" | "github_advisory" | "osv" | string;
  name: string;
  kind: string;
  enabled: boolean;
  status: string;
  count: number;
  last_count?: number;
  message?: string;
}

export interface InformationSource {
  id: string;
  name: string;
  kind: string;
  website?: string;
  region?: string;
  group?: string;
  catalog?: string;
  source_image_version?: string;
  enabled: boolean;
  status: string;
  item_count: number;
  failure_count?: number;
  last_checked?: string;
  last_success?: string;
  message?: string;
}

export interface ChatTurn {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
  state?: "streaming" | "completed" | "error";
  trace?: TraceItem[];
  result?: AskResult;
  task?: AgentTask;
  /** 随该条消息一并提交的项目附件（发送后即从输入区消耗）。 */
  workspace?: { name: string; path: string };
}
