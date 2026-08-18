import type { LlmConfig, ReasoningEffort, ReasoningOption } from "../types";

export interface ProviderPreset {
  id: string;
  label: string;
  endpoint: string;
  backendProvider: "openai" | "claude" | "deepseek" | "custom";
  catalogProvider: string;
  consoleHost?: string;
  badge?: string;
  models: string[];
  wireApi?: "chat" | "responses";
}

export const providerPresets: ProviderPreset[] = [
  { id: "kimi", label: "Kimi · Moonshot", endpoint: "https://api.moonshot.cn/v1", backendProvider: "custom", catalogProvider: "moonshot", consoleHost: "platform.moonshot.cn", badge: "推荐", models: ["kimi-k3", "kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k2.6", "kimi-k2.5"], wireApi: "chat" },
  { id: "openai", label: "OpenAI", endpoint: "https://api.openai.com/v1", backendProvider: "openai", catalogProvider: "openai", consoleHost: "platform.openai.com", models: ["gpt-5.6", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.4", "gpt-4.1"], wireApi: "responses" },
  { id: "claude", label: "Anthropic Claude", endpoint: "https://api.anthropic.com", backendProvider: "claude", catalogProvider: "claude", consoleHost: "console.anthropic.com", models: ["claude-sonnet-5", "claude-opus-4-8", "claude-fable-5", "claude-haiku-4-5"], wireApi: "chat" },
  { id: "deepseek", label: "DeepSeek", endpoint: "https://api.deepseek.com", backendProvider: "deepseek", catalogProvider: "deepseek", consoleHost: "platform.deepseek.com", models: ["deepseek-chat", "deepseek-reasoner"], wireApi: "chat" },
  { id: "ollama", label: "Ollama 本地模型", endpoint: "http://localhost:11434/v1", backendProvider: "custom", catalogProvider: "ollama", consoleHost: "ollama.com", badge: "离线", models: ["qwen3:8b", "llama3.1:8b", "deepseek-r1:8b"], wireApi: "chat" },
  { id: "custom", label: "OpenAI 兼容接口", endpoint: "", backendProvider: "custom", catalogProvider: "custom", models: [], wireApi: "chat" },
];

const responseReasoningOptions: ReasoningOption[] = [
  { value: "none" },
  { value: "low" },
  { value: "medium" },
  { value: "high" },
  { value: "xhigh" },
  { value: "max" },
];

export function selectedProviderId(config?: Partial<LlmConfig>): string {
  const provider = String(config?.provider || "").trim().toLowerCase();
  const catalogProvider = String(config?.catalog_provider || "").trim().toLowerCase();

  // Older setup builds persisted the UI id directly. Keep those records visible
  // while all new writes use the backend-safe provider/catalog pair below.
  if (providerPresets.some((item) => item.id === provider) && provider !== "custom") return provider;

  const canonicalCatalog = catalogProvider === "kimi" ? "moonshot" : catalogProvider;
  const catalogPreset = providerPresets.find((item) => item.catalogProvider === canonicalCatalog);
  if (provider === "custom" && catalogPreset) return catalogPreset.id;
  return providerPresets.some((item) => item.id === provider) ? provider : "custom";
}

export function configForProvider<T extends Partial<LlmConfig>>(current: T, providerId: string): T {
  const preset = providerPresets.find((item) => item.id === providerId);
  if (!preset) return current;
  const providerChanged = selectedProviderId(current) !== preset.id;
  return {
    ...current,
    provider: preset.backendProvider,
    catalog_provider: preset.catalogProvider,
    endpoint: preset.endpoint || current.endpoint || "",
    model: preset.models[0] || current.model || "",
    wire_api: preset.wireApi || "chat",
    reasoning_options: undefined,
    ...(providerChanged ? {
      api_key: "",
      api_key_configured: false,
      has_api_key: false,
      configured: false,
    } : {}),
  };
}

type RemoteModel = string | { id: string };

export function modelOptionsFor(
  config?: Partial<LlmConfig>,
  remoteModels: ReadonlyArray<RemoteModel> = [],
): string[] {
  const selectedId = selectedProviderId(config);
  const preset = providerPresets.find((item) => item.id === selectedId);
  const remoteIds = remoteModels.map((item) => typeof item === "string" ? item : item.id);
  return Array.from(new Set(
    [config?.model, ...(preset?.models || []), ...remoteIds]
      .map((item) => String(item || "").trim())
      .filter(Boolean),
  ));
}

export function reasoningOptionsFor(config?: Partial<LlmConfig>): ReasoningOption[] {
  if (config?.reasoning_options?.length) return config.reasoning_options;
  const provider = String(config?.provider || "").toLowerCase();
  const model = String(config?.model || "").toLowerCase();
  if (provider === "openai" || config?.wire_api === "responses") return responseReasoningOptions;
  if (provider === "deepseek" && model.includes("reasoner")) return [{ value: "high", fixed: true }];
  return [{ value: "none", fixed: true }];
}

export function normalizedReasoningEffort(
  config: Partial<LlmConfig>,
  requested?: ReasoningEffort,
): ReasoningEffort {
  const options = reasoningOptionsFor(config);
  if (requested && options.some((option) => option.value === requested)) return requested;
  if (options.some((option) => option.value === "medium")) return "medium";
  return options[0]?.value || "none";
}

export function reasoningLabel(value?: ReasoningEffort): string {
  return ({
    none: "标准",
    low: "低推理",
    medium: "中推理",
    high: "高推理",
    xhigh: "极高推理",
    max: "最大推理",
  } as Record<ReasoningEffort, string>)[value || "none"];
}

export function reasoningDescription(value: ReasoningEffort): string {
  return ({
    none: "最快响应，不使用额外推理",
    low: "适合简单问题的轻量推理",
    medium: "平衡响应速度与分析深度",
    high: "适合复杂任务的深入分析",
    xhigh: "适合困难任务的扩展推理",
    max: "使用模型可用的最大推理预算",
  } as Record<ReasoningEffort, string>)[value];
}
