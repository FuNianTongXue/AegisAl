import type { LlmConfig, ReasoningEffort, ReasoningOption } from "../types";

export interface ProviderPreset {
  id: string;
  label: string;
  endpoint: string;
  consoleHost?: string;
  badge?: string;
  models: string[];
}

export const providerPresets: ProviderPreset[] = [
  { id: "kimi", label: "Kimi · Moonshot", endpoint: "https://api.moonshot.cn/v1", consoleHost: "platform.moonshot.cn", badge: "推荐", models: ["kimi-k2.6", "kimi-k2.5", "kimi-k2-thinking", "moonshot-v1-128k"] },
  { id: "openai", label: "OpenAI", endpoint: "https://api.openai.com/v1", consoleHost: "platform.openai.com", models: ["gpt-5.6", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.4", "gpt-4.1"] },
  { id: "claude", label: "Anthropic Claude", endpoint: "https://api.anthropic.com", consoleHost: "console.anthropic.com", models: ["claude-sonnet-5", "claude-opus-5", "claude-sonnet-4-5", "claude-haiku-4-5"] },
  { id: "deepseek", label: "DeepSeek", endpoint: "https://api.deepseek.com", consoleHost: "platform.deepseek.com", models: ["deepseek-chat", "deepseek-reasoner"] },
  { id: "ollama", label: "Ollama 本地模型", endpoint: "http://localhost:11434/v1", consoleHost: "ollama.com", badge: "离线", models: ["qwen3:8b", "llama3.1:8b", "deepseek-r1:8b"] },
  { id: "custom", label: "OpenAI 兼容接口", endpoint: "", models: [] },
];

const responseReasoningOptions: ReasoningOption[] = [
  { value: "none" },
  { value: "low" },
  { value: "medium" },
  { value: "high" },
  { value: "xhigh" },
  { value: "max" },
];

export function modelOptionsFor(config?: Partial<LlmConfig>): string[] {
  const preset = providerPresets.find((item) => item.id === config?.provider);
  return Array.from(new Set([config?.model, ...(preset?.models || [])].filter(Boolean) as string[]));
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
