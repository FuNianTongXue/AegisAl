import { describe, expect, it } from "vitest";

import { configForProvider, modelOptionsFor, normalizedReasoningEffort, reasoningOptionsFor, selectedProviderId } from "./modelControls";

describe("model provider controls", () => {
  it("maps the Kimi UI choice to a backend-safe Moonshot catalog", () => {
    const config = configForProvider({ provider: "deepseek", endpoint: "", model: "" }, "kimi");

    expect(config).toMatchObject({
      provider: "custom",
      catalog_provider: "moonshot",
      endpoint: "https://api.moonshot.cn/v1",
      model: "kimi-k3",
      wire_api: "chat",
    });
    expect(selectedProviderId(config)).toBe("kimi");
  });

  it("keeps the Ollama catalog identity when using the custom backend adapter", () => {
    const config = configForProvider({ provider: "openai", endpoint: "", model: "" }, "ollama");

    expect(config).toMatchObject({
      provider: "custom",
      catalog_provider: "ollama",
      endpoint: "http://localhost:11434/v1",
      model: "qwen3:8b",
    });
    expect(selectedProviderId(config)).toBe("ollama");
  });

  it("merges current, preset, and remote models without empty values or duplicates", () => {
    expect(modelOptionsFor(
      { provider: "custom", catalog_provider: "moonshot", model: "enterprise-kimi" },
      [{ id: "kimi-k3" }, { id: "remote-kimi" }, " remote-kimi "],
    )).toEqual([
      "enterprise-kimi",
      "kimi-k3",
      "kimi-k2.7-code",
      "kimi-k2.7-code-highspeed",
      "kimi-k2.6",
      "kimi-k2.5",
      "remote-kimi",
    ]);
  });

  it("preserves custom endpoint and model values", () => {
    const config = configForProvider(
      { provider: "deepseek", endpoint: "https://gateway.example/v1", model: "enterprise-reasoner" },
      "custom",
    );

    expect(config).toMatchObject({
      provider: "custom",
      catalog_provider: "custom",
      endpoint: "https://gateway.example/v1",
      model: "enterprise-reasoner",
    });
  });

  it("normalizes historical blank or unsupported reasoning values for the selected model", () => {
    const openai = {
      provider: "openai",
      endpoint: "https://api.openai.com/v1",
      model: "gpt-5.6-sol",
      wire_api: "responses" as const,
    };
    const deepseek = {
      provider: "deepseek",
      endpoint: "https://api.deepseek.com/v1",
      model: "deepseek-chat",
      wire_api: "chat" as const,
    };

    expect(normalizedReasoningEffort(openai, "")).toBe("medium");
    expect(normalizedReasoningEffort(deepseek, "max")).toBe("none");
    expect(reasoningOptionsFor({
      ...openai,
      reasoning_options: [{ value: "invalid" as never }, { value: "high" }],
    })).toEqual([{ value: "high" }]);
  });
});
