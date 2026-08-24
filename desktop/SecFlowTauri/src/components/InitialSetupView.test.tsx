// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import { InitialSetupView } from "./InitialSetupView";

async function continueToModelSetup() {
  fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "新用户" } });
  fireEvent.change(screen.getByLabelText("邮箱"), { target: { value: "new@example.com" } });
  fireEvent.click(screen.getByRole("button", { name: "保存并继续" }));
  expect(await screen.findByRole("heading", { name: "接入模型" })).toBeInTheDocument();
}

describe("InitialSetupView", () => {
  beforeEach(() => {
    useAppStore.setState({
      userId: "new-user",
      initialSetupRequired: true,
      settings: {
        profile: { display_name: "", email: "", department: "", role: "" },
        preferences: { language: "zh-Hans", dark_mode: false, font_size: "default" },
      },
      llm: {
        provider: "deepseek",
        endpoint: "https://api.deepseek.com",
        model: "deepseek-chat",
        max_tokens: 1800,
        timeout_ms: 60000,
        enabled: false,
        configured: false,
      },
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("saves personal information, validates the model, and then unlocks the workspace", async () => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-06T12:00:00Z",
    }));
    vi.spyOn(api, "testLlmConfig").mockResolvedValue({
      status: "success",
      configured: true,
      latency_ms: 88,
    });
    vi.spyOn(api, "saveLlmConfig").mockImplementation(async (_userId, config) => ({
      ...config,
      configured: true,
      api_key_configured: true,
    }));

    const { container } = render(<InitialSetupView />);
    expect(container.querySelector(".initial-setup-card")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "配置步骤" })).toHaveClass("wizard-progress");
    fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "新用户" } });
    fireEvent.change(screen.getByLabelText("邮箱"), { target: { value: "new@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "保存并继续" }));

    expect(await screen.findByRole("heading", { name: "接入模型" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("API Key"), { target: { value: "test-key" } });
    fireEvent.click(screen.getByRole("button", { name: "测试连接" }));
    expect(await screen.findByText("连接成功 · 88ms")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "保存并进入工作区" }));

    await waitFor(() => expect(api.saveLlmConfig).toHaveBeenCalled());
    expect(useAppStore.getState().initialSetupRequired).toBe(false);
    expect(useAppStore.getState().settings?.profile.display_name).toBe("新用户");
  });

  it("saves the model after an optional connection test fails", async () => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-06T12:00:00Z",
    }));
    const testSpy = vi.spyOn(api, "testLlmConfig").mockRejectedValue(new Error("第三方网关暂时不可用"));
    const saveSpy = vi.spyOn(api, "saveLlmConfig").mockImplementation(async (_userId, config) => ({
      ...config,
      configured: true,
      api_key_configured: true,
    }));

    render(<InitialSetupView />);
    await continueToModelSetup();
    fireEvent.change(screen.getByLabelText("API Key"), { target: { value: "third-party-key" } });
    const save = screen.getByRole("button", { name: "保存并进入工作区" });
    expect(save).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "测试连接" }));
    expect(await screen.findByText("第三方网关暂时不可用")).toBeInTheDocument();
    expect(save).toBeEnabled();
    fireEvent.click(save);

    await waitFor(() => expect(saveSpy).toHaveBeenCalledWith("new-user", expect.objectContaining({
      api_key: "third-party-key",
      enabled: true,
    })));
    expect(testSpy).toHaveBeenCalledOnce();
    expect(useAppStore.getState().initialSetupRequired).toBe(false);
  });

  it("uses the same complete provider catalog as model settings", async () => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-09T09:00:00Z",
    }));

    render(<InitialSetupView />);
    await continueToModelSetup();

    const providerNames = [
      "Kimi · Moonshot",
      "OpenAI",
      "Anthropic Claude",
      "DeepSeek",
      "Ollama 本地模型",
      "OpenAI 兼容接口",
    ];
    const providerPicker = screen.getByRole("group", { name: "选择模型厂商" });
    for (const name of providerNames) {
      expect(within(providerPicker).getByRole("button", { name })).toBeInTheDocument();
    }
    expect(within(providerPicker).getAllByRole("button")).toHaveLength(6);
  });

  it("adds a custom OpenAI-compatible model through the shared model selector", async () => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-09T09:00:00Z",
    }));

    render(<InitialSetupView />);
    await continueToModelSetup();

    fireEvent.click(screen.getByRole("button", { name: /OpenAI 兼容接口/ }));
    const model = screen.getByRole("combobox", { name: "选择模型" });
    fireEvent.click(screen.getByRole("button", { name: "添加模型" }));
    fireEvent.change(screen.getByLabelText("模型 ID"), { target: { value: "enterprise-reasoner-v1" } });
    fireEvent.click(screen.getByRole("button", { name: "确认添加模型" }));

    expect(model).toHaveValue("enterprise-reasoner-v1");
    expect(screen.getByRole("option", { name: "enterprise-reasoner-v1" })).toBeInTheDocument();
  });

  it.each([
    {
      label: "Kimi · Moonshot",
      catalogProvider: "moonshot",
      endpoint: "https://api.moonshot.cn/v1",
      model: "kimi-k3",
    },
    {
      label: "Ollama 本地模型",
      catalogProvider: "ollama",
      endpoint: "http://localhost:11434/v1",
      model: "qwen3:8b",
    },
  ])("normalizes $label to a canonical compatible-provider payload", async ({
    label,
    catalogProvider,
    endpoint,
    model,
  }) => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-09T09:00:00Z",
    }));
    const testSpy = vi.spyOn(api, "testLlmConfig").mockResolvedValue({
      status: "success",
      configured: true,
      latency_ms: 48,
    });
    const saveSpy = vi.spyOn(api, "saveLlmConfig").mockImplementation(async (_userId, config) => ({
      ...config,
      configured: true,
      api_key_configured: true,
    }));

    render(<InitialSetupView />);
    await continueToModelSetup();
    fireEvent.click(screen.getByRole("button", { name: label }));
    fireEvent.change(screen.getByLabelText("API Key"), { target: { value: "test-key" } });

    expect(screen.getByRole("combobox", { name: "选择模型" })).toHaveValue(model);
    expect(screen.getByLabelText("Base URL")).toHaveValue(endpoint);

    fireEvent.click(screen.getByRole("button", { name: "测试连接" }));
    await waitFor(() => expect(testSpy).toHaveBeenCalledWith("new-user", expect.objectContaining({
      provider: "custom",
      catalog_provider: catalogProvider,
      endpoint,
      model,
      wire_api: "chat",
    })));
    fireEvent.click(screen.getByRole("button", { name: "保存并进入工作区" }));

    await waitFor(() => expect(saveSpy).toHaveBeenCalledWith("new-user", expect.objectContaining({
      provider: "custom",
      catalog_provider: catalogProvider,
      endpoint,
      model,
      wire_api: "chat",
      enabled: true,
    })));
  });

  it("loads remote models into the same selector and selects a returned model", async () => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-09T09:00:00Z",
    }));
    const catalogSpy = vi.spyOn(api, "modelCatalog").mockResolvedValue({
      models: [
        { id: "deepseek-enterprise-v3", name: "DeepSeek Enterprise V3" },
        { id: "deepseek-reasoner" },
      ],
    });

    render(<InitialSetupView />);
    await continueToModelSetup();
    fireEvent.click(screen.getByRole("button", { name: "DeepSeek" }));
    fireEvent.click(screen.getByRole("button", { name: "从厂商读取" }));

    await waitFor(() => expect(catalogSpy).toHaveBeenCalledWith("new-user", expect.objectContaining({
      provider: "deepseek",
      catalog_provider: "deepseek",
      endpoint: "https://api.deepseek.com",
      model: "deepseek-chat",
    })));
    const model = screen.getByRole("combobox", { name: "选择模型" });
    expect(await screen.findByRole("option", { name: "DeepSeek Enterprise V3" })).toHaveValue("deepseek-enterprise-v3");
    fireEvent.change(model, { target: { value: "deepseek-enterprise-v3" } });
    expect(model).toHaveValue("deepseek-enterprise-v3");
  });

  it("clears the verified status after a model change without blocking local save", async () => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-09T09:00:00Z",
    }));
    vi.spyOn(api, "testLlmConfig").mockResolvedValue({
      status: "success",
      configured: true,
      latency_ms: 64,
    });

    render(<InitialSetupView />);
    await continueToModelSetup();
    fireEvent.change(screen.getByLabelText("API Key"), { target: { value: "test-key" } });
    const save = screen.getByRole("button", { name: "保存并进入工作区" });
    expect(save).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "测试连接" }));
    await waitFor(() => expect(save).toBeEnabled());

    fireEvent.change(screen.getByRole("combobox", { name: "选择模型" }), {
      target: { value: "deepseek-reasoner" },
    });
    expect(save).toBeEnabled();
    expect(screen.queryByText(/\u8fde\u63a5\u6210\u529f/)).not.toBeInTheDocument();
  });
});
