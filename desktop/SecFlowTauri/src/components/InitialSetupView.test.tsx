// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import { InitialSetupView } from "./InitialSetupView";

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

  it("allows a custom OpenAI-compatible model ID during initial setup", async () => {
    vi.spyOn(api, "saveProfile").mockImplementation(async (_userId, profile) => ({
      ...profile,
      updated_at: "2026-08-09T09:00:00Z",
    }));

    render(<InitialSetupView />);
    fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "新用户" } });
    fireEvent.change(screen.getByLabelText("邮箱"), { target: { value: "new@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "保存并继续" }));

    expect(await screen.findByRole("heading", { name: "接入模型" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "OpenAI 兼容接口" }));
    const model = screen.getByRole("textbox", { name: "模型" });
    fireEvent.change(model, { target: { value: "enterprise-reasoner-v1" } });

    expect(model).toHaveValue("enterprise-reasoner-v1");
    expect(screen.queryByRole("combobox", { name: "模型" })).not.toBeInTheDocument();
  });
});
