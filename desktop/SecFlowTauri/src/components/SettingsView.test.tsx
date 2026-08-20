// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { InformationSource, LlmConfig, ModelUsageSnapshot, SettingsSnapshot, UserProfile } from "../types";
import { SettingsView } from "./SettingsView";

const informationSource: InformationSource = {
  id: "freebuf",
  name: "FreeBuf",
  kind: "rss",
  group: "安全媒体",
  catalog: "curated",
  enabled: true,
  status: "success",
  item_count: 12,
  failure_count: 0,
  message: "连接正常",
};

const settings: SettingsSnapshot = {
  profile: {
    display_name: "本机用户",
    email: "analyst@example.com",
    department: "安全运营中心",
    role: "安全分析师",
  },
  preferences: {
    language: "zh-Hans",
    dark_mode: false,
    font_size: "default",
    launch_at_login: false,
    auto_check_updates: true,
  },
};

beforeEach(() => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
  useAppStore.setState({
    userId: "default",
    settings: structuredClone(settings),
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.localStorage.clear();
  useAppStore.setState({ userId: "default", settings: undefined, llm: undefined });
});

describe("SettingsView source separation", () => {
  it("keeps the current form open when unsaved changes are not discarded", () => {
    vi.mocked(window.confirm).mockReturnValue(false);
    render(<SettingsView />);

    fireEvent.click(screen.getByRole("button", { name: "解锁模型配置" }));
    fireEvent.click(screen.getByRole("button", { name: /DeepSeek/ }));
    fireEvent.click(screen.getByRole("button", { name: "用户资料" }));

    expect(window.confirm).toHaveBeenCalledOnce();
    expect(screen.getByRole("heading", { name: "模型设置" })).toBeInTheDocument();
  });

  it("opens with the Zcode-style model workspace and supports returning to the app", () => {
    const onBack = vi.fn();
    const { container } = render(<SettingsView onBack={onBack} />);
    const stableContent = container.querySelector(".settings-content");

    expect(screen.getByRole("heading", { name: "模型设置" })).toBeInTheDocument();
    expect(screen.getByText(/\u6f0f洞翻译由本机离线能力完成/)).toHaveTextContent("不依赖模型配置");
    expect(screen.getByText(/\u6f0f洞翻译由本机离线能力完成/)).toHaveTextContent("不计入 Token 用量");
    expect(screen.getByText(/选择厂商/)).toBeInTheDocument();
    expect(screen.getByText(/接入凭证/)).toBeInTheDocument();
    expect(container.querySelector(".settings-window-drag")).toHaveAttribute("data-tauri-drag-region");

    fireEvent.click(screen.getByRole("button", { name: "解锁模型配置" }));
    fireEvent.click(screen.getByRole("button", { name: /DeepSeek/ }));
    expect(screen.getByRole("button", { name: /DeepSeek/ })).toHaveClass("active");

    fireEvent.click(screen.getByRole("button", { name: "用户资料" }));
    expect(screen.getByRole("heading", { name: "用户资料" })).toBeInTheDocument();
    expect(container.querySelector(".settings-content")).toBe(stableContent);
    expect(container.querySelector(".settings-panel")).toHaveAttribute("data-settings-tab", "general");

    fireEvent.click(screen.getByRole("button", { name: "返回工作区" }));
    expect(onBack).toHaveBeenCalledOnce();
  });

  it("uses the open-lock control to save and relock model settings", async () => {
    const config: LlmConfig = {
      provider: "custom",
      catalog_provider: "sub2api",
      endpoint: "https://carpool.example",
      model: "gpt-5.6-sol",
      max_tokens: 1800,
      timeout_ms: 60000,
      enabled: false,
      api_key_configured: true,
    };
    useAppStore.setState({ userId: "default", llm: config });
    const saveSpy = vi.spyOn(api, "saveLlmConfig").mockImplementation(async (_userId, value) => ({
      ...value,
      enabled: true,
      configured: true,
      api_key_configured: true,
    }));
    vi.spyOn(api, "testLlmConfig").mockResolvedValue({ status: "success", configured: true, latency_ms: 120 });

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "接入凭证" }));
    const endpoint = screen.getByRole("textbox", { name: "Base URL" });

    expect(endpoint).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "解锁模型配置" }));
    expect(endpoint).not.toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "高级选项" }));
    const enabled = screen.getByRole("checkbox", { name: "启用模型" });
    expect(enabled).not.toBeDisabled();
    expect(enabled).not.toBeChecked();
    expect(enabled.closest(".model-switch")?.querySelectorAll(".model-switch-track")).toHaveLength(1);
    expect(enabled.closest(".model-switch")?.querySelectorAll(".model-switch-thumb")).toHaveLength(1);
    fireEvent.click(enabled);
    expect(enabled).toBeChecked();
    expect(screen.queryByRole("button", { name: "保存并启用" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "保存并锁定模型配置" }));

    await waitFor(() => expect(saveSpy).toHaveBeenCalledWith("default", expect.objectContaining({ enabled: true })));
    expect(await screen.findByText("模型配置已验证、保存并启用")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "接入凭证" }));
    expect(screen.getByRole("textbox", { name: "Base URL" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "解锁模型配置" })).toBeInTheDocument();
  });

  it("keeps model actions horizontally grouped and places connection testing with credentials", () => {
    useAppStore.setState({
      llm: {
        provider: "deepseek",
        endpoint: "https://api.deepseek.com",
        model: "deepseek-chat",
        max_tokens: 8192,
        timeout_ms: 120000,
        enabled: true,
      },
    });

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "解锁模型配置" }));
    fireEvent.click(screen.getByRole("button", { name: "选择模型" }));

    const readModels = screen.getByRole("button", { name: "从厂商读取" });
    const addModel = screen.getByRole("button", { name: "添加模型" });
    expect(readModels.parentElement).toBe(addModel.parentElement);
    expect(readModels.parentElement).toHaveClass("model-select-actions");
    fireEvent.click(screen.getByRole("button", { name: "接入凭证" }));
    expect(screen.getByRole("button", { name: "测试连接" }).closest(".model-panel-section")).toHaveTextContent("验证接入凭证");
  });

  it("uses a horizontal transition wizard for the guide page", () => {
    const { container } = render(<SettingsView />);

    fireEvent.click(screen.getByRole("button", { name: "引导" }));
    expect(screen.getByRole("list", { name: "安全智脑使用引导" })).toHaveClass("wizard-progress");
    expect(screen.getByRole("heading", { name: "连接你的模型" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("heading", { name: "确认安全服务就绪" })).toBeInTheDocument();
    expect(container.querySelector(".guide-transition-panel")).toBeInTheDocument();
  });

  it("shows built-in Agent, MCP and Skill capabilities from the runtime catalog", async () => {
    vi.spyOn(api, "capabilities").mockResolvedValue({
      schema_version: "secflow.client-capabilities/v1",
      generated_at: "2026-08-09T08:00:00+08:00",
      platform: { system: "Darwin", architecture: "arm64", adapter: "macos" },
      summary: { agent_count: 2, mcp_server_count: 2, mcp_tool_count: 2, skill_count: 1 },
      agents: [
        { agent_id: "report_planner", label: "Report Planner Agent", capabilities: ["report-plan"] },
        { agent_id: "qa", label: "QA Agent", capabilities: ["report-validation"] },
      ],
      mcp_servers: [
        { id: "report-template", name: "SecFlow Template MCP", transport: "in-process", tool_count: 1, tools: [{ name: "resolve_report_template" }] },
        { id: "report-excel", name: "SecFlow Excel MCP", transport: "in-process", tool_count: 1, tools: [{ name: "render_excel_report" }] },
      ],
      skills: [{ id: "secflow-report-generation", name: "报告生成", description: "统一报告工作流", source: "built-in" }],
    });

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "Agent" }));

    expect(await screen.findByRole("heading", { name: "Agent" })).toBeInTheDocument();
    expect(await screen.findByText("Report Planner Agent")).toBeInTheDocument();
    expect(screen.queryByText("SecFlow Template MCP")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "MCP" }));
    expect(await screen.findByText("SecFlow Template MCP")).toBeInTheDocument();
    expect(screen.getByText("SecFlow Excel MCP")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Skills" }));
    expect(await screen.findByText("报告生成")).toBeInTheDocument();
    expect(screen.getByText(/Platform Adapter：macOS · arm64/i)).toBeInTheDocument();
  });

  it("saves the personal profile and updates the shared account state", async () => {
    const saved: UserProfile = {
      ...settings.profile,
      display_name: "沈安全",
      email: "shen@example.com",
      bio: "负责多云安全运营",
      updated_at: "2026-08-02T09:30:00+08:00",
    };
    const saveSpy = vi.spyOn(api, "saveProfile").mockResolvedValue(saved);

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "用户资料" }));
    fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "沈安全" } });
    fireEvent.change(screen.getByLabelText("邮箱"), { target: { value: "shen@example.com" } });
    fireEvent.change(screen.getByLabelText("个人简介"), { target: { value: "负责多云安全运营" } });
    fireEvent.click(screen.getByRole("button", { name: "保存资料并锁定" }));

    await waitFor(() => expect(saveSpy).toHaveBeenCalledWith("default", expect.objectContaining({
      display_name: "沈安全",
      email: "shen@example.com",
      bio: "负责多云安全运营",
    })));
    expect(await screen.findByText("已保存")).toBeInTheDocument();
    expect(useAppStore.getState().settings?.profile).toEqual(saved);
    expect(screen.getByLabelText("显示名称")).toBeDisabled();
    expect(screen.getByRole("button", { name: "解锁个人信息" })).toBeInTheDocument();
  });

  it("requires explicit unlock before editing an already saved profile", () => {
    useAppStore.setState({
      settings: {
        ...settings,
        profile: { ...settings.profile, updated_at: "2026-08-06T08:00:00Z" },
      },
    });

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "用户资料" }));
    expect(screen.getByLabelText("显示名称")).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "解锁个人信息" }));
    expect(screen.getByLabelText("显示名称")).not.toBeDisabled();
  });

  it("switches the client language immediately and persists the preference", async () => {
    const preferenceSpy = vi.spyOn(api, "savePreferences").mockImplementation(async (preferences) => preferences);

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "用户资料" }));
    fireEvent.change(screen.getByRole("combobox", { name: "客户端语言" }), { target: { value: "en" } });

    expect(screen.getByRole("button", { name: "Back to workspace" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "User profile" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Client language" })).toHaveValue("en");
    await waitFor(() => expect(preferenceSpy).toHaveBeenCalledWith(expect.objectContaining({ language: "en" })));
    expect(useAppStore.getState().settings?.preferences.language).toBe("en");
  });

  it("uploads and removes an avatar while synchronizing the shared profile", async () => {
    const uploaded: UserProfile = {
      ...settings.profile,
      avatar_available: true,
      avatar_file_name: "avatar.png",
      avatar_content_type: "image/png",
      avatar_updated_at: "2026-08-02T09:35:00+08:00",
    };
    const uploadSpy = vi.spyOn(api, "uploadProfileAvatar").mockResolvedValue(uploaded);
    const removeSpy = vi.spyOn(api, "removeProfileAvatar").mockResolvedValue({
      ...settings.profile,
      avatar_available: false,
      avatar_updated_at: "",
    });
    const { container } = render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "用户资料" }));
    const input = container.querySelector<HTMLInputElement>(".profile-avatar-input");
    expect(input).not.toBeNull();

    const avatar = new File([new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])], "avatar.png", { type: "image/png" });
    fireEvent.change(input!, { target: { files: [avatar] } });

    await waitFor(() => expect(uploadSpy).toHaveBeenCalledWith(
      "default",
      "avatar.png",
      expect.any(String),
      "image/png",
    ));
    expect(useAppStore.getState().settings?.profile.avatar_available).toBe(true);

    fireEvent.click(await screen.findByRole("button", { name: "移除头像" }));
    await waitFor(() => expect(removeSpy).toHaveBeenCalledWith("default"));
    expect(useAppStore.getState().settings?.profile.avatar_available).toBe(false);
  });

  it("does not report a successful connection when the model business status failed", async () => {
    useAppStore.setState({
      llm: {
        provider: "custom",
        endpoint: "https://carpool.example",
        model: "gpt-5.6-sol",
        max_tokens: 1800,
        timeout_ms: 60000,
        enabled: true,
      },
    });
    vi.spyOn(api, "testLlmConfig").mockResolvedValue({
      status: "failed",
      configured: false,
      message: "模型鉴权失败",
    });

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "解锁模型配置" }));
    fireEvent.click(screen.getByRole("button", { name: "接入凭证" }));
    fireEvent.click(screen.getByRole("button", { name: "测试连接" }));

    expect(await screen.findByText("模型鉴权失败")).toBeInTheDocument();
    expect(screen.queryByText(/模型连接正常/)).not.toBeInTheDocument();
  });

  it("shows only the locally stored index count and keeps consultation subscriptions separate", async () => {
    const dashboardSpy = vi.spyOn(api, "dashboard").mockResolvedValue({
      records: [],
      stats: { total: 796_933 },
      catalog_count: 796_933,
    });
    const informationSpy = vi.spyOn(api, "information").mockResolvedValue({
      items: [],
      sources: [informationSource],
      source_summary: { total: 513, enabled: 10, opml_total: 503, opml_enabled: 0, opml_enabled_limit: 50 },
    });
    const toggleSpy = vi.spyOn(api, "updateInformationSource").mockResolvedValue({ ...informationSource, enabled: false, status: "idle" });

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "索引库" }));
    expect(await screen.findByText("796,933")).toBeInTheDocument();
    expect(screen.getByText("条已存储数据")).toBeInTheDocument();
    expect(screen.queryByText("NVD 漏洞数据库")).not.toBeInTheDocument();
    expect(screen.queryByText("GitHub 安全公告")).not.toBeInTheDocument();
    expect(screen.queryByText("OSV 开源漏洞库")).not.toBeInTheDocument();
    expect(screen.queryByText("FreeBuf")).not.toBeInTheDocument();
    expect(dashboardSpy).toHaveBeenCalledOnce();
    expect(informationSpy).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /咨询订阅/ }));
    expect(await screen.findByText("FreeBuf")).toBeInTheDocument();
    expect(screen.getByText("513")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "FreeBuf订阅" }));
    await waitFor(() => expect(toggleSpy).toHaveBeenCalledWith("freebuf", false));
  });

  it("loads actual model token usage and switches between 7 and 30 days", async () => {
    const snapshot: ModelUsageSnapshot = {
      range_days: 30,
      totals: { input_tokens: 1200, output_tokens: 345, total_tokens: 1545, call_count: 3 },
      conversation_count: 2,
      message_count: 4,
      active_days: 2,
      current_streak: 1,
      most_used_model: { provider: "openai", model: "gpt-secflow", tokens: 1545, share: 100 },
      daily: [{ date: "2026-08-02", input_tokens: 1200, output_tokens: 345, total_tokens: 1545, calls: 3, messages: 4 }],
      heatmap: [{ date: "2026-08-02", count: 7, level: 4 }],
      updated_at: "2026-08-02T10:00:00+08:00",
    };
    const usageSpy = vi.spyOn(api, "modelUsage").mockImplementation(async (_userId, days) => ({ ...snapshot, range_days: days }));

    render(<SettingsView />);
    fireEvent.click(screen.getByRole("button", { name: "使用统计" }));

    expect((await screen.findAllByText("1,545")).length).toBeGreaterThan(0);
    expect(screen.getByText("gpt-secflow")).toBeInTheDocument();
    expect(usageSpy).toHaveBeenCalledWith("default", 30);

    fireEvent.click(screen.getByRole("button", { name: "最近 7 天" }));
    await waitFor(() => expect(usageSpy).toHaveBeenCalledWith("default", 7));
    expect(screen.getByRole("button", { name: "最近 7 天" })).toHaveAttribute("aria-pressed", "true");
  });
});
