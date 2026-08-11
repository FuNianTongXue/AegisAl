// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";
import { api } from "./lib/api";
import { useAppStore } from "./store/appStore";

vi.mock("./hooks/useBackend", () => ({
  useBackendBootstrap: () => vi.fn(),
  useActiveTaskStream: vi.fn(),
}));

describe("App navigation theme", () => {
  beforeEach(() => {
    useAppStore.setState({
      view: "assistant",
      sidebarOpen: true,
      inspectorOpen: false,
      commandOpen: false,
      bootstrapReady: true,
      initialSetupRequired: false,
      conversations: [],
      archivedConversations: [],
      tasks: [],
      archivedTasks: [],
      turns: [],
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
        enabled: true,
        configured: true,
      },
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("keeps the Zcode shell palette while switching primary navigation views", () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({ records: [], stats: {}, catalog_status: "ready" });
    const { container } = render(<App />);
    const shell = container.querySelector(".app-shell");

    expect(shell).toHaveClass("assistant-shell");

    fireEvent.click(screen.getByRole("button", { name: "漏洞情报" }));
    expect(useAppStore.getState().view).toBe("intelligence");
    expect(container.querySelector(".app-shell")).toHaveClass("assistant-shell");

    fireEvent.click(screen.getByRole("button", { name: "漏洞库" }));
    expect(useAppStore.getState().view).toBe("records");
    expect(container.querySelector(".app-shell")).toHaveClass("assistant-shell");
    expect(screen.queryByRole("button", { name: "运行状态" })).not.toBeInTheDocument();
  });

  it("shows execution progress only in the inspector and restores it after navigation", () => {
    vi.spyOn(api, "dashboard").mockResolvedValue({ records: [], stats: {}, catalog_status: "ready" });
    useAppStore.setState({
      turns: [{
        id: "assistant-running",
        role: "assistant",
        content: "正在分析漏洞情报",
        createdAt: "2026-08-06T08:00:00Z",
        state: "streaming",
        trace: [{ node: "supervisor_agent", status: "running", message: "正在规划报告任务" }],
      }],
    });

    const { container } = render(<App />);
    expect(screen.queryByRole("button", { name: /思考过程/ })).not.toBeInTheDocument();
    expect(screen.queryByText("正在规划报告任务")).not.toBeInTheDocument();

    act(() => useAppStore.getState().set({ view: "assistant", inspectorOpen: true }));
    expect(screen.getByText("正在规划报告任务")).toBeInTheDocument();

    act(() => {
      useAppStore.getState().updateTurn("assistant-running", {
        state: "completed",
        trace: [{ node: "supervisor_agent", status: "completed", message: "规划完成" }],
        result: { answer: "分析完成", orchestration: { agentic: true } },
      });
    });
    expect(screen.queryByRole("button", { name: /思考过程/ })).not.toBeInTheDocument();
    expect(screen.getByText("规划完成")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "漏洞情报" }));
    expect(container.querySelector(".assistant-workspace")).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryByText("规划完成")).not.toBeInTheDocument();

    act(() => useAppStore.getState().set({ view: "assistant", inspectorOpen: true }));
    expect(container.querySelector(".assistant-workspace")).toHaveAttribute("aria-hidden", "false");
    expect(screen.queryByRole("button", { name: /思考过程/ })).not.toBeInTheDocument();
    expect(screen.getByText("规划完成")).toBeInTheDocument();
  });

  it("keeps the active workspace and event subscription mounted while settings is open", () => {
    const { container } = render(<App />);
    const workspace = container.querySelector(".assistant-workspace");
    const shell = container.querySelector(".app-shell");

    expect(workspace).toBeInTheDocument();
    act(() => useAppStore.getState().set({ view: "settings" }));

    expect(shell).toHaveStyle({ display: "none" });
    expect(shell).toHaveAttribute("aria-hidden", "true");
    expect(workspace).toBeInTheDocument();

    act(() => useAppStore.getState().set({ view: "assistant" }));
    expect(container.querySelector(".assistant-workspace")).toBe(workspace);
    expect(shell).not.toHaveStyle({ display: "none" });
  });

  it("restores persisted trace actions from the current answer_payload field", async () => {
    useAppStore.setState({
      conversations: [{
        id: "conversation-actions",
        session_id: "conversation-actions",
        title: "恢复动作任务",
        updated_at: "2026-08-06T08:00:00Z",
      }],
    });
    vi.spyOn(api, "conversation").mockResolvedValue({
      id: "conversation-actions",
      session_id: "conversation-actions",
      title: "恢复动作任务",
      updated_at: "2026-08-06T08:00:00Z",
      exchanges: [{
        id: "exchange-1",
        question: "查询组件漏洞",
        answer: "已完成",
        answer_payload: {
          answer: "已完成",
          orchestration: { agentic: true },
          trace: [{
            node: "component_catalog.query",
            status: "completed",
            message: "查询动作已恢复",
            tool_name: "query_component_vulnerability_catalog",
          }],
        },
      }],
    });

    render(<App />);
    fireEvent.click(screen.getByText("恢复动作任务"));

    expect((await screen.findAllByText("已完成")).length).toBeGreaterThan(0);
    expect(screen.queryByText("查询动作已恢复")).not.toBeInTheDocument();
    act(() => useAppStore.getState().set({ inspectorOpen: true }));
    expect(screen.getByText("查询动作已恢复")).toBeInTheDocument();
    const restored = useAppStore.getState().turns.find((turn) => turn.role === "assistant");
    expect(restored?.result?.answer).toBe("已完成");
    expect(restored?.trace?.[0]?.tool_name).toBe("query_component_vulnerability_catalog");
  });

  it("updates the document language when the persisted locale changes", () => {
    const { rerender } = render(<App />);
    expect(document.documentElement.lang).toBe("zh-Hans");

    useAppStore.getState().set({
      settings: {
        ...useAppStore.getState().settings!,
        preferences: { ...useAppStore.getState().settings!.preferences, language: "en" },
      },
    });
    rerender(<App />);

    expect(document.documentElement.lang).toBe("en");
    expect(screen.getByRole("button", { name: "Vulnerability intelligence" })).toBeInTheDocument();
  });

  it("opens the initial setup guide before the workspace on a fresh install", () => {
    useAppStore.setState({ initialSetupRequired: true, bootstrapReady: true });
    const { container } = render(<App />);

    expect(screen.getByRole("heading", { name: "欢迎使用安全智脑" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "配置个人信息" })).toBeInTheDocument();
    expect(container.querySelector(".app-shell")).not.toBeInTheDocument();
  });
});
