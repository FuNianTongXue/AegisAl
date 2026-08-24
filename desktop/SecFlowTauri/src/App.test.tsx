// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";
import { api } from "./lib/api";
import { useAppStore } from "./store/appStore";

const refreshBackend = vi.hoisted(() => vi.fn());

vi.mock("./hooks/useBackend", () => ({
  useBackendBootstrap: () => refreshBackend,
  useActiveTaskStream: vi.fn(),
}));

describe("App navigation theme", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    refreshBackend.mockReset();
    useAppStore.setState({
      view: "assistant",
      sidebarOpen: true,
      inspectorOpen: false,
      commandOpen: false,
      bootstrapReady: true,
      bootstrapError: undefined,
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
    window.history.replaceState({}, "", "/");
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

  it("shows execution progress in the main thinking trace and keeps the inspector focused on runtime status", () => {
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
    const executionSummary = screen.getByRole("button", { name: /正在思考 Supervisor 规划报告任务/ });
    expect(executionSummary).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(executionSummary);
    expect(screen.getByRole("list", { name: "执行过程" })).toBeInTheDocument();
    expect(screen.getByText("正在规划报告任务")).toBeInTheDocument();

    act(() => useAppStore.getState().set({ view: "assistant", inspectorOpen: true }));
    expect(screen.getByText("正在规划报告任务")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "执行过程" })).toBeInTheDocument();
    expect(within(container.querySelector(".inspector-panel") as HTMLElement).queryByRole("list", { name: "执行过程" })).not.toBeInTheDocument();

    act(() => {
      useAppStore.getState().updateTurn("assistant-running", {
        state: "completed",
        trace: [{ node: "supervisor_agent", status: "completed", message: "规划完成" }],
        result: { answer: "分析完成", orchestration: { agentic: true } },
      });
    });
    expect(screen.getByRole("list", { name: "执行过程" })).toBeInTheDocument();
    expect(screen.getByText("规划完成")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "漏洞情报" }));
    expect(container.querySelector(".assistant-workspace")).toHaveAttribute("aria-hidden", "true");

    act(() => useAppStore.getState().set({ view: "assistant", inspectorOpen: true }));
    expect(container.querySelector(".assistant-workspace")).toHaveAttribute("aria-hidden", "false");
    expect(screen.getByRole("list", { name: "执行过程" })).toBeInTheDocument();
    expect(within(container.querySelector(".inspector-panel") as HTMLElement).queryByRole("list", { name: "执行过程" })).not.toBeInTheDocument();
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
    expect(screen.getByText("查询动作已恢复")).toBeInTheDocument();
    act(() => useAppStore.getState().set({ inspectorOpen: true }));
    expect(screen.getByText("查询动作已恢复")).toBeInTheDocument();
    const restored = useAppStore.getState().turns.find((turn) => turn.role === "assistant");
    expect(restored?.result?.answer).toBe("已完成");
    expect(restored?.trace?.[0]?.tool_name).toBe("query_component_vulnerability_catalog");
  });

  it("keeps completed thinking traces collapsed when switching historical conversations", async () => {
    const conversations = [
      {
        id: "conversation-first",
        session_id: "session-first",
        title: "第一段历史任务",
        updated_at: "2026-08-06T08:00:00Z",
      },
      {
        id: "conversation-second",
        session_id: "session-second",
        title: "第二段历史任务",
        updated_at: "2026-08-06T09:00:00Z",
      },
    ];
    useAppStore.setState({ conversations });
    vi.spyOn(api, "conversation").mockImplementation(async (sessionId) => {
      const first = sessionId === "session-first";
      const conversation = first ? conversations[0] : conversations[1];
      return {
        ...conversation,
        exchanges: [{
          id: "shared-exchange-id",
          question: first ? "打开第一段历史" : "打开第二段历史",
          answer: first ? "第一段历史回答" : "第二段历史回答",
          answer_payload: {
            answer: first ? "第一段历史回答" : "第二段历史回答",
            trace: [{
              node: first ? "first_history_step" : "second_history_step",
              status: "completed",
              message: first ? "第一段历史执行完成" : "第二段历史执行完成",
            }],
          },
        }],
      };
    });

    render(<App />);
    fireEvent.click(screen.getByText("第一段历史任务"));

    const firstThinking = await screen.findByRole("button", { name: /思考完成/ });
    expect(firstThinking).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("第一段历史执行完成").closest(".thinking-state-body")).toHaveAttribute("aria-hidden", "true");
    fireEvent.click(firstThinking);
    expect(firstThinking).toHaveAttribute("aria-expanded", "true");

    fireEvent.click(screen.getByText("第二段历史任务"));

    expect(await screen.findByText("第二段历史回答")).toBeInTheDocument();
    const secondThinking = screen.getByRole("button", { name: /思考完成/ });
    expect(secondThinking).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("第二段历史执行完成").closest(".thinking-state-body")).toHaveAttribute("aria-hidden", "true");
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

    expect(screen.getByRole("heading", { name: "欢迎使用神盾" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "配置个人信息" })).toBeInTheDocument();
    expect(container.querySelector(".app-shell")).not.toBeInTheDocument();
  });

  it("provides a skip link whose target follows the visible primary view", () => {
    const { container } = render(<App />);

    const skipLink = screen.getByRole("link", { name: "跳到主要内容" });
    const workspaceMain = container.querySelector("main#main-content");
    expect(skipLink).toHaveAttribute("href", "#main-content");
    expect(workspaceMain).toHaveAttribute("tabindex", "-1");
    fireEvent.click(skipLink);
    expect(workspaceMain).toHaveFocus();

    act(() => useAppStore.getState().set({ view: "settings" }));
    expect(container.querySelector(".workspace-content")).not.toHaveAttribute("id");
    expect(container.querySelector("#main-content .settings-stage")).toBeInTheDocument();
  });

  it("mirrors navigation in the URL while preserving task-window parameters", () => {
    window.history.replaceState({}, "", "/?secflowWindow=task&taskWindowId=window-1");
    render(<App />);

    act(() => useAppStore.getState().set({
      view: "archive",
      activeSessionId: "session-7",
      activeTaskId: "task-9",
    }));

    const params = new URLSearchParams(window.location.search);
    expect(params.get("secflowWindow")).toBe("task");
    expect(params.get("taskWindowId")).toBe("window-1");
    expect(params.get("view")).toBe("archive");
    expect(params.get("session")).toBe("session-7");
    expect(params.get("task")).toBe("task-9");
  });

  it("shows startup failures and invokes the retry action", () => {
    useAppStore.setState({ bootstrapReady: false, bootstrapError: "connection refused" });
    render(<App />);

    expect(screen.getByRole("alert")).toHaveTextContent("本机服务初始化失败");
    expect(screen.getByText("connection refused")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "重试" }));
    expect(refreshBackend).toHaveBeenCalledOnce();
  });
});
