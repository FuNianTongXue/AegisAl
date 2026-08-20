// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { AgentTask, ConversationDetail, ConversationSummary } from "../types";
import { AppSidebar } from "./AppSidebar";

const conversation: ConversationSummary = {
  id: "conversation-row",
  session_id: "conversation-session",
  title: "待删除的历史任务",
  preview: "仍显示在主区域的旧内容",
  updated_at: "2026-08-06T08:00:00Z",
};

const task: AgentTask = {
  id: "agent-task-delete",
  objective: "待删除的项目扫描",
  workspace_path: "/Users/test/project",
  workspace_name: "project",
  user_id: "analyst",
  status: "completed",
  current_node: "compose_result",
  languages: ["python"],
  plan: [],
  events: [],
  report_ready: false,
  report_decision: "unavailable",
  created_at: "2026-08-06T08:00:00Z",
  updated_at: "2026-08-06T08:00:00Z",
};

describe("AppSidebar deletion state", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    useAppStore.setState({
      userId: "analyst",
      view: "assistant",
      sidebarOpen: true,
      sidebarView: "tasks",
      activeTaskId: "",
      activeSessionId: "",
      workspacePath: "",
      workspaceName: "",
      composerAttachment: null,
      composerAttachmentLeaving: false,
      tasks: [],
      archivedTasks: [],
      conversations: [],
      archivedConversations: [],
      turns: [],
      settings: undefined,
      llm: undefined,
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("clears the active conversation content and persisted identifiers after deletion", async () => {
    vi.spyOn(api, "deleteConversation").mockResolvedValue({ id: conversation.id });
    useAppStore.setState({
      conversations: [conversation],
      archivedConversations: [conversation],
      activeSessionId: conversation.session_id,
      activeTaskId: "stale-linked-task",
      workspacePath: "/Users/test/project",
      workspaceName: "project",
      turns: [{
        id: "exchange:assistant",
        role: "assistant",
        content: "删除后不应继续显示",
        createdAt: conversation.updated_at,
        state: "completed",
      }],
    });

    render(<AppSidebar />);
    fireEvent.click(screen.getByRole("button", { name: "删除" }));

    await waitFor(() => expect(useAppStore.getState().conversations).toEqual([]));
    expect(api.deleteConversation).toHaveBeenCalledWith("conversation-session", "analyst");
    expect(useAppStore.getState()).toMatchObject({
      archivedConversations: [],
      activeSessionId: "",
      activeTaskId: "",
      workspacePath: "",
      workspaceName: "",
      turns: [],
    });
  });

  it("clears the active project task card and related conversation state after deletion", async () => {
    vi.spyOn(api, "deleteTask").mockResolvedValue({ id: task.id });
    useAppStore.setState({
      tasks: [task],
      archivedTasks: [task],
      activeTaskId: task.id,
      activeSessionId: "linked-session",
      workspacePath: task.workspace_path,
      workspaceName: task.workspace_name,
      turns: [{
        id: `task:${task.id}`,
        role: "assistant",
        content: task.objective,
        createdAt: task.updated_at,
        state: "completed",
        task,
      }],
    });

    render(<AppSidebar />);
    fireEvent.click(within(screen.getByRole("group", { name: "导航视图" })).getByRole("button", { name: "项目" }));
    fireEvent.click(screen.getByRole("button", { name: "删除" }));

    await waitFor(() => expect(useAppStore.getState().tasks).toEqual([]));
    expect(api.deleteTask).toHaveBeenCalledWith(task.id, "analyst");
    expect(useAppStore.getState()).toMatchObject({
      archivedTasks: [],
      activeSessionId: "",
      activeTaskId: "",
      workspacePath: "",
      workspaceName: "",
      turns: [],
    });
  });

  it("removes the running-status shortcut and opens new tasks in another window", () => {
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    render(<AppSidebar />);

    expect(screen.queryByRole("button", { name: "运行状态" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /新建任务/ }));

    expect(open).toHaveBeenCalledOnce();
    expect(String(open.mock.calls[0][0])).toContain("secflowWindow=task");
  });

  it("returns to the task landing page without creating another task window or session", () => {
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    useAppStore.setState({
      view: "intelligence",
      activeSessionId: "existing-session",
      activeTaskId: task.id,
      workspacePath: task.workspace_path,
      workspaceName: task.workspace_name,
      turns: [{
        id: "existing-turn",
        role: "assistant",
        content: "旧任务内容",
        createdAt: task.updated_at,
        state: "completed",
      }],
    });

    render(<AppSidebar />);
    fireEvent.click(within(screen.getByRole("group", { name: "导航视图" })).getByRole("button", { name: "任务" }));

    expect(open).not.toHaveBeenCalled();
    expect(useAppStore.getState()).toMatchObject({
      view: "assistant",
      activeSessionId: "",
      activeTaskId: "",
      workspacePath: "",
      workspaceName: "",
      turns: [],
    });
  });

  it("replaces stale conversation state when the same project task is opened repeatedly", () => {
    useAppStore.setState({
      tasks: [task],
      activeSessionId: "old-session",
      turns: [{
        id: "old-turn",
        role: "assistant",
        content: "旧会话",
        createdAt: task.updated_at,
        state: "completed",
      }],
    });

    render(<AppSidebar />);
    fireEvent.click(within(screen.getByRole("group", { name: "导航视图" })).getByRole("button", { name: "项目" }));
    fireEvent.click(screen.getByText(task.objective));
    fireEvent.click(screen.getByText(task.objective));

    expect(useAppStore.getState().activeSessionId).toBe("");
    expect(useAppStore.getState().turns).toHaveLength(1);
    expect(useAppStore.getState().turns[0]).toMatchObject({ id: `task:${task.id}`, task });
  });

  it("keeps the newest conversation when an older request finishes last", async () => {
    const firstConversation = { ...conversation, id: "first-row", session_id: "first-session", title: "第一个对话" };
    const secondConversation = { ...conversation, id: "second-row", session_id: "second-session", title: "第二个对话" };
    const first = deferred<ConversationDetail>();
    const second = deferred<ConversationDetail>();
    vi.spyOn(api, "conversation").mockImplementation((sessionId) => (
      sessionId === firstConversation.session_id ? first.promise : second.promise
    ));
    useAppStore.setState({ conversations: [firstConversation, secondConversation] });

    render(<AppSidebar />);
    fireEvent.click(screen.getByText(firstConversation.title));
    fireEvent.click(screen.getByText(secondConversation.title));

    await act(async () => {
      second.resolve(conversationDetail(secondConversation, "second-exchange", "最新回答"));
      await second.promise;
    });
    await waitFor(() => expect(useAppStore.getState().turns.some((turn) => turn.content === "最新回答")).toBe(true));

    await act(async () => {
      first.resolve(conversationDetail(firstConversation, "first-exchange", "过期回答"));
      await first.promise;
    });

    expect(useAppStore.getState().activeSessionId).toBe("second-session");
    expect(useAppStore.getState().turns.some((turn) => turn.content === "过期回答")).toBe(false);
  });

  it("shows a recoverable error when conversation detail cannot be loaded", async () => {
    vi.spyOn(api, "conversation").mockRejectedValue(new Error("本机服务断开"));
    useAppStore.setState({ conversations: [conversation] });

    render(<AppSidebar />);
    fireEvent.click(screen.getByText(conversation.title));

    expect(await screen.findByRole("alert")).toHaveTextContent("无法加载对话：本机服务断开");
    expect(useAppStore.getState().activeSessionId).toBe("");
    expect(useAppStore.getState().turns).toEqual([]);
  });

  it("does not delete a conversation when confirmation is declined", () => {
    vi.mocked(window.confirm).mockReturnValueOnce(false);
    const remove = vi.spyOn(api, "deleteConversation").mockResolvedValue({ id: conversation.id });
    useAppStore.setState({ conversations: [conversation] });

    render(<AppSidebar />);
    fireEvent.click(screen.getByRole("button", { name: "删除" }));

    expect(remove).not.toHaveBeenCalled();
    expect(useAppStore.getState().conversations).toEqual([conversation]);
  });

  it("exposes the project/task switch as a pressed button group", () => {
    render(<AppSidebar />);
    const switcher = screen.getByRole("group", { name: "导航视图" });
    const projectButton = within(switcher).getByRole("button", { name: "项目" });
    const taskButton = within(switcher).getByRole("button", { name: "任务" });

    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(projectButton).toHaveAttribute("aria-pressed", "false");
    expect(taskButton).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(projectButton);
    expect(projectButton).toHaveAttribute("aria-pressed", "true");
    expect(taskButton).toHaveAttribute("aria-pressed", "false");
  });

  it("switches to task navigation when a project is opened from another surface", () => {
    useAppStore.setState({ sidebarView: "projects" });
    render(<AppSidebar />);
    const switcher = screen.getByRole("group", { name: "导航视图" });

    act(() => useAppStore.getState().openProjectForTask("/Users/test/projects/demo-project"));

    expect(within(switcher).getByRole("button", { name: "项目" })).toHaveAttribute("aria-pressed", "false");
    expect(within(switcher).getByRole("button", { name: "任务" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("暂无历史任务")).toBeInTheDocument();
  });

  it("renders conversation history in batches of forty and resets after switching views", async () => {
    useAppStore.setState({ conversations: makeConversations(85) });
    const { container } = render(<AppSidebar />);
    const switcher = screen.getByRole("group", { name: "导航视图" });

    expect(container.querySelectorAll(".sidebar-section .sidebar-item")).toHaveLength(40);
    expect(screen.getByRole("button", { name: "显示更多" })).toHaveTextContent("45");

    fireEvent.click(screen.getByRole("button", { name: "显示更多" }));
    expect(container.querySelectorAll(".sidebar-section .sidebar-item")).toHaveLength(80);
    expect(screen.getByRole("button", { name: "显示更多" })).toHaveTextContent("5");

    act(() => useAppStore.getState().set({ conversations: makeConversations(84) }));
    await waitFor(() => expect(container.querySelectorAll(".sidebar-section .sidebar-item")).toHaveLength(40));

    fireEvent.click(screen.getByRole("button", { name: "显示更多" }));
    expect(container.querySelectorAll(".sidebar-section .sidebar-item")).toHaveLength(80);

    fireEvent.click(within(switcher).getByRole("button", { name: "项目" }));
    fireEvent.click(within(switcher).getByRole("button", { name: "任务" }));
    await waitFor(() => expect(container.querySelectorAll(".sidebar-section .sidebar-item")).toHaveLength(40));
  });

  it("keeps collapsed icon navigation named and localizes history pagination", () => {
    useAppStore.setState({
      sidebarOpen: false,
      conversations: makeConversations(41),
      settings: {
        profile: { display_name: "Analyst", email: "", department: "", role: "" },
        preferences: { language: "en", dark_mode: false, font_size: "default" },
      },
    });
    render(<AppSidebar />);

    ["New task", "Search", "Vulnerability intelligence", "Vulnerability catalog", "User profile"].forEach((name) => {
      expect(screen.getByRole("button", { name })).toBeInTheDocument();
    });
    expect(document.querySelector('button.archive-entry[aria-label="Archive"]')).toBeInTheDocument();
    const switcher = screen.getByRole("group", { name: "Navigation view" });
    expect(within(switcher).getByRole("button", { name: "Projects" })).toBeInTheDocument();
    expect(within(switcher).getByRole("button", { name: "Tasks" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show more" })).toBeInTheDocument();
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

function conversationDetail(summary: ConversationSummary, exchangeId: string, answer: string): ConversationDetail {
  return {
    ...summary,
    exchanges: [{
      id: exchangeId,
      question: "问题",
      answer,
      created_at: summary.updated_at,
    }],
  };
}

function makeConversations(count: number): ConversationSummary[] {
  return Array.from({ length: count }, (_, index) => ({
    id: `conversation-${index + 1}`,
    session_id: `session-${index + 1}`,
    title: `历史对话 ${index + 1}`,
    updated_at: `2026-08-${String((index % 28) + 1).padStart(2, "0")}T08:00:00Z`,
  }));
}
