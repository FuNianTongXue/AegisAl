// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { useAppStore } from "../store/appStore";
import type { AgentTask, ConversationSummary } from "../types";
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
    useAppStore.setState({
      userId: "analyst",
      view: "assistant",
      sidebarOpen: true,
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
    fireEvent.click(screen.getByRole("tab", { name: "项目" }));
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
    fireEvent.click(screen.getByRole("tab", { name: "任务" }));

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
});
