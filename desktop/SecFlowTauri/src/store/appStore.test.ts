// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { useAppStore } from "./appStore";

const storageKey = "secflow-desktop-state-v1";

describe("app store persistence", () => {
  beforeEach(() => {
    localStorage.clear();
    useAppStore.setState({
      userId: "default",
      view: "assistant",
      theme: "system",
      fontScale: 1,
      sidebarOpen: true,
      sidebarView: "tasks",
      inspectorOpen: false,
      activeTaskId: "",
      activeSessionId: "",
      workspacePath: "",
      workspaceName: "",
      turns: [],
    });
  });

  afterEach(() => localStorage.clear());

  it("persists preferences but not active identifiers without their message detail", () => {
    useAppStore.setState({
      theme: "dark",
      activeTaskId: "task-persisted-without-detail",
      activeSessionId: "session-persisted-without-detail",
      workspacePath: "/tmp/project",
      workspaceName: "project",
      turns: [{
        id: "transient-turn",
        role: "assistant",
        content: "transient",
        createdAt: "2026-08-06T08:00:00Z",
        state: "completed",
      }],
    });

    const persisted = JSON.parse(localStorage.getItem(storageKey) || "{}") as { version?: number; state?: Record<string, unknown> };
    expect(persisted.version).toBe(2);
    expect(persisted.state).toMatchObject({ theme: "dark" });
    expect(persisted.state).not.toHaveProperty("activeTaskId");
    expect(persisted.state).not.toHaveProperty("activeSessionId");
    expect(persisted.state).not.toHaveProperty("workspacePath");
    expect(persisted.state).not.toHaveProperty("sidebarView");
    expect(persisted.state).not.toHaveProperty("turns");
  });

  it("opens a selected project as a clean task with a ready composer attachment", () => {
    useAppStore.setState({
      view: "records",
      sidebarView: "projects",
      activeTaskId: "old-task",
      activeSessionId: "old-session",
      workspacePath: "/tmp/old-project",
      workspaceName: "old-project",
      composerAttachment: { path: "/tmp/stale-project", name: "stale-project" },
      composerAttachmentLeaving: true,
      turns: [{
        id: "old-turn",
        role: "assistant",
        content: "旧任务内容",
        createdAt: "2026-08-06T08:00:00Z",
        state: "completed",
      }],
    });

    useAppStore.getState().openProjectForTask("/Users/test/projects/demo-project");

    expect(useAppStore.getState()).toMatchObject({
      view: "assistant",
      sidebarView: "tasks",
      activeTaskId: "",
      activeSessionId: "",
      workspacePath: "/Users/test/projects/demo-project",
      workspaceName: "demo-project",
      composerAttachment: {
        path: "/Users/test/projects/demo-project",
        name: "demo-project",
      },
      composerAttachmentLeaving: false,
      turns: [],
    });
  });

  it("clears incomplete active navigation when migrating version-one data", async () => {
    useAppStore.setState({
      activeTaskId: "current-task",
      activeSessionId: "current-session",
      workspacePath: "/tmp/current",
      workspaceName: "current",
    });
    localStorage.setItem(storageKey, JSON.stringify({
      version: 1,
      state: {
        userId: "analyst",
        theme: "dark",
        fontScale: 1.12,
        sidebarOpen: false,
        inspectorOpen: true,
        activeTaskId: "legacy-task",
        activeSessionId: "legacy-session",
        workspacePath: "/tmp/legacy",
        workspaceName: "legacy",
      },
    }));

    await useAppStore.persist.rehydrate();

    expect(useAppStore.getState()).toMatchObject({
      userId: "analyst",
      theme: "dark",
      fontScale: 1.12,
      sidebarOpen: false,
      inspectorOpen: true,
      view: "assistant",
      sidebarView: "tasks",
      activeTaskId: "",
      activeSessionId: "",
      workspacePath: "",
      workspaceName: "",
      turns: [],
    });
  });
});
