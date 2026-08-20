// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { chooseProjectDirectory } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import { CommandPalette } from "./CommandPalette";

vi.mock("../lib/platform", () => ({
  chooseProjectDirectory: vi.fn(),
  openNewTaskWindow: vi.fn(),
}));

function Harness() {
  return (
    <>
      <button type="button" onClick={() => useAppStore.getState().set({ commandOpen: true })}>Open commands</button>
      <CommandPalette />
    </>
  );
}

describe("CommandPalette accessibility", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(chooseProjectDirectory).mockResolvedValue(null);
    useAppStore.setState({
      commandOpen: false,
      view: "assistant",
      sidebarView: "tasks",
      activeTaskId: "",
      activeSessionId: "",
      workspacePath: "",
      workspaceName: "",
      composerAttachment: null,
      composerAttachmentLeaving: false,
      turns: [],
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("isolates the background, traps focus, and restores the opening control", async () => {
    render(<Harness />);
    const trigger = screen.getByRole("button", { name: "Open commands" });
    trigger.focus();
    fireEvent.click(trigger);

    const dialog = await screen.findByRole("dialog", { name: "命令" });
    const search = screen.getByRole("searchbox", { name: "搜索命令" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(search).toHaveFocus();
    expect(search).toHaveAttribute("name", "command-query");
    expect(search).toHaveAttribute("autocomplete", "off");
    expect(trigger).toHaveAttribute("aria-hidden", "true");
    expect(trigger.inert).toBe(true);

    fireEvent.keyDown(search, { key: "ArrowDown" });
    expect(screen.getByRole("button", { name: /新建安全任务/ })).toHaveFocus();

    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(trigger).toHaveFocus();
    expect(trigger).not.toHaveAttribute("aria-hidden");
    expect(trigger.inert).not.toBe(true);
  });

  it("keeps Tab navigation inside the dialog", () => {
    useAppStore.setState({ commandOpen: true });
    render(<Harness />);

    const search = screen.getByRole("searchbox", { name: "搜索命令" });
    const buttons = screen.getAllByRole("button");
    const last = buttons.at(-1)!;
    last.focus();
    fireEvent.keyDown(document, { key: "Tab" });

    expect(search).toHaveFocus();
  });

  it("opens the selected project on the task page with a ready attachment", async () => {
    vi.mocked(chooseProjectDirectory).mockResolvedValue("/Users/test/projects/demo-project");
    useAppStore.setState({
      commandOpen: true,
      view: "records",
      sidebarView: "projects",
      activeTaskId: "old-task",
      activeSessionId: "old-session",
      workspacePath: "/Users/test/projects/old-project",
      workspaceName: "old-project",
      composerAttachment: { path: "/Users/test/projects/stale", name: "stale" },
      composerAttachmentLeaving: true,
      turns: [{
        id: "old-turn",
        role: "assistant",
        content: "旧任务内容",
        createdAt: "2026-08-06T08:00:00Z",
        state: "completed",
      }],
    });
    render(<Harness />);

    fireEvent.click(screen.getByRole("button", { name: /打开代码项目/ }));

    await waitFor(() => expect(useAppStore.getState().commandOpen).toBe(false));
    expect(chooseProjectDirectory).toHaveBeenCalledOnce();
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
    expect(screen.queryByRole("dialog", { name: "命令" })).not.toBeInTheDocument();
  });

  it("closes after directory selection is cancelled without changing task context", async () => {
    vi.mocked(chooseProjectDirectory).mockResolvedValue(null);
    useAppStore.setState({
      commandOpen: true,
      view: "records",
      sidebarView: "projects",
      activeTaskId: "current-task",
      activeSessionId: "current-session",
      workspacePath: "/Users/test/projects/current",
      workspaceName: "current",
      composerAttachment: { path: "/Users/test/projects/current", name: "current" },
    });
    render(<Harness />);

    fireEvent.click(screen.getByRole("button", { name: /打开代码项目/ }));

    await waitFor(() => expect(useAppStore.getState().commandOpen).toBe(false));
    expect(useAppStore.getState()).toMatchObject({
      view: "records",
      sidebarView: "projects",
      activeTaskId: "current-task",
      activeSessionId: "current-session",
      workspacePath: "/Users/test/projects/current",
      workspaceName: "current",
      composerAttachment: { path: "/Users/test/projects/current", name: "current" },
    });
  });
});
