// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ProjectDropHandlers } from "../lib/platform";
import { api } from "../lib/api";
import { listenForProjectDirectoryDrop } from "../lib/platform";
import { useAppStore } from "../store/appStore";
import { PromptComposer } from "./PromptComposer";

vi.mock("../lib/platform", () => ({
  chooseProjectDirectory: vi.fn(),
  listenForProjectDirectoryDrop: vi.fn(),
}));

describe("PromptComposer project attachment", () => {
  let handlers: ProjectDropHandlers;

  beforeEach(() => {
    useAppStore.setState({
      workspacePath: "/tmp/old-project",
      workspaceName: "old-project",
      activeTaskId: "task-from-old-project",
      composerAttachment: null,
      composerAttachmentLeaving: false,
      turns: [],
      llm: undefined,
    });
    vi.mocked(listenForProjectDirectoryDrop).mockImplementation(async (nextHandlers) => {
      handlers = nextHandlers;
      return vi.fn();
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
  });

  it("shows the native drop state and pins the dropped directory as a per-message attachment", async () => {
    render(<PromptComposer busy={false} onSubmit={vi.fn()} onStop={vi.fn()} />);
    await act(async () => undefined);

    act(() => handlers.onActive(true));
    expect(screen.getByText("松开以关联整个项目")).toBeInTheDocument();

    act(() => handlers.onDrop("/Users/test/projects/kafka-4.3.1-src"));

    // 附件进入输入区 chip，但不写入会话项目状态（不再一直显示在前端）。
    expect(useAppStore.getState().composerAttachment).toEqual({
      path: "/Users/test/projects/kafka-4.3.1-src",
      name: "kafka-4.3.1-src",
    });
    expect(screen.getByText("kafka-4.3.1-src")).toBeInTheDocument();
    expect(useAppStore.getState().workspacePath).toBe("/tmp/old-project");
    expect(useAppStore.getState().activeTaskId).toBe("task-from-old-project");
  });

  it("submits the attachment with the message and clears the chip afterwards", async () => {
    const onSubmit = vi.fn().mockReturnValue(true);
    render(<PromptComposer busy={false} onSubmit={onSubmit} onStop={vi.fn()} />);
    await act(async () => undefined);
    act(() => handlers.onDrop("/Users/test/projects/kafka-4.3.1-src"));

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "扫描这个项目" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    expect(onSubmit).toHaveBeenCalledWith("扫描这个项目", {
      path: "/Users/test/projects/kafka-4.3.1-src",
      name: "kafka-4.3.1-src",
    });
    expect(useAppStore.getState().composerAttachmentLeaving).toBe(true);
    await waitFor(() => expect(useAppStore.getState().composerAttachment).toBeNull());
    expect(screen.queryByText("kafka-4.3.1-src")).not.toBeInTheDocument();
  });

  it("keeps the attachment when the submit is intercepted for scan-type confirmation", async () => {
    const onSubmit = vi.fn().mockReturnValue(false);
    render(<PromptComposer busy={false} onSubmit={onSubmit} onStop={vi.fn()} />);
    await act(async () => undefined);
    act(() => handlers.onDrop("/Users/test/projects/kafka-4.3.1-src"));

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "扫描这个项目" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    expect(onSubmit).toHaveBeenCalled();
    expect(useAppStore.getState().composerAttachment).not.toBeNull();
    expect(screen.getByText("kafka-4.3.1-src")).toBeInTheDocument();
  });

  it("removes the attachment when the user clicks the chip close button", async () => {
    render(<PromptComposer busy={false} onSubmit={vi.fn()} onStop={vi.fn()} />);
    await act(async () => undefined);
    act(() => handlers.onDrop("/Users/test/projects/kafka-4.3.1-src"));

    fireEvent.click(screen.getByRole("button", { name: "移除项目附件" }));

    await waitFor(() => expect(useAppStore.getState().composerAttachment).toBeNull());
    expect(screen.queryByText("kafka-4.3.1-src")).not.toBeInTheDocument();
  });

  it("explains that a single dropped file is not a project", async () => {
    render(<PromptComposer busy={false} onSubmit={vi.fn()} onStop={vi.fn()} />);
    await act(async () => undefined);

    act(() => handlers.onError("请拖入一个完整的项目目录，不能只拖入单个文件。"));

    expect(screen.getByRole("alert")).toHaveTextContent("请拖入一个完整的项目目录");
  });

  it("offers model-specific reasoning levels and persists the selected effort", async () => {
    useAppStore.setState({
      llm: {
        provider: "openai",
        endpoint: "https://api.openai.com/v1",
        model: "gpt-5.6-sol",
        max_tokens: 8192,
        timeout_ms: 120000,
        enabled: true,
        wire_api: "responses",
        reasoning_effort: "medium",
        reasoning_options: [
          { value: "none" },
          { value: "low" },
          { value: "medium" },
          { value: "high" },
          { value: "xhigh" },
          { value: "max" },
        ],
      },
    });
    const save = vi.spyOn(api, "saveLlmConfig").mockResolvedValue({
      ...useAppStore.getState().llm!,
      reasoning_effort: "high",
    });

    render(<PromptComposer busy={false} onSubmit={vi.fn()} onStop={vi.fn()} />);
    await act(async () => undefined);
    fireEvent.click(screen.getByRole("button", { name: "选择推理强度" }));
    fireEvent.click(screen.getByRole("menuitemradio", { name: /^高推理/ }));

    await waitFor(() => expect(save).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({ model: "gpt-5.6-sol", reasoning_effort: "high" }),
    ));
    await waitFor(() => expect(useAppStore.getState().llm?.reasoning_effort).toBe("high"));
  });

  it("switches DeepSeek chat to its dedicated reasoning model from the compact model menu", async () => {
    useAppStore.setState({
      llm: {
        provider: "deepseek",
        endpoint: "https://api.deepseek.com",
        model: "deepseek-chat",
        max_tokens: 8192,
        timeout_ms: 120000,
        enabled: true,
        reasoning_effort: "none",
        reasoning_options: [{ value: "none", fixed: true }],
      },
    });
    const save = vi.spyOn(api, "saveLlmConfig").mockResolvedValue({
      ...useAppStore.getState().llm!,
      model: "deepseek-reasoner",
      reasoning_effort: "high",
      reasoning_options: [{ value: "high", fixed: true }],
    });

    render(<PromptComposer busy={false} onSubmit={vi.fn()} onStop={vi.fn()} />);
    await act(async () => undefined);
    fireEvent.click(screen.getByRole("button", { name: "deepseek-chat" }));
    fireEvent.click(screen.getByRole("menuitemradio", { name: /deepseek-reasoner/ }));

    await waitFor(() => expect(save).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({ model: "deepseek-reasoner", reasoning_effort: "high" }),
    ));
  });
});
