// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { listenForProjectDirectoryDrop } from "../lib/platform";
import { waitForBackendReady } from "../hooks/useBackend";
import { useAppStore } from "../store/appStore";
import type { AgentTask } from "../types";
import { AssistantWorkspace } from "./AssistantWorkspace";

vi.mock("../hooks/useBackend", () => ({
  useActiveTaskStream: vi.fn(),
  waitForBackendReady: vi.fn(),
}));
vi.mock("../lib/platform", () => ({
  chooseProjectDirectory: vi.fn(),
  listenForProjectDirectoryDrop: vi.fn().mockResolvedValue(vi.fn()),
}));

describe("AssistantWorkspace project routing", () => {
  beforeEach(() => {
    // restoreAllMocks wipes the module mock implementation; re-apply it per test.
    vi.mocked(listenForProjectDirectoryDrop).mockResolvedValue(vi.fn());
    vi.mocked(waitForBackendReady).mockResolvedValue({ ok: true } as never);
    useAppStore.setState({
      userId: "analyst",
      activeSessionId: "session-1",
      activeTaskId: "old-task",
      workspacePath: "/Users/test/projects/kafka",
      workspaceName: "kafka",
      composerAttachment: null,
      composerAttachmentLeaving: false,
      health: undefined,
      tasks: [{ id: "old-task", workspace_path: "/Users/test/projects/old" } as AgentTask],
      turns: [],
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("uses the selected workspace instead of submitting to a stale active task", async () => {
    const workspaceAction = vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "已创建扫描任务" },
    } as never);
    const taskAction = vi.spyOn(api, "taskAction");
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "这个项目存在哪些漏洞" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    // A workspace-scoped question without an explicit slash command must first ask
    // for the scan type; the confirmed action must target the selected workspace.
    const codeScanButton = await screen.findByRole("button", { name: "代码扫描" });
    fireEvent.click(codeScanButton);

    await waitFor(() => expect(workspaceAction).toHaveBeenCalledWith(
      "请仅执行代码安全扫描（不包含SBOM）：这个项目存在哪些漏洞",
      "/Users/test/projects/kafka",
      "analyst",
      "session-1",
      "zh-Hans",
    ));
    expect(taskAction).not.toHaveBeenCalled();
  });

  it("waits for the packaged backend before sending an early cold-start request", async () => {
    let markReady!: (value: never) => void;
    vi.mocked(waitForBackendReady).mockReturnValue(new Promise((resolve) => { markReady = resolve; }));
    const workspaceAction = vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "服务已就绪" },
    } as never);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "什么是 SQL 注入" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    expect(workspaceAction).not.toHaveBeenCalled();
    markReady({ ok: true } as never);

    await waitFor(() => expect(workspaceAction).toHaveBeenCalledOnce());
    expect(screen.queryByText("本机安全服务暂时不可用，请刷新本机服务后重试。")).not.toBeInTheDocument();
  });

  it("routes submitted progress to the inspector without showing execution details in the conversation", async () => {
    vi.spyOn(api, "workspaceAction").mockReturnValue(new Promise(() => {}) as never);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "什么是 SQL 注入" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    await waitFor(() => expect(useAppStore.getState().turns.some((turn) => (
      turn.trace?.some((item) => item.message === "已提交项目目标，正在进入分析流程…")
    ))).toBe(true));
    expect(useAppStore.getState().inspectorOpen).toBe(true);
    expect(screen.queryByText("已提交项目目标，正在进入分析流程…")).not.toBeInTheDocument();
    expect(screen.getByLabelText("正在生成")).toBeInTheDocument();
  });

  it("asks for the scan type when the question uses common check wording", async () => {
    vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "ok" },
    } as never);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "检查这个项目的安全状况" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    expect(await screen.findByRole("button", { name: "代码扫描" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "SBOM扫描" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "完整扫描" })).toBeInTheDocument();
  });

  it("sends report requests straight through without the scan-type prompt", async () => {
    const workspaceAction = vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "报告已生成" },
    } as never);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "把刚才的扫描结果生成报告" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    await waitFor(() => expect(workspaceAction).toHaveBeenCalledWith(
      "把刚才的扫描结果生成报告",
      "/Users/test/projects/kafka",
      "analyst",
      "session-1",
      "zh-Hans",
    ));
    expect(screen.queryByRole("button", { name: "代码扫描" })).not.toBeInTheDocument();
  });

  it("sends non-scan questions straight to the assistant without the scan-type prompt", async () => {
    const workspaceAction = vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "SQL 注入是一种……" },
    } as never);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "什么是 SQL 注入" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    await waitFor(() => expect(workspaceAction).toHaveBeenCalledWith(
      "什么是 SQL 注入",
      "/Users/test/projects/kafka",
      "analyst",
      "session-1",
      "zh-Hans",
    ));
    expect(screen.queryByRole("button", { name: "代码扫描" })).not.toBeInTheDocument();
  });

  it("submits the composer attachment as the target workspace and consumes the chip", async () => {
    const workspaceAction = vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "已创建扫描任务" },
    } as never);
    const taskAction = vi.spyOn(api, "taskAction");
    useAppStore.setState({
      composerAttachment: { path: "/Users/test/projects/fresh", name: "fresh" },
      composerAttachmentLeaving: false,
    });
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "检查这个项目的安全状况" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    // 附件存在时扫描类问题先询问扫描类型，确认后附件随消息一并提交并消耗。
    fireEvent.click(await screen.findByRole("button", { name: "完整扫描" }));

    await waitFor(() => expect(workspaceAction).toHaveBeenCalledWith(
      "请执行完整安全扫描（代码安全扫描 + SBOM生成 + 许可证识别）：检查这个项目的安全状况",
      "/Users/test/projects/fresh",
      "analyst",
      "session-1",
      "zh-Hans",
    ));
    expect(taskAction).not.toHaveBeenCalled();
    // 附件并入会话项目上下文，用户消息携带附件 chip，输入区附件被消耗。
    expect(useAppStore.getState().workspacePath).toBe("/Users/test/projects/fresh");
    expect(useAppStore.getState().workspaceName).toBe("fresh");
    await waitFor(() => expect(useAppStore.getState().composerAttachment).toBeNull());
    const userTurn = document.querySelector(".user-turn");
    expect(userTurn?.querySelector(".user-attachment-chip")).toHaveTextContent("fresh");
  });

  it("routes to the active task when the attachment matches its workspace", async () => {
    const taskAction = vi.spyOn(api, "taskAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "报告已生成" },
    } as never);
    const workspaceAction = vi.spyOn(api, "workspaceAction");
    useAppStore.setState({
      composerAttachment: { path: "/Users/test/projects/old", name: "old" },
      composerAttachmentLeaving: false,
    });
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "把刚才的扫描结果生成报告" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    await waitFor(() => expect(taskAction).toHaveBeenCalledWith(
      "old-task",
      "把刚才的扫描结果生成报告",
      "analyst",
      "session-1",
      "zh-Hans",
    ));
    expect(workspaceAction).not.toHaveBeenCalled();
    await waitFor(() => expect(useAppStore.getState().composerAttachment).toBeNull());
  });

  it("routes the vulnerability quick action deterministically and keeps one useful error turn", async () => {
    useAppStore.setState({
      activeTaskId: "",
      workspacePath: "",
      workspaceName: "",
      tasks: [],
      turns: [],
    });
    const streamQuestion = vi.spyOn(api, "streamQuestion").mockRejectedValue(new Error("database is locked"));
    render(<AssistantWorkspace />);

    fireEvent.click(screen.getByRole("button", { name: /查询最新漏洞/ }));

    await waitFor(() => expect(streamQuestion).toHaveBeenCalled());
    expect(streamQuestion.mock.calls[0][0]).toMatchObject({
      question: "查询本月严重和高危组件漏洞",
      intent_hint: "component_vulnerability_catalog",
      response_language: "zh-Hans",
    });
    await waitFor(() => expect(screen.getByText("本地漏洞库正在更新，请稍后重试。")).toBeInTheDocument());
    const turns = useAppStore.getState().turns;
    expect(turns.filter((turn) => turn.role === "assistant")).toHaveLength(1);
    expect(turns.find((turn) => turn.role === "assistant")?.state).toBe("error");
    expect(turns.some((turn) => turn.state === "streaming")).toBe(false);
  });

  it("uses the shared Information Center mark inside the kinetic welcome stage", () => {
    useAppStore.setState({ turns: [] });
    render(<AssistantWorkspace />);

    expect(screen.getByTestId("kinetic-grid")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "SecFlow 信息中心标识" })).toBeInTheDocument();
  });
});
