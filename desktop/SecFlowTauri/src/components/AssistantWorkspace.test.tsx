// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { listenForProjectDirectoryDrop } from "../lib/platform";
import { waitForBackendReady } from "../hooks/useBackend";
import { useAppStore } from "../store/appStore";
import type { AgentTask, ChatTurn } from "../types";
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
      inspectorOpen: false,
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

  it("keeps submitted progress compact without forcing the inspector open", async () => {
    vi.spyOn(api, "workspaceAction").mockReturnValue(new Promise(() => {}) as never);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "什么是 SQL 注入" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    await waitFor(() => expect(useAppStore.getState().turns.some((turn) => (
      turn.trace?.some((item) => item.message === "已提交项目目标，正在进入分析流程…")
    ))).toBe(true));
    expect(useAppStore.getState().inspectorOpen).toBe(false);
    expect(screen.getByText("已提交项目目标，正在进入分析流程…")).toBeInTheDocument();
    const executionSummary = screen.getByRole("button", { name: /正在思考 submit objective/ });
    expect(executionSummary).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(executionSummary);
    expect(screen.getByRole("list", { name: "执行过程" })).toBeInTheDocument();
    expect(screen.queryByLabelText("正在生成")).not.toBeInTheDocument();
  });

  it("asks for the scan type when the question uses common check wording", async () => {
    vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "ok" },
    } as never);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "检查这个项目的安全状况" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    const codeScan = await screen.findByRole("button", { name: "代码扫描" });
    expect(screen.getByRole("alertdialog", { name: "请选择本次扫描的类型：" })).toBeInTheDocument();
    expect(codeScan).toHaveFocus();
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

  it("submits the project prepared by the command palette through the task quick action", async () => {
    const workspaceAction = vi.spyOn(api, "workspaceAction").mockResolvedValue({
      kind: "assistant",
      answer: { answer: "已创建扫描任务" },
    } as never);
    useAppStore.getState().openProjectForTask("/Users/test/projects/demo-project");
    render(<AssistantWorkspace />);

    expect(screen.getByText("demo-project")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /扫描代码项目/ }));
    fireEvent.click(await screen.findByRole("button", { name: "完整扫描" }));

    await waitFor(() => expect(workspaceAction).toHaveBeenCalledWith(
      "请执行完整安全扫描（代码安全扫描 + SBOM生成 + 许可证识别）：对我选择的项目进行完整代码安全扫描",
      "/Users/test/projects/demo-project",
      "analyst",
      "default",
      "zh-Hans",
    ));
    await waitFor(() => expect(useAppStore.getState().composerAttachment).toBeNull());
    expect(document.querySelector(".user-attachment-chip")).toHaveTextContent("demo-project");
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

  it("includes the selected emoji mode when streaming a regular question", async () => {
    useAppStore.setState({
      activeTaskId: "",
      workspacePath: "",
      workspaceName: "",
      tasks: [],
      turns: [],
      health: { ok: true } as never,
      settings: {
        profile: {
          display_name: "分析员",
          email: "analyst@example.com",
          department: "安全运营中心",
          role: "安全分析师",
        },
        preferences: {
          language: "zh-Hans",
          dark_mode: false,
          font_size: "default",
          emoji_mode: "active",
        },
      },
    });
    const streamQuestion = vi.spyOn(api, "streamQuestion").mockResolvedValue({ answer: "你好 👋" } as never);
    vi.spyOn(api, "conversations").mockResolvedValue([]);
    render(<AssistantWorkspace />);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "你好" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    await waitFor(() => expect(streamQuestion).toHaveBeenCalledWith(
      expect.objectContaining({
        question: "你好",
        response_language: "zh-Hans",
        emoji_mode: "active",
      }),
      expect.any(Object),
      expect.any(AbortSignal),
    ));
  });

  it("uses the local sparkles and glowing-card welcome stage without decorative icons", () => {
    useAppStore.setState({ turns: [] });
    render(<AssistantWorkspace />);

    const stage = screen.getByTestId("aceternity-sparkles-stage");
    expect(stage).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: "AegisAl 信息中心标识" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /扫描代码项目|查询最新漏洞|导出 SBOM/ })).toHaveLength(3);
    expect(stage.querySelector(".empty-suggestions svg")).not.toBeInTheDocument();
  });

  it("renders the latest 60 turns, reveals older batches, and resets the window for a new session", async () => {
    const makeTurns = (prefix: string): ChatTurn[] => Array.from({ length: 125 }, (_, index) => ({
      id: `${prefix}-${index + 1}`,
      role: "user",
      content: `${prefix} ${index + 1}`,
      createdAt: `2026-08-19T10:${String(index % 60).padStart(2, "0")}:00Z`,
    }));
    useAppStore.setState({ turns: makeTurns("旧会话") });

    render(<AssistantWorkspace />);

    const log = screen.getByRole("log", { name: "安全分析对话" });
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(60);
    expect(screen.queryByText("旧会话 65")).not.toBeInTheDocument();
    expect(screen.getByText("旧会话 66")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "显示更早消息" }));
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(120);
    expect(log).toHaveAttribute("aria-live", "off");
    expect(screen.queryByText("旧会话 5")).not.toBeInTheDocument();
    expect(screen.getByText("旧会话 6")).toBeInTheDocument();
    await waitFor(() => expect(log).toHaveAttribute("aria-live", "polite"));

    fireEvent.click(screen.getByRole("button", { name: "显示更早消息" }));
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(125);
    expect(screen.queryByRole("button", { name: "显示更早消息" })).not.toBeInTheDocument();

    act(() => {
      useAppStore.setState({ activeSessionId: "session-2", turns: makeTurns("新会话") });
    });
    await waitFor(() => expect(log.querySelectorAll(".chat-turn")).toHaveLength(60));
    expect(screen.queryByText("新会话 65")).not.toBeInTheDocument();
    expect(screen.getByText("新会话 66")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "显示更早消息" }));
    expect(log.querySelectorAll(".chat-turn")).toHaveLength(120);
    act(() => {
      useAppStore.setState({ activeTaskId: "new-task", turns: makeTurns("新任务") });
    });
    await waitFor(() => expect(log.querySelectorAll(".chat-turn")).toHaveLength(60));
    expect(screen.queryByText("新任务 65")).not.toBeInTheDocument();
    expect(screen.getByText("新任务 66")).toBeInTheDocument();

    act(() => {
      useAppStore.setState({ turns: [] });
    });
    await waitFor(() => expect(log.querySelectorAll(".chat-turn")).toHaveLength(0));
    act(() => {
      useAppStore.setState({ turns: makeTurns("清空后") });
    });
    await waitFor(() => expect(log.querySelectorAll(".chat-turn")).toHaveLength(60));
    expect(screen.queryByText("清空后 65")).not.toBeInTheDocument();
  });

  it("marks the conversation as a live log and regenerates from a user turn outside the visible window", async () => {
    const turns: ChatTurn[] = [
      { id: "user-1", role: "user", content: "第一个问题", createdAt: "2026-08-19T10:00:00Z" },
      { id: "assistant-1", role: "assistant", content: "第一个回答", createdAt: "2026-08-19T10:00:01Z", state: "completed" },
      ...Array.from({ length: 59 }, (_, index): ChatTurn => ({
        id: `later-${index}`,
        role: "user",
        content: `后续消息 ${index + 1}`,
        createdAt: "2026-08-19T10:00:02Z",
      })),
    ];
    useAppStore.setState({
      activeTaskId: "",
      workspacePath: "",
      workspaceName: "",
      tasks: [],
      turns,
      health: { ok: true } as never,
    });
    const streamQuestion = vi.spyOn(api, "streamQuestion").mockResolvedValue({ answer: "已重新生成" } as never);
    vi.spyOn(api, "conversations").mockResolvedValue([]);

    render(<AssistantWorkspace />);

    expect(screen.getByRole("log", { name: "安全分析对话" })).toHaveAttribute("aria-live", "polite");
    expect(screen.queryByText("第一个问题")).not.toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "重新生成" })[0]);

    await waitFor(() => expect(streamQuestion).toHaveBeenCalledWith(
      expect.objectContaining({ question: "第一个问题" }),
      expect.any(Object),
      expect.any(AbortSignal),
    ));
  });

  it("persists edited translated tables and writes the saved snapshot back to the turn", async () => {
    const turn: ChatTurn = {
      id: "msg-42:assistant",
      role: "assistant",
      content: "已返回翻译后的记录。",
      createdAt: "2026-08-23T09:00:00+08:00",
      state: "completed",
      result: {
        answer: "已返回翻译后的记录。",
        session_id: "translated-session",
        tables: [{
          id: "translated-findings",
          title: "翻译后的漏洞记录",
          columns: [
            { key: "id", label: "漏洞编号", editable: false },
            { key: "title", label: "标题" },
          ],
          rows: [{ id: "CVE-2026-4242", title: "原中文标题" }],
        }],
      },
    };
    useAppStore.setState({
      activeTaskId: "",
      activeSessionId: "translated-session",
      workspacePath: "",
      workspaceName: "",
      tasks: [],
      turns: [turn],
      health: { ok: true } as never,
    });
    const update = vi.spyOn(api, "updateConversationTableEdits").mockImplementation(
      async (_sessionId, exchangeId, _userId, tables) => ({ exchange_id: exchangeId, tables }),
    );

    render(<AssistantWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "编辑记录表" }));
    fireEvent.change(screen.getByRole("textbox", { name: "标题，第 1" }), {
      target: { value: "保存后的中文标题" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }));

    await waitFor(() => expect(update).toHaveBeenCalledWith(
      "translated-session",
      "msg-42",
      "analyst",
      expect.arrayContaining([
        expect.objectContaining({
          id: "translated-findings",
          rows: [{ id: "CVE-2026-4242", title: "保存后的中文标题" }],
        }),
      ]),
    ));
    await waitFor(() => expect(
      useAppStore.getState().turns[0].result?.structured_data_edits?.[0].rows[0],
    ).toEqual({ id: "CVE-2026-4242", title: "保存后的中文标题" }));
  });
});
